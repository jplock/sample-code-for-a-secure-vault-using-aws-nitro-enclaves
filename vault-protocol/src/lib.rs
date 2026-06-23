// Copyright Smoke Turner, LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Wire protocol between the parent instance and the Nitro Enclave.
//!
//! # Frame format
//!
//! Every message on the vsock channel is a single frame:
//!
//! ```text
//! +-------+-------+-------------+--------------------+
//! | u8 v  | u8 t  | u32 le len  | CBOR body          |
//! +-------+-------+-------------+--------------------+
//!   1 B     1 B     4 B            N bytes
//! ```
//!
//! - `v` — wire format version. Current = [`WIRE_VERSION`]. Unknown versions
//!   are rejected without parsing the body.
//! - `t` — message type discriminant ([`MessageType::Request`] or
//!   [`MessageType::Response`]). Lets the receiver reject mis-typed frames
//!   before deserialization.
//! - `len` — body length in bytes (little-endian). Bounded by
//!   [`MAX_FRAME_BODY_SIZE`]; oversize bodies are rejected before allocation.
//! - body — CBOR-serialized [`EnclaveRequest`] (when `t = Request`) or
//!   [`EnclaveResponse`] (when `t = Response`), produced via the
//!   [`ciborium`](https://crates.io/crates/ciborium) crate.
//!
//! # Why CBOR
//!
//! - Compact: small integer / short string / byte string encodings; raw
//!   byte slices stay raw. Per-field ciphertext crosses the boundary as
//!   `Vec<u8>` instead of a base64- or hex-encoded JSON string (~30–60%
//!   smaller per frame than the previous JSON-over-length-prefix format).
//! - Self-describing, so `serde_json::Value` (which carries CEL expression
//!   results of unknown variant) round-trips through `Serialize` /
//!   `Deserialize` without any custom enum.
//! - Rust-native and serde-compatible — the wire types use the same
//!   `#[derive(Serialize, Deserialize)]` they already had under JSON.
//! - Small dependency tree; no proc macros at the codec layer.
//!
//! # Trust model
//!
//! Both ends run on the same EC2 instance over an in-kernel vsock channel.
//! There is no MitM concern; only the parent can connect to the enclave.
//! The protocol therefore favors throughput and clarity over wire-level
//! cryptographic framing. The payload-level secrets (HPKE-encrypted
//! per-field values, KMS-encrypted private key) are protected by their
//! own cryptographic envelopes.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

/// Current wire protocol version. Receivers reject any other value.
pub const WIRE_VERSION: u8 = 1;

/// Maximum body size that will be accepted by [`recv_request`] / [`recv_response`].
/// Bounds attacker-controlled allocation on the receive path. Sized for the
/// legitimate upper bound (`MAX_FIELDS` × [`MAX_FIELD_CIPHERTEXT_SIZE`] plus
/// envelope overhead) with comfortable headroom.
pub const MAX_FRAME_BODY_SIZE: u32 = 10 * 1024 * 1024;

/// Maximum decoded ciphertext size per field (64 KB). Real PII/PHI values
/// (SSN, name, email, address) are all well under 1 KB; this leaves ample
/// headroom while bounding attacker-controlled per-field allocation.
///
/// Enforced on both sides as defense in depth: the parent rejects oversize
/// fields when decoding the API request, and the enclave re-checks before
/// HPKE decryption.
pub const MAX_FIELD_CIPHERTEXT_SIZE: usize = 64 * 1024;

const HEADER_LEN: usize = 6;
const HEADER_VERSION_OFFSET: usize = 0;
const HEADER_TYPE_OFFSET: usize = 1;
const HEADER_LEN_OFFSET: usize = 2;

/// Discriminant byte for the frame's payload kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Parent → enclave: an [`EnclaveRequest`].
    Request = 1,
    /// Enclave → parent: an [`EnclaveResponse`].
    Response = 2,
}

impl MessageType {
    fn from_u8(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(anyhow!("unknown message type byte: {b}")),
        }
    }
}

// =============================================================================
// Wire types
// =============================================================================

/// HPKE cipher-suite discriminant on the wire. The mapping to a concrete
/// `rustls::crypto::hpke::Hpke` implementation lives in the enclave; this
/// crate only carries the choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Suite {
    /// DH-KEM-P256 + HKDF-SHA256 + AES-256-GCM (RFC 9180).
    P256,
    /// DH-KEM-P384 + HKDF-SHA384 + AES-256-GCM (RFC 9180).
    P384,
    /// DH-KEM-P521 + HKDF-SHA512 + AES-256-GCM (RFC 9180).
    P521,
}

impl Suite {
    /// Encapsulated-key size in bytes for this suite (RFC 9180 Nenc).
    pub const fn encapped_key_size(self) -> usize {
        match self {
            Suite::P256 => 65,
            Suite::P384 => 97,
            Suite::P521 => 133,
        }
    }
}

/// One HPKE-encrypted per-field value. Both halves are raw bytes; the
/// API sends them as CBOR `bstr` values so they arrive here without any
/// hex/base64 encoding.
///
/// `serde_bytes` is used so the CBOR wire encoding is a compact byte
/// string (`bstr`, major type 2) rather than the default array of
/// small ints. This matches what Python's `cbor2` (and any other
/// language's idiomatic CBOR library) produces on the API ↔ parent
/// leg, and saves space on the parent ↔ enclave leg too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedField {
    #[serde(with = "serde_bytes")]
    pub encapped_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// AWS STS credentials, forwarded from the parent's IMDS cache.
///
/// Fields are private and `Clone` is intentionally NOT derived so the
/// type system can enforce the single-owner / zeroize-on-drop invariant.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,

    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,

    #[serde(rename = "Token")]
    session_token: String,
}

impl Credential {
    pub fn new(access_key_id: String, secret_access_key: String, session_token: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            session_token,
        }
    }

    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    pub fn session_token(&self) -> &str {
        &self.session_token
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .finish()
    }
}

/// Request body the parent forwards to the enclave on every decrypt call.
///
/// `expressions` is kept as `Option` to distinguish "no expressions
/// provided" from "explicitly empty map" rather than for wire-size
/// savings — CBOR encodes either form compactly.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParentRequest {
    pub vault_id: String,
    pub region: String,
    pub fields: HashMap<String, EncryptedField>,
    pub suite: Suite,
    /// KMS-encrypted HPKE private key blob. Decrypted via the vsock KMS
    /// proxy inside the enclave. `serde_bytes` for the same reason as
    /// [`EncryptedField`] — keep the CBOR wire as a compact `bstr`.
    #[serde(with = "serde_bytes")]
    pub encrypted_private_key: Vec<u8>,
    pub expressions: Option<HashMap<String, String>>,
}

/// Top-level request frame body (`MessageType::Request`).
#[derive(Debug, Serialize, Deserialize)]
pub struct EnclaveRequest {
    pub credential: Credential,
    pub request: ParentRequest,
}

/// Top-level response frame body (`MessageType::Response`).
///
/// `fields` carries decrypted (and possibly CEL-transformed) per-field
/// values. `errors` carries sanitized per-field decryption / expression
/// failures; see `enclave/src/utils.rs::sanitize_error_message`.
///
/// The parent maps `fields: None` to `DecryptError` (HTTP 500) rather than
/// a 200 response with an empty map, so total failures are distinguishable
/// from partial failures at the HTTP layer.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EnclaveResponse {
    /// `Some(map)` for successful (possibly partial) decrypt; `None` only
    /// when the enclave couldn't process the request at all (parse error,
    /// KMS failure before any field was attempted). The parent maps `None`
    /// to HTTP 500 (`DecryptError`), not an empty 200 response.
    pub fields: Option<HashMap<String, Value>>,
    /// Sanitized per-field decryption / expression failures. `None`
    /// means no errors at all (vs `Some(empty)` which never occurs).
    pub errors: Option<Vec<String>>,
}

impl EnclaveResponse {
    pub fn new(fields: HashMap<String, Value>, errors: Option<Vec<String>>) -> Self {
        Self {
            fields: Some(fields),
            errors,
        }
    }

    /// Builds a response carrying only a single already-sanitized error.
    pub fn error_msg(sanitized: String) -> Self {
        Self {
            fields: None,
            errors: Some(vec![sanitized]),
        }
    }
}

// =============================================================================
// Frame send / recv
// =============================================================================

/// Serialize and send a request frame. Reusable for any `impl Write`
/// so unit tests can target an in-memory cursor.
#[tracing::instrument(skip(writer, req))]
pub fn send_request<W: Write>(writer: &mut W, req: &EnclaveRequest) -> Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(req, &mut body)
        .map_err(|err| anyhow!("failed to serialize request: {err}"))?;
    write_frame(writer, MessageType::Request, &body)
}

/// Serialize and send a response frame.
#[tracing::instrument(skip(writer, resp))]
pub fn send_response<W: Write>(writer: &mut W, resp: &EnclaveResponse) -> Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(resp, &mut body)
        .map_err(|err| anyhow!("failed to serialize response: {err}"))?;
    write_frame(writer, MessageType::Response, &body)
}

/// Read and deserialize a request frame. Returns an error if the wire
/// version, message type, or body length is out of policy.
#[tracing::instrument(skip(reader))]
pub fn recv_request<R: Read>(reader: &mut R) -> Result<EnclaveRequest> {
    let body = read_frame(reader, MessageType::Request)?;
    ciborium::from_reader(body.as_slice())
        .map_err(|err| anyhow!("failed to deserialize request: {err}"))
}

/// Read and deserialize a response frame.
#[tracing::instrument(skip(reader))]
pub fn recv_response<R: Read>(reader: &mut R) -> Result<EnclaveResponse> {
    let body = read_frame(reader, MessageType::Response)?;
    ciborium::from_reader(body.as_slice())
        .map_err(|err| anyhow!("failed to deserialize response: {err}"))
}

fn write_frame<W: Write>(writer: &mut W, msg_type: MessageType, body: &[u8]) -> Result<()> {
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| anyhow!("frame body length {} exceeds u32", body.len()))?;
    if len > MAX_FRAME_BODY_SIZE {
        bail!(
            "frame body length {} exceeds maximum {}",
            len,
            MAX_FRAME_BODY_SIZE
        );
    }

    // Concatenate header + body and emit in a single `write_all` so the
    // frame goes out in one syscall on `VsockStream`. The 6-byte header
    // is tiny next to the body; the upfront capacity hint costs one
    // alloc per send but halves the kernel round-trips on the hot path.
    let mut frame: Vec<u8> = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    frame.push(WIRE_VERSION);
    frame.push(msg_type as u8);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(body);

    writer
        .write_all(&frame)
        .map_err(|err| anyhow!("failed to write frame: {err}"))?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R, expected: MessageType) -> Result<Vec<u8>> {
    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|err| anyhow!("failed to read frame header: {err}"))?;

    let version = header[HEADER_VERSION_OFFSET];
    if version != WIRE_VERSION {
        bail!("unsupported wire version: got {version}, expected {WIRE_VERSION}");
    }

    let msg_type = MessageType::from_u8(header[HEADER_TYPE_OFFSET])?;
    if msg_type != expected {
        bail!(
            "unexpected message type: got {:?}, expected {:?}",
            msg_type,
            expected
        );
    }

    // Safe: header is exactly 6 bytes; this slice is always valid.
    let len_bytes: [u8; 4] = header
        .get(HEADER_LEN_OFFSET..HEADER_LEN)
        .ok_or_else(|| anyhow!("frame header truncated"))?
        .try_into()
        .map_err(|_| anyhow!("frame header length slice malformed"))?;
    let len = u32::from_le_bytes(len_bytes);

    if len > MAX_FRAME_BODY_SIZE {
        bail!(
            "frame body length {} exceeds maximum {}",
            len,
            MAX_FRAME_BODY_SIZE
        );
    }

    let len_usize: usize = len
        .try_into()
        .map_err(|_| anyhow!("frame body length {len} too large for platform"))?;

    let mut body = Vec::new();
    body.try_reserve(len_usize)
        .map_err(|_| anyhow!("failed to allocate {len_usize} bytes for frame body"))?;
    body.resize(len_usize, 0);
    reader
        .read_exact(&mut body)
        .map_err(|err| anyhow!("failed to read frame body: {err}"))?;

    Ok(body)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use unwrap/expect/indexing for terseness"
)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    fn sample_credential() -> Credential {
        Credential::new("AKIA".into(), "SECRET".into(), "TOKEN".into())
    }

    fn sample_request() -> EnclaveRequest {
        let mut fields = HashMap::new();
        fields.insert(
            "first_name".to_string(),
            EncryptedField {
                encapped_key: vec![0xAB; 97],
                ciphertext: vec![0xCD; 32],
            },
        );
        EnclaveRequest {
            credential: sample_credential(),
            request: ParentRequest {
                vault_id: "v_test".into(),
                region: "us-east-1".into(),
                fields,
                suite: Suite::P384,
                encrypted_private_key: vec![0xEE; 256],
                expressions: None,
            },
        }
    }

    fn sample_response() -> EnclaveResponse {
        let mut fields = HashMap::new();
        fields.insert("first_name".to_string(), Value::String("Bob".to_string()));
        EnclaveResponse::new(fields, None)
    }

    // --- round trips -------------------------------------------------------

    #[test]
    fn request_round_trip() {
        let original = sample_request();
        let mut buf = Vec::new();
        send_request(&mut buf, &original).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = recv_request(&mut cursor).unwrap();
        assert_eq!(decoded.request.vault_id, original.request.vault_id);
        assert_eq!(decoded.request.region, original.request.region);
        assert_eq!(decoded.request.suite, original.request.suite);
        assert_eq!(decoded.request.fields, original.request.fields);
        assert_eq!(
            decoded.request.encrypted_private_key,
            original.request.encrypted_private_key
        );
        assert_eq!(
            decoded.credential.access_key_id(),
            original.credential.access_key_id()
        );
    }

    #[test]
    fn response_round_trip() {
        let original = sample_response();
        let mut buf = Vec::new();
        send_response(&mut buf, &original).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = recv_response(&mut cursor).unwrap();
        assert_eq!(decoded.fields, original.fields);
        assert_eq!(decoded.errors, original.errors);
    }

    #[test]
    fn error_response_round_trip() {
        let original = EnclaveResponse::error_msg("sanitized error".to_string());
        let mut buf = Vec::new();
        send_response(&mut buf, &original).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = recv_response(&mut cursor).unwrap();
        assert!(decoded.fields.is_none());
        assert_eq!(
            decoded.errors.as_deref(),
            Some(&["sanitized error".to_string()][..])
        );
    }

    // --- header validation -------------------------------------------------

    #[test]
    fn rejects_unknown_wire_version() {
        let mut buf = Vec::new();
        send_request(&mut buf, &sample_request()).unwrap();
        buf[0] = 99; // tamper version
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("unsupported wire version"), "got: {err}");
    }

    #[test]
    fn rejects_wrong_message_type_on_recv_request() {
        let mut buf = Vec::new();
        send_response(&mut buf, &sample_response()).unwrap();
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("unexpected message type"), "got: {err}");
    }

    #[test]
    fn rejects_wrong_message_type_on_recv_response() {
        let mut buf = Vec::new();
        send_request(&mut buf, &sample_request()).unwrap();
        let mut cursor = Cursor::new(buf);
        let err = recv_response(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("unexpected message type"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_message_type_byte() {
        let body = vec![0u8; 4];
        let mut buf = Vec::new();
        buf.push(WIRE_VERSION);
        buf.push(99); // unknown type
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(&body);
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("unknown message type"), "got: {err}");
    }

    #[test]
    fn rejects_oversize_body() {
        // Header claims a body larger than MAX_FRAME_BODY_SIZE.
        let oversize = MAX_FRAME_BODY_SIZE + 1;
        let mut buf = Vec::new();
        buf.push(WIRE_VERSION);
        buf.push(MessageType::Request as u8);
        buf.extend_from_slice(&oversize.to_le_bytes());
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn rejects_truncated_header() {
        let buf = vec![WIRE_VERSION, MessageType::Request as u8]; // only 2 of 6 bytes
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("failed to read frame header"), "got: {err}");
    }

    #[test]
    fn rejects_truncated_body() {
        let mut buf = Vec::new();
        buf.push(WIRE_VERSION);
        buf.push(MessageType::Request as u8);
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]); // 10 < 100 promised
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("failed to read frame body"), "got: {err}");
    }

    #[test]
    fn rejects_garbage_body() {
        // Valid header announcing a 4-byte body, but the body is not a
        // CBOR-encoded EnclaveRequest.
        let mut buf = Vec::new();
        buf.push(WIRE_VERSION);
        buf.push(MessageType::Request as u8);
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&[0xFFu8; 4]);
        let mut cursor = Cursor::new(buf);
        let err = recv_request(&mut cursor).unwrap_err().to_string();
        assert!(err.contains("failed to deserialize request"), "got: {err}");
    }

    #[test]
    fn credential_debug_redacts_all_fields() {
        let cred = Credential::new(
            "AKIASECRET".into(),
            "SUPER_SECRET".into(),
            "SESSION_TOKEN".into(),
        );
        let s = format!("{cred:?}");
        assert!(s.contains("[REDACTED]"));
        assert!(!s.contains("AKIASECRET"));
        assert!(!s.contains("SUPER_SECRET"));
        assert!(!s.contains("SESSION_TOKEN"));
    }

    // --- property tests ----------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Round-trip an arbitrary request through send → recv.
        #[test]
        fn prop_request_round_trip(
            vault_id in "[a-zA-Z0-9_-]{1,32}",
            region in "[a-z0-9-]{1,16}",
            ekey_seed in any::<u8>(),
            ekey_len in 1usize..256,
            ct_seed in any::<u8>(),
            ct_len in 1usize..256,
            suite_idx in 0usize..3,
        ) {
            let suite = [Suite::P256, Suite::P384, Suite::P521][suite_idx];
            let mut fields = HashMap::new();
            fields.insert(
                "f".to_string(),
                EncryptedField {
                    encapped_key: vec![ekey_seed; ekey_len],
                    ciphertext: vec![ct_seed; ct_len],
                },
            );
            let original = EnclaveRequest {
                credential: sample_credential(),
                request: ParentRequest {
                    vault_id,
                    region,
                    fields,
                    suite,
                    encrypted_private_key: vec![0xAA; 64],
                    expressions: None,
                },
            };

            let mut buf = Vec::new();
            send_request(&mut buf, &original).unwrap();
            let mut cursor = Cursor::new(buf);
            let decoded = recv_request(&mut cursor).unwrap();
            prop_assert_eq!(decoded.request.vault_id, original.request.vault_id);
            prop_assert_eq!(decoded.request.region, original.request.region);
            prop_assert_eq!(decoded.request.fields, original.request.fields);
            prop_assert_eq!(decoded.request.suite, original.request.suite);
        }

        /// recv_request must not panic for ANY tampered version byte.
        #[test]
        fn prop_arbitrary_version_byte_never_panics(version in any::<u8>()) {
            let mut buf = Vec::new();
            send_request(&mut buf, &sample_request()).unwrap();
            buf[0] = version;
            let mut cursor = Cursor::new(buf);
            let result = recv_request(&mut cursor);
            if version != WIRE_VERSION {
                prop_assert!(result.is_err());
            }
        }

        /// recv_request must not panic for ANY tampered type byte.
        #[test]
        fn prop_arbitrary_type_byte_never_panics(msg_type in any::<u8>()) {
            let mut buf = Vec::new();
            send_request(&mut buf, &sample_request()).unwrap();
            buf[1] = msg_type;
            let mut cursor = Cursor::new(buf);
            let result = recv_request(&mut cursor);
            if msg_type != MessageType::Request as u8 {
                prop_assert!(result.is_err());
            }
        }

        /// recv_request must reject any body length above the cap without
        /// allocating that many bytes.
        #[test]
        fn prop_oversize_lengths_rejected(extra in 1u32..1024) {
            let len = MAX_FRAME_BODY_SIZE.saturating_add(extra);
            let mut buf = Vec::new();
            buf.push(WIRE_VERSION);
            buf.push(MessageType::Request as u8);
            buf.extend_from_slice(&len.to_le_bytes());
            let mut cursor = Cursor::new(buf);
            let result = recv_request(&mut cursor);
            prop_assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            prop_assert!(msg.contains("exceeds maximum"));
        }
    }
}
