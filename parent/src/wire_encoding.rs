// Copyright Smoke Turner, LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Boundary translation between the API's JSON request shape and the
//! enclave's binary [`vault_protocol`] wire shape.
//!
//! The API speaks JSON over HTTPS:
//! - `suite_id: String` — base64 of a 10-byte HPKE suite identifier
//! - `encrypted_private_key: String` — base64 of the KMS ciphertext
//! - `fields: HashMap<String, String>` — each value is either hex
//!   (`encap_hex#ct_hex`) or base64 (concat of `encap || ciphertext`),
//!   selected by the optional `encoding` field (`"1"` = hex, `"2"` =
//!   binary; default = binary).
//!
//! The enclave's wire format (in [`vault_protocol`]) carries everything
//! as bytes / typed enums. This module is the one place where the JSON
//! representation is unwound; the enclave never sees a base64 or hex
//! string. Doing the decode here gets the work out of the enclave's
//! single-threaded hot path and tightens the enclave's attack surface.
//!
//! Per-field ciphertext is capped at
//! [`vault_protocol::MAX_FIELD_CIPHERTEXT_SIZE`]; the enclave re-checks
//! as defense in depth.

use anyhow::{Result, anyhow, bail};
use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use std::collections::HashMap;
use vault_protocol::{
    Credential, EnclaveRequest, EncryptedField, MAX_FIELD_CIPHERTEXT_SIZE,
    ParentRequest as WireParentRequest, Suite,
};

use crate::models::{ParentRequest, ParentRequestCbor};

// HPKE suite identifiers (RFC 9180). Same byte sequences as before; this
// is just the parent-side parser.
const SUITE_ID_P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
const SUITE_ID_P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
const SUITE_ID_P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];

const ENCODING_HEX: &str = "1";
const ENCODING_BINARY: &str = "2";

/// Map raw HPKE suite identifier bytes (10 bytes per RFC 9180) to a
/// typed [`Suite`]. Shared by the JSON path (base64-decoded first) and
/// the CBOR path (bytes already).
pub fn suite_from_bytes(bytes: &[u8]) -> Result<Suite> {
    match bytes {
        b if b == SUITE_ID_P256 => Ok(Suite::P256),
        b if b == SUITE_ID_P384 => Ok(Suite::P384),
        b if b == SUITE_ID_P521 => Ok(Suite::P521),
        _ => bail!("unknown suite_id"),
    }
}

/// Decode the API's base64 `suite_id` into a typed [`Suite`].
pub fn decode_suite_id(b64: &str) -> Result<Suite> {
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|err| anyhow!("invalid suite_id base64: {err}"))?;
    suite_from_bytes(&bytes)
}

/// Decode a single per-field encrypted value into raw bytes. The
/// encoding selector determines the wire format used by the API.
fn decode_encrypted_field(value: &str, encoding: Encoding, suite: Suite) -> Result<EncryptedField> {
    let ef = match encoding {
        Encoding::Hex => decode_hex(value)?,
        Encoding::Binary => decode_binary(value, suite)?,
    };
    if ef.ciphertext.len() > MAX_FIELD_CIPHERTEXT_SIZE {
        bail!(
            "ciphertext size {} exceeds maximum {}",
            ef.ciphertext.len(),
            MAX_FIELD_CIPHERTEXT_SIZE
        );
    }
    Ok(ef)
}

/// `encap_hex#ct_hex`.
fn decode_hex(value: &str) -> Result<EncryptedField> {
    let (encap_hex, ct_hex) = value
        .split_once('#')
        .ok_or_else(|| anyhow!("hex-encoded value missing '#' separator"))?;

    // Pre-decode bound: hex is exactly 2 chars per byte.
    if ct_hex.len() / 2 > MAX_FIELD_CIPHERTEXT_SIZE {
        bail!(
            "ciphertext size {} exceeds maximum {}",
            ct_hex.len() / 2,
            MAX_FIELD_CIPHERTEXT_SIZE
        );
    }

    let encapped_key = HEXLOWER_PERMISSIVE
        .decode(encap_hex.as_bytes())
        .map_err(|err| anyhow!("invalid hex encapped key: {err}"))?;
    let ciphertext = HEXLOWER_PERMISSIVE
        .decode(ct_hex.as_bytes())
        .map_err(|err| anyhow!("invalid hex ciphertext: {err}"))?;
    Ok(EncryptedField {
        encapped_key,
        ciphertext,
    })
}

/// Base64 of `encap || ciphertext`; split by the suite's `Nenc`.
fn decode_binary(value: &str, suite: Suite) -> Result<EncryptedField> {
    let data = BASE64
        .decode(value.as_bytes())
        .map_err(|err| anyhow!("invalid base64 value: {err}"))?;
    let key_size = suite.encapped_key_size();
    if data.len() < key_size {
        bail!(
            "encrypted data too short: {} bytes, need at least {} for {:?}",
            data.len(),
            key_size,
            suite
        );
    }
    let encapped_key = data
        .get(..key_size)
        .ok_or_else(|| anyhow!("failed to extract encapped key"))?
        .to_vec();
    let ciphertext = data
        .get(key_size..)
        .ok_or_else(|| anyhow!("failed to extract ciphertext"))?
        .to_vec();
    Ok(EncryptedField {
        encapped_key,
        ciphertext,
    })
}

#[derive(Clone, Copy)]
enum Encoding {
    Hex,
    Binary,
}

impl Encoding {
    fn from_optional(s: Option<&String>) -> Result<Self> {
        match s.map(String::as_str) {
            None => Ok(Encoding::Binary), // historical default
            Some(s) if s == ENCODING_HEX => Ok(Encoding::Hex),
            Some(s) if s == ENCODING_BINARY => Ok(Encoding::Binary),
            Some(s) => bail!("unknown encoding selector: {s}"),
        }
    }
}

/// Translate an API `ParentRequest` plus IMDS credentials into the
/// `vault_protocol::EnclaveRequest` that the enclave reads. All
/// base64/hex envelopes are unwound here; per-field ciphertext caps and
/// the suite identifier are validated as part of the decode.
pub fn build_enclave_request(
    api_req: ParentRequest,
    credential: Credential,
) -> Result<EnclaveRequest> {
    let suite = decode_suite_id(&api_req.suite_id)?;
    let encoding = Encoding::from_optional(api_req.encoding.as_ref())?;

    let encrypted_private_key = BASE64
        .decode(api_req.encrypted_private_key.as_bytes())
        .map_err(|err| anyhow!("invalid encrypted_private_key base64: {err}"))?;

    let mut fields: HashMap<String, EncryptedField> = HashMap::with_capacity(api_req.fields.len());
    for (name, encoded) in api_req.fields {
        let ef = decode_encrypted_field(&encoded, encoding, suite)
            .map_err(|err| anyhow!("field '{name}': {err}"))?;
        fields.insert(name, ef);
    }

    let expressions = api_req.expressions.map(|m| m.into_iter().collect());

    Ok(EnclaveRequest {
        credential,
        request: WireParentRequest {
            vault_id: api_req.vault_id,
            region: api_req.region,
            fields,
            suite,
            encrypted_private_key,
            expressions,
        },
    })
}

/// Translate a CBOR `ParentRequestCbor` plus IMDS credentials into the
/// `vault_protocol::EnclaveRequest` the enclave reads. The CBOR wire
/// shape already carries raw bytes and typed `EncryptedField` values,
/// so this is essentially credential injection plus mapping the 10-byte
/// suite identifier to the typed [`Suite`] enum. Per-field ciphertext
/// caps are re-checked here as defense in depth — the enclave checks
/// them again on the vsock side.
pub fn build_enclave_request_cbor(
    api_req: ParentRequestCbor,
    credential: Credential,
) -> Result<EnclaveRequest> {
    let suite = suite_from_bytes(&api_req.suite_id)?;

    let mut fields: HashMap<String, EncryptedField> = HashMap::with_capacity(api_req.fields.len());
    for (name, ef) in api_req.fields {
        if ef.ciphertext.len() > MAX_FIELD_CIPHERTEXT_SIZE {
            bail!(
                "field '{}': ciphertext size {} exceeds maximum {}",
                name,
                ef.ciphertext.len(),
                MAX_FIELD_CIPHERTEXT_SIZE
            );
        }
        fields.insert(name, ef);
    }

    let expressions = api_req.expressions.map(|m| m.into_iter().collect());

    Ok(EnclaveRequest {
        credential,
        request: WireParentRequest {
            vault_id: api_req.vault_id,
            region: api_req.region,
            fields,
            suite,
            encrypted_private_key: api_req.encrypted_private_key,
            expressions,
        },
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use unwrap/expect/indexing for terseness"
)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn decode_suite_id_p384() {
        let b64 = BASE64.encode(SUITE_ID_P384);
        assert_eq!(decode_suite_id(&b64).unwrap(), Suite::P384);
    }

    #[test]
    fn decode_suite_id_p256() {
        let b64 = BASE64.encode(SUITE_ID_P256);
        assert_eq!(decode_suite_id(&b64).unwrap(), Suite::P256);
    }

    #[test]
    fn decode_suite_id_p521() {
        let b64 = BASE64.encode(SUITE_ID_P521);
        assert_eq!(decode_suite_id(&b64).unwrap(), Suite::P521);
    }

    #[test]
    fn decode_suite_id_rejects_unknown() {
        let b64 = BASE64.encode(b"not-a-suite");
        assert!(decode_suite_id(&b64).is_err());
    }

    #[test]
    fn decode_suite_id_rejects_invalid_base64() {
        assert!(decode_suite_id("not!valid!base64!").is_err());
    }

    #[test]
    fn decode_hex_round_trip() {
        let encap = vec![0xABu8; 97];
        let ct = vec![0xCDu8; 24];
        let value = format!(
            "{}#{}",
            HEXLOWER_PERMISSIVE.encode(&encap),
            HEXLOWER_PERMISSIVE.encode(&ct)
        );
        let ef = decode_encrypted_field(&value, Encoding::Hex, Suite::P384).unwrap();
        assert_eq!(ef.encapped_key, encap);
        assert_eq!(ef.ciphertext, ct);
    }

    #[test]
    fn decode_binary_round_trip() {
        let key_size = Suite::P384.encapped_key_size();
        let mut data = vec![0xABu8; key_size];
        data.extend(vec![0xCDu8; 24]);
        let b64 = BASE64.encode(&data);
        let ef = decode_encrypted_field(&b64, Encoding::Binary, Suite::P384).unwrap();
        assert_eq!(ef.encapped_key.len(), key_size);
        assert_eq!(ef.ciphertext.len(), 24);
    }

    #[test]
    fn decode_hex_rejects_oversize_ciphertext() {
        let encap = HEXLOWER_PERMISSIVE.encode(&[0xAB; 97]);
        let ct = HEXLOWER_PERMISSIVE.encode(&vec![0xCD; MAX_FIELD_CIPHERTEXT_SIZE + 1]);
        let value = format!("{encap}#{ct}");
        let err = decode_encrypted_field(&value, Encoding::Hex, Suite::P384).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn decode_binary_rejects_oversize_ciphertext() {
        let key_size = Suite::P384.encapped_key_size();
        let mut data = vec![0xABu8; key_size];
        data.extend(vec![0xCDu8; MAX_FIELD_CIPHERTEXT_SIZE + 1]);
        let b64 = BASE64.encode(&data);
        let err = decode_encrypted_field(&b64, Encoding::Binary, Suite::P384).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn encoding_from_optional() {
        assert!(matches!(
            Encoding::from_optional(None).unwrap(),
            Encoding::Binary
        ));
        assert!(matches!(
            Encoding::from_optional(Some(&"1".to_string())).unwrap(),
            Encoding::Hex
        ));
        assert!(matches!(
            Encoding::from_optional(Some(&"2".to_string())).unwrap(),
            Encoding::Binary
        ));
        assert!(Encoding::from_optional(Some(&"99".to_string())).is_err());
    }

    #[test]
    fn build_enclave_request_translates_full_request() {
        // Build an API ParentRequest with a single base64-binary field.
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        let key_size = Suite::P384.encapped_key_size();
        let mut field_bytes = vec![0xABu8; key_size];
        field_bytes.extend(vec![0xCDu8; 16]);
        fields.insert("ssn".to_string(), BASE64.encode(&field_bytes));

        let api_req = ParentRequest {
            vault_id: "v_test".to_string(),
            region: "us-east-1".to_string(),
            fields,
            suite_id: BASE64.encode(SUITE_ID_P384),
            encrypted_private_key: BASE64.encode(b"kms-ciphertext"),
            expressions: None,
            encoding: None, // default = binary
        };

        let cred = Credential::new("AKIA".into(), "SECRET".into(), "TOKEN".into());

        let enc_req = build_enclave_request(api_req, cred).unwrap();
        assert_eq!(enc_req.request.vault_id, "v_test");
        assert_eq!(enc_req.request.suite, Suite::P384);
        assert_eq!(enc_req.request.encrypted_private_key, b"kms-ciphertext");
        let ef = enc_req.request.fields.get("ssn").unwrap();
        assert_eq!(ef.encapped_key.len(), key_size);
        assert_eq!(ef.ciphertext.len(), 16);
    }

    /// Cross-language wire-compatibility check (minimal vector). The
    /// byte sequence below is produced by Python's `cbor2.dumps({...})`
    /// with the same shape `api/src/app/vault.py::decrypt_vault` now
    /// builds. If parent's `ParentRequestCbor` ever diverges from what
    /// the API encodes — different field names, different shape, or
    /// different types — this test will fail loudly.
    #[test]
    fn deserialize_python_cbor_minimal_vector() {
        // Python:
        // cbor2.dumps({
        //   "vault_id": "v1", "region": "us-east-1", "fields": {},
        //   "suite_id": b"HPKE\x00\x11\x00\x02\x00\x02",
        //   "encrypted_private_key": b"\xef" * 8,
        // }).hex()
        let cbor_hex = concat!(
            "a5687661756c745f696462763166726567696f6e6975732d6561",
            "73742d31666669656c6473a06873756974655f69644a48504b45",
            "00110002000275656e637279707465645f707269766174655f6b",
            "657948efefefefefefefef",
        );
        let bytes = HEXLOWER_PERMISSIVE.decode(cbor_hex.as_bytes()).unwrap();
        let parsed: ParentRequestCbor = ciborium::de::from_reader(&*bytes).unwrap();

        assert_eq!(parsed.vault_id, "v1");
        assert_eq!(parsed.region, "us-east-1");
        assert!(parsed.fields.is_empty());
        assert_eq!(parsed.suite_id, SUITE_ID_P384);
        assert_eq!(parsed.encrypted_private_key, vec![0xEFu8; 8]);
        assert!(parsed.expressions.is_none());
    }

    /// Cross-language wire-compatibility check with a fully-populated
    /// payload — typed `{encapped_key, ciphertext}` per field, multiple
    /// fields, and an `expressions` map. Mirrors a realistic call shape.
    #[test]
    fn deserialize_python_cbor_full_vector() {
        // Python:
        // cbor2.dumps({
        //   "vault_id": "v_test_123", "region": "us-east-1",
        //   "fields": {
        //     "ssn":   {"encapped_key": bytes(range(97)),       "ciphertext": bytes([0xAB] * 32)},
        //     "email": {"encapped_key": bytes(range(50, 50+97)), "ciphertext": bytes([0xCD] * 24)},
        //   },
        //   "suite_id": b"HPKE\x00\x11\x00\x02\x00\x02",
        //   "encrypted_private_key": b"\xef" * 64,
        //   "expressions": {"age": "date(dob).age()"},
        // }).hex()
        let cbor_hex = concat!(
            "a6687661756c745f69646a765f746573745f31323366726567696f6e6975",
            "732d656173742d31666669656c6473a26373736ea26c656e636170706564",
            "5f6b65795861000102030405060708090a0b0c0d0e0f1011121314151617",
            "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435",
            "363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515253",
            "5455565758595a5b5c5d5e5f606a636970686572746578745820abababab",
            "abababababababababababababababababababababababababababab6565",
            "6d61696ca26c656e6361707065645f6b6579586132333435363738393a3b",
            "3c3d3e3f404142434445464748494a4b4c4d4e4f50515253545556575859",
            "5a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374757677",
            "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091926a6369",
            "70686572746578745818cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "cdcdcdcd6873756974655f69644a48504b4500110002000275656e637279",
            "707465645f707269766174655f6b65795840efefefefefefefefefefefef",
            "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
            "efefefefefefefefefefefefefefefefefefefefefef6b65787072657373",
            "696f6e73a1636167656f6461746528646f62292e6167652829",
        );
        let bytes = HEXLOWER_PERMISSIVE.decode(cbor_hex.as_bytes()).unwrap();
        let parsed: ParentRequestCbor = ciborium::de::from_reader(&*bytes).unwrap();

        assert_eq!(parsed.vault_id, "v_test_123");
        assert_eq!(parsed.region, "us-east-1");
        assert_eq!(parsed.suite_id, SUITE_ID_P384);
        assert_eq!(parsed.encrypted_private_key, vec![0xEFu8; 64]);
        assert_eq!(parsed.fields.len(), 2);

        let ssn = parsed.fields.get("ssn").unwrap();
        assert_eq!(ssn.encapped_key.len(), 97);
        assert_eq!(ssn.encapped_key[0], 0);
        assert_eq!(ssn.encapped_key[96], 96);
        assert_eq!(ssn.ciphertext, vec![0xABu8; 32]);

        let email = parsed.fields.get("email").unwrap();
        assert_eq!(email.encapped_key.len(), 97);
        assert_eq!(email.encapped_key[0], 50);
        assert_eq!(email.ciphertext, vec![0xCDu8; 24]);

        let expressions = parsed.expressions.as_ref().unwrap();
        assert_eq!(
            expressions.get("age").map(String::as_str),
            Some("date(dob).age()")
        );

        let cred = Credential::new("AKIA".into(), "SECRET".into(), "TOKEN".into());
        let enc_req = build_enclave_request_cbor(parsed, cred).unwrap();
        assert_eq!(enc_req.request.suite, Suite::P384);
        assert_eq!(enc_req.request.vault_id, "v_test_123");
        assert_eq!(enc_req.request.fields.len(), 2);
    }
}
