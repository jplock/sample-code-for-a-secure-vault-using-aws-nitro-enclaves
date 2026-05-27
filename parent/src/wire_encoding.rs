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

use crate::models::ParentRequest;

// HPKE suite identifiers (RFC 9180). Same byte sequences as before; this
// is just the parent-side parser.
const SUITE_ID_P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
const SUITE_ID_P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
const SUITE_ID_P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];

const ENCODING_HEX: &str = "1";
const ENCODING_BINARY: &str = "2";

/// Decode the API's base64 `suite_id` into a typed [`Suite`].
pub fn decode_suite_id(b64: &str) -> Result<Suite> {
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|err| anyhow!("invalid suite_id base64: {err}"))?;
    match bytes.as_slice() {
        b if b == SUITE_ID_P256 => Ok(Suite::P256),
        b if b == SUITE_ID_P384 => Ok(Suite::P384),
        b if b == SUITE_ID_P521 => Ok(Suite::P521),
        _ => bail!("unknown suite_id"),
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
}
