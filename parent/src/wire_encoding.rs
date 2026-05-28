// Copyright Smoke Turner, LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Boundary translation between the API's CBOR request shape and the
//! enclave's binary [`vault_protocol`] wire shape.
//!
//! The API speaks CBOR over HTTPS (`application/cbor`), carrying:
//! - `suite_id: bstr` — the 10-byte HPKE suite identifier (RFC 9180)
//! - `encrypted_private_key: bstr` — the raw KMS ciphertext
//! - `fields: { tstr => {encapped_key: bstr, ciphertext: bstr} }`
//!
//! Translation to the enclave wire shape is essentially a move plus
//! mapping the 10-byte suite identifier to the typed [`Suite`] enum
//! and injecting IMDS credentials. Per-field ciphertext is capped at
//! [`vault_protocol::MAX_FIELD_CIPHERTEXT_SIZE`]; the enclave re-checks
//! as defense in depth.

use anyhow::{Result, bail};
use std::collections::HashMap;
use vault_protocol::{
    Credential, EnclaveRequest, EncryptedField, MAX_FIELD_CIPHERTEXT_SIZE,
    ParentRequest as WireParentRequest, Suite,
};

use crate::models::ParentRequest;

// HPKE suite identifiers (RFC 9180). 10 bytes each: `"HPKE"` + KEM/KDF/AEAD
// IDs as big-endian u16. Built by the API per Python's
// `struct.pack(">HHH", ...)` and matched here verbatim.
const SUITE_ID_P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
const SUITE_ID_P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
const SUITE_ID_P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];

/// Map a raw HPKE suite identifier (10 bytes per RFC 9180) to a typed
/// [`Suite`]. Unknown patterns surface as an error.
pub fn suite_from_bytes(bytes: &[u8]) -> Result<Suite> {
    match bytes {
        b if b == SUITE_ID_P256 => Ok(Suite::P256),
        b if b == SUITE_ID_P384 => Ok(Suite::P384),
        b if b == SUITE_ID_P521 => Ok(Suite::P521),
        _ => bail!("unknown suite_id"),
    }
}

/// Translate an API `ParentRequest` plus IMDS credentials into the
/// `vault_protocol::EnclaveRequest` the enclave reads. Per-field
/// ciphertext caps are re-checked here as defense in depth — the
/// enclave checks them again on the vsock side.
pub fn build_enclave_request(
    api_req: ParentRequest,
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

    /// Decode lowercase hex into bytes. Inlined here to avoid pulling
    /// `data-encoding` into the parent crate for test-only use.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn suite_from_bytes_p256() {
        assert_eq!(suite_from_bytes(SUITE_ID_P256).unwrap(), Suite::P256);
    }

    #[test]
    fn suite_from_bytes_p384() {
        assert_eq!(suite_from_bytes(SUITE_ID_P384).unwrap(), Suite::P384);
    }

    #[test]
    fn suite_from_bytes_p521() {
        assert_eq!(suite_from_bytes(SUITE_ID_P521).unwrap(), Suite::P521);
    }

    #[test]
    fn suite_from_bytes_rejects_unknown() {
        assert!(suite_from_bytes(b"not-a-suite").is_err());
    }

    /// Cross-language wire-compatibility check (minimal vector). The
    /// byte sequence below is produced by Python's `cbor2.dumps({...})`
    /// with the same shape `api/src/app/vault.py::decrypt_vault` now
    /// builds. If parent's `ParentRequest` ever diverges from what the
    /// API encodes — different field names, different shape, or
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
        let bytes = hex_to_bytes(cbor_hex);
        let parsed: ParentRequest = ciborium::de::from_reader(&*bytes).unwrap();

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
        let bytes = hex_to_bytes(cbor_hex);
        let parsed: ParentRequest = ciborium::de::from_reader(&*bytes).unwrap();

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
        let enc_req = build_enclave_request(parsed, cred).unwrap();
        assert_eq!(enc_req.request.suite, Suite::P384);
        assert_eq!(enc_req.request.vault_id, "v_test_123");
        assert_eq!(enc_req.request.fields.len(), 2);
    }

    #[test]
    fn build_enclave_request_rejects_oversize_ciphertext() {
        use std::collections::BTreeMap;
        let mut fields: BTreeMap<String, EncryptedField> = BTreeMap::new();
        fields.insert(
            "field".to_string(),
            EncryptedField {
                encapped_key: vec![0xABu8; 97],
                ciphertext: vec![0xCDu8; MAX_FIELD_CIPHERTEXT_SIZE + 1],
            },
        );
        let req = ParentRequest {
            vault_id: "v_test".to_string(),
            region: "us-east-1".to_string(),
            fields,
            suite_id: SUITE_ID_P384.to_vec(),
            encrypted_private_key: vec![0xEFu8; 32],
            expressions: None,
        };
        let cred = Credential::new("AKIA".into(), "SECRET".into(), "TOKEN".into());
        let err = build_enclave_request(req, cred).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }
}
