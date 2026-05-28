// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! HPKE decryption module for the Nitro Enclave.
//!
//! Decrypts individual field values using HPKE via the rustls crypto
//! backend (aws-lc-rs). Operates on [`vault_protocol::EncryptedField`]
//! values, which carry the encapsulated key and ciphertext as raw bytes
//! (any base64/hex transport encoding is unwound by the parent before
//! the field crosses the vsock).
//!
//! # Supported Cipher Suites
//!
//! - P-256 with HKDF-SHA256 and AES-256-GCM
//! - P-384 with HKDF-SHA384 and AES-256-GCM
//! - P-521 with HKDF-SHA512 and AES-256-GCM
//!
//! # Security
//!
//! The decryption uses the field name (lowercased) as Additional
//! Authenticated Data (AAD) and the vault ID as the info parameter,
//! binding the ciphertext to its intended context.

use anyhow::{Result, anyhow};
use rustls::crypto::hpke::{EncapsulatedSecret, Hpke, HpkePrivateKey};
use serde_json::Value;
use vault_protocol::EncryptedField;
use zeroize::Zeroizing;

/// Decrypts an HPKE-encrypted field value.
///
/// # Errors
///
/// - HPKE decryption fails (wrong key, corrupted data, AAD mismatch)
/// - The decrypted bytes are not valid UTF-8
pub fn decrypt_value(
    suite: &dyn Hpke,
    private_key: &HpkePrivateKey,
    info: &[u8],
    field: &str,
    encrypted_field: &EncryptedField,
) -> Result<Value> {
    let aad = field.to_lowercase();

    // EncapsulatedSecret needs ownership of the bytes. The shared crate
    // hands us a borrow; clone the few-byte encapped key for the call.
    let enc = EncapsulatedSecret(encrypted_field.encapped_key.clone());

    // Wrap plaintext bytes immediately so they zeroize on drop regardless
    // of the UTF-8 conversion outcome. The resulting `String` is not
    // zeroized (accepted scope), but this closes the larger window of the
    // raw `Vec<u8>` surviving on the heap.
    let plaintext_value: Zeroizing<Vec<u8>> = Zeroizing::new(
        suite
            .open(
                &enc,
                info,
                aad.as_bytes(),
                &encrypted_field.ciphertext,
                private_key,
            )
            .map_err(|err| anyhow!("[{}] unable to decrypt data: {:?}", aad, err))?,
    );

    let string_value = std::str::from_utf8(&plaintext_value)
        .map_err(|err| {
            anyhow!(
                "[{}] unable to convert plaintext data to string: {:?}",
                aad,
                err
            )
        })?
        .to_owned();

    Ok(Value::String(string_value))
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
    use crate::models::SuiteExt;
    use crate::utils::base64_decode;
    use aws_lc_rs::{encoding::AsBigEndian, signature::EcdsaKeyPair};
    use data_encoding::HEXLOWER;
    use serde_json::json;
    use vault_protocol::Suite;

    #[test]
    fn test_decrypt_value() {
        let vault_id = "v_2hRK9u2DOzmAPMhdVNt9qlJ3UvL";
        let suite = Suite::P384;

        let b64_sk = "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCt+Ad+qIiVIK4e/tj6u+boZ63IAgT2ZttR14ZGjL3XLjNC//WNJcFyNSOGDt2kNE+gBwYFK4EEACKhZANiAASMfDcAvCD3J8in7EzaM6hNvkQD+S6C0H2hI7biRlkHMXcIjZ/7LVNQ2+VMlFAWV8ESbahT0wKiYLNreDvPIDFJOZyzfURR/HTRtf5Vd+aEjXl9EI7XxRu6OILEfQC9afg=";
        let der_sk = base64_decode(b64_sk).unwrap();

        let algo = suite.signing_algorithm();
        let sk = EcdsaKeyPair::from_private_key_der(algo, &der_sk).unwrap();
        let sk_bytes = sk.private_key().as_be_bytes().unwrap();
        let sk_ref = sk_bytes.as_ref();
        let secret_key: HpkePrivateKey = sk_ref.to_vec().into();

        // Same encrypted blob as before; just split into raw bytes the way
        // the parent now does at the API boundary.
        let encapped_key = HEXLOWER
            .decode(b"04cebfe3667db3305777774f14a7ed4f26ce90b2d68935a30f9b086dc915e6ede23e6dfdde7aaf34dc34cd964c76f94bc91ba99edb3707281862c990c54782eace8c687770d72d4c714d4edd239e010facfb7c3d5c168b14d9040194059529f5e6")
            .unwrap();
        let ciphertext = HEXLOWER
            .decode(b"80c10441ae55442775bc5d1b0b8465eaaaa33b")
            .unwrap();
        let encrypted_field = EncryptedField {
            encapped_key,
            ciphertext,
        };

        let hpke_suite = suite.hpke();
        let info = vault_id.as_bytes();
        let field = "first_name";

        let expected = json!("Bob");

        let actual = decrypt_value(hpke_suite, &secret_key, info, field, &encrypted_field).unwrap();

        assert_eq!(actual, expected);
    }
}
