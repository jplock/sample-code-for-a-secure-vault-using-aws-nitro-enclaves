// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Enclave-side processing built on top of the wire types in
//! [`vault_protocol`].
//!
//! The wire definitions ([`vault_protocol::EnclaveRequest`],
//! [`vault_protocol::Suite`], [`vault_protocol::EncryptedField`], etc.)
//! are shared with the parent. This module adds the enclave-only
//! behavior on top:
//!
//! - [`SuiteExt`] — maps the wire `Suite` discriminant to the concrete
//!   `rustls::crypto::hpke::Hpke` impl and the matching
//!   `aws_lc_rs::signature::EcdsaSigningAlgorithm`.
//! - [`validate_request`] — sanity checks the request before any KMS or
//!   HPKE work is attempted.
//! - [`decrypt_fields`] — the parallel HPKE decrypt pipeline.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "enclave stdout/stderr is the only diagnostic channel in --debug-mode (visible via nitro-cli console); production stdout is discarded by design. See `.claude/memory/enclave-no-observability.md`."
)]

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Error, Result, bail};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING,
    EcdsaSigningAlgorithm,
};
use rayon::prelude::*;
use rustls::crypto::aws_lc_rs::hpke::{
    DH_KEM_P256_HKDF_SHA256_AES_256, DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P521_HKDF_SHA512_AES_256,
};
use rustls::crypto::hpke::Hpke;
use serde_json::Value;
use vault_protocol::{EnclaveRequest, EncryptedField, MAX_FIELD_CIPHERTEXT_SIZE, Suite};

use crate::constants::MAX_FIELDS;
use crate::hpke::decrypt_value;
use crate::kms::get_secret_key;

/// Enclave-only methods on the wire [`Suite`] discriminant. Lives here
/// rather than in `vault-protocol` because the mapping pulls in rustls
/// and aws-lc-rs, which the parent doesn't need to drag in.
pub trait SuiteExt {
    fn hpke(&self) -> &'static dyn Hpke;
    fn signing_algorithm(&self) -> &'static EcdsaSigningAlgorithm;
}

impl SuiteExt for Suite {
    fn hpke(&self) -> &'static dyn Hpke {
        match self {
            Suite::P256 => DH_KEM_P256_HKDF_SHA256_AES_256,
            Suite::P384 => DH_KEM_P384_HKDF_SHA384_AES_256,
            Suite::P521 => DH_KEM_P521_HKDF_SHA512_AES_256,
        }
    }

    fn signing_algorithm(&self) -> &'static EcdsaSigningAlgorithm {
        match self {
            Suite::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            Suite::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            Suite::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
        }
    }
}

/// Rejects requests whose field count exceeds the per-request maximum.
fn validate_field_count(count: usize) -> Result<()> {
    if count > MAX_FIELDS {
        bail!("field count {} exceeds maximum {}", count, MAX_FIELDS);
    }
    Ok(())
}

/// Rejects per-field ciphertext blobs whose decoded size exceeds the cap.
/// The parent enforces the same bound at the API boundary; this is the
/// enclave's defense-in-depth check.
fn validate_field_ciphertext(field: &str, ef: &EncryptedField) -> Result<()> {
    if ef.ciphertext.len() > MAX_FIELD_CIPHERTEXT_SIZE {
        bail!(
            "ciphertext for field '{}' size {} exceeds maximum {}",
            field,
            ef.ciphertext.len(),
            MAX_FIELD_CIPHERTEXT_SIZE
        );
    }
    Ok(())
}

/// Validates every aspect of an incoming request before any KMS or HPKE
/// work is performed. Returns an error suitable for the response
/// `errors[]` (callers should still sanitize via
/// [`crate::utils::sanitize_error_message`] before sending on the wire).
pub fn validate_request(req: &EnclaveRequest) -> Result<()> {
    if req.request.vault_id.is_empty() {
        bail!("vault_id cannot be empty");
    }
    if req.request.region.is_empty() {
        bail!("region cannot be empty");
    }
    if !req
        .request
        .region
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("region contains invalid characters");
    }
    if req.request.encrypted_private_key.is_empty() {
        bail!("encrypted_private_key cannot be empty");
    }
    validate_field_count(req.request.fields.len())?;
    for (field, ef) in &req.request.fields {
        validate_field_ciphertext(field, ef)?;
    }
    Ok(())
}

/// Decrypts every field in `req.request.fields` in parallel using HPKE.
/// Returns the decrypted values alongside any per-field errors. Hard
/// errors (KMS failure, invalid request) short-circuit and propagate.
pub fn decrypt_fields(req: &EnclaveRequest) -> Result<(HashMap<String, Value>, Vec<Error>)> {
    validate_request(req)?;

    let suite = req.request.suite;

    // Decrypt the KMS-encrypted private key; the wrapper zeroizes on drop.
    let secure_private_key = get_secret_key(suite.signing_algorithm(), req)?;
    println!("[enclave] decrypted KMS secret key");

    // Note: this creates a short-lived copy of the key bytes that rustls
    // won't zeroize. The secure wrapper still zeroizes its own copy on drop.
    let private_key = secure_private_key.as_hpke_private_key();

    let hpke_suite = suite.hpke();
    let info = req.request.vault_id.as_bytes();
    let errors: Mutex<Vec<Error>> = Mutex::new(Vec::new());

    // Sensitive context — debug builds only.
    #[cfg(debug_assertions)]
    {
        println!("[enclave] vault_id: {:?}", &req.request.vault_id);
    }

    let decrypted_fields: HashMap<String, Value> = req
        .request
        .fields
        .par_iter()
        .map(|(field, ef)| {
            let decrypted = decrypt_value(hpke_suite, &private_key, info, field, ef)
                .unwrap_or_else(|err| {
                    match errors.lock() {
                        Ok(mut err_vec) => err_vec.push(err),
                        Err(poisoned) => {
                            eprintln!(
                                "[enclave critical] mutex poisoned during decryption — a thread may have panicked"
                            );
                            poisoned.into_inner().push(err);
                        }
                    }
                    Value::Null
                });
            (field.clone(), decrypted)
        })
        .collect();

    let final_errors = match errors.into_inner() {
        Ok(errs) => errs,
        Err(poisoned) => {
            eprintln!(
                "[enclave critical] mutex poisoned during final error extraction — a thread may have panicked"
            );
            poisoned.into_inner()
        }
    };

    Ok((decrypted_fields, final_errors))
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

    #[test]
    fn validate_field_count_at_max_is_ok() {
        assert!(validate_field_count(MAX_FIELDS).is_ok());
    }

    #[test]
    fn validate_field_count_over_max_errors() {
        let result = validate_field_count(MAX_FIELDS + 1);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("field count"));
        assert!(msg.contains(&(MAX_FIELDS + 1).to_string()));
        assert!(msg.contains(&MAX_FIELDS.to_string()));
    }

    #[test]
    fn validate_field_count_zero_is_ok() {
        assert!(validate_field_count(0).is_ok());
    }

    #[test]
    fn validate_field_ciphertext_at_cap_is_ok() {
        let ef = EncryptedField {
            encapped_key: vec![0xAB; 97],
            ciphertext: vec![0xCD; MAX_FIELD_CIPHERTEXT_SIZE],
        };
        assert!(validate_field_ciphertext("ssn", &ef).is_ok());
    }

    #[test]
    fn validate_field_ciphertext_over_cap_errors() {
        let ef = EncryptedField {
            encapped_key: vec![0xAB; 97],
            ciphertext: vec![0xCD; MAX_FIELD_CIPHERTEXT_SIZE + 1],
        };
        let result = validate_field_ciphertext("ssn", &ef);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("ciphertext for field 'ssn'"));
        assert!(msg.contains("exceeds maximum"));
    }

    #[test]
    fn suite_ext_p256_hpke() {
        let hpke = Suite::P256.hpke();
        assert_eq!(hpke.suite(), DH_KEM_P256_HKDF_SHA256_AES_256.suite());
    }

    #[test]
    fn suite_ext_p384_hpke() {
        let hpke = Suite::P384.hpke();
        assert_eq!(hpke.suite(), DH_KEM_P384_HKDF_SHA384_AES_256.suite());
    }

    #[test]
    fn suite_ext_p521_hpke() {
        let hpke = Suite::P521.hpke();
        assert_eq!(hpke.suite(), DH_KEM_P521_HKDF_SHA512_AES_256.suite());
    }

    #[test]
    fn suite_ext_signing_algorithm_per_curve() {
        assert_eq!(
            Suite::P256.signing_algorithm(),
            &ECDSA_P256_SHA256_ASN1_SIGNING
        );
        assert_eq!(
            Suite::P384.signing_algorithm(),
            &ECDSA_P384_SHA384_ASN1_SIGNING
        );
        assert_eq!(
            Suite::P521.signing_algorithm(),
            &ECDSA_P521_SHA512_ASN1_SIGNING
        );
    }
}
