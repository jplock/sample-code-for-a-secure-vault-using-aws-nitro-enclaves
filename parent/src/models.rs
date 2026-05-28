// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Data models and validation for parent vault requests and responses.
//!
//! This module defines the core data structures used for:
//! - Enclave management (describe, run, terminate)
//! - Decrypt request/response handling
//! - AWS credential passing
//!
//! All request types implement validation via the [`validator`] crate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;
use vault_protocol::EncryptedField;

use crate::constants::{
    MAX_ENCODING_LENGTH, MAX_ENCRYPTED_KEY_BYTES, MAX_ENCRYPTED_KEY_LENGTH, MAX_EXPRESSIONS_COUNT,
    MAX_FIELDS_COUNT, MAX_REGION_LENGTH, MAX_SUITE_ID_BYTES, MAX_SUITE_ID_LENGTH,
    MAX_VAULT_ID_LENGTH,
};

/// The information to be provided for a `describe-enclaves` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveDescribeInfo {
    /// Enclave name assigned by the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    pub enclave_name: Option<String>,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "ProcessID")]
    /// The PID of the enclave process which manages the enclave.
    pub process_id: u32,
    #[serde(rename = "EnclaveCID")]
    /// The enclave's CID.
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    /// The number of CPUs used by the enclave.
    pub cpu_count: u64,
    #[serde(rename = "CPUIDs")]
    /// The IDs of the CPUs used by the enclave.
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    /// The memory provided to the enclave (in MiB).
    pub memory_mib: u64,
    #[serde(rename = "State")]
    /// The current state of the enclave.
    pub state: String,
    #[serde(rename = "Flags")]
    /// The bit-mask which provides the enclave's launch flags.
    pub flags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    /// Build measurements containing PCRs
    pub build_info: Option<EnclaveBuildInfo>,
    /// Assigned or default EIF name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ImageName")]
    pub img_name: Option<String>,
    #[serde(rename = "ImageVersion")]
    /// Assigned or default EIF version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_version: Option<String>,
}

/// The information to be provided for a `run-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveRunInfo {
    #[serde(rename = "EnclaveName")]
    /// The name of the enclave.
    pub enclave_name: String,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "ProcessID")]
    /// The PID of the enclave process which manages the enclave.
    pub process_id: u32,
    #[serde(rename = "EnclaveCID")]
    /// The enclave's CID.
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    /// The number of CPUs used by the enclave.
    pub cpu_count: usize,
    #[serde(rename = "CPUIDs")]
    /// The IDs of the CPUs used by the enclave.
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    /// The memory provided to the enclave (in MiB).
    pub memory_mib: u64,
}

/// The information to be provided for a `terminate-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveTerminateInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    /// The name of the enclave. Optional for older versions.
    pub enclave_name: Option<String>,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "Terminated")]
    /// A flag indicating if the enclave has terminated.
    pub terminated: bool,
}

/// The information to be provided for a `build-enclave` request.
#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct EnclaveBuildInfo {
    #[serde(rename = "Measurements")]
    /// The measurement results (hashes) of various enclave properties.
    pub measurements: BTreeMap<String, String>,
}

// AWS credentials flow through the parent as `aws_credential_types::Credentials`
// directly — see `crate::imds::CredentialCache`. The parent runs on a trusted EC2
// host with filesystem access, so the wrapper that previously added Debug-
// redaction and ZeroizeOnDrop here didn't materially raise the bar. At the vsock
// boundary, `crate::routes::decrypt` builds a `vault_protocol::Credential` (which
// IS non-Clone + ZeroizeOnDrop) from the SDK type before forwarding.

/// Decrypt request received from the API tier.
///
/// This struct contains all information needed to decrypt vault data:
/// - Vault identification and region
/// - Encrypted data fields
/// - HPKE cryptographic parameters
/// - Optional CEL transformation expressions
///
/// All fields are validated according to size limits defined in [`crate::constants`].
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ParentRequest {
    /// Unique identifier for the vault (1-256 characters).
    #[validate(length(min = 1, max = "MAX_VAULT_ID_LENGTH"))]
    pub vault_id: String,

    /// AWS region where the KMS key resides (e.g., "us-east-1").
    #[validate(length(min = 1, max = "MAX_REGION_LENGTH"))]
    #[validate(custom(function = "validate_aws_region"))]
    pub region: String,

    /// Map of field names to encrypted values (max 100 fields).
    #[validate(custom(function = "validate_fields_count"))]
    pub fields: BTreeMap<String, String>,

    /// HPKE suite identifier, base64 encoded.
    #[validate(length(min = 1, max = "MAX_SUITE_ID_LENGTH"))]
    pub suite_id: String,

    /// HPKE encrypted private key, base64 encoded.
    #[validate(length(min = 1, max = "MAX_ENCRYPTED_KEY_LENGTH"))]
    pub encrypted_private_key: String,

    /// Optional CEL expressions for transforming decrypted values (max 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_expressions_count"))]
    pub expressions: Option<BTreeMap<String, String>>,

    /// Optional encoding for the decrypted values (e.g., "utf-8").
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = "MAX_ENCODING_LENGTH"))]
    pub encoding: Option<String>,
}

/// CBOR-shaped decrypt request received from the API tier.
///
/// Same semantics as [`ParentRequest`], but everything that was
/// base64/hex-encoded for the JSON wire travels as raw bytes here. The
/// per-field shape matches [`vault_protocol::EncryptedField`] exactly,
/// so translation to the enclave wire format is essentially a move.
///
/// There is no `encoding` selector — CBOR always carries raw bytes,
/// and the API decodes any legacy `_v = 1` (hex) DynamoDB records into
/// the same `(encapped_key, ciphertext)` byte tuple before sending.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ParentRequestCbor {
    #[validate(length(min = 1, max = "MAX_VAULT_ID_LENGTH"))]
    pub vault_id: String,

    #[validate(length(min = 1, max = "MAX_REGION_LENGTH"))]
    #[validate(custom(function = "validate_aws_region"))]
    pub region: String,

    /// Map of field names to typed encrypted values (max 100 fields).
    #[validate(custom(function = "validate_typed_fields_count"))]
    pub fields: BTreeMap<String, EncryptedField>,

    /// HPKE suite identifier, raw 10 bytes. `serde_bytes` ensures CBOR
    /// decodes the wire `bstr` (what Python's `cbor2.dumps(bytes(...))`
    /// emits) rather than expecting an array of small ints.
    #[serde(with = "serde_bytes")]
    #[validate(length(min = 1, max = "MAX_SUITE_ID_BYTES"))]
    pub suite_id: Vec<u8>,

    /// KMS-encrypted HPKE private key, raw bytes. Same `serde_bytes`
    /// rationale as `suite_id`.
    #[serde(with = "serde_bytes")]
    #[validate(length(min = 1, max = "MAX_ENCRYPTED_KEY_BYTES"))]
    pub encrypted_private_key: Vec<u8>,

    /// Optional CEL expressions for transforming decrypted values (max 100).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_expressions_count"))]
    pub expressions: Option<BTreeMap<String, String>>,
}

/// Validates AWS region format.
///
/// Valid format: `{continent}-{direction}-{number}` where:
/// - continent: exactly 2 lowercase letters (e.g., "us", "eu", "ap")
/// - direction: one or more lowercase letter parts separated by hyphens (e.g., "east", "southeast")
/// - number: one or more digits (e.g., "1", "2")
///
/// # Examples
///
/// Valid: "us-east-1", "eu-west-2", "ap-southeast-1", "me-south-1"
/// Invalid: "US-EAST-1", "useast1", "us-east"
fn validate_aws_region(region: &str) -> Result<(), validator::ValidationError> {
    let parts: Vec<&str> = region.split('-').collect();
    if parts.len() < 3 {
        return Err(validator::ValidationError::new("invalid_aws_region"));
    }

    // First part: exactly 2 lowercase letters (e.g., "us", "eu", "ap")
    let first = parts
        .first()
        .ok_or_else(|| validator::ValidationError::new("invalid_aws_region"))?;
    if first.len() != 2 || !first.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(validator::ValidationError::new("invalid_aws_region"));
    }

    // Middle parts: lowercase letters (e.g., "east", "west", "southeast")
    // Safe slice: we know parts.len() >= 3, so indices 1..parts.len()-1 are valid
    let middle_parts = parts
        .get(1..parts.len().saturating_sub(1))
        .ok_or_else(|| validator::ValidationError::new("invalid_aws_region"))?;
    for part in middle_parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(validator::ValidationError::new("invalid_aws_region"));
        }
    }

    // Last part: digits (e.g., "1", "2")
    let last = parts
        .last()
        .ok_or_else(|| validator::ValidationError::new("invalid_aws_region"))?;
    if last.is_empty() || !last.chars().all(|c| c.is_ascii_digit()) {
        return Err(validator::ValidationError::new("invalid_aws_region"));
    }

    Ok(())
}

/// Validates that the fields map doesn't exceed [`MAX_FIELDS_COUNT`].
fn validate_fields_count(
    fields: &BTreeMap<String, String>,
) -> Result<(), validator::ValidationError> {
    if fields.len() > MAX_FIELDS_COUNT {
        return Err(validator::ValidationError::new("too_many_fields"));
    }
    Ok(())
}

/// Validates that the typed fields map doesn't exceed [`MAX_FIELDS_COUNT`].
fn validate_typed_fields_count(
    fields: &BTreeMap<String, EncryptedField>,
) -> Result<(), validator::ValidationError> {
    if fields.len() > MAX_FIELDS_COUNT {
        return Err(validator::ValidationError::new("too_many_fields"));
    }
    Ok(())
}

/// Validates that the expressions map doesn't exceed [`MAX_EXPRESSIONS_COUNT`].
fn validate_expressions_count(
    expressions: &BTreeMap<String, String>,
) -> Result<(), validator::ValidationError> {
    if expressions.len() > MAX_EXPRESSIONS_COUNT {
        return Err(validator::ValidationError::new("too_many_expressions"));
    }
    Ok(())
}

/// Response returned to the API tier after decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentResponse {
    /// Map of field names to decrypted values.
    pub fields: BTreeMap<String, Value>,

    /// Optional list of errors encountered during decryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

// The enclave-bound wire types (`EnclaveRequest`, `EnclaveResponse`)
// now live in the `vault_protocol` workspace crate so they cannot drift
// between the parent and the enclave. The parent assembles a
// `vault_protocol::EnclaveRequest` via `crate::wire_encoding::build_enclave_request`
// when forwarding an API request to the enclave.

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests use unwrap for terseness")]
mod tests {
    use super::*;

    // Helper to create a valid ParentRequest for testing
    fn valid_parent_request() -> ParentRequest {
        let mut fields = BTreeMap::new();
        fields.insert("ssn".to_string(), "encrypted_value".to_string());

        ParentRequest {
            vault_id: "v_test_123".to_string(),
            region: "us-east-1".to_string(),
            fields,
            suite_id: "base64_suite_id".to_string(),
            encrypted_private_key: "base64_key".to_string(),
            expressions: None,
            encoding: None,
        }
    }

    // ==================== AWS Region Validation Tests ====================

    #[test]
    fn test_validate_aws_region_us_east_1() {
        assert!(validate_aws_region("us-east-1").is_ok());
    }

    #[test]
    fn test_validate_aws_region_us_west_2() {
        assert!(validate_aws_region("us-west-2").is_ok());
    }

    #[test]
    fn test_validate_aws_region_eu_west_1() {
        assert!(validate_aws_region("eu-west-1").is_ok());
    }

    #[test]
    fn test_validate_aws_region_ap_southeast_1() {
        assert!(validate_aws_region("ap-southeast-1").is_ok());
    }

    #[test]
    fn test_validate_aws_region_ap_northeast_2() {
        assert!(validate_aws_region("ap-northeast-2").is_ok());
    }

    #[test]
    fn test_validate_aws_region_me_south_1() {
        assert!(validate_aws_region("me-south-1").is_ok());
    }

    #[test]
    fn test_validate_aws_region_sa_east_1() {
        assert!(validate_aws_region("sa-east-1").is_ok());
    }

    #[test]
    fn test_validate_aws_region_invalid_uppercase() {
        assert!(validate_aws_region("US-EAST-1").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_no_hyphens() {
        assert!(validate_aws_region("useast1").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_missing_number() {
        assert!(validate_aws_region("us-east").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_three_letter_continent() {
        assert!(validate_aws_region("usa-east-1").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_single_letter_continent() {
        assert!(validate_aws_region("u-east-1").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_number_in_direction() {
        assert!(validate_aws_region("us-east1-1").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_empty() {
        assert!(validate_aws_region("").is_err());
    }

    #[test]
    fn test_validate_aws_region_invalid_just_hyphens() {
        assert!(validate_aws_region("--").is_err());
    }

    // ==================== Fields Count Validation Tests ====================

    #[test]
    fn test_validate_fields_count_empty() {
        let fields = BTreeMap::new();
        assert!(validate_fields_count(&fields).is_ok());
    }

    #[test]
    fn test_validate_fields_count_at_max() {
        let mut fields = BTreeMap::new();
        for i in 0..MAX_FIELDS_COUNT {
            fields.insert(format!("field_{}", i), "value".to_string());
        }
        assert!(validate_fields_count(&fields).is_ok());
    }

    #[test]
    fn test_validate_fields_count_exceeds_max() {
        let mut fields = BTreeMap::new();
        for i in 0..=MAX_FIELDS_COUNT {
            fields.insert(format!("field_{}", i), "value".to_string());
        }
        assert!(validate_fields_count(&fields).is_err());
    }

    // ==================== Expressions Count Validation Tests ====================

    #[test]
    fn test_validate_expressions_count_empty() {
        let expressions = BTreeMap::new();
        assert!(validate_expressions_count(&expressions).is_ok());
    }

    #[test]
    fn test_validate_expressions_count_at_max() {
        let mut expressions = BTreeMap::new();
        for i in 0..MAX_EXPRESSIONS_COUNT {
            expressions.insert(format!("expr_{}", i), "cel_expr".to_string());
        }
        assert!(validate_expressions_count(&expressions).is_ok());
    }

    #[test]
    fn test_validate_expressions_count_exceeds_max() {
        let mut expressions = BTreeMap::new();
        for i in 0..=MAX_EXPRESSIONS_COUNT {
            expressions.insert(format!("expr_{}", i), "cel_expr".to_string());
        }
        assert!(validate_expressions_count(&expressions).is_err());
    }

    // ==================== ParentRequest Validation Tests ====================

    #[test]
    fn test_parent_request_valid() {
        let request = valid_parent_request();
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_parent_request_empty_vault_id() {
        let mut request = valid_parent_request();
        request.vault_id = "".to_string();
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_parent_request_vault_id_too_long() {
        let mut request = valid_parent_request();
        request.vault_id = "x".repeat(MAX_VAULT_ID_LENGTH as usize + 1);
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_parent_request_invalid_region() {
        let mut request = valid_parent_request();
        request.region = "invalid".to_string();
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_parent_request_empty_suite_id() {
        let mut request = valid_parent_request();
        request.suite_id = "".to_string();
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_parent_request_empty_encrypted_key() {
        let mut request = valid_parent_request();
        request.encrypted_private_key = "".to_string();
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_parent_request_with_expressions() {
        let mut request = valid_parent_request();
        let mut expressions = BTreeMap::new();
        expressions.insert("ssn".to_string(), "mask(value, 4)".to_string());
        request.expressions = Some(expressions);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_parent_request_with_encoding() {
        let mut request = valid_parent_request();
        request.encoding = Some("utf-8".to_string());
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_parent_request_encoding_too_long() {
        let mut request = valid_parent_request();
        request.encoding = Some("x".repeat(MAX_ENCODING_LENGTH as usize + 1));
        assert!(request.validate().is_err());
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_parent_response_serialize_with_errors() {
        let response = ParentResponse {
            fields: BTreeMap::new(),
            errors: Some(vec!["error1".to_string(), "error2".to_string()]),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("errors"));
        assert!(json.contains("error1"));
    }

    #[test]
    fn test_parent_response_serialize_without_errors() {
        let response = ParentResponse {
            fields: BTreeMap::new(),
            errors: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("errors"));
    }

    #[test]
    fn test_enclave_describe_info_deserialize() {
        let json = r#"{
            "EnclaveName": "enclave-vault-1",
            "EnclaveID": "i-1234567890",
            "ProcessID": 1234,
            "EnclaveCID": 16,
            "NumberOfCPUs": 2,
            "CPUIDs": [0, 1],
            "MemoryMiB": 512,
            "State": "RUNNING",
            "Flags": "NONE"
        }"#;
        let info: EnclaveDescribeInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.enclave_name, Some("enclave-vault-1".to_string()));
        assert_eq!(info.enclave_cid, 16);
        assert_eq!(info.state, "RUNNING");
    }

    #[test]
    fn test_enclave_run_info_deserialize() {
        let json = r#"{
            "EnclaveName": "enclave-vault-1",
            "EnclaveID": "i-1234567890",
            "ProcessID": 1234,
            "EnclaveCID": 16,
            "NumberOfCPUs": 2,
            "CPUIDs": [0, 1],
            "MemoryMiB": 512
        }"#;
        let info: EnclaveRunInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.enclave_name, "enclave-vault-1");
        assert_eq!(info.cpu_count, 2);
    }

    #[test]
    fn test_parent_request_deserialization() {
        let json = r#"{
            "vault_id": "v_123",
            "region": "us-east-1",
            "fields": {"ssn": "encrypted"},
            "suite_id": "suite",
            "encrypted_private_key": "key"
        }"#;
        let request: ParentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.vault_id, "v_123");
        assert_eq!(request.region, "us-east-1");
    }
}
