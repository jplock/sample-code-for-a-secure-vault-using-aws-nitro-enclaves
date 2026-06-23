// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! HTTP route handlers for the parent vault API.
//!
//! This module provides the following endpoints:
//!
//! | Method | Path | Handler | Description |
//! |--------|------|---------|-------------|
//! | GET | `/health` | [`health`] | Health check endpoint |
//! | GET | `/enclaves` | [`get_enclaves`] | List running enclaves |
//! | POST | `/decrypt` | [`decrypt`] | Decrypt vault fields |
//!
//! Additional endpoints (currently disabled):
//! - POST `/enclaves` - Launch a new enclave
//! - GET `/creds` - Get current IAM credentials

use std::sync::Arc;

use crate::application::AppState;
use crate::cbor::Cbor;
use crate::constants;
use crate::errors::AppError;
use crate::models::{EnclaveDescribeInfo, EnclaveRunInfo, ParentRequest, ParentResponse};
use crate::wire_encoding::build_enclave_request;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;
use validator::Validate;
use vault_protocol::{Credential as WireCredential, EnclaveResponse};

/// Health check endpoint.
///
/// Returns a simple JSON response indicating the service is running.
///
/// # Response
///
/// ```json
/// {"status": "ok"}
/// ```
pub async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

/// Lists all running Nitro Enclaves.
///
/// Returns information about all enclaves that match the vault prefix.
///
/// # Response
///
/// A JSON array of [`EnclaveDescribeInfo`] objects.
#[tracing::instrument(skip(state))]
pub async fn get_enclaves(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<EnclaveDescribeInfo>>, AppError> {
    let enclaves = state.enclaves.get_enclaves().await;

    Ok(Json(enclaves))
}

/// Launches a new Nitro Enclave.
///
/// This endpoint is currently disabled in the router configuration.
///
/// # Response
///
/// Returns [`EnclaveRunInfo`] on success.
#[tracing::instrument(skip(state))]
pub async fn run_enclave(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EnclaveRunInfo>, AppError> {
    let run_info = state.enclaves.run_enclave().await?;

    Ok(Json(run_info))
}

// The `/creds` route handler that previously returned IAM credentials
// as JSON has been removed. It was always disabled at the router and
// `aws_credential_types::Credentials` (the SDK type we now hold) does
// not implement `Serialize`, which is appropriate — credentials should
// not be observable from outside this process.

/// Decrypts vault fields using a Nitro Enclave.
///
/// Main endpoint for decrypting PII/PHI data stored in the vault. The
/// request/response wire format is CBOR (`application/cbor`); the API
/// Lambda is the only client and always sends CBOR. JSON support was
/// removed once the API → parent leg fully migrated.
///
/// # Request flow
///
/// 1. Validate the deserialized [`ParentRequest`].
/// 2. Check for available enclaves (fail fast on none).
/// 3. Fetch IAM credentials from the IMDS cache.
/// 4. Build the binary `EnclaveRequest` via
///    [`build_enclave_request`].
/// 5. Pick a random enclave for load balancing.
/// 6. Send over vsock (blocking call wrapped in `spawn_blocking`).
/// 7. Return the response as CBOR.
///
/// # Errors
///
/// - [`AppError::ValidationError`] — request validation or translation failure
/// - [`AppError::EnclaveNotFound`] — no enclaves available
/// - [`AppError::InternalServerError`] — credential or enclave communication failure
/// - [`AppError::DecryptError`] — enclave signalled a total decrypt failure
#[tracing::instrument(skip(state, request))]
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    Cbor(request): Cbor<ParentRequest>,
) -> Result<Cbor<ParentResponse>, AppError> {
    // 1. Validate incoming request against size limits and format rules.
    tracing::debug!(
        "[parent] validating decrypt request for vault_id: {}",
        request.vault_id
    );
    request.validate().map_err(|e| {
        tracing::error!("[parent] validation failed: {}", e);
        AppError::ValidationError(e.to_string())
    })?;

    // 2. Get available enclaves early to fail fast if none are available.
    let enclaves: Vec<EnclaveDescribeInfo> = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    // 3. Fetch (or use cached) IAM credentials from IMDS.
    tracing::debug!("[parent] fetching credentials from cache");
    let credential = state.credentials.get_credentials().await.map_err(|e| {
        tracing::error!("[parent] failed to get credentials: {:?}", e);
        e
    })?;

    // Translate the SDK `Credentials` into the wire crate's typed,
    // zeroize-on-drop `Credential` (orphan rules prevent an `impl From`
    // here), then build the binary EnclaveRequest.
    let wire_credential = WireCredential::new(
        credential.access_key_id().to_string(),
        credential.secret_access_key().to_string(),
        credential.session_token().unwrap_or_default().to_string(),
    );
    let enclave_req = build_enclave_request(request, wire_credential).map_err(|e| {
        tracing::error!(
            "[parent] failed to translate request to wire format: {:?}",
            e
        );
        AppError::ValidationError(e.to_string())
    })?;

    // 4. Select a random enclave for load balancing.
    let index = fastrand::usize(..enclaves.len());
    let enclave = enclaves.get(index).ok_or(AppError::EnclaveNotFound)?;
    let cid: u32 = enclave
        .enclave_cid
        .try_into()
        .map_err(|_| AppError::InternalServerError)?;

    tracing::debug!("[parent] sending decrypt request to CID: {:?}", cid);

    // 5. Send request to enclave via vsock (blocking operation).
    // spawn_blocking is used because vsock I/O is synchronous.
    let enclaves_ref = state.enclaves.clone();
    let port = constants::ENCLAVE_PORT;
    let response: EnclaveResponse =
        tokio::task::spawn_blocking(move || enclaves_ref.decrypt(cid, port, enclave_req))
            .await
            .map_err(|e| {
                tracing::error!("[parent] spawn_blocking task failed: {:?}", e);
                AppError::InternalServerError
            })?
            .map_err(|e| {
                tracing::error!("[parent] enclave decrypt failed: {:?}", e);
                e
            })?;

    tracing::debug!("[parent] received response from CID: {:?}", cid);

    // 6. Transform enclave response to parent response format, surfacing a
    // total-failure signal as an error rather than an empty 200.
    let parent_response = build_parent_response(response)?;

    Ok(Cbor(parent_response))
}

/// Transforms an [`EnclaveResponse`] into a [`ParentResponse`].
///
/// `fields: None` is the enclave's total-failure signal — it could not process
/// the request at all (parse error, or KMS failure before any field was
/// attempted). Surfacing that as [`AppError::DecryptError`] (HTTP 500) keeps the
/// API from recording a `VaultDecrypt` success on a complete failure.
/// `fields: Some(map)` is a processed (possibly partial) decrypt and stays a
/// `200` response — per-field failures ride along in `errors`.
///
/// The enclave returns a `HashMap` (no ordering guarantee); the API returns a
/// `BTreeMap` so output is deterministic for clients.
fn build_parent_response(response: EnclaveResponse) -> Result<ParentResponse, AppError> {
    let Some(fields) = response.fields else {
        tracing::error!(
            "[parent] enclave signalled total decrypt failure: {:?}",
            response.errors
        );
        return Err(AppError::DecryptError);
    };

    Ok(ParentResponse {
        fields: fields.into_iter().collect(),
        errors: response.errors,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests use unwrap/indexing for terseness"
)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use std::collections::HashMap;

    // Unit tests for route handlers (testing handler functions directly)
    // Integration tests using TestServer are in tests/http_integration.rs

    #[tokio::test]
    async fn test_health_returns_ok() {
        let response = health().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_health_response_structure() {
        let response = health().await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should have exactly one key
        assert_eq!(json.as_object().unwrap().len(), 1);
        assert!(json.get("status").is_some());
    }

    #[test]
    fn test_build_parent_response_total_failure_is_decrypt_error() {
        // fields: None is the enclave's total-failure signal (bug #38): it
        // must surface as DecryptError (HTTP 500), not a flattened empty 200.
        let response = EnclaveResponse::error_msg("kms access denied".to_string());
        assert_eq!(
            build_parent_response(response).unwrap_err(),
            AppError::DecryptError
        );
    }

    #[test]
    fn test_build_parent_response_success_preserves_fields() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), json!("alice"));
        fields.insert("ssn".to_string(), json!("123-45-6789"));
        let response = EnclaveResponse::new(fields, None);

        let parent = build_parent_response(response).unwrap();
        assert_eq!(parent.fields.get("name"), Some(&json!("alice")));
        assert_eq!(parent.fields.get("ssn"), Some(&json!("123-45-6789")));
        assert!(parent.errors.is_none());
    }

    #[test]
    fn test_build_parent_response_partial_failure_stays_ok() {
        // The request was processed (fields: Some) but every field failed:
        // empty map + errors. This is partial failure, not total, so it must
        // remain an Ok (HTTP 200) response with the errors preserved.
        let response =
            EnclaveResponse::new(HashMap::new(), Some(vec!["field x failed".to_string()]));

        let parent = build_parent_response(response).unwrap();
        assert!(parent.fields.is_empty());
        assert_eq!(parent.errors, Some(vec!["field x failed".to_string()]));
    }
}
