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
use crate::cbor::{CBOR_CONTENT_TYPE, Cbor};
use crate::constants;
use crate::errors::AppError;
use crate::models::{
    EnclaveDescribeInfo, EnclaveRunInfo, ParentRequest, ParentRequestCbor, ParentResponse,
};
use crate::wire_encoding::{build_enclave_request, build_enclave_request_cbor};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use validator::Validate;
use vault_protocol::{Credential as WireCredential, EnclaveRequest, EnclaveResponse};

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

/// Returns true when the request's `Content-Type` header indicates a
/// CBOR body. Anything else (including absent header) falls through to
/// the JSON path.
fn is_cbor_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| {
            // Tolerate parameters like `application/cbor; charset=binary`.
            let media_type = s.split(';').next().unwrap_or(s).trim();
            media_type.eq_ignore_ascii_case(CBOR_CONTENT_TYPE)
        })
}

/// Returns true when the request's `Accept` header explicitly asks for
/// CBOR. `*/*` and missing fall through to the JSON default so existing
/// clients keep getting JSON back.
fn wants_cbor_response(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| {
            s.split(',').any(|part| {
                let media_type = part.split(';').next().unwrap_or(part).trim();
                media_type.eq_ignore_ascii_case(CBOR_CONTENT_TYPE)
            })
        })
}

/// Holds a deserialized request body in whichever shape arrived on the
/// wire. Both shapes carry equivalent data; only the translation to
/// `vault_protocol::EnclaveRequest` differs.
enum ParsedBody {
    Json(ParentRequest),
    Cbor(ParentRequestCbor),
}

impl ParsedBody {
    fn vault_id(&self) -> &str {
        match self {
            Self::Json(p) => &p.vault_id,
            Self::Cbor(p) => &p.vault_id,
        }
    }

    fn into_enclave_request(self, credential: WireCredential) -> anyhow::Result<EnclaveRequest> {
        match self {
            Self::Json(p) => build_enclave_request(p, credential),
            Self::Cbor(p) => build_enclave_request_cbor(p, credential),
        }
    }
}

/// Decrypts vault fields using a Nitro Enclave.
///
/// Main endpoint for decrypting PII/PHI data stored in the vault. The
/// handler dispatches on the request `Content-Type` to decode the body
/// (JSON or CBOR), runs the shared validate → credentials → enclave →
/// vsock pipeline, then serializes the response in whichever format
/// the client's `Accept` header asks for (defaulting to JSON).
///
/// # Content negotiation
///
/// | request `Content-Type` | request `Accept` | wire shape in / out |
/// |---|---|---|
/// | `application/cbor`     | contains `application/cbor` | CBOR / CBOR |
/// | `application/cbor`     | other / missing             | CBOR / JSON |
/// | other / missing        | contains `application/cbor` | JSON / CBOR |
/// | other / missing        | other / missing             | JSON / JSON |
///
/// # Errors
///
/// - [`AppError::ValidationError`] - body parse, validation, or translation failure
/// - [`AppError::EnclaveNotFound`] - no enclaves available
/// - [`AppError::InternalServerError`] - credential or enclave communication failure
#[tracing::instrument(skip(state, req))]
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response, AppError> {
    let (parts, body) = req.into_parts();
    let cbor_in = is_cbor_content_type(&parts.headers);
    let cbor_out = wants_cbor_response(&parts.headers);

    // Read the body once. tower-http's RequestBodyLimitLayer already
    // caps payload size, and `Bytes::from_request` surfaces a `413
    // Payload Too Large` rejection if the cap is hit. We pass that
    // rejection through unchanged so the size-limit response shape
    // stays exactly as it did before this handler was rewritten for
    // content negotiation.
    let req = Request::from_parts(parts, body);
    let body_bytes = match Bytes::from_request(req, &()).await {
        Ok(b) => b,
        Err(rejection) => {
            tracing::error!("[parent] failed to read request body: {:?}", rejection);
            return Ok(rejection.into_response());
        }
    };

    // 1. Deserialize + validate, path-specific. We keep the parsed
    // value through the next few steps so the translator runs once the
    // wire credential is in hand.
    let parsed: ParsedBody = if cbor_in {
        let p: ParentRequestCbor = ciborium::de::from_reader(&*body_bytes).map_err(|e| {
            tracing::error!("[parent] CBOR deserialization failed: {:?}", e);
            AppError::ValidationError(format!("invalid CBOR body: {e}"))
        })?;
        tracing::debug!(
            "[parent] validating CBOR decrypt request for vault_id: {}",
            p.vault_id
        );
        p.validate().map_err(|e| {
            tracing::error!("[parent] CBOR validation failed: {}", e);
            AppError::ValidationError(e.to_string())
        })?;
        ParsedBody::Cbor(p)
    } else {
        let p: ParentRequest = serde_json::from_slice(&body_bytes).map_err(|e| {
            tracing::error!("[parent] JSON deserialization failed: {:?}", e);
            AppError::ValidationError(format!("invalid JSON body: {e}"))
        })?;
        tracing::debug!(
            "[parent] validating JSON decrypt request for vault_id: {}",
            p.vault_id
        );
        p.validate().map_err(|e| {
            tracing::error!("[parent] JSON validation failed: {}", e);
            AppError::ValidationError(e.to_string())
        })?;
        ParsedBody::Json(p)
    };

    // 2. Get available enclaves early to fail fast if none are available
    let enclaves: Vec<EnclaveDescribeInfo> = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    // 3. Fetch (or use cached) IAM credentials from IMDS
    tracing::debug!(
        "[parent] fetching credentials for vault_id: {}",
        parsed.vault_id()
    );
    let credential = state.credentials.get_credentials().await.map_err(|e| {
        tracing::error!("[parent] failed to get credentials: {:?}", e);
        e
    })?;

    // Translate the SDK `Credentials` into the wire crate's typed,
    // zeroize-on-drop `Credential` (orphan rules prevent an `impl From`
    // here), then build the binary EnclaveRequest. Whichever path the
    // body arrived on, the resulting `EnclaveRequest` is identical.
    let wire_credential = WireCredential::new(
        credential.access_key_id().to_string(),
        credential.secret_access_key().to_string(),
        credential.session_token().unwrap_or_default().to_string(),
    );
    let enclave_req = parsed.into_enclave_request(wire_credential).map_err(|e| {
        tracing::error!(
            "[parent] failed to translate request to wire format: {:?}",
            e
        );
        AppError::ValidationError(e.to_string())
    })?;

    // 4. Select a random enclave for load balancing
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

    // 6. Transform enclave response to parent response format. The
    // enclave returns a HashMap (no ordering guarantee); the API
    // returns a BTreeMap so output is deterministic for clients.
    let parent_response = ParentResponse {
        fields: response.fields.unwrap_or_default().into_iter().collect(),
        errors: response.errors,
    };

    // 7. Serialize in whichever format the client asked for.
    if cbor_out {
        Ok(Cbor(parent_response).into_response())
    } else {
        Ok(Json(parent_response).into_response())
    }
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
}
