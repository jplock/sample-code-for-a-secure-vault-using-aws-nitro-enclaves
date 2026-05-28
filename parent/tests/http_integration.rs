// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! HTTP integration tests for the parent vault API.
//!
//! These tests use `axum-test` to test the full HTTP request/response cycle
//! through the Axum router with all middleware applied.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;

use axum::body::Bytes;
use axum_test::TestServer;
use parent_vault::application::create_router;
use parent_vault::configuration::ParentOptions;
use parent_vault::enclaves::Enclaves;

/// Creates a test server for HTTP integration testing.
///
/// Returns a configured `TestServer` with default options and no enclaves.
/// The server includes the same middleware as production (body limit, timeout).
fn create_test_server() -> TestServer {
    let options = ParentOptions::default();
    let enclaves = Arc::new(Enclaves::new());
    let app = create_router(options, enclaves);
    TestServer::new(app).unwrap()
}

/// Returns a valid decrypt request JSON for testing.
///
/// The returned JSON contains all required fields with valid values.
#[allow(
    dead_code,
    reason = "helper kept for future integration tests; not all tests in this file consume it"
)]
fn valid_decrypt_request() -> serde_json::Value {
    serde_json::json!({
        "vault_id": "v_test_123",
        "region": "us-east-1",
        "fields": {"ssn": "encrypted_value"},
        "suite_id": "base64_suite_id",
        "encrypted_private_key": "base64_key"
    })
}

// =============================================================================
// Health Endpoint Tests
// Requirements: 2.1, 2.2, 2.3
// =============================================================================

/// Test GET /health returns HTTP 200 status code.
/// Requirements: 2.1
#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let server = create_test_server();
    let response = server.get("/health").await;
    response.assert_status_ok();
}

/// Test GET /health returns JSON body {"status": "ok"}.
/// Requirements: 2.2
#[tokio::test]
async fn test_health_endpoint_returns_status_ok_body() {
    let server = create_test_server();
    let response = server.get("/health").await;
    response.assert_json(&serde_json::json!({"status": "ok"}));
}

// =============================================================================
// Enclaves Endpoint Tests
// Requirements: 3.1, 3.2
// =============================================================================

/// Test GET /enclaves returns HTTP 200 with empty array when no enclaves running.
/// Requirements: 3.1
#[tokio::test]
async fn test_enclaves_endpoint_returns_empty_array() {
    let server = create_test_server();
    let response = server.get("/enclaves").await;
    response.assert_status_ok();
    response.assert_json(&serde_json::json!([]));
}

// =============================================================================
// Decrypt Endpoint Tests
// Requirements: 4.1, 4.2, 4.3, 4.4
// =============================================================================

/// Test POST /decrypt with valid request returns HTTP 404 when no enclaves available.
/// Requirements: 4.1
#[tokio::test]
async fn test_decrypt_with_no_enclaves_returns_404() {
    let server = create_test_server();
    let response = server.post("/decrypt").json(&valid_decrypt_request()).await;
    response.assert_status_not_found();
    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], 404);
    assert_eq!(body["message"], "No enclaves found");
}

/// Test POST /decrypt with malformed JSON returns HTTP 400.
/// Requirements: 4.2
#[tokio::test]
async fn test_decrypt_with_invalid_json_returns_400() {
    let server = create_test_server();
    let response = server
        .post("/decrypt")
        .content_type("application/json")
        .bytes(Bytes::from("{invalid json"))
        .await;
    response.assert_status_bad_request();
}

/// Test POST /decrypt with empty vault_id returns HTTP 400.
/// Requirements: 4.3
#[tokio::test]
async fn test_decrypt_with_empty_vault_id_returns_400() {
    let server = create_test_server();
    let request = serde_json::json!({
        "vault_id": "",
        "region": "us-east-1",
        "fields": {"ssn": "encrypted_value"},
        "suite_id": "base64_suite_id",
        "encrypted_private_key": "base64_key"
    });
    let response = server.post("/decrypt").json(&request).await;
    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], 400);
}

/// Test POST /decrypt with invalid region format returns HTTP 400.
/// Requirements: 4.4
#[tokio::test]
async fn test_decrypt_with_invalid_region_returns_400() {
    let server = create_test_server();
    let request = serde_json::json!({
        "vault_id": "v_test_123",
        "region": "invalid-region",
        "fields": {"ssn": "encrypted_value"},
        "suite_id": "base64_suite_id",
        "encrypted_private_key": "base64_key"
    });
    let response = server.post("/decrypt").json(&request).await;
    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], 400);
}

// =============================================================================
// Request Body Size Limit Tests
// Requirements: 5.1, 5.2
// =============================================================================

/// Test POST with >1MB body returns HTTP 413 Payload Too Large.
/// Requirements: 5.1
#[tokio::test]
async fn test_oversized_request_body_returns_413() {
    let server = create_test_server();
    // Create a body larger than 1MB (1024 * 1024 = 1,048,576 bytes)
    // Using 1MB + 1 byte to exceed the limit
    let oversized_body = vec![b'a'; 1024 * 1024 + 1];
    let response = server
        .post("/decrypt")
        .content_type("application/json")
        .bytes(Bytes::from(oversized_body))
        .await;
    response.assert_status(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
}

// =============================================================================
// CBOR content negotiation tests
// =============================================================================

use ciborium::Value as CborValue;

/// Build a CBOR map from `(key, value)` pairs, with text-typed keys.
fn cbor_map<I: IntoIterator<Item = (&'static str, CborValue)>>(entries: I) -> CborValue {
    CborValue::Map(
        entries
            .into_iter()
            .map(|(k, v)| (CborValue::Text(k.into()), v))
            .collect(),
    )
}

fn cbor_encode(value: &CborValue) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).unwrap();
    buf
}

/// Returns a valid CBOR-shaped decrypt request body. Suite bytes are
/// arbitrary — translation to the `Suite` enum doesn't run before the
/// "no enclaves" early return that the tests below trigger.
fn valid_cbor_decrypt_request() -> Vec<u8> {
    let field_value = cbor_map([
        ("encapped_key", CborValue::Bytes(vec![0xAAu8; 32])),
        ("ciphertext", CborValue::Bytes(vec![0xBBu8; 16])),
    ]);
    let fields = cbor_map([("ssn", field_value)]);

    let body = cbor_map([
        ("vault_id", CborValue::Text("v_test_123".into())),
        ("region", CborValue::Text("us-east-1".into())),
        ("fields", fields),
        ("suite_id", CborValue::Bytes(vec![0u8; 10])),
        ("encrypted_private_key", CborValue::Bytes(vec![0xCDu8; 32])),
    ]);
    cbor_encode(&body)
}

#[tokio::test]
async fn test_decrypt_cbor_in_no_enclaves_returns_404() {
    let server = create_test_server();
    let response = server
        .post("/decrypt")
        .content_type("application/cbor")
        .bytes(Bytes::from(valid_cbor_decrypt_request()))
        .await;
    response.assert_status_not_found();
}

#[tokio::test]
async fn test_decrypt_malformed_cbor_returns_400() {
    let server = create_test_server();
    let response = server
        .post("/decrypt")
        .content_type("application/cbor")
        .bytes(Bytes::from(vec![0xFFu8; 8])) // not valid CBOR
        .await;
    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_decrypt_cbor_with_invalid_region_returns_400() {
    let server = create_test_server();
    let body = cbor_encode(&cbor_map([
        ("vault_id", CborValue::Text("v_test_123".into())),
        ("region", CborValue::Text("invalid".into())),
        ("fields", CborValue::Map(Vec::new())),
        ("suite_id", CborValue::Bytes(vec![0u8; 10])),
        ("encrypted_private_key", CborValue::Bytes(vec![0xCDu8; 32])),
    ]));

    let response = server
        .post("/decrypt")
        .content_type("application/cbor")
        .bytes(Bytes::from(body))
        .await;
    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_decrypt_cbor_in_accept_cbor_routes_correctly() {
    // Asking for CBOR back on an error path still routes through
    // `AppError`'s JSON response — error envelopes don't honor Accept.
    // Pinning this so future content-negotiation changes are explicit.
    let server = create_test_server();
    let response = server
        .post("/decrypt")
        .content_type("application/cbor")
        .add_header("accept", "application/cbor")
        .bytes(Bytes::from(valid_cbor_decrypt_request()))
        .await;
    response.assert_status_not_found();
}

#[tokio::test]
async fn test_decrypt_json_default_content_type_still_works() {
    // No Content-Type header at all should fall through to the JSON
    // path. axum-test's `.json()` sets the header, so we deliberately
    // skip it and send raw bytes.
    let server = create_test_server();
    let body = serde_json::to_vec(&valid_decrypt_request()).unwrap();
    let response = server.post("/decrypt").bytes(Bytes::from(body)).await;
    // Default JSON path → "no enclaves" → 404
    response.assert_status_not_found();
}
