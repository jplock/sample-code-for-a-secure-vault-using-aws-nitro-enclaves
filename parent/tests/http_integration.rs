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
use ciborium::Value as CborValue;
use parent_vault::application::create_router;
use parent_vault::configuration::ParentOptions;
use parent_vault::enclaves::Enclaves;

const CBOR_CT: &str = "application/cbor";

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

// =============================================================================
// Health Endpoint
// =============================================================================

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let server = create_test_server();
    let response = server.get("/health").await;
    response.assert_status_ok();
}

#[tokio::test]
async fn test_health_endpoint_returns_status_ok_body() {
    let server = create_test_server();
    let response = server.get("/health").await;
    response.assert_json(&serde_json::json!({"status": "ok"}));
}

// =============================================================================
// Enclaves Endpoint
// =============================================================================

#[tokio::test]
async fn test_enclaves_endpoint_returns_empty_array() {
    let server = create_test_server();
    let response = server.get("/enclaves").await;
    response.assert_status_ok();
    response.assert_json(&serde_json::json!([]));
}

// =============================================================================
// Decrypt Endpoint
// =============================================================================

#[tokio::test]
async fn test_decrypt_with_no_enclaves_returns_404() {
    let server = create_test_server();
    let response = server
        .post("/decrypt")
        .content_type(CBOR_CT)
        .bytes(Bytes::from(valid_cbor_decrypt_request()))
        .await;
    response.assert_status_not_found();
    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], 404);
    assert_eq!(body["message"], "No enclaves found");
}

#[tokio::test]
async fn test_decrypt_with_malformed_cbor_returns_400() {
    let server = create_test_server();
    let response = server
        .post("/decrypt")
        .content_type(CBOR_CT)
        .bytes(Bytes::from(vec![0xFFu8; 8])) // not valid CBOR
        .await;
    response.assert_status_bad_request();
}

#[tokio::test]
async fn test_decrypt_with_empty_vault_id_returns_400() {
    let server = create_test_server();
    let body = cbor_encode(&cbor_map([
        ("vault_id", CborValue::Text("".into())),
        ("region", CborValue::Text("us-east-1".into())),
        ("fields", CborValue::Map(Vec::new())),
        ("suite_id", CborValue::Bytes(vec![0u8; 10])),
        ("encrypted_private_key", CborValue::Bytes(vec![0xCDu8; 32])),
    ]));
    let response = server
        .post("/decrypt")
        .content_type(CBOR_CT)
        .bytes(Bytes::from(body))
        .await;
    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], 400);
}

#[tokio::test]
async fn test_decrypt_with_invalid_region_returns_400() {
    let server = create_test_server();
    let body = cbor_encode(&cbor_map([
        ("vault_id", CborValue::Text("v_test_123".into())),
        ("region", CborValue::Text("invalid-region".into())),
        ("fields", CborValue::Map(Vec::new())),
        ("suite_id", CborValue::Bytes(vec![0u8; 10])),
        ("encrypted_private_key", CborValue::Bytes(vec![0xCDu8; 32])),
    ]));
    let response = server
        .post("/decrypt")
        .content_type(CBOR_CT)
        .bytes(Bytes::from(body))
        .await;
    response.assert_status_bad_request();
    let body: serde_json::Value = response.json();
    assert_eq!(body["code"], 400);
}

// =============================================================================
// Request Body Size Limit
// =============================================================================

#[tokio::test]
async fn test_oversized_request_body_returns_413() {
    let server = create_test_server();
    // 1 MB + 1 byte exceeds tower-http's RequestBodyLimitLayer cap.
    let oversized_body = vec![b'a'; 1024 * 1024 + 1];
    let response = server
        .post("/decrypt")
        .content_type(CBOR_CT)
        .bytes(Bytes::from(oversized_body))
        .await;
    response.assert_status(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
}
