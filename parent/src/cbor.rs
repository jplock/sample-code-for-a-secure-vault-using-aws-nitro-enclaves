// Copyright Smoke Turner, LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! `Cbor<T>` extractor and response type.
//!
//! Mirrors `axum::Json<T>` for `application/cbor` bodies. Hand-rolled
//! because `axum-extra` ships Protobuf but not CBOR; pulling it in
//! just for the JSON-family extras would be excess dep surface for
//! one type. `ciborium` is already in the workspace via
//! [`vault_protocol`].

use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};

/// Media type for CBOR payloads (RFC 8949 / IANA).
pub const CBOR_CONTENT_TYPE: &str = "application/cbor";

/// CBOR extractor / response wrapper. Behaves like `axum::Json<T>` but
/// for `application/cbor`.
#[derive(Debug)]
pub struct Cbor<T>(pub T);

/// Rejection produced when CBOR decoding fails or the body cannot be
/// read. Surfaced as `400 Bad Request` — these are client-side errors.
#[derive(thiserror::Error, Debug)]
pub enum CborRejection {
    #[error("invalid CBOR body: {0}")]
    Deserialization(String),
    #[error("failed to read request body: {0}")]
    BodyRead(String),
}

impl IntoResponse for CborRejection {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

impl<T, S> FromRequest<S> for Cbor<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = CborRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| CborRejection::BodyRead(e.to_string()))?;
        ciborium::de::from_reader(&*bytes)
            .map(Cbor)
            .map_err(|e| CborRejection::Deserialization(e.to_string()))
    }
}

impl<T: Serialize> IntoResponse for Cbor<T> {
    fn into_response(self) -> Response {
        let mut buf = Vec::new();
        match ciborium::ser::into_writer(&self.0, &mut buf) {
            Ok(()) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(CBOR_CONTENT_TYPE),
                )],
                buf,
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("CBOR serialization failed: {e}"),
            )
                .into_response(),
        }
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
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use serde::Deserialize;

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    struct Sample {
        a: String,
        b: Vec<u8>,
        c: u32,
    }

    fn sample() -> Sample {
        Sample {
            a: "hello".into(),
            b: vec![0xDE, 0xAD, 0xBE, 0xEF],
            c: 42,
        }
    }

    #[tokio::test]
    async fn from_request_round_trip() {
        let s = sample();
        let mut body = Vec::new();
        ciborium::ser::into_writer(&s, &mut body).unwrap();

        let req = HttpRequest::builder()
            .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
            .body(Body::from(body))
            .unwrap();
        let Cbor(decoded): Cbor<Sample> = Cbor::from_request(req, &()).await.unwrap();
        assert_eq!(decoded, s);
    }

    #[tokio::test]
    async fn from_request_rejects_malformed_cbor() {
        let body = vec![0xFFu8; 8]; // not valid CBOR
        let req = HttpRequest::builder()
            .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
            .body(Body::from(body))
            .unwrap();
        let err = Cbor::<Sample>::from_request(req, &()).await.unwrap_err();
        assert!(matches!(err, CborRejection::Deserialization(_)));
    }

    #[tokio::test]
    async fn into_response_sets_content_type() {
        let resp = Cbor(sample()).into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(ct, CBOR_CONTENT_TYPE);
    }

    #[tokio::test]
    async fn round_trip_through_response_and_request() {
        let s = sample();
        let resp = Cbor(s.clone()).into_response();
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();

        let req = HttpRequest::builder()
            .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
            .body(Body::from(body_bytes))
            .unwrap();
        let Cbor(decoded): Cbor<Sample> = Cbor::from_request(req, &()).await.unwrap();
        assert_eq!(decoded, s);
    }
}
