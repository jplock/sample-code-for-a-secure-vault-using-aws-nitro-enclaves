// Copyright Smoke Turner, LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "benches use unwrap and arithmetic on bounded test inputs for terseness"
)]

//! Benchmarks for the vault-protocol frame codec.
//!
//! Measures the per-frame cost of `send_request` (CBOR encode + frame
//! header + write) and `recv_request` (header parse + CBOR decode)
//! across realistic field counts. Run with `cargo bench --bench roundtrip`.

use std::collections::HashMap;
use std::io::Cursor;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use vault_protocol::{
    Credential, EnclaveRequest, EncryptedField, ParentRequest, Suite, recv_request, send_request,
};

/// Build a representative `EnclaveRequest` with `n_fields` per-field
/// ciphertext blobs of `ct_bytes` bytes each.
fn make_request(n_fields: usize, ct_bytes: usize) -> EnclaveRequest {
    let mut fields = HashMap::with_capacity(n_fields);
    for i in 0..n_fields {
        fields.insert(
            format!("field_{i}"),
            EncryptedField {
                encapped_key: vec![0xABu8; 97], // P-384 encapped key size
                ciphertext: vec![0xCDu8; ct_bytes],
            },
        );
    }
    EnclaveRequest {
        credential: Credential::new(
            "AKIAEXAMPLE".to_string(),
            "secret_example".to_string(),
            "session_token_example".to_string(),
        ),
        request: ParentRequest {
            vault_id: "v_bench_0123456789".to_string(),
            region: "us-east-1".to_string(),
            fields,
            suite: Suite::P384,
            encrypted_private_key: vec![0xEEu8; 256],
            expressions: None,
        },
    }
}

fn bench_send_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("send_request");
    for n_fields in [1usize, 4, 16, 64] {
        let req = make_request(n_fields, 96);
        // Throughput is approximate body size (varies with field count).
        let mut sink = Vec::with_capacity(8192);
        send_request(&mut sink, &req).unwrap();
        group.throughput(Throughput::Bytes(sink.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_fields), &req, |b, req| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(8192);
                send_request(&mut buf, std::hint::black_box(req)).unwrap();
                buf
            });
        });
    }
    group.finish();
}

fn bench_recv_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("recv_request");
    for n_fields in [1usize, 4, 16, 64] {
        let req = make_request(n_fields, 96);
        let mut buf = Vec::with_capacity(8192);
        send_request(&mut buf, &req).unwrap();
        group.throughput(Throughput::Bytes(buf.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_fields), &buf, |b, buf| {
            b.iter(|| {
                let mut cursor = Cursor::new(std::hint::black_box(buf.as_slice()));
                recv_request(&mut cursor).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("round_trip");
    for n_fields in [1usize, 4, 16, 64] {
        let req = make_request(n_fields, 96);
        let mut probe = Vec::with_capacity(8192);
        send_request(&mut probe, &req).unwrap();
        group.throughput(Throughput::Bytes(probe.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_fields), &req, |b, req| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(8192);
                send_request(&mut buf, std::hint::black_box(req)).unwrap();
                let mut cursor = Cursor::new(buf.as_slice());
                recv_request(&mut cursor).unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_send_request,
    bench_recv_request,
    bench_round_trip
);
criterion_main!(benches);
