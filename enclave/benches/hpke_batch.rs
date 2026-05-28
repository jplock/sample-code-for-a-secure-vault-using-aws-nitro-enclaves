// Copyright Smoke Turner, LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "benches use unwrap and arithmetic on fixed test vectors for terseness"
)]

//! Benchmarks for the HPKE batch decrypt path inside the enclave.
//!
//! The KMS step (decrypt the symmetric private key) is *not* exercised
//! here — it's a one-time cost per request and gated behind the FFI to
//! the Nitro Enclaves SDK that isn't available off-musl. The bench
//! instead measures the dominant per-field work: HPKE decrypt of N
//! field values, both sequentially and via rayon's `par_iter`. The
//! crossover point between the two informs the sequential-fast-path
//! threshold in `models::decrypt_fields`.
//!
//! Test vectors come from the same key + ciphertext used by
//! `enclave/src/hpke.rs::tests::test_decrypt_value`, so the bench
//! exercises real HPKE work end-to-end.

use std::time::Duration;

use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::EcdsaKeyPair;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use data_encoding::{BASE64, HEXLOWER};
use enclave_vault::decrypt_value;
use enclave_vault::models::SuiteExt;
use rayon::prelude::*;
use rustls::crypto::hpke::HpkePrivateKey;
use vault_protocol::{EncryptedField, Suite};

const VAULT_ID: &str = "v_2hRK9u2DOzmAPMhdVNt9qlJ3UvL";
const FIELD_NAME: &str = "first_name";
const SECRET_KEY_B64: &str = "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCt+Ad+qIiVIK4e/tj6u+boZ63IAgT2ZttR14ZGjL3XLjNC//WNJcFyNSOGDt2kNE+gBwYFK4EEACKhZANiAASMfDcAvCD3J8in7EzaM6hNvkQD+S6C0H2hI7biRlkHMXcIjZ/7LVNQ2+VMlFAWV8ESbahT0wKiYLNreDvPIDFJOZyzfURR/HTRtf5Vd+aEjXl9EI7XxRu6OILEfQC9afg=";
const ENCAPPED_KEY_HEX: &str = "04cebfe3667db3305777774f14a7ed4f26ce90b2d68935a30f9b086dc915e6ede23e6dfdde7aaf34dc34cd964c76f94bc91ba99edb3707281862c990c54782eace8c687770d72d4c714d4edd239e010facfb7c3d5c168b14d9040194059529f5e6";
const CIPHERTEXT_HEX: &str = "80c10441ae55442775bc5d1b0b8465eaaaa33b";

fn make_key_and_field() -> (HpkePrivateKey, EncryptedField) {
    let suite = Suite::P384;
    let algo = suite.signing_algorithm();
    let der_sk = BASE64.decode(SECRET_KEY_B64.as_bytes()).unwrap();
    let sk = EcdsaKeyPair::from_private_key_der(algo, &der_sk).unwrap();
    let sk_bytes = sk.private_key().as_be_bytes().unwrap();
    let private_key: HpkePrivateKey = sk_bytes.as_ref().to_vec().into();

    let encapped_key = HEXLOWER.decode(ENCAPPED_KEY_HEX.as_bytes()).unwrap();
    let ciphertext = HEXLOWER.decode(CIPHERTEXT_HEX.as_bytes()).unwrap();
    let field = EncryptedField {
        encapped_key,
        ciphertext,
    };

    (private_key, field)
}

fn bench_sequential(c: &mut Criterion) {
    let (private_key, sample_field) = make_key_and_field();
    let suite = Suite::P384;
    let hpke_suite = suite.hpke();
    let info = VAULT_ID.as_bytes();

    let mut group = c.benchmark_group("hpke_sequential");
    group.measurement_time(Duration::from_secs(5));
    for n in [1usize, 2, 4, 8, 16, 32] {
        let fields: Vec<EncryptedField> = (0..n).map(|_| sample_field.clone()).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &fields, |b, fields| {
            b.iter(|| {
                for ef in fields.iter() {
                    let _ = decrypt_value(
                        std::hint::black_box(hpke_suite),
                        std::hint::black_box(&private_key),
                        std::hint::black_box(info),
                        std::hint::black_box(FIELD_NAME),
                        std::hint::black_box(ef),
                    )
                    .unwrap();
                }
            });
        });
    }
    group.finish();
}

fn bench_parallel(c: &mut Criterion) {
    let (private_key, sample_field) = make_key_and_field();
    let suite = Suite::P384;
    let hpke_suite = suite.hpke();
    let info = VAULT_ID.as_bytes();

    let mut group = c.benchmark_group("hpke_parallel");
    group.measurement_time(Duration::from_secs(5));
    for n in [1usize, 2, 4, 8, 16, 32] {
        let fields: Vec<EncryptedField> = (0..n).map(|_| sample_field.clone()).collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &fields, |b, fields| {
            b.iter(|| {
                let _: Vec<_> = fields
                    .par_iter()
                    .map(|ef| {
                        decrypt_value(
                            std::hint::black_box(hpke_suite),
                            std::hint::black_box(&private_key),
                            std::hint::black_box(info),
                            std::hint::black_box(FIELD_NAME),
                            std::hint::black_box(ef),
                        )
                        .unwrap()
                    })
                    .collect();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sequential, bench_parallel);
criterion_main!(benches);
