// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::time::Duration;

pub const ENCLAVE_PORT: u32 = 5050;

/// Maximum concurrent connections to prevent resource exhaustion DoS attacks.
/// Each connection spawns a thread (~8KB stack minimum), so this limits memory usage.
/// With 32 connections and 10MB max message size, worst case is ~320MB memory.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Maximum allowed message size (10 MB) to prevent memory exhaustion DoS attacks
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of fields allowed per request to prevent resource exhaustion
pub const MAX_FIELDS: usize = 1000;

/// Maximum allowed expression length (10 KB) to prevent resource exhaustion attacks
pub const MAX_EXPRESSION_LENGTH: usize = 10 * 1024;

/// Maximum decoded ciphertext size per field (64 KB). Real PII/PHI values
/// (SSN, email, name, address) are all well under 1 KB; this leaves ample
/// headroom while bounding attacker-controlled per-field allocation.
pub const MAX_FIELD_CIPHERTEXT_SIZE: usize = 64 * 1024;

/// Maximum number of CEL expressions per request. Kept well below
/// `MAX_FIELDS` (1000) because each expression is evaluated in a context
/// populated with every decrypted field — a quadratic cost amplifier.
pub const MAX_EXPRESSIONS: usize = 100;

/// Read/write timeout for accepted vsock streams in the enclave.
/// Mirrors the parent's `VSOCK_IO_TIMEOUT` (20s) with extra headroom for
/// the enclave's KMS + HPKE decrypt latency.
pub const VSOCK_IO_TIMEOUT: Duration = Duration::from_secs(30);

// build_suite_id(0x0010u16, 0x0001u16, 0x0002u16) - DH_KEM_P256_HKDF_SHA256_AES_256
pub const P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
// build_suite_id(0x0011u16, 0x0002u16, 0x0002u16) - DH_KEM_P384_HKDF_SHA384_AES_256
pub const P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
// build_suite_id(0x0012u16, 0x0003u16, 0x0002u16) - DH_KEM_P521_HKDF_SHA512_AES_256
pub const P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];

// Encoding discriminants sent over the wire. These string values are the
// over-the-wire form of the encoding selector on the JSON request payload
// and MUST stay in lockstep with the Python side at
// `api/src/app/enums.py::EncodingVersion` (HEX = 1, BINARY = 2). Round-trip
// is asserted by `models::tests::test_encoding_try_from_hex_str` and
// `test_encoding_try_from_binary_str`.
pub const ENCODING_HEX: &str = "1";
pub const ENCODING_BINARY: &str = "2";
