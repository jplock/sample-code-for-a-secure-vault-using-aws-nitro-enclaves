// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Enclave-side processing limits.
//!
//! Wire-protocol-level limits (`MAX_FRAME_BODY_SIZE`,
//! `MAX_FIELD_CIPHERTEXT_SIZE`) live in the `vault-protocol` crate so both
//! the enclave and the parent see the same values. This module holds the
//! limits that only concern the enclave's processing loop.

use std::time::Duration;

pub const ENCLAVE_PORT: u32 = 5050;

/// Maximum concurrent connections to prevent resource exhaustion DoS attacks.
/// Each connection spawns a thread (~8KB stack minimum), so this limits memory
/// usage. With 32 connections and `vault_protocol::MAX_FRAME_BODY_SIZE` (10 MB)
/// per message, worst case is ~320MB memory.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Maximum number of fields allowed per request to prevent resource exhaustion.
pub const MAX_FIELDS: usize = 1000;

/// Maximum allowed expression length (10 KB) to prevent resource exhaustion attacks.
pub const MAX_EXPRESSION_LENGTH: usize = 10 * 1024;

/// Maximum number of CEL expressions per request. Kept well below
/// `MAX_FIELDS` (1000) because each expression is evaluated in a context
/// populated with every decrypted field — a quadratic cost amplifier.
pub const MAX_EXPRESSIONS: usize = 100;

/// Read/write timeout for accepted vsock streams in the enclave.
/// Mirrors the parent's `VSOCK_IO_TIMEOUT` (20s) with extra headroom for
/// the enclave's KMS + HPKE decrypt latency.
pub const VSOCK_IO_TIMEOUT: Duration = Duration::from_secs(30);
