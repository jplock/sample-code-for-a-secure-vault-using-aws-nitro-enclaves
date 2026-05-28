// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// Modules consumed by the bin (`enclave_vault::…` from main.rs) remain `pub`.
// Modules used only inside the lib are scoped down to `pub(crate)`.
// `aws_ne` is intentionally `pub` despite being internal: its FFI structs
// and constants are only constructed in musl-gated code, and tightening
// the module to `pub(crate)` surfaces spurious dead-code warnings for the
// FFI surface on non-musl host builds (where the cfg-gated impls don't
// compile).
//
// Wire protocol (framing + Request/Response types) lives in the
// `vault-protocol` workspace crate; re-export through here would be
// noise, so `main.rs` imports `vault_protocol::…` directly.
pub mod aws_ne;
pub mod constants;
pub mod expressions;
pub(crate) mod functions;
pub(crate) mod hpke;
pub(crate) mod kms;
pub mod models;
pub mod utils;

// Re-export the per-field HPKE decrypt entry point so external benches
// (under `benches/`) can drive it without widening the `hpke` module's
// visibility.
pub use crate::hpke::decrypt_value;
