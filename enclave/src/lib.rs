// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

// Modules consumed by the bin (`enclave_vault::…` from main.rs) remain `pub`.
// Modules used only inside the lib are scoped down to `pub(crate)`.
// `aws_ne` is intentionally `pub` despite being internal: its FFI structs
// and constants are only constructed in musl-gated code, and tightening
// the module to `pub(crate)` surfaces spurious dead-code warnings for the
// FFI surface on non-musl host builds (where the cfg-gated impls don't
// compile).
pub mod aws_ne;
pub mod constants;
pub mod expressions;
pub(crate) mod functions;
pub(crate) mod hpke;
pub(crate) mod kms;
pub mod models;
pub mod protocol;
pub mod utils;
