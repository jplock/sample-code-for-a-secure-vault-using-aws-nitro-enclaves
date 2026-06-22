// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "enclave stdout/stderr is the only diagnostic channel in --debug-mode (visible via nitro-cli console); production stdout is discarded. process::exit on bind failure is the correct response — the enclave cannot do anything useful without a listener. See `.claude/memory/enclave-no-observability.md`."
)]

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use anyhow::{Error, Result};
use enclave_vault::{
    constants::{ENCLAVE_PORT, MAX_CONCURRENT_CONNECTIONS, VSOCK_IO_TIMEOUT},
    expressions::{execute_expressions, validate_expressions_count},
    models::decrypt_fields,
    utils::sanitize_error_message,
};
use vault_protocol::{EnclaveResponse, recv_request, send_response};
use vsock::VsockListener;

// Avoid musl's default allocator due to terrible performance
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn send_sanitized_error<W: Write>(mut stream: W, err: Error) -> Result<()> {
    // Sanitize before logging AND before including in the wire response.
    let sanitized_msg = sanitize_error_message(&err);
    println!("[enclave error] {sanitized_msg}");

    // Build the response from the already-sanitized string so raw library
    // error text never reaches the vsock boundary.
    let response = EnclaveResponse::error_msg(sanitized_msg);

    if let Err(err) = send_response(&mut stream, &response) {
        let sanitized = sanitize_error_message(&err);
        println!("[enclave error] failed to send error: {sanitized}");
    }

    Ok(())
}

fn handle_client<S: Read + Write>(mut stream: S) -> Result<()> {
    println!("[enclave] handling client");

    let payload = match recv_request(&mut stream) {
        Ok(payload) => payload,
        Err(err) => return send_sanitized_error(stream, err),
    };

    // Bound the number of CEL expressions before any decrypt work — a request
    // with thousands of expressions would otherwise force the enclave through
    // a full HPKE decrypt pass first.
    if let Some(ref expressions) = payload.request.expressions
        && let Err(err) = validate_expressions_count(expressions.len())
    {
        return send_sanitized_error(stream, err);
    }

    // Decrypt the individual field values (uses rayon for parallelization internally)
    let (decrypted_fields, errors) = match decrypt_fields(&payload) {
        Ok(result) => result,
        Err(err) => return send_sanitized_error(stream, err),
    };

    // Short-circuit when there are no expressions to evaluate: skip the
    // call entirely (avoiding the per-call HashMap clone of decrypted_fields
    // that `execute_expressions` would otherwise do on its empty fast path).
    let (final_fields, cel_errors) = match payload.request.expressions {
        Some(ref expressions) if !expressions.is_empty() => {
            match execute_expressions(&decrypted_fields, expressions) {
                Ok((fields, errs)) => (fields, errs),
                Err(err) => {
                    println!("[enclave warning] expression execution failed");
                    // Only log error details in debug builds
                    #[cfg(debug_assertions)]
                    println!("[enclave debug] expression error: {:?}", err);
                    // Preserve the raw decrypted fields, but surface the failure
                    // so callers can tell their transformations were not applied
                    // (e.g. an expression rejected for exceeding the max length).
                    // The error is sanitized downstream before crossing the vsock
                    // boundary.
                    (decrypted_fields, vec![err])
                }
            }
        }
        _ => (decrypted_fields, Vec::new()),
    };

    // Merge per-field decryption errors with CEL expression errors.
    let sanitized_errors: Vec<String> = errors
        .into_iter()
        .chain(cel_errors)
        .map(|e| sanitize_error_message(&e))
        .collect();
    let errors_field = if sanitized_errors.is_empty() {
        None
    } else {
        Some(sanitized_errors)
    };

    let response = EnclaveResponse::new(final_fields, errors_field);

    println!("[enclave] sending response to parent");

    if let Err(err) = send_response(&mut stream, &response) {
        return send_sanitized_error(stream, err);
    }

    println!("[enclave] finished client");

    Ok(())
}

fn main() -> Result<()> {
    println!("[enclave] init");

    let listener = match VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, ENCLAVE_PORT) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[enclave fatal] failed to bind listener on port {}: {:?}",
                ENCLAVE_PORT, e
            );
            std::process::exit(1);
        }
    };

    println!("[enclave] listening on port {ENCLAVE_PORT}");
    println!(
        "[enclave] max concurrent connections: {}",
        MAX_CONCURRENT_CONNECTIONS
    );

    // Track active connections to prevent resource exhaustion DoS
    let active_connections = Arc::new(AtomicUsize::new(0));

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // Bound how long any single accepted connection can stall a
                // worker thread. The parent already sets matching timeouts on
                // its end (see parent::enclaves::VSOCK_IO_TIMEOUT) — without
                // this, a peer that opens a vsock connection and never sends
                // a payload would tie up a thread until the kernel kills it.
                if let Err(e) = stream.set_read_timeout(Some(VSOCK_IO_TIMEOUT)) {
                    println!(
                        "[enclave warning] failed to set vsock read timeout: {e:?}, rejecting connection"
                    );
                    drop(stream);
                    continue;
                }
                if let Err(e) = stream.set_write_timeout(Some(VSOCK_IO_TIMEOUT)) {
                    println!(
                        "[enclave warning] failed to set vsock write timeout: {e:?}, rejecting connection"
                    );
                    drop(stream);
                    continue;
                }

                // Atomically claim a slot before checking the limit.
                // fetch_add returns the *previous* value; if that was already
                // at (or beyond) the limit we immediately release our slot and
                // reject. This eliminates the TOCTOU window that existed with
                // a separate load + add.
                //
                // Relaxed is sufficient: this counter never participates in
                // synchronizing other memory accesses — it only gates whether
                // we accept the connection. The atomicity of fetch_add itself
                // is what matters, not its ordering with respect to other ops.
                let prev = active_connections.fetch_add(1, Ordering::Relaxed);
                if prev >= MAX_CONCURRENT_CONNECTIONS {
                    active_connections.fetch_sub(1, Ordering::Relaxed);
                    println!(
                        "[enclave warning] connection limit reached ({}/{}), rejecting",
                        prev, MAX_CONCURRENT_CONNECTIONS
                    );
                    drop(stream);
                    continue;
                }
                let connections = Arc::clone(&active_connections);

                // Spawn a new thread to handle each client concurrently
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream) {
                        let sanitized = sanitize_error_message(&err);
                        println!("[enclave error] {sanitized}");
                    }
                    connections.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                println!("[enclave error] failed to accept connection: {:?}", e);
                continue;
            }
        }
    }

    Ok(())
}
