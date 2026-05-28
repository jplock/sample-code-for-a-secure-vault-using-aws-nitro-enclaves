// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! AWS Nitro Enclaves SDK FFI wrapper module.
//!
//! This module provides safe Rust wrappers around the aws-nitro-enclaves-sdk-c library
//! for KMS operations within Nitro Enclaves.

pub mod ffi;

use std::fmt;

#[cfg(target_env = "musl")]
use std::ptr;
#[cfg(target_env = "musl")]
use std::slice;
#[cfg(target_env = "musl")]
use std::sync::OnceLock;
#[cfg(target_env = "musl")]
use std::sync::mpsc::{self, SyncSender};
#[cfg(target_env = "musl")]
use std::thread;
#[cfg(target_env = "musl")]
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_env = "musl")]
use zeroize::Zeroizing;

#[cfg(target_env = "musl")]
use ffi::{
    AWS_ADDRESS_MAX_LEN, AWS_NE_VSOCK_PROXY_ADDR, AWS_NE_VSOCK_PROXY_PORT, AWS_SOCKET_VSOCK_DOMAIN,
    aws_allocator, aws_byte_buf, aws_byte_buf_clean_up_secure, aws_kms_decrypt_blocking,
    aws_nitro_enclaves_get_allocator, aws_nitro_enclaves_kms_client,
    aws_nitro_enclaves_kms_client_config_default, aws_nitro_enclaves_kms_client_config_destroy,
    aws_nitro_enclaves_kms_client_configuration, aws_nitro_enclaves_kms_client_destroy,
    aws_nitro_enclaves_kms_client_new, aws_nitro_enclaves_library_init, aws_socket_endpoint,
    aws_string, aws_string_destroy_secure, aws_string_new_from_array,
};

/// One-time initialization guard for the AWS Nitro Enclaves SDK.
///
/// The SDK manages process-global state (HTTP client, auth credentials provider, allocator).
/// Re-initializing or cleaning it up while other threads have in-flight KMS calls can free
/// state that is still in use, leading to a use-after-free. The SDK is therefore initialized
/// exactly once per process and is never cleaned up — it lives for the lifetime of the enclave.
#[cfg(target_env = "musl")]
static SDK_INIT: OnceLock<()> = OnceLock::new();

/// Ensure the AWS Nitro Enclaves SDK has been initialized exactly once for this process.
///
/// Safe to call from multiple threads concurrently; `OnceLock::get_or_init` guarantees the
/// underlying FFI call executes at most once.
#[cfg(target_env = "musl")]
fn ensure_sdk_initialized() {
    SDK_INIT.get_or_init(|| {
        // SAFETY: `aws_nitro_enclaves_library_init` initializes process-global SDK state.
        // `OnceLock::get_or_init` guarantees this closure runs exactly once per process,
        // so there is no concurrent or repeated initialization. A null allocator argument
        // selects the SDK's default allocator, which is the documented contract.
        unsafe {
            aws_nitro_enclaves_library_init(ptr::null_mut());
        }
    });
}

/// Identity used to decide whether a cached KMS client can be reused. We
/// only key on region + access_key_id (not the secret or session token)
/// because IMDS rotates the whole credential triple atomically; a change
/// in access_key_id implies the secret/token changed too.
///
/// The fields are zeroized on drop so that the heap memory holding the
/// previous credentials' identity cannot be recovered after a rotation.
/// `Debug` is derived so test assertion failures are useful. The fields
/// are not secret — `region` is public, `access_key_id` is the IAM
/// identifier (the "username"; the secret material lives separately
/// and is wrapped in `Zeroizing` at the request boundary).
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[allow(
    dead_code,
    reason = "host build has no consumers; the cfg(musl) worker constructs and compares these"
)]
struct CredentialKey {
    region: Vec<u8>,
    access_key_id: Vec<u8>,
}

/// Per-call timeout on the entire KMS decrypt round trip. Bounded
/// shorter than the parent's `VSOCK_IO_TIMEOUT` (30s) so a stuck KMS
/// call surfaces as an enclave error before the parent's connection
/// timeout fires. Without this bound, a wedged `aws_kms_decrypt_blocking`
/// call would block decryption for every other concurrent request
/// until the SDK's own (longer) internal timeout returned.
#[cfg(target_env = "musl")]
const KMS_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Channel capacity matches the per-enclave concurrent-connection cap so
/// the worker queue never grows beyond what the listener will accept.
#[cfg(target_env = "musl")]
const KMS_WORKER_QUEUE: usize = 32;

/// Request sent from a caller thread to the KMS worker. Sensitive
/// credential fields are wrapped in `Zeroizing` so they are erased from
/// the heap after the worker copies them into the C SDK's `aws_string`s.
#[cfg(target_env = "musl")]
struct KmsRequest {
    key: CredentialKey,
    secret_access_key: Zeroizing<Vec<u8>>,
    session_token: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
    response_tx: SyncSender<Result<Vec<u8>, Error>>,
}

/// A KMS client cached together with the credentials it was built from.
/// Lives inside the worker thread only — no Send/Sync required.
#[cfg(target_env = "musl")]
struct CachedClient {
    key: CredentialKey,
    resources: KmsResources,
}

/// Lazily-spawned worker that owns the cached KMS client and serializes
/// `aws_kms_decrypt_blocking` calls.
///
/// Why a worker thread instead of a mutex over the client:
///
/// - The `aws-nitro-enclaves-sdk-c` library is event-loop based; we
///   cannot independently verify that a single client handle is safe
///   under concurrent decrypt calls. Funneling all calls through one
///   thread keeps the SDK in a single-threaded usage pattern.
/// - Callers wait on the response channel with a bounded timeout
///   ([`KMS_REQUEST_TIMEOUT`]). If KMS is stuck, the caller returns an
///   error after the timeout while the worker is free to handle the
///   next request; a wedged KMS handshake no longer holds an
///   enclave-wide lock indefinitely.
/// - The cache lives inside the worker, so the raw FFI pointers in
///   `KmsResources` never cross a thread boundary — the `Send`
///   discipline is enforced by ownership rather than by an
///   `unsafe impl Send`.
#[cfg(target_env = "musl")]
static KMS_WORKER: OnceLock<SyncSender<KmsRequest>> = OnceLock::new();

#[cfg(target_env = "musl")]
fn kms_worker() -> &'static SyncSender<KmsRequest> {
    KMS_WORKER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<KmsRequest>(KMS_WORKER_QUEUE);
        thread::Builder::new()
            .name("kms-worker".into())
            .spawn(move || {
                // Cache lives entirely within this thread; raw FFI
                // pointers never escape.
                let mut cached: Option<CachedClient> = None;
                while let Ok(req) = rx.recv() {
                    let result = handle_kms_request(&mut cached, &req);
                    // If the caller already timed out the response
                    // channel is dropped — `send` returns Err; ignore.
                    let _ = req.response_tx.send(result);
                }
                // The receiver closes when the OnceLock-owned sender
                // is dropped; at that point the process is shutting
                // down and the worker exits.
            })
            .ok();
        tx
    })
}

#[cfg(target_env = "musl")]
fn handle_kms_request(
    cached: &mut Option<CachedClient>,
    req: &KmsRequest,
) -> Result<Vec<u8>, Error> {
    let needs_rebuild = match cached {
        Some(c) => c.key != req.key,
        None => true,
    };
    if needs_rebuild {
        if let Some(mut old) = cached.take() {
            // Tear down the old client + credential strings in reverse
            // alloc order before allocating the new ones so the SDK
            // doesn't briefly hold two clients open against the same
            // vsock proxy.
            unsafe { old.resources.cleanup() };
        }
        let new = build_cached_client(&req.key, &req.secret_access_key, &req.session_token)?;
        *cached = Some(new);
    }
    let entry = match cached.as_mut() {
        Some(c) => c,
        None => return Err(Error::SdkKmsClientError),
    };
    unsafe { do_decrypt(&mut entry.resources, &req.ciphertext) }
}

/// Errors that can occur during KMS operations via FFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// SDK initialization failed (aws_nitro_enclaves_library_init or get_allocator)
    SdkInitError,
    /// Generic SDK error (string allocation failed)
    SdkGenericError,
    /// KMS client configuration failed
    SdkKmsConfigError,
    /// KMS client creation failed
    SdkKmsClientError,
    /// KMS decrypt operation failed
    SdkKmsDecryptError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SdkInitError => write!(f, "Failed to initialize Nitro Enclaves SDK"),
            Error::SdkGenericError => write!(f, "SDK memory allocation failed"),
            Error::SdkKmsConfigError => write!(f, "Failed to configure KMS client"),
            Error::SdkKmsClientError => write!(f, "Failed to create KMS client"),
            Error::SdkKmsDecryptError => write!(f, "KMS decrypt operation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Helper struct to track allocated resources for cleanup
#[cfg(target_env = "musl")]
struct KmsResources {
    allocator: *mut aws_allocator,
    region: *mut aws_string,
    access_key_id: *mut aws_string,
    secret_access_key: *mut aws_string,
    session_token: *mut aws_string,
    config: *mut aws_nitro_enclaves_kms_client_configuration,
    client: *mut aws_nitro_enclaves_kms_client,
    plaintext_buf: Option<aws_byte_buf>,
}

#[cfg(target_env = "musl")]
impl KmsResources {
    fn new() -> Self {
        Self {
            allocator: ptr::null_mut(),
            region: ptr::null_mut(),
            access_key_id: ptr::null_mut(),
            secret_access_key: ptr::null_mut(),
            session_token: ptr::null_mut(),
            config: ptr::null_mut(),
            client: ptr::null_mut(),
            plaintext_buf: None,
        }
    }

    /// Clean up all allocated per-request resources in reverse order of allocation.
    /// Uses secure cleanup functions to zero memory before freeing.
    ///
    /// The process-global AWS Nitro Enclaves SDK state is intentionally not cleaned up here;
    /// it is initialized once and remains live for the lifetime of the enclave process.
    ///
    /// # Safety
    ///
    /// Caller must ensure this is called from within an unsafe context and that
    /// all pointers stored in this struct are valid or null.
    unsafe fn cleanup(&mut self) {
        // Clean up plaintext buffer (securely erase decrypted data)
        if let Some(ref mut buf) = self.plaintext_buf {
            unsafe { aws_byte_buf_clean_up_secure(buf) };
        }
        self.plaintext_buf = None;

        // Destroy KMS client
        if !self.client.is_null() {
            unsafe { aws_nitro_enclaves_kms_client_destroy(self.client) };
            self.client = ptr::null_mut();
        }

        // Destroy KMS client config
        if !self.config.is_null() {
            unsafe { aws_nitro_enclaves_kms_client_config_destroy(self.config) };
            self.config = ptr::null_mut();
        }

        // Securely destroy credential strings (in reverse order of creation)
        if !self.session_token.is_null() {
            unsafe { aws_string_destroy_secure(self.session_token) };
            self.session_token = ptr::null_mut();
        }

        if !self.secret_access_key.is_null() {
            unsafe { aws_string_destroy_secure(self.secret_access_key) };
            self.secret_access_key = ptr::null_mut();
        }

        if !self.access_key_id.is_null() {
            unsafe { aws_string_destroy_secure(self.access_key_id) };
            self.access_key_id = ptr::null_mut();
        }

        if !self.region.is_null() {
            unsafe { aws_string_destroy_secure(self.region) };
            self.region = ptr::null_mut();
        }
    }
}

/// Decrypt ciphertext using KMS with Nitro Enclave attestation.
///
/// On the first call in the process, this function initializes the AWS Nitro Enclaves SDK
/// exactly once via `OnceLock`; subsequent calls reuse that initialization. It then performs
/// decryption and cleans up all per-request resources before returning. The SDK's
/// process-global state is intentionally left initialized for the lifetime of the enclave
/// — concurrent cleanup of that state across threads would free HTTP/auth state still in use
/// by other in-flight KMS calls. The SDK automatically generates an attestation document
/// and sends it to KMS for verification.
///
/// # Encryption context
///
/// KMS encryption context is intentionally NOT bound here. The `aws-nitro-enclaves-sdk-c`
/// library does not currently expose an FFI for it — see upstream
/// <https://github.com/aws/aws-nitro-enclaves-sdk-c/issues/35>. The
/// [`aws_kms_decrypt_blocking`](ffi::aws_kms_decrypt_blocking) signature has no parameter
/// for it, and the matching `EncryptionContext={"vault_id": …}` on the encrypt side at
/// `api/src/app/resources/kms.py:60-63` is therefore also commented out. Both sides must
/// remain in sync: wire up encryption context here only after the upstream issue resolves
/// AND the Python encrypt side is updated in the same release.
///
/// # Arguments
///
/// * `aws_region` - AWS region (e.g., "us-east-1")
/// * `aws_key_id` - AWS access key ID
/// * `aws_secret_key` - AWS secret access key
/// * `aws_session_token` - AWS session token
/// * `ciphertext` - The encrypted data to decrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext
/// * `Err(Error)` - An error if any step fails
///
/// # Safety Invariants
///
/// This function maintains the following safety invariants:
/// - The AWS Nitro Enclaves SDK is initialized exactly once per process via `OnceLock`;
///   `aws_nitro_enclaves_library_clean_up` is never called, so global SDK state cannot be
///   torn down while another thread is mid-KMS-call.
/// - All FFI calls check return values for null pointers before use
/// - cleanup() is called on ALL error paths to prevent per-request resource leaks
/// - No unwrap() or expect() is used on FFI results
/// - Per-request resources are cleaned up in reverse order of allocation
/// - Secure cleanup functions zero memory before freeing (credentials, plaintext)
/// - The function never panics - all errors are returned via Result
#[cfg(target_env = "musl")]
pub fn kms_decrypt(
    aws_region: &[u8],
    aws_key_id: &[u8],
    aws_secret_key: &[u8],
    aws_session_token: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    ensure_sdk_initialized();

    let (response_tx, response_rx) = mpsc::sync_channel(1);
    let req = KmsRequest {
        key: CredentialKey {
            region: aws_region.to_vec(),
            access_key_id: aws_key_id.to_vec(),
        },
        secret_access_key: Zeroizing::new(aws_secret_key.to_vec()),
        session_token: Zeroizing::new(aws_session_token.to_vec()),
        ciphertext: ciphertext.to_vec(),
        response_tx,
    };

    // Bounded sync send: if the worker queue is full (>KMS_WORKER_QUEUE
    // requests in flight), the caller waits its turn instead of growing
    // the queue without bound.
    if kms_worker().send(req).is_err() {
        // Worker thread died; only happens if the worker panicked, which
        // with panic=abort means the whole process aborts anyway.
        return Err(Error::SdkKmsClientError);
    }

    match response_rx.recv_timeout(KMS_REQUEST_TIMEOUT) {
        Ok(result) => result,
        Err(_) => Err(Error::SdkKmsDecryptError),
    }
}

/// Build a fresh `KmsResources` (allocator, credential strings, config,
/// client) for the given credentials. Returns an error if any FFI step
/// fails; partial state is cleaned up before returning.
#[cfg(target_env = "musl")]
fn build_cached_client(
    key: &CredentialKey,
    aws_secret_key: &[u8],
    aws_session_token: &[u8],
) -> Result<CachedClient, Error> {
    let mut resources = KmsResources::new();

    unsafe {
        resources.allocator = aws_nitro_enclaves_get_allocator();
        if resources.allocator.is_null() {
            resources.cleanup();
            return Err(Error::SdkInitError);
        }

        resources.region =
            aws_string_new_from_array(resources.allocator, key.region.as_ptr(), key.region.len());
        if resources.region.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        resources.access_key_id = aws_string_new_from_array(
            resources.allocator,
            key.access_key_id.as_ptr(),
            key.access_key_id.len(),
        );
        if resources.access_key_id.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        resources.secret_access_key = aws_string_new_from_array(
            resources.allocator,
            aws_secret_key.as_ptr(),
            aws_secret_key.len(),
        );
        if resources.secret_access_key.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        resources.session_token = aws_string_new_from_array(
            resources.allocator,
            aws_session_token.as_ptr(),
            aws_session_token.len(),
        );
        if resources.session_token.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        let mut endpoint = aws_socket_endpoint {
            address: [0u8; AWS_ADDRESS_MAX_LEN],
            port: AWS_NE_VSOCK_PROXY_PORT,
        };
        endpoint.address[..AWS_NE_VSOCK_PROXY_ADDR.len()].copy_from_slice(&AWS_NE_VSOCK_PROXY_ADDR);

        resources.config = aws_nitro_enclaves_kms_client_config_default(
            resources.region,
            &mut endpoint,
            AWS_SOCKET_VSOCK_DOMAIN,
            resources.access_key_id,
            resources.secret_access_key,
            resources.session_token,
        );
        if resources.config.is_null() {
            resources.cleanup();
            return Err(Error::SdkKmsConfigError);
        }

        resources.client = aws_nitro_enclaves_kms_client_new(resources.config);
        if resources.client.is_null() {
            resources.cleanup();
            return Err(Error::SdkKmsClientError);
        }
    }

    Ok(CachedClient {
        key: key.clone(),
        resources,
    })
}

/// Perform a single decrypt call against an already-built client. The
/// per-request plaintext buffer is securely cleaned up before returning.
///
/// # Safety
///
/// `resources.client` must be a valid client created by
/// `aws_nitro_enclaves_kms_client_new`. The caller must hold the
/// `CLIENT_CACHE` mutex.
#[cfg(target_env = "musl")]
unsafe fn do_decrypt(resources: &mut KmsResources, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let ciphertext_buf = aws_byte_buf {
        len: ciphertext.len(),
        buffer: ciphertext.as_ptr() as *mut u8,
        capacity: ciphertext.len(),
        allocator: ptr::null_mut(),
    };

    let mut plaintext_buf = aws_byte_buf {
        len: 0,
        buffer: ptr::null_mut(),
        capacity: 0,
        allocator: ptr::null_mut(),
    };

    let rc = unsafe {
        aws_kms_decrypt_blocking(
            resources.client,
            ptr::null_mut(),
            ptr::null_mut(),
            &ciphertext_buf,
            &mut plaintext_buf,
        )
    };

    if rc != 0 {
        // Even on KMS error the SDK may have allocated the buffer; clean it up.
        if !plaintext_buf.buffer.is_null() {
            unsafe { aws_byte_buf_clean_up_secure(&mut plaintext_buf) };
        }
        return Err(Error::SdkKmsDecryptError);
    }

    let plaintext = if !plaintext_buf.buffer.is_null() && plaintext_buf.len > 0 {
        unsafe { slice::from_raw_parts(plaintext_buf.buffer, plaintext_buf.len) }.to_vec()
    } else {
        Vec::new()
    };

    // Securely erase the SDK-allocated plaintext buffer before returning.
    unsafe { aws_byte_buf_clean_up_secure(&mut plaintext_buf) };

    Ok(plaintext)
}

/// Stub implementation for non-musl platforms (compilation only).
/// This function returns an error - it's only meant to allow compilation
/// on development machines. The actual implementation requires the AWS Nitro
/// Enclaves SDK which is only available when building for musl target inside Docker.
#[cfg(not(target_env = "musl"))]
pub fn kms_decrypt(
    _aws_region: &[u8],
    _aws_key_id: &[u8],
    _aws_secret_key: &[u8],
    _aws_session_token: &[u8],
    _ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Return an error instead of panicking - this code path should never be reached
    // in production as the enclave is always built for musl target
    Err(Error::SdkInitError)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use unwrap/expect/indexing for terseness"
)]
mod tests {
    use super::*;

    /// **Feature: kms-ffi-wrapper, Property 2: Error enum is convertible to anyhow::Error**
    /// **Validates: Requirements 3.3**
    ///
    /// Verifies that all Error variants can be converted to anyhow::Error
    /// with descriptive messages. Since Error implements std::error::Error
    /// and Display, it can be converted via anyhow's blanket From implementation.
    #[test]
    fn test_error_conversion_to_anyhow() {
        // Test all error variants can be converted to anyhow::Error
        let errors = [
            Error::SdkInitError,
            Error::SdkGenericError,
            Error::SdkKmsConfigError,
            Error::SdkKmsClientError,
            Error::SdkKmsDecryptError,
        ];

        let expected_messages = [
            "Failed to initialize Nitro Enclaves SDK",
            "SDK memory allocation failed",
            "Failed to configure KMS client",
            "Failed to create KMS client",
            "KMS decrypt operation failed",
        ];

        for (error, expected_msg) in errors.iter().zip(expected_messages.iter()) {
            // Convert to anyhow::Error using the blanket From implementation
            let anyhow_err: anyhow::Error = (*error).into();

            // Verify the error message is descriptive
            let err_string = anyhow_err.to_string();
            assert!(
                err_string.contains(expected_msg),
                "Error {:?} should contain '{}', got '{}'",
                error,
                expected_msg,
                err_string
            );
        }
    }

    /// Test that Error implements std::error::Error trait
    #[test]
    fn test_error_implements_std_error() {
        fn assert_std_error<E: std::error::Error>() {}
        assert_std_error::<Error>();
    }

    // ---------- CredentialKey behavior (host-testable) ----------
    //
    // The cfg(musl) worker uses these properties to decide whether to
    // rebuild the cached KMS client. Tested here so the rebuild logic
    // is covered by host CI in addition to the docker-build path.

    #[test]
    fn credential_key_same_region_same_id_is_equal() {
        let a = CredentialKey {
            region: b"us-east-1".to_vec(),
            access_key_id: b"AKIATEST".to_vec(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn credential_key_differs_on_access_key_change() {
        // This is the case that triggers a rebuild on credential rotation.
        let a = CredentialKey {
            region: b"us-east-1".to_vec(),
            access_key_id: b"AKIAOLD".to_vec(),
        };
        let b = CredentialKey {
            region: b"us-east-1".to_vec(),
            access_key_id: b"AKIANEW".to_vec(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn credential_key_differs_on_region_change() {
        let a = CredentialKey {
            region: b"us-east-1".to_vec(),
            access_key_id: b"AKIATEST".to_vec(),
        };
        let b = CredentialKey {
            region: b"us-west-2".to_vec(),
            access_key_id: b"AKIATEST".to_vec(),
        };
        assert_ne!(a, b);
    }

    /// Test that Error implements Display trait with descriptive messages
    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::SdkInitError.to_string(),
            "Failed to initialize Nitro Enclaves SDK"
        );
        assert_eq!(
            Error::SdkGenericError.to_string(),
            "SDK memory allocation failed"
        );
        assert_eq!(
            Error::SdkKmsConfigError.to_string(),
            "Failed to configure KMS client"
        );
        assert_eq!(
            Error::SdkKmsClientError.to_string(),
            "Failed to create KMS client"
        );
        assert_eq!(
            Error::SdkKmsDecryptError.to_string(),
            "KMS decrypt operation failed"
        );
    }
}
