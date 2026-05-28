// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{Error, Result, anyhow};
use data_encoding::BASE64;

/// Maximum byte length for error messages that cross the vsock boundary.
const MAX_ERROR_MSG_LEN: usize = 200;

/// Sanitizes an error message before it crosses the vsock boundary or reaches a log.
///
/// Truncates messages that exceed [`MAX_ERROR_MSG_LEN`] bytes to prevent sensitive
/// field values, file paths, or library internals from leaking into responses.
/// This is the single canonical implementation; all modules must use it.
///
/// Truncation uses [`str::floor_char_boundary`] so the cut never falls inside a
/// multi-byte codepoint (which would panic with `panic = "abort"` in release builds).
pub fn sanitize_error_message(err: &Error) -> String {
    let msg = err.to_string();
    if msg.len() > MAX_ERROR_MSG_LEN {
        // floor_char_boundary finds the largest valid char boundary <= MAX_ERROR_MSG_LEN,
        // ensuring we never slice through a multi-byte codepoint.
        let boundary = msg.floor_char_boundary(MAX_ERROR_MSG_LEN);
        format!("{}... (truncated)", &msg[..boundary])
    } else {
        msg
    }
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let decoded = BASE64
        .decode(input.as_bytes())
        .map_err(|err| anyhow!("unable to base64 decode input: {:?}", err))?;
    Ok(decoded)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use unwrap/expect/indexing for terseness"
)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_short_message_is_unchanged() {
        let err = anyhow::anyhow!("short error");
        assert_eq!(sanitize_error_message(&err), "short error");
    }

    #[test]
    fn test_sanitize_long_message_is_truncated() {
        let long_msg = "x".repeat(300);
        let err = anyhow::anyhow!("{}", long_msg);
        let result = sanitize_error_message(&err);
        assert!(
            result.len() <= 220, // 200 chars + "... (truncated)"
            "Sanitized message should be truncated, got length {}",
            result.len()
        );
        assert!(
            result.ends_with("... (truncated)"),
            "Should have truncation suffix"
        );
    }

    #[test]
    fn test_sanitize_exactly_200_chars_is_unchanged() {
        let msg = "y".repeat(200);
        let err = anyhow::anyhow!("{}", msg);
        let result = sanitize_error_message(&err);
        assert_eq!(result, msg, "Exactly 200 chars should not be truncated");
    }

    #[test]
    fn test_sanitize_truncates_at_char_boundary() {
        // 199 ASCII bytes + '€' (3 UTF-8 bytes) = 202 total bytes.
        // A naive &msg[..200] would split the 3-byte codepoint and panic at runtime
        // (which with panic=abort kills the enclave process).
        let msg = "x".repeat(199) + "€";
        let err = anyhow::anyhow!("{}", msg);
        let result = sanitize_error_message(&err); // must not panic
        assert!(result.ends_with("... (truncated)"));
        // The result must be valid UTF-8 ending on a char boundary
        assert!(result.is_char_boundary(result.len()));
    }

    #[test]
    fn test_base64_decode() {
        // Round-trip a small base64 value through base64_decode.
        let input = "SGVsbG8="; // "Hello"
        let actual = base64_decode(input).unwrap();
        assert_eq!(actual, b"Hello");
    }

    #[test]
    fn test_base64_decode_invalid_input() {
        let result = base64_decode("not!valid!base64!");
        assert!(result.is_err());
    }
}
