// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use cel_interpreter::Value as celValue;
use cel_interpreter::{Context, Program};
use serde_json::Value;

use crate::constants::{MAX_EXPRESSION_LENGTH, MAX_EXPRESSIONS};
use crate::functions;

/// Rejects requests that try to enqueue more CEL expressions than the
/// enclave is willing to evaluate in a single call. Surfaced as a hard
/// error to the caller rather than the silent-fallback path inside
/// `execute_expressions`, so clients see the cap rejection in the
/// response `errors[]` list instead of getting un-transformed fields.
pub fn validate_expressions_count(n: usize) -> Result<()> {
    if n > MAX_EXPRESSIONS {
        bail!("expression count {} exceeds maximum {}", n, MAX_EXPRESSIONS);
    }
    Ok(())
}

/// Applies CEL expressions to a set of decrypted fields.
///
/// Returns the transformed field map and a (possibly empty) list of expression
/// errors. Errors from failing expressions are sanitized before being returned
/// so they never carry raw library internals or attacker-supplied content to
/// the vsock response.
///
/// An in-place expression (whose key matches an existing field) that fails is
/// silently skipped — the original decrypted value is preserved. A new-field
/// expression that fails contributes a sanitized error entry and stores
/// `Value::Null` for that field.
pub fn execute_expressions(
    fields: &HashMap<String, Value>,
    expressions: &HashMap<String, String>,
) -> Result<(HashMap<String, Value>, Vec<anyhow::Error>)> {
    if expressions.is_empty() {
        return Ok((fields.clone(), Vec::new()));
    }

    // Validate expression lengths before processing
    for (field, expression) in expressions {
        if expression.len() > MAX_EXPRESSION_LENGTH {
            bail!(
                "expression for field '{}' exceeds maximum length: {} > {}",
                field,
                expression.len(),
                MAX_EXPRESSION_LENGTH
            );
        }
    }

    let mut context = Context::default();
    // strings
    context.add_function("is_empty", functions::is_empty);
    context.add_function("to_lowercase", functions::to_lowercase);
    context.add_function("to_uppercase", functions::to_uppercase);
    // base64
    context.add_function("base64_encode", functions::base64_encode);
    context.add_function("base64_decode", functions::base64_decode);
    // hex
    context.add_function("hex_encode", functions::hex_encode);
    context.add_function("hex_decode", functions::hex_decode);
    // hmac
    context.add_function("sha256", functions::sha256_hash);
    context.add_function("sha384", functions::sha384_hash);
    context.add_function("sha512", functions::sha512_hash);
    // datetime
    context.add_function("today_utc", functions::today_utc);
    context.add_function("date", functions::date);
    context.add_function("age", functions::age);

    let mut transformed: HashMap<String, Value> =
        HashMap::with_capacity(fields.len() + expressions.len());
    let mut cel_errors: Vec<anyhow::Error> = Vec::new();

    for (field, decrypted_value) in fields {
        context
            .add_variable(field, decrypted_value)
            .map_err(|err| anyhow!("Unable to add variable '{field}': {err}"))?;
        transformed.insert(field.to_string(), decrypted_value.clone());
    }

    for (field, expression) in expressions {
        let program = Program::compile(expression.as_str());

        let value: celValue = match program {
            Ok(program) => match program.execute(&context) {
                Ok(value) => value,
                Err(_) => {
                    // Preserve the original decrypted field value when an in-place expression
                    // (one whose key matches an existing field) fails to execute. Without this,
                    // the error string would overwrite the PII/PHI value the caller relies on.
                    if fields.contains_key(field) {
                        continue;
                    }
                    // For new fields: record a sanitized error and store Null rather than
                    // emitting the raw CEL error text (which can echo attacker-supplied content).
                    cel_errors.push(anyhow!("expression execution error for field '{field}'"));
                    transformed.insert(field.to_string(), Value::Null);
                    continue;
                }
            },
            Err(_) => {
                // Same preservation rule for compile failures on in-place expressions.
                if fields.contains_key(field) {
                    continue;
                }
                cel_errors.push(anyhow!("expression compile error for field '{field}'"));
                transformed.insert(field.to_string(), Value::Null);
                continue;
            }
        };

        context.add_variable_from_value(field, value.clone());

        let result: Value = value
            .json()
            .map_err(|err| anyhow!("Unable to serialize JSON value: {err}"))?;

        // Only log expression results in debug builds to prevent sensitive data leakage
        #[cfg(debug_assertions)]
        println!("[enclave] expression: {expression} = {result:?}");

        transformed.insert(field.to_string(), result);
    }

    Ok((transformed, cel_errors))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    // **Feature: enclave-improvements, Property 5: Expression failure fallback**
    // **Validates: Requirements 8.2**
    //
    // *For any* set of decrypted fields and any expression that fails to execute,
    // the system SHALL return the original decrypted fields unchanged.
    //
    // Note: The execute_expressions function handles errors in two ways:
    // 1. Individual expression compile/execution errors are captured as error strings in the output
    // 2. Variable addition errors cause the function to return Err
    //
    // This property test verifies that when expressions fail to compile or execute,
    // the original field values are preserved (though the expression result may be an error string).
    // The fallback behavior in main.rs (returning original fields on Err) is tested separately.

    /// Simulates the fallback behavior from main.rs:
    /// When execute_expressions returns Err, return the original fields unchanged.
    fn execute_with_fallback(
        fields: &HashMap<String, Value>,
        expressions: &HashMap<String, String>,
    ) -> HashMap<String, Value> {
        match execute_expressions(fields, expressions) {
            Ok((result, _errors)) => result,
            Err(_) => fields.clone(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_expression_failure_preserves_original_fields(
            // Generate random field names and values
            field_name in "[a-z][a-z0-9_]{0,10}",
            field_value in "[a-zA-Z0-9 ]{1,20}",
            // Generate invalid expression that will fail to execute (but not panic)
            // Note: We avoid syntax errors that cause the CEL parser to panic
            invalid_expr_type in 0usize..3
        ) {
            // Create original fields
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            // Create an invalid expression that will fail to execute gracefully
            // These expressions compile but fail at runtime, or reference undefined variables
            let invalid_expression = match invalid_expr_type {
                0 => "undefined_variable.method()".to_string(),
                1 => "nonexistent_function()".to_string(),
                _ => "undefined_var.to_uppercase()".to_string(),
            };

            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert("result".to_string(), invalid_expression);

            // Execute with fallback (simulating main.rs behavior)
            let result = execute_with_fallback(&fields, &expressions);

            // The original field should be preserved
            prop_assert!(
                result.contains_key(&field_name),
                "Original field '{}' should be preserved in result",
                field_name
            );
            prop_assert_eq!(
                result.get(&field_name),
                Some(&Value::String(field_value.clone())),
                "Original field value should be unchanged"
            );
        }

        #[test]
        fn prop_expression_error_does_not_modify_original_field_values(
            // Generate multiple fields
            num_fields in 1usize..5,
            field_seed in any::<u64>()
        ) {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            // Generate deterministic field names and values based on seed
            let mut fields: HashMap<String, Value> = HashMap::new();
            for i in 0..num_fields {
                let mut hasher = DefaultHasher::new();
                (field_seed, i).hash(&mut hasher);
                let hash = hasher.finish();
                let name = format!("field_{}", i);
                let value = format!("value_{}", hash % 1000);
                fields.insert(name, Value::String(value));
            }

            // Create an expression that references an undefined variable
            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert("computed".to_string(), "undefined_var.to_uppercase()".to_string());

            // Execute with fallback
            let result = execute_with_fallback(&fields, &expressions);

            // All original fields should be preserved with their original values
            for (name, value) in &fields {
                prop_assert!(
                    result.contains_key(name),
                    "Original field '{}' should be preserved",
                    name
                );
                prop_assert_eq!(
                    result.get(name),
                    Some(value),
                    "Original field '{}' value should be unchanged",
                    name
                );
            }
        }

        #[test]
        fn prop_empty_expressions_returns_original_fields_unchanged(
            // Generate random fields
            field_name in "[a-z][a-z0-9_]{0,10}",
            field_value in "[a-zA-Z0-9 ]{1,20}"
        ) {
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            let expressions: HashMap<String, String> = HashMap::new();

            let (result, errors) = execute_expressions(&fields, &expressions).unwrap();

            prop_assert_eq!(
                result,
                fields,
                "Empty expressions should return original fields unchanged"
            );
            prop_assert!(errors.is_empty(), "No errors expected for empty expressions");
        }

        #[test]
        fn prop_failed_expression_on_existing_field_preserves_value(
            // Generate random field names and values
            field_name in "[a-z][a-z0-9_]{0,10}",
            field_value in "[a-zA-Z0-9 ]{1,20}",
            // Invalid expression variants that fail at runtime without panicking the parser
            invalid_expr_type in 0usize..3
        ) {
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            let invalid_expression = match invalid_expr_type {
                0 => "undefined_variable.method()".to_string(),
                1 => "nonexistent_function()".to_string(),
                _ => "undefined_var.to_uppercase()".to_string(),
            };

            // Collision case: expression key matches an existing field.
            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert(field_name.clone(), invalid_expression);

            let result = execute_with_fallback(&fields, &expressions);

            // The original decrypted value must be preserved, not overwritten by an error string.
            prop_assert!(
                result.contains_key(&field_name),
                "Original field '{}' should be preserved in result",
                field_name
            );
            prop_assert_eq!(
                result.get(&field_name),
                Some(&Value::String(field_value.clone())),
                "Original field value should be unchanged when a colliding expression fails"
            );
        }

        #[test]
        fn prop_valid_expression_on_existing_field_transforms_correctly(
            // Generate a field name that's valid for CEL
            field_name in "[a-z][a-z0-9_]{0,10}",
            // Generate lowercase string to test to_uppercase
            field_value in "[a-z]{1,10}"
        ) {
            let mut fields: HashMap<String, Value> = HashMap::new();
            fields.insert(field_name.clone(), Value::String(field_value.clone()));

            // Create expression to uppercase the field
            let mut expressions: HashMap<String, String> = HashMap::new();
            expressions.insert(field_name.clone(), format!("{}.to_uppercase()", field_name));

            let (result, errors) = execute_expressions(&fields, &expressions).unwrap();

            // The field should be transformed to uppercase
            prop_assert_eq!(
                result.get(&field_name),
                Some(&Value::String(field_value.to_uppercase())),
                "Field should be transformed to uppercase"
            );
            prop_assert!(errors.is_empty(), "No errors expected for successful expressions");
        }
    }

    #[test]
    fn test_failed_in_place_expression_preserves_field() {
        // An in-place expression (keyed to an existing field) that fails must NOT overwrite the
        // original decrypted value with an error string. The original PII/PHI must pass through.
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".to_string(),
            "undefined_var.to_uppercase()".to_string(),
        )]);

        let fields: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "Bob".into())]);

        let (actual, errors) = execute_expressions(&fields, &expressions).unwrap();

        assert_eq!(
            actual.get("first_name"),
            Some(&Value::String("Bob".to_string())),
            "Original decrypted field must be preserved when a colliding expression fails"
        );
        // In-place failures are silent — no error entry for them
        assert!(
            errors.is_empty(),
            "In-place expression failure should produce no error entry"
        );
    }

    #[test]
    fn test_failed_new_field_expression_produces_null_and_error() {
        // A non-in-place expression that fails must store Null (not a raw error string)
        // and record a sanitized error entry.
        let expressions: HashMap<String, String> = HashMap::from([(
            "computed".to_string(),
            "undefined_var.to_uppercase()".to_string(),
        )]);

        let fields: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "Bob".into())]);

        let (actual, errors) = execute_expressions(&fields, &expressions).unwrap();

        // The failed new field should be Null, not a raw error string
        assert_eq!(
            actual.get("computed"),
            Some(&Value::Null),
            "Failed new-field expression must store Value::Null, not raw error text"
        );
        // The error entry must not contain raw CEL internals or attacker content
        assert_eq!(
            errors.len(),
            1,
            "One error expected for the failed new-field expression"
        );
        let err_msg = errors[0].to_string();
        assert!(
            err_msg.contains("expression") && err_msg.contains("computed"),
            "Error should name the field but not contain raw library details: {err_msg}"
        );
        assert!(
            err_msg.len() <= 200,
            "Error message should be within sanitized length limit"
        );
    }

    #[test]
    fn test_validate_expressions_count_at_max() {
        assert!(validate_expressions_count(MAX_EXPRESSIONS).is_ok());
    }

    #[test]
    fn test_validate_expressions_count_over_max() {
        let result = validate_expressions_count(MAX_EXPRESSIONS + 1);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("expression count"));
        assert!(err_msg.contains(&(MAX_EXPRESSIONS + 1).to_string()));
        assert!(err_msg.contains(&MAX_EXPRESSIONS.to_string()));
    }

    #[test]
    fn test_validate_expressions_count_zero() {
        assert!(validate_expressions_count(0).is_ok());
    }

    #[test]
    fn test_skip_expressions() {
        let expressions = HashMap::new();

        let expected: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "Bob".into())]);

        let (actual, errors) = execute_expressions(&expected, &expressions).unwrap();
        assert_eq!(actual, expected);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_execute_transforms() {
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".to_string(),
            "first_name.to_uppercase()".to_string(),
        )]);

        let fields: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "Bob".into())]);

        let expected: HashMap<String, Value> =
            HashMap::from([("first_name".to_string(), "BOB".into())]);

        let (actual, errors) = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_base64() {
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".into(),
            "first_name.base64_encode().base64_decode()".into(),
        )]);

        let fields: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let expected: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let (actual, _errors) = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_hex() {
        let expressions: HashMap<String, String> = HashMap::from([(
            "first_name".into(),
            "first_name.hex_encode().hex_decode()".into(),
        )]);

        let fields: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let expected: HashMap<String, Value> = HashMap::from([("first_name".into(), "Bob".into())]);

        let (actual, _errors) = execute_expressions(&fields, &expressions).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_functions() {
        let expressions: HashMap<String, String> = HashMap::from([
            ("is_empty".into(), "''.is_empty() == true".into()),
            ("to_lowercase".into(), "'Bob'.to_lowercase()".into()),
            ("to_uppercase".into(), "'Bob'.to_uppercase()".into()),
            ("sha256".into(), "'Bob'.sha256()".into()),
            ("sha384".into(), "'Bob'.sha384()".into()),
            ("sha512".into(), "'Bob'.sha512()".into()),
            ("hex_encode".into(), "'Bob'.hex_encode()".into()),
            ("hex_decode".into(), "'426f62'.hex_decode()".into()),
            ("base64_encode".into(), "'Bob'.base64_encode()".into()),
            ("base64_decode".into(), "'Qm9i'.base64_decode()".into()),
            ("date".into(), "date('1979-04-05')".into()),
        ]);

        let fields = HashMap::default();
        // Note: Using Vec for comparison since HashMap ordering is non-deterministic
        let (actual, errors) = execute_expressions(&fields, &expressions).unwrap();
        assert!(
            errors.is_empty(),
            "No errors expected for valid expressions"
        );

        assert_eq!(actual.get("is_empty"), Some(&Value::Bool(true)));
        assert_eq!(
            actual.get("to_lowercase"),
            Some(&Value::String("bob".into()))
        );
        assert_eq!(
            actual.get("to_uppercase"),
            Some(&Value::String("BOB".into()))
        );
        assert_eq!(
            actual.get("sha256"),
            Some(&Value::String(
                "cd9fb1e148ccd8442e5aa74904cc73bf6fb54d1d54d333bd596aa9bb4bb4e961".into()
            ))
        );
        assert_eq!(actual.get("sha384"), Some(&Value::String("b7808c5991933fa578a7d41a177b013f2f745a2c4fac90d1e8631a1ce21918dc5fee092a290a6443e47649989ec9871f".into())));
        assert_eq!(actual.get("sha512"), Some(&Value::String("0c3e99453b4ae505617a3c9b6ce73fc3cd13ddc3b2e2237459710a57f8ec6d26d056db144ff7c71b00ed4e4c39716e9e2099c8076e604423dd74554d4db1e649".into())));
        assert_eq!(
            actual.get("hex_encode"),
            Some(&Value::String("426f62".into()))
        );
        assert_eq!(actual.get("hex_decode"), Some(&Value::String("Bob".into())));
        assert_eq!(
            actual.get("base64_encode"),
            Some(&Value::String("Qm9i".into()))
        );
        assert_eq!(
            actual.get("base64_decode"),
            Some(&Value::String("Bob".into()))
        );
        assert_eq!(
            actual.get("date"),
            Some(&Value::String("1979-04-05T00:00:00+00:00".into()))
        );
    }

    #[test]
    fn test_hex_decode_accepts_uppercase() {
        let expressions: HashMap<String, String> =
            HashMap::from([("hex_decode".into(), "'426F6F'.hex_decode()".into())]);

        let fields = HashMap::default();
        let (actual, _errors) = execute_expressions(&fields, &expressions).unwrap();

        assert_eq!(actual.get("hex_decode"), Some(&Value::String("Boo".into())));
    }

    #[test]
    fn test_hex_decode_accepts_mixed_case() {
        let expressions: HashMap<String, String> =
            HashMap::from([("hex_decode".into(), "'426F62'.hex_decode()".into())]);

        let fields = HashMap::default();
        let (actual, _errors) = execute_expressions(&fields, &expressions).unwrap();

        assert_eq!(actual.get("hex_decode"), Some(&Value::String("Bob".into())));
    }

    #[test]
    fn test_complex() {
        use chrono::{NaiveDate, Utc};

        let expressions: HashMap<String, String> =
            HashMap::from([("age".into(), "date(birth_date).age()".into())]);

        let fields: HashMap<String, Value> = HashMap::from([
            ("first_name".into(), "Bob".into()),
            ("birth_date".into(), "1979-01-01".into()),
        ]);

        let (actual, errors) = execute_expressions(&fields, &expressions).unwrap();

        let birth = NaiveDate::from_ymd_opt(1979, 1, 1).unwrap();
        let expected_age = Utc::now().date_naive().years_since(birth).unwrap();

        assert_eq!(actual.get("first_name"), Some(&Value::String("Bob".into())));
        assert_eq!(
            actual.get("birth_date"),
            Some(&Value::String("1979-01-01".into()))
        );
        assert_eq!(
            actual.get("age"),
            Some(&Value::Number(u64::from(expected_age).into()))
        );
        assert!(errors.is_empty());
    }
}
