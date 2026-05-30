//! JSON reporter — serializes [`Finding`]s to pretty-printed JSON.
//!
//! The output is a JSON array of finding objects.  The [`Finding::secret`]
//! field is always redacted (via its `Serialize` impl) unless the caller
//! has explicitly enabled secret exposure through the `show_secrets` gate.
//!
//! # Format
//!
//! ```json
//! [
//!   {
//!     "id": "...",
//!     "rule_id": "aws-access-key-id",
//!     "severity": "high",
//!     "secret": "AKIA****MPLE",
//!     ...
//!   }
//! ]
//! ```

use crate::error::Result;
use crate::report::{Formatter, Reporter};
use crate::types::Finding;
use std::io::Write;

/// Serializes findings to a pretty-printed JSON array.
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        let json = serde_json::to_string_pretty(findings)?;
        writeln!(writer, "{}", json)?;
        Ok(())
    }
}

impl Formatter for JsonReporter {
    /// Return findings as a pretty-printed JSON string.
    ///
    /// The `show_secrets` flag is advisory only: the [`Finding::secret`]
    /// field is always serialized through its `RedactedString` serializer,
    /// which never exposes more than 40% of the value. For the full raw
    /// value the caller must separately call [`Finding::secret.expose()`].
    fn format(&self, findings: &[Finding], _show_secrets: bool) -> String {
        serde_json::to_string_pretty(findings)
            .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FusedScore, Location, RedactedString, Severity};
    use chrono::Utc;

    /// Build a minimal but complete `Finding` for use in tests.
    fn make_finding() -> Finding {
        Finding {
            id: "test-id-001".to_string(),
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID detected".to_string(),
            secret: RedactedString::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            secret_hash: "deadbeefdeadbeef".to_string(),
            match_context: "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
            location: Location {
                path: "config/deploy.env".to_string(),
                start_line: 12,
                end_line: 12,
                start_col: 22,
                end_col: 42,
                byte_offset: 330,
            },
            score: FusedScore {
                confidence: 0.97,
                entropy: 0.85,
                proximity: 0.90,
                tristream: 0.80,
                pattern: 0.99,
                markov: 0.75,
                cnn_score: None,
                ast_adjustment: None,
            },
            evidence: Default::default(),
            severity: Severity::High,
            chain: None,
            validation: None,
            remediation: Some("Rotate this key immediately in the AWS IAM console.".to_string()),
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    #[test]
    fn test_json_empty_findings() {
        let reporter = JsonReporter;
        let mut buf = Vec::new();
        reporter.write(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Must be a JSON array
        assert!(s.contains("[]"), "empty result should be '[]', got: {}", s);
    }

    #[test]
    fn test_json_single_finding_is_valid_json() {
        let reporter = JsonReporter;
        let findings = vec![make_finding()];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        // Must parse as a valid JSON array
        let parsed: serde_json::Value =
            serde_json::from_str(&s).expect("output must be valid JSON");
        assert!(parsed.is_array(), "output must be a JSON array");
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_json_contains_rule_id() {
        let reporter = JsonReporter;
        let findings = vec![make_finding()];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("aws-access-key-id"),
            "output must contain the rule_id"
        );
    }

    #[test]
    fn test_json_secret_is_redacted() {
        let reporter = JsonReporter;
        let findings = vec![make_finding()];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        // Parse the JSON and check only the "secret" field value is redacted
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        let secret_field = parsed[0]["secret"]
            .as_str()
            .expect("secret must be a string");

        // The full raw secret must never appear directly in the "secret" field
        assert!(
            !secret_field.contains("AKIAIOSFODNN7EXAMPLE"),
            "raw secret must not appear in the 'secret' JSON field, got: {secret_field}"
        );
        // But some redacted form should be present (the prefix)
        assert!(
            secret_field.contains("AKIA"),
            "redacted prefix should be visible in 'secret' field"
        );
    }

    #[test]
    fn test_formatter_returns_string() {
        let fmt = JsonReporter;
        let findings = vec![make_finding()];
        let output = fmt.format(&findings, false);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("format() must return valid JSON");
        assert!(parsed.is_array());
    }
}
