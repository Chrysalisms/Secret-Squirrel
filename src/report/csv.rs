//! CSV reporter — serializes [`Finding`]s to comma-separated values.
//!
//! The CSV output is suitable for import into spreadsheet tools and SIEM
//! systems.  All fields are RFC 4180-compliant: values containing commas,
//! double-quotes, or newlines are wrapped in double-quotes, and embedded
//! double-quotes are doubled.
//!
//! # Columns
//!
//! ```text
//! rule_id,severity,confidence,path,line,column,match,remediation
//! ```
//!
//! The `match` column always contains the **redacted** form of the secret
//! (using [`RedactedString::redacted`]) unless `show_secrets` is `true`.

use crate::error::Result;
use crate::report::{Formatter, Reporter};
use crate::types::Finding;
use std::io::Write;

// ============================================================================
// CSV escaping
// ============================================================================

/// Escape a string value for inclusion in a CSV field (RFC 4180).
///
/// Wraps the value in double-quotes if it contains commas, double-quotes, or
/// newlines. Embedded double-quotes are doubled (`"` → `""`).
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ============================================================================
// Core write logic
// ============================================================================

const CSV_HEADER: &str = "rule_id,severity,confidence,path,line,column,match,remediation";

fn write_csv(findings: &[Finding], writer: &mut dyn Write, show_secrets: bool) -> Result<()> {
    writeln!(writer, "{}", CSV_HEADER)?;

    for finding in findings {
        let match_val = if show_secrets {
            finding.secret.expose().to_string()
        } else {
            finding.secret.redacted()
        };

        writeln!(
            writer,
            "{},{},{:.4},{},{},{},{},{}",
            csv_escape(&finding.rule_id),
            csv_escape(&finding.severity.to_string()),
            finding.confidence(),
            csv_escape(&finding.location.path),
            finding.location.start_line,
            finding.location.start_col,
            csv_escape(&match_val),
            csv_escape(finding.remediation.as_deref().unwrap_or("")),
        )?;
    }

    Ok(())
}

// ============================================================================
// Trait implementations
// ============================================================================

/// Serializes findings to RFC 4180-compliant CSV.
pub struct CsvReporter;

impl Reporter for CsvReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        write_csv(findings, writer, false)
    }
}

impl Formatter for CsvReporter {
    fn format(&self, findings: &[Finding], show_secrets: bool) -> String {
        let mut buf = Vec::new();
        write_csv(findings, &mut buf, show_secrets).expect("write to Vec<u8> cannot fail");
        String::from_utf8(buf).expect("CSV output is always valid UTF-8")
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

    fn make_finding() -> Finding {
        Finding {
            id: "csv-test-001".to_string(),
            rule_id: "stripe-api-key".to_string(),
            description: "Stripe API Key detected".to_string(),
            secret: RedactedString::new("sk_live_ABCDEFGHIJ1234567890klmnop".to_string()),
            secret_hash: "abcdabcdabcdabcd".to_string(),
            match_context: "STRIPE_KEY=sk_live_ABCDEFGHIJ1234567890klmnop".to_string(),
            location: Location {
                path: "payments/config.py".to_string(),
                start_line: 7,
                end_line: 7,
                start_col: 11,
                end_col: 41,
                byte_offset: 200,
            },
            score: FusedScore {
                confidence: 0.95,
                entropy: 0.88,
                proximity: 0.92,
                tristream: 0.85,
                pattern: 0.97,
                markov: 0.79,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity: Severity::Critical,
            chain: None,
            validation: None,
            remediation: Some("Revoke this key in the Stripe dashboard.".to_string()),
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    #[test]
    fn test_csv_header_row_present() {
        let reporter = CsvReporter;
        let mut buf = Vec::new();
        reporter.write(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.starts_with("rule_id,"),
            "first row must be the header: got '{}'",
            &s[..s.find('\n').unwrap_or(s.len())]
        );
        assert!(s.contains("severity"), "header must contain 'severity'");
        assert!(s.contains("confidence"), "header must contain 'confidence'");
        assert!(s.contains("path"), "header must contain 'path'");
        assert!(s.contains("match"), "header must contain 'match'");
        assert!(
            s.contains("remediation"),
            "header must contain 'remediation'"
        );
    }

    #[test]
    fn test_csv_single_finding_data_row() {
        let reporter = CsvReporter;
        let findings = vec![make_finding()];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        // Lines: header + 1 data row
        assert_eq!(lines.len(), 2, "expected header + 1 data row");
        let data = lines[1];
        assert!(
            data.contains("stripe-api-key"),
            "data row must contain rule_id"
        );
        // Severity::Display outputs uppercase (CRITICAL, HIGH, etc.)
        assert!(
            data.to_uppercase().contains("CRITICAL"),
            "data row must contain severity, got: {data}"
        );
        assert!(
            data.contains("payments/config.py"),
            "data row must contain path"
        );
    }

    #[test]
    fn test_csv_secret_is_redacted_by_default() {
        let reporter = CsvReporter;
        let findings = vec![make_finding()];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // The raw secret must not appear
        assert!(
            !s.contains("sk_live_ABCDEFGHIJ1234567890klmnop"),
            "raw secret must not appear in default CSV output"
        );
    }

    #[test]
    fn test_csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_with_comma() {
        assert_eq!(csv_escape("hello, world"), "\"hello, world\"");
    }

    #[test]
    fn test_csv_escape_with_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_csv_escape_with_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn test_csv_remediation_with_comma_is_escaped() {
        let reporter = CsvReporter;
        let mut finding = make_finding();
        finding.remediation = Some("Step 1, Step 2, Step 3".to_string());
        let mut buf = Vec::new();
        reporter.write(&[finding], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // The remediation field must be quoted
        assert!(
            s.contains("\"Step 1, Step 2, Step 3\""),
            "commas in remediation must be CSV-escaped"
        );
    }

    #[test]
    fn test_csv_empty_remediation() {
        let reporter = CsvReporter;
        let mut finding = make_finding();
        finding.remediation = None;
        let mut buf = Vec::new();
        reporter.write(&[finding], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Last field should be empty (trailing comma then nothing or newline)
        let data_line = s.lines().nth(1).unwrap();
        assert!(
            data_line.ends_with(','),
            "empty remediation should produce trailing comma"
        );
    }

    #[test]
    fn test_csv_formatter_show_secrets() {
        let fmt = CsvReporter;
        let findings = vec![make_finding()];
        // With show_secrets=false (default): raw secret must NOT appear
        let hidden = fmt.format(&findings, false);
        assert!(!hidden.contains("sk_live_ABCDEFGHIJ1234567890klmnop"));
        // With show_secrets=true: raw secret MUST appear
        let exposed = fmt.format(&findings, true);
        assert!(
            exposed.contains("sk_live_ABCDEFGHIJ1234567890klmnop"),
            "show_secrets=true must expose raw secret in CSV"
        );
    }
}
