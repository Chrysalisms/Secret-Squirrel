//! Human-readable table reporter for terminal output.
//!
//! Uses ANSI escape codes for color directly (no external dependency needed
//! for the core `Reporter` impl).  When the `cli` feature is enabled, the
//! output uses the same escape sequences that the `colored` crate would
//! produce, keeping the two paths compatible.
//!
//! # Color scheme
//!
//! | Severity | Color          |
//! |----------|----------------|
//! | CRITICAL | Bold Red       |
//! | HIGH     | Red            |
//! | MEDIUM   | Yellow         |
//! | LOW      | Cyan           |
//! | INFO     | Dim/Gray       |
//!
//! # Output structure
//!
//! ```text
//! 🐿️  Secret Squirrel — Scan Results
//! N findings detected
//! ────────────────────────────────────────────────────────────────────────────────
//!
//! Finding #1 — HIGH 🟠  aws-access-key-id
//!   Location:   config/deploy.env:12:22
//!   Rule:       AWS Access Key ID detected
//!   Secret:     AKIA****MPLE
//!   Confidence: 97% [██████████]
//!   Fix:        Rotate this key in the AWS IAM console.
//!   ──────────────────────────────────────────────────────────────────────────
//!
//! Summary:
//!   🔴 Critical: 0
//!   🟠 High:     1
//! ```

use crate::error::Result;
use crate::report::{Formatter, Reporter};
use crate::types::{Finding, Severity};
use std::io::Write;

// ============================================================================
// ANSI color constants
// ============================================================================

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const BOLD_RED: &str = "\x1b[1;31m";

// ============================================================================
// Helpers
// ============================================================================

fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => BOLD_RED,
        Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Low => CYAN,
        Severity::Info => DIM,
    }
}

fn severity_icon(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

fn confidence_bar(confidence: f64) -> String {
    let filled = (confidence * 10.0).round() as usize;
    let empty = 10_usize.saturating_sub(filled);
    let color = if confidence >= 0.8 {
        RED
    } else if confidence >= 0.6 {
        YELLOW
    } else {
        DIM
    };
    format!(
        "{}[{}{}]{}",
        color,
        "█".repeat(filled),
        "░".repeat(empty),
        RESET
    )
}

// ============================================================================
// Core write logic (shared between Reporter and Formatter)
// ============================================================================

fn write_table(findings: &[Finding], writer: &mut dyn Write, show_secrets: bool) -> Result<()> {
    if findings.is_empty() {
        writeln!(writer, "\n{}✅ No secrets detected.{}", GREEN, RESET)?;
        return Ok(());
    }

    // ── Header ───────────────────────────────────────────────────────────────
    writeln!(
        writer,
        "\n{}🐿️  Secret Squirrel — Scan Results{}",
        BOLD, RESET
    )?;
    writeln!(
        writer,
        "{}{} finding{} detected{}",
        BOLD,
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        RESET
    )?;
    writeln!(writer, "{}", "─".repeat(80))?;

    // ── Per-finding blocks ───────────────────────────────────────────────────
    for (i, finding) in findings.iter().enumerate() {
        let color = severity_color(&finding.severity);
        let icon = severity_icon(&finding.severity);

        writeln!(
            writer,
            "\n{}Finding #{} — {}{}{} {}  {}{}{}",
            BOLD,
            i + 1,
            color,
            finding.severity,
            RESET,
            icon,
            DIM,
            finding.rule_id,
            RESET
        )?;

        writeln!(
            writer,
            "  {}Location:{}  {}:{}:{}",
            BOLD,
            RESET,
            finding.location.path,
            finding.location.start_line,
            finding.location.start_col
        )?;

        writeln!(
            writer,
            "  {}Rule:{}      {}",
            BOLD, RESET, finding.description
        )?;

        // Secret: show raw or redacted depending on flag
        let secret_display = if show_secrets {
            finding.secret.expose().to_string()
        } else {
            finding.secret.redacted()
        };
        writeln!(
            writer,
            "  {}Secret:{}    {}{}{}",
            BOLD, RESET, MAGENTA, secret_display, RESET
        )?;

        let conf_bar = confidence_bar(finding.confidence());
        writeln!(
            writer,
            "  {}Confidence:{} {:.0}% {}",
            BOLD,
            RESET,
            finding.confidence() * 100.0,
            conf_bar
        )?;

        if let Some(chain) = &finding.chain {
            writeln!(
                writer,
                "  {}Chain:{}     {} ({} files linked)",
                BOLD,
                RESET,
                chain.variable_name,
                1 + chain.propagation_ids.len() + chain.usage_ids.len()
            )?;
        }

        if let Some(val) = &finding.validation {
            let status_color = match val.status {
                crate::types::ValidationStatus::Active => RED,
                crate::types::ValidationStatus::Inactive => YELLOW,
                crate::types::ValidationStatus::Revoked => GREEN,
                _ => DIM,
            };
            writeln!(
                writer,
                "  {}Validation:{} {}{:?}{}",
                BOLD, RESET, status_color, val.status, RESET
            )?;
        }

        if let Some(rem) = &finding.remediation {
            writeln!(
                writer,
                "  {}Fix:{}       {}{}{}",
                BOLD, RESET, DIM, rem, RESET
            )?;
        }

        writeln!(writer, "  {}{}", DIM, "─".repeat(74))?;
        write!(writer, "{}", RESET)?;
    }

    // ── Summary footer ───────────────────────────────────────────────────────
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    writeln!(writer, "\n{}Summary:{}", BOLD, RESET)?;
    writeln!(
        writer,
        "  Total: {} findings ({} critical, {} high, {} medium, {} low)",
        findings.len(),
        critical,
        high,
        medium,
        low
    )?;

    if critical > 0 {
        writeln!(writer, "  🔴 Critical: {}", critical)?;
    }
    if high > 0 {
        writeln!(writer, "  🟠 High:     {}", high)?;
    }
    if medium > 0 {
        writeln!(writer, "  🟡 Medium:   {}", medium)?;
    }
    if low > 0 {
        writeln!(writer, "  🔵 Low:      {}", low)?;
    }
    writeln!(writer)?;

    Ok(())
}

// ============================================================================
// Trait implementations
// ============================================================================

/// Human-readable colored table reporter.
pub struct TableReporter;

impl Reporter for TableReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        write_table(findings, writer, false)
    }
}

impl Formatter for TableReporter {
    fn format(&self, findings: &[Finding], show_secrets: bool) -> String {
        let mut buf = Vec::new();
        write_table(findings, &mut buf, show_secrets).expect("write to Vec<u8> cannot fail");
        String::from_utf8(buf).expect("ANSI output is always valid UTF-8")
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

    fn make_finding(severity: Severity, rule_id: &str) -> Finding {
        Finding {
            id: format!("test-{}", rule_id),
            rule_id: rule_id.to_string(),
            description: format!("Test finding for {}", rule_id),
            secret: RedactedString::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            secret_hash: "deadbeef".to_string(),
            match_context: String::new(),
            location: Location {
                path: "src/config.env".to_string(),
                start_line: 5,
                end_line: 5,
                start_col: 0,
                end_col: 20,
                byte_offset: 100,
            },
            score: FusedScore {
                confidence: 0.88,
                entropy: 0.75,
                proximity: 0.80,
                tristream: 0.70,
                pattern: 0.95,
                markov: 0.65,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity,
            chain: None,
            validation: None,
            remediation: Some("Rotate this credential immediately.".to_string()),
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    #[test]
    fn test_table_empty_findings() {
        let reporter = TableReporter;
        let mut buf = Vec::new();
        reporter.write(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("No secrets detected"),
            "empty output should say 'No secrets detected'"
        );
    }

    #[test]
    fn test_table_contains_rule_id() {
        let reporter = TableReporter;
        let findings = vec![make_finding(Severity::High, "aws-access-key-id")];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("aws-access-key-id"),
            "output must contain the rule_id"
        );
    }

    #[test]
    fn test_table_contains_severity_label() {
        let reporter = TableReporter;
        let findings = vec![make_finding(Severity::Critical, "test-rule")];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("CRITICAL"), "output must contain severity label");
    }

    #[test]
    fn test_table_contains_location() {
        let reporter = TableReporter;
        let findings = vec![make_finding(Severity::Medium, "test-rule")];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("src/config.env"), "output must contain path");
        assert!(s.contains(":5:"), "output must contain line number");
    }

    #[test]
    fn test_table_secret_is_redacted_by_default() {
        let reporter = TableReporter;
        let findings = vec![make_finding(Severity::High, "aws-key")];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.contains("AKIAIOSFODNN7EXAMPLE"),
            "raw secret must not appear in table output"
        );
    }

    #[test]
    fn test_table_footer_summary_counts() {
        let reporter = TableReporter;
        let findings = vec![
            make_finding(Severity::Critical, "r1"),
            make_finding(Severity::High, "r2"),
            make_finding(Severity::Medium, "r3"),
            make_finding(Severity::Low, "r4"),
        ];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("Total: 4 findings"),
            "footer must show total count"
        );
        assert!(s.contains("1 critical"), "footer must show critical count");
        assert!(s.contains("1 high"), "footer must show high count");
    }

    #[test]
    fn test_formatter_returns_non_empty_string() {
        let fmt = TableReporter;
        let findings = vec![make_finding(Severity::High, "test-rule")];
        let output = fmt.format(&findings, false);
        assert!(!output.is_empty());
        assert!(output.contains("test-rule"));
    }

    #[test]
    fn test_confidence_bar_full() {
        let bar = confidence_bar(1.0);
        assert!(
            bar.contains("██████████"),
            "full bar should have 10 filled blocks"
        );
    }

    #[test]
    fn test_confidence_bar_empty() {
        let bar = confidence_bar(0.0);
        assert!(
            bar.contains("░░░░░░░░░░"),
            "empty bar should have 10 open blocks"
        );
    }
}
