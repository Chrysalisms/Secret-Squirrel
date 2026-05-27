use crate::error::Result;
use crate::types::{Finding, Severity};
use crate::report::Reporter;
use std::io::Write;

/// Human-readable table reporter for terminal output.
pub struct TableReporter;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";

fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "\x1b[1;31m", // bold red
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

impl Reporter for TableReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        if findings.is_empty() {
            writeln!(writer, "\n{}✅ No secrets detected.{}", GREEN, RESET)?;
            return Ok(());
        }

        // Header
        writeln!(writer, "\n{}🐿️  Secret Squirrel — Scan Results{}", BOLD, RESET)?;
        writeln!(writer, "{}{} findings detected{}", BOLD, findings.len(), RESET)?;
        writeln!(writer, "{}{}", "─".repeat(80), RESET)?;

        for (i, finding) in findings.iter().enumerate() {
            let color = severity_color(&finding.severity);
            let icon = severity_icon(&finding.severity);

            writeln!(writer, "\n{}Finding #{} — {}{}{} {}{}{}{}",
                BOLD, i + 1,
                color, finding.severity, RESET,
                icon,
                DIM, finding.rule_id, RESET
            )?;

            // Location
            writeln!(writer, "  {}Location:{} {}:{}:{}",
                BOLD, RESET,
                finding.location.path,
                finding.location.start_line,
                finding.location.start_col
            )?;

            // Description
            writeln!(writer, "  {}Rule:{} {}",
                BOLD, RESET, finding.description)?;

            // Secret (redacted)
            writeln!(writer, "  {}Secret:{} {}{}{}",
                BOLD, RESET,
                MAGENTA, finding.secret, RESET
            )?;

            // Confidence
            let conf_bar = confidence_bar(finding.confidence());
            writeln!(writer, "  {}Confidence:{} {:.0}% {}",
                BOLD, RESET,
                finding.confidence() * 100.0,
                conf_bar
            )?;

            // Credential chain
            if let Some(chain) = &finding.chain {
                writeln!(writer, "  {}Chain:{} {} ({} files linked)",
                    BOLD, RESET,
                    chain.variable_name,
                    1 + chain.propagation_ids.len() + chain.usage_ids.len()
                )?;
            }

            // Validation
            if let Some(val) = &finding.validation {
                let status_color = match val.status {
                    crate::types::ValidationStatus::Active => RED,
                    crate::types::ValidationStatus::Inactive => YELLOW,
                    crate::types::ValidationStatus::Revoked => GREEN,
                    _ => DIM,
                };
                writeln!(writer, "  {}Validation:{} {}{:?}{}",
                    BOLD, RESET,
                    status_color, val.status, RESET
                )?;
            }

            // Remediation
            if let Some(rem) = &finding.remediation {
                writeln!(writer, "  {}Fix:{} {}{}{}",
                    BOLD, RESET,
                    DIM, rem, RESET
                )?;
            }

            writeln!(writer, "  {}{}", DIM, "─".repeat(74))?;
            write!(writer, "{}", RESET)?;
        }

        // Summary
        writeln!(writer, "\n{}Summary:{}", BOLD, RESET)?;
        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

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
}

fn confidence_bar(confidence: f64) -> String {
    let filled = (confidence * 10.0).round() as usize;
    let empty = 10usize.saturating_sub(filled);
    let color = if confidence >= 0.8 {
        RED
    } else if confidence >= 0.6 {
        YELLOW
    } else {
        DIM
    };
    format!("{}[{}{}]{}", color, "█".repeat(filled), "░".repeat(empty), RESET)
}
