use crate::error::Result;
use crate::types::Finding;
use crate::report::Reporter;
use std::io::Write;

/// CSV reporter — outputs findings as comma-separated values.
pub struct CsvReporter;

impl Reporter for CsvReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        // Header row
        writeln!(
            writer,
            "rule_id,severity,confidence,path,start_line,start_col,secret_redacted,description,remediation"
        )?;

        for finding in findings {
            writeln!(
                writer,
                "{},{},{:.2},{},{},{},{},{},{}",
                csv_escape(&finding.rule_id),
                csv_escape(&finding.severity.to_string()),
                finding.confidence(),
                csv_escape(&finding.location.path),
                finding.location.start_line,
                finding.location.start_col,
                csv_escape(&finding.secret.redacted()),
                csv_escape(&finding.description),
                csv_escape(finding.remediation.as_deref().unwrap_or("")),
            )?;
        }

        Ok(())
    }
}

/// Escape a string for CSV output.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_csv_empty_findings() {
        let reporter = CsvReporter;
        let mut buf = Vec::new();
        reporter.write(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("rule_id,"));
    }
}
