use crate::error::Result;
use crate::types::Finding;
use crate::report::Reporter;
use serde_json;
use std::io::Write;

/// JSON reporter — outputs findings as a JSON array.
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        let json = serde_json::to_string_pretty(findings)?;
        writeln!(writer, "{}", json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_empty() {
        let reporter = JsonReporter;
        let mut buf = Vec::new();
        reporter.write(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("[]"));
    }
}
