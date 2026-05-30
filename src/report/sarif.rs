//! SARIF v2.1.0 reporter — produces output compatible with the GitHub Security tab.
//!
//! The Static Analysis Results Interchange Format (SARIF) is an OASIS standard
//! for representing the output of static analysis tools. GitHub uses it to
//! populate the Security → Code Scanning Alerts view.
//!
//! # Schema
//!
//! ```json
//! {
//!   "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/...",
//!   "version": "2.1.0",
//!   "runs": [{
//!     "tool": { "driver": { "name": "secret-squirrel", "rules": [...] } },
//!     "results": [...]
//!   }]
//! }
//! ```
//!
//! # Severity mapping
//!
//! | Squirrel  | SARIF   |
//! |-----------|---------|
//! | Critical  | error   |
//! | High      | error   |
//! | Medium    | warning |
//! | Low       | note    |
//! | Info      | note    |

use crate::error::Result;
use crate::report::{Formatter, Reporter};
use crate::types::{Finding, Severity};
use serde::Serialize;
use std::io::Write;

/// Produces SARIF v2.1.0 JSON output.
pub struct SarifReporter;

// ============================================================================
// SARIF data structures
// ============================================================================

#[derive(Serialize)]
struct SarifRoot {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(rename = "columnKind")]
    column_kind: &'static str,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    organization: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifRuleConfig,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifRuleConfig {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
    precision: &'static str,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    fingerprints: std::collections::HashMap<String, String>,
    properties: SarifResultProperties,
}

#[derive(Serialize)]
struct SarifResultProperties {
    confidence: f64,
    #[serde(rename = "secretHash")]
    secret_hash: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: &'static str,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "endLine")]
    end_line: u32,
    #[serde(rename = "startColumn")]
    start_column: u32,
    #[serde(rename = "endColumn")]
    end_column: u32,
}

// ============================================================================
// Severity mapping
// ============================================================================

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

// ============================================================================
// Serialization helper
// ============================================================================

fn build_sarif(findings: &[Finding]) -> SarifRoot {
    // Collect unique rules (one SARIF rule per unique rule_id)
    let mut seen_rules = std::collections::HashSet::new();
    let mut sarif_rules: Vec<SarifRule> = Vec::new();

    for finding in findings {
        if seen_rules.insert(finding.rule_id.clone()) {
            sarif_rules.push(SarifRule {
                id: finding.rule_id.clone(),
                name: finding.rule_id.clone(),
                short_description: SarifMessage {
                    text: finding.description.clone(),
                },
                full_description: SarifMessage {
                    text: finding.description.clone(),
                },
                default_configuration: SarifRuleConfig {
                    level: severity_to_sarif_level(&finding.severity),
                },
                properties: SarifRuleProperties {
                    tags: vec!["security".to_string(), "credentials".to_string()],
                    precision: "high",
                },
            });
        }
    }

    let sarif_results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let mut fingerprints = std::collections::HashMap::new();
            fingerprints.insert("secret-hash/v1".to_string(), f.secret_hash.clone());

            SarifResult {
                rule_id: f.rule_id.clone(),
                level: severity_to_sarif_level(&f.severity),
                message: SarifMessage {
                    text: format!(
                        "{} — Confidence: {:.0}%",
                        f.description,
                        f.confidence() * 100.0
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            // SARIF URIs use forward slashes
                            uri: f.location.path.replace('\\', "/"),
                            uri_base_id: "%SRCROOT%",
                        },
                        region: SarifRegion {
                            start_line: f.location.start_line,
                            end_line: f.location.end_line,
                            // SARIF columns are 1-indexed; our Location uses 0-indexed
                            start_column: f.location.start_col + 1,
                            end_column: f.location.end_col + 1,
                        },
                    },
                }],
                fingerprints,
                properties: SarifResultProperties {
                    confidence: f.confidence(),
                    secret_hash: f.secret_hash.clone(),
                },
            }
        })
        .collect();

    SarifRoot {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "secret-squirrel",
                    version: env!("CARGO_PKG_VERSION"),
                    organization: "Secret Squirrel Contributors",
                    information_uri: "https://github.com/Chrysalisms/Secret-Squirrel",
                    rules: sarif_rules,
                },
            },
            results: sarif_results,
            column_kind: "utf16CodeUnits",
        }],
    }
}

// ============================================================================
// Trait implementations
// ============================================================================

impl Reporter for SarifReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        let sarif = build_sarif(findings);
        let json = serde_json::to_string_pretty(&sarif)?;
        writeln!(writer, "{}", json)?;
        Ok(())
    }
}

impl Formatter for SarifReporter {
    fn format(&self, findings: &[Finding], _show_secrets: bool) -> String {
        let sarif = build_sarif(findings);
        serde_json::to_string_pretty(&sarif)
            .unwrap_or_else(|e| format!("{{\"error\": \"sarif serialization failed: {}\"}}", e))
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
            id: "sarif-test-001".to_string(),
            rule_id: "github-pat".to_string(),
            description: "GitHub Personal Access Token detected".to_string(),
            secret: RedactedString::new("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345".to_string()),
            secret_hash: "cafecafecafecafe".to_string(),
            match_context: "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345".to_string(),
            location: Location {
                path: "src/deploy/client.py".to_string(),
                start_line: 42,
                end_line: 42,
                start_col: 7,
                end_col: 43,
                byte_offset: 1024,
            },
            score: FusedScore {
                confidence: 0.99,
                entropy: 0.90,
                proximity: 0.95,
                tristream: 0.88,
                pattern: 1.0,
                markov: 0.82,
                cnn_score: None,
                ast_adjustment: None,
            },
            evidence: Default::default(),
            severity: Severity::Critical,
            chain: None,
            validation: None,
            remediation: Some(
                "Revoke this PAT in GitHub Settings → Developer settings.".to_string(),
            ),
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    #[test]
    fn test_sarif_empty_findings() {
        let reporter = SarifReporter;
        let mut buf = Vec::new();
        reporter.write(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
        assert_eq!(parsed["version"], "2.1.0", "SARIF version must be 2.1.0");
        assert!(parsed["runs"].is_array(), "runs must be an array");
        let results = &parsed["runs"][0]["results"];
        assert!(results.is_array());
        assert_eq!(results.as_array().unwrap().len(), 0, "no results expected");
    }

    #[test]
    fn test_sarif_single_finding_schema_keys() {
        let reporter = SarifReporter;
        let findings = vec![make_finding()];
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");

        // Top-level schema keys
        assert!(parsed["$schema"].is_string(), "$schema key must be present");
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["runs"].is_array());

        // Tool driver
        let driver = &parsed["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "secret-squirrel");

        // Result
        let result = &parsed["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "github-pat");
        assert_eq!(result["level"], "error"); // Critical → error

        // Location
        let loc = &result["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "src/deploy/client.py");
        assert_eq!(loc["region"]["startLine"], 42);
    }

    #[test]
    fn test_sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn test_sarif_deduplicates_rules() {
        // Two findings with the same rule_id should produce only one SARIF rule.
        let f1 = make_finding();
        let mut f2 = make_finding();
        f2.id = "sarif-test-002".to_string();

        let reporter = SarifReporter;
        let mut buf = Vec::new();
        reporter.write(&[f1, f2], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1, "same rule_id should produce 1 SARIF rule");

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "both findings should appear as results");
    }

    #[test]
    fn test_sarif_columns_are_one_indexed() {
        let reporter = SarifReporter;
        let findings = vec![make_finding()]; // start_col = 7
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();

        let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        // Our location has start_col=7 (0-indexed), SARIF should emit 8
        assert_eq!(
            region["startColumn"], 8,
            "columns must be converted to 1-indexed"
        );
    }

    #[test]
    fn test_sarif_formatter_returns_valid_json() {
        let fmt = SarifReporter;
        let findings = vec![make_finding()];
        let output = fmt.format(&findings, false);
        let parsed: serde_json::Value =
            serde_json::from_str(&output).expect("format() must return valid JSON");
        assert_eq!(parsed["version"], "2.1.0");
    }
}
