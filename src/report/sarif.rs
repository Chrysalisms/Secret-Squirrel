use crate::error::Result;
use crate::types::{Finding, Severity};
use crate::report::Reporter;
use serde::Serialize;
use std::io::Write;

/// SARIF v2.1.0 reporter — outputs findings as SARIF JSON for GitHub Security Tab.
pub struct SarifReporter;

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

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

impl Reporter for SarifReporter {
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()> {
        // Collect unique rules
        let mut seen_rules = std::collections::HashSet::new();
        let mut sarif_rules = Vec::new();

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

        let sarif_results: Vec<SarifResult> = findings.iter().map(|f| {
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
                            uri: f.location.path.replace('\\', "/"),
                            uri_base_id: "%SRCROOT%",
                        },
                        region: SarifRegion {
                            start_line: f.location.start_line,
                            end_line: f.location.end_line,
                            start_column: f.location.start_col + 1, // SARIF is 1-indexed
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
        }).collect();

        let sarif = SarifRoot {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Secret Squirrel",
                        version: env!("CARGO_PKG_VERSION"),
                        organization: "Secret Squirrel Contributors",
                        rules: sarif_rules,
                    },
                },
                results: sarif_results,
                column_kind: "utf16CodeUnits",
            }],
        };

        let json = serde_json::to_string_pretty(&sarif)?;
        writeln!(writer, "{}", json)?;
        Ok(())
    }
}
