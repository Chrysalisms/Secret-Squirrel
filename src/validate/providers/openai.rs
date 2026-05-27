//! OpenAI credential validator.
//!
//! Validates OpenAI API keys by calling `GET https://api.openai.com/v1/models`.
//!
//! # Response interpretation
//!
//! | HTTP status | `ValidationStatus`        |
//! |-------------|--------------------------|
//! | 200         | `Active`                 |
//! | 401         | `Inactive`               |
//! | 429         | `Error` (rate limited)   |
//! | other       | `Error`                  |
//!
//! A 200 response means the key is valid and can list models. The
//! `BlastRadius` is set to `Critical` because an OpenAI key can generate
//! arbitrary content and incur significant charges.

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::{BlastRadius, RiskLevel},
    engine::{ValidationResult, Validator},
};

/// Validates OpenAI API keys.
pub struct OpenAiValidator {
    client: reqwest::Client,
}

impl OpenAiValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for OpenAiValidator {
    fn provider_name(&self) -> &str {
        "openai"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("openai-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: expose() is used only to build the Authorization header.
        // The value is not stored or logged.
        let token = finding.secret.expose().to_string();

        let response = match self
            .client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "OpenAI validation: network error"
                );
                return ValidationResult::error(
                    format!("Network error: {e}"),
                    self.provider_name(),
                );
            }
        };

        let http_status = response.status();
        tracing::debug!(
            finding_id = %finding.id,
            http_status = %http_status,
            "OpenAI validation response"
        );

        match http_status.as_u16() {
            200 => {
                // Count available models to enrich the description
                let model_count = response
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v["data"].as_array().map(|a| a.len()))
                    .unwrap_or(0);

                let blast_radius = BlastRadius {
                    provider: "openai".to_string(),
                    permissions: vec![
                        "models:read".to_string(),
                        "completions:write".to_string(),
                        "embeddings:write".to_string(),
                        "fine_tuning:write".to_string(),
                    ],
                    resources: vec!["api.openai.com/*".to_string()],
                    risk_level: RiskLevel::Critical,
                    description: format!(
                        "Active OpenAI API key. Can access {model_count} model(s) and generate \
                         completions (may incur charges)."
                    ),
                };

                ValidationResult {
                    status: ValidationStatus::Active,
                    reason: format!(
                        "OpenAI key is active. Access to {model_count} model(s)."
                    ),
                    blast_radius: Some(blast_radius),
                    validated_at: chrono::Utc::now(),
                    provider: self.provider_name().to_string(),
                }
            }
            401 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Key rejected: 401 Unauthorized (invalid or revoked OpenAI API key)",
                self.provider_name(),
            ),
            429 => {
                tracing::warn!(finding_id = %finding.id, "OpenAI validation: rate limited");
                ValidationResult::simple(
                    ValidationStatus::Error,
                    "Rate limited by OpenAI API (429) — key may still be active",
                    self.provider_name(),
                )
            }
            other => ValidationResult::error(
                format!("Unexpected HTTP {other} from OpenAI API"),
                self.provider_name(),
            ),
        }
    }
}

// ===========================
// Tests
// ===========================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FusedScore, Location, RedactedString, Severity};
    use chrono::Utc;

    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            id: "test-id".to_string(),
            rule_id: rule_id.to_string(),
            description: "test".to_string(),
            secret: RedactedString::new("sk-proj-test1234567890abcdef".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "config.py".to_string(),
                start_line: 10,
                end_line: 10,
                start_col: 0,
                end_col: 28,
                byte_offset: 100,
            },
            score: FusedScore {
                confidence: 0.98,
                entropy: 0.85,
                proximity: 0.9,
                tristream: 0.9,
                pattern: 0.99,
                markov: 0.8,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity: Severity::Critical,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn test_can_validate_openai_rules() {
        let client = reqwest::Client::new();
        let validator = OpenAiValidator::new(client);
        assert!(validator.can_validate(&make_finding("openai-api-key")));
        assert!(validator.can_validate(&make_finding("openai-key")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = OpenAiValidator::new(client);
        assert!(!validator.can_validate(&make_finding("anthropic-api-key")));
        assert!(!validator.can_validate(&make_finding("github-pat")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = OpenAiValidator::new(client);
        assert_eq!(validator.provider_name(), "openai");
    }
}
