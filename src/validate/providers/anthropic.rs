//! Anthropic credential validator.
//!
//! Validates Anthropic API keys by calling `GET https://api.anthropic.com/v1/models`.
//!
//! # Response interpretation
//!
//! | HTTP status | `ValidationStatus` |
//! |-------------|-------------------|
//! | 200         | `Active`          |
//! | 401         | `Inactive`        |
//! | other       | `Error`           |
//!
//! The Anthropic API uses an `x-api-key` header rather than `Authorization`.

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::{BlastRadius, RiskLevel},
    engine::{ValidationResult, Validator},
};

/// Validates Anthropic API credentials.
pub struct AnthropicValidator {
    client: reqwest::Client,
}

impl AnthropicValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for AnthropicValidator {
    fn provider_name(&self) -> &str {
        "anthropic"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("anthropic-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: expose() is used only to build the x-api-key header.
        let token = finding.secret.expose().to_string();

        let response = match self
            .client
            .get("https://api.anthropic.com/v1/models")
            .header("x-api-key", token)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "Anthropic validation: network error"
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
            "Anthropic validation response"
        );

        match http_status.as_u16() {
            200 => {
                let model_count = response
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v["data"].as_array().map(|a| a.len()))
                    .unwrap_or(0);

                let blast_radius = BlastRadius {
                    provider: "anthropic".to_string(),
                    permissions: vec![
                        "models:read".to_string(),
                        "messages:write".to_string(),
                    ],
                    resources: vec!["api.anthropic.com/*".to_string()],
                    risk_level: RiskLevel::Critical,
                    description: format!(
                        "Active Anthropic API key. Access to {model_count} Claude model(s) \
                         (may incur charges)."
                    ),
                };

                ValidationResult {
                    status: ValidationStatus::Active,
                    reason: format!(
                        "Anthropic key is active. Access to {model_count} Claude model(s)."
                    ),
                    blast_radius: Some(blast_radius),
                    validated_at: chrono::Utc::now(),
                    provider: self.provider_name().to_string(),
                }
            }
            401 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Key rejected: 401 Unauthorized (invalid or revoked Anthropic API key)",
                self.provider_name(),
            ),
            403 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Key rejected: 403 Forbidden (key may be suspended or lack model access)",
                self.provider_name(),
            ),
            other => ValidationResult::error(
                format!("Unexpected HTTP {other} from Anthropic API"),
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
            secret: RedactedString::new("sk-ant-test1234567890".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "app.py".to_string(),
                start_line: 1,
                end_line: 1,
                start_col: 0,
                end_col: 21,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.97,
                entropy: 0.83,
                proximity: 0.9,
                tristream: 0.88,
                pattern: 0.99,
                markov: 0.79,
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
    fn test_can_validate_anthropic_rules() {
        let client = reqwest::Client::new();
        let validator = AnthropicValidator::new(client);
        assert!(validator.can_validate(&make_finding("anthropic-api-key")));
        assert!(validator.can_validate(&make_finding("anthropic-key")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = AnthropicValidator::new(client);
        assert!(!validator.can_validate(&make_finding("openai-api-key")));
        assert!(!validator.can_validate(&make_finding("github-pat")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = AnthropicValidator::new(client);
        assert_eq!(validator.provider_name(), "anthropic");
    }
}
