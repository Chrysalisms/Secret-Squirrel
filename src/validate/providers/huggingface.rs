//! HuggingFace credential validator.
//!
//! Validates HuggingFace User Access Tokens by calling
//! `GET https://huggingface.co/api/whoami-v2`.
//!
//! # Response interpretation
//!
//! | HTTP status | `ValidationStatus` |
//! |-------------|-------------------|
//! | 200         | `Active`          |
//! | 401         | `Inactive`        |
//! | other       | `Error`           |

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::BlastRadius,
    engine::{ValidationResult, Validator},
};

/// Validates HuggingFace User Access Token credentials.
pub struct HuggingFaceValidator {
    client: reqwest::Client,
}

impl HuggingFaceValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for HuggingFaceValidator {
    fn provider_name(&self) -> &str {
        "huggingface"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("huggingface-")
            || finding.rule_id.starts_with("hugging-face-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: expose() is used only to build the Authorization header.
        let token = finding.secret.expose().to_string();

        let response = match self
            .client
            .get("https://huggingface.co/api/whoami-v2")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "HuggingFace validation: network error"
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
            "HuggingFace validation response"
        );

        match http_status.as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.unwrap_or_default();
                let username = body["name"].as_str().unwrap_or("<unknown>");
                let full_name = body["fullname"].as_str().unwrap_or("<unknown>");

                // Parse token roles/scopes if present
                let roles: Vec<String> = body["auth"]["accessToken"]["role"]
                    .as_str()
                    .map(|r| vec![r.to_string()])
                    .unwrap_or_default();

                let blast_radius = BlastRadius::new(
                    "huggingface",
                    roles,
                    vec!["huggingface.co/*".to_string()],
                    format!(
                        "Active HuggingFace token for user '{username}' ({full_name}). \
                         Can download models, run inference, and access private repos."
                    ),
                );

                ValidationResult {
                    status: ValidationStatus::Active,
                    reason: format!(
                        "HuggingFace token is active (user: {username})"
                    ),
                    blast_radius: Some(blast_radius),
                    validated_at: chrono::Utc::now(),
                    provider: self.provider_name().to_string(),
                }
            }
            401 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Token rejected: 401 Unauthorized (invalid or revoked HuggingFace token)",
                self.provider_name(),
            ),
            other => ValidationResult::error(
                format!("Unexpected HTTP {other} from HuggingFace API"),
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
            secret: RedactedString::new("hf_test1234567890abcdef".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "train.py".to_string(),
                start_line: 3,
                end_line: 3,
                start_col: 0,
                end_col: 23,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.94,
                entropy: 0.8,
                proximity: 0.85,
                tristream: 0.85,
                pattern: 0.97,
                markov: 0.77,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity: Severity::High,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn test_can_validate_huggingface_rules() {
        let client = reqwest::Client::new();
        let validator = HuggingFaceValidator::new(client);
        assert!(validator.can_validate(&make_finding("huggingface-api-token")));
        assert!(validator.can_validate(&make_finding("huggingface-user-token")));
        assert!(validator.can_validate(&make_finding("hugging-face-token")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = HuggingFaceValidator::new(client);
        assert!(!validator.can_validate(&make_finding("openai-api-key")));
        assert!(!validator.can_validate(&make_finding("github-pat")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = HuggingFaceValidator::new(client);
        assert_eq!(validator.provider_name(), "huggingface");
    }
}
