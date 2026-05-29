//! GitLab credential validator.
//!
//! Validates GitLab Personal Access Tokens (PATs) by calling
//! `GET https://gitlab.com/api/v4/user`.
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

/// Validates GitLab credentials.
pub struct GitlabValidator {
    client: reqwest::Client,
}

impl GitlabValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for GitlabValidator {
    fn provider_name(&self) -> &str {
        "gitlab"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("gitlab-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: expose() is called only to build the PRIVATE-TOKEN header.
        let token = finding.secret.expose().to_string();

        let response = match self
            .client
            .get("https://gitlab.com/api/v4/user")
            .header("PRIVATE-TOKEN", token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "GitLab validation: network error"
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
            "GitLab validation response"
        );

        match http_status.as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.unwrap_or_default();
                let username = body["username"].as_str().unwrap_or("<unknown>");
                let name = body["name"].as_str().unwrap_or("<unknown>");
                let is_admin = body["is_admin"].as_bool().unwrap_or(false);

                // GitLab PATs with admin flag get Critical
                let permissions = if is_admin {
                    vec!["admin".to_string()]
                } else {
                    vec!["api:read".to_string()]
                };

                let blast_radius = BlastRadius::new(
                    "gitlab",
                    permissions,
                    vec!["gitlab.com/*".to_string()],
                    format!("Active GitLab token for user '{username}' ({name}), admin={is_admin}"),
                );

                ValidationResult {
                    status: ValidationStatus::Active,
                    reason: format!(
                        "GitLab token is active (user: {username}, admin: {is_admin})"
                    ),
                    blast_radius: Some(blast_radius),
                    validated_at: chrono::Utc::now(),
                    provider: self.provider_name().to_string(),
                }
            }
            401 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Token rejected: 401 Unauthorized (invalid or revoked GitLab PAT)",
                self.provider_name(),
            ),
            403 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Token rejected: 403 Forbidden (insufficient permissions or suspended)",
                self.provider_name(),
            ),
            other => ValidationResult::error(
                format!("Unexpected HTTP {other} from GitLab API"),
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
            secret: RedactedString::new("glpat-test1234567890".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: ".env".to_string(),
                start_line: 7,
                end_line: 7,
                start_col: 0,
                end_col: 20,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.97,
                entropy: 0.82,
                proximity: 0.88,
                tristream: 0.88,
                pattern: 0.98,
                markov: 0.78,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity: Severity::Critical,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(), encoding_chain: None,
        }
    }

    #[test]
    fn test_can_validate_gitlab_rules() {
        let client = reqwest::Client::new();
        let validator = GitlabValidator::new(client);
        assert!(validator.can_validate(&make_finding("gitlab-pat")));
        assert!(validator.can_validate(&make_finding("gitlab-personal-access-token")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = GitlabValidator::new(client);
        assert!(!validator.can_validate(&make_finding("github-pat")));
        assert!(!validator.can_validate(&make_finding("aws-access-key-id")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = GitlabValidator::new(client);
        assert_eq!(validator.provider_name(), "gitlab");
    }
}
