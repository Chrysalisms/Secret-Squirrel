//! GitHub credential validator.
//!
//! Validates GitHub Personal Access Tokens (PATs) and OAuth tokens by calling
//! `GET https://api.github.com/user`.
//!
//! # Response interpretation
//!
//! | HTTP status | `ValidationStatus` |
//! |-------------|-------------------|
//! | 200         | `Active`          |
//! | 401         | `Inactive`        |
//! | 403         | `Inactive` (scoped token, no `user` scope) |
//! | other       | `Error`           |
//!
//! When the token is active, the `X-OAuth-Scopes` response header is parsed to
//! populate `BlastRadius.permissions`.

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::BlastRadius,
    engine::{ValidationResult, Validator},
};

/// Validates GitHub credentials.
pub struct GithubValidator {
    client: reqwest::Client,
}

impl GithubValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for GithubValidator {
    fn provider_name(&self) -> &str {
        "github"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("github-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: `expose()` is called here within a tight scope and the
        // value is never stored, logged, or cloned beyond building the header.
        let token = finding.secret.expose().to_string();

        let response = match self
            .client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    rule_id = %finding.rule_id,
                    error = %e,
                    "GitHub validation: network error"
                );
                return ValidationResult::error(
                    format!("Network error: {e}"),
                    self.provider_name(),
                );
            }
        };

        let status = response.status();
        tracing::debug!(
            finding_id = %finding.id,
            http_status = %status,
            "GitHub validation response"
        );

        match status.as_u16() {
            200 => {
                // Parse OAuth scopes from the response header
                let scopes: Vec<String> = response
                    .headers()
                    .get("X-OAuth-Scopes")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| {
                        s.split(',')
                            .map(|scope| scope.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();

                // Parse login from body for the description
                let login = response
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v["login"].as_str().map(str::to_string))
                    .unwrap_or_else(|| "<unknown>".to_string());

                let scope_description = if scopes.is_empty() {
                    "No OAuth scopes (likely a fine-grained PAT)".to_string()
                } else {
                    format!("Scopes: {}", scopes.join(", "))
                };

                let blast_radius = BlastRadius::new(
                    "github",
                    scopes,
                    vec!["github.com".to_string()],
                    format!("Active GitHub token for user '{login}'. {scope_description}"),
                );

                ValidationResult {
                    status: ValidationStatus::Active,
                    reason: format!("Token is active (login: {login}). {scope_description}"),
                    blast_radius: Some(blast_radius),
                    validated_at: chrono::Utc::now(),
                    provider: self.provider_name().to_string(),
                }
            }
            401 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Token rejected: 401 Unauthorized (invalid or revoked)",
                self.provider_name(),
            ),
            403 => ValidationResult::simple(
                ValidationStatus::Inactive,
                "Token rejected: 403 Forbidden (token lacks 'user' scope or is suspended)",
                self.provider_name(),
            ),
            429 => {
                tracing::warn!(finding_id = %finding.id, "GitHub validation: rate limited");
                ValidationResult::simple(
                    ValidationStatus::Error,
                    "Rate limited by GitHub API (429)",
                    self.provider_name(),
                )
            }
            other => ValidationResult::error(
                format!("Unexpected HTTP {other} from GitHub API"),
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
            secret: RedactedString::new("ghp_test1234567890".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "test.yml".to_string(),
                start_line: 1,
                end_line: 1,
                start_col: 0,
                end_col: 18,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.99,
                entropy: 0.9,
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
    fn test_can_validate_github_rules() {
        let client = reqwest::Client::new();
        let validator = GithubValidator::new(client);

        assert!(validator.can_validate(&make_finding("github-pat")));
        assert!(validator.can_validate(&make_finding("github-oauth-token")));
        assert!(validator.can_validate(&make_finding("github-app-token")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = GithubValidator::new(client);

        assert!(!validator.can_validate(&make_finding("gitlab-token")));
        assert!(!validator.can_validate(&make_finding("aws-access-key-id")));
        assert!(!validator.can_validate(&make_finding("openai-api-key")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = GithubValidator::new(client);
        assert_eq!(validator.provider_name(), "github");
    }
}
