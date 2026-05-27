//! Slack credential validator.
//!
//! Validates Slack Bot Tokens and User Tokens by calling
//! `POST https://slack.com/api/auth.test`.
//!
//! # Response interpretation
//!
//! The Slack API always returns HTTP 200; the actual success/failure is in the
//! JSON body's `"ok"` field.
//!
//! | `ok` field | `ValidationStatus` |
//! |------------|-------------------|
//! | `true`     | `Active`          |
//! | `false`    | `Inactive`        |
//! | (error)    | `Error`           |

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::BlastRadius,
    engine::{ValidationResult, Validator},
};

/// Validates Slack credentials.
pub struct SlackValidator {
    client: reqwest::Client,
}

impl SlackValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for SlackValidator {
    fn provider_name(&self) -> &str {
        "slack"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("slack-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: expose() is called only to build the Authorization header.
        let token = finding.secret.expose().to_string();

        let response = match self
            .client
            .post("https://slack.com/api/auth.test")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "Slack validation: network error"
                );
                return ValidationResult::error(
                    format!("Network error: {e}"),
                    self.provider_name(),
                );
            }
        };

        tracing::debug!(
            finding_id = %finding.id,
            http_status = %response.status(),
            "Slack validation response"
        );

        // Slack API always returns 200; parse the JSON body
        let body: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult::error(
                    format!("Failed to parse Slack API response: {e}"),
                    self.provider_name(),
                );
            }
        };

        let ok = body["ok"].as_bool().unwrap_or(false);
        if ok {
            let team = body["team"].as_str().unwrap_or("<unknown>");
            let user = body["user"].as_str().unwrap_or("<unknown>");
            let scopes: Vec<String> = body["response_metadata"]["scopes"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();

            let blast_radius = BlastRadius::new(
                "slack",
                scopes.clone(),
                vec![format!("slack.com/workspace/{team}")],
                format!(
                    "Active Slack token for user '{user}' in workspace '{team}'"
                ),
            );

            ValidationResult {
                status: ValidationStatus::Active,
                reason: format!(
                    "Slack token is active (user: {user}, workspace: {team})"
                ),
                blast_radius: Some(blast_radius),
                validated_at: chrono::Utc::now(),
                provider: self.provider_name().to_string(),
            }
        } else {
            let error = body["error"].as_str().unwrap_or("unknown_error");
            ValidationResult::simple(
                ValidationStatus::Inactive,
                format!("Slack auth.test returned ok=false: {error}"),
                self.provider_name(),
            )
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
            secret: RedactedString::new("xoxb-test-token".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "app.js".to_string(),
                start_line: 5,
                end_line: 5,
                start_col: 0,
                end_col: 15,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.95,
                entropy: 0.8,
                proximity: 0.85,
                tristream: 0.85,
                pattern: 0.98,
                markov: 0.75,
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
    fn test_can_validate_slack_rules() {
        let client = reqwest::Client::new();
        let validator = SlackValidator::new(client);
        assert!(validator.can_validate(&make_finding("slack-bot-token")));
        assert!(validator.can_validate(&make_finding("slack-user-token")));
        assert!(validator.can_validate(&make_finding("slack-webhook-url")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = SlackValidator::new(client);
        assert!(!validator.can_validate(&make_finding("github-pat")));
        assert!(!validator.can_validate(&make_finding("stripe-api-key")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = SlackValidator::new(client);
        assert_eq!(validator.provider_name(), "slack");
    }
}
