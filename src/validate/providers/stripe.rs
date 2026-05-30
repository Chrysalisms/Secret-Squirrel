//! Stripe credential validator.
//!
//! Validates Stripe API keys by calling `GET https://api.stripe.com/v1/account`.
//!
//! # Response interpretation
//!
//! | HTTP status | `ValidationStatus` |
//! |-------------|-------------------|
//! | 200         | `Active`          |
//! | 401         | `Inactive`        |
//! | other       | `Error`           |
//!
//! Stripe distinguishes between live keys (`sk_live_*`) and test keys
//! (`sk_test_*`). Both are validated the same way; the key prefix is noted in
//! the blast radius description.

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::{BlastRadius, RiskLevel},
    engine::{ValidationResult, Validator},
};

/// Validates Stripe API credentials.
pub struct StripeValidator {
    client: reqwest::Client,
}

impl StripeValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for StripeValidator {
    fn provider_name(&self) -> &str {
        "stripe"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("stripe-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: expose() is called only to check if it is a test key
        // and to build the Authorization header. The value is not logged.
        let token = finding.secret.expose().to_string();
        let is_live_key = token.starts_with("sk_live_");
        let is_test_key = token.starts_with("sk_test_");
        let key_type = if is_live_key {
            "LIVE"
        } else if is_test_key {
            "TEST"
        } else {
            "unknown"
        };

        let response = match self
            .client
            .get("https://api.stripe.com/v1/account")
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "Stripe validation: network error"
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
            key_type,
            "Stripe validation response"
        );

        match http_status.as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await.unwrap_or_default();
                let account_id = body["id"].as_str().unwrap_or("<unknown>");
                let business_name = body
                    .get("business_profile")
                    .and_then(|bp| bp["name"].as_str())
                    .unwrap_or("<unknown>");

                // Live keys are Critical; test keys are High (no real money)
                let risk_level = if is_live_key {
                    RiskLevel::Critical
                } else {
                    RiskLevel::High
                };

                let blast_radius = BlastRadius {
                    provider: "stripe".to_string(),
                    permissions: vec![
                        "charges:write".to_string(),
                        "customers:write".to_string(),
                        "payouts:write".to_string(),
                    ],
                    resources: vec![format!("stripe.com/account/{account_id}")],
                    risk_level,
                    description: format!(
                        "Active Stripe {key_type} key for account '{account_id}' \
                         ({business_name}). Can create charges and manage customers."
                    ),
                };

                ValidationResult {
                    status: ValidationStatus::Active,
                    reason: format!(
                        "Stripe {key_type} key is active (account: {account_id}, \
                         business: {business_name})"
                    ),
                    blast_radius: Some(blast_radius),
                    validated_at: chrono::Utc::now(),
                    provider: self.provider_name().to_string(),
                }
            }
            401 => {
                // Stripe 401 body has an error code
                let body: serde_json::Value = response.json().await.unwrap_or_default();
                let code = body["error"]["code"].as_str().unwrap_or("unknown");
                ValidationResult::simple(
                    ValidationStatus::Inactive,
                    format!("Key rejected: 401 Unauthorized (Stripe error code: {code})"),
                    self.provider_name(),
                )
            }
            other => ValidationResult::error(
                format!("Unexpected HTTP {other} from Stripe API"),
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
            secret: RedactedString::new("sk_test_testkey1234567890".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "settings.py".to_string(),
                start_line: 42,
                end_line: 42,
                start_col: 0,
                end_col: 25,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.98,
                entropy: 0.88,
                proximity: 0.9,
                tristream: 0.9,
                pattern: 0.99,
                markov: 0.8,
                cnn_score: None,
                ast_adjustment: None,
            },
            evidence: Default::default(),
            severity: Severity::Critical,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    #[test]
    fn test_can_validate_stripe_rules() {
        let client = reqwest::Client::new();
        let validator = StripeValidator::new(client);
        assert!(validator.can_validate(&make_finding("stripe-api-key")));
        assert!(validator.can_validate(&make_finding("stripe-restricted-key")));
        assert!(validator.can_validate(&make_finding("stripe-live-key")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = StripeValidator::new(client);
        assert!(!validator.can_validate(&make_finding("openai-api-key")));
        assert!(!validator.can_validate(&make_finding("github-pat")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = StripeValidator::new(client);
        assert_eq!(validator.provider_name(), "stripe");
    }
}
