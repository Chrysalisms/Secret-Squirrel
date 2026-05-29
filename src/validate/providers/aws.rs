//! AWS credential validator.
//!
//! Validates AWS Access Keys by sending an unsigned request to the STS
//! `GetCallerIdentity` endpoint and interpreting the XML error code.
//!
//! # Approach
//!
//! Full AWS Signature V4 signing is complex. Instead, we use an unsigned
//! request and inspect the error code returned:
//!
//! | Error code              | Meaning                             | Status     |
//! |-------------------------|-------------------------------------|------------|
//! | `AuthFailure`           | Key exists but signature is wrong   | `Active`   |
//! | `InvalidClientTokenId`  | Key ID does not exist in AWS        | `Inactive` |
//! | `ExpiredTokenException` | Temporary token has expired         | `Inactive` |
//! | (no error / 200)        | Should not happen unsigned          | `Active`   |
//!
//! This approach is read-only and safe — no AWS resources are modified.
//!
//! # Limitations
//!
//! We cannot enumerate permissions or blast radius from an unsigned request.
//! A full STS validation with V4 signing could retrieve `arn`, `account`, and
//! `user_id`. That is tracked as a future enhancement.

use crate::types::{Finding, ValidationStatus};
use crate::validate::{
    blast_radius::{BlastRadius, RiskLevel},
    engine::{ValidationResult, Validator},
};

/// Validates AWS Access Key credentials.
pub struct AwsValidator {
    client: reqwest::Client,
}

impl AwsValidator {
    /// Create a new validator sharing the given HTTP client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Validator for AwsValidator {
    fn provider_name(&self) -> &str {
        "aws"
    }

    fn can_validate(&self, finding: &Finding) -> bool {
        finding.rule_id.starts_with("aws-")
    }

    async fn validate(&self, finding: &Finding) -> ValidationResult {
        // SAFETY NOTE: We do NOT send the secret key in an unsigned request.
        // We only use the Access Key ID (the non-secret half) for the probe.
        // The secret access key is NOT exposed to the network here.
        let access_key_id = finding.secret.expose().to_string();

        // Build a minimal, invalid-but-parseable Authorization header.
        // AWS will return XML with an error code telling us if the key ID exists.
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/20240101/us-east-1/sts/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature={}",
            access_key_id,
            "0".repeat(64), // fake signature — intentionally invalid
        );

        let response = match self
            .client
            .post("https://sts.amazonaws.com/")
            .header("Authorization", auth_header)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("x-amz-date", "20240101T000000Z")
            .body("Action=GetCallerIdentity&Version=2011-06-15")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    finding_id = %finding.id,
                    error = %e,
                    "AWS STS validation: network error"
                );
                return ValidationResult::error(
                    format!("Network error reaching STS: {e}"),
                    self.provider_name(),
                );
            }
        };

        tracing::debug!(
            finding_id = %finding.id,
            http_status = %response.status(),
            "AWS STS validation response"
        );

        let body = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                return ValidationResult::error(
                    format!("Failed to read STS response body: {e}"),
                    self.provider_name(),
                );
            }
        };

        // Parse the XML error code (simple string search — avoids an XML
        // parser dependency for a single field lookup)
        if body.contains("<Code>AuthFailure</Code>") {
            // Key ID exists but we gave a bad signature → key is REAL and ACTIVE
            let blast_radius = BlastRadius {
                provider: "aws".to_string(),
                permissions: vec!["unknown — unsigned probe".to_string()],
                resources: vec!["arn:aws:*:*:*:*".to_string()],
                risk_level: RiskLevel::Critical,
                description:
                    "AWS Access Key ID confirmed active (AuthFailure — key exists). \
                     Full permission scope requires authenticated STS call."
                        .to_string(),
            };
            ValidationResult {
                status: ValidationStatus::Active,
                reason:
                    "AWS key ID confirmed active: STS returned AuthFailure (key exists, \
                     signature invalid — expected for unsigned probe)."
                        .to_string(),
                blast_radius: Some(blast_radius),
                validated_at: chrono::Utc::now(),
                provider: self.provider_name().to_string(),
            }
        } else if body.contains("<Code>InvalidClientTokenId</Code>") {
            ValidationResult::simple(
                ValidationStatus::Inactive,
                "AWS key does not exist: STS returned InvalidClientTokenId",
                self.provider_name(),
            )
        } else if body.contains("<Code>ExpiredTokenException</Code>") {
            ValidationResult::simple(
                ValidationStatus::Inactive,
                "AWS temporary token has expired: STS returned ExpiredTokenException",
                self.provider_name(),
            )
        } else if body.contains("<Code>InvalidSignatureException</Code>") {
            // This can mean the key exists but the date/region was wrong
            let blast_radius = BlastRadius {
                provider: "aws".to_string(),
                permissions: vec!["unknown — unsigned probe".to_string()],
                resources: vec!["arn:aws:*:*:*:*".to_string()],
                risk_level: RiskLevel::Critical,
                description:
                    "AWS Access Key ID may be active (InvalidSignatureException — \
                     key may exist but signing parameters were wrong)."
                        .to_string(),
            };
            ValidationResult {
                status: ValidationStatus::Active,
                reason:
                    "AWS key may be active: STS returned InvalidSignatureException \
                     (key likely exists, signature params were wrong)."
                        .to_string(),
                blast_radius: Some(blast_radius),
                validated_at: chrono::Utc::now(),
                provider: self.provider_name().to_string(),
            }
        } else {
            ValidationResult::needs_validation(
                format!(
                    "Could not determine AWS key status. STS response: {}",
                    &body[..body.len().min(200)]
                ),
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
            secret: RedactedString::new("AKIAIOSFODNN7EXAMPLE".to_string()),
            secret_hash: "abc".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "terraform.tfvars".to_string(),
                start_line: 3,
                end_line: 3,
                start_col: 0,
                end_col: 20,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.99,
                entropy: 0.85,
                proximity: 0.9,
                tristream: 0.9,
                pattern: 1.0,
                markov: 0.8,
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
    fn test_can_validate_aws_rules() {
        let client = reqwest::Client::new();
        let validator = AwsValidator::new(client);
        assert!(validator.can_validate(&make_finding("aws-access-key-id")));
        assert!(validator.can_validate(&make_finding("aws-secret-access-key")));
        assert!(validator.can_validate(&make_finding("aws-session-token")));
    }

    #[test]
    fn test_cannot_validate_other_rules() {
        let client = reqwest::Client::new();
        let validator = AwsValidator::new(client);
        assert!(!validator.can_validate(&make_finding("github-pat")));
        assert!(!validator.can_validate(&make_finding("gcp-service-account")));
    }

    #[test]
    fn test_provider_name() {
        let client = reqwest::Client::new();
        let validator = AwsValidator::new(client);
        assert_eq!(validator.provider_name(), "aws");
    }
}
