//! Core validation engine — dispatches findings to provider-specific validators.
//!
//! # Design
//!
//! [`ValidationEngine`] holds a list of [`Validator`] trait objects. When
//! [`validate_finding`] is called it walks the list and delegates to the first
//! validator whose [`can_validate`] returns `true`. Rate limiting and circuit
//! breaking are the responsibility of the individual validators (they receive a
//! shared `reqwest::Client` and can consult `ProviderRateLimiter`/
//! `CircuitBreaker` via `Arc` if needed).
//!
//! [`validate_finding`]: ValidationEngine::validate_finding
//! [`can_validate`]: Validator::can_validate

use crate::types::{Finding, ValidationStatus};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// The result of attempting to validate a single credential finding.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    /// Outcome of the validation attempt.
    pub status: ValidationStatus,
    /// Human-readable explanation of the status.
    pub reason: String,
    /// Blast-radius assessment (populated when status is `Active`).
    pub blast_radius: Option<super::blast_radius::BlastRadius>,
    /// UTC timestamp of when validation was performed.
    pub validated_at: DateTime<Utc>,
    /// Name of the provider/validator that produced this result.
    pub provider: String,
}

impl ValidationResult {
    /// Construct a simple result with no blast-radius information.
    pub fn simple(
        status: ValidationStatus,
        reason: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        Self {
            status,
            reason: reason.into(),
            blast_radius: None,
            validated_at: Utc::now(),
            provider: provider.into(),
        }
    }

    /// Construct a result indicating a network or parsing error.
    pub fn error(reason: impl Into<String>, provider: impl Into<String>) -> Self {
        Self::simple(ValidationStatus::Error, reason, provider)
    }

    /// Construct a result indicating the validator cannot determine the status.
    pub fn needs_validation(reason: impl Into<String>, provider: impl Into<String>) -> Self {
        Self::simple(ValidationStatus::NeedsValidation, reason, provider)
    }
}

/// A provider-specific credential validator.
///
/// Implementors must be [`Send`] + [`Sync`] because the engine may run them
/// concurrently. Validators **must not** log or store the raw secret value;
/// they should only call [`RedactedString::expose`] within the hot-path of
/// the HTTP request and discard the reference immediately afterwards.
///
/// [`RedactedString::expose`]: crate::types::RedactedString::expose
#[async_trait::async_trait]
pub trait Validator: Send + Sync {
    /// Short, stable identifier for this provider (e.g. `"github"`, `"aws"`).
    fn provider_name(&self) -> &str;

    /// Returns `true` if this validator can handle the given finding.
    ///
    /// Typically checks `finding.rule_id.starts_with("<provider>-")`.
    fn can_validate(&self, finding: &Finding) -> bool;

    /// Perform the live validation. This method **must not** panic.
    ///
    /// On any network or parsing failure, return a [`ValidationResult`] with
    /// `status = ValidationStatus::Error` rather than propagating an error —
    /// validation failures should never abort a scan.
    async fn validate(&self, finding: &Finding) -> ValidationResult;
}

/// The top-level validation engine.
///
/// # Example
///
/// ```rust,ignore
/// use secret_squirrel::validate::{ValidationEngine};
///
/// let engine = ValidationEngine::new();
/// if let Some(result) = engine.validate_finding(&finding).await {
///     println!("Status: {:?}", result.status);
/// }
/// ```
pub struct ValidationEngine {
    /// Ordered list of validators. The first one whose `can_validate` returns
    /// `true` wins.
    validators: Vec<Box<dyn Validator>>,
    /// Shared HTTP client (connection pool, TLS, timeout configured once).
    /// Exposed `pub(crate)` so sub-modules can reuse the connection pool
    /// without building an additional client.
    #[allow(dead_code)]
    pub(crate) http_client: reqwest::Client,
}

impl ValidationEngine {
    /// Build a new engine with the default set of validators.
    ///
    /// The HTTP client is configured with:
    /// - `redirect::Policy::none()` — we never want automatic redirects during
    ///   credential checks (a redirect to a login page could be a false
    ///   negative)
    /// - 5-second timeout per request
    /// - `User-Agent: secret-squirrel/<version>`
    pub fn new() -> Self {
        let client = Self::build_client();
        let validators = crate::validate::providers::all_validators(&client);
        Self {
            validators,
            http_client: client,
        }
    }

    /// Build a new engine with a custom list of validators.
    pub fn with_validators(validators: Vec<Box<dyn Validator>>) -> Self {
        let client = Self::build_client();
        Self {
            validators,
            http_client: client,
        }
    }

    /// Build the shared `reqwest::Client`.
    fn build_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .user_agent(concat!("secret-squirrel/", env!("CARGO_PKG_VERSION")))
            // Prefer rustls to avoid OpenSSL linking issues
            .build()
            .expect("Failed to build reqwest client — this is a programming error")
    }

    /// Validate a single finding.
    ///
    /// Returns `None` if no validator can handle this finding's rule ID.
    /// Returns `Some(ValidationResult)` otherwise — even on network errors
    /// the result is wrapped rather than propagated.
    ///
    /// # Security
    ///
    /// This function only passes the finding reference to a validator. It does
    /// not log or store `finding.secret` at any point.
    pub async fn validate_finding(&self, finding: &Finding) -> Option<ValidationResult> {
        for validator in &self.validators {
            if validator.can_validate(finding) {
                tracing::debug!(
                    finding_id = %finding.id,
                    rule_id = %finding.rule_id,
                    provider = %validator.provider_name(),
                    "Dispatching to validator"
                );
                let result = validator.validate(finding).await;
                return Some(result);
            }
        }
        tracing::debug!(
            finding_id = %finding.id,
            rule_id = %finding.rule_id,
            "No validator found for rule_id"
        );
        None
    }

    /// Returns the names of all registered providers.
    pub fn provider_names(&self) -> Vec<&str> {
        self.validators.iter().map(|v| v.provider_name()).collect()
    }
}

impl Default for ValidationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================
// Tests
// ===========================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, FusedScore, Location, RedactedString, Severity, ValidationStatus};
    use chrono::Utc;

    /// Build a minimal `Finding` for testing. The `rule_id` is parameterisable.
    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            id: "test-id".to_string(),
            rule_id: rule_id.to_string(),
            description: "test finding".to_string(),
            secret: RedactedString::new("sk-test1234567890".to_string()),
            secret_hash: "deadbeef".to_string(),
            match_context: "ctx".to_string(),
            location: Location {
                path: "test.py".to_string(),
                start_line: 1,
                end_line: 1,
                start_col: 0,
                end_col: 20,
                byte_offset: 0,
            },
            score: FusedScore {
                confidence: 0.95,
                entropy: 0.8,
                proximity: 0.9,
                tristream: 0.85,
                pattern: 0.99,
                markov: 0.7,
                cnn_score: None,
                ast_adjustment: None,
            },
            severity: Severity::Critical,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    /// A minimal stub validator for testing dispatch.
    struct StubValidator {
        prefix: &'static str,
        name: &'static str,
    }

    #[async_trait::async_trait]
    impl Validator for StubValidator {
        fn provider_name(&self) -> &str {
            self.name
        }

        fn can_validate(&self, finding: &Finding) -> bool {
            finding.rule_id.starts_with(self.prefix)
        }

        async fn validate(&self, _finding: &Finding) -> ValidationResult {
            ValidationResult::simple(ValidationStatus::Active, "stub active", self.name)
        }
    }

    #[tokio::test]
    async fn test_engine_dispatches_to_correct_validator() {
        let engine = ValidationEngine::with_validators(vec![
            Box::new(StubValidator {
                prefix: "github-",
                name: "github",
            }),
            Box::new(StubValidator {
                prefix: "aws-",
                name: "aws",
            }),
        ]);

        let gh_finding = make_finding("github-token");
        let result = engine.validate_finding(&gh_finding).await.unwrap();
        assert_eq!(result.provider, "github");

        let aws_finding = make_finding("aws-access-key-id");
        let result = engine.validate_finding(&aws_finding).await.unwrap();
        assert_eq!(result.provider, "aws");
    }

    #[tokio::test]
    async fn test_engine_returns_none_for_unknown_rule() {
        let engine = ValidationEngine::with_validators(vec![Box::new(StubValidator {
            prefix: "github-",
            name: "github",
        })]);

        let unknown = make_finding("custom-internal-key");
        assert!(engine.validate_finding(&unknown).await.is_none());
    }

    #[tokio::test]
    async fn test_engine_returns_first_matching_validator() {
        let engine = ValidationEngine::with_validators(vec![
            Box::new(StubValidator {
                prefix: "aws-",
                name: "first",
            }),
            Box::new(StubValidator {
                prefix: "aws-",
                name: "second",
            }),
        ]);

        let finding = make_finding("aws-access-key-id");
        let result = engine.validate_finding(&finding).await.unwrap();
        // Should dispatch to the first matching validator
        assert_eq!(result.provider, "first");
    }

    #[test]
    fn test_validation_result_simple() {
        let r = ValidationResult::simple(ValidationStatus::Inactive, "key revoked", "github");
        assert_eq!(r.provider, "github");
        assert_eq!(r.reason, "key revoked");
        assert!(r.blast_radius.is_none());
    }

    #[test]
    fn test_provider_names() {
        let engine = ValidationEngine::with_validators(vec![
            Box::new(StubValidator {
                prefix: "a-",
                name: "alpha",
            }),
            Box::new(StubValidator {
                prefix: "b-",
                name: "beta",
            }),
        ]);
        let names = engine.provider_names();
        assert_eq!(names, vec!["alpha", "beta"]);
    }
}
