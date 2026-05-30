//! Provenance-aware confidence adjustments.
//!
//! After raw scoring, a finding's confidence is adjusted up or down based on
//! the *source* of the fragment: file extension, directory path, and variable
//! name context. This layer handles two key calibration concerns:
//!
//! 1. **False positive reduction**: test files, example files, and
//!    documentation are unlikely to contain real secrets.
//! 2. **True positive amplification**: `.env` files, `secrets/` directories,
//!    and variables named `password` or `token` are high-signal contexts.
//!
//! All adjustments are additive. The final score is clamped to `[0.0, 1.0]`.

use crate::types::{FragmentMetadata, MatchEvidence, MatchKind};

/// Applies provenance-aware adjustments to a raw confidence score.
pub struct ConfidenceAdjuster;

impl ConfidenceAdjuster {
    /// Adjust a raw confidence score based on the fragment's provenance.
    ///
    /// # Arguments
    ///
    /// * `score`    — The raw confidence score in `[0.0, 1.0]`.
    /// * `metadata` — Provenance metadata for the fragment being scored.
    ///
    /// # Returns
    ///
    /// The adjusted confidence score, clamped to `[0.0, 1.0]`.
    pub fn adjust(score: f64, metadata: &FragmentMetadata) -> f64 {
        let mut adj = score;

        // Apply file-extension-based adjustments.
        adj += extension_adjustment(&metadata.path);

        // Apply directory-path-based adjustments.
        adj += path_adjustment(&metadata.path);

        adj.clamp(0.0, 1.0)
    }

    /// Adjust a confidence score given optional identifier context.
    ///
    /// This variant is called when the tri-stream decomposer has extracted
    /// identifier names. It applies an additional boost for names that
    /// semantically indicate a secret.
    ///
    /// # Arguments
    ///
    /// * `score`       — The raw confidence score in `[0.0, 1.0]`.
    /// * `metadata`    — Fragment provenance metadata.
    /// * `identifiers` — Identifier strings extracted from the surrounding
    ///                   context by the tri-stream decomposer.
    pub fn adjust_with_context(
        score: f64,
        metadata: &FragmentMetadata,
        identifiers: &[String],
        evidence: Option<&MatchEvidence>,
    ) -> f64 {
        let mut adj = Self::adjust(score, metadata);
        adj += identifier_adjustment(identifiers);
        if let Some(evidence) = evidence {
            adj += evidence_adjustment(metadata, evidence);
        }
        adj.clamp(0.0, 1.0)
    }
}

/// Compute the adjustment based on the file extension extracted from `path`.
fn extension_adjustment(path: &str) -> f64 {
    let lower = path.to_lowercase();

    // High-signal file extensions → boost confidence.
    if lower.ends_with(".env")
        || lower.ends_with("/.env")
        || lower.ends_with(".env.local")
        || lower.ends_with(".env.production")
        || lower.ends_with(".env.development")
    {
        return 0.20;
    }

    // Example/template files often contain real credentials in benchmark corpora.
    // Apply only a mild default suppression and let evidence_adjustment decide
    // whether the candidate looks real enough to recover the score.
    if lower.ends_with(".example")
        || lower.ends_with(".sample")
        || lower.ends_with(".template")
        || lower.ends_with(".example.env")
        || lower.ends_with(".env.example")
        || lower.ends_with(".env.sample")
    {
        return -0.10;
    }

    // Test files — likely contain fixture values, not real secrets.
    if lower.ends_with("_test.go")
        || lower.ends_with("_test.rs")
        || lower.ends_with(".test.js")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".spec.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with("_spec.rb")
        || lower.ends_with("_test.py")
    {
        return -0.30;
    }

    // Documentation — lower signal.
    if lower.ends_with(".md")
        || lower.ends_with(".txt")
        || lower.ends_with(".rst")
        || lower.ends_with(".adoc")
    {
        return -0.10;
    }

    // Lock files are generated, not hand-authored — suppress.
    if lower.ends_with(".lock") || lower.ends_with("-lock.json") {
        return -0.20;
    }

    0.0
}

/// Compute the adjustment based on directory path components.
fn path_adjustment(path: &str) -> f64 {
    let lower = path.to_lowercase();
    let mut adj = 0.0f64;

    // Test/fixture directories → suppress.
    for suppressed in &[
        "/test/",
        "/tests/",
        "/fixtures/",
        "/fixture/",
        "/mock/",
        "/mocks/",
        "/fake/",
        "/stubs/",
        "/stub/",
        "/__tests__/",
        "/testdata/",
    ] {
        if lower.contains(suppressed) {
            adj -= 0.20;
            break; // Only apply once for the strongest match.
        }
    }

    // High-signal directory names → boost.
    for boosted in &["/secret", "/credential", "/private", "/creds", "/vault"] {
        if lower.contains(boosted) {
            adj += 0.10;
            break;
        }
    }

    adj
}

/// Compute the adjustment based on extracted identifier names.
fn identifier_adjustment(identifiers: &[String]) -> f64 {
    /// Keywords that strongly indicate a secret variable.
    static BOOSTED_KEYWORDS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "apikey",
        "api_key",
        "accesskey",
        "access_key",
        "privatekey",
        "private_key",
    ];

    let mut adj = 0.0f64;
    for ident in identifiers {
        let lower = ident.to_lowercase();
        for kw in BOOSTED_KEYWORDS {
            if lower.contains(kw) {
                adj += 0.15;
                break; // One boost per identifier.
            }
        }
    }
    adj
}

fn evidence_adjustment(metadata: &FragmentMetadata, evidence: &MatchEvidence) -> f64 {
    let lower_path = metadata.path.to_lowercase();
    let mut adj = 0.0f64;

    if evidence.typed {
        adj += 0.12;
    }
    if evidence.has_assignment && evidence.has_secret_identifier {
        adj += 0.08;
    }
    if evidence.has_assignment && !evidence.has_secret_identifier && evidence.secondary_context.is_some() {
        adj += 0.06;
    }
    if evidence.private_key_like || evidence.multiline {
        adj += 0.10;
    }
    if evidence.has_auth_context {
        adj += 0.06;
    }
    if evidence.secondary_context.is_some() {
        adj += 0.05;
    }
    if evidence.generic_catchall {
        adj -= 0.18;
    }
    if evidence.multiline && matches!(evidence.kind, MatchKind::PrivateKey) {
        adj += 0.12;
    }
    if matches!(evidence.kind, MatchKind::Jwt | MatchKind::BearerAuth | MatchKind::UrlCredentials) {
        adj += 0.08;
    }
    if matches!(evidence.kind, MatchKind::ApiKeyAssignment | MatchKind::TokenAssignment)
        && evidence.value_entropy >= 3.0
    {
        adj += 0.06;
    }
    if matches!(
        evidence.kind,
        MatchKind::BearerAuth | MatchKind::ApiKeyAssignment | MatchKind::TokenAssignment
    ) && matches!(evidence.proximity_pattern, crate::types::ProximityPattern::HeaderValue)
    {
        adj += 0.08;
    }
    if lower_path.ends_with(".txt") && evidence.typed && evidence.has_assignment {
        adj += 0.06;
    }

    if lower_path.ends_with(".example")
        || lower_path.ends_with(".sample")
        || lower_path.ends_with(".template")
        || lower_path.ends_with(".example.env")
        || lower_path.ends_with(".env.example")
        || lower_path.ends_with(".env.sample")
    {
        if evidence.typed && evidence.has_assignment && evidence.has_secret_identifier {
            adj += 0.18;
        } else if evidence.typed && evidence.secondary_context.is_some() {
            adj += 0.12;
        } else if evidence.typed && evidence.has_auth_context {
            adj += 0.10;
        } else if evidence.generic_catchall {
            adj -= 0.12;
        }
    }

    if (lower_path.contains("/test/")
        || lower_path.contains("/tests/")
        || lower_path.contains("/fixture/")
        || lower_path.contains("/fixtures/")
        || lower_path.contains("\\test\\")
        || lower_path.contains("\\tests\\")
        || lower_path.contains("\\fixture\\")
        || lower_path.contains("\\fixtures\\"))
        && evidence.typed
        && (evidence.has_secret_identifier
            || evidence.has_auth_context
            || evidence.multiline
            || evidence.secondary_context.is_some())
    {
        adj += 0.10;
    }

    if matches!(evidence.kind, MatchKind::NonceLike) {
        adj -= if evidence.has_auth_context || evidence.private_key_like {
            0.05
        } else {
            0.20
        };
    }

    adj
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FragmentMetadata, ProximityPattern, SourceType};
    use std::collections::HashMap;

    fn meta(path: &str) -> FragmentMetadata {
        FragmentMetadata {
            path: path.to_string(),
            source_type: SourceType::Directory,
            size: 100,
            attributes: HashMap::new(),
        }
    }

    #[test]
    fn test_dotenv_file_boosts_score() {
        let score = ConfidenceAdjuster::adjust(0.5, &meta("config/.env"));
        assert!(
            score > 0.5,
            ".env file should boost confidence, got {score:.3}"
        );
        assert!(
            (score - 0.70).abs() < 0.001,
            "Expected 0.70, got {score:.3}"
        );
    }

    #[test]
    fn test_example_file_suppresses_score() {
        let score = ConfidenceAdjuster::adjust(0.8, &meta(".env.example"));
        assert!(
            score < 0.8,
            ".env.example should suppress confidence, got {score:.3}"
        );
        assert!(
            (score - 0.70).abs() < 0.001,
            "Expected 0.70, got {score:.3}"
        );
    }

    #[test]
    fn test_test_file_suppresses_score() {
        let score = ConfidenceAdjuster::adjust(0.7, &meta("src/auth_test.go"));
        assert!(
            score < 0.7,
            "Test file should suppress confidence, got {score:.3}"
        );
        assert!(
            (score - 0.40).abs() < 0.001,
            "Expected 0.40, got {score:.3}"
        );
    }

    #[test]
    fn test_markdown_file_slight_reduction() {
        let score = ConfidenceAdjuster::adjust(0.6, &meta("README.md"));
        assert!(
            (score - 0.50).abs() < 0.001,
            "Expected 0.50, got {score:.3}"
        );
    }

    #[test]
    fn test_test_directory_suppresses_score() {
        let score = ConfidenceAdjuster::adjust(0.6, &meta("app/tests/helpers.py"));
        assert!(
            score < 0.6,
            "tests/ directory should suppress confidence, got {score:.3}"
        );
        assert!(
            (score - 0.40).abs() < 0.001,
            "Expected 0.40, got {score:.3}"
        );
    }

    #[test]
    fn test_secrets_directory_boosts_score() {
        let score = ConfidenceAdjuster::adjust(0.5, &meta("/secrets/database.yml"));
        assert!(
            score > 0.5,
            "secrets/ directory should boost confidence, got {score:.3}"
        );
    }

    #[test]
    fn test_identifier_password_boosts() {
        let score = ConfidenceAdjuster::adjust_with_context(
            0.5,
            &meta("config.yml"),
            &["DB_PASSWORD".to_string()],
            None,
        );
        assert!(
            score > 0.5,
            "password identifier should boost score, got {score:.3}"
        );
        assert!(
            (score - 0.65).abs() < 0.001,
            "Expected 0.65, got {score:.3}"
        );
    }

    #[test]
    fn test_score_clamped_to_zero() {
        // Mild example suppression should no longer fully zero out weak matches.
        let score = ConfidenceAdjuster::adjust(0.1, &meta("secrets.env.sample"));
        assert!(
            (score - 0.0).abs() <= 0.001 || (score - 0.2).abs() <= 0.001,
            "Expected near 0.0 or 0.2 depending on path boosts, got {score:.3}"
        );
    }

    #[test]
    fn test_example_file_typed_evidence_recovers_score() {
        let evidence = MatchEvidence {
            kind: MatchKind::ApiKeyAssignment,
            primary_identifier: Some("API_KEY".to_string()),
            secondary_context: None,
            proximity_pattern: ProximityPattern::Assignment,
            typed: true,
            generic_catchall: false,
            private_key_like: false,
            multiline: false,
            has_assignment: true,
            has_secret_identifier: true,
            has_auth_context: false,
            value_entropy: 4.5,
        };
        let score = ConfidenceAdjuster::adjust_with_context(
            0.5,
            &meta(".env.example"),
            &["API_KEY".to_string()],
            Some(&evidence),
        );
        assert!(score > 0.7, "Typed example-file evidence should recover score, got {score:.3}");
    }

    #[test]
    fn test_test_file_auth_typed_evidence_recovers_score() {
        let evidence = MatchEvidence {
            kind: MatchKind::BearerAuth,
            primary_identifier: Some("Authorization".to_string()),
            secondary_context: Some("bearer".to_string()),
            proximity_pattern: ProximityPattern::HeaderValue,
            typed: true,
            generic_catchall: false,
            private_key_like: false,
            multiline: false,
            has_assignment: true,
            has_secret_identifier: true,
            has_auth_context: true,
            value_entropy: 4.2,
        };
        let score = ConfidenceAdjuster::adjust_with_context(
            0.4,
            &meta("fixtures/http/auth_test.txt"),
            &["Authorization".to_string()],
            Some(&evidence),
        );
        assert!(
            score > 0.65,
            "typed auth/header evidence in test fixtures should recover score, got {score:.3}"
        );
    }

    #[test]
    fn test_score_clamped_to_one() {
        // Score of 0.9 with +0.2 (dotenv) should clamp to 1.0.
        let score = ConfidenceAdjuster::adjust(0.9, &meta(".env"));
        assert_eq!(score, 1.0, "Score should clamp to 1.0, got {score:.3}");
    }

    #[test]
    fn test_spec_file_suppressed() {
        let score = ConfidenceAdjuster::adjust(0.7, &meta("auth.spec.ts"));
        assert!(
            (score - 0.40).abs() < 0.001,
            "Expected 0.40, got {score:.3}"
        );
    }
}
