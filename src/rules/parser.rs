//! Rule parser — converts TOML rule configs into [`Rule`] structs.
//!
//! Supports three rule formats:
//!
//! | Format        | File extension       | Detection heuristic                   |
//! |---------------|----------------------|---------------------------------------|
//! | Squirrel      | `.squirrel.toml`     | Contains `squirrel.*` extension fields|
//! | Betterleaks   | `.betterleaks.toml`  | Contains `[[rules]]` (no squirrel key)|
//! | Gitleaks      | `.gitleaks.toml`     | Contains `[[rules]]` + `title` field  |
//!
//! Format auto-detection is best-effort and falls back to [`RuleFormat::Betterleaks`].

use crate::error::{Result, SquirrelError};
use crate::types::Severity;
use serde::{Deserialize, Serialize};

// ============================================================================
// Rule format enum
// ============================================================================

/// The on-disk format of a rule configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleFormat {
    /// Native Squirrel format with GPU hints and Markov thresholds.
    Squirrel,
    /// Betterleaks-compatible format (subset of Squirrel).
    Betterleaks,
    /// Gitleaks-compatible format (mapped to Squirrel fields on load).
    Gitleaks,
}

// ============================================================================
// Rule category
// ============================================================================

/// Broad category of the credential type a rule targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RuleCategory {
    /// Cloud provider credentials (AWS, GCP, Azure, etc.)
    Cloud,
    /// SaaS service tokens (Slack, Twilio, SendGrid, etc.)
    Saas,
    /// Developer tool credentials (GitHub, GitLab, npm, etc.)
    Devtools,
    /// Database connection strings and passwords
    Database,
    /// Cryptographic keys and certificates
    Crypto,
    /// AI/ML provider keys (OpenAI, Anthropic, HuggingFace, etc.)
    Ai,
    /// Payment processor credentials (Stripe, PayPal, etc.)
    Payments,
    /// Generic / catch-all patterns (password assignments, API keys)
    Generic,
    /// CI/CD service tokens (CircleCI, Travis CI, Jenkins, Buildkite)
    Ci,
    /// Messaging / event-bus service secrets (Kafka, RabbitMQ, Pusher, PubNub)
    Messaging,
    /// Identity provider secrets (Okta, Auth0, Keycloak, Cognito, Azure AD)
    Identity,
    /// Monitoring / observability service secrets (Sentry, New Relic, Grafana)
    Monitoring,
    /// Object storage secrets (MinIO, Backblaze B2, Cloudflare R2, Wasabi)
    Storage,
    /// Mobile app secrets (Google Maps, Firebase, iOS/Android, OneSignal)
    Mobile,
    /// IoT device and embedded systems secrets (MQTT, Particle, Arduino Cloud)
    Iot,
}

// ============================================================================
// Squirrel-specific extension block
// ============================================================================

/// Optional Squirrel-specific extensions that can be added to any rule.
///
/// These fields are ignored when loading Gitleaks/Betterleaks configs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquirrelExtension {
    /// GPU stage hint: `"entropy_first"` routes through entropy gate first,
    /// `"proximity_first"` routes through proximity filter first.
    pub gpu_hint: Option<String>,
    /// Override the global Markov randomness threshold for this rule.
    pub markov_threshold: Option<f32>,
    /// Additional context patterns to look for near the secret value.
    pub proximity_patterns: Option<Vec<String>>,
}

// ============================================================================
// Parsed Rule
// ============================================================================

/// A fully parsed rule, ready for compilation.
///
/// This is the intermediate representation between the on-disk TOML format
/// and the runtime [`CompiledRule`](crate::rules::compiler::CompiledRule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier (e.g., `"aws-access-key-id"`).
    pub id: String,

    /// Human-readable description of what this rule detects.
    pub description: String,

    /// Primary detection regex pattern.
    pub regex: String,

    /// Optional secondary regex to extract just the secret group.
    pub secret_group_regex: Option<String>,

    /// Keywords fed into the Aho-Corasick pre-filter.
    ///
    /// Fragments that contain none of these keywords are skipped before regex
    /// matching — dramatically reducing false-positive overhead.
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Severity level of findings produced by this rule.
    #[serde(default = "default_severity")]
    pub severity: Severity,

    /// Broad category for this rule.
    #[serde(default = "default_category")]
    pub category: RuleCategory,

    /// Arbitrary tags for filtering and reporting.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Regex patterns whose matches should be excluded from results (allowlist).
    ///
    /// If the matched text also matches any allowlist pattern, the finding
    /// is suppressed.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Per-rule entropy threshold override. If `None`, uses the global value.
    pub entropy_threshold: Option<f32>,

    /// Per-rule confidence weight override (0.0–1.0). If `None`, defaults to 1.0.
    pub confidence_weight: Option<f64>,

    /// Name of the validator to use (e.g., `"aws"`, `"github"`, `"stripe"`).
    pub validation_provider: Option<String>,

    /// Remediation guidance text for this rule.
    pub remediation: Option<String>,

    /// Squirrel-specific GPU and Markov extensions.
    pub squirrel: Option<SquirrelExtension>,
}

fn default_severity() -> Severity {
    Severity::Medium
}

fn default_category() -> RuleCategory {
    RuleCategory::Generic
}

// ============================================================================
// Gitleaks intermediate format
// ============================================================================

/// Intermediate struct for deserializing Gitleaks-format TOML.
///
/// Gitleaks uses slightly different field names that we map to our [`Rule`].
#[derive(Debug, Deserialize)]
struct GitleaksRule {
    id: String,
    #[serde(default)]
    description: String,
    // Gitleaks calls it `title` not `description`
    #[serde(default)]
    title: String,
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    allowlist: GitleaksAllowlist,
    entropy: Option<f32>,
}

#[derive(Debug, Default, Deserialize)]
struct GitleaksAllowlist {
    #[serde(default)]
    regexes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GitleaksConfig {
    #[serde(default)]
    rules: Vec<GitleaksRule>,
}

// ============================================================================
// Squirrel / Betterleaks intermediate format
// ============================================================================

#[derive(Debug, Deserialize)]
struct SquirrelConfig {
    #[serde(default)]
    rules: Vec<Rule>,
}

// ============================================================================
// Public parse functions
// ============================================================================

/// Parse a Squirrel (or Betterleaks) TOML rule config.
///
/// Both formats share the same schema — the distinction is purely in which
/// optional fields are present.
pub fn parse_squirrel_config(content: &str) -> Result<Vec<Rule>> {
    let config: SquirrelConfig = toml::from_str(content).map_err(|e| SquirrelError::RuleParse {
        path: "<inline>".to_string(),
        reason: e.to_string(),
    })?;
    Ok(config.rules)
}

/// Parse a Betterleaks TOML rule config (alias for [`parse_squirrel_config`]).
pub fn parse_betterleaks_config(content: &str) -> Result<Vec<Rule>> {
    parse_squirrel_config(content)
}

/// Parse a Gitleaks TOML rule config and map to Squirrel [`Rule`]s.
///
/// Field mapping:
///
/// | Gitleaks              | Squirrel            |
/// |-----------------------|---------------------|
/// | `title`               | `description`       |
/// | `entropy`             | `entropy_threshold` |
/// | `allowlist.regexes`   | `allowlist`         |
pub fn parse_gitleaks_config(content: &str) -> Result<Vec<Rule>> {
    let config: GitleaksConfig = toml::from_str(content).map_err(|e| SquirrelError::RuleParse {
        path: "<inline>".to_string(),
        reason: e.to_string(),
    })?;

    let rules = config
        .rules
        .into_iter()
        .map(|g| Rule {
            id: g.id,
            description: if g.description.is_empty() {
                g.title
            } else {
                g.description
            },
            regex: g.regex,
            secret_group_regex: None,
            keywords: g.keywords,
            severity: Severity::Medium, // Gitleaks has no severity field
            category: RuleCategory::Generic,
            tags: g.tags,
            allowlist: g.allowlist.regexes,
            entropy_threshold: g.entropy,
            confidence_weight: None,
            validation_provider: None,
            remediation: None,
            squirrel: None,
        })
        .collect();

    Ok(rules)
}

/// Auto-detect the format of a TOML rule config from its structure.
///
/// Detection heuristics (in priority order):
///
/// 1. If content contains `gpu_hint` or `markov_threshold` → [`RuleFormat::Squirrel`]
/// 2. If content contains a `title =` field → [`RuleFormat::Gitleaks`]
/// 3. Otherwise → [`RuleFormat::Betterleaks`]
pub fn detect_format(content: &str) -> RuleFormat {
    // Simple string-based heuristics — avoid full TOML parse overhead.
    if content.contains("gpu_hint") || content.contains("markov_threshold") {
        return RuleFormat::Squirrel;
    }
    if content.contains("title =") || content.contains("title=") {
        return RuleFormat::Gitleaks;
    }
    RuleFormat::Betterleaks
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SQUIRREL_TOML: &str = r#"
[[rules]]
id = "aws-access-key-id"
description = "AWS Access Key ID"
regex = 'AKIA[0-9A-Z]{16}'
keywords = ["AKIA"]
severity = "critical"
category = "cloud"
remediation = "Revoke at IAM console."

[[rules]]
id = "generic-password"
description = "Generic password assignment"
regex = '(?i)(password|passwd)\s*[:=]\s*\S{8,}'
keywords = ["password", "passwd"]
severity = "medium"
category = "generic"
"#;

    const GITLEAKS_TOML: &str = r#"
[[rules]]
id = "github-pat"
title = "GitHub Personal Access Token"
regex = 'ghp_[a-zA-Z0-9]{36}'
keywords = ["ghp_"]
entropy = 3.5

  [rules.allowlist]
  regexes = ['ghp_test.*']
"#;

    #[test]
    fn test_parse_squirrel_config() {
        let rules = parse_squirrel_config(SQUIRREL_TOML).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "aws-access-key-id");
        assert_eq!(rules[0].severity, Severity::Critical);
        assert_eq!(rules[0].category, RuleCategory::Cloud);
        assert!(rules[0].remediation.is_some());
    }

    #[test]
    fn test_parse_gitleaks_config() {
        let rules = parse_gitleaks_config(GITLEAKS_TOML).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "github-pat");
        assert_eq!(rules[0].description, "GitHub Personal Access Token");
        assert_eq!(rules[0].entropy_threshold, Some(3.5));
        assert_eq!(rules[0].allowlist, vec!["ghp_test.*".to_string()]);
    }

    #[test]
    fn test_detect_format_squirrel() {
        let content = "[[rules]]\ngpu_hint = \"entropy_first\"\n";
        assert_eq!(detect_format(content), RuleFormat::Squirrel);
    }

    #[test]
    fn test_detect_format_gitleaks() {
        let content = "[[rules]]\ntitle = \"My Rule\"\n";
        assert_eq!(detect_format(content), RuleFormat::Gitleaks);
    }

    #[test]
    fn test_detect_format_betterleaks() {
        let content = "[[rules]]\nid = \"test\"\ndescription = \"test\"\n";
        assert_eq!(detect_format(content), RuleFormat::Betterleaks);
    }

    #[test]
    fn test_rule_defaults() {
        let toml = r#"
[[rules]]
id = "min-rule"
description = "Minimal rule"
regex = "test"
"#;
        let rules = parse_squirrel_config(toml).unwrap();
        assert_eq!(rules[0].severity, Severity::Medium);
        assert_eq!(rules[0].category, RuleCategory::Generic);
        assert!(rules[0].keywords.is_empty());
        assert!(rules[0].allowlist.is_empty());
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        let bad = "[[rules\nid = broken toml}}";
        assert!(parse_squirrel_config(bad).is_err());
    }

    #[test]
    fn test_betterleaks_alias() {
        let rules = parse_betterleaks_config(SQUIRREL_TOML).unwrap();
        assert_eq!(rules.len(), 2);
    }
}
