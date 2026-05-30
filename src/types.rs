use bytes::Bytes;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use zeroize::ZeroizeOnDrop;

// ============================
// RedactedString
// ============================

/// A secret value that is never fully exposed in logs, output, or debug prints.
///
/// The inner string is wrapped in `secrecy::SecretString` and zeroed on Drop.
/// Display uses a tiered redaction strategy — never more than 40% visible.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RedactedString {
    #[zeroize(skip)]
    inner: SecretString,
    /// Character length (not byte length — computed at construction for safe slicing)
    char_len: usize,
}

impl RedactedString {
    /// Create a new RedactedString from a plain String.
    pub fn new(s: String) -> Self {
        let char_len = s.chars().count();
        Self {
            inner: SecretString::new(s.into()),
            char_len,
        }
    }

    /// Return a redacted display string. Never exposes > 40% of the value.
    /// Uses char-safe iteration (never byte indexing into UTF-8).
    pub fn redacted(&self) -> String {
        use secrecy::ExposeSecret;
        let s = self.inner.expose_secret();
        let len = self.char_len;

        if len == 0 {
            return String::new();
        }
        if len <= 3 {
            return "*".repeat(len);
        }

        let (prefix_chars, suffix_chars) = match len {
            1..=8 => (2_usize, 0_usize),
            9..=16 => (4, 2),
            17..=32 => (4, 4),
            _ => (6, 6),
        };

        // Enforce 40% max exposure
        let total_visible = prefix_chars + suffix_chars;
        let max_visible = (len as f64 * 0.40).floor() as usize;
        let (prefix_chars, suffix_chars) = if total_visible > max_visible {
            let half = max_visible / 2;
            (half.max(1), half)
        } else {
            (prefix_chars, suffix_chars)
        };

        let chars: Vec<char> = s.chars().collect();
        let prefix: String = chars[..prefix_chars].iter().collect();
        let suffix: String = if suffix_chars > 0 {
            chars[len - suffix_chars..].iter().collect()
        } else {
            String::new()
        };

        let hidden = len - prefix_chars - suffix_chars;
        format!(
            "{}{}{}",
            prefix,
            "*".repeat(hidden.min(8)), // cap displayed stars at 8 for readability
            suffix,
        )
    }

    /// Expose the raw secret for validated use cases ONLY.
    /// This should NEVER be called in output/logging paths.
    pub fn expose(&self) -> &str {
        use secrecy::ExposeSecret;
        self.inner.expose_secret()
    }

    /// Return the character length of the secret.
    pub fn char_len(&self) -> usize {
        self.char_len
    }

    /// Return true if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.char_len == 0
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.redacted())
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedString({})", self.redacted())
    }
}

impl From<String> for RedactedString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for RedactedString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

// ============================
// Fragment — Input Unit
// ============================

/// A chunk of content to be scanned, along with its provenance metadata.
#[derive(Debug, Clone)]
pub struct Fragment {
    /// The raw bytes to scan (zero-copy from mmap where possible)
    pub content: Bytes,
    /// Provenance and context metadata
    pub metadata: FragmentMetadata,
}

impl Fragment {
    /// Create a Fragment from a UTF-8 string slice.
    pub fn from_text(text: &str, path: impl Into<String>) -> Self {
        let content = Bytes::copy_from_slice(text.as_bytes());
        let size = content.len() as u64;
        Self {
            content,
            metadata: FragmentMetadata {
                path: path.into(),
                source_type: SourceType::Stdin,
                size,
                attributes: Default::default(),
            },
        }
    }

    /// Create a Fragment from raw bytes.
    pub fn from_bytes(content: Bytes, path: impl Into<String>) -> Self {
        let size = content.len() as u64;
        Self {
            content,
            metadata: FragmentMetadata {
                path: path.into(),
                source_type: SourceType::Directory,
                size,
                attributes: Default::default(),
            },
        }
    }
}

/// Metadata associated with a Fragment — where it came from and what it is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentMetadata {
    /// Logical path (may be virtual for archives, git history, APIs)
    pub path: String,
    /// Type of source that produced this fragment
    pub source_type: SourceType,
    /// Byte size of content
    pub size: u64,
    /// Additional source-specific attributes (e.g., commit hash, channel name)
    pub attributes: std::collections::HashMap<String, String>,
}

/// Enumeration of all supported source types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    Directory,
    Git,
    Stdin,
    Archive,
    Dotenv,
    GitHub,
    GitLab,
    Bitbucket,
    AzureDevOps,
    S3,
    Docker,
    Kubernetes,
    Terraform,
    Ansible,
    CiLogs,
    Slack,
    Discord,
    Jira,
    Confluence,
    Postman,
    Jupyter,
    Database,
    Elasticsearch,
    NpmPackage,
    Http,
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_string(self).unwrap_or_default();
        write!(f, "{}", s.trim_matches('"'))
    }
}

// ============================
// Location — Finding Position
// ============================

/// Precise source location of a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    /// File or virtual path
    pub path: String,
    /// 1-indexed start line
    pub start_line: u32,
    /// 1-indexed end line
    pub end_line: u32,
    /// 0-indexed start column (byte offset within line)
    pub start_col: u32,
    /// 0-indexed end column (byte offset within line)
    pub end_col: u32,
    /// Byte offset within the fragment
    pub byte_offset: u64,
}

// ============================
// Severity
// ============================

/// Risk severity level of a finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

// ============================
// FusedScore
// ============================

/// Composite confidence score produced by the fusion engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedScore {
    /// Overall confidence (0.0–1.0)
    pub confidence: f64,
    /// Stage 1: Shannon entropy contribution
    pub entropy: f64,
    /// Stage 2: Semantic proximity contribution
    pub proximity: f64,
    /// Stage 3: Tri-stream decomposition contribution
    pub tristream: f64,
    /// Stage 4: Pattern match strength
    pub pattern: f64,
    /// Markov randomness score
    pub markov: f64,
    /// Optional CNN classification score (GitHub Action / self-hosted)
    pub cnn_score: Option<f64>,
    /// Optional AST context adjustment (--semantic flag)
    pub ast_adjustment: Option<f64>,
}

// ============================
// MatchKind / MatchEvidence
// ============================

/// High-level semantic class for a detected secret candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    ApiKeyAssignment,
    PasswordAssignment,
    TokenAssignment,
    UrlCredentials,
    PrivateKey,
    BearerAuth,
    Jwt,
    NonceLike,
    Catchall,
    Unknown,
}

impl MatchKind {
    /// Rule-precedence rank used when choosing between overlapping findings.
    pub fn precedence_rank(self) -> u8 {
        match self {
            MatchKind::PrivateKey => 6,
            MatchKind::ApiKeyAssignment | MatchKind::PasswordAssignment => 5,
            MatchKind::UrlCredentials | MatchKind::TokenAssignment => 4,
            MatchKind::BearerAuth | MatchKind::Jwt => 3,
            MatchKind::NonceLike => 2,
            MatchKind::Catchall => 1,
            MatchKind::Unknown => 0,
        }
    }

    pub fn is_typed(self) -> bool {
        !matches!(self, MatchKind::Catchall | MatchKind::Unknown)
    }
}

/// Structured evidence attached to a pattern match and final finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEvidence {
    pub kind: MatchKind,
    pub primary_identifier: Option<String>,
    pub proximity_pattern: ProximityPattern,
    pub typed: bool,
    pub generic_catchall: bool,
    pub private_key_like: bool,
    pub multiline: bool,
    pub has_assignment: bool,
    pub has_secret_identifier: bool,
    pub has_auth_context: bool,
    pub value_entropy: f32,
}

impl MatchEvidence {
    pub fn precedence_rank(&self) -> u8 {
        let base = self.kind.precedence_rank();
        if self.generic_catchall {
            base.min(1)
        } else {
            base
        }
    }
}

impl Default for MatchEvidence {
    fn default() -> Self {
        Self {
            kind: MatchKind::Unknown,
            primary_identifier: None,
            proximity_pattern: ProximityPattern::Unknown,
            typed: false,
            generic_catchall: false,
            private_key_like: false,
            multiline: false,
            has_assignment: false,
            has_secret_identifier: false,
            has_auth_context: false,
            value_entropy: 0.0,
        }
    }
}

// ============================
// Finding
// ============================

/// A detected secret finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Unique finding ID (HMAC-based, session-scoped)
    pub id: String,
    /// Rule that triggered this finding
    pub rule_id: String,
    /// Human-readable description
    pub description: String,
    /// The detected secret (redacted in output, exposed only for hashing/validation)
    #[serde(serialize_with = "serialize_redacted")]
    pub secret: RedactedString,
    /// HMAC-SHA256 hash of the secret value (for deduplication and correlation)
    pub secret_hash: String,
    /// Surrounding context (lines before and after, with secret redacted)
    pub match_context: String,
    /// Where in the source the finding was detected
    pub location: Location,
    /// Composite confidence and sub-scores
    pub score: FusedScore,
    /// Structured evidence captured during detection and scoring.
    pub evidence: MatchEvidence,
    /// Severity level
    pub severity: Severity,
    /// Cross-file credential chain (populated by correlation engine)
    pub chain: Option<CredentialChain>,
    /// Validation result (populated when --validate is used)
    pub validation: Option<ValidationRef>,
    /// Remediation guidance
    pub remediation: Option<String>,
    /// Timestamp of detection
    pub detected_at: DateTime<Utc>,
    /// Deep decoding chain (if secret was obfuscated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_chain: Option<Vec<String>>,
}

fn serialize_redacted<S>(
    value: &RedactedString,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.redacted())
}

impl Finding {
    /// Convenience accessor for confidence score.
    pub fn confidence(&self) -> f64 {
        self.score.confidence
    }
}

// ============================
// Credential Chain
// ============================

/// Represents a credential detected across multiple files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialChain {
    /// The variable name linking the chain (e.g., "DB_PASSWORD")
    pub variable_name: String,
    /// The source finding where the credential value is defined
    pub origin_id: String,
    /// Finding IDs where the credential is propagated/referenced
    pub propagation_ids: Vec<String>,
    /// Finding IDs where the credential is consumed at runtime
    pub usage_ids: Vec<String>,
    /// Combined confidence score for the chain
    pub chain_confidence: f64,
}

// ============================
// ValidationRef
// ============================

/// Reference to a validation result (stored separately to avoid holding secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRef {
    pub status: ValidationStatus,
    pub provider: String,
    pub validated_at: DateTime<Utc>,
    pub reason: Option<String>,
}

/// Status of a validated credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Credential is confirmed active and usable
    Active,
    /// Credential exists but is disabled/expired
    Inactive,
    /// Credential has been explicitly revoked
    Revoked,
    /// Cannot determine status without additional information
    NeedsValidation,
    /// Validation attempt failed (network error, etc.)
    Error,
    /// Provider not supported or validation not applicable
    Unknown,
}

// ============================
// EntropyCandidate (Stage 1 output)
// ============================

/// A byte range identified by the entropy gate as potentially secret.
#[derive(Debug, Clone)]
pub struct EntropyCandidate {
    pub offset: u64,
    pub length: u32,
    pub entropy: f32,
    pub raw: Bytes,
}

// ============================
// ProximityMatch (Stage 2 output)
// ============================

/// A candidate that passed the semantic proximity filter.
#[derive(Debug, Clone)]
pub struct ProximityMatch {
    pub candidate: EntropyCandidate,
    pub pattern: ProximityPattern,
    pub proximity_score: f32,
    /// Surrounding context bytes (up to 256 bytes either side)
    pub context: Bytes,
}

/// The type of assignment pattern that triggered proximity detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProximityPattern {
    Assignment,   // VAR_NAME = "..."
    Export,       // export KEY=value
    JsonKey,      // "apiKey": "..."
    YamlKey,      // api_key: value
    EnvVar,       // ENV VAR_NAME=value (Docker/shell)
    FunctionArg,  // func(key="...")
    HeaderValue,  // Authorization: Bearer ...
    DockerEnv,    // ENV or ARG in Dockerfile
    K8sSecret,    // data: key: base64
    TerraformVar, // variable "..." { default = "..." }
    Unknown,
}

// ============================
// TriStreamResult (Stage 3 output)
// ============================

/// Result from the tri-stream decomposition stage.
#[derive(Debug, Clone)]
pub struct TriStreamResult {
    pub source: ProximityMatch,
    /// Extracted identifier/variable names (Stream A)
    pub identifiers: Vec<String>,
    /// Extracted literal values (Stream B)
    pub literals: Vec<Bytes>,
    /// Structural context score (Stream C)
    pub structure_score: f32,
    /// Combined tri-stream confidence
    pub combined_score: f32,
}

// ============================
// PatternMatch (Stage 4 output)
// ============================

/// A finding from the pattern verification stage.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub source: TriStreamResult,
    pub rule_id: String,
    pub matched_text: String,
    pub match_start: usize,
    pub match_end: usize,
    pub pattern_score: f32,
    pub evidence: MatchEvidence,
    pub encoding_chain: Option<Vec<String>>,
}

// ============================
// Secret Hashing
// ============================

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of a secret value using a session-scoped nonce.
/// This produces a stable, non-reversible hash for deduplication and correlation
/// without persisting the raw secret value.
pub fn hash_secret(secret: &RedactedString, nonce: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(nonce).expect("HMAC can take key of any size");
    mac.update(secret.expose().as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_string_short() {
        let s = RedactedString::new("abcd".to_string());
        let r = s.redacted();
        // 4 chars: prefix=2, no suffix → 2 chars exposed = 50% — capped by 40% rule → prefix=1, suffix=0
        // Actually 4 <= 8: prefix=2, suffix=0 → 2/4 = 50% > 40% → half = 0, capped to 1
        // Let's just verify it contains some redaction
        assert!(r.contains('*'), "Should contain redaction: {}", r);
        assert!(!r.contains("abcd"), "Should not expose full secret");
    }

    #[test]
    fn test_redacted_string_medium() {
        let s = RedactedString::new("mysecretpassword123".to_string()); // 19 chars
        let r = s.redacted();
        // 19 chars → prefix=4, suffix=4 → 8/19 = 42% > 40% → half=4 → 4+4=8 still > 40% → half=3
        assert!(r.contains('*'));
        assert!(r.len() > 4); // Has some content
    }

    #[test]
    fn test_redacted_string_aws_key() {
        // AWS access key: AKIAIOSFODNN7EXAMPLE (20 chars)
        let s = RedactedString::new("AKIAIOSFODNN7EXAMPLE".to_string());
        let r = s.redacted();
        assert!(r.contains('*'));
        assert!(
            !r.contains("AKIAIOSFODNN7EXAMPLE"),
            "Full key must not be visible"
        );
        // Verify max 40% exposure
        let visible: usize = r.chars().filter(|c| *c != '*').count();
        assert!(
            visible as f64 / s.char_len() as f64 <= 0.41,
            "Exposed {}/{} = {:.1}% > 40%",
            visible,
            s.char_len(),
            visible as f64 / s.char_len() as f64 * 100.0
        );
    }

    #[test]
    fn test_redacted_string_utf8() {
        // Multi-byte UTF-8 characters should not cause panics
        let s = RedactedString::new("🔑secret_key_🗝️_value".to_string());
        let r = s.redacted(); // Should not panic
        assert!(r.contains('*'));
    }

    #[test]
    fn test_redacted_string_empty() {
        let s = RedactedString::new(String::new());
        assert_eq!(s.redacted(), "");
        assert!(s.is_empty());
    }

    #[test]
    fn test_hash_secret_deterministic() {
        let nonce = b"test_nonce_12345";
        let s = RedactedString::new("my_secret_value".to_string());
        let h1 = hash_secret(&s, nonce);
        let h2 = hash_secret(&s, nonce);
        assert_eq!(h1, h2, "Same nonce + secret should produce same hash");
    }

    #[test]
    fn test_hash_secret_nonce_sensitivity() {
        let s = RedactedString::new("my_secret_value".to_string());
        let h1 = hash_secret(&s, b"nonce1");
        let h2 = hash_secret(&s, b"nonce2");
        assert_ne!(h1, h2, "Different nonces should produce different hashes");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_proximity_pattern_serialization() {
        let p = ProximityPattern::JsonKey;
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("JsonKey"));
    }
}
