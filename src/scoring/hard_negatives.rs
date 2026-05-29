//! Hard negative mining for false-positive reduction.
//!
//! Maintains a corpus of known placeholder / example strings that look like
//! secrets but are definitively not (they appear in documentation, template
//! files, test fixtures, etc.).
//!
//! When a matched string overlaps a hard-negative pattern the confidence score
//! receives a penalty, controlled by [`HardNegativeMatcher::PENALTY`].
//!
//! # Usage
//!
//! ```rust,no_run
//! use secret_squirrel::scoring::hard_negatives::HardNegativeMatcher;
//!
//! let hn = HardNegativeMatcher::default();
//! let penalty = hn.penalty("YOUR_API_KEY_HERE");
//! assert!(penalty < 0.0); // -0.30
//! ```

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Penalty constant
// ---------------------------------------------------------------------------

/// Confidence score penalty applied when a matched string is a known
/// hard negative. Range: -1.0 to 0.0 (subtracted from the fused confidence).
pub const HARD_NEGATIVE_PENALTY: f64 = -0.35;

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Static list of known placeholder / example secret strings.
///
/// These are gathered from:
/// * Gitleaks allow-lists
/// * TruffleHog detector test fixtures
/// * CredData false-positive annotations
/// * Common documentation boilerplate
///
/// All strings are stored lower-cased for case-insensitive matching.
static KNOWN_PLACEHOLDERS: &[&str] = &[
    // ── Generic placeholders ──────────────────────────────────────────────
    "your_api_key",
    "your_api_key_here",
    "your-api-key",
    "your_secret_key",
    "your_secret",
    "your_token",
    "your_access_token",
    "your_client_secret",
    "your_password",
    "your_private_key",
    "your_public_key",
    "your_auth_token",
    "yourapikey",
    "yoursecretkey",
    "yourtoken",
    "yourpassword",
    "api_key_here",
    "api-key-here",
    "secret_key_here",
    "token_here",
    "put_your_token_here",
    "insert_your_key_here",
    // ── Example / demo values ────────────────────────────────────────────
    "example_api_key",
    "example_secret",
    "example_token",
    "example_key",
    "example_password",
    "examplekey",
    "examplesecret",
    "demo_api_key",
    "demo_key",
    "demo_secret",
    "samplekey",
    "sample_api_key",
    "sample_secret",
    // ── Placeholder patterns (often in .env.example / .env.template) ────
    "changeme",
    "change_me",
    "change-me",
    "change_me_please",
    "pleasechange",
    "please_change",
    "replace_me",
    "replace_this",
    "replacethis",
    "fill_in_here",
    "fill_me_in",
    "todo_fill_me",
    "todo",
    // ── Empty / null-like ────────────────────────────────────────────────
    "null",
    "none",
    "empty",
    "undefined",
    "not_set",
    "not-set",
    "notset",
    "missing",
    "n/a",
    "na",
    // ── Test credentials (common in CI fixtures) ─────────────────────────
    "test_key",
    "test_secret",
    "test_token",
    "test_password",
    "test_api_key",
    "testkey",
    "testsecret",
    "testtoken",
    "testpassword",
    "testing123",
    "testtest",
    "test1234",
    "test12345",
    // ── Dummy / fake ─────────────────────────────────────────────────────
    "dummy_key",
    "dummy_secret",
    "dummy_token",
    "dummy_password",
    "dummykey",
    "fake_key",
    "fake_secret",
    "fake_token",
    "fake_password",
    "fakekey",
    "faketoken",
    "placeholder",
    "placeholder_key",
    "placeholder_secret",
    // ── Documentation boilerplate ────────────────────────────────────────
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxxxxxxxxxxxxxx",
    "xxxxxxxx",
    "1234567890abcdef",
    "abcdefghijklmnop",
    "0000000000000000",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "1111111111111111111111111111111",
    "abcdefgh",
    "12345678",
    // ── AWS-specific fake ARNs / keys ────────────────────────────────────
    "akiaiosfodnn7example",          // AWS documentation example key
    "wjalrxutnfemi/k7mdeng/bpxrfye", // AWS documentation example secret
    "akiaiosfodnn7example_",
    // ── GitHub token examples ─────────────────────────────────────────────
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "github_pat_",
    // ── Stripe test keys ──────────────────────────────────────────────────
    "sk_test_",          // prefix only — matches if the whole value is this
    "pk_test_",
    // ── JWT examples ─────────────────────────────────────────────────────
    "your.jwt.token",
    "jwt_secret_here",
    // ── Bracket / angle-bracket templates ────────────────────────────────
    "<your_api_key>",
    "<api_key>",
    "<token>",
    "<secret>",
    "<password>",
    "<your_token>",
    "<your_secret>",
    "[your_api_key]",
    "[api_key]",
    "[token]",
    "[secret]",
    "{api_key}",
    "{your_api_key}",
    "{token}",
    "{secret}",
    // ── Env-var reference patterns (not actual values) ────────────────────
    "$api_key",
    "$secret",
    "$token",
    "$your_api_key",
    "$(api_key)",
    "$(secret)",
    "${api_key}",
    "${secret}",
    "${your_token}",
    // ── Common documentation phrases ──────────────────────────────────────────────
    "paste_your_key_here",
    "enter_your_key",
    "set_this_to_your_key",
    "replace_with_your_key",
    "replace_with_your_token",
    "your_secret_goes_here",
    // ── GitHub Actions / CI expressions (not actual secret values) ────────
    "${{ secrets.github_token }}",
    "${{ secrets.aws_access_key_id }}",
    "${{ secrets.aws_secret_access_key }}",
    "secrets.github_token",
    "secrets.aws_access_key_id",
    // ── Mock / stub credential patterns ──────────────────────────────────
    "mock_api_key",
    "mock_key",
    "mock_secret",
    "mock_token",
    "mock_password",
    "mockkey",
    "mocksecret",
    "stub_key",
    "stub_secret",
    "stub_token",
    "fake_api_key_for_testing",
    "mock_key_for_testing",
    // ── Low-entropy dictionary words (common in weak password FPs) ───────
    "password123",
    "password1234",
    "testpassword",
    "testtoken",
    "testtest",
    "testkey",
    "admin123",
    "admin1234",
    "letmein",
    "welcome1",
    "qwerty",
    "qwerty123",
    "abc123",
    "abc1234",
    // ── Sample/demo key patterns from AWS/GH docs ─────────────────────────
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",  // full AWS example secret
    "akiatest",
    // ── Numeric sequences ─────────────────────────────────────────────────
    "123456789012345678901234567890123456",
    "12345678901234567890",
    "1234567890123456",
];

// ---------------------------------------------------------------------------
// Suffix / prefix patterns (checked via contains())
// ---------------------------------------------------------------------------

static PLACEHOLDER_SUBSTRINGS: &[&str] = &[
    "_placeholder",
    "_example",
    "_template",
    "_dummy",
    "_fake",
    "example_",
    "sample_",
    "demo_",
    "test_",       // only as substring in longer fake values
    "_here",
    "_todo",
    "changeme",
    "replace_me",
    "your_",
    "_your_",
    "xxxx",        // four or more x's
    "0000",        // four or more zeros
    "aaaa",        // four or more a's
    "1111",        // four or more 1's
    // CI/CD expression delimiters
    "${{" ,        // GitHub Actions / GitLab CI expression — never a real secret
    "secrets.",    // Reference to a secret store, not a literal value
    // Mock/stub markers
    "mock_",
    "_mock",
    "stub_",
    "_stub",
    "fake_key",
    "fake_token",
    "fake_secret",
    // Documentation and tutorial markers
    "_for_testing",
    "_for_demo",
    "_for_example",
    "_replace_me",
];

// ---------------------------------------------------------------------------
// HardNegativeMatcher
// ---------------------------------------------------------------------------

/// Fast O(1) lookup of known hard-negative patterns.
pub struct HardNegativeMatcher {
    exact: HashSet<String>,
}

impl HardNegativeMatcher {
    /// Build the matcher from the built-in corpus.
    pub fn new() -> Self {
        let exact: HashSet<String> = KNOWN_PLACEHOLDERS
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        Self { exact }
    }

    /// Return the confidence penalty for `candidate` (0.0 if not a hard negative).
    ///
    /// Checks:
    /// 1. Exact match against the known-placeholder corpus (case-insensitive).
    /// 2. Substring match against placeholder substrings.
    /// 3. High repetition: a string where >75% of characters are the same byte.
    /// 4. Very low character diversity (<4 unique chars in a 16+ char string).
    pub fn penalty(&self, candidate: &str) -> f64 {
        let lower = candidate.to_lowercase();
        let trimmed = lower.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-');

        // 1. Exact match
        if self.exact.contains(trimmed) {
            return HARD_NEGATIVE_PENALTY;
        }

        // 2. Substring patterns
        for &sub in PLACEHOLDER_SUBSTRINGS {
            if trimmed.contains(sub) {
                return HARD_NEGATIVE_PENALTY;
            }
        }

        // 3. High repetition (e.g., "xxxxxxxxxxxxxxxxxxxxxxx")
        if candidate.len() >= 8 {
            let bytes = candidate.as_bytes();
            let most_common = {
                let mut freq = [0u32; 256];
                for &b in bytes {
                    freq[b as usize] += 1;
                }
                *freq.iter().max().unwrap_or(&0)
            };
            let ratio = most_common as f64 / bytes.len() as f64;
            if ratio >= 0.80 {
                return HARD_NEGATIVE_PENALTY * 0.7; // -0.245 (softer penalty)
            }
        }

        // 4. Very low character diversity
        if candidate.len() >= 16 {
            let unique: HashSet<char> = candidate.chars().collect();
            if unique.len() <= 3 {
                return HARD_NEGATIVE_PENALTY * 0.5; // -0.175
            }
        }

        // 5. Pure digit strings (no alpha chars) — never a real API key/token
        if candidate.len() >= 8 && candidate.chars().all(|c| c.is_ascii_digit()) {
            return HARD_NEGATIVE_PENALTY * 0.8; // -0.28
        }

        // 6. Pure alpha lowercase (e.g., "testtoken", "password") — dictionary words
        if candidate.len() >= 8
            && candidate.len() <= 20
            && candidate.chars().all(|c| c.is_ascii_lowercase())
        {
            // Only penalise if it looks like a word (no digits/special chars)
            // Real secrets always have mixed char classes
            return HARD_NEGATIVE_PENALTY * 0.5; // -0.175
        }

        0.0
    }

    /// Return `true` if the candidate is a known hard negative.
    #[inline]
    pub fn is_hard_negative(&self, candidate: &str) -> bool {
        self.penalty(candidate) < 0.0
    }
}

impl Default for HardNegativeMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hn() -> HardNegativeMatcher {
        HardNegativeMatcher::new()
    }

    #[test]
    fn exact_placeholder_is_penalized() {
        let m = hn();
        assert!(m.penalty("YOUR_API_KEY") < 0.0);
        assert!(m.penalty("your_api_key") < 0.0);
        assert!(m.penalty("CHANGEME") < 0.0);
        assert!(m.penalty("changeme") < 0.0);
    }

    #[test]
    fn substring_placeholder_is_penalized() {
        let m = hn();
        assert!(m.penalty("some_value_placeholder") < 0.0);
        assert!(m.penalty("abc_example_key") < 0.0);
        assert!(m.penalty("my_dummy_secret") < 0.0);
    }

    #[test]
    fn high_repetition_is_penalized() {
        let m = hn();
        // All same character
        assert!(m.penalty("xxxxxxxxxxxxxxxxxxxxxxxx") < 0.0);
        assert!(m.penalty("00000000000000000000") < 0.0);
        assert!(m.penalty("AAAAAAAAAAAAAAAAAAA") < 0.0);
    }

    #[test]
    fn real_aws_key_not_penalized() {
        let m = hn();
        // Real-looking (but fake) AWS key with good character diversity
        let fake_real = "AKIAIOSFODNN7REALKEY";
        // Note: "akiaiosfodnn7example" IS in the corpus, but a different value should not be
        assert_eq!(m.penalty(fake_real), 0.0);
    }

    #[test]
    fn real_stripe_key_not_penalized() {
        let m = hn();
        let key = "sk_live_51H7VFgLkTVxRMboNabcXYZ0123456789abcdef";
        assert_eq!(m.penalty(key), 0.0);
    }

    #[test]
    fn github_token_not_penalized() {
        let m = hn();
        let token = "ghp_1234567890abcdefghijklmnopqrstuv";
        assert_eq!(m.penalty(token), 0.0);
    }

    #[test]
    fn aws_example_key_is_penalized() {
        let m = hn();
        assert!(m.penalty("AKIAIOSFODNN7EXAMPLE") < 0.0);
        assert!(m.penalty("akiaiosfodnn7example") < 0.0);
    }

    #[test]
    fn low_diversity_penalized() {
        let m = hn();
        // Only uses 2 chars: "ab" repeated
        assert!(m.penalty("ababababababababab") < 0.0);
    }

    #[test]
    fn penalty_is_zero_for_normal_string() {
        let m = hn();
        assert_eq!(m.penalty("hello"), 0.0);
        assert_eq!(m.penalty("normal_variable"), 0.0);
    }
}
