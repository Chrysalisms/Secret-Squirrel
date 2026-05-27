//! Stage 3 — Tri-Stream Decomposer.
//!
//! Decomposes each [`ProximityMatch`] into three orthogonal signal streams:
//!
//! - **Stream A — Identifiers**: Variable/function names in the surrounding
//!   256-byte context. Scored against a keyword table (`password`, `secret`, …).
//! - **Stream B — Literals**: The high-entropy value itself, scored by its
//!   character-class distribution (hex, base64, JWT, UUID, …).
//! - **Stream C — Structure**: Surrounding syntax delimiters (quotes, `=`, `:`).
//!
//! The three stream scores are fused with fixed weights:
//!
//! ```text
//! combined = 0.35 * stream_a + 0.45 * stream_b + 0.20 * stream_c
//! ```
//!
//! This stage outputs [`TriStreamResult`]s whose `combined_score` feeds the
//! pattern-verification and fusion stages.

use bytes::Bytes;

use crate::types::{ProximityMatch, TriStreamResult};

// ---------------------------------------------------------------------------
// Stream A — Identifier scoring
// ---------------------------------------------------------------------------

/// Maximum context to scan (bytes) before the candidate literal for identifiers.
const IDENTIFIER_CONTEXT: usize = 256;

/// Pre-built lookup table mapping lowercase keyword → identifier score (0.0–1.0).
/// Uppercase variants are handled by lowercasing during scan.
static KEYWORD_SCORES: &[(&[u8], f32)] = &[
    (b"password",   0.90),
    (b"passwd",     0.90),
    (b"secret",     0.90),
    (b"credential", 0.80),
    (b"token",      0.80),
    (b"private",    0.70),
    (b"key",        0.70),
    (b"api",        0.60),
    (b"auth",       0.60),
    (b"access",     0.55),
];

/// Score the identifier stream for the context bytes preceding the candidate.
///
/// Extracts `[a-zA-Z_][a-zA-Z0-9_]{2,}` tokens and matches them against the
/// keyword table, returning the highest matching score.
fn score_stream_a(context_before: &[u8]) -> (f32, Vec<String>) {
    let mut identifiers: Vec<String> = Vec::new();
    let mut best_score = 0.0f32;

    // Simple state-machine identifier extractor.
    let mut in_ident = false;
    let mut start = 0usize;

    for (i, &b) in context_before.iter().enumerate() {
        let is_start_char = b.is_ascii_alphabetic() || b == b'_';
        let is_cont_char = b.is_ascii_alphanumeric() || b == b'_';

        if !in_ident {
            if is_start_char {
                in_ident = true;
                start = i;
            }
        } else if !is_cont_char {
            let token = &context_before[start..i];
            if token.len() >= 3 {
                let score = lookup_keyword_score(token);
                if score > best_score {
                    best_score = score;
                }
                if let Ok(s) = std::str::from_utf8(token) {
                    identifiers.push(s.to_owned());
                }
            }
            in_ident = false;
        }
    }

    // Handle identifier at end of slice.
    if in_ident {
        let token = &context_before[start..];
        if token.len() >= 3 {
            let score = lookup_keyword_score(token);
            if score > best_score {
                best_score = score;
            }
            if let Ok(s) = std::str::from_utf8(token) {
                identifiers.push(s.to_owned());
            }
        }
    }

    (best_score, identifiers)
}

/// Look up a token (case-insensitive) in the keyword score table.
fn lookup_keyword_score(token: &[u8]) -> f32 {
    // Lowercase the token for comparison (max 64 bytes → stack allocation).
    let lower: Vec<u8> = token.iter().map(|b| b.to_ascii_lowercase()).collect();

    for &(keyword, score) in KEYWORD_SCORES {
        // Subword match: the token contains the keyword as a substring.
        if lower.windows(keyword.len()).any(|w| w == keyword) {
            return score;
        }
    }
    0.0
}

// ---------------------------------------------------------------------------
// Stream B — Literal scoring
// ---------------------------------------------------------------------------

/// Detect whether `data` looks like a UUID (8-4-4-4-12 hex pattern).
fn is_uuid(data: &[u8]) -> bool {
    // e.g., 550e8400-e29b-41d4-a716-446655440000  (36 chars)
    if data.len() != 36 {
        return false;
    }
    let dashes = [8, 13, 18, 23];
    for (i, &b) in data.iter().enumerate() {
        if dashes.contains(&i) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Detect whether `data` looks like a JWT (three base64url segments separated
/// by `.`).
fn is_jwt(data: &[u8]) -> bool {
    let mut dot_count = 0u8;
    let mut segment_len = 0usize;
    for &b in data {
        if b == b'.' {
            dot_count += 1;
            if segment_len == 0 {
                return false; // Empty segment
            }
            segment_len = 0;
        } else {
            // Base64url chars: A-Za-z0-9_-=
            if !b.is_ascii_alphanumeric() && b != b'_' && b != b'-' && b != b'=' {
                return false;
            }
            segment_len += 1;
        }
    }
    dot_count == 2 && segment_len > 0
}

/// Score the literal stream based on character-class distribution of the
/// high-entropy byte sequence.
///
/// Returns (score, `Vec<Bytes>` containing the raw literal as single element).
fn score_stream_b(literal: &[u8]) -> (f32, Vec<Bytes>) {
    let raw = Bytes::copy_from_slice(literal);

    // JWT check first (most specific).
    if is_jwt(literal) {
        return (0.95, vec![raw]);
    }

    // UUID check.
    if is_uuid(literal) {
        return (0.65, vec![raw]);
    }

    // Character-class counts.
    let mut hex_chars = 0usize;
    let mut base64_chars = 0usize;
    let mut special_chars = 0usize;
    let total = literal.len();

    for &b in literal {
        if b.is_ascii_hexdigit() {
            hex_chars += 1;
        }
        // Base64 alphabet: A-Za-z0-9+/= and URL-safe _-
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'_' || b == b'-' {
            base64_chars += 1;
        }
        if !b.is_ascii_alphanumeric() {
            special_chars += 1;
        }
    }

    let hex_ratio = hex_chars as f32 / total as f32;
    let b64_ratio = base64_chars as f32 / total as f32;
    let special_ratio = special_chars as f32 / total as f32;

    let score = if hex_ratio >= 0.95 {
        // Pure hex string
        0.70
    } else if b64_ratio >= 0.95 {
        // Pure base64 alphabet
        0.75
    } else if special_ratio > 0.05 && b64_ratio < 1.0 {
        // Mixed alphanumeric + special chars
        0.85
    } else {
        // Generic random alphanumeric
        0.60
    };

    (score, vec![raw])
}

// ---------------------------------------------------------------------------
// Stream C — Structure scoring
// ---------------------------------------------------------------------------

/// Score the structure stream based on syntax delimiters in the context.
fn score_stream_c(context: &[u8]) -> f32 {
    let mut score = 0.0f32;

    if context.iter().any(|&b| b == b'"' || b == b'\'') {
        score += 0.30;
    }
    if context.iter().any(|&b| b == b'=') {
        score += 0.20;
    }
    if context.iter().any(|&b| b == b':') {
        score += 0.15;
    }
    // Check for "export" keyword in context
    if context.windows(6).any(|w| w == b"export") {
        score += 0.30;
    }

    score.min(1.0)
}

// ---------------------------------------------------------------------------
// TriStreamDecomposer
// ---------------------------------------------------------------------------

/// Fusion weights for the three streams.
const WEIGHT_A: f32 = 0.35;
const WEIGHT_B: f32 = 0.45;
const WEIGHT_C: f32 = 0.20;

/// Stage 3: Tri-stream decomposer.
///
/// Processes each [`ProximityMatch`] and emits a [`TriStreamResult`] with
/// per-stream scores and the fused `combined_score`.
#[derive(Debug, Clone, Default)]
pub struct TriStreamDecomposer;

impl TriStreamDecomposer {
    /// Create a new decomposer.
    pub fn new() -> Self {
        Self
    }

    /// Decompose all proximity matches into tri-stream results.
    ///
    /// # Arguments
    ///
    /// * `matches` — Output from [`ProximityDetector::filter`].
    pub fn decompose(&self, matches: Vec<ProximityMatch>) -> Vec<TriStreamResult> {
        matches.into_iter().map(|pm| self.decompose_one(pm)).collect()
    }

    /// Decompose a single [`ProximityMatch`].
    fn decompose_one(&self, pm: ProximityMatch) -> TriStreamResult {
        let context = &pm.context;
        let _candidate_offset = pm.candidate.offset as usize;
        let candidate_len = pm.candidate.length as usize;

        // Determine context-before the literal within the context window.
        // The context starts at `ctx_start = candidate_offset - (up to 128)`.
        // We stored the raw context bytes; the candidate is somewhere inside.
        // Since ProximityDetector captures CONTEXT_WINDOW=128 bytes before the
        // candidate, the candidate starts at min(128, candidate_offset) into the
        // context slice.
        let before_len = context.len().saturating_sub(candidate_len);
        let before_slice = &context[..before_len.min(IDENTIFIER_CONTEXT)];
        let literal_slice = pm.candidate.raw.as_ref();

        // Stream A — identifier score from context before literal.
        let (stream_a, identifiers) = score_stream_a(before_slice);

        // Stream B — literal character-class score.
        let (stream_b, literals) = score_stream_b(literal_slice);

        // Stream C — structure score from full context.
        let stream_c = score_stream_c(context);

        // Fuse the three streams.
        let combined = WEIGHT_A * stream_a + WEIGHT_B * stream_b + WEIGHT_C * stream_c;

        TriStreamResult {
            source: pm,
            identifiers,
            literals,
            structure_score: stream_c,
            combined_score: combined.min(1.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::entropy::shannon_entropy;
    use crate::types::{EntropyCandidate, ProximityPattern};

    /// Build a minimal [`ProximityMatch`] for testing.
    fn make_proximity_match(full_line: &[u8], secret: &[u8]) -> ProximityMatch {
        let offset = full_line
            .windows(secret.len())
            .position(|w| w == secret)
            .unwrap_or(0);

        ProximityMatch {
            candidate: EntropyCandidate {
                offset: offset as u64,
                length: secret.len() as u32,
                entropy: shannon_entropy(secret),
                raw: Bytes::copy_from_slice(secret),
            },
            pattern: ProximityPattern::Assignment,
            proximity_score: 0.5,
            context: Bytes::copy_from_slice(full_line),
        }
    }

    #[test]
    fn test_stream_a_password_identifier_scores_high() {
        // DB_PASSWORD should hit the "password" keyword entry.
        let line = b"DB_PASSWORD = \"supersecret123\"";
        let secret = b"supersecret123";
        let pm = make_proximity_match(line, secret);
        let decomposer = TriStreamDecomposer::new();
        let result = decomposer.decompose_one(pm);

        // Stream A must detect PASSWORD → score ~0.9
        // We check that identifiers include DB_PASSWORD and combined is non-trivial.
        assert!(
            result.identifiers.iter().any(|id| id.to_lowercase().contains("password")),
            "Should detect PASSWORD identifier, got: {:?}",
            result.identifiers
        );
        // combined_score should be meaningful (not zero)
        assert!(result.combined_score > 0.3, "combined score should be > 0.3");
    }

    #[test]
    fn test_stream_b_jwt_detected() {
        // A well-formed JWT: header.payload.signature (base64url segments)
        let header  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0";
        let sig     = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let jwt = format!("{header}.{payload}.{sig}");

        let line = format!("Authorization: Bearer {jwt}");
        let pm = make_proximity_match(line.as_bytes(), jwt.as_bytes());
        let (score, _) = score_stream_b(jwt.as_bytes());

        assert!(
            (score - 0.95).abs() < 0.001,
            "JWT should get stream B score of 0.95, got {score}"
        );

        let decomposer = TriStreamDecomposer::new();
        let result = decomposer.decompose_one(pm);
        // With stream B = 0.95 (weight 0.45) the combined should be significant.
        assert!(result.combined_score > 0.4, "JWT combined score should be > 0.4");
    }

    #[test]
    fn test_stream_b_uuid_detected() {
        let uuid = b"550e8400-e29b-41d4-a716-446655440000";
        let (score, _) = score_stream_b(uuid);
        assert!((score - 0.65).abs() < 0.001, "UUID score should be 0.65, got {score}");
    }

    #[test]
    fn test_stream_b_hex_string() {
        // Pure hex string (e.g., MD5 hash)
        let hex = b"d41d8cd98f00b204e9800998ecf8427e";
        let (score, _) = score_stream_b(hex);
        assert!((score - 0.70).abs() < 0.001, "Hex string score should be 0.70, got {score}");
    }

    #[test]
    fn test_plain_text_scores_low() {
        // A plain English phrase — no secret identifiers, low literal score.
        let line = b"the quick brown fox jumps over the lazy dog";
        let pm = make_proximity_match(line, b"brown fox");
        let decomposer = TriStreamDecomposer::new();
        let result = decomposer.decompose_one(pm);
        assert!(
            result.combined_score < 0.5,
            "Plain text combined score should be < 0.5, got {}",
            result.combined_score
        );
    }

    #[test]
    fn test_stream_c_quote_equals_adds_score() {
        let ctx = b"SECRET_KEY = \"abc\"";
        let score = score_stream_c(ctx);
        // Should detect quote (+0.30) + '=' (+0.20) = 0.50
        assert!(score >= 0.49, "Structure score should be >= 0.50, got {score}");
    }

    #[test]
    fn test_is_jwt() {
        assert!(is_jwt(b"aaa.bbb.ccc"), "Simple 3-part JWT should pass");
        assert!(!is_jwt(b"aaa.bbb"), "2 segments should fail");
        assert!(!is_jwt(b"aaa.bbb.ccc.ddd"), "4 segments should fail");
        assert!(!is_jwt(b"aaa..ccc"), "Empty segment should fail");
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid(b"550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid(b"550e8400-e29b-41d4-a716"), "Short UUID should fail");
        assert!(!is_uuid(b"550e8400-e29b-41d4-a716-44665544000G"), "Non-hex char should fail");
    }
}
