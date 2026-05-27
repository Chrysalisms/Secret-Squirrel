//! Markov chain randomness scorer.
//!
//! Uses a 64-character alphabet trigram model to score how random (and thus
//! how likely to be a secret) a string is.
//!
//! # Alphabet
//!
//! ```text
//! abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-
//! ```
//! (64 characters, indices 0–63)
//!
//! # Table
//!
//! A `[f32; 262_144]` (64³) table stores log-probabilities for every ordered
//! trigram. The index into the table for trigram `(a, b, c)` is:
//!
//! ```text
//! idx = a * 64 * 64 + b * 64 + c
//! ```
//!
//! Higher log-probability (closer to 0.0) means the trigram is more "natural"
//! (common in English or code identifiers). Very negative values indicate rare,
//! random-looking trigrams.
//!
//! # Scoring
//!
//! [`MarkovScorer::score`] slides a window of 3 over the input, accumulates
//! log-probabilities, averages them, and maps the result to [0.0, 1.0] where
//! **1.0 = definitely a secret** (very random).

/// The 64-character alphabet used by the Markov model.
const ALPHABET: &[u8; 64] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

/// Size of the trigram table: 64 * 64 * 64.
const TABLE_SIZE: usize = 64 * 64 * 64;

/// Log-probability assigned to a "common" trigram (English / code).
/// Using log2(0.05) ≈ −4.32 as a representative common probability.
const LOG_COMMON: f32 = -4.322;

/// Log-probability assigned to a "mixed" (medium-frequency) trigram.
/// Using log2(0.001) ≈ −9.97.
const LOG_MIXED: f32 = -9.966;

/// Log-probability assigned to a "rare" (random-looking) trigram.
/// Using log2(0.0001) ≈ −13.29.
const LOG_RARE: f32 = -13.288;

/// Approximate range for normalization.
/// Best-case (English trigrams) avg log ≈ −4.0; worst-case ≈ −14.0.
const SCORE_MIN: f32 = -4.0;  // most natural
const SCORE_MAX: f32 = -14.0; // most random

/// 64-character trigram Markov chain randomness scorer.
///
/// Lower internal log-probability average → higher randomness → higher output
/// score (closer to 1.0).
pub struct MarkovScorer {
    /// Flattened 64×64×64 table of log-probabilities.
    table: Box<[f32; TABLE_SIZE]>,
    /// Character → alphabet index lookup (non-alphabet chars map to `None`).
    char_index: [Option<u8>; 256],
}

impl std::fmt::Debug for MarkovScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkovScorer")
            .field("table_len", &TABLE_SIZE)
            .finish()
    }
}

impl MarkovScorer {
    /// Initialise the Markov scorer with heuristic log-probabilities.
    ///
    /// The initial implementation uses three tiers of log-probability:
    /// - **Common**: same-character runs (`aaa`, `bbb`), common code patterns
    ///   (`key`, `oken`, `pass`, …)
    /// - **Mixed**: most alphanumeric combinations
    /// - **Rare**: combinations involving digits mixed with uppercase or special
    ///   chars that rarely appear in natural text
    ///
    /// When a proper training pipeline is added (see `scripts/train_markov.py`),
    /// this table will be replaced with empirically derived values from a large
    /// corpus of code + English text.
    pub fn new() -> Self {
        // Build the char_index lookup table (256 entries, all None by default).
        let mut char_index = [None::<u8>; 256];
        for (idx, &c) in ALPHABET.iter().enumerate() {
            char_index[c as usize] = Some(idx as u8);
        }

        // Allocate the trigram table on the heap to avoid stack overflow.
        // Default everything to LOG_MIXED.
        let mut table = Box::new([LOG_MIXED; TABLE_SIZE]);

        // Apply heuristic overrides.
        for a in 0u8..64 {
            for b in 0u8..64 {
                for c in 0u8..64 {
                    let idx = trigram_idx(a, b, c);
                    let log_p = heuristic_log_prob(a, b, c);
                    table[idx] = log_p;
                }
            }
        }

        Self { table, char_index }
    }

    /// Score a string for randomness.
    ///
    /// Returns a value in `[0.0, 1.0]` where:
    /// - `0.0` = completely natural/predictable (e.g., English text)
    /// - `1.0` = highly random (very likely a secret)
    ///
    /// Characters not in the 64-char alphabet are skipped. If fewer than 3
    /// alphabet characters are present, returns `0.0` (insufficient data).
    pub fn score(&self, input: &str) -> f32 {
        // Map input bytes to alphabet indices, skipping unmapped chars.
        let indices: Vec<u8> = input
            .bytes()
            .filter_map(|b| self.char_index[b as usize])
            .collect();

        if indices.len() < 3 {
            return 0.0;
        }

        let mut total_log_p = 0.0f32;
        let mut count = 0usize;

        for window in indices.windows(3) {
            let (a, b, c) = (window[0], window[1], window[2]);
            total_log_p += self.table[trigram_idx(a, b, c)];
            count += 1;
        }

        if count == 0 {
            return 0.0;
        }

        let avg_log_p = total_log_p / count as f32;

        // Normalize: map [SCORE_MIN, SCORE_MAX] → [0.0, 1.0]
        // avg_log_p near SCORE_MIN (natural) → score near 0.0
        // avg_log_p near SCORE_MAX (random)  → score near 1.0
        let normalized = (avg_log_p - SCORE_MIN) / (SCORE_MAX - SCORE_MIN);
        normalized.clamp(0.0, 1.0)
    }
}

impl Default for MarkovScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the flat table index for a trigram (a, b, c) in a 64³ table.
#[inline(always)]
fn trigram_idx(a: u8, b: u8, c: u8) -> usize {
    (a as usize) * 64 * 64 + (b as usize) * 64 + (c as usize)
}

/// Assign a heuristic log-probability to a trigram `(a, b, c)` where indices
/// are in 0..63 (corresponding to the ALPHABET).
///
/// Rules (approximate — will be replaced by trained values):
/// - Same-character trigram (e.g., `aaa`) → LOG_COMMON (low randomness)
/// - All lowercase letters (0..25) → LOG_COMMON
/// - Mixed case → LOG_MIXED
/// - Any digit (index 52–61) mixed with letters → LOG_RARE
/// - Special chars `_` (62) and `-` (63) → LOG_RARE when between digits
fn heuristic_log_prob(a: u8, b: u8, c: u8) -> f32 {
    // Same-character run (e.g., "aaa", "111").
    if a == b && b == c {
        return LOG_COMMON;
    }

    // All lowercase (0..=25).
    let all_lower = a < 26 && b < 26 && c < 26;
    if all_lower {
        return LOG_COMMON;
    }

    // All uppercase (26..=51).
    let all_upper = (26..=51).contains(&a) && (26..=51).contains(&b) && (26..=51).contains(&c);
    if all_upper {
        return LOG_MIXED;
    }

    // Digits (52..=61).
    let a_digit = (52..=61).contains(&a);
    let b_digit = (52..=61).contains(&b);
    let c_digit = (52..=61).contains(&c);

    if a_digit && b_digit && c_digit {
        // All-digit trigram (e.g., "123") — relatively common in code.
        return LOG_MIXED;
    }

    // Mixed digits + letters → high randomness signal.
    if (a_digit || b_digit || c_digit) && !all_lower && !all_upper {
        return LOG_RARE;
    }

    // Special chars `_` (62) or `-` (63) mixed with other classes.
    if a >= 62 || b >= 62 || c >= 62 {
        return LOG_RARE;
    }

    LOG_MIXED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scorer() -> MarkovScorer {
        MarkovScorer::new()
    }

    #[test]
    fn test_english_text_scores_low() {
        let s = scorer();
        // Natural English text should score low (not random).
        let score = s.score("the quick brown fox jumps over the lazy dog");
        assert!(
            score < 0.5,
            "English text should score < 0.5, got {score:.3}"
        );
    }

    #[test]
    fn test_repeated_pattern_scores_very_low() {
        let s = scorer();
        // Highly repetitive content should score near 0.
        let score = s.score("aaabbbcccaaabbbccc");
        assert!(
            score < 0.3,
            "Repeated pattern should score < 0.3, got {score:.3}"
        );
    }

    #[test]
    fn test_aws_access_key_scores_high() {
        let s = scorer();
        // AWS access key IDs are random-looking uppercase+digit strings.
        let score = s.score("AKIAIOSFODNN7EXAMPLE");
        assert!(
            score > 0.5,
            "AWS key should score > 0.5, got {score:.3}"
        );
    }

    #[test]
    fn test_github_pat_scores_high() {
        let s = scorer();
        // GitHub PATs: "ghp_" + 36 random alphanumeric chars.
        let score = s.score("ghp_R2yte8xVd7WqKjLm3NzOsFp9YcAhEoUBCI");
        assert!(
            score > 0.5,
            "GitHub PAT should score > 0.5, got {score:.3}"
        );
    }

    #[test]
    fn test_short_string_returns_zero() {
        let s = scorer();
        // Fewer than 3 alphabet chars → insufficient data.
        assert_eq!(s.score("ab"), 0.0);
        assert_eq!(s.score(""), 0.0);
    }

    #[test]
    fn test_score_clamped_to_unit_range() {
        let s = scorer();
        // All scores must be in [0.0, 1.0].
        for input in &[
            "AKIAIOSFODNN7EXAMPLE",
            "the quick brown fox",
            "aaabbbccc",
            "ghp_R2yte8xVd7WqKjLm3NzOsFp9YcAhEoUBCI",
            "sk-proj-ABCDEF1234567890abcdef",
        ] {
            let score = s.score(input);
            assert!(
                (0.0..=1.0).contains(&score),
                "Score for '{input}' out of range: {score}"
            );
        }
    }

    #[test]
    fn test_trigram_idx_correctness() {
        // (0, 0, 0) → 0
        assert_eq!(trigram_idx(0, 0, 0), 0);
        // (1, 0, 0) → 64*64 = 4096
        assert_eq!(trigram_idx(1, 0, 0), 4096);
        // (0, 1, 0) → 64
        assert_eq!(trigram_idx(0, 1, 0), 64);
        // (63, 63, 63) → last entry
        assert_eq!(trigram_idx(63, 63, 63), TABLE_SIZE - 1);
    }
}
