//! Stage 2 — Semantic Proximity Detector.
//!
//! Filters [`EntropyCandidate`]s by examining the surrounding byte context for
//! patterns that indicate a secret assignment:
//!
//! - Assignment operators (`= "`, `='`)
//! - Key-value separators (`: "`, YAML/JSON style)
//! - Export statements and environment variable declarations
//! - HTTP header values (`Bearer`)
//! - Identifier keywords (`password`, `secret`, `token`, etc.)
//!
//! Candidates that accumulate a proximity score above the configured threshold
//! are promoted to [`ProximityMatch`]es for the tri-stream stage.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use bytes::Bytes;
use memchr::memmem;
use std::sync::OnceLock;

use crate::config::PipelineConfig;
use crate::types::{EntropyCandidate, ProximityMatch, ProximityPattern};

/// How many bytes of context to examine on either side of a candidate.
const CONTEXT_WINDOW: usize = 256;

/// A proximity signal: a byte pattern to search for and the score / pattern
/// type it implies when found.
struct ProximityRule {
    needle: &'static [u8],
    score: f32,
    pattern: ProximityPattern,
}

/// All proximity rules, ordered roughly by specificity (most specific first).
static PROXIMITY_RULES: &[ProximityRule] = &[
    ProximityRule { needle: b"= \"",    score: 0.35, pattern: ProximityPattern::Assignment   },
    ProximityRule { needle: b"='",      score: 0.30, pattern: ProximityPattern::Assignment   },
    ProximityRule { needle: b"= '",     score: 0.30, pattern: ProximityPattern::Assignment   },
    ProximityRule { needle: b": \"",    score: 0.25, pattern: ProximityPattern::JsonKey      },
    ProximityRule { needle: b": '",     score: 0.25, pattern: ProximityPattern::YamlKey      },
    ProximityRule { needle: b"export ", score: 0.25, pattern: ProximityPattern::Export       },
    ProximityRule { needle: b"ENV ",    score: 0.20, pattern: ProximityPattern::DockerEnv    },
    ProximityRule { needle: b"Bearer ", score: 0.30, pattern: ProximityPattern::HeaderValue  },
    ProximityRule { needle: b"ARG ",    score: 0.15, pattern: ProximityPattern::DockerEnv    },
    // Add generic unquoted variants for higher recall
    ProximityRule { needle: b"= ",      score: 0.20, pattern: ProximityPattern::Assignment   },
    ProximityRule { needle: b": ",      score: 0.20, pattern: ProximityPattern::JsonKey      },
];

/// Keyword identifiers that, if found in context, each contribute +0.20 to
/// the proximity score.
static KEYWORD_PROXIMITY: &[&[u8]] = &[
    b"password",
    b"secret",
    b"token",
    b"key",
    b"api",
    b"auth",
    b"credential",
    b"access",
    b"private",
];

static KEYWORD_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn keyword_ac() -> &'static AhoCorasick {
    KEYWORD_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(KEYWORD_PROXIMITY)
            .expect("failed to build proximity keyword automaton")
    })
}

/// Stage 2: Semantic proximity filter.
///
/// For each [`EntropyCandidate`], examines up to [`CONTEXT_WINDOW`] bytes on
/// either side of the candidate for assignment operators and secret-related
/// keywords. Candidates whose accumulated proximity score exceeds `threshold`
/// are promoted.
#[derive(Debug, Clone)]
pub struct ProximityDetector {
    /// Minimum cumulative proximity score to promote a candidate.
    pub threshold: f32,
}

impl ProximityDetector {
    /// Create a new [`ProximityDetector`] from pipeline configuration.
    pub fn new(config: &PipelineConfig) -> Self {
        Self {
            threshold: config.proximity_threshold,
        }
    }

    /// Scan all candidates against the full content and return those that pass
    /// the proximity threshold.
    ///
    /// # Arguments
    ///
    /// * `candidates`    — Output from [`EntropyGate::filter`].
    /// * `full_content`  — The original bytes being scanned (needed for context
    ///                     windows that may extend before `candidate.offset`).
    pub fn filter(
        &self,
        candidates: Vec<EntropyCandidate>,
        full_content: &Bytes,
    ) -> Vec<ProximityMatch> {
        let mut matches = Vec::new();

        for candidate in candidates {
            let offset = candidate.offset as usize;
            let end = (offset + candidate.length as usize).min(full_content.len());

            // Build the context window — up to CONTEXT_WINDOW bytes on each side.
            let ctx_start = offset.saturating_sub(CONTEXT_WINDOW);
            let ctx_end = (end + CONTEXT_WINDOW).min(full_content.len());
            let context_bytes = &full_content[ctx_start..ctx_end];

            let (score, dominant_pattern) = score_context(context_bytes);

            if score >= self.threshold {
                let context = full_content.slice(ctx_start..ctx_end);
                matches.push(ProximityMatch {
                    candidate,
                    pattern: dominant_pattern,
                    proximity_score: score.min(1.0),
                    context,
                });
            }
        }

        matches
    }
}

/// Compute a proximity score and the dominant [`ProximityPattern`] for a
/// context byte slice.
///
/// Returns `(score, pattern)` where score is the sum of all matched rule
/// scores (not clamped — caller may clamp to 1.0).
fn score_context(context: &[u8]) -> (f32, ProximityPattern) {
    let mut total_score = 0.0f32;
    let mut dominant = ProximityPattern::Unknown;
    let mut best_rule_score = 0.0f32;

    // Check proximity rules (structural patterns) — case-insensitive for text keywords
    let context_lower = context.to_ascii_lowercase();
    for rule in PROXIMITY_RULES {
        let matched = if rule.needle.iter().all(|c| c.is_ascii_alphabetic() || *c == b' ') {
            memmem::find(&context_lower, &rule.needle.to_ascii_lowercase()).is_some()
        } else {
            memmem::find(context, rule.needle).is_some()
        };
        
        if matched {
            total_score += rule.score;
            if rule.score > best_rule_score {
                best_rule_score = rule.score;
                dominant = rule.pattern;
            }
        }
    }

    // Check keyword proximity (each hit adds +0.20).
    // Using case-insensitive Aho-Corasick.
    for _ in keyword_ac().find_iter(context) {
        total_score += 0.20;
    }

    (total_score, dominant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PipelineConfig;
    use crate::stages::entropy::shannon_entropy;

    fn make_candidate(content: &[u8], offset: usize) -> EntropyCandidate {
        EntropyCandidate {
            offset: offset as u64,
            length: content.len() as u32,
            entropy: shannon_entropy(content),
            raw: Bytes::copy_from_slice(content),
        }
    }

    fn detector() -> ProximityDetector {
        ProximityDetector::new(&PipelineConfig::default())
    }

    #[test]
    fn test_aws_secret_key_assignment_passes() {
        // Classic AWS secret key assignment — should score high.
        let line = b"AWS_SECRET_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"";
        let secret = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        // The secret starts at offset 18 in `line`
        let secret_offset_in_line = line
            .windows(secret.len())
            .position(|w| w == secret)
            .expect("secret must be in line");

        let content = Bytes::copy_from_slice(line);
        let candidate = make_candidate(secret, secret_offset_in_line);
        let detector = detector();
        let matches = detector.filter(vec![candidate], &content);

        assert!(
            !matches.is_empty(),
            "AWS_SECRET_KEY assignment should pass proximity filter"
        );
        assert!(
            matches[0].proximity_score > 0.3,
            "Proximity score should be > 0.3, got {}",
            matches[0].proximity_score
        );
    }

    #[test]
    fn test_plain_text_fails_proximity() {
        // A plain English sentence — no assignment operators, no secret keywords.
        let line = b"The quick brown fox jumps over the lazy dog and runs away fast";
        // A medium-entropy substring
        let candidate_bytes = b"jumps over the lazy";
        let offset = line
            .windows(candidate_bytes.len())
            .position(|w| w == candidate_bytes)
            .unwrap();

        let content = Bytes::copy_from_slice(line);
        let candidate = make_candidate(candidate_bytes, offset);

        // Use a detector with a non-zero threshold so plain text is rejected.
        let detector = detector(); // threshold = 0.2
        let matches = detector.filter(vec![candidate], &content);

        assert!(
            matches.is_empty(),
            "Plain English text should fail proximity filter"
        );
    }

    #[test]
    fn test_bearer_header_passes() {
        let line = b"Authorization: Bearer ghp_R2yte8xVd7WqKjLm3NzOsFp9YcAhEoUBCI";
        let secret = b"ghp_R2yte8xVd7WqKjLm3NzOsFp9YcAhEoUBCI";
        let offset = line
            .windows(secret.len())
            .position(|w| w == secret)
            .unwrap();
        let content = Bytes::copy_from_slice(line);
        let candidate = make_candidate(secret, offset);
        let matches = detector().filter(vec![candidate], &content);

        assert!(!matches.is_empty(), "Bearer header token should pass");
        assert_eq!(matches[0].pattern, ProximityPattern::HeaderValue);
    }

    #[test]
    fn test_json_key_passes() {
        let line = br#"{"api_key": "sk-proj-ABCDEF123456789"}"#;
        let secret = b"sk-proj-ABCDEF123456789";
        let offset = line
            .windows(secret.len())
            .position(|w| w == secret)
            .unwrap();
        let content = Bytes::copy_from_slice(line);
        let candidate = make_candidate(secret, offset);
        let matches = detector().filter(vec![candidate], &content);
        assert!(!matches.is_empty(), "JSON api_key pattern should pass");
    }

    #[test]
    fn test_score_context_accumulates() {
        // Context with multiple signals should accumulate higher score.
        let ctx = b"export PASSWORD = \"hunter2\"";
        let (score, _) = score_context(ctx);
        // export (+0.25) + PASSWORD keyword (+0.20) + = " (+0.35) = 0.80
        assert!(score >= 0.7, "Multi-signal context should score >= 0.7, got {score}");
    }
}
