//! Finding deduplication.
//!
//! After fusion, the same secret may appear as multiple findings if it:
//! - Occurs in multiple overlapping entropy windows
//! - Matches several rules simultaneously
//! - Is found in a file that was processed by multiple pipeline workers
//!
//! [`Deduplicator`] groups findings by `(rule_id, secret_hash, path)` and
//! retains the single best finding per group using a stable, deterministic
//! policy.
//!
//! # Deduplication policy
//!
//! Within a group:
//! 1. **Highest confidence** — the finding with the best `score.confidence`
//!    is retained.
//! 2. **Tie-break: smallest range** — if confidence is equal, keep the finding
//!    with the most specific location (smallest `end_col - start_col` span on
//!    the same line, or smallest `end_line - start_line` span).
//! 3. **Tie-break: earliest offset** — if range is also equal, keep the one
//!    with the smaller `byte_offset`.

use std::collections::HashMap;

use crate::types::Finding;

/// Deduplication key: the triple that identifies a unique (credential, rule, file).
#[derive(Hash, PartialEq, Eq)]
struct DedupKey {
    secret_hash: String,
    path: String,
}

/// Deduplicates a collection of findings.
pub struct Deduplicator;

impl Deduplicator {
    /// Deduplicate a vector of findings.
    ///
    /// The input `findings` may be in any order. The output is sorted by
    /// descending confidence so the most significant findings appear first.
    ///
    /// # Arguments
    ///
    /// * `findings` — All raw findings from the pipeline (may contain duplicates).
    ///
    /// # Returns
    ///
    /// A deduplicated, sorted `Vec<Finding>`.
    pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
        // Group findings by (secret_hash, path).
        let mut groups: HashMap<DedupKey, Vec<Finding>> = HashMap::new();

        for finding in findings {
            let key = DedupKey {
                secret_hash: finding.secret_hash.clone(),
                path: finding.location.path.clone(),
            };
            groups.entry(key).or_default().push(finding);
        }

        // Within each group, select the best finding.
        let mut result: Vec<Finding> = groups
            .into_values()
            .map(|mut group| {
                // Sort by (descending confidence, ascending range, ascending offset).
                group.sort_by(|a, b| {
                    let precedence_cmp = b.evidence.precedence_rank().cmp(&a.evidence.precedence_rank());
                    if precedence_cmp != std::cmp::Ordering::Equal {
                        return precedence_cmp;
                    }

                    // Primary: higher confidence wins.
                    let conf_cmp = b
                        .score
                        .confidence
                        .partial_cmp(&a.score.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    if conf_cmp != std::cmp::Ordering::Equal {
                        return conf_cmp;
                    }

                    // Secondary: smaller line range wins (more specific location).
                    let a_lines = a.location.end_line.saturating_sub(a.location.start_line);
                    let b_lines = b.location.end_line.saturating_sub(b.location.start_line);
                    let range_cmp = a_lines.cmp(&b_lines);
                    if range_cmp != std::cmp::Ordering::Equal {
                        return range_cmp;
                    }

                    // Tertiary: smaller byte offset wins (earlier in file).
                    a.location.byte_offset.cmp(&b.location.byte_offset)
                });

                // Keep the first (best) finding in the sorted group.
                group.remove(0)
            })
            .collect();

        // Sort the output by descending confidence for presentation.
        result.sort_by(|a, b| {
            b.score
                .confidence
                .partial_cmp(&a.score.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FusedScore, Location, RedactedString, Severity};
    use chrono::Utc;

    fn make_finding(
        rule_id: &str,
        secret_hash: &str,
        path: &str,
        confidence: f64,
        byte_offset: u64,
        start_line: u32,
        end_line: u32,
    ) -> Finding {
        Finding {
            id: format!("{rule_id}-{byte_offset}"),
            rule_id: rule_id.to_string(),
            description: "Test finding".to_string(),
            secret: RedactedString::new("REDACTED".to_string()),
            secret_hash: secret_hash.to_string(),
            match_context: String::new(),
            location: Location {
                path: path.to_string(),
                start_line,
                end_line,
                start_col: 0,
                end_col: 20,
                byte_offset,
            },
            score: FusedScore {
                confidence,
                entropy: 0.5,
                proximity: 0.5,
                tristream: 0.5,
                pattern: 0.5,
                markov: 0.5,
                cnn_score: None,
                ast_adjustment: None,
            },
            evidence: crate::types::MatchEvidence {
                kind: if rule_id.contains("generic") {
                    crate::types::MatchKind::Catchall
                } else {
                    crate::types::MatchKind::ApiKeyAssignment
                },
                primary_identifier: None,
                secondary_context: None,
                proximity_pattern: crate::types::ProximityPattern::Assignment,
                typed: !rule_id.contains("generic"),
                generic_catchall: rule_id.contains("generic"),
                private_key_like: false,
                multiline: false,
                has_assignment: true,
                has_secret_identifier: true,
                has_auth_context: false,
                value_entropy: 4.0,
            },
            severity: Severity::High,
            chain: None,
            validation: None,
            remediation: None,
            detected_at: Utc::now(),
            encoding_chain: None,
        }
    }

    #[test]
    fn test_dedup_same_rule_hash_path() {
        // Two findings with identical (rule, hash, path) → deduplicated to one.
        let f1 = make_finding("aws-key", "abc123", "src/config.py", 0.8, 100, 10, 10);
        let f2 = make_finding("aws-key", "abc123", "src/config.py", 0.6, 200, 20, 20);

        let result = Deduplicator::deduplicate(vec![f1, f2]);
        assert_eq!(result.len(), 1, "Should deduplicate to one finding");
        assert!(
            (result[0].score.confidence - 0.8).abs() < 1e-9,
            "Should keep highest-confidence finding"
        );
    }

    #[test]
    fn test_dedup_different_paths_kept() {
        // Same rule and hash but different paths → both kept.
        let f1 = make_finding("aws-key", "abc123", "src/config.py", 0.8, 100, 10, 10);
        let f2 = make_finding("aws-key", "abc123", "tests/config.py", 0.8, 200, 20, 20);

        let result = Deduplicator::deduplicate(vec![f1, f2]);
        assert_eq!(result.len(), 2, "Different paths → both findings kept");
    }

    #[test]
    fn test_dedup_different_rules_same_secret() {
        // Different rule IDs with same hash and path → deduplicated to one.
        let f1 = make_finding("aws-key", "abc123", "src/main.rs", 0.8, 100, 10, 10);
        let f2 = make_finding("generic-key", "abc123", "src/main.rs", 0.7, 100, 10, 10);

        let result = Deduplicator::deduplicate(vec![f1, f2]);
        assert_eq!(
            result.len(),
            1,
            "Different rules but same secret → deduplicate to one"
        );
        assert_eq!(
            result[0].rule_id, "aws-key",
            "Should keep highest confidence finding"
        );
    }

    #[test]
    fn test_dedup_tie_break_by_range() {
        // Equal confidence but one has a tighter range (end_line - start_line = 0 vs 2).
        let f1 = make_finding("aws-key", "abc123", "src/main.rs", 0.8, 100, 10, 10); // range=0
        let f2 = make_finding("aws-key", "abc123", "src/main.rs", 0.8, 200, 10, 12); // range=2

        let result = Deduplicator::deduplicate(vec![f2, f1]); // note reversed order
        assert_eq!(result.len(), 1);
        // f1 has smaller range → should win.
        assert_eq!(
            result[0].location.byte_offset, 100,
            "Smaller-range finding should win tie-break"
        );
    }

    #[test]
    fn test_dedup_empty_input() {
        let result = Deduplicator::deduplicate(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_dedup_output_sorted_by_confidence() {
        let f1 = make_finding("rule-a", "h1", "a.py", 0.6, 10, 1, 1);
        let f2 = make_finding("rule-b", "h2", "a.py", 0.9, 20, 2, 2);
        let f3 = make_finding("rule-c", "h3", "a.py", 0.75, 30, 3, 3);

        let result = Deduplicator::deduplicate(vec![f1, f2, f3]);
        assert_eq!(result.len(), 3);
        assert!(result[0].score.confidence >= result[1].score.confidence);
        assert!(result[1].score.confidence >= result[2].score.confidence);
    }
}
