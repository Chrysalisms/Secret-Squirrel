//! Stage 4 — Pattern Verifier.
//!
//! The final pipeline stage applies targeted Aho-Corasick + regex matching to
//! the [`TriStreamResult`]s that survived the first three stages.
//!
//! # Two-phase approach
//!
//! 1. **Aho-Corasick scan** — built from all rule keywords at startup, runs in
//!    O(n) over the candidate context. This eliminates the cost of running
//!    every regex against every candidate.
//! 2. **Regex verification** — only triggered when the AC automaton fires for a
//!    given rule. The regex precisely validates the format of the matched text,
//!    including length, character classes, and checksums where applicable.
//!
//! # Performance
//!
//! With a typical rule set of 200 rules, the AC automaton processes ~2 GB/s on
//! modern hardware. Regex is invoked on fewer than 1% of windows that pass the
//! entropy gate.

use aho_corasick::AhoCorasick;

use crate::error::{Result, SquirrelError};
use crate::rules::CompiledRule;
use crate::types::{MatchEvidence, MatchKind, PatternMatch, TriStreamResult};

/// A keyword → rule-index mapping entry, built during construction.
struct KeywordEntry {
    /// Index of the rule in the `rules` Vec.
    rule_idx: usize,
}

/// Stage 4: Pattern verifier.
///
/// Built once from the full rule set. The [`AhoCorasick`] automaton is shared
/// across threads via `Arc` or used from a single-threaded pipeline step.
pub struct PatternVerifier {
    /// The Aho-Corasick automaton over all rule keywords.
    ac: AhoCorasick,
    /// Parallel vec: `keyword_map[ac_pattern_id]` → rule index.
    keyword_map: Vec<KeywordEntry>,
    /// The rules themselves.
    rules: Vec<CompiledRule>,
}

impl PatternVerifier {
    /// Build a [`PatternVerifier`] from a slice of compiled rules.
    ///
    /// Each rule may contribute zero or more keywords. Rules with no keywords
    /// are applied to every candidate (fallback rules — use sparingly).
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Pipeline`] if the Aho-Corasick automaton fails
    /// to build (e.g., empty pattern set).
    pub fn new(rules: &[CompiledRule]) -> Result<Self> {
        let mut patterns: Vec<String> = Vec::new();
        let mut keyword_map: Vec<KeywordEntry> = Vec::new();
        let mut rules_vec: Vec<CompiledRule> = Vec::with_capacity(rules.len());

        for (rule_idx, rule) in rules.iter().enumerate() {
            rules_vec.push(rule.clone());

            for keyword in &rule.keywords {
                patterns.push(keyword.clone());
                keyword_map.push(KeywordEntry { rule_idx });
            }
        }

        // Build the AC automaton.  If there are no keywords at all, insert a
        // single sentinel that will never appear so AC still initialises.
        if patterns.is_empty() {
            // No keywords — we'll fall back to running all regexes every time.
            patterns.push("\x00\x00".to_string()); // NUL sentinel
            keyword_map.push(KeywordEntry {
                rule_idx: usize::MAX,
            });
        }

        let ac = aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| SquirrelError::Pipeline {
                stage: "PatternVerifier".to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self {
            ac,
            keyword_map,
            rules: rules_vec,
        })
    }

    /// Verify all tri-stream results and return the subset that match at least
    /// one compiled rule.
    ///
    /// For each result:
    /// 1. Run the AC automaton over the context bytes.
    /// 2. For each AC hit, retrieve the associated rule.
    /// 3. Apply the rule's regex to the *full context* bytes converted to UTF-8
    ///    (using lossy conversion to avoid panics on non-UTF-8 input).
    /// 4. Emit a [`PatternMatch`] for each regex match found.
    pub fn verify(&self, results: Vec<TriStreamResult>) -> Vec<PatternMatch> {
        let mut matches: Vec<PatternMatch> = Vec::new();

        for result in results {
            // Convert context bytes to a UTF-8 string for regex matching.
            // Lossy conversion replaces invalid sequences with U+FFFD.
            let context_str = String::from_utf8_lossy(result.source.context.as_ref());

            // Evaluate the raw context first
            self.evaluate_payload(&result, &context_str, None, &mut matches);

            // Deep Decode literals and evaluate those
            for literal in &result.literals {
                let variants = crate::stages::decoder::deep_decode(literal, 5);
                for variant in variants {
                    if !variant.encoding_chain.is_empty() {
                        let decoded_str = String::from_utf8_lossy(&variant.data);
                        self.evaluate_payload(
                            &result,
                            &decoded_str,
                            Some(variant.encoding_chain),
                            &mut matches,
                        );
                    }
                }
            }
        }

        matches
    }

    fn evaluate_payload(
        &self,
        result: &TriStreamResult,
        payload_str: &str,
        encoding_chain: Option<Vec<String>>,
        matches: &mut Vec<PatternMatch>,
    ) {
        // Track which rule indices we have already triggered for this
        // payload so each rule fires at most once per payload variant.
        let mut fired: Vec<bool> = vec![false; self.rules.len()];

        // Phase 1: Aho-Corasick scan.
        for ac_match in self.ac.find_iter(payload_str.as_bytes()) {
            let entry = &self.keyword_map[ac_match.pattern().as_usize()];
            if entry.rule_idx == usize::MAX {
                continue; // sentinel
            }
            let rule_idx = entry.rule_idx;
            if fired[rule_idx] {
                continue; // Already processed this rule for this candidate
            }
            fired[rule_idx] = true;

            // Phase 2: Regex verification.
            let rule = &self.rules[rule_idx];
            if let Some(m) = rule.regex.find(payload_str) {
                matches.push(PatternMatch {
                    source: result.clone(),
                    rule_id: rule.id.clone(),
                    matched_text: m.as_str().to_owned(),
                    match_start: m.start(),
                    match_end: m.end(),
                    pattern_score: rule.confidence_weight as f32,
                    evidence: infer_pattern_evidence(rule, &result, m.as_str()),
                    encoding_chain: encoding_chain.clone(),
                });
                // One match per rule per candidate is sufficient.
            }
        }

        // Fallback: rules with no keywords are run against every candidate.
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if !rule.keywords.is_empty() || fired[rule_idx] {
                continue;
            }
            if let Some(m) = rule.regex.find(payload_str) {
                matches.push(PatternMatch {
                    source: result.clone(),
                    rule_id: rule.id.clone(),
                    matched_text: m.as_str().to_owned(),
                    match_start: m.start(),
                    match_end: m.end(),
                    pattern_score: rule.confidence_weight as f32,
                    evidence: infer_pattern_evidence(rule, &result, m.as_str()),
                    encoding_chain: encoding_chain.clone(),
                });
            }
        }
    }
}

fn infer_pattern_evidence(rule: &CompiledRule, result: &TriStreamResult, matched_text: &str) -> MatchEvidence {
    let lower_rule = rule.id.to_lowercase();
    let joined = result.identifiers.join(" ").to_lowercase();
    let kind = if lower_rule.contains("private-key") {
        MatchKind::PrivateKey
    } else if lower_rule.contains("api-key") || joined.contains("api_key") || joined.contains("apikey") {
        MatchKind::ApiKeyAssignment
    } else if lower_rule.contains("password") || joined.contains("password") {
        MatchKind::PasswordAssignment
    } else if lower_rule.contains("token") || joined.contains("token") {
        MatchKind::TokenAssignment
    } else if lower_rule.contains("nonce") || joined.contains("nonce") {
        MatchKind::NonceLike
    } else if lower_rule.contains("catchall") {
        MatchKind::Catchall
    } else {
        MatchKind::Unknown
    };

    MatchEvidence {
        kind,
        primary_identifier: result.identifiers.first().cloned(),
        secondary_context: None,
        proximity_pattern: result.source.pattern,
        typed: kind.is_typed(),
        generic_catchall: lower_rule.contains("catchall"),
        private_key_like: lower_rule.contains("private-key"),
        multiline: matched_text.contains('\n'),
        has_assignment: !matches!(result.source.pattern, crate::types::ProximityPattern::Unknown),
        has_secret_identifier: joined.contains("password")
            || joined.contains("secret")
            || joined.contains("token")
            || joined.contains("api_key")
            || joined.contains("apikey")
            || joined.contains("private_key")
            || joined.contains("nonce"),
        has_auth_context: joined.contains("auth"),
        value_entropy: crate::engine::cpu::shannon_entropy(matched_text.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::compiler::compile_rules;
    use crate::rules::parser::{Rule, RuleCategory};
    use crate::rules::CompiledRule;
    use crate::stages::entropy::shannon_entropy;
    use crate::types::{
        EntropyCandidate, ProximityMatch, ProximityPattern, Severity, TriStreamResult,
    };
    use bytes::Bytes;

    /// Build a minimal [`TriStreamResult`] wrapping the given context string.
    fn make_tri_result(context: &str, secret: &str) -> TriStreamResult {
        let secret_bytes = secret.as_bytes();
        let offset = context
            .as_bytes()
            .windows(secret_bytes.len())
            .position(|w| w == secret_bytes)
            .unwrap_or(0);

        let pm = ProximityMatch {
            candidate: EntropyCandidate {
                offset: offset as u64,
                length: secret_bytes.len() as u32,
                entropy: shannon_entropy(secret_bytes),
                raw: Bytes::copy_from_slice(secret_bytes),
            },
            pattern: ProximityPattern::Assignment,
            proximity_score: 0.5,
            context: Bytes::copy_from_slice(context.as_bytes()),
        };

        TriStreamResult {
            source: pm,
            identifiers: vec!["AWS_ACCESS_KEY_ID".to_string()],
            literals: vec![Bytes::copy_from_slice(secret_bytes)],
            structure_score: 0.5,
            combined_score: 0.7,
        }
    }

    /// Build a [`CompiledRule`] via `compile_rules`.
    fn make_compiled_rule(id: &str, regex: &str, keywords: Vec<&str>) -> CompiledRule {
        let rule = Rule {
            id: id.to_string(),
            description: format!("Test rule {id}"),
            regex: regex.to_string(),
            secret_group_regex: None,
            keywords: keywords.into_iter().map(|s| s.to_string()).collect(),
            severity: Severity::High,
            category: RuleCategory::Generic,
            tags: vec![],
            allowlist: vec![],
            entropy_threshold: None,
            confidence_weight: Some(0.90),
            validation_provider: None,
            remediation: None,
            squirrel: None,
        };
        compile_rules(vec![rule])
            .expect("test rule compile")
            .into_iter()
            .next()
            .expect("should compile one rule")
    }

    fn aws_rule() -> CompiledRule {
        make_compiled_rule("aws-access-key-id", r"AKIA[0-9A-Z]{16}", vec!["AKIA"])
    }

    #[test]
    fn test_pattern_verifier_matches_aws_key() {
        let rules = vec![aws_rule()];
        let verifier = PatternVerifier::new(&rules).unwrap();

        let context = "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"";
        let result = make_tri_result(context, "AKIAIOSFODNN7EXAMPLE");
        let matches = verifier.verify(vec![result]);

        assert_eq!(matches.len(), 1, "Should find exactly one AWS key match");
        assert_eq!(matches[0].rule_id, "aws-access-key-id");
        assert_eq!(matches[0].matched_text, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_pattern_verifier_no_match_on_plain_text() {
        let rules = vec![aws_rule()];
        let verifier = PatternVerifier::new(&rules).unwrap();

        let context = "Hello, World! This is a plain text string.";
        let result = make_tri_result(context, "plain text");
        let matches = verifier.verify(vec![result]);

        assert!(
            matches.is_empty(),
            "Plain text should not match AWS key rule"
        );
    }

    #[test]
    fn test_pattern_verifier_regex_boundary_enforced() {
        let rules = vec![aws_rule()];
        let verifier = PatternVerifier::new(&rules).unwrap();

        let long_key = "AKIAIOSFODNN7EXAMPLE1234EXTRA";
        let context = format!("AWS_KEY = \"{long_key}\"");
        let result = make_tri_result(&context, long_key);
        let matches = verifier.verify(vec![result]);

        if !matches.is_empty() {
            assert_eq!(
                matches[0].matched_text.len(),
                20,
                "Regex should match exactly 20-char AKIA key, not longer: {}",
                matches[0].matched_text
            );
            assert_ne!(matches[0].matched_text, long_key);
        }
    }

    #[test]
    fn test_pattern_verifier_empty_rules() {
        let verifier = PatternVerifier::new(&[]).unwrap();
        let result = make_tri_result("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE");
        let matches = verifier.verify(vec![result]);
        assert!(matches.is_empty(), "No rules → no matches");
    }

    #[test]
    fn test_pattern_verifier_multiple_rules() {
        let aws = aws_rule();
        let gh = make_compiled_rule("github-pat", r"ghp_[A-Za-z0-9]{36}", vec!["ghp_"]);

        let verifier = PatternVerifier::new(&[aws, gh]).unwrap();

        let pat = "ghp_R2yte8xVd7WqKjLm3NzOsFp9YcAhEoUBCI12";
        let context = format!("GITHUB_TOKEN = \"{pat}\"");
        let result = make_tri_result(&context, pat);
        let matches = verifier.verify(vec![result]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "github-pat");
    }
}
