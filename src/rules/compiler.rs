//! Rule compiler — transforms parsed [`Rule`]s into efficient runtime structures.
//!
//! # Compilation pipeline
//!
//! 1. For each [`Rule`]: attempt to compile regex with the standard [`regex`] crate.
//! 2. If the pattern contains backreferences (`\1`, `\2`, ...): use
//!    [`fancy_regex::Regex`] instead, which supports them at some cost.
//! 3. If the pattern looks like it could cause catastrophic backtracking (nested
//!    quantifiers such as `(a+)+`): log a warning and **skip** the rule rather
//!    than risk a ReDoS attack on the scan process.
//! 4. Invalid regexes are logged as warnings and skipped — a bad rule should
//!    never crash the entire scan.
//! 5. After all rules are compiled, [`build_automaton`] constructs a single
//!    Aho-Corasick automaton from all keyword sets for fast pre-filtering.

use crate::error::Result;
use crate::rules::parser::{Rule, RuleCategory};
use crate::types::Severity;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use tracing::{debug, warn};

// ============================================================================
// CompiledRule
// ============================================================================

/// A rule that has been parsed, validated, and compiled into runtime form.
///
/// This is the primary data structure consumed by the pattern verification stage.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Unique rule identifier (e.g., `"aws-access-key-id"`).
    pub id: String,

    /// Human-readable description surfaced in findings.
    pub description: String,

    /// The compiled standard regex (always present).
    ///
    /// Patterns that required [`fancy_regex`] will have this set to a trivial
    /// always-false pattern; use `fancy_regex` field instead in that case.
    pub regex: regex::Regex,

    /// Compiled fancy-regex for rules that use backreferences.
    ///
    /// When `Some`, this should be used **instead of** `regex` for matching.
    pub fancy_regex: Option<fancy_regex::Regex>,

    /// Optional secondary regex to extract just the secret group from a match.
    pub secret_group_regex: Option<regex::Regex>,

    /// Keywords for Aho-Corasick pre-filtering.
    ///
    /// The pattern verifier only applies this rule to fragments where at least
    /// one keyword is found by the global automaton. Empty = match all fragments.
    pub keywords: Vec<String>,

    /// Severity of findings produced by this rule.
    pub severity: Severity,

    /// Category of credential this rule targets.
    pub category: RuleCategory,

    /// Compiled allowlist regexes. Matches that also match an allowlist are suppressed.
    pub allowlist_regexes: Vec<regex::Regex>,

    /// Per-rule entropy threshold override.
    pub entropy_threshold: Option<f32>,

    /// Confidence weight for the scoring engine (0.0–1.0, default 1.0).
    pub confidence_weight: f64,

    /// Name of the validator to use for active validation.
    pub validation_provider: Option<String>,

    /// Remediation guidance text.
    pub remediation: Option<String>,
}

impl CompiledRule {
    /// Returns `true` if this rule uses fancy-regex (backreference capable).
    pub fn uses_fancy_regex(&self) -> bool {
        self.fancy_regex.is_some()
    }

    /// Test whether the given text matches this rule's main pattern.
    pub fn is_match(&self, text: &str) -> bool {
        if let Some(ref fr) = self.fancy_regex {
            fr.is_match(text).unwrap_or(false)
        } else {
            self.regex.is_match(text)
        }
    }
}

// ============================================================================
// ReDoS detection
// ============================================================================

/// Returns `true` if the pattern contains nested quantifiers that could cause
/// catastrophic backtracking (e.g. `(a+)+`, `(a*)*`, `(a|aa)+`).
///
/// This is a conservative heuristic. It correctly skips characters inside
/// `[...]` character classes so patterns like `[A-Za-z0-9+/]{40}` are not
/// falsely flagged.
fn looks_like_redos(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let len = bytes.len();
    let mut depth = 0i32;
    let mut group_has_quantifier = vec![false; 64];
    let mut in_char_class = false;

    let mut i = 0;
    while i < len {
        match bytes[i] {
            b'\\' => {
                // Skip escaped character — covers \+, \*, \[, etc.
                i += 2;
                continue;
            }
            b'[' if !in_char_class => {
                in_char_class = true;
            }
            b']' if in_char_class => {
                in_char_class = false;
            }
            // Inside a character class, +/* have no quantifier meaning.
            b'(' if !in_char_class => {
                depth += 1;
                let d = depth as usize;
                if d < group_has_quantifier.len() {
                    group_has_quantifier[d] = false;
                }
            }
            b')' if !in_char_class => {
                let next = if i + 1 < len { bytes[i + 1] } else { 0 };
                let is_quantified = matches!(next, b'+' | b'*' | b'?');
                let d = depth as usize;
                if is_quantified && d < group_has_quantifier.len() && group_has_quantifier[d] {
                    return true;
                }
                depth -= 1;
            }
            b'+' | b'*' if !in_char_class => {
                let d = depth as usize;
                if d < group_has_quantifier.len() {
                    group_has_quantifier[d] = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Returns `true` if the pattern contains backreferences (`\1` through `\9`).
fn has_backreferences(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next.is_ascii_digit() && next != b'0' {
                return true;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Returns `true` if the pattern contains lookahead or lookbehind assertions
/// (`(?=`, `(?!`, `(?<=`, `(?<!`), which require `fancy_regex`.
fn has_lookaround(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        // Look for (? then = ! < 
        if bytes[i] == b'(' && bytes[i + 1] == b'?' {
            let c = bytes[i + 2];
            if matches!(c, b'=' | b'!') {
                return true; // lookahead (?= or (?!
            }
            if c == b'<' && i + 3 < bytes.len() && matches!(bytes[i + 3], b'=' | b'!') {
                return true; // lookbehind (?<= or (?<!
            }
        }
        i += 1;
    }
    false
}

// ============================================================================
// Public compilation functions
// ============================================================================

/// Compile a slice of parsed [`Rule`]s into runtime [`CompiledRule`]s.
///
/// Rules with invalid or dangerous regex patterns are **skipped** with a
/// warning rather than aborting the scan. This ensures a single bad rule
/// file doesn't bring down the entire scan session.
pub fn compile_rules(rules: Vec<Rule>) -> Result<Vec<CompiledRule>> {
    let mut compiled = Vec::with_capacity(rules.len());

    for rule in rules {
        // ── ReDoS guard ──────────────────────────────────────────────────────
        if looks_like_redos(&rule.regex) {
            warn!(
                rule_id = %rule.id,
                pattern = %rule.regex,
                "skipping rule — pattern may cause catastrophic backtracking (ReDoS)"
            );
            continue;
        }

        // ── Backreference / lookaround detection ─────────────────────────────
        // Both backreferences and lookaround assertions require fancy_regex.
        let needs_fancy = has_backreferences(&rule.regex) || has_lookaround(&rule.regex);

        // ── Main regex compilation ───────────────────────────────────────────
        let (regex, fancy_regex) = if needs_fancy {
            // Compile with fancy_regex (supports backreferences + lookaround).
            match fancy_regex::Regex::new(&rule.regex) {
                Ok(fr) => {
                    // Provide a trivial never-matching standard regex as placeholder.
                    let placeholder = regex::Regex::new(r"\A\z").expect("static regex");
                    (placeholder, Some(fr))
                }
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        error = %e,
                        "skipping rule — fancy_regex compilation failed"
                    );
                    continue;
                }
            }
        } else {
            match regex::Regex::new(&rule.regex) {
                Ok(r) => (r, None),
                Err(e) => {
                    // Standard regex failed — try fancy_regex as a fallback
                    // (handles inline flag groups like (?-i:...) or other extensions).
                    match fancy_regex::Regex::new(&rule.regex) {
                        Ok(fr) => {
                            let placeholder = regex::Regex::new(r"\A\z").expect("static regex");
                            (placeholder, Some(fr))
                        }
                        Err(_) => {
                            warn!(
                                rule_id = %rule.id,
                                error = %e,
                                "skipping rule — regex compilation failed"
                            );
                            continue;
                        }
                    }
                }
            }
        };

        // ── Secret group regex ───────────────────────────────────────────────
        let secret_group_regex = if let Some(ref sgr) = rule.secret_group_regex {
            match regex::Regex::new(sgr) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        error = %e,
                        "ignoring secret_group_regex — compilation failed"
                    );
                    None
                }
            }
        } else {
            None
        };

        // ── Allowlist regexes ────────────────────────────────────────────────
        let allowlist_regexes: Vec<regex::Regex> = rule
            .allowlist
            .iter()
            .filter_map(|pat| match regex::Regex::new(pat) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        allowlist_pattern = %pat,
                        error = %e,
                        "ignoring invalid allowlist pattern"
                    );
                    None
                }
            })
            .collect();

        debug!(rule_id = %rule.id, "compiled rule successfully");

        compiled.push(CompiledRule {
            id: rule.id,
            description: rule.description,
            regex,
            fancy_regex,
            secret_group_regex,
            keywords: rule.keywords,
            severity: rule.severity,
            category: rule.category,
            allowlist_regexes,
            entropy_threshold: rule.entropy_threshold,
            confidence_weight: rule.confidence_weight.unwrap_or(1.0),
            validation_provider: rule.validation_provider,
            remediation: rule.remediation,
        });
    }

    Ok(compiled)
}

/// Build an [`AhoCorasick`] automaton from all keywords in the compiled rules.
///
/// The automaton is used as a fast pre-filter: only fragments that contain at
/// least one keyword from any rule need to be tested against full regexes.
///
/// Keywords are matched case-insensitively to catch `AWS_ACCESS_KEY`,
/// `aws_access_key`, and mixed-case variants.
pub fn build_automaton(rules: &[CompiledRule]) -> AhoCorasick {
    let keywords: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.keywords.iter().map(|k| k.as_str()))
        .collect();

    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&keywords)
        .expect("failed to build AhoCorasick automaton — this is a bug")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parser::{Rule, RuleCategory};
    use crate::types::Severity;

    fn make_rule(id: &str, regex: &str, keywords: Vec<&str>) -> Rule {
        Rule {
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
            confidence_weight: None,
            validation_provider: None,
            remediation: None,
            squirrel: None,
        }
    }

    #[test]
    fn test_valid_rule_compiles() {
        let rule = make_rule("aws-key", r"AKIA[0-9A-Z]{16}", vec!["AKIA"]);
        let compiled = compile_rules(vec![rule]).unwrap();
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].id, "aws-key");
    }

    #[test]
    fn test_invalid_regex_is_skipped() {
        let rule = make_rule("bad-rule", r"(unclosed[", vec![]);
        let compiled = compile_rules(vec![rule]).unwrap();
        // Rule should be skipped — no panic.
        assert_eq!(compiled.len(), 0);
    }

    #[test]
    fn test_redos_pattern_is_rejected() {
        // Classic ReDoS: `(a+)+`
        let rule = make_rule("redos-rule", r"(a+)+b", vec![]);
        let compiled = compile_rules(vec![rule]).unwrap();
        assert_eq!(compiled.len(), 0, "ReDoS pattern should be rejected");
    }

    #[test]
    fn test_allowlist_invalid_pattern_is_skipped() {
        let mut rule = make_rule("test", r"test\d+", vec!["test"]);
        rule.allowlist = vec!["(invalid[regex".to_string()]; // bad allowlist pattern
        let compiled = compile_rules(vec![rule]).unwrap();
        // Rule itself compiles; bad allowlist pattern is ignored.
        assert_eq!(compiled.len(), 1);
        assert!(compiled[0].allowlist_regexes.is_empty());
    }

    #[test]
    fn test_regex_matching() {
        let rule = make_rule("aws-key", r"AKIA[0-9A-Z]{16}", vec!["AKIA"]);
        let compiled = compile_rules(vec![rule]).unwrap();
        assert!(compiled[0].is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(!compiled[0].is_match("not-a-key"));
    }

    #[test]
    fn test_build_automaton() {
        let rules = compile_rules(vec![
            make_rule("r1", r"AKIA\w+", vec!["AKIA"]),
            make_rule("r2", r"ghp_\w+", vec!["ghp_"]),
        ])
        .unwrap();
        let ac = build_automaton(&rules);
        // The automaton should find "AKIA" in the test string.
        assert!(ac.is_match("config AKIAIOSFODNN7EXAMPLE_KEY=secret"));
        assert!(ac.is_match("token=ghp_sometoken"));
    }

    #[test]
    fn test_multiple_rules_compile() {
        let rules = vec![
            make_rule("r1", r"AKIA[0-9A-Z]{16}", vec!["AKIA"]),
            make_rule("r2", r"ghp_[a-zA-Z0-9]{36}", vec!["ghp_"]),
            make_rule("r3", r"sk-[a-zA-Z0-9]{48}", vec!["sk-"]),
        ];
        let compiled = compile_rules(rules).unwrap();
        assert_eq!(compiled.len(), 3);
    }

    #[test]
    fn test_confidence_weight_default() {
        let rule = make_rule("test", r"\d+", vec![]);
        let compiled = compile_rules(vec![rule]).unwrap();
        assert_eq!(compiled[0].confidence_weight, 1.0);
    }
}
