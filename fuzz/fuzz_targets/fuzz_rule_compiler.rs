#![no_main]
// Fuzz target: rule compiler
//
// The compiler takes parsed Rules and compiles regexes. This is the most
// dangerous stage because:
//   1. A crafted regex pattern could cause catastrophic backtracking (ReDoS)
//   2. The fancy-regex path (backreferences) has different parsing rules
//   3. Allowlist regex compilation can panic on some inputs
//
// We use a 5-second wall-clock timeout per fuzz iteration via libFuzzer's
// -timeout flag (set in .cargo/fuzz-config.toml). Any regex that hangs
// beyond the timeout is reported as a crash.

use libfuzzer_sys::fuzz_target;
use secret_squirrel::rules::parser::{Rule, RuleCategory};
use secret_squirrel::types::Severity;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // Split data into: regex pattern | allowlist_regex (separated by null byte)
    let parts: Vec<&str> = s.splitn(3, '\0').collect();
    let regex_str = parts.first().copied().unwrap_or("");
    let allowlist_str = parts.get(1).copied().unwrap_or("");
    let id_str = parts.get(2).copied().unwrap_or("fuzz-rule");

    if regex_str.is_empty() {
        return;
    }

    let rule = Rule {
        id: id_str.chars().take(64).collect(),
        description: "fuzz-generated rule".to_string(),
        regex: regex_str.to_string(),
        secret_group_regex: None,
        keywords: vec!["fuzz".to_string()],
        severity: Severity::Medium,
        category: RuleCategory::Generic,
        tags: vec![],
        allowlist: if allowlist_str.is_empty() {
            vec![]
        } else {
            vec![allowlist_str.to_string()]
        },
        entropy_threshold: None,
        confidence_weight: None,
        validation_provider: None,
        remediation: None,
        squirrel: None,
    };

    // compile_rules must never panic — bad regexes should be skipped with a warning
    let compiled = secret_squirrel::rules::compiler::compile_rules(vec![rule]);
    // Result: either Ok with 0 or 1 rules (invalid/ReDoS skipped), never a panic
    let _ = compiled;
});
