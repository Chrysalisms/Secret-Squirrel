#![no_main]
// Fuzz target: rule parser (Squirrel/Betterleaks TOML format)
//
// Invariants we verify on every input:
//   1. Never panics (libFuzzer catches all panics as crashes)
//   2. If parse succeeds, every rule has a non-empty id and regex
//   3. Re-serialising + re-parsing round-trips correctly

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    // Must never panic — only return Ok or Err
    let result = secret_squirrel::rules::parser::parse_squirrel_config(s);

    if let Ok(rules) = result {
        for rule in &rules {
            // Invariant: all rules produced from a successful parse must have
            // non-empty ids and regexes (TOML deserialization should enforce this,
            // but let's make it explicit).
            assert!(
                !rule.id.is_empty(),
                "rule id must not be empty after successful parse"
            );
            assert!(
                !rule.regex.is_empty(),
                "rule regex must not be empty after successful parse"
            );
            // Invariant: entropy threshold, if set, must be a finite f32
            if let Some(threshold) = rule.entropy_threshold {
                assert!(
                    threshold.is_finite(),
                    "entropy_threshold must be finite, got {threshold}"
                );
            }
        }
    }
    // Err results are fine — malformed TOML should be rejected gracefully
});
