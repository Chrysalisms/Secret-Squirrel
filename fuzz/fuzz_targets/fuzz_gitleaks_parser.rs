#![no_main]
// Fuzz target: Gitleaks format parser
//
// Gitleaks configs have a slightly different schema (title vs description,
// allowlist.regexes vs allowlist). Fuzzing separately catches format-specific
// edge cases in the mapping layer.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let result = secret_squirrel::rules::parser::parse_gitleaks_config(s);

    if let Ok(rules) = result {
        for rule in &rules {
            assert!(!rule.id.is_empty(), "gitleaks rule must have non-empty id");
            // description may be empty if both title and description were absent
            // entropy threshold must be finite if present
            if let Some(t) = rule.entropy_threshold {
                assert!(t.is_finite(), "entropy threshold {t} is not finite");
            }
        }
    }
});
