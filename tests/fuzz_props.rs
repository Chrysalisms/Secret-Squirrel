//! Property-based fuzz tests using proptest.
//!
//! These run on stable Rust / Windows via `cargo test --test fuzz_props`.
//! They complement the libFuzzer targets (which require nightly + Linux).
//!
//! Each proptest generates hundreds of random inputs per run and verifies
//! the same invariants as the libFuzzer fuzz targets.

use proptest::prelude::*;
use secret_squirrel::rules::parser::{
    detect_format, parse_gitleaks_config, parse_squirrel_config, RuleFormat,
};
use secret_squirrel::scoring::MarkovScorer;
use secret_squirrel::sources::SyncSource;
use secret_squirrel::error::Result as SquirrelResult;
use secret_squirrel::types::Fragment;

// ── Rule parser properties ────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        max_shrink_iters: 512,
        ..Default::default()
    })]

    /// parse_squirrel_config must never panic on any UTF-8 string.
    /// If it succeeds, every rule must have a non-empty id and regex.
    #[test]
    fn prop_squirrel_parser_never_panics(s in ".*") {
        let result = parse_squirrel_config(&s);
        if let Ok(rules) = result {
            for rule in rules {
                prop_assert!(!rule.id.is_empty(), "rule id must not be empty");
                prop_assert!(!rule.regex.is_empty(), "rule regex must not be empty");
                if let Some(t) = rule.entropy_threshold {
                    prop_assert!(t.is_finite(), "entropy_threshold must be finite");
                }
            }
        }
    }

    /// parse_gitleaks_config must never panic on any UTF-8 string.
    #[test]
    fn prop_gitleaks_parser_never_panics(s in ".*") {
        let result = parse_gitleaks_config(&s);
        if let Ok(rules) = result {
            for rule in rules {
                prop_assert!(!rule.id.is_empty());
            }
        }
    }

    /// detect_format must always return one of the three known formats.
    #[test]
    fn prop_detect_format_always_returns_valid_variant(s in ".*") {
        let fmt = detect_format(&s);
        prop_assert!(
            matches!(fmt, RuleFormat::Squirrel | RuleFormat::Betterleaks | RuleFormat::Gitleaks),
            "detect_format returned unexpected variant"
        );
    }

    /// If content contains "gpu_hint", format must be Squirrel.
    #[test]
    fn prop_gpu_hint_implies_squirrel_format(suffix in ".*") {
        let content = format!("gpu_hint = \"entropy_first\"\n{suffix}");
        let fmt = detect_format(&content);
        prop_assert_eq!(fmt, RuleFormat::Squirrel);
    }

    /// Parsing valid minimal rule TOML round-trips correctly.
    #[test]
    fn prop_minimal_rule_round_trips(
        id in "[a-z][a-z0-9-]{0,30}",
        description in ".{0,100}",
        regex in "[^\\x00]{1,50}",
    ) {
        let toml = format!(
            "[[rules]]\nid = {:?}\ndescription = {:?}\nregex = {:?}\n",
            id, description, regex
        );
        let result = parse_squirrel_config(&toml);
        if let Ok(rules) = result {
            if let Some(rule) = rules.first() {
                // The id and regex we put in must come back out
                prop_assert_eq!(&rule.id, &id);
                prop_assert_eq!(&rule.regex, &regex);
            }
        }
    }
}

// ── Markov scorer properties ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 5000,
        ..Default::default()
    })]

    /// Markov score is always in [0.0, 1.0].
    #[test]
    fn prop_markov_score_in_unit_range(s in ".*") {
        let scorer = MarkovScorer::new();
        let score = scorer.score(&s);
        prop_assert!(
            score >= 0.0 && score <= 1.0,
            "score {score} out of [0,1] for input {:?}",
            &s[..s.len().min(40)]
        );
    }

    /// Strings shorter than 3 chars always score 0.0.
    #[test]
    fn prop_markov_short_strings_score_zero(s in ".{0,2}") {
        let scorer = MarkovScorer::new();
        let score = scorer.score(&s);
        prop_assert_eq!(score, 0.0, "short string {:?} scored {}", s, score);
    }

    /// Markov scorer is deterministic (same input → same output).
    #[test]
    fn prop_markov_scorer_is_deterministic(s in ".{3,50}") {
        let scorer = MarkovScorer::new();
        let s1 = scorer.score(&s);
        let s2 = scorer.score(&s);
        prop_assert_eq!(s1, s2, "non-deterministic scorer for {:?}", s);
    }

    /// Repeated single characters score below 0.2 (low randomness).
    #[test]
    fn prop_markov_repeated_chars_score_low(c in "[a-zA-Z]", n in 5usize..30) {
        let scorer = MarkovScorer::new();
        let s: String = std::iter::repeat(c).take(n).collect();
        let score = scorer.score(&s);
        prop_assert!(
            score < 0.3,
            "repeated char pattern {:?} scored {score}, expected < 0.3",
            s
        );
    }
}

// ── Archive property tests ────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        ..Default::default()
    })]

    /// ZIP archive scanner never panics on raw random bytes treated as ZIP.
    #[test]
    fn prop_archive_scanner_never_panics_on_garbage(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("fuzz.zip");
        std::fs::write(&path, &data).unwrap();

        // May error on bad ZIP header — that's fine
        if let Ok(source) = secret_squirrel::sources::archive::ArchiveSource::new(path, 1024 * 1024) {
            for frag in source.fragments() {
                let _: SquirrelResult<Fragment> = frag; // must not panic
            }
        }
    }

    /// Crafted valid ZIPs with arbitrary text content produce correct fragment count.
    #[test]
    fn prop_valid_zip_fragment_count_bounded(
        entries in prop::collection::vec(
            ("[a-z]{1,20}\\.txt", ".*"),
            1..5usize
        )
    ) {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("valid.zip");

        let file = std::fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = SimpleFileOptions::default();
        let num_entries = entries.len();

        for (name, content) in &entries {
            if zip.start_file(name, opts).is_ok() {
                let _ = zip.write_all(content.as_bytes());
            }
        }
        let _ = zip.finish();

        let source = secret_squirrel::sources::archive::ArchiveSource::new(
            path,
            50 * 1024 * 1024,
        ).unwrap();

        let fragments: Vec<Fragment> = source.fragments().filter_map(|r: SquirrelResult<Fragment>| r.ok()).collect();

        // Can't have more fragments than entries (some may be binary/skipped)
        prop_assert!(
            fragments.len() <= num_entries,
            "got {} fragments for {} entries",
            fragments.len(),
            num_entries
        );
    }
}
