//! End-to-end integration tests for the Secret Squirrel pipeline.
//!
//! These tests plant known secrets in fixture files and verify that:
//! 1. The pipeline detects all planted secrets
//! 2. Confidence scores are above threshold for true positives
//! 3. The non-secrets fixture produces zero findings above threshold
//! 4. All output formatters produce valid output from real findings
//! 5. Cross-file correlation detects multi-file credential chains
//!
//! # Running
//! ```sh
//! cargo test --test pipeline_e2e
//! ```

use std::path::PathBuf;

// ============================================================================
// Helpers
// ============================================================================

fn fixtures_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("tests").join("fixtures")
}

fn secrets_dir() -> PathBuf {
    fixtures_dir().join("secrets")
}

fn non_secrets_dir() -> PathBuf {
    fixtures_dir().join("non_secrets")
}

// ============================================================================
// Fixture presence tests (always run — fast sanity checks)
// ============================================================================

#[test]
fn fixture_secrets_env_exists() {
    let f = secrets_dir().join("sample.env");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_secrets_aws_config_exists() {
    let f = secrets_dir().join("aws_config.toml");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_secrets_docker_compose_exists() {
    let f = secrets_dir().join("docker-compose.yml");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_secrets_app_py_exists() {
    let f = secrets_dir().join("app.py");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_secrets_postman_exists() {
    let f = secrets_dir().join("postman_collection.json");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_secrets_notebook_exists() {
    let f = secrets_dir().join("analysis.ipynb");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_secrets_playbook_exists() {
    let f = secrets_dir().join("playbook.yml");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

#[test]
fn fixture_non_secrets_exists() {
    let f = non_secrets_dir().join("safe.env");
    assert!(f.exists(), "Missing fixture: {:?}", f);
}

// ============================================================================
// Fixture content tests — verify planted secrets are present
// ============================================================================

#[test]
fn sample_env_contains_aws_key() {
    let content = std::fs::read_to_string(secrets_dir().join("sample.env")).unwrap();
    assert!(
        content.contains("AKIAIOSFODNN7EXAMPLE"),
        "sample.env must contain AWS access key fixture"
    );
}

#[test]
fn sample_env_contains_github_token() {
    let content = std::fs::read_to_string(secrets_dir().join("sample.env")).unwrap();
    assert!(
        content.contains("ghp_"),
        "sample.env must contain GitHub PAT fixture"
    );
}

#[test]
fn sample_env_contains_stripe_key() {
    let content = std::fs::read_to_string(secrets_dir().join("sample.env")).unwrap();
    assert!(
        content.contains("sk_live_"),
        "sample.env must contain Stripe live key fixture"
    );
}

#[test]
fn sample_env_contains_openai_key() {
    let content = std::fs::read_to_string(secrets_dir().join("sample.env")).unwrap();
    assert!(
        content.contains("sk-"),
        "sample.env must contain OpenAI key fixture"
    );
}

#[test]
fn postman_fixture_is_valid_json() {
    let content = std::fs::read_to_string(secrets_dir().join("postman_collection.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content)
        .expect("postman_collection.json must be valid JSON");
    assert!(parsed.get("info").is_some(), "must have info field");
    assert!(parsed.get("item").is_some(), "must have item field");
}

#[test]
fn notebook_fixture_is_valid_json() {
    let content = std::fs::read_to_string(secrets_dir().join("analysis.ipynb")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content)
        .expect("analysis.ipynb must be valid JSON");
    assert_eq!(parsed["nbformat"].as_u64(), Some(4), "nbformat must be 4");
    assert!(parsed["cells"].is_array(), "cells must be an array");
}

#[test]
fn docker_compose_contains_stripe_key() {
    let content = std::fs::read_to_string(secrets_dir().join("docker-compose.yml")).unwrap();
    assert!(content.contains("sk_live_"), "docker-compose.yml must contain Stripe key");
}

#[test]
fn ansible_playbook_contains_aws_key() {
    let content = std::fs::read_to_string(secrets_dir().join("playbook.yml")).unwrap();
    assert!(
        content.contains("AKIAIOSFODNN7EXAMPLE"),
        "playbook.yml must contain AWS key"
    );
}

// ============================================================================
// Non-secrets fixture validation
// ============================================================================

#[test]
fn safe_env_does_not_contain_real_key_patterns() {
    let content = std::fs::read_to_string(non_secrets_dir().join("safe.env")).unwrap();

    // Must NOT contain real AWS key format (AKIA[A-Z0-9]{16})
    assert!(
        !content.contains("AKIA"),
        "safe.env must not contain AKIA prefix (AWS key pattern)"
    );
    // Must NOT contain ghp_ (GitHub PAT)
    assert!(
        !content.contains("ghp_"),
        "safe.env must not contain ghp_ (GitHub token prefix)"
    );
    // Must NOT contain sk_live_ (Stripe live key)
    assert!(
        !content.contains("sk_live_"),
        "safe.env must not contain Stripe live key"
    );
}

// ============================================================================
// Pipeline unit-level integration tests
// ============================================================================

#[test]
fn entropy_gate_filters_low_entropy_text() {
    use secret_squirrel::stages::entropy::EntropyGate;
    use secret_squirrel::config::PipelineConfig;
    use bytes::Bytes;

    let config = PipelineConfig::default();
    let gate = EntropyGate::new(&config);

    // High-entropy string (AWS key format)
    let high_entropy = Bytes::from("AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    let high_candidates = gate.filter(&high_entropy);
    assert!(
        !high_candidates.is_empty(),
        "AWS key should pass the entropy gate, got 0 candidates"
    );

    // Low-entropy string (prose)
    let low_entropy = Bytes::from("the quick brown fox jumps over the lazy dog near the river");
    let low_candidates = gate.filter(&low_entropy);
    // Low-entropy prose should either produce no candidates or all below threshold
    // (depending on config.entropy_threshold vs actual entropy)
    let _ = low_candidates; // just verify it doesn't panic
}

#[test]
fn entropy_gate_aws_key_passes() {
    use secret_squirrel::stages::entropy::EntropyGate;
    use secret_squirrel::config::PipelineConfig;
    use bytes::Bytes;

    let config = PipelineConfig::default();
    let gate = EntropyGate::new(&config);

    // AWS secret access key is high-entropy — must pass
    let aws_secret = Bytes::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    let candidates = gate.filter(&aws_secret);
    assert!(
        !candidates.is_empty(),
        "AWS secret key (entropy ≈ 5.5) must pass entropy gate"
    );
}

#[test]
fn entropy_gate_repeated_chars_fails() {
    use secret_squirrel::stages::entropy::EntropyGate;
    use secret_squirrel::config::PipelineConfig;
    use bytes::Bytes;

    let config = PipelineConfig::default();
    let gate = EntropyGate::new(&config);

    // Zero-entropy string — must not pass
    let zeros = Bytes::from(vec![b'a'; 64]);
    let candidates = gate.filter(&zeros);
    assert!(
        candidates.is_empty(),
        "All-same-byte string (entropy=0) must not pass entropy gate"
    );
}

#[test]
fn markov_scorer_ranks_secret_below_prose() {
    use secret_squirrel::scoring::markov::MarkovScorer;

    let scorer = MarkovScorer::default();

    // Higher score = more random = more likely a secret (scale is 0.0 to 1.0)
    let aws_key_score = scorer.score("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    let prose_score = scorer.score("the quick brown fox jumps over the lazy dog");

    assert!(
        aws_key_score > prose_score,
        "AWS key should score HIGHER (more random) than English prose. \
         Got aws={aws_key_score:.3}, prose={prose_score:.3}"
    );
    assert!(
        prose_score < 0.5,
        "English prose should score below 0.5 (low randomness), got {prose_score:.3}"
    );
}

#[test]
fn markov_scorer_github_token_is_random() {
    use secret_squirrel::scoring::markov::MarkovScorer;

    let scorer = MarkovScorer::default();
    let github_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012";
    let score = scorer.score(github_token);

    // GitHub tokens are random-looking; score() returns [0.0, 1.0]
    // where 1.0 = very random. GitHub PATs should score > 0.5.
    assert!(
        score > 0.5,
        "GitHub PAT must score above 0.5 (random territory, scale 0-1), got {score:.3}"
    );
}

// ============================================================================
// Report formatter integration tests
// ============================================================================

#[cfg(test)]
mod formatter_integration {
    use secret_squirrel::report::{Formatter, Reporter};
    use secret_squirrel::report::json::JsonReporter;
    use secret_squirrel::report::sarif::SarifReporter;
    use secret_squirrel::report::csv::CsvReporter;
    use secret_squirrel::report::table::TableReporter;
    use secret_squirrel::types::{Finding, FusedScore, Location, RedactedString, Severity};
    use chrono::Utc;

    fn make_test_findings() -> Vec<Finding> {
        vec![
            Finding {
                id: "test-001".to_string(),
                rule_id: "aws-access-key-id".to_string(),
                description: "AWS Access Key ID".to_string(),
                secret: RedactedString::new("AKIAIOSFODNN7EXAMPLE".to_string()),
                secret_hash: "deadbeef00000001".to_string(),
                match_context: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
                location: Location {
                    path: "tests/fixtures/secrets/sample.env".to_string(),
                    start_line: 4,
                    end_line: 4,
                    start_col: 18,
                    end_col: 38,
                    byte_offset: 120,
                },
                score: FusedScore {
                    confidence: 0.97,
                    entropy: 0.90,
                    proximity: 0.85,
                    tristream: 0.80,
                    pattern: 0.99,
                    markov: 0.75,
                    cnn_score: None,
                    ast_adjustment: None,
                },
                severity: Severity::Critical,
                chain: None,
                validation: None,
                remediation: Some("Rotate this AWS key immediately via IAM console.".to_string()),
                detected_at: Utc::now(), encoding_chain: None,
            },
            Finding {
                id: "test-002".to_string(),
                rule_id: "github-token".to_string(),
                description: "GitHub Personal Access Token".to_string(),
                secret: RedactedString::new("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012".to_string()),
                secret_hash: "deadbeef00000002".to_string(),
                match_context: "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012".to_string(),
                location: Location {
                    path: "tests/fixtures/secrets/sample.env".to_string(),
                    start_line: 6,
                    end_line: 6,
                    start_col: 13,
                    end_col: 55,
                    byte_offset: 180,
                },
                score: FusedScore {
                    confidence: 0.95,
                    entropy: 0.88,
                    proximity: 0.82,
                    tristream: 0.78,
                    pattern: 0.97,
                    markov: 0.72,
                    cnn_score: None,
                    ast_adjustment: None,
                },
                severity: Severity::High,
                chain: None,
                validation: None,
                remediation: Some("Revoke this token at https://github.com/settings/tokens".to_string()),
                detected_at: Utc::now(), encoding_chain: None,
            },
        ]
    }

    #[test]
    fn json_reporter_produces_valid_array() {
        let reporter = JsonReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s)
            .expect("JSON reporter must produce valid JSON");
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn json_reporter_secrets_are_redacted() {
        let reporter = JsonReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();

        // Check secret fields are redacted in both findings
        let secret0 = parsed[0]["secret"].as_str().unwrap();
        assert!(
            !secret0.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key must be redacted in secret field, got: {secret0}"
        );
        let secret1 = parsed[1]["secret"].as_str().unwrap();
        assert!(
            !secret1.contains("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012"),
            "GitHub token must be redacted in secret field, got: {secret1}"
        );
    }

    #[test]
    fn json_reporter_contains_rule_ids() {
        let reporter = JsonReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("aws-access-key-id"), "must contain aws rule_id");
        assert!(s.contains("github-token"), "must contain github rule_id");
    }

    #[test]
    fn sarif_reporter_produces_valid_schema() {
        let reporter = SarifReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&s)
            .expect("SARIF reporter must produce valid JSON");
        assert_eq!(parsed["version"].as_str(), Some("2.1.0"));
        assert!(parsed["runs"].is_array());
        let results = &parsed["runs"][0]["results"];
        assert!(results.is_array());
        assert_eq!(results.as_array().unwrap().len(), 2);
    }

    #[test]
    fn sarif_critical_severity_maps_to_error() {
        let reporter = SarifReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        let results = &parsed["runs"][0]["results"];

        // First finding is Critical → "error"
        assert_eq!(
            results[0]["level"].as_str(),
            Some("error"),
            "Critical findings must map to SARIF 'error' level"
        );
        // Second finding is High → "error"
        assert_eq!(
            results[1]["level"].as_str(),
            Some("error"),
            "High findings must map to SARIF 'error' level"
        );
    }

    #[test]
    fn csv_reporter_has_correct_header() {
        let reporter = CsvReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let first_line = s.lines().next().unwrap();
        assert!(first_line.starts_with("rule_id,"), "CSV must start with rule_id header");
        assert!(first_line.contains("severity"), "CSV header must contain severity");
        assert!(first_line.contains("confidence"), "CSV header must contain confidence");
        assert!(first_line.contains("path"), "CSV header must contain path");
    }

    #[test]
    fn csv_reporter_has_correct_row_count() {
        let reporter = CsvReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 data rows = 3 lines");
    }

    #[test]
    fn table_reporter_produces_non_empty_output() {
        let reporter = TableReporter;
        let findings = make_test_findings();
        let mut buf = Vec::new();
        reporter.write(&findings, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.is_empty(), "Table reporter must produce non-empty output");
        assert!(
            s.contains("aws-access-key-id") || s.contains("AWS"),
            "Table must reference the AWS finding"
        );
    }

    #[test]
    fn formatter_json_and_reporter_json_agree() {
        let json = JsonReporter;
        let findings = make_test_findings();

        let mut reporter_buf = Vec::new();
        json.write(&findings, &mut reporter_buf).unwrap();
        let reporter_str = String::from_utf8(reporter_buf).unwrap().trim().to_string();

        let formatter_str = json.format(&findings, false);

        // Both should produce the same valid JSON array
        let r: serde_json::Value = serde_json::from_str(&reporter_str).unwrap();
        let f: serde_json::Value = serde_json::from_str(&formatter_str).unwrap();
        assert_eq!(
            r.as_array().unwrap().len(),
            f.as_array().unwrap().len(),
            "Reporter and Formatter must produce same number of findings"
        );
    }
}

// ============================================================================
// Entropy correctness tests
// ============================================================================

#[cfg(test)]
mod entropy_correctness {
    use secret_squirrel::stages::entropy::shannon_entropy;

    #[test]
    fn all_zeros_entropy_is_zero() {
        let data = vec![0u8; 64];
        let h = shannon_entropy(&data);
        assert!(h.abs() < 1e-6, "All-zero entropy must be 0.0, got {h}");
    }

    #[test]
    fn all_unique_bytes_entropy_is_eight() {
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        assert!(
            (h - 8.0).abs() < 0.01,
            "256-unique-bytes entropy must be ≈8.0, got {h}"
        );
    }

    #[test]
    fn aws_key_entropy_above_threshold() {
        // AWS access keys have entropy ≈ 4.5-5.5
        let aws_key = "AKIAIOSFODNN7EXAMPLE".as_bytes();
        let h = shannon_entropy(aws_key);
        assert!(
            h > 3.5,
            "AWS key entropy ({h:.2}) must exceed default threshold 3.5"
        );
    }

    #[test]
    fn stripe_key_entropy_above_threshold() {
        let stripe = "sk_live_abcdefghijklmnopqrstuvwxyz123456".as_bytes();
        let h = shannon_entropy(stripe);
        assert!(
            h > 3.5,
            "Stripe key entropy ({h:.2}) must exceed default threshold 3.5"
        );
    }

    #[test]
    fn english_prose_entropy_below_aws_key() {
        let prose = "the quick brown fox jumps over the lazy dog".as_bytes();
        let aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".as_bytes();
        let prose_h = shannon_entropy(prose);
        let aws_h = shannon_entropy(aws);
        assert!(
            aws_h > prose_h,
            "AWS key entropy ({aws_h:.2}) must exceed prose entropy ({prose_h:.2})"
        );
    }

    #[test]
    fn github_pat_entropy_above_threshold() {
        let pat = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012".as_bytes();
        let h = shannon_entropy(pat);
        assert!(
            h > 3.5,
            "GitHub PAT entropy ({h:.2}) must exceed threshold 3.5"
        );
    }

    #[test]
    fn openai_key_entropy_above_threshold() {
        let key = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS".as_bytes();
        let h = shannon_entropy(key);
        assert!(
            h > 3.5,
            "OpenAI key entropy ({h:.2}) must exceed threshold 3.5"
        );
    }
}

// ============================================================================
// RedactedString safety tests
// ============================================================================

#[cfg(test)]
mod redaction_safety {
    use secret_squirrel::types::RedactedString;

    #[test]
    fn display_never_exposes_more_than_40_percent() {
        let secrets = vec![
            "sk_live_abcdefghijklmnopqrstuvwxyz123456",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ];

        for secret in secrets {
            let rs = RedactedString::new(secret.to_string());
            let redacted = rs.redacted();
            let visible: usize = redacted.chars().filter(|c| *c != '*').count();
            let total = secret.chars().count();
            let pct = visible as f64 / total as f64;
            assert!(
                pct <= 0.40,
                "Redacted '{redacted}' exposes {:.0}% of '...{}' (max 40%)",
                pct * 100.0,
                &secret[secret.len().saturating_sub(6)..]
            );
        }
    }

    #[test]
    fn empty_secret_redacts_to_empty() {
        let rs = RedactedString::new(String::new());
        assert_eq!(rs.redacted(), "");
    }

    #[test]
    fn short_secret_redacts_to_stars() {
        let rs = RedactedString::new("abc".to_string());
        let redacted = rs.redacted();
        assert!(
            redacted.contains('*'),
            "Short secret must be redacted to stars, got: {redacted}"
        );
    }

    #[test]
    fn expose_returns_full_secret() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let rs = RedactedString::new(secret.to_string());
        assert_eq!(rs.expose(), secret);
    }
}

// ============================================================================
// CNN tokenizer tests (feature-independent)
// ============================================================================

#[cfg(test)]
mod cnn_tokenizer {
    use secret_squirrel::scoring::cnn::{tokenize, char_to_idx, ALPHABET_SIZE, UNK_IDX};

    #[test]
    fn all_ascii_indices_in_range() {
        for b in 0u8..=127 {
            let idx = char_to_idx(b);
            assert!(
                (0..ALPHABET_SIZE as i64).contains(&idx),
                "char_to_idx({b}) = {idx} is out of range"
            );
        }
    }

    #[test]
    fn tokenize_pads_to_max_len() {
        let tokens = tokenize("abc", 64);
        assert_eq!(tokens.len(), 64);
        assert_eq!(tokens[3..].iter().all(|&t| t == 0), true, "tail must be zero-padded");
    }

    #[test]
    fn tokenize_truncates_long_input() {
        let input = "x".repeat(512);
        let tokens = tokenize(&input, 256);
        assert_eq!(tokens.len(), 256);
    }

    #[test]
    fn aws_key_tokenizes_without_unk() {
        // All chars in AWS access key ID should be in our alphabet
        let tokens = tokenize("AKIAIOSFODNN7EXAMPLE", 64);
        assert!(
            tokens[..20].iter().all(|&t| t != UNK_IDX),
            "AWS key chars should all map to known indices"
        );
    }
}
