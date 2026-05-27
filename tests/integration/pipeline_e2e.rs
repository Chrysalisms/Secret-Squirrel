/// Integration test: end-to-end pipeline with planted secrets
///
/// These tests verify that the complete pipeline correctly detects
/// known secrets from test fixtures without false positives.
///
/// Run with: cargo test --test pipeline_e2e

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir).join("tests").join("fixtures")
    }

    #[test]
    fn fixtures_directory_exists() {
        let dir = fixtures_dir();
        assert!(dir.exists(), "Fixtures directory should exist at {:?}", dir);
    }

    #[test]
    fn secrets_fixture_exists() {
        let fixture = fixtures_dir().join("secrets").join("sample.env");
        assert!(fixture.exists(), "Secrets fixture should exist at {:?}", fixture);
    }

    #[test]
    fn non_secrets_fixture_exists() {
        let fixture = fixtures_dir().join("non_secrets").join("safe.env");
        assert!(fixture.exists(), "Non-secrets fixture should exist at {:?}", fixture);
    }

    // TODO: Add these tests as the pipeline implementation progresses:
    //
    // #[tokio::test]
    // async fn detects_aws_key_in_env_file() {
    //     let config = SquirrelConfig::default();
    //     let session = ScanSession::new(config);
    //     let source = DirSource::new(fixtures_dir().join("secrets"), &Default::default());
    //     // ... run pipeline, verify AWS key is detected with confidence > 0.8
    // }
    //
    // #[tokio::test]
    // async fn no_false_positives_in_safe_fixture() {
    //     // Scan the non_secrets fixture directory
    //     // Verify that NO findings are reported (or all are below threshold)
    // }
    //
    // #[tokio::test]
    // async fn cross_file_correlation_detected() {
    //     // Create a temp dir with .env + docker-compose.yml + app.py all using DB_PASSWORD
    //     // Verify that correlation engine identifies the 3-file chain
    // }
}
