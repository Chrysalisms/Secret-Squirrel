//! CI/CD log source adapter.
//!
//! Fetches recent workflow run logs from CI/CD providers and produces
//! [`Fragment`]s for the scanning pipeline. CI logs frequently contain
//! accidentally-exposed secrets such as tokens echoed during build steps,
//! credentials in error tracebacks, or environment variable dumps.
//!
//! # Supported providers
//!
//! | Provider        | Status      |
//! |-----------------|-------------|
//! | GitHub Actions  | Implemented |
//! | GitLab CI       | Stub        |
//! | Jenkins         | Stub        |
//! | CircleCI        | Stub        |
//!
//! # GitHub Actions log extraction
//!
//! 1. `GET /repos/{owner}/{repo}/actions/runs?per_page={max_runs}` — list runs.
//! 2. For each run: `GET /repos/{owner}/{repo}/actions/runs/{id}/logs` — the
//!    API returns a `302` redirect to a pre-signed ZIP download URL.
//! 3. The ZIP is extracted in-memory; each log file inside becomes one
//!    [`Fragment`] with path `github-actions://{owner}/{repo}/{run_id}/{name}`.
//!
//! # Example
//!
//! ```rust,ignore
//! use secret_squirrel::sources::ci_logs::CiLogSourceBuilder;
//! use secret_squirrel::sources::traits::AsyncSource as _;
//!
//! # tokio_test::block_on(async {
//! let source = CiLogSourceBuilder::new()
//!     .github("my-org", "my-repo", None)
//!     .max_runs(5)
//!     .build()
//!     .unwrap();
//!
//! let fragments = source.fragments().await.unwrap();
//! # });
//! ```

use std::collections::HashMap;
use std::io::Read;

use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};
use zip::ZipArchive;

use crate::error::{Result, SquirrelError};
use crate::sources::traits::AsyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// CiProvider — supported providers
// ============================================================================

/// Identifies which CI/CD provider to scan and carries its configuration.
#[derive(Debug)]
pub enum CiProvider {
    /// GitHub Actions — requires owner and repo; token is optional for public
    /// repositories but highly recommended to avoid rate limiting.
    GitHub {
        owner: String,
        repo: String,
        token: Option<String>,
    },
    /// GitLab CI — stub, not yet implemented.
    GitLab {
        project_id: String,
        token: Option<String>,
    },
    /// Jenkins — stub, not yet implemented.
    Jenkins {
        base_url: String,
        token: Option<String>,
    },
    /// CircleCI — stub, not yet implemented.
    CircleCi {
        project_slug: String,
        token: Option<String>,
    },
}

// ============================================================================
// GitHub Actions API types
// ============================================================================

/// Response from `GET /repos/{owner}/{repo}/actions/runs`.
#[derive(Debug, Deserialize)]
struct GhRunsResponse {
    workflow_runs: Vec<GhRun>,
}

/// A single GitHub Actions workflow run.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GhRun {
    id: u64,
    name: Option<String>,
    status: Option<String>,
}

// ============================================================================
// CiLogSource
// ============================================================================

/// Async source that fetches CI/CD run logs and produces credential fragments.
///
/// Construct via [`CiLogSourceBuilder`].
#[derive(Debug)]
pub struct CiLogSource {
    provider: CiProvider,
    client: reqwest::Client,
    max_runs: usize,
    /// Override base URL for the GitHub API (used in tests).
    github_api_base: String,
}

impl CiLogSource {
    // ── GitHub Actions helpers ───────────────────────────────────────────────

    /// Attach GitHub-specific authentication and required headers.
    fn gh_get(&self, url: &str, token: Option<&str>) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Accept", "application/vnd.github.v3+json");
        if let Some(tok) = token {
            req = req.header("Authorization", format!("Bearer {tok}"));
        }
        req
    }

    /// Map an HTTP status to a [`SquirrelError`].
    fn gh_error(&self, status: reqwest::StatusCode, url: &str) -> SquirrelError {
        match status.as_u16() {
            401 => SquirrelError::Source {
                src_name: "ci-logs".into(),
                reason: "GitHub authentication failed — check token".into(),
            },
            403 => SquirrelError::Source {
                src_name: "ci-logs".into(),
                reason: "GitHub rate limited or forbidden".into(),
            },
            404 => SquirrelError::Source {
                src_name: "ci-logs".into(),
                reason: format!("GitHub resource not found: {url}"),
            },
            code => SquirrelError::Source {
                src_name: "ci-logs".into(),
                reason: format!("HTTP {code} from GitHub: {url}"),
            },
        }
    }

    /// Fetch log fragments for all recent GitHub Actions runs.
    async fn github_fragments(
        &self,
        owner: &str,
        repo: &str,
        token: Option<&str>,
    ) -> Result<Vec<Fragment>> {
        // 1. List recent runs.
        let runs_url = format!(
            "{}/repos/{}/{}/actions/runs?per_page={}",
            self.github_api_base, owner, repo, self.max_runs
        );

        let resp =
            self.gh_get(&runs_url, token)
                .send()
                .await
                .map_err(|e| SquirrelError::Source {
                    src_name: "ci-logs".into(),
                    reason: format!("GitHub request failed: {e}"),
                })?;

        if !resp.status().is_success() {
            return Err(self.gh_error(resp.status(), &runs_url));
        }

        let runs_resp: GhRunsResponse = resp.json().await.map_err(|e| SquirrelError::Source {
            src_name: "ci-logs".into(),
            reason: format!("JSON parse error for runs: {e}"),
        })?;

        debug!(
            source = "ci-logs",
            owner = owner,
            repo = repo,
            count = runs_resp.workflow_runs.len(),
            "Listed workflow runs"
        );

        let mut all_fragments = Vec::new();

        // 2. Fetch logs for each run.
        for run in &runs_resp.workflow_runs {
            let log_frags = self.github_run_logs(owner, repo, token, run).await;
            all_fragments.extend(log_frags);
        }

        Ok(all_fragments)
    }

    /// Fetch and extract logs for a single workflow run.
    ///
    /// GitHub returns a redirect (302) to a ZIP archive; we follow it,
    /// download the ZIP, and extract each log file as a separate fragment.
    async fn github_run_logs(
        &self,
        owner: &str,
        repo: &str,
        token: Option<&str>,
        run: &GhRun,
    ) -> Vec<Fragment> {
        let logs_url = format!(
            "{}/repos/{}/{}/actions/runs/{}/logs",
            self.github_api_base, owner, repo, run.id
        );

        // GitHub redirects to a pre-signed S3 URL — reqwest follows redirects
        // automatically, so we just download the response body.
        let resp = match self.gh_get(&logs_url, token).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "ci-logs",
                    run_id = run.id,
                    error = %e,
                    "Failed to fetch logs URL; skipping run"
                );
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            // 410 Gone means the logs have expired — this is normal.
            if resp.status().as_u16() == 410 {
                debug!(
                    source = "ci-logs",
                    run_id = run.id,
                    "Log archive expired (410); skipping run"
                );
            } else {
                warn!(
                    source = "ci-logs",
                    run_id = run.id,
                    status = resp.status().as_u16(),
                    "Non-success status fetching logs; skipping run"
                );
            }
            return Vec::new();
        }

        let zip_bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    source = "ci-logs",
                    run_id = run.id,
                    error = %e,
                    "Failed to download log ZIP; skipping run"
                );
                return Vec::new();
            }
        };

        // Extract the ZIP in memory.
        self.extract_log_zip(owner, repo, run, &zip_bytes)
    }

    /// Extract all text files from a log ZIP archive, producing one fragment
    /// per file.
    fn extract_log_zip(
        &self,
        owner: &str,
        repo: &str,
        run: &GhRun,
        zip_bytes: &[u8],
    ) -> Vec<Fragment> {
        let cursor = std::io::Cursor::new(zip_bytes);
        let mut archive = match ZipArchive::new(cursor) {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    source = "ci-logs",
                    run_id = run.id,
                    error = %e,
                    "Failed to open log ZIP; skipping run"
                );
                return Vec::new();
            }
        };

        let mut fragments = Vec::new();

        for i in 0..archive.len() {
            let mut zip_file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    warn!(
                        source = "ci-logs",
                        run_id = run.id,
                        entry = i,
                        error = %e,
                        "Failed to read ZIP entry; skipping"
                    );
                    continue;
                }
            };

            if zip_file.is_dir() {
                continue;
            }

            let entry_name = zip_file.name().to_owned();
            let mut buf = Vec::new();

            if let Err(e) = zip_file.read_to_end(&mut buf) {
                warn!(
                    source = "ci-logs",
                    run_id = run.id,
                    entry = %entry_name,
                    error = %e,
                    "Failed to read ZIP entry content; skipping"
                );
                continue;
            }

            let size = buf.len() as u64;
            let path = format!(
                "github-actions://{}/{}/{}/{}",
                owner, repo, run.id, entry_name
            );

            let mut attributes = HashMap::new();
            attributes.insert("owner".to_string(), owner.to_string());
            attributes.insert("repo".to_string(), repo.to_string());
            attributes.insert("run_id".to_string(), run.id.to_string());
            attributes.insert("log_file".to_string(), entry_name.clone());
            if let Some(run_name) = &run.name {
                attributes.insert("workflow_name".to_string(), run_name.clone());
            }

            debug!(
                source = "ci-logs",
                run_id = run.id,
                entry = %entry_name,
                bytes = size,
                "Extracted log fragment"
            );

            fragments.push(Fragment {
                content: Bytes::from(buf),
                metadata: FragmentMetadata {
                    path,
                    source_type: SourceType::CiLogs,
                    size,
                    attributes,
                },
            });
        }

        fragments
    }
}

// ============================================================================
// AsyncSource implementation
// ============================================================================

#[async_trait::async_trait]
impl AsyncSource for CiLogSource {
    fn name(&self) -> &str {
        "ci-logs"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        match &self.provider {
            CiProvider::GitHub { owner, repo, token } => {
                self.github_fragments(owner, repo, token.as_deref()).await
            }

            CiProvider::GitLab { project_id, .. } => {
                warn!(
                    source = "ci-logs",
                    provider = "gitlab",
                    project_id = %project_id,
                    "GitLab CI log scanning is not yet implemented"
                );
                Ok(vec![])
            }

            CiProvider::Jenkins { base_url, .. } => {
                warn!(
                    source = "ci-logs",
                    provider = "jenkins",
                    base_url = %base_url,
                    "Jenkins log scanning is not yet implemented"
                );
                Ok(vec![])
            }

            CiProvider::CircleCi { project_slug, .. } => {
                warn!(
                    source = "ci-logs",
                    provider = "circleci",
                    project_slug = %project_slug,
                    "CircleCI log scanning is not yet implemented"
                );
                Ok(vec![])
            }
        }
    }
}

// ============================================================================
// CiLogSourceBuilder
// ============================================================================

/// Builder for [`CiLogSource`].
///
/// # Example
///
/// ```rust,no_run
/// use secret_squirrel::sources::ci_logs::CiLogSourceBuilder;
///
/// let source = CiLogSourceBuilder::new()
///     .github("my-org", "infra", Some("ghp_token".to_string()))
///     .max_runs(20)
///     .build()
///     .unwrap();
/// ```
pub struct CiLogSourceBuilder {
    provider: Option<CiProvider>,
    max_runs: usize,
    github_api_base: Option<String>,
}

impl CiLogSourceBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            provider: None,
            max_runs: 10,
            github_api_base: None,
        }
    }

    /// Configure for GitHub Actions scanning.
    ///
    /// `token` is optional but highly recommended for rate-limit avoidance.
    /// If not supplied, the `GITHUB_TOKEN` environment variable is checked at
    /// build time.
    pub fn github(
        mut self,
        owner: impl Into<String>,
        repo: impl Into<String>,
        token: Option<String>,
    ) -> Self {
        let token = token.or_else(|| std::env::var("GITHUB_TOKEN").ok());
        self.provider = Some(CiProvider::GitHub {
            owner: owner.into(),
            repo: repo.into(),
            token,
        });
        self
    }

    /// Configure for GitLab CI scanning (stub).
    pub fn gitlab(mut self, project_id: impl Into<String>, token: Option<String>) -> Self {
        self.provider = Some(CiProvider::GitLab {
            project_id: project_id.into(),
            token,
        });
        self
    }

    /// Configure for Jenkins scanning (stub).
    pub fn jenkins(mut self, base_url: impl Into<String>, token: Option<String>) -> Self {
        self.provider = Some(CiProvider::Jenkins {
            base_url: base_url.into(),
            token,
        });
        self
    }

    /// Configure for CircleCI scanning (stub).
    pub fn circleci(mut self, project_slug: impl Into<String>, token: Option<String>) -> Self {
        self.provider = Some(CiProvider::CircleCi {
            project_slug: project_slug.into(),
            token,
        });
        self
    }

    /// Maximum number of workflow runs to fetch logs for (default: 10).
    pub fn max_runs(mut self, n: usize) -> Self {
        self.max_runs = n;
        self
    }

    /// Override the GitHub API base URL (used in tests).
    pub fn github_api_base(mut self, url: impl Into<String>) -> Self {
        self.github_api_base = Some(url.into());
        self
    }

    /// Build the [`CiLogSource`].
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Config`] if no provider was configured.
    pub fn build(self) -> Result<CiLogSource> {
        let provider = self
            .provider
            .ok_or_else(|| SquirrelError::Config("CiLogSource: a provider must be set".into()))?;

        Ok(CiLogSource {
            provider,
            client: reqwest::Client::new(),
            max_runs: self.max_runs,
            github_api_base: self
                .github_api_base
                .unwrap_or_else(|| "https://api.github.com".into()),
        })
    }
}

impl Default for CiLogSourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::traits::AsyncSource;
    use mockito::Server;

    fn build_github_source(server: &Server) -> CiLogSource {
        CiLogSourceBuilder::new()
            .github("test-owner", "test-repo", Some("test-token".to_string()))
            .max_runs(5)
            .github_api_base(server.url())
            .build()
            .expect("builder should succeed")
    }

    // ── name() ───────────────────────────────────────────────────────────────

    #[test]
    fn test_name_returns_ci_logs() {
        let source = CiLogSourceBuilder::new()
            .github("o", "r", None)
            .build()
            .unwrap();
        assert_eq!(source.name(), "ci-logs");
    }

    // ── Builder validation ───────────────────────────────────────────────────

    #[test]
    fn test_builder_requires_provider() {
        let result = CiLogSourceBuilder::new().build();
        assert!(result.is_err(), "build() should fail with no provider");
        assert!(
            result.unwrap_err().to_string().contains("provider"),
            "Error should mention provider"
        );
    }

    #[test]
    fn test_builder_sets_max_runs() {
        let source = CiLogSourceBuilder::new()
            .github("o", "r", None)
            .max_runs(42)
            .build()
            .unwrap();
        assert_eq!(source.max_runs, 42);
    }

    // ── 401 returns auth error ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_401_returns_auth_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/test-owner/test-repo/actions/runs?per_page=5")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Bad credentials"}"#)
            .create_async()
            .await;

        let source = build_github_source(&server);
        let result = source.fragments().await;

        assert!(result.is_err(), "401 should produce an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("authentication failed"),
            "Error should mention auth failure, got: {err}"
        );
    }

    // ── Empty run list returns empty vec ──────────────────────────────────────

    #[tokio::test]
    async fn test_empty_run_list_returns_empty_vec() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/test-owner/test-repo/actions/runs?per_page=5")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"workflow_runs":[]}"#)
            .create_async()
            .await;

        let source = build_github_source(&server);
        let fragments = source.fragments().await.expect("should succeed");
        assert!(fragments.is_empty(), "No runs → no fragments");
    }

    // ── Stub providers return empty vecs with no error ────────────────────────

    #[tokio::test]
    async fn test_gitlab_stub_returns_empty() {
        let source = CiLogSourceBuilder::new()
            .gitlab("12345", None)
            .build()
            .unwrap();
        let result = source.fragments().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_jenkins_stub_returns_empty() {
        let source = CiLogSourceBuilder::new()
            .jenkins("https://ci.example.com", None)
            .build()
            .unwrap();
        let result = source.fragments().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_circleci_stub_returns_empty() {
        let source = CiLogSourceBuilder::new()
            .circleci("gh/my-org/my-repo", None)
            .build()
            .unwrap();
        let result = source.fragments().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
