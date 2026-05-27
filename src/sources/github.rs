//! GitHub source adapter.
//!
//! Scans one or all repositories belonging to an owner (user or organisation)
//! by walking the Git tree via the GitHub REST API v3 and fetching each blob.
//!
//! # Scanning strategy
//!
//! 1. If [`GitHubSource::repo`] is `Some`, scan only that repository.
//! 2. Otherwise, list every repository accessible under the owner and scan each.
//! 3. For each repository, resolve the target branch (explicit or default) to a
//!    commit SHA, then request the recursive Git tree to enumerate every blob.
//! 4. Blobs whose size exceeds [`GitHubSource::max_file_size`] are skipped to
//!    avoid fetching multi-megabyte binaries.
//! 5. File content is fetched via the Contents API and decoded from base64.
//!
//! # Authentication
//!
//! A GitHub Personal Access Token is required for private repositories and to
//! avoid aggressive rate limiting on public ones. Supply it via:
//! - The `GITHUB_TOKEN` environment variable, or
//! - [`GitHubSourceBuilder::token`] at construction time.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// GitHub API response types
// ============================================================================

/// A single entry returned by the GitHub List Repositories endpoint.
#[derive(Debug, Deserialize)]
struct GhRepo {
    name: String,
    default_branch: String,
}

/// The recursive tree response from `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1`.
#[derive(Debug, Deserialize)]
struct GhTree {
    tree: Vec<GhTreeEntry>,
    /// When `true` the response was truncated; the tree is too large for a
    /// single request (GitHub limit: 100 000 entries / 7 MB). We log a warning
    /// and process what we have.
    #[serde(default)]
    truncated: bool,
}

/// A single item in the Git tree (either a blob or a subtree).
#[derive(Debug, Deserialize)]
struct GhTreeEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String, // "blob" | "tree"
    sha: String,
    size: Option<u64>,
}

/// The Contents API response for a single file.
#[derive(Debug, Deserialize)]
struct GhContents {
    encoding: String,
    /// Base-64 encoded file content (with embedded newlines from GitHub).
    content: String,
}

/// A repository entry from the List Repos response (may include extra fields
/// we don't need — `#[serde(deny_unknown_fields)]` is intentionally absent).
#[derive(Debug, Deserialize)]
struct GhRepoRef {
    name: String,
    default_branch: String,
}

// ============================================================================
// GitHubSource
// ============================================================================

/// Async source that scans GitHub repositories for credential fragments.
///
/// Construct via [`GitHubSourceBuilder`]:
///
/// ```rust,no_run
/// # use secret_squirrel::sources::github::GitHubSourceBuilder;
/// let source = GitHubSourceBuilder::new()
///     .owner("my-org")
///     .repo("my-repo")
///     .build()
///     .unwrap();
/// ```
pub struct GitHubSource {
    client: reqwest::Client,
    token: Option<String>,
    owner: String,
    repo: Option<String>,
    max_file_size: u64,
    branch: Option<String>,
    /// Override the API base URL (used in unit tests via mockito).
    base_url: String,
}

impl GitHubSource {
    /// The default maximum file size to fetch (1 MiB).
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;

    /// Return a builder for constructing a [`GitHubSource`].
    pub fn builder() -> GitHubSourceBuilder {
        GitHubSourceBuilder::new()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Attach authentication and the mandatory User-Agent header to a request.
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Accept", "application/vnd.github.v3+json");
        if let Some(tok) = &self.token {
            req = req.header("Authorization", format!("Bearer {tok}"));
        }
        req
    }

    /// Map an HTTP status code to a [`SquirrelError`].
    fn status_error(&self, status: reqwest::StatusCode, url: &str) -> SquirrelError {
        match status.as_u16() {
            401 => SquirrelError::Source {
                src_name: "github".into(),
                reason: "authentication failed — check GITHUB_TOKEN".into(),
            },
            403 => SquirrelError::Source {
                src_name: "github".into(),
                reason: "rate limited or forbidden".into(),
            },
            404 => SquirrelError::Source {
                src_name: "github".into(),
                reason: format!("not found: {url}"),
            },
            code => SquirrelError::Source {
                src_name: "github".into(),
                reason: format!("HTTP {code} from {url}"),
            },
        }
    }

    /// Fetch all repositories for `self.owner`.
    async fn list_repos(&self) -> Result<Vec<GhRepoRef>> {
        let mut repos = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/orgs/{}/repos?per_page=100&page={page}",
                self.base_url, self.owner
            );
            let resp = self.authed_get(&url).send().await.map_err(|e| {
                SquirrelError::Source {
                    src_name: "github".into(),
                    reason: e.to_string(),
                }
            })?;

            if !resp.status().is_success() {
                // Fallback: try the /users/ endpoint (for personal accounts).
                if resp.status().as_u16() == 404 {
                    return self.list_user_repos().await;
                }
                return Err(self.status_error(resp.status(), &url));
            }

            let batch: Vec<GhRepoRef> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "github".into(),
                reason: format!("JSON parse error listing repos: {e}"),
            })?;

            let done = batch.len() < 100;
            repos.extend(batch);
            if done {
                break;
            }
            page += 1;
        }

        Ok(repos)
    }

    /// Fallback: list repos for a *user* (not an org).
    async fn list_user_repos(&self) -> Result<Vec<GhRepoRef>> {
        let mut repos = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/users/{}/repos?per_page=100&page={page}",
                self.base_url, self.owner
            );
            let resp = self.authed_get(&url).send().await.map_err(|e| {
                SquirrelError::Source {
                    src_name: "github".into(),
                    reason: e.to_string(),
                }
            })?;

            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), &url));
            }

            let batch: Vec<GhRepoRef> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "github".into(),
                reason: format!("JSON parse error listing user repos: {e}"),
            })?;

            let done = batch.len() < 100;
            repos.extend(batch);
            if done {
                break;
            }
            page += 1;
        }

        Ok(repos)
    }

    /// Fetch the recursive Git tree for a repository.
    ///
    /// `branch` is the branch/tag/SHA to start from. If `None` we use `HEAD`.
    async fn fetch_tree(&self, repo: &str, branch: &str) -> Result<GhTree> {
        let url = format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            self.base_url, self.owner, repo, branch
        );
        let resp = self.authed_get(&url).send().await.map_err(|e| {
            SquirrelError::Source {
                src_name: "github".into(),
                reason: e.to_string(),
            }
        })?;

        if !resp.status().is_success() {
            return Err(self.status_error(resp.status(), &url));
        }

        resp.json::<GhTree>().await.map_err(|e| SquirrelError::Source {
            src_name: "github".into(),
            reason: format!("JSON parse error fetching tree for {repo}: {e}"),
        })
    }

    /// Fetch the decoded content of a single file.
    ///
    /// Returns `None` when the file should be skipped (size limit, encoding).
    async fn fetch_blob(
        &self,
        repo: &str,
        path: &str,
        sha: &str,
    ) -> Option<Bytes> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}",
            self.base_url, self.owner, repo, path
        );
        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "github",
                    repo = repo,
                    path = path,
                    error = %e,
                    "HTTP request failed; skipping file"
                );
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "github",
                repo = repo,
                path = path,
                status = resp.status().as_u16(),
                "Non-success status fetching file; skipping"
            );
            return None;
        }

        let contents: GhContents = match resp.json().await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    source = "github",
                    repo = repo,
                    path = path,
                    error = %e,
                    "JSON parse error for file contents; skipping"
                );
                return None;
            }
        };

        if contents.encoding != "base64" {
            warn!(
                source = "github",
                repo = repo,
                path = path,
                encoding = %contents.encoding,
                "Unsupported encoding; skipping"
            );
            return None;
        }

        // GitHub inserts newlines into the base64 blob — strip them first.
        let clean = contents.content.replace('\n', "").replace('\r', "");
        match BASE64.decode(&clean) {
            Ok(bytes) => {
                debug!(
                    source = "github",
                    repo = repo,
                    path = path,
                    sha = sha,
                    bytes = bytes.len(),
                    "Fetched blob"
                );
                Some(Bytes::from(bytes))
            }
            Err(e) => {
                warn!(
                    source = "github",
                    repo = repo,
                    path = path,
                    error = %e,
                    "Base64 decode error; skipping"
                );
                None
            }
        }
    }

    /// Scan a single repository and return its fragments.
    async fn scan_repo(&self, repo: &str, default_branch: &str) -> Vec<Fragment> {
        let branch = self.branch.as_deref().unwrap_or(default_branch);

        let tree = match self.fetch_tree(repo, branch).await {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    source = "github",
                    repo = repo,
                    error = %e,
                    "Failed to fetch tree; skipping repo"
                );
                return Vec::new();
            }
        };

        if tree.truncated {
            warn!(
                source = "github",
                repo = repo,
                "Tree response was truncated by GitHub — some files may be missed"
            );
        }

        let mut fragments = Vec::new();

        for entry in &tree.tree {
            if entry.kind != "blob" {
                continue;
            }

            // Size check — GitHub sometimes omits the size for large blobs.
            if let Some(sz) = entry.size {
                if sz > self.max_file_size {
                    debug!(
                        source = "github",
                        repo = repo,
                        path = %entry.path,
                        size = sz,
                        max = self.max_file_size,
                        "Skipping oversized file"
                    );
                    continue;
                }
            }

            let content = match self.fetch_blob(repo, &entry.path, &entry.sha).await {
                Some(c) => c,
                None => continue,
            };

            // Final size guard after download (size field may have been absent).
            if content.len() as u64 > self.max_file_size {
                debug!(
                    source = "github",
                    repo = repo,
                    path = %entry.path,
                    "Skipping oversized file after download"
                );
                continue;
            }

            let size = content.len() as u64;
            let mut attributes = HashMap::new();
            attributes.insert("owner".into(), self.owner.clone());
            attributes.insert("repo".into(), repo.to_owned());
            attributes.insert("sha".into(), entry.sha.clone());
            attributes.insert("branch".into(), branch.to_owned());

            fragments.push(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: format!("{}/{}/{}", self.owner, repo, entry.path),
                    source_type: SourceType::GitHub,
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
impl crate::sources::traits::AsyncSource for GitHubSource {
    fn name(&self) -> &str {
        "github"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let repos: Vec<(String, String)> = if let Some(repo) = &self.repo {
            // Single-repo mode: resolve the default branch via the repo endpoint.
            let url = format!("{}/repos/{}/{}", self.base_url, self.owner, repo);
            let resp = self.authed_get(&url).send().await.map_err(|e| {
                SquirrelError::Source {
                    src_name: "github".into(),
                    reason: e.to_string(),
                }
            })?;

            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), &url));
            }

            let info: GhRepo = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "github".into(),
                reason: format!("JSON parse error fetching repo info: {e}"),
            })?;

            vec![(info.name, info.default_branch)]
        } else {
            // Multi-repo mode.
            self.list_repos()
                .await?
                .into_iter()
                .map(|r| (r.name, r.default_branch))
                .collect()
        };

        let mut all_fragments = Vec::new();
        for (repo, default_branch) in &repos {
            debug!(
                source = "github",
                owner = %self.owner,
                repo = %repo,
                "Scanning repository"
            );
            let frags = self.scan_repo(repo, default_branch).await;
            all_fragments.extend(frags);
        }

        Ok(all_fragments)
    }
}

// ============================================================================
// GitHubSourceBuilder
// ============================================================================

/// Builder for [`GitHubSource`].
///
/// # Example
///
/// ```rust,no_run
/// # use secret_squirrel::sources::github::GitHubSourceBuilder;
/// let source = GitHubSourceBuilder::new()
///     .owner("acme-corp")
///     .repo("infra")
///     .max_file_size_bytes(512 * 1024)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct GitHubSourceBuilder {
    token: Option<String>,
    owner: Option<String>,
    repo: Option<String>,
    max_file_size: Option<u64>,
    branch: Option<String>,
    /// Override the API base URL (used in tests).
    base_url: Option<String>,
}

impl GitHubSourceBuilder {
    /// Create a new builder with all fields unset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an explicit Personal Access Token.
    ///
    /// If not called, the builder will try `GITHUB_TOKEN` at [`build`] time.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Set the owner (organisation or user) to scan.
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Limit the scan to a specific repository name.
    ///
    /// If not set, all repositories accessible to `owner` will be scanned.
    pub fn repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    /// Set the maximum file size in bytes to fetch (default: 1 MiB).
    pub fn max_file_size_bytes(mut self, bytes: u64) -> Self {
        self.max_file_size = Some(bytes);
        self
    }

    /// Pin a specific branch/tag name. Defaults to the repository's default branch.
    pub fn branch(mut self, branch: impl Into<String>) -> Self {
        self.branch = Some(branch.into());
        self
    }

    /// Override the GitHub API base URL (useful for tests / GitHub Enterprise).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Build the [`GitHubSource`].
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Config`] if `owner` was not set.
    pub fn build(self) -> Result<GitHubSource> {
        let owner = self
            .owner
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SquirrelError::Config("GitHubSource: owner must be non-empty".into()))?;

        // Prefer explicit token, then fall back to env var.
        let token = self
            .token
            .or_else(|| std::env::var("GITHUB_TOKEN").ok());

        let client = reqwest::Client::new();

        Ok(GitHubSource {
            client,
            token,
            owner,
            repo: self.repo,
            max_file_size: self
                .max_file_size
                .unwrap_or(GitHubSource::DEFAULT_MAX_FILE_SIZE),
            branch: self.branch,
            base_url: self
                .base_url
                .unwrap_or_else(|| "https://api.github.com".into()),
        })
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

    // -----------------------------------------------------------------------
    // Helper: build a source pointed at the mockito server
    // -----------------------------------------------------------------------
    fn build_source(server: &Server) -> GitHubSource {
        GitHubSourceBuilder::new()
            .owner("test-owner")
            .repo("test-repo")
            .base_url(server.url())
            .build()
            .expect("builder should succeed")
    }

    // -----------------------------------------------------------------------
    // name()
    // -----------------------------------------------------------------------

    #[test]
    fn test_name_returns_github() {
        let source = GitHubSourceBuilder::new()
            .owner("test-owner")
            .build()
            .unwrap();
        assert_eq!(source.name(), "github");
    }

    // -----------------------------------------------------------------------
    // builder
    // -----------------------------------------------------------------------

    #[test]
    fn test_builder_requires_owner() {
        let result = GitHubSourceBuilder::new().build();
        assert!(
            result.is_err(),
            "build() should fail when owner is not set"
        );
    }

    #[test]
    fn test_builder_sets_fields() {
        let src = GitHubSourceBuilder::new()
            .owner("my-org")
            .repo("my-repo")
            .max_file_size_bytes(512)
            .branch("main")
            .token("ghp_test")
            .build()
            .unwrap();

        assert_eq!(src.owner, "my-org");
        assert_eq!(src.repo.as_deref(), Some("my-repo"));
        assert_eq!(src.max_file_size, 512);
        assert_eq!(src.branch.as_deref(), Some("main"));
        assert_eq!(src.token.as_deref(), Some("ghp_test"));
    }

    // -----------------------------------------------------------------------
    // HTTP 401 returns appropriate error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_401_returns_auth_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/test-owner/test-repo")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Bad credentials"}"#)
            .create_async()
            .await;

        let source = build_source(&server);
        let result = source.fragments().await;

        assert!(result.is_err(), "401 should produce an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("authentication failed"),
            "Error should mention auth failure, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 403 (rate limit / forbidden)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_403_returns_forbidden_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/test-owner/test-repo")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"API rate limit exceeded"}"#)
            .create_async()
            .await;

        let source = build_source(&server);
        let result = source.fragments().await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("rate limited or forbidden"),
            "Expected rate limit message, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // File content is decoded correctly (base64 → raw bytes)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_file_content_decoded() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        let mut server = Server::new_async().await;

        let secret_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        let encoded = BASE64.encode(secret_content);

        // 1) Repo info endpoint
        let _m_repo = server
            .mock("GET", "/repos/test-owner/test-repo")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"name":"test-repo","default_branch":"main"}"#)
            .create_async()
            .await;

        // 2) Git tree endpoint
        let tree_body = serde_json::json!({
            "tree": [
                {
                    "path": ".env",
                    "type": "blob",
                    "sha": "abc123",
                    "size": secret_content.len()
                }
            ],
            "truncated": false
        });
        let _m_tree = server
            .mock("GET", "/repos/test-owner/test-repo/git/trees/main?recursive=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(tree_body.to_string())
            .create_async()
            .await;

        // 3) Contents endpoint
        let contents_body = serde_json::json!({
            "encoding": "base64",
            "content": encoded
        });
        let _m_contents = server
            .mock("GET", "/repos/test-owner/test-repo/contents/.env")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(contents_body.to_string())
            .create_async()
            .await;

        let source = build_source(&server);
        let fragments = source.fragments().await.expect("should succeed");

        assert_eq!(fragments.len(), 1, "Should have exactly one fragment");
        let frag = &fragments[0];
        assert_eq!(
            std::str::from_utf8(&frag.content).unwrap(),
            secret_content,
            "Content should be correctly base64-decoded"
        );
        assert_eq!(frag.metadata.source_type, SourceType::GitHub);
        assert!(frag.metadata.path.contains(".env"));
        assert_eq!(frag.metadata.attributes["owner"], "test-owner");
        assert_eq!(frag.metadata.attributes["repo"], "test-repo");
    }

    // -----------------------------------------------------------------------
    // Oversized files are skipped
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_oversized_file_skipped() {
        let mut server = Server::new_async().await;

        let _m_repo = server
            .mock("GET", "/repos/test-owner/test-repo")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"name":"test-repo","default_branch":"main"}"#)
            .create_async()
            .await;

        let tree_body = serde_json::json!({
            "tree": [
                {
                    "path": "huge_binary.bin",
                    "type": "blob",
                    "sha": "def456",
                    "size": 10_000_000u64   // 10 MB — way over the 1 MB default
                }
            ],
            "truncated": false
        });
        let _m_tree = server
            .mock("GET", "/repos/test-owner/test-repo/git/trees/main?recursive=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(tree_body.to_string())
            .create_async()
            .await;

        let source = build_source(&server);
        let fragments = source.fragments().await.expect("should succeed");
        assert!(
            fragments.is_empty(),
            "Oversized file should be skipped, got {} fragments",
            fragments.len()
        );
    }
}
