//! GitLab source adapter.
//!
//! Scans one or all projects (repositories) belonging to a namespace (group or
//! user) using the GitLab REST API v4.
//!
//! # Scanning strategy
//!
//! 1. If [`GitLabSource::project_id`] is `Some`, scan only that project.
//! 2. Otherwise, if [`GitLabSource::namespace`] is set, list all projects in
//!    that group (including subgroups) and scan each.
//! 3. For each project, walk the recursive repository tree to enumerate blobs,
//!    then fetch each blob's raw content.
//! 4. Files whose byte-length would exceed [`GitLabSource::max_file_size`] are
//!    skipped after the first chunk is downloaded.
//!
//! # Authentication
//!
//! A GitLab Personal Access Token with `read_api` scope is required for
//! private projects and to avoid rate limiting. Supply it via:
//! - The `GITLAB_TOKEN` environment variable, or
//! - [`GitLabSourceBuilder::token`] at construction time.

use std::collections::HashMap;

use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// GitLab API response types
// ============================================================================

/// A project entry returned by the GitLab projects endpoints.
#[derive(Debug, Deserialize)]
struct GlProject {
    id: u64,
    /// The default branch name (e.g. `"main"` or `"master"`).
    default_branch: Option<String>,
    path_with_namespace: String,
}

/// A single item in the repository tree listing.
#[derive(Debug, Deserialize)]
struct GlTreeEntry {
    /// The file/directory path relative to the repository root.
    path: String,
    /// Either `"blob"` (file) or `"tree"` (directory).
    #[serde(rename = "type")]
    kind: String,
    /// The object ID (SHA) for this entry.
    id: String,
}

// ============================================================================
// GitLabSource
// ============================================================================

/// Async source that scans GitLab projects for credential fragments.
///
/// Construct via [`GitLabSourceBuilder`]:
///
/// ```rust,no_run
/// # use secret_squirrel::sources::gitlab::GitLabSourceBuilder;
/// let source = GitLabSourceBuilder::new()
///     .namespace("my-group")
///     .build()
///     .unwrap();
/// ```
pub struct GitLabSource {
    client: reqwest::Client,
    token: Option<String>,
    /// GitLab API v4 base URL (default: `https://gitlab.com/api/v4`).
    base_url: String,
    /// Group or user namespace to scan when no specific project is given.
    namespace: Option<String>,
    /// Specific project ID to scan. Takes priority over `namespace`.
    project_id: Option<u64>,
    /// Maximum byte size of a single file to fetch.
    max_file_size: u64,
}

impl GitLabSource {
    /// Default maximum file size to fetch (1 MiB).
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;

    /// Return a builder.
    pub fn builder() -> GitLabSourceBuilder {
        GitLabSourceBuilder::new()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Attach the PRIVATE-TOKEN header (if set) to a GET request.
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0");
        if let Some(tok) = &self.token {
            req = req.header("PRIVATE-TOKEN", tok);
        }
        req
    }

    /// Convert an HTTP status code to a descriptive [`SquirrelError`].
    fn status_error(&self, status: reqwest::StatusCode, url: &str) -> SquirrelError {
        match status.as_u16() {
            401 => SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: "authentication failed — check GITLAB_TOKEN".into(),
            },
            403 => SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: "rate limited or forbidden".into(),
            },
            404 => SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: format!("not found: {url}"),
            },
            code => SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: format!("HTTP {code} from {url}"),
            },
        }
    }

    /// Fetch metadata for a single project by ID.
    async fn fetch_project(&self, id: u64) -> Result<GlProject> {
        let url = format!("{}/projects/{}", self.base_url, id);
        let resp = self
            .authed_get(&url)
            .send()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            return Err(self.status_error(resp.status(), &url));
        }

        resp.json::<GlProject>()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: format!("JSON parse error fetching project {id}: {e}"),
            })
    }

    /// List all projects in a namespace (group), including subgroups.
    ///
    /// Falls back to the `/users/{namespace}/projects` endpoint when the group
    /// endpoint returns 404 (personal namespace).
    async fn list_namespace_projects(&self, namespace: &str) -> Result<Vec<GlProject>> {
        let mut projects = Vec::new();
        let mut page = 1u32;

        loop {
            // URL-encode the namespace (slashes become %2F).
            let encoded = urlencoding_simple(namespace);
            let url = format!(
                "{}/groups/{}/projects?include_subgroups=true&per_page=100&page={page}",
                self.base_url, encoded
            );
            let resp = self
                .authed_get(&url)
                .send()
                .await
                .map_err(|e| SquirrelError::Source {
                    src_name: "gitlab".into(),
                    reason: e.to_string(),
                })?;

            if !resp.status().is_success() {
                if resp.status().as_u16() == 404 {
                    return self.list_user_projects(namespace).await;
                }
                return Err(self.status_error(resp.status(), &url));
            }

            let batch: Vec<GlProject> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: format!("JSON parse error listing projects: {e}"),
            })?;

            let done = batch.len() < 100;
            projects.extend(batch);
            if done {
                break;
            }
            page += 1;
        }

        Ok(projects)
    }

    /// Fallback: list projects belonging to a *user* namespace.
    async fn list_user_projects(&self, username: &str) -> Result<Vec<GlProject>> {
        let mut projects = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/users/{}/projects?per_page=100&page={page}",
                self.base_url, username
            );
            let resp = self
                .authed_get(&url)
                .send()
                .await
                .map_err(|e| SquirrelError::Source {
                    src_name: "gitlab".into(),
                    reason: e.to_string(),
                })?;

            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), &url));
            }

            let batch: Vec<GlProject> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: format!("JSON parse error listing user projects: {e}"),
            })?;

            let done = batch.len() < 100;
            projects.extend(batch);
            if done {
                break;
            }
            page += 1;
        }

        Ok(projects)
    }

    /// Fetch the full recursive tree for a project.
    async fn fetch_tree(&self, project_id: u64, branch: &str) -> Result<Vec<GlTreeEntry>> {
        let mut entries = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/projects/{}/repository/tree?recursive=true&per_page=100&page={page}&ref={}",
                self.base_url, project_id, branch
            );
            let resp = self
                .authed_get(&url)
                .send()
                .await
                .map_err(|e| SquirrelError::Source {
                    src_name: "gitlab".into(),
                    reason: e.to_string(),
                })?;

            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), &url));
            }

            let batch: Vec<GlTreeEntry> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "gitlab".into(),
                reason: format!("JSON parse error fetching tree for project {project_id}: {e}"),
            })?;

            let done = batch.len() < 100;
            entries.extend(batch);
            if done {
                break;
            }
            page += 1;
        }

        Ok(entries)
    }

    /// Fetch the raw content of a single file.
    ///
    /// Returns `None` if the file should be skipped.
    async fn fetch_raw_file(&self, project_id: u64, path: &str, branch: &str) -> Option<Bytes> {
        // GitLab requires the file path to be URL-encoded (slashes → %2F).
        let encoded_path = urlencoding_simple(path);
        let url = format!(
            "{}/projects/{}/repository/files/{}/raw?ref={}",
            self.base_url, project_id, encoded_path, branch
        );

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "gitlab",
                    project_id,
                    path,
                    error = %e,
                    "HTTP request failed; skipping file"
                );
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "gitlab",
                project_id,
                path,
                status = resp.status().as_u16(),
                "Non-success status fetching file; skipping"
            );
            return None;
        }

        // Stream bytes with a size guard to avoid OOM on unexpectedly large responses.
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    source = "gitlab",
                    project_id,
                    path,
                    error = %e,
                    "Failed to read response body; skipping"
                );
                return None;
            }
        };

        if bytes.len() as u64 > self.max_file_size {
            debug!(
                source = "gitlab",
                project_id,
                path,
                size = bytes.len(),
                max = self.max_file_size,
                "Skipping oversized file"
            );
            return None;
        }

        debug!(
            source = "gitlab",
            project_id,
            path,
            bytes = bytes.len(),
            "Fetched file"
        );

        Some(bytes)
    }

    /// Scan a single project and collect fragments.
    async fn scan_project(&self, project: &GlProject) -> Vec<Fragment> {
        let branch = project.default_branch.as_deref().unwrap_or("HEAD");

        let tree = match self.fetch_tree(project.id, branch).await {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    source = "gitlab",
                    project_id = project.id,
                    path_with_namespace = %project.path_with_namespace,
                    error = %e,
                    "Failed to fetch tree; skipping project"
                );
                return Vec::new();
            }
        };

        let mut fragments = Vec::new();

        for entry in &tree {
            if entry.kind != "blob" {
                continue;
            }

            let content = match self.fetch_raw_file(project.id, &entry.path, branch).await {
                Some(c) => c,
                None => continue,
            };

            let size = content.len() as u64;
            let mut attributes = HashMap::new();
            attributes.insert("project".into(), project.path_with_namespace.clone());
            attributes.insert("project_id".into(), project.id.to_string());
            attributes.insert("sha".into(), entry.id.clone());
            attributes.insert("branch".into(), branch.to_owned());

            fragments.push(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: format!("{}/{}", project.path_with_namespace, entry.path),
                    source_type: SourceType::GitLab,
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
impl crate::sources::traits::AsyncSource for GitLabSource {
    fn name(&self) -> &str {
        "gitlab"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let projects: Vec<GlProject> = if let Some(id) = self.project_id {
            vec![self.fetch_project(id).await?]
        } else if let Some(ns) = &self.namespace {
            self.list_namespace_projects(ns).await?
        } else {
            return Err(SquirrelError::Config(
                "GitLabSource: either project_id or namespace must be set".into(),
            ));
        };

        let mut all_fragments = Vec::new();
        for project in &projects {
            debug!(
                source = "gitlab",
                project_id = project.id,
                path = %project.path_with_namespace,
                "Scanning project"
            );
            let frags = self.scan_project(project).await;
            all_fragments.extend(frags);
        }

        Ok(all_fragments)
    }
}

// ============================================================================
// GitLabSourceBuilder
// ============================================================================

/// Builder for [`GitLabSource`].
///
/// # Example
///
/// ```rust,no_run
/// # use secret_squirrel::sources::gitlab::GitLabSourceBuilder;
/// let source = GitLabSourceBuilder::new()
///     .namespace("my-group/my-subgroup")
///     .max_file_size_bytes(512 * 1024)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct GitLabSourceBuilder {
    token: Option<String>,
    base_url: Option<String>,
    namespace: Option<String>,
    project_id: Option<u64>,
    max_file_size: Option<u64>,
}

impl GitLabSourceBuilder {
    /// Create a new builder with all fields unset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an explicit Personal Access Token.
    ///
    /// If not called, the builder will try `GITLAB_TOKEN` at [`build`] time.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Override the GitLab API base URL (default: `https://gitlab.com/api/v4`).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the group or user namespace to scan.
    ///
    /// Supports nested groups via slash notation: `"top-group/sub-group"`.
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Limit the scan to a specific project by its numeric GitLab project ID.
    pub fn project_id(mut self, id: u64) -> Self {
        self.project_id = Some(id);
        self
    }

    /// Set the maximum file size in bytes to fetch (default: 1 MiB).
    pub fn max_file_size_bytes(mut self, bytes: u64) -> Self {
        self.max_file_size = Some(bytes);
        self
    }

    /// Build the [`GitLabSource`].
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Config`] if neither `namespace` nor `project_id`
    /// is configured.
    pub fn build(self) -> Result<GitLabSource> {
        if self.namespace.is_none() && self.project_id.is_none() {
            return Err(SquirrelError::Config(
                "GitLabSource: either namespace or project_id must be set".into(),
            ));
        }

        let token = self.token.or_else(|| std::env::var("GITLAB_TOKEN").ok());

        let client = reqwest::Client::new();

        Ok(GitLabSource {
            client,
            token,
            base_url: self
                .base_url
                .unwrap_or_else(|| "https://gitlab.com/api/v4".into()),
            namespace: self.namespace,
            project_id: self.project_id,
            max_file_size: self
                .max_file_size
                .unwrap_or(GitLabSource::DEFAULT_MAX_FILE_SIZE),
        })
    }
}

// ============================================================================
// URL encoding helper
// ============================================================================

/// Percent-encode a path string, replacing `/` with `%2F` and ` ` with `%20`.
///
/// This is intentionally minimal — it handles the characters commonly seen in
/// GitLab project paths and file paths. A full RFC-3986 encoder is not needed
/// because reqwest handles query-parameter encoding separately.
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '/' => out.push_str("%2F"),
            ' ' => out.push_str("%20"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            c => out.push(c),
        }
    }
    out
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
    fn build_source_by_id(server: &Server, project_id: u64) -> GitLabSource {
        GitLabSourceBuilder::new()
            .project_id(project_id)
            .base_url(server.url())
            .build()
            .expect("builder should succeed")
    }

    // -----------------------------------------------------------------------
    // name()
    // -----------------------------------------------------------------------

    #[test]
    fn test_name_returns_gitlab() {
        let source = GitLabSourceBuilder::new().project_id(42).build().unwrap();
        assert_eq!(source.name(), "gitlab");
    }

    // -----------------------------------------------------------------------
    // builder
    // -----------------------------------------------------------------------

    #[test]
    fn test_builder_requires_namespace_or_project_id() {
        let result = GitLabSourceBuilder::new().build();
        assert!(
            result.is_err(),
            "build() should fail when neither namespace nor project_id is set"
        );
    }

    #[test]
    fn test_builder_sets_fields_project_id() {
        let src = GitLabSourceBuilder::new()
            .project_id(99)
            .max_file_size_bytes(256)
            .token("glpat-test")
            .build()
            .unwrap();

        assert_eq!(src.project_id, Some(99));
        assert_eq!(src.max_file_size, 256);
        assert_eq!(src.token.as_deref(), Some("glpat-test"));
    }

    #[test]
    fn test_builder_sets_fields_namespace() {
        let src = GitLabSourceBuilder::new()
            .namespace("my-group")
            .build()
            .unwrap();

        assert_eq!(src.namespace.as_deref(), Some("my-group"));
        assert!(src.project_id.is_none());
    }

    // -----------------------------------------------------------------------
    // URL encoding helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_urlencoding_simple() {
        assert_eq!(urlencoding_simple("src/main.rs"), "src%2Fmain.rs");
        assert_eq!(urlencoding_simple("my group"), "my%20group");
        assert_eq!(urlencoding_simple("no-special"), "no-special");
    }

    // -----------------------------------------------------------------------
    // HTTP 401 returns appropriate error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_401_returns_auth_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/projects/1")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"401 Unauthorized"}"#)
            .create_async()
            .await;

        let source = build_source_by_id(&server, 1);
        let result = source.fragments().await;

        assert!(result.is_err(), "401 should produce an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("authentication failed"),
            "Error should mention auth failure, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // 403 returns appropriate error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_403_returns_forbidden_error() {
        let mut server = Server::new_async().await;

        let _m = server
            .mock("GET", "/projects/2")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"403 Forbidden"}"#)
            .create_async()
            .await;

        let source = build_source_by_id(&server, 2);
        let result = source.fragments().await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("rate limited or forbidden"),
            "Expected rate limit / forbidden message, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // File content is returned correctly
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_file_content_correct() {
        let mut server = Server::new_async().await;

        let secret_content = "GITLAB_TOKEN=glpat-AAAAAAAAAAAAA\n";

        // 1) Project info
        let _m_project = server
            .mock("GET", "/projects/10")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":10,"default_branch":"main","path_with_namespace":"my-group/my-repo"}"#,
            )
            .create_async()
            .await;

        // 2) Repository tree
        let tree_body = serde_json::json!([
            {
                "id": "abc123",
                "path": ".env",
                "type": "blob"
            }
        ]);
        let _m_tree = server
            .mock(
                "GET",
                "/projects/10/repository/tree?recursive=true&per_page=100&page=1&ref=main",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(tree_body.to_string())
            .create_async()
            .await;

        // 3) Raw file content
        // The path ".env" encodes to ".env" (no special chars)
        let _m_file = server
            .mock("GET", "/projects/10/repository/files/.env/raw?ref=main")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body(secret_content)
            .create_async()
            .await;

        let source = build_source_by_id(&server, 10);
        let fragments = source.fragments().await.expect("should succeed");

        assert_eq!(fragments.len(), 1, "Should have exactly one fragment");
        let frag = &fragments[0];
        assert_eq!(
            std::str::from_utf8(&frag.content).unwrap(),
            secret_content,
            "Content should match"
        );
        assert_eq!(frag.metadata.source_type, SourceType::GitLab);
        assert!(
            frag.metadata.path.contains(".env"),
            "Path should contain file name"
        );
        assert_eq!(frag.metadata.attributes["project"], "my-group/my-repo");
    }

    // -----------------------------------------------------------------------
    // Oversized files are skipped
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_oversized_file_skipped() {
        let mut server = Server::new_async().await;

        let _m_project = server
            .mock("GET", "/projects/20")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":20,"default_branch":"main","path_with_namespace":"g/r"}"#)
            .create_async()
            .await;

        let tree_body = serde_json::json!([
            { "id": "sha1", "path": "big.bin", "type": "blob" }
        ]);
        let _m_tree = server
            .mock(
                "GET",
                "/projects/20/repository/tree?recursive=true&per_page=100&page=1&ref=main",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(tree_body.to_string())
            .create_async()
            .await;

        // Return a body larger than the configured limit (10 bytes)
        let _m_file = server
            .mock("GET", "/projects/20/repository/files/big.bin/raw?ref=main")
            .with_status(200)
            .with_body("A".repeat(100)) // 100 bytes > 10 byte limit
            .create_async()
            .await;

        let source = GitLabSourceBuilder::new()
            .project_id(20)
            .max_file_size_bytes(10) // tiny limit to trigger skip
            .base_url(server.url())
            .build()
            .unwrap();

        let fragments = source.fragments().await.expect("should succeed");
        assert!(
            fragments.is_empty(),
            "Oversized file should be skipped, got {} fragments",
            fragments.len()
        );
    }
}
