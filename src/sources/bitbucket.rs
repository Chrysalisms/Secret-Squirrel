//! Bitbucket Cloud source adapter.
//!
//! Scans one or all repositories in a Bitbucket workspace using the
//! Bitbucket Cloud REST API v2. Supports file contents, commit history,
//! and pull request descriptions and diffs.
//!
//! # Scanning strategy
//!
//! 1. If [`BitbucketSource::repo_slugs`] is non-empty, scan only those repos.
//! 2. Otherwise list every repository in the workspace and scan each.
//! 3. For each repository, walk the file tree at HEAD and fetch each file.
//! 4. Optionally scan commit diffs (`scan_commits`) and PR descriptions/diffs
//!    (`scan_prs`) up to `max_depth` items.
//!
//! # Authentication
//!
//! Bitbucket supports two auth schemes:
//! - **App password**: set `token` to `"username:app-password"` — sent as
//!   HTTP Basic auth.
//! - **OAuth token**: set `token` to `"Bearer <oauth-token>"` — sent as-is.
//!
//! If the token value starts with `"Bearer "` it is used verbatim; otherwise
//! it is Base64-encoded and sent as `Authorization: Basic <base64>`.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Bitbucket API response types
// ============================================================================

/// Paginated envelope returned by Bitbucket list endpoints.
#[derive(Debug, Deserialize)]
struct BbPage<T> {
    values: Vec<T>,
    /// URL of the next page, absent on the last page.
    next: Option<String>,
}

/// A repository entry from `GET /2.0/repositories/{workspace}`.
#[derive(Debug, Deserialize)]
struct BbRepo {
    slug: String,
    /// The main branch ref object (may be absent for empty repos).
    mainbranch: Option<BbBranch>,
}

/// Branch reference embedded in a [`BbRepo`].
#[derive(Debug, Deserialize)]
struct BbBranch {
    name: String,
}

/// An entry in the source tree listing.
#[derive(Debug, Deserialize)]
struct BbSrcEntry {
    #[serde(rename = "type")]
    kind: String, // "commit_file" | "commit_directory"
    path: String,
    /// Byte size — present for files, absent for directories.
    size: Option<u64>,
    /// The commit SHA this path was resolved at.
    commit: Option<BbCommitRef>,
}

/// Slim commit reference embedded in a directory listing entry.
#[derive(Debug, Deserialize)]
struct BbCommitRef {
    hash: String,
}

/// A commit from `GET /2.0/repositories/{workspace}/{slug}/commits`.
#[derive(Debug, Deserialize)]
struct BbCommit {
    hash: String,
    message: Option<String>,
}

/// A pull request from `GET /2.0/repositories/{workspace}/{slug}/pullrequests`.
#[derive(Debug, Deserialize)]
struct BbPullRequest {
    id: u64,
    title: Option<String>,
    description: Option<String>,
    source: Option<BbPrRef>,
}

/// PR source branch reference.
#[derive(Debug, Deserialize)]
struct BbPrRef {
    commit: Option<BbCommitRef>,
}

// ============================================================================
// BitbucketSource
// ============================================================================

/// Async source that scans Bitbucket Cloud repositories for credential fragments.
///
/// Construct with [`BitbucketSource::new`] and use the builder-style methods to
/// configure optional behaviour:
///
/// ```rust,no_run
/// # use secret_squirrel::sources::bitbucket::BitbucketSource;
/// let source = BitbucketSource::new("myworkspace", "user:app-password")
///     .with_repos(vec!["infra".into(), "backend".into()])
///     .with_scan_commits(50);
/// ```
pub struct BitbucketSource {
    client: reqwest::Client,
    workspace: String,
    repo_slugs: Vec<String>,
    /// Raw token string. If it starts with "Bearer " it is used as-is,
    /// otherwise it is treated as "user:pass" and Base64-encoded.
    token: String,
    host: String,
    scan_commits: bool,
    scan_prs: bool,
    max_depth: usize,
    max_file_size: u64,
}

impl BitbucketSource {
    /// Default maximum file size (1 MiB).
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;

    /// Create a new source for the given `workspace`.
    ///
    /// `token` may be either `"username:app-password"` (Basic auth) or
    /// `"Bearer <oauth-token>"` (Bearer auth).
    pub fn new(workspace: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            workspace: workspace.into(),
            repo_slugs: Vec::new(),
            token: token.into(),
            host: "https://api.bitbucket.org".into(),
            scan_commits: false,
            scan_prs: false,
            max_depth: 0,
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
        }
    }

    /// Limit scanning to specific repository slugs (default: all repos).
    pub fn with_repos(mut self, repos: Vec<String>) -> Self {
        self.repo_slugs = repos;
        self
    }

    /// Enable commit-history scanning up to `depth` commits (0 = unlimited).
    pub fn with_scan_commits(mut self, depth: usize) -> Self {
        self.scan_commits = true;
        self.max_depth = depth;
        self
    }

    /// Enable pull-request description and diff scanning.
    pub fn with_scan_prs(mut self) -> Self {
        self.scan_prs = true;
        self
    }

    /// Override the Bitbucket API host (default: `https://api.bitbucket.org`).
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the `Authorization` header value from the stored token.
    fn auth_header(&self) -> String {
        if self.token.starts_with("Bearer ") {
            self.token.clone()
        } else {
            format!("Basic {}", BASE64.encode(&self.token))
        }
    }

    /// Attach authentication and User-Agent to a GET request.
    fn authed_get(&self, url: &str) -> reqwest::RequestBuilder {
        self.client
            .get(url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .header("Authorization", self.auth_header())
    }

    /// Convert an HTTP status code into a [`SquirrelError`].
    fn status_error(&self, status: reqwest::StatusCode, url: &str) -> SquirrelError {
        match status.as_u16() {
            401 => SquirrelError::Source {
                src_name: "bitbucket".into(),
                reason: "authentication failed — check token/app-password".into(),
            },
            403 => SquirrelError::Source {
                src_name: "bitbucket".into(),
                reason: "rate limited or forbidden".into(),
            },
            404 => SquirrelError::Source {
                src_name: "bitbucket".into(),
                reason: format!("not found: {url}"),
            },
            code => SquirrelError::Source {
                src_name: "bitbucket".into(),
                reason: format!("HTTP {code} from {url}"),
            },
        }
    }

    /// Fetch all repository slugs in the workspace, following Bitbucket's
    /// page-number pagination (`?page=N&pagelen=50`).
    pub async fn list_repos(&self) -> Result<Vec<String>> {
        let mut slugs = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/2.0/repositories/{}?page={}&pagelen=50",
                self.host, self.workspace, page
            );
            let resp = self.authed_get(&url).send().await.map_err(|e| {
                SquirrelError::Source {
                    src_name: "bitbucket".into(),
                    reason: e.to_string(),
                }
            })?;

            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), &url));
            }

            let body: BbPage<BbRepo> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "bitbucket".into(),
                reason: format!("JSON parse error listing repos: {e}"),
            })?;

            let has_next = body.next.is_some();
            for repo in body.values {
                slugs.push(repo.slug);
            }

            if !has_next {
                break;
            }
            page += 1;
        }

        Ok(slugs)
    }

    /// Resolve the default branch for a repository.
    async fn default_branch(&self, slug: &str) -> String {
        let url = format!(
            "{}/2.0/repositories/{}/{}",
            self.host, self.workspace, slug
        );
        match self.authed_get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<BbRepo>().await {
                    Ok(repo) => repo.mainbranch.map(|b| b.name).unwrap_or_else(|| "main".into()),
                    Err(_) => "main".into(),
                }
            }
            _ => "main".into(),
        }
    }

    /// Walk the file tree of a repository at `commit` (HEAD of the branch).
    ///
    /// Bitbucket's `/src/{commit}/{path}` endpoint returns a paginated directory
    /// listing. We start at the root and follow `next` links.
    async fn list_files(&self, slug: &str, commit: &str) -> Result<Vec<BbSrcEntry>> {
        let mut entries = Vec::new();
        let mut next_url: Option<String> = Some(format!(
            "{}/2.0/repositories/{}/{}/src/{}/",
            self.host, self.workspace, slug, commit
        ));

        while let Some(url) = next_url.take() {
            // Append pagelen if not already in the URL from a `next` link.
            let fetch_url = if url.contains("pagelen=") {
                url.clone()
            } else {
                format!("{url}?pagelen=100")
            };

            let resp = self.authed_get(&fetch_url).send().await.map_err(|e| {
                SquirrelError::Source {
                    src_name: "bitbucket".into(),
                    reason: e.to_string(),
                }
            })?;

            if !resp.status().is_success() {
                return Err(self.status_error(resp.status(), &fetch_url));
            }

            let body: BbPage<BbSrcEntry> = resp.json().await.map_err(|e| SquirrelError::Source {
                src_name: "bitbucket".into(),
                reason: format!("JSON parse error listing files for {slug}: {e}"),
            })?;

            next_url = body.next.clone();
            for entry in body.values {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Fetch the raw bytes of a single file.
    async fn fetch_file(&self, slug: &str, commit: &str, path: &str) -> Option<Bytes> {
        let url = format!(
            "{}/2.0/repositories/{}/{}/src/{}/{}",
            self.host, self.workspace, slug, commit, path
        );

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    source = "bitbucket",
                    workspace = %self.workspace,
                    repo = slug,
                    path,
                    error = %e,
                    "HTTP request failed; skipping file"
                );
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "bitbucket",
                workspace = %self.workspace,
                repo = slug,
                path,
                status = resp.status().as_u16(),
                "Non-success status fetching file; skipping"
            );
            return None;
        }

        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    source = "bitbucket",
                    workspace = %self.workspace,
                    repo = slug,
                    path,
                    error = %e,
                    "Failed to read response body; skipping"
                );
                return None;
            }
        };

        if bytes.len() as u64 > self.max_file_size {
            debug!(
                source = "bitbucket",
                repo = slug,
                path,
                size = bytes.len(),
                max = self.max_file_size,
                "Skipping oversized file"
            );
            return None;
        }

        Some(bytes)
    }

    /// Fetch commit list for a repository.
    async fn list_commits(&self, slug: &str) -> Vec<BbCommit> {
        let mut commits = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/2.0/repositories/{}/{}/commits?page={}&pagelen=50",
                self.host, self.workspace, slug, page
            );

            let resp = match self.authed_get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(source = "bitbucket", repo = slug, error = %e, "Failed to list commits");
                    break;
                }
            };

            if !resp.status().is_success() {
                warn!(
                    source = "bitbucket",
                    repo = slug,
                    status = resp.status().as_u16(),
                    "Non-success listing commits"
                );
                break;
            }

            let body: BbPage<BbCommit> = match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    warn!(source = "bitbucket", repo = slug, error = %e, "JSON error listing commits");
                    break;
                }
            };

            let has_next = body.next.is_some();
            commits.extend(body.values);

            // Respect max_depth (0 = unlimited).
            if self.max_depth > 0 && commits.len() >= self.max_depth {
                commits.truncate(self.max_depth);
                break;
            }

            if !has_next {
                break;
            }
            page += 1;
        }

        commits
    }

    /// Fetch the unified diff for a single commit.
    async fn fetch_commit_diff(&self, slug: &str, sha: &str) -> Option<Bytes> {
        let url = format!(
            "{}/2.0/repositories/{}/{}/diff/{}",
            self.host, self.workspace, slug, sha
        );

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(source = "bitbucket", repo = slug, sha, error = %e, "Failed to fetch commit diff");
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(
                source = "bitbucket",
                repo = slug,
                sha,
                status = resp.status().as_u16(),
                "Non-success fetching commit diff"
            );
            return None;
        }

        resp.bytes().await.ok()
    }

    /// Fetch pull requests for a repository.
    async fn list_pull_requests(&self, slug: &str) -> Vec<BbPullRequest> {
        let mut prs = Vec::new();
        let mut page = 1u32;

        loop {
            let url = format!(
                "{}/2.0/repositories/{}/{}/pullrequests?state=ALL&page={}&pagelen=50",
                self.host, self.workspace, slug, page
            );

            let resp = match self.authed_get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(source = "bitbucket", repo = slug, error = %e, "Failed to list PRs");
                    break;
                }
            };

            if !resp.status().is_success() {
                warn!(
                    source = "bitbucket",
                    repo = slug,
                    status = resp.status().as_u16(),
                    "Non-success listing PRs"
                );
                break;
            }

            let body: BbPage<BbPullRequest> = match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    warn!(source = "bitbucket", repo = slug, error = %e, "JSON error listing PRs");
                    break;
                }
            };

            let has_next = body.next.is_some();
            prs.extend(body.values);

            // Respect max_depth.
            if self.max_depth > 0 && prs.len() >= self.max_depth {
                prs.truncate(self.max_depth);
                break;
            }

            if !has_next {
                break;
            }
            page += 1;
        }

        prs
    }

    /// Fetch the diff for a pull request.
    async fn fetch_pr_diff(&self, slug: &str, pr_id: u64) -> Option<Bytes> {
        let url = format!(
            "{}/2.0/repositories/{}/{}/pullrequests/{}/diff",
            self.host, self.workspace, slug, pr_id
        );

        let resp = match self.authed_get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(source = "bitbucket", repo = slug, pr_id, error = %e, "Failed to fetch PR diff");
                return None;
            }
        };

        if !resp.status().is_success() {
            return None;
        }

        resp.bytes().await.ok()
    }

    /// Scan a single repository and return all discovered fragments.
    pub async fn scan_repo(&self, slug: &str) -> Result<Vec<Fragment>> {
        let mut fragments = Vec::new();

        // ---- 1. File tree at HEAD ----
        let branch = self.default_branch(slug).await;

        // Resolve the branch to a commit SHA by fetching the latest commit on it.
        // We use the /commits?branch=<name>&pagelen=1 shortcut.
        let head_sha = {
            let url = format!(
                "{}/2.0/repositories/{}/{}/commits?branch={}&pagelen=1",
                self.host, self.workspace, slug, branch
            );
            match self.authed_get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<BbPage<BbCommit>>().await {
                        Ok(page) => page.values.into_iter().next().map(|c| c.hash),
                        Err(_) => None,
                    }
                }
                _ => None,
            }
        };

        let commit = head_sha.as_deref().unwrap_or("HEAD");

        let entries = match self.list_files(slug, commit).await {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    source = "bitbucket",
                    workspace = %self.workspace,
                    repo = slug,
                    error = %e,
                    "Failed to list files; skipping repo file tree"
                );
                Vec::new()
            }
        };

        for entry in &entries {
            if entry.kind != "commit_file" {
                continue;
            }

            // Pre-size check.
            if let Some(sz) = entry.size {
                if sz > self.max_file_size {
                    debug!(
                        source = "bitbucket",
                        repo = slug,
                        path = %entry.path,
                        size = sz,
                        "Skipping oversized file"
                    );
                    continue;
                }
            }

            let sha = entry
                .commit
                .as_ref()
                .map(|c| c.hash.as_str())
                .unwrap_or(commit);

            let content = match self.fetch_file(slug, sha, &entry.path).await {
                Some(c) => c,
                None => continue,
            };

            let size = content.len() as u64;
            let mut attributes = HashMap::new();
            attributes.insert("workspace".into(), self.workspace.clone());
            attributes.insert("repo".into(), slug.to_owned());
            attributes.insert("sha".into(), sha.to_owned());
            attributes.insert("branch".into(), branch.clone());

            debug!(
                source = "bitbucket",
                workspace = %self.workspace,
                repo = slug,
                path = %entry.path,
                bytes = size,
                "Fetched file"
            );

            fragments.push(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: format!("bitbucket://{}/{}/{}", self.workspace, slug, entry.path),
                    source_type: SourceType::Bitbucket,
                    size,
                    attributes,
                },
            });
        }

        // ---- 2. Commit history ----
        if self.scan_commits {
            let commits = self.list_commits(slug).await;
            for commit_obj in &commits {
                // Include the commit message itself.
                if let Some(msg) = &commit_obj.message {
                    if !msg.trim().is_empty() {
                        let content = Bytes::from(msg.clone().into_bytes());
                        let size = content.len() as u64;
                        let mut attributes = HashMap::new();
                        attributes.insert("workspace".into(), self.workspace.clone());
                        attributes.insert("repo".into(), slug.to_owned());
                        attributes.insert("sha".into(), commit_obj.hash.clone());
                        attributes.insert("kind".into(), "commit_message".into());

                        fragments.push(Fragment {
                            content,
                            metadata: FragmentMetadata {
                                path: format!(
                                    "bitbucket://{}/{}/commits/{}",
                                    self.workspace, slug, commit_obj.hash
                                ),
                                source_type: SourceType::Bitbucket,
                                size,
                                attributes,
                            },
                        });
                    }
                }

                // Fetch and include the diff.
                if let Some(diff_bytes) = self.fetch_commit_diff(slug, &commit_obj.hash).await {
                    if !diff_bytes.is_empty() {
                        let size = diff_bytes.len() as u64;
                        let mut attributes = HashMap::new();
                        attributes.insert("workspace".into(), self.workspace.clone());
                        attributes.insert("repo".into(), slug.to_owned());
                        attributes.insert("sha".into(), commit_obj.hash.clone());
                        attributes.insert("kind".into(), "commit_diff".into());

                        fragments.push(Fragment {
                            content: diff_bytes,
                            metadata: FragmentMetadata {
                                path: format!(
                                    "bitbucket://{}/{}/commits/{}.diff",
                                    self.workspace, slug, commit_obj.hash
                                ),
                                source_type: SourceType::Bitbucket,
                                size,
                                attributes,
                            },
                        });
                    }
                }
            }
        }

        // ---- 3. Pull requests ----
        if self.scan_prs {
            let prs = self.list_pull_requests(slug).await;
            for pr in &prs {
                // PR description.
                let description = pr
                    .description
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if !description.is_empty() {
                    let title = pr.title.as_deref().unwrap_or("");
                    let combined = format!("PR #{}: {}\n\n{}", pr.id, title, description);
                    let content = Bytes::from(combined.into_bytes());
                    let size = content.len() as u64;
                    let mut attributes = HashMap::new();
                    attributes.insert("workspace".into(), self.workspace.clone());
                    attributes.insert("repo".into(), slug.to_owned());
                    attributes.insert("pr_id".into(), pr.id.to_string());
                    attributes.insert("kind".into(), "pr_description".into());

                    fragments.push(Fragment {
                        content,
                        metadata: FragmentMetadata {
                            path: format!(
                                "bitbucket://{}/{}/pullrequests/{}",
                                self.workspace, slug, pr.id
                            ),
                            source_type: SourceType::Bitbucket,
                            size,
                            attributes,
                        },
                    });
                }

                // PR diff.
                if let Some(diff_bytes) = self.fetch_pr_diff(slug, pr.id).await {
                    if !diff_bytes.is_empty() {
                        let size = diff_bytes.len() as u64;
                        let sha = pr
                            .source
                            .as_ref()
                            .and_then(|s| s.commit.as_ref())
                            .map(|c| c.hash.as_str())
                            .unwrap_or("unknown");

                        let mut attributes = HashMap::new();
                        attributes.insert("workspace".into(), self.workspace.clone());
                        attributes.insert("repo".into(), slug.to_owned());
                        attributes.insert("pr_id".into(), pr.id.to_string());
                        attributes.insert("sha".into(), sha.to_owned());
                        attributes.insert("kind".into(), "pr_diff".into());

                        fragments.push(Fragment {
                            content: diff_bytes,
                            metadata: FragmentMetadata {
                                path: format!(
                                    "bitbucket://{}/{}/pullrequests/{}.diff",
                                    self.workspace, slug, pr.id
                                ),
                                source_type: SourceType::Bitbucket,
                                size,
                                attributes,
                            },
                        });
                    }
                }
            }
        }

        Ok(fragments)
    }
}

// ============================================================================
// AsyncSource implementation
// ============================================================================

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for BitbucketSource {
    fn name(&self) -> &str {
        "bitbucket"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Determine the list of repos to scan.
        let slugs: Vec<String> = if self.repo_slugs.is_empty() {
            self.list_repos().await?
        } else {
            self.repo_slugs.clone()
        };

        let mut all_fragments = Vec::new();
        for slug in &slugs {
            debug!(
                source = "bitbucket",
                workspace = %self.workspace,
                repo = %slug,
                "Scanning repository"
            );
            match self.scan_repo(slug).await {
                Ok(frags) => all_fragments.extend(frags),
                Err(e) => {
                    warn!(
                        source = "bitbucket",
                        workspace = %self.workspace,
                        repo = %slug,
                        error = %e,
                        "Failed to scan repo; continuing"
                    );
                }
            }
        }

        Ok(all_fragments)
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::traits::AsyncSource;

    #[test]
    fn test_name_returns_bitbucket() {
        let source = BitbucketSource::new("myworkspace", "user:pass");
        assert_eq!(source.name(), "bitbucket");
    }

    #[test]
    fn test_auth_header_basic() {
        let source = BitbucketSource::new("ws", "user:mypassword");
        let header = source.auth_header();
        assert!(header.starts_with("Basic "), "Should be Basic auth: {header}");
        // Decode and verify
        let encoded = header.trim_start_matches("Basic ");
        let decoded = String::from_utf8(BASE64.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, "user:mypassword");
    }

    #[test]
    fn test_auth_header_bearer() {
        let source = BitbucketSource::new("ws", "Bearer myoauthtoken");
        let header = source.auth_header();
        assert_eq!(header, "Bearer myoauthtoken");
    }

    #[test]
    fn test_with_repos_sets_slugs() {
        let source = BitbucketSource::new("ws", "u:p")
            .with_repos(vec!["repo-a".into(), "repo-b".into()]);
        assert_eq!(source.repo_slugs, vec!["repo-a", "repo-b"]);
    }

    #[test]
    fn test_with_scan_commits_sets_flags() {
        let source = BitbucketSource::new("ws", "u:p").with_scan_commits(100);
        assert!(source.scan_commits);
        assert_eq!(source.max_depth, 100);
    }

    #[test]
    fn test_with_scan_prs_sets_flag() {
        let source = BitbucketSource::new("ws", "u:p").with_scan_prs();
        assert!(source.scan_prs);
    }

    #[test]
    fn test_default_flags() {
        let source = BitbucketSource::new("ws", "u:p");
        assert!(!source.scan_commits);
        assert!(!source.scan_prs);
        assert_eq!(source.max_depth, 0);
        assert_eq!(source.max_file_size, BitbucketSource::DEFAULT_MAX_FILE_SIZE);
    }
}
