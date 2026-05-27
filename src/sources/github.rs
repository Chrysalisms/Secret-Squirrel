//! GitHub source adapter — implementation in Phase 2.
//!
//! When fully implemented this source will scan:
//!
//! - Repository source code (default branch + all branches)
//! - Pull request diffs
//! - Issue and PR comments
//! - GitHub Actions workflow files
//! - Release artifacts and release notes
//! - Gist files
//! - GitHub Discussions
//!
//! # Authentication
//!
//! Requires a GitHub Personal Access Token with appropriate scopes. Set the
//! `GITHUB_TOKEN` environment variable or configure via `sources.github_token`
//! in `.squirrel.toml`.

use crate::error::Result;
use crate::types::Fragment;

/// GitHub source adapter (Phase 2 stub).
///
/// See module documentation for the planned feature set.
pub struct GitHubSource;

impl GitHubSource {
    /// Create a new (no-op) GitHub source.
    pub fn new() -> Self {
        Self
    }
}

impl Default for GitHubSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for GitHubSource {
    fn name(&self) -> &str {
        "github"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Phase 2: implement GitHub REST + GraphQL API scanning.
        Ok(Vec::new())
    }
}
