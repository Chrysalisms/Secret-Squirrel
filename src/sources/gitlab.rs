//! GitLab source adapter — implementation in Phase 2.
//!
//! When fully implemented this source will scan:
//!
//! - Repository source code (all branches)
//! - Merge request diffs and comments
//! - GitLab CI/CD pipeline configurations
//! - Issue comments and description fields
//! - Snippet files
//! - Package registry metadata
//!
//! # Authentication
//!
//! Requires a GitLab Personal Access Token with `read_api` scope. Set the
//! `GITLAB_TOKEN` environment variable or configure via `sources.gitlab_token`
//! in `.squirrel.toml`.

use crate::error::Result;
use crate::types::Fragment;

/// GitLab source adapter (Phase 2 stub).
pub struct GitLabSource;

impl GitLabSource {
    /// Create a new (no-op) GitLab source.
    pub fn new() -> Self {
        Self
    }
}

impl Default for GitLabSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for GitLabSource {
    fn name(&self) -> &str {
        "gitlab"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Phase 2: implement GitLab REST API scanning.
        Ok(Vec::new())
    }
}
