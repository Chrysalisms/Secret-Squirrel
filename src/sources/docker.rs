//! Docker image layer scanner — implementation in Phase 2.
//!
//! When fully implemented this source will:
//!
//! - Pull Docker images from any registry
//! - Extract and scan each image layer's filesystem
//! - Inspect `ENV` and `ARG` instructions in Dockerfile metadata
//! - Scan `docker inspect` JSON output for embedded secrets
//! - Support OCI image format
//!
//! # Authentication
//!
//! Uses Docker credential helpers (`~/.docker/config.json`) or explicit
//! registry credentials configured in `.squirrel.toml`.

use crate::error::Result;
use crate::types::Fragment;

/// Docker image scanner source adapter (Phase 2 stub).
pub struct DockerSource;

impl DockerSource {
    /// Create a new (no-op) Docker source.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DockerSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for DockerSource {
    fn name(&self) -> &str {
        "docker"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Phase 2: implement Docker Registry API v2 scanning.
        Ok(Vec::new())
    }
}
