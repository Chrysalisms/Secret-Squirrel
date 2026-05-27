//! S3 / R2 / GCS object storage source adapter — implementation in Phase 2.
//!
//! When fully implemented this source will scan:
//!
//! - AWS S3 buckets (with prefix filtering)
//! - Cloudflare R2 buckets (S3-compatible API)
//! - Google Cloud Storage buckets (via S3-compatible API or native)
//!
//! # Authentication
//!
//! Uses standard AWS credential chain (environment variables, `~/.aws/credentials`,
//! IAM instance profiles). For R2 and GCS, configure endpoint URLs in
//! `.squirrel.toml`.

use crate::error::Result;
use crate::types::Fragment;

/// S3-compatible object storage source adapter (Phase 2 stub).
pub struct S3Source;

impl S3Source {
    /// Create a new (no-op) S3 source.
    pub fn new() -> Self {
        Self
    }
}

impl Default for S3Source {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for S3Source {
    fn name(&self) -> &str {
        "s3"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Phase 2: implement AWS SDK / S3-compatible API scanning.
        Ok(Vec::new())
    }
}
