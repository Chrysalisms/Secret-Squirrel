//! Terraform state and configuration scanner — implementation in Phase 2.
//!
//! When fully implemented this source will:
//!
//! - Parse `terraform.tfstate` and `*.tfstate.backup` files
//! - Parse `*.tf` variable blocks for `sensitive = true` fields
//! - Scan Terraform variable files (`*.tfvars`)
//! - Inspect Terraform Cloud / Terraform Enterprise workspace variables via API
//! - Support S3, GCS, and Azure Blob remote state backends
//!
//! # Why Terraform state is dangerous
//!
//! Terraform state files routinely contain plaintext secrets: database passwords,
//! cloud credentials, TLS private keys, and API tokens are all persisted as part
//! of provider resource attributes.

use crate::error::Result;
use crate::types::Fragment;

/// Terraform state and configuration scanner source adapter (Phase 2 stub).
pub struct TerraformSource;

impl TerraformSource {
    /// Create a new (no-op) Terraform source.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerraformSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for TerraformSource {
    fn name(&self) -> &str {
        "terraform"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Phase 2: implement Terraform state file parser and TF Cloud API.
        Ok(Vec::new())
    }
}
