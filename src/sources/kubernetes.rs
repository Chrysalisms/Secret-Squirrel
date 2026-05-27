//! Kubernetes secrets and ConfigMap scanner — implementation in Phase 2.
//!
//! When fully implemented this source will:
//!
//! - Enumerate `Secret` resources across all namespaces (or a filtered set)
//! - Enumerate `ConfigMap` resources for embedded credentials
//! - Scan pod environment variable definitions
//! - Inspect Helm chart templates and values files
//! - Optionally decode base64-encoded secret data for scanning
//!
//! # Authentication
//!
//! Uses the active `kubectl` context (`~/.kube/config`) or in-cluster
//! service account credentials when running inside a pod.

use crate::error::Result;
use crate::types::Fragment;

/// Kubernetes cluster scanner source adapter (Phase 2 stub).
pub struct KubernetesSource;

impl KubernetesSource {
    /// Create a new (no-op) Kubernetes source.
    pub fn new() -> Self {
        Self
    }
}

impl Default for KubernetesSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for KubernetesSource {
    fn name(&self) -> &str {
        "kubernetes"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        // Phase 2: implement kube-rs API client scanning.
        Ok(Vec::new())
    }
}
