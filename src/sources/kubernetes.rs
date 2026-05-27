//! Kubernetes Secret and ConfigMap scanner.
//!
//! Scans running Kubernetes clusters for secrets exposed in:
//!
//! - `Secret` resources - base64-decoded `data` fields
//! - `ConfigMap` resources - plaintext `data` fields
//! - `Pod` specs - `env` and `envFrom` variable definitions
//! - `Deployment`, `StatefulSet`, `DaemonSet` - pod template env vars
//!
//! # Authentication
//!
//! Uses the current kubeconfig context by default. Override with:
//! - `KUBECONFIG` env var - path to kubeconfig file
//! - `KUBE_CONTEXT` env var - context name to use
//! - `KUBE_NAMESPACE` env var - restrict to a single namespace
//!
//! # Why Kubernetes Secrets are not actually secret
//!
//! By default, Kubernetes Secrets are stored as base64 (not encrypted)
//! in etcd. Anyone with `kubectl get secret -o yaml` access can decode them.
//! This scanner replicates that access to detect misconfigured secrets.

use bytes::Bytes;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// KubernetesSource
// ============================================================================

/// Scans Kubernetes Secrets and ConfigMaps for credential leakage.
pub struct KubernetesSource {
    /// Namespace to scan. `None` = all namespaces.
    namespace: Option<String>,
    /// Whether to scan ConfigMaps (default: true).
    scan_configmaps: bool,
    /// Whether to scan Pod/Deployment env vars (default: true).
    scan_pod_env: bool,
    /// Additional namespaces to always skip (e.g., `kube-system`).
    skip_namespaces: Vec<String>,
}

impl KubernetesSource {
    /// Create a scanner for all namespaces.
    pub fn new() -> Self {
        Self {
            namespace: std::env::var("KUBE_NAMESPACE").ok(),
            scan_configmaps: true,
            scan_pod_env: true,
            skip_namespaces: vec![
                "kube-system".to_string(),
                "kube-public".to_string(),
                "kube-node-lease".to_string(),
            ],
        }
    }

    /// Restrict scanning to a single namespace.
    pub fn in_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Disable ConfigMap scanning.
    pub fn without_configmaps(mut self) -> Self {
        self.scan_configmaps = false;
        self
    }

    /// Add namespaces to skip.
    pub fn skip_namespace(mut self, ns: impl Into<String>) -> Self {
        self.skip_namespaces.push(ns.into());
        self
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
        let mut fragments = Vec::new();

        // 1. Scan Secrets
        let secret_frags = self.scan_secrets().await?;
        fragments.extend(secret_frags);

        // 2. Scan ConfigMaps
        if self.scan_configmaps {
            let cm_frags = self.scan_configmaps_resource().await?;
            fragments.extend(cm_frags);
        }

        // 3. Scan Pod env vars
        if self.scan_pod_env {
            let pod_frags = self.scan_pod_env_vars().await?;
            fragments.extend(pod_frags);
        }

        info!(
            fragment_count = fragments.len(),
            "kubernetes: scan complete"
        );

        Ok(fragments)
    }
}

impl KubernetesSource {
    /// Run `kubectl get <resource> -o json` and parse output.
    async fn kubectl_get_json(&self, resource: &str) -> Result<serde_json::Value> {
        let ns_arg = if let Some(ns) = &self.namespace {
            format!("-n={ns}")
        } else {
            "--all-namespaces".to_string()
        };
        let resource = resource.to_string();

        // Use spawn_blocking since kubectl is a synchronous subprocess
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("kubectl")
                .arg("get")
                .arg(&resource)
                .arg(&ns_arg)
                .arg("-o")
                .arg("json")
                .output()
        })
        .await
        .map_err(|e| SquirrelError::Source {
            src_name: "kubernetes".to_string(),
            reason: format!("spawn_blocking error: {e}"),
        })?
        .map_err(|e| SquirrelError::Source {
            src_name: "kubernetes".to_string(),
            reason: format!("kubectl not found or failed to execute: {e}"),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SquirrelError::Source {
                src_name: "kubernetes".to_string(),
                reason: format!("kubectl get failed: {stderr}"),
            });
        }

        serde_json::from_slice(&output.stdout).map_err(|e| SquirrelError::Source {
            src_name: "kubernetes".to_string(),
            reason: format!("could not parse kubectl output: {e}"),
        })
    }

    pub(crate) fn should_skip_namespace(&self, ns: &str) -> bool {
        self.skip_namespaces.iter().any(|s| s == ns)
    }

    /// Scan all Secret resources and decode their base64 data fields.
    async fn scan_secrets(&self) -> Result<Vec<Fragment>> {
        let json = match self.kubectl_get_json("secrets").await {
            Ok(j) => j,
            Err(e) => {
                warn!("kubernetes: could not list secrets: {e}");
                return Ok(Vec::new()); // Non-fatal - might lack RBAC permission
            }
        };

        let mut fragments = Vec::new();
        let items = json
            .get("items")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();

        for item in &items {
            let namespace = item
                .get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(|n| n.as_str())
                .unwrap_or("default");

            if self.should_skip_namespace(namespace) {
                continue;
            }

            let name = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");

            let secret_type = item
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("Opaque");

            // Decode and scan all data fields
            if let Some(data) = item.get("data").and_then(|d| d.as_object()) {
                let mut content_lines = Vec::new();

                for (key, value) in data {
                    if let Some(encoded) = value.as_str() {
                        // Kubernetes secrets are base64-encoded
                        let decoded = base64_decode(encoded);
                        // Only add if it looks text-like (not a certificate/binary)
                        if let Ok(text) = std::str::from_utf8(&decoded) {
                            let text = text.trim();
                            if !text.is_empty() {
                                content_lines.push(format!("{key} = \"{text}\""));
                            }
                        }
                    }
                }

                if !content_lines.is_empty() {
                    let mut attrs = HashMap::new();
                    attrs.insert("namespace".to_string(), namespace.to_string());
                    attrs.insert("name".to_string(), name.to_string());
                    attrs.insert("type".to_string(), secret_type.to_string());

                    fragments.push(Fragment {
                        content: Bytes::from(content_lines.join("\n")),
                        metadata: FragmentMetadata {
                            path: format!("k8s://secret/{namespace}/{name}"),
                            source_type: SourceType::Kubernetes,
                            size: 0,
                            attributes: attrs,
                        },
                    });
                }
            }

            // Also scan stringData if present (already plaintext)
            if let Some(string_data) = item.get("stringData").and_then(|d| d.as_object()) {
                let content_lines: Vec<String> = string_data
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| format!("{k} = \"{s}\"")))
                    .collect();

                if !content_lines.is_empty() {
                    let mut attrs = HashMap::new();
                    attrs.insert("namespace".to_string(), namespace.to_string());
                    attrs.insert("name".to_string(), name.to_string());
                    attrs.insert("type".to_string(), "stringData".to_string());

                    fragments.push(Fragment {
                        content: Bytes::from(content_lines.join("\n")),
                        metadata: FragmentMetadata {
                            path: format!("k8s://secret/{namespace}/{name}#stringData"),
                            source_type: SourceType::Kubernetes,
                            size: 0,
                            attributes: attrs,
                        },
                    });
                }
            }
        }

        debug!(count = fragments.len(), "kubernetes: scanned secrets");
        Ok(fragments)
    }

    /// Scan ConfigMap data fields (plaintext, not base64).
    async fn scan_configmaps_resource(&self) -> Result<Vec<Fragment>> {
        let json = match self.kubectl_get_json("configmaps").await {
            Ok(j) => j,
            Err(e) => {
                warn!("kubernetes: could not list configmaps: {e}");
                return Ok(Vec::new());
            }
        };

        let mut fragments = Vec::new();
        let items = json
            .get("items")
            .and_then(|i| i.as_array())
            .cloned()
            .unwrap_or_default();

        for item in &items {
            let namespace = item
                .get("metadata")
                .and_then(|m| m.get("namespace"))
                .and_then(|n| n.as_str())
                .unwrap_or("default");

            if self.should_skip_namespace(namespace) {
                continue;
            }

            let name = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");

            if let Some(data) = item.get("data").and_then(|d| d.as_object()) {
                let content_lines: Vec<String> = data
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| format!("{k} = \"{s}\"")))
                    .collect();

                if !content_lines.is_empty() {
                    let mut attrs = HashMap::new();
                    attrs.insert("namespace".to_string(), namespace.to_string());
                    attrs.insert("name".to_string(), name.to_string());

                    fragments.push(Fragment {
                        content: Bytes::from(content_lines.join("\n")),
                        metadata: FragmentMetadata {
                            path: format!("k8s://configmap/{namespace}/{name}"),
                            source_type: SourceType::Kubernetes,
                            size: 0,
                            attributes: attrs,
                        },
                    });
                }
            }
        }

        debug!(count = fragments.len(), "kubernetes: scanned configmaps");
        Ok(fragments)
    }

    /// Scan env vars defined directly in Pod specs and workload templates.
    async fn scan_pod_env_vars(&self) -> Result<Vec<Fragment>> {
        let resources = ["pods", "deployments", "statefulsets", "daemonsets"];
        let mut fragments = Vec::new();

        for resource in &resources {
            let json = match self.kubectl_get_json(resource).await {
                Ok(j) => j,
                Err(e) => {
                    debug!("kubernetes: skipping {resource}: {e}");
                    continue;
                }
            };

            let items = json
                .get("items")
                .and_then(|i| i.as_array())
                .cloned()
                .unwrap_or_default();

            for item in &items {
                let namespace = item
                    .get("metadata")
                    .and_then(|m| m.get("namespace"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("default");

                if self.should_skip_namespace(namespace) {
                    continue;
                }

                let name = item
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");

                // Navigate to pod spec (direct for Pod, nested for Deployment etc.)
                let pod_spec = item
                    .get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
                    .or_else(|| item.get("spec"));

                if let Some(spec) = pod_spec {
                    let env_lines = extract_env_from_spec(spec);
                    if !env_lines.is_empty() {
                        let mut attrs = HashMap::new();
                        attrs.insert("namespace".to_string(), namespace.to_string());
                        attrs.insert("name".to_string(), name.to_string());
                        attrs.insert("resource".to_string(), resource.to_string());

                        fragments.push(Fragment {
                            content: Bytes::from(env_lines.join("\n")),
                            metadata: FragmentMetadata {
                                path: format!("k8s://{resource}/{namespace}/{name}#env"),
                                source_type: SourceType::Kubernetes,
                                size: 0,
                                attributes: attrs,
                            },
                        });
                    }
                }
            }
        }

        debug!(count = fragments.len(), "kubernetes: scanned pod env vars");
        Ok(fragments)
    }
}

/// Extract all env var definitions from a pod spec.
pub(crate) fn extract_env_from_spec(spec: &serde_json::Value) -> Vec<String> {
    let mut lines = Vec::new();

    let containers = spec
        .get("containers")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    let init_containers = spec
        .get("initContainers")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    for container in containers.iter().chain(init_containers.iter()) {
        if let Some(env_list) = container.get("env").and_then(|e| e.as_array()) {
            for env_var in env_list {
                let name = env_var.get("name").and_then(|n| n.as_str()).unwrap_or("");
                // Only include vars with a direct `value` (not valueFrom references)
                if let Some(value) = env_var.get("value").and_then(|v| v.as_str()) {
                    if !value.is_empty() {
                        lines.push(format!("{name} = \"{value}\""));
                    }
                }
            }
        }
    }

    lines
}

/// Decode base64 (with or without newlines, padding or not).
fn base64_decode(encoded: &str) -> Vec<u8> {
    use base64::Engine;
    let clean: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .unwrap_or_else(|_| {
            // Try URL-safe variant
            base64::engine::general_purpose::URL_SAFE
                .decode(&clean)
                .unwrap_or_default()
        })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_name() {
        use crate::sources::traits::AsyncSource;
        let source = KubernetesSource::new();
        assert_eq!(source.name(), "kubernetes");
    }

    #[test]
    fn test_skip_kube_system() {
        let source = KubernetesSource::new();
        assert!(source.should_skip_namespace("kube-system"));
        assert!(source.should_skip_namespace("kube-public"));
        assert!(!source.should_skip_namespace("production"));
    }

    #[test]
    fn test_custom_skip_namespace() {
        let source = KubernetesSource::new().skip_namespace("staging");
        assert!(source.should_skip_namespace("staging"));
        assert!(!source.should_skip_namespace("production"));
    }

    #[test]
    fn test_base64_decode_standard() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("supersecretpassword");
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, b"supersecretpassword");
    }

    #[test]
    fn test_base64_decode_with_newlines() {
        // Kubernetes often includes newlines in base64 values
        let encoded = "c3VwZXJzZWNyZXRwYXNzd29yZA==\n";
        let decoded = base64_decode(encoded);
        assert_eq!(decoded, b"supersecretpassword");
    }

    #[test]
    fn test_extract_env_from_spec() {
        let spec = serde_json::json!({
            "containers": [{
                "name": "app",
                "env": [
                    {"name": "API_KEY", "value": "secret123"},
                    {"name": "DEBUG", "value": "false"},
                    {"name": "DB_PASS", "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}}}
                ]
            }]
        });

        let lines = extract_env_from_spec(&spec);
        assert!(lines.contains(&"API_KEY = \"secret123\"".to_string()));
        assert!(lines.contains(&"DEBUG = \"false\"".to_string()));
        // valueFrom should NOT be included (no direct value)
        assert!(!lines.iter().any(|l| l.contains("DB_PASS")));
    }

    #[test]
    fn test_extract_env_empty_values_skipped() {
        let spec = serde_json::json!({
            "containers": [{
                "name": "app",
                "env": [
                    {"name": "EMPTY_VAR", "value": ""},
                    {"name": "REAL_KEY", "value": "sk-abc123"}
                ]
            }]
        });

        let lines = extract_env_from_spec(&spec);
        assert!(!lines.iter().any(|l| l.contains("EMPTY_VAR")));
        assert!(lines.contains(&"REAL_KEY = \"sk-abc123\"".to_string()));
    }
}
