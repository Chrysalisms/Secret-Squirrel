//! Docker image scanner.
//!
//! Scans Docker images for secrets by inspecting:
//!
//! - `ENV` variables baked into image layers
//! - `ARG` build arguments (visible in image history)
//! - Label values
//! - Layer tarballs — scans file content within each layer for secrets
//!   (e.g., `.env` files, configs, scripts committed to the image)
//!
//! # Security Model
//!
//! Docker images are surprisingly common vectors for secret leakage:
//! - `ENV API_KEY=abc123` in a Dockerfile permanently bakes the key into the image
//! - Build args passed at `docker build --build-arg SECRET=val` appear in history
//! - Files added via `COPY` or `ADD` that contain secrets remain in the layer
//!
//! # Authentication
//!
//! Set `DOCKER_HOST` env var or leave unset to use the default Docker socket.
//! For private registries, use `docker login` first — this scanner does not
//! manage registry auth.
//!
//! # Requirements
//!
//! Requires a running Docker daemon. If Docker is unavailable, `fragments()`
//! returns an error rather than an empty vec.

use bytes::Bytes;
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// DockerSource
// ============================================================================

/// Scans Docker images for secrets in ENV vars, labels, history, and file layers.
pub struct DockerSource {
    /// Docker image reference to scan (e.g., `"nginx:latest"`, `"my-app:1.0"`)
    image_ref: String,
    /// Maximum size of any single file extracted from a layer (bytes). Default: 5MB.
    max_file_bytes: u64,
    /// File extensions to skip when scanning layers (binary blobs, media, etc.)
    skip_extensions: Vec<String>,
}

impl DockerSource {
    /// Create a scanner for the given Docker image reference.
    pub fn new(image_ref: impl Into<String>) -> Self {
        Self {
            image_ref: image_ref.into(),
            max_file_bytes: 5 * 1024 * 1024,
            skip_extensions: default_skip_extensions(),
        }
    }

    /// Override the maximum file size.
    pub fn with_max_file_bytes(mut self, bytes: u64) -> Self {
        self.max_file_bytes = bytes;
        self
    }

    /// Override the list of file extensions to skip.
    pub fn with_skip_extensions(mut self, exts: Vec<String>) -> Self {
        self.skip_extensions = exts;
        self
    }
}

fn default_skip_extensions() -> Vec<String> {
    [
        "jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "svg", "mp4", "avi", "mkv", "mov",
        "mp3", "ogg", "wav", "zip", "gz", "bz2", "xz", "tar", "whl", "egg", "pyc", "class", "so",
        "dll", "exe", "bin", "pdf", "doc", "docx", "xls", "xlsx", "ttf", "otf", "woff", "woff2",
        "eot",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[async_trait::async_trait]
impl crate::sources::traits::AsyncSource for DockerSource {
    fn name(&self) -> &str {
        "docker"
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        let mut fragments = Vec::new();

        // ── 1. ENV + ARG + label scanning (via `docker inspect`) ────────────
        let env_frags = self.scan_image_metadata()?;
        fragments.extend(env_frags);

        // ── 2. Layer file scanning (via `docker save` + tar extraction) ─────
        let layer_frags = self.scan_image_layers().await?;
        fragments.extend(layer_frags);

        debug!(
            image = %self.image_ref,
            fragment_count = fragments.len(),
            "docker: scan complete"
        );

        Ok(fragments)
    }
}

impl DockerSource {
    /// Scan image metadata: ENV vars, labels, history ENV/ARG instructions.
    ///
    /// Uses `docker inspect` to get the image config without pulling layers.
    fn scan_image_metadata(&self) -> Result<Vec<Fragment>> {
        let output = std::process::Command::new("docker")
            .args(["inspect", "--format", "{{json .}}", &self.image_ref])
            .output()
            .map_err(|e| SquirrelError::Source {
                src_name: "docker".to_string(),
                reason: format!("docker inspect failed: {e}. Is Docker running?"),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SquirrelError::Source {
                src_name: "docker".to_string(),
                reason: format!(
                    "docker inspect returned error for '{}': {stderr}",
                    self.image_ref
                ),
            });
        }

        let inspect: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|e| SquirrelError::Source {
                src_name: "docker".to_string(),
                reason: format!("could not parse docker inspect output: {e}"),
            })?;

        let mut fragments = Vec::new();

        // Extract from a single image or an array (docker inspect returns array)
        let images = if inspect.is_array() {
            inspect.as_array().cloned().unwrap_or_default()
        } else {
            vec![inspect]
        };

        for image in images {
            // ── ENV variables ────────────────────────────────────────────────
            if let Some(env_list) = image
                .get("Config")
                .and_then(|c| c.get("Env"))
                .and_then(|e| e.as_array())
            {
                let env_content: String = env_list
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| format!("export {s}"))
                    .collect::<Vec<_>>()
                    .join("\n");

                if !env_content.is_empty() {
                    let mut attrs = HashMap::new();
                    attrs.insert("image".to_string(), self.image_ref.clone());
                    attrs.insert("layer".to_string(), "env".to_string());

                    fragments.push(Fragment {
                        content: Bytes::from(env_content),
                        metadata: FragmentMetadata {
                            path: format!("docker://{}#ENV", self.image_ref),
                            source_type: SourceType::Docker,
                            size: 0,
                            attributes: attrs,
                        },
                    });
                }
            }

            // ── Labels ───────────────────────────────────────────────────────
            if let Some(labels) = image
                .get("Config")
                .and_then(|c| c.get("Labels"))
                .and_then(|l| l.as_object())
            {
                let label_content: String = labels
                    .iter()
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("\n");

                if !label_content.is_empty() {
                    let mut attrs = HashMap::new();
                    attrs.insert("image".to_string(), self.image_ref.clone());
                    attrs.insert("layer".to_string(), "labels".to_string());

                    fragments.push(Fragment {
                        content: Bytes::from(label_content),
                        metadata: FragmentMetadata {
                            path: format!("docker://{}#LABELS", self.image_ref),
                            source_type: SourceType::Docker,
                            size: 0,
                            attributes: attrs,
                        },
                    });
                }
            }

            // ── Build history (CMD, ENTRYPOINT, ARG instructions) ────────────
            if let Some(history) = image.get("History").and_then(|h| h.as_array()) {
                let history_content: String = history
                    .iter()
                    .filter_map(|h| h.get("CreatedBy").and_then(|c| c.as_str()))
                    .filter(|s| {
                        // Only include lines that might contain secrets
                        s.contains("ENV") || s.contains("ARG") || s.contains("RUN")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                if !history_content.is_empty() {
                    let mut attrs = HashMap::new();
                    attrs.insert("image".to_string(), self.image_ref.clone());
                    attrs.insert("layer".to_string(), "history".to_string());

                    fragments.push(Fragment {
                        content: Bytes::from(history_content),
                        metadata: FragmentMetadata {
                            path: format!("docker://{}#HISTORY", self.image_ref),
                            source_type: SourceType::Docker,
                            size: 0,
                            attributes: attrs,
                        },
                    });
                }
            }
        }

        Ok(fragments)
    }

    /// Scan files within image layers by streaming `docker save` output.
    ///
    /// Uses `docker save <image> | tar -xO` to extract the OCI image tarball,
    /// then scans individual layer tarballs for sensitive files.
    async fn scan_image_layers(&self) -> Result<Vec<Fragment>> {
        // Use spawn_blocking + std::process::Command for async-safe execution
        let image_ref = self.image_ref.clone();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("docker")
                .args(["save", &image_ref])
                .output()
        })
        .await
        .map_err(|e| SquirrelError::Source {
            src_name: "docker".to_string(),
            reason: format!("spawn_blocking error: {e}"),
        })?
        .map_err(|e| SquirrelError::Source {
            src_name: "docker".to_string(),
            reason: format!("docker save failed: {e}"),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SquirrelError::Source {
                src_name: "docker".to_string(),
                reason: format!("docker save error: {stderr}"),
            });
        }

        self.extract_from_tar(&output.stdout)
    }

    /// Extract and scan files from an OCI image tarball.
    fn extract_from_tar(&self, tar_data: &[u8]) -> Result<Vec<Fragment>> {
        use std::io::Read;

        let mut fragments = Vec::new();
        let cursor = std::io::Cursor::new(tar_data);
        let mut outer_archive = tar::Archive::new(cursor);

        let entries = outer_archive.entries().map_err(|e| SquirrelError::Source {
            src_name: "docker".to_string(),
            reason: format!("could not read OCI tar: {e}"),
        })?;

        for entry in entries {
            let mut entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("docker: tar entry error: {e}");
                    continue;
                }
            };

            let path = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            // Layer tarballs are nested: <sha256>/layer.tar
            if !path.ends_with("/layer.tar") && path != "layer.tar" {
                continue;
            }

            let mut layer_data = Vec::new();
            if entry.read_to_end(&mut layer_data).is_err() {
                warn!("docker: could not read layer: {path}");
                continue;
            }

            // Extract files from the layer tarball
            let layer_fragments = self.extract_from_layer_tar(&layer_data, &path);
            fragments.extend(layer_fragments);
        }

        Ok(fragments)
    }

    /// Extract scannable files from a single layer tarball.
    fn extract_from_layer_tar(&self, layer_data: &[u8], layer_path: &str) -> Vec<Fragment> {
        use std::io::Read;

        let mut fragments = Vec::new();
        let cursor = std::io::Cursor::new(layer_data);
        let mut archive = tar::Archive::new(cursor);

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                warn!("docker: could not read layer tar {layer_path}: {e}");
                return fragments;
            }
        };

        for entry in entries {
            let mut entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Only scan regular files
            if !matches!(entry.header().entry_type(), tar::EntryType::Regular) {
                continue;
            }

            let file_path = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            // Skip binary/media extensions
            if self.should_skip_path(&file_path) {
                continue;
            }

            let file_size = entry.header().size().unwrap_or(0);
            if file_size > self.max_file_bytes {
                debug!("docker: skipping oversized file {file_path} ({file_size} bytes)");
                continue;
            }

            let mut content = Vec::new();
            if let Err(e) = entry.read_to_end(&mut content) {
                warn!("docker: could not read file {file_path}: {e}");
                continue;
            }

            // Skip empty or non-text files (heuristic: null bytes in first 512 bytes)
            if content.is_empty() || is_binary(&content) {
                continue;
            }

            let mut attrs = HashMap::new();
            attrs.insert("image".to_string(), self.image_ref.clone());
            attrs.insert("layer".to_string(), layer_path.to_string());

            fragments.push(Fragment {
                content: Bytes::from(content),
                metadata: FragmentMetadata {
                    path: format!("docker://{}#{}", self.image_ref, file_path),
                    source_type: SourceType::Docker,
                    size: file_size,
                    attributes: attrs,
                },
            });
        }

        fragments
    }

    fn should_skip_path(&self, path: &str) -> bool {
        if let Some(ext) = path.rsplit('.').next() {
            let ext_lower = ext.to_lowercase();
            self.skip_extensions.iter().any(|s| s == &ext_lower)
        } else {
            false
        }
    }
}

/// Heuristic: check if bytes look like binary data (null bytes in first 512 bytes).
fn is_binary(data: &[u8]) -> bool {
    let check_len = data.len().min(512);
    data[..check_len].contains(&0u8)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_binary_with_null() {
        assert!(is_binary(b"hello\x00world"));
    }

    #[test]
    fn test_is_binary_text() {
        assert!(!is_binary(b"export API_KEY=supersecretvalue123"));
    }

    #[test]
    fn test_should_skip_jpg() {
        let source = DockerSource::new("test:latest");
        assert!(source.should_skip_path("/app/logo.jpg"));
    }

    #[test]
    fn test_should_not_skip_dotenv() {
        let source = DockerSource::new("test:latest");
        assert!(!source.should_skip_path("/app/.env"));
    }

    #[test]
    fn test_should_not_skip_toml() {
        let source = DockerSource::new("test:latest");
        assert!(!source.should_skip_path("/etc/app/config.toml"));
    }

    #[test]
    fn test_default_source_name() {
        let source = DockerSource::new("my-image:1.0");
        use crate::sources::traits::AsyncSource;
        assert_eq!(source.name(), "docker");
    }

    #[test]
    fn test_extract_from_tar_empty() {
        // Create a minimal valid tar (just end-of-archive marker)
        let tar_data = vec![0u8; 1024]; // two 512-byte zero blocks = end of archive
        let source = DockerSource::new("test:latest");
        let result = source.extract_from_tar(&tar_data);
        // Should not error, should return empty fragments
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_env_content_formatted() {
        // Test that ENV vars are formatted as `export KEY=VALUE`
        let env_vars = vec!["API_KEY=secret123", "DEBUG=true"];
        let content: String = env_vars
            .iter()
            .map(|s| format!("export {s}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(content.contains("export API_KEY=secret123"));
    }
}
