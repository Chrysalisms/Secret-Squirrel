//! Terraform state and configuration scanner.
//!
//! Scans the following Terraform file types:
//!
//! - `terraform.tfstate` / `*.tfstate.backup` — **highest priority**: plaintext JSON
//!   state that often contains resolved secrets (DB passwords, API keys, TLS keys)
//! - `*.tf` — HCL configuration files (regex-based extraction of variable defaults)
//! - `*.tfvars` / `*.tfvars.json` — Variable definition files
//!
//! # Why Terraform state is critical
//!
//! Terraform state persists *all* provider resource attributes in plaintext, including
//! fields marked `sensitive = true`. Any `.tfstate` file that was ever committed to
//! git or left on disk is a high-severity finding.

use bytes::Bytes;
use std::path::Path;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::error::Result;
use crate::types::{Fragment, FragmentMetadata, SourceType};

/// Terraform state and configuration scanner.
pub struct TerraformSource {
    /// Root directory to scan for Terraform files.
    root: std::path::PathBuf,
    /// Maximum file size to read (bytes). Default: 50MB.
    max_file_bytes: u64,
}

impl TerraformSource {
    /// Create a scanner rooted at `root`.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_file_bytes: 50 * 1024 * 1024,
        }
    }

    /// Override the maximum file size.
    pub fn with_max_bytes(mut self, bytes: u64) -> Self {
        self.max_file_bytes = bytes;
        self
    }
}

impl Default for TerraformSource {
    fn default() -> Self {
        Self::new(".")
    }
}

impl crate::sources::traits::SyncSource for TerraformSource {
    fn name(&self) -> &str {
        "terraform"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        let walker = WalkDir::new(&self.root).follow_links(false).into_iter();

        let max = self.max_file_bytes;

        let iter = walker.filter_map(move |entry| {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("terraform: walk error: {e}");
                    return None;
                }
            };

            if !entry.file_type().is_file() {
                return None;
            }

            let path = entry.path().to_owned();
            let name = path.file_name()?.to_string_lossy().to_lowercase();

            // Skip hidden files
            if name.starts_with('.') {
                return None;
            }

            // Only process Terraform-related files
            let is_terraform = name.ends_with(".tfstate")
                || name.ends_with(".tfstate.backup")
                || name.ends_with(".tf")
                || name.ends_with(".tfvars")
                || name.ends_with(".tfvars.json");

            if !is_terraform {
                return None;
            }

            Some(read_terraform_file(&path, max))
        });

        Box::new(iter)
    }
}

/// Read a Terraform file and produce a Fragment.
///
/// For `.tfstate` JSON files, we also extract just the `"value"` fields
/// from `sensitive_attributes` and `attributes` to produce a denser,
/// more scannable fragment.
fn read_terraform_file(path: &Path, max_bytes: u64) -> Result<Fragment> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();

    if size > max_bytes {
        warn!(
            path = %path.display(),
            size_bytes = size,
            max_bytes,
            "terraform: skipping oversized file"
        );
        return Ok(Fragment {
            content: Bytes::new(),
            metadata: FragmentMetadata {
                path: path.to_string_lossy().into_owned(),
                source_type: SourceType::Terraform,
                size: 0,
                attributes: [("skipped".to_string(), "oversized".to_string())]
                    .into_iter()
                    .collect(),
            },
        });
    }

    let raw = std::fs::read(path)?;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    // For .tfstate files, extract sensitive fields to make scanning denser
    let content = if name.ends_with(".tfstate") || name.ends_with(".tfstate.backup") {
        extract_tfstate_values(&raw).unwrap_or_else(|| Bytes::from(raw))
    } else {
        Bytes::from(raw)
    };

    debug!(
        path = %path.display(),
        source_bytes = size,
        fragment_bytes = content.len(),
        "terraform: produced fragment"
    );

    Ok(Fragment {
        content,
        metadata: FragmentMetadata {
            path: path.to_string_lossy().into_owned(),
            source_type: SourceType::Terraform,
            size,
            attributes: Default::default(),
        },
    })
}

/// Extract all leaf string values from a Terraform state JSON.
///
/// State files contain resource attributes nested under `resources[].instances[].attributes`.
/// We extract every string value at any depth and concatenate them so the scanner
/// sees a dense stream of potential secrets without having to navigate JSON structure.
fn extract_tfstate_values(raw: &[u8]) -> Option<Bytes> {
    let json: serde_json::Value = serde_json::from_slice(raw).ok()?;

    let mut values: Vec<String> = Vec::new();
    collect_string_values(&json, &mut values, 0);

    if values.is_empty() {
        return None;
    }

    // Emit as `key = "value"` pairs for better proximity detection
    let content = values.join("\n");
    Some(Bytes::from(content))
}

/// Recursively collect all string values from a JSON value.
fn collect_string_values(val: &serde_json::Value, out: &mut Vec<String>, depth: usize) {
    if depth > 20 {
        return; // Prevent stack overflow on malicious JSON
    }
    match val {
        serde_json::Value::String(s) if !s.is_empty() => {
            out.push(s.clone());
        }
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                if let serde_json::Value::String(s) = v {
                    if !s.is_empty() {
                        // Emit as assignment for proximity detection
                        out.push(format!("{key} = \"{s}\""));
                    }
                } else {
                    collect_string_values(v, out, depth + 1);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_string_values(item, out, depth + 1);
            }
        }
        _ => {}
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::traits::SyncSource;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn test_tf_file_produces_fragment() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "main.tf",
            r#"variable "db_password" { default = "hunter2" }"#,
        );

        let source = TerraformSource::new(dir.path());
        let fragments: Vec<_> = source
            .fragments()
            .filter_map(|r| r.ok())
            .filter(|f| !f.content.is_empty())
            .collect();

        assert_eq!(fragments.len(), 1);
        assert!(std::str::from_utf8(&fragments[0].content)
            .unwrap()
            .contains("hunter2"));
        assert_eq!(fragments[0].metadata.source_type, SourceType::Terraform);
    }

    #[test]
    fn test_tfstate_extracts_values() {
        let dir = TempDir::new().unwrap();
        let state = serde_json::json!({
            "resources": [{
                "instances": [{
                    "attributes": {
                        "password": "supersecretpassword",
                        "api_key": "sk-abcdefghij1234567890"
                    }
                }]
            }]
        });
        write_file(dir.path(), "terraform.tfstate", &state.to_string());

        let source = TerraformSource::new(dir.path());
        let fragments: Vec<_> = source
            .fragments()
            .filter_map(|r| r.ok())
            .filter(|f| !f.content.is_empty())
            .collect();

        assert!(!fragments.is_empty());
        let content = std::str::from_utf8(&fragments[0].content).unwrap();
        assert!(
            content.contains("supersecretpassword"),
            "content: {content}"
        );
        assert!(
            content.contains("sk-abcdefghij1234567890"),
            "content: {content}"
        );
    }

    #[test]
    fn test_non_terraform_files_skipped() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "README.md", "# Terraform\nsome text");
        write_file(dir.path(), "main.py", "print('hello')");
        write_file(dir.path(), "main.tf", r#"variable "x" { default = "val" }"#);

        let source = TerraformSource::new(dir.path());
        let fragments: Vec<_> = source
            .fragments()
            .filter_map(|r| r.ok())
            .filter(|f| !f.content.is_empty())
            .collect();

        // Only main.tf should be included
        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].metadata.path.ends_with("main.tf"));
    }

    #[test]
    fn test_oversized_file_skipped() {
        let dir = TempDir::new().unwrap();
        let small_limit = 10u64; // only 10 bytes
        write_file(dir.path(), "big.tfstate", r#"{"resources":[]}"#);

        let source = TerraformSource::new(dir.path()).with_max_bytes(small_limit);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        // Content should be empty (skipped)
        assert!(fragments[0].content.is_empty());
    }

    #[test]
    fn test_tfvars_file_produces_fragment() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "prod.tfvars",
            "db_password = \"MySecret123!\"\napi_key = \"sk-prod-abc123\"",
        );

        let source = TerraformSource::new(dir.path());
        let fragments: Vec<_> = source
            .fragments()
            .filter_map(|r| r.ok())
            .filter(|f| !f.content.is_empty())
            .collect();

        assert_eq!(fragments.len(), 1);
        let content = std::str::from_utf8(&fragments[0].content).unwrap();
        assert!(content.contains("MySecret123!"));
    }
}
