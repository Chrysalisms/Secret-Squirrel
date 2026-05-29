//! Ansible playbook directory source adapter.
//!
//! Walks a directory tree looking for `.yml` and `.yaml` files that belong to
//! Ansible playbooks, roles, or inventory files.  Files that begin with the
//! Ansible Vault header (`$ANSIBLE_VAULT;`) are **not** scanned — their
//! content is encrypted and cannot yield plaintext secrets.  Instead, a
//! warning [`Fragment`] is produced so the pipeline can flag the presence of
//! vault files without attempting to decode them.
//!
//! # Example
//!
//! ```rust,no_run
//! use secret_squirrel::sources::ansible::AnsibleSourceBuilder;
//! use secret_squirrel::sources::traits::SyncSource as _;
//!
//! let source = AnsibleSourceBuilder::new()
//!     .root("/srv/ansible")
//!     .build()
//!     .unwrap();
//!
//! for fragment in source.fragments() {
//!     let fragment = fragment.unwrap();
//!     println!("{}", fragment.metadata.path);
//! }
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use bytes::Bytes;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::error::{Result, SquirrelError};
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Vault detection
// ============================================================================

/// The magic prefix that identifies an Ansible Vault-encrypted file.
const VAULT_HEADER: &[u8] = b"$ANSIBLE_VAULT;";

/// Warning comment injected into vault-file fragments so the scanner can
/// surface "found encrypted vault" findings without exposing ciphertext.
const VAULT_WARNING: &str = "# [squirrel: encrypted vault file - content not scanned]\n";

// ============================================================================
// AnsibleSource
// ============================================================================

/// A synchronous source that scans an Ansible playbook directory for
/// credential fragments.
///
/// Construct via [`AnsibleSourceBuilder`].
#[derive(Debug)]
pub struct AnsibleSource {
    /// Root directory to walk.
    root: PathBuf,
    /// Files larger than this (in bytes) are skipped entirely.
    max_file_size: u64,
}

impl SyncSource for AnsibleSource {
    fn name(&self) -> &str {
        "ansible"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        // Collect all fragments eagerly. The directory walk is inherently
        // sequential and bounded by the filesystem, so collecting upfront is
        // acceptable and avoids having to name a closure type inside a struct.
        let frags = walk_ansible_dir(&self.root, self.max_file_size);
        Box::new(frags.into_iter())
    }
}

/// Walk `root` for `.yml`/`.yaml` files and return a vec of fragment results.
///
/// Separated from the `SyncSource` impl so it can be a plain function that
/// avoids the unspeakable `FilterEntry<IntoIter, {closure}>` generic.
fn walk_ansible_dir(root: &std::path::Path, max_file_size: u64) -> Vec<Result<Fragment>> {
    let mut out = Vec::new();

    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                return true;
            }
            matches!(
                e.path().extension().and_then(|s| s.to_str()),
                Some("yml") | Some("yaml")
            )
        });

    for entry_result in walker {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                warn!(source = "ansible", error = %e, "Walk error; skipping entry");
                continue;
            }
        };

        if entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path().to_path_buf();

        // ── Size guard ──────────────────────────────────────────────────────
        let file_size = match entry.metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                warn!(
                    source = "ansible",
                    path = %path.display(),
                    error = %e,
                    "Cannot stat file; skipping"
                );
                continue;
            }
        };

        if file_size > max_file_size {
            debug!(
                source = "ansible",
                path = %path.display(),
                size = file_size,
                limit = max_file_size,
                "Skipping oversized YAML file"
            );
            continue;
        }

        // ── Read file ────────────────────────────────────────────────────────
        let raw = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                out.push(Err(SquirrelError::Io(e)));
                continue;
            }
        };

        let path_str = path.to_string_lossy().into_owned();
        let mut attributes = HashMap::new();
        attributes.insert("file_size".to_string(), file_size.to_string());

        // ── Vault detection ──────────────────────────────────────────────────
        if raw.starts_with(VAULT_HEADER) {
            let header_line = raw
                .iter()
                .position(|&b| b == b'\n')
                .map(|pos| &raw[..=pos])
                .unwrap_or(raw.as_slice());

            let mut content = Vec::with_capacity(header_line.len() + VAULT_WARNING.len());
            content.extend_from_slice(header_line);
            content.extend_from_slice(VAULT_WARNING.as_bytes());

            attributes.insert("vault".to_string(), "true".to_string());

            debug!(
                source = "ansible",
                path = %path.display(),
                "Vault file detected — producing warning fragment"
            );

            out.push(Ok(Fragment {
                content: Bytes::from(content),
                metadata: FragmentMetadata {
                    path: path_str,
                    source_type: SourceType::Ansible,
                    size: file_size,
                    attributes,
                },
            }));
            continue;
        }

        // ── Normal YAML file ─────────────────────────────────────────────────
        debug!(
            source = "ansible",
            path = %path.display(),
            bytes = raw.len(),
            "Producing YAML fragment"
        );

        out.push(Ok(Fragment {
            content: Bytes::from(raw),
            metadata: FragmentMetadata {
                path: path_str,
                source_type: SourceType::Ansible,
                size: file_size,
                attributes,
            },
        }));
    }

    out
}

// ============================================================================
// AnsibleSourceBuilder
// ============================================================================

/// Builder for [`AnsibleSource`].
///
/// # Example
///
/// ```rust,no_run
/// use secret_squirrel::sources::ansible::AnsibleSourceBuilder;
///
/// let source = AnsibleSourceBuilder::new()
///     .root("/srv/ansible/roles")
///     .max_file_size(2 * 1024 * 1024)
///     .build()
///     .unwrap();
/// ```
pub struct AnsibleSourceBuilder {
    root: Option<PathBuf>,
    max_file_size: u64,
}

impl AnsibleSourceBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            root: None,
            max_file_size: 1024 * 1024, // 1 MiB default
        }
    }

    /// Set the root directory to scan (required).
    pub fn root(mut self, p: impl Into<PathBuf>) -> Self {
        self.root = Some(p.into());
        self
    }

    /// Override the maximum file size in bytes (default: 1 MiB).
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Build the [`AnsibleSource`].
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Config`] if `root` was not set.
    pub fn build(self) -> Result<AnsibleSource> {
        let root = self
            .root
            .ok_or_else(|| SquirrelError::Config("AnsibleSource: root is required".into()))?;
        Ok(AnsibleSource {
            root,
            max_file_size: self.max_file_size,
        })
    }
}

impl Default for AnsibleSourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    // ── name() ───────────────────────────────────────────────────────────────

    #[test]
    fn test_name_returns_ansible() {
        let dir = TempDir::new().unwrap();
        let source = AnsibleSourceBuilder::new()
            .root(dir.path())
            .build()
            .unwrap();
        assert_eq!(source.name(), "ansible");
    }

    // ── Builder validation ───────────────────────────────────────────────────

    #[test]
    fn test_builder_requires_root() {
        let result = AnsibleSourceBuilder::new().build();
        assert!(
            result.is_err(),
            "build() should fail when root is not provided"
        );
        assert!(
            result.unwrap_err().to_string().contains("root is required"),
            "Error message should mention root"
        );
    }

    // ── Vault file detection ─────────────────────────────────────────────────

    #[test]
    fn test_vault_file_produces_warning_fragment() {
        let dir = TempDir::new().unwrap();
        write_file(
            &dir,
            "secrets.yml",
            b"$ANSIBLE_VAULT;1.1;AES256\n3264386239336338663463376434\n",
        );

        let source = AnsibleSourceBuilder::new()
            .root(dir.path())
            .build()
            .unwrap();
        let fragments: Vec<_> = source.fragments().collect();

        assert_eq!(fragments.len(), 1, "Should produce exactly one fragment");
        let frag = fragments[0].as_ref().expect("fragment should be Ok");

        let content = std::str::from_utf8(&frag.content).unwrap();
        // Should start with the vault header line.
        assert!(
            content.contains("$ANSIBLE_VAULT;"),
            "Fragment should include vault header"
        );
        // Should include our warning comment.
        assert!(
            content.contains("[squirrel: encrypted vault file - content not scanned]"),
            "Fragment should include warning comment"
        );
        // Should NOT include ciphertext.
        assert!(
            !content.contains("3264386239336338663463376434"),
            "Fragment must not expose ciphertext"
        );
        assert_eq!(frag.metadata.source_type, SourceType::Ansible);
        assert_eq!(
            frag.metadata.attributes.get("vault").map(|s| s.as_str()),
            Some("true")
        );
    }

    // ── Normal YAML ──────────────────────────────────────────────────────────

    #[test]
    fn test_normal_yaml_produces_full_content() {
        let dir = TempDir::new().unwrap();
        let content = b"---\n- name: Deploy\n  hosts: all\n  vars:\n    db_pass: super_secret\n";
        write_file(&dir, "playbook.yml", content);

        let source = AnsibleSourceBuilder::new()
            .root(dir.path())
            .build()
            .unwrap();
        let fragments: Vec<_> = source.fragments().collect();

        assert_eq!(fragments.len(), 1);
        let frag = fragments[0].as_ref().unwrap();
        assert_eq!(frag.content.as_ref(), content);
        assert_eq!(frag.metadata.source_type, SourceType::Ansible);
    }

    // ── Only YAML files are picked up ─────────────────────────────────────────

    #[test]
    fn test_only_yaml_files_are_scanned() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "playbook.yml", b"---\n- name: test\n");
        write_file(&dir, "readme.md", b"# README\nignore me\n");
        write_file(&dir, "config.json", b"{\"key\": \"value\"}");

        let source = AnsibleSourceBuilder::new()
            .root(dir.path())
            .build()
            .unwrap();
        let fragments: Vec<_> = source.fragments().collect();

        assert_eq!(
            fragments.len(),
            1,
            "Only .yml files should be picked up (not .md or .json)"
        );
    }

    // ── Oversized files are skipped ───────────────────────────────────────────

    #[test]
    fn test_oversized_file_skipped() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "small.yml", b"---\n- name: ok\n");
        write_file(
            &dir,
            "big.yml",
            b"---\n- name: a very long playbook indeed\n",
        );

        let source = AnsibleSourceBuilder::new()
            .root(dir.path())
            .max_file_size(10) // tiny limit
            .build()
            .unwrap();

        let fragments: Vec<_> = source.fragments().collect();
        // Both files are > 10 bytes, so zero should survive.
        // (small.yml is also > 10 bytes: "---\n- name: ok\n" = 16 bytes)
        assert_eq!(
            fragments.len(),
            0,
            "All files over the size limit should be skipped"
        );
    }
}
