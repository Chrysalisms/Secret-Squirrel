//! Directory/filesystem source — `.gitignore`-aware file walker.
//!
//! Uses the [`ignore`] crate for gitignore-aware directory traversal. Binary files are
//! detected by scanning the first 512 bytes for null bytes and skipped
//! automatically.

use crate::config::SourcesConfig;
use crate::error::{Result, SquirrelError};
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};
use bytes::Bytes;
use ignore::WalkBuilder;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use tracing::{debug, warn};

// Maximum number of bytes inspected to determine if a file is binary.
const BINARY_PROBE_LEN: usize = 512;

/// A source that walks a directory tree, skipping binaries and files over the
/// configured size limit, and produces one [`Fragment`] per readable text file.
pub struct DirSource {
    /// Root directory to walk from.
    root: PathBuf,
    /// Maximum file size in bytes (files larger than this are skipped).
    max_file_size: u64,
    /// Additional glob patterns to ignore (beyond `.gitignore`).
    ignore_patterns: Vec<String>,
}

impl DirSource {
    /// Create a new `DirSource` rooted at `root`.
    ///
    /// `config` is used to read `max_file_size` (via [`crate::config::ScanConfig`])
    /// and any extra ignore patterns from [`SourcesConfig`].
    ///
    /// # Arguments
    ///
    /// * `root` — Directory to scan (must exist).
    /// * `max_file_size` — Skip files larger than this many bytes.
    /// * `config` — Source configuration (ignore patterns).
    pub fn new(root: PathBuf, max_file_size: u64, config: &SourcesConfig) -> Self {
        Self {
            root,
            max_file_size,
            ignore_patterns: config.ignore_patterns.clone(),
        }
    }

    /// Returns `true` if the first `BINARY_PROBE_LEN` bytes of `data` contain
    /// a null byte — a reliable heuristic for binary file detection.
    fn is_binary(data: &[u8]) -> bool {
        let probe = &data[..data.len().min(BINARY_PROBE_LEN)];
        probe.contains(&0u8)
    }
}

impl SyncSource for DirSource {
    fn name(&self) -> &str {
        "directory"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        let mut builder = WalkBuilder::new(&self.root);
        builder
            .hidden(false) // include dotfiles like .env
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true);

        // Add user-configured ignore patterns as overrides.
        for pattern in &self.ignore_patterns {
            builder.add_ignore(pattern);
        }

        let walk = builder.build_parallel();
        let max_file_size = self.max_file_size;

        let (tx, rx) = crossbeam_channel::bounded(1024);

        std::thread::spawn(move || {
            walk.run(|| {
                let tx = tx.clone();
                Box::new(move |result| {
                    let entry = match result {
                        Ok(e) => e,
                        Err(e) => {
                            warn!("walk error: {e}");
                            return ignore::WalkState::Continue;
                        }
                    };

                    // Skip directories — we only want files.
                    if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                        return ignore::WalkState::Continue;
                    }

                    let path = entry.path().to_path_buf();

                    // ── Size guard ──────────────────────────────────────────────────
                    let metadata = match entry.metadata() {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("cannot read metadata for {}: {e}", path.display());
                            return ignore::WalkState::Continue;
                        }
                    };
                    let file_size = metadata.len();
                    if file_size > max_file_size {
                        debug!(
                            "skipping {} — size {} > limit {}",
                            path.display(),
                            file_size,
                            max_file_size
                        );
                        return ignore::WalkState::Continue;
                    }

                    // Empty files produce an empty fragment (valid — they may match
                    // path-based rules in future pipeline stages).
                    if file_size == 0 {
                        let path_str = path.to_string_lossy().into_owned();
                        let _ = tx.send(Ok(Fragment {
                            content: Bytes::new(),
                            metadata: FragmentMetadata {
                                path: path_str,
                                source_type: SourceType::Directory,
                                size: 0,
                                attributes: HashMap::new(),
                            },
                        }));
                        return ignore::WalkState::Continue;
                    }

                    // ── Read file directly ───────────────────────────────────────────
                    let file_content = match std::fs::read(&path) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(Err(SquirrelError::Io(e)));
                            return ignore::WalkState::Continue;
                        }
                    };

                    // ── Binary detection ─────────────────────────────────────────────
                    if Self::is_binary(&file_content) {
                        debug!("skipping binary file: {}", path.display());
                        return ignore::WalkState::Continue;
                    }

                    let content = Bytes::from(file_content);
                    let path_str = path.to_string_lossy().into_owned();

                    let mut attrs = HashMap::new();
                    attrs.insert("file_size".to_string(), file_size.to_string());

                    let _ = tx.send(Ok(Fragment {
                        content,
                        metadata: FragmentMetadata {
                            path: path_str,
                            source_type: SourceType::Directory,
                            size: file_size,
                            attributes: attrs,
                        },
                    }));

                    ignore::WalkState::Continue
                })
            });
        });

        Box::new(rx.into_iter())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn default_config() -> SourcesConfig {
        SourcesConfig::default()
    }

    /// Helper: write a file with given content inside `dir`.
    fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn test_all_three_text_files_are_produced() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "a.txt", b"plain text file");
        write_file(&dir, "b.env", b"SECRET=AKIAIOSFODNN7EXAMPLE");
        write_file(&dir, "c.md", b"# Docs\nNothing secret here.");

        let config = default_config();
        let source = DirSource::new(dir.path().to_path_buf(), 50 * 1024 * 1024, &config);
        let fragments: Vec<_> = source.fragments().collect();

        assert_eq!(fragments.len(), 3, "expected 3 text fragments");
        assert!(fragments.iter().all(|r| r.is_ok()), "all fragments should be Ok");
    }

    #[test]
    fn test_binary_file_is_skipped() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "text.txt", b"I am readable text");
        // Binary file: contains null byte in first 512 bytes.
        let mut binary_content = vec![0u8; 100];
        binary_content[10] = b'\0';
        write_file(&dir, "binary.bin", &binary_content);

        let config = default_config();
        let source = DirSource::new(dir.path().to_path_buf(), 50 * 1024 * 1024, &config);
        let fragments: Vec<_> = source
            .fragments()
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(fragments.len(), 1, "binary file should be skipped");
        assert!(fragments[0].metadata.path.ends_with("text.txt"));
    }

    #[test]
    fn test_oversized_file_is_skipped() {
        let dir = TempDir::new().unwrap();
        // "hi!" is 3 bytes — under any reasonable limit.
        write_file(&dir, "small.txt", b"hi!");
        // 36-byte file — will be over a 10-byte limit.
        write_file(&dir, "big.txt", b"content longer than ten bytes here!!!");

        let config = default_config();
        // Set max_file_size to 10 bytes so big.txt (36 bytes) is skipped
        // but small.txt (3 bytes) passes.
        let source = DirSource::new(dir.path().to_path_buf(), 10, &config);
        let fragments: Vec<_> = source
            .fragments()
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(fragments.len(), 1, "only the small file should pass the size filter");
        assert!(
            fragments[0].metadata.path.ends_with("small.txt"),
            "the surviving fragment should be small.txt"
        );
    }

    #[test]
    fn test_fragment_has_correct_source_type_and_size() {
        let dir = TempDir::new().unwrap();
        let content = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE";
        write_file(&dir, "secrets.env", content);

        let config = default_config();
        let source = DirSource::new(dir.path().to_path_buf(), 50 * 1024 * 1024, &config);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        let f = &fragments[0];
        assert_eq!(f.metadata.source_type, SourceType::Directory);
        assert_eq!(f.metadata.size, content.len() as u64);
        assert_eq!(f.content.as_ref(), content);
    }
}
