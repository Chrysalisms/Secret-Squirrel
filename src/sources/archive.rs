//! Archive source — extracts ZIP and TAR family archives into scannable
//! [`Fragment`]s with zip-bomb protection.
//!
//! # Supported formats
//!
//! | Extension             | Backend                      |
//! |-----------------------|------------------------------|
//! | `.zip`                | [`zip`] crate                |
//! | `.tar.gz`, `.tgz`     | [`tar`] + [`flate2`] (gzip)  |
//! | `.tar.bz2`            | [`tar`] + [`bzip2`]          |
//! | `.tar.xz`             | [`tar`] + [`xz2`]            |
//!
//! # Zip-bomb protection
//!
//! The decompression ratio (uncompressed / compressed) is tracked across the
//! entire archive. If it exceeds [`MAX_DECOMPRESSION_RATIO`], extraction is
//! aborted with [`SquirrelError::CompressionBomb`].

use crate::error::{Result, SquirrelError};
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};
use bytes::Bytes;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use tracing::{debug, warn};

/// Default maximum decompression ratio (100:1) before declaring a zip bomb.
const MAX_DECOMPRESSION_RATIO: u64 = 100;

/// Supported archive formats, detected from file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveFormat {
    Zip,
    TarGz,
    TarBz2,
    TarXz,
}

/// A source that extracts an archive and produces one [`Fragment`] per entry.
pub struct ArchiveSource {
    /// Path to the archive file.
    path: PathBuf,
    /// Maximum decompressed size of a single entry (bytes). Larger files are skipped.
    max_file_size: u64,
    /// Detected archive format.
    format: ArchiveFormat,
    /// Maximum allowed decompression ratio.
    max_ratio: u64,
}

impl ArchiveSource {
    /// Open an archive at `path` and prepare to extract its entries.
    ///
    /// The archive format is detected from the file extension. Returns an error
    /// if the extension is not recognized.
    ///
    /// # Arguments
    ///
    /// * `path` — Path to the archive.
    /// * `max_file_size` — Skip entries larger than this many bytes (uncompressed).
    pub fn new(path: PathBuf, max_file_size: u64) -> Result<Self> {
        let format = detect_format(&path).ok_or_else(|| {
            SquirrelError::Archive(format!("unsupported archive format: {}", path.display()))
        })?;
        Ok(Self {
            path,
            max_file_size,
            format,
            max_ratio: MAX_DECOMPRESSION_RATIO,
        })
    }

    /// Override the maximum decompression ratio (useful for testing).
    #[allow(dead_code)]
    pub fn with_max_ratio(mut self, ratio: u64) -> Self {
        self.max_ratio = ratio;
        self
    }

    /// Read a ZIP archive, producing fragments for each text entry.
    fn read_zip(&self) -> Vec<Result<Fragment>> {
        use std::fs::File;
        use zip::ZipArchive;

        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => return vec![Err(e.into())],
        };

        let compressed_size = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => return vec![Err(e.into())],
        };

        let mut archive = match ZipArchive::new(file) {
            Ok(a) => a,
            Err(e) => {
                return vec![Err(SquirrelError::Archive(e.to_string()))];
            }
        };

        let mut fragments = Vec::new();
        let mut total_decompressed: u64 = 0;

        for i in 0..archive.len() {
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(e) => {
                    warn!("zip: failed to read entry {i}: {e}");
                    continue;
                }
            };

            // Skip directories.
            if entry.is_dir() {
                continue;
            }

            let entry_name = entry.name().to_string();
            let uncompressed_size = entry.size();

            // ── Per-entry size guard ─────────────────────────────────────────
            if uncompressed_size > self.max_file_size {
                debug!("zip: skipping {entry_name} — size {uncompressed_size} > limit");
                continue;
            }

            // ── Zip-bomb check ───────────────────────────────────────────────
            total_decompressed = total_decompressed.saturating_add(uncompressed_size);
            if compressed_size > 0 {
                let ratio = total_decompressed / compressed_size.max(1);
                if ratio > self.max_ratio {
                    fragments.push(Err(SquirrelError::CompressionBomb { ratio }));
                    return fragments;
                }
            }

            // ── Read content ─────────────────────────────────────────────────
            let mut buf = Vec::with_capacity(uncompressed_size as usize);
            if let Err(e) = entry.read_to_end(&mut buf) {
                warn!("zip: cannot read {entry_name}: {e}");
                continue;
            }

            // Skip binary entries.
            if is_binary(&buf) {
                debug!("zip: skipping binary entry {entry_name}");
                continue;
            }

            let mut attrs = HashMap::new();
            attrs.insert(
                "archive_path".to_string(),
                self.path.to_string_lossy().into_owned(),
            );

            fragments.push(Ok(Fragment {
                content: Bytes::from(buf),
                metadata: FragmentMetadata {
                    path: format!("{}:{}", self.path.display(), entry_name),
                    source_type: SourceType::Archive,
                    size: uncompressed_size,
                    attributes: attrs,
                },
            }));
        }

        fragments
    }

    /// Read a TAR archive (with optional compression), producing fragments.
    fn read_tar(&self) -> Vec<Result<Fragment>> {
        use std::fs::File;

        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => return vec![Err(e.into())],
        };

        let compressed_size = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => return vec![Err(e.into())],
        };

        // Wrap in the appropriate decompressor.
        let reader: Box<dyn Read> = match self.format {
            ArchiveFormat::TarGz => Box::new(flate2::read::GzDecoder::new(file)),
            ArchiveFormat::TarBz2 => Box::new(bzip2::read::BzDecoder::new(file)),
            ArchiveFormat::TarXz => Box::new(xz2::read::XzDecoder::new(file)),
            ArchiveFormat::Zip => unreachable!("read_tar called for zip format"),
        };

        let mut archive = tar::Archive::new(reader);
        let mut fragments = Vec::new();
        let mut total_decompressed: u64 = 0;

        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => return vec![Err(e.into())],
        };

        for entry_result in entries {
            let mut entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    warn!("tar: entry error: {e}");
                    continue;
                }
            };

            // Skip non-files.
            let entry_type = entry.header().entry_type();
            if !entry_type.is_file() {
                continue;
            }

            let entry_path = entry
                .path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "<unknown>".to_string());

            let uncompressed_size = entry.header().size().unwrap_or(0);

            // ── Per-entry size guard ─────────────────────────────────────────
            if uncompressed_size > self.max_file_size {
                debug!("tar: skipping {entry_path} — size {uncompressed_size} > limit");
                continue;
            }

            // ── Zip-bomb check ───────────────────────────────────────────────
            total_decompressed = total_decompressed.saturating_add(uncompressed_size);
            if compressed_size > 0 {
                let ratio = total_decompressed / compressed_size.max(1);
                if ratio > self.max_ratio {
                    fragments.push(Err(SquirrelError::CompressionBomb { ratio }));
                    return fragments;
                }
            }

            // ── Read content ─────────────────────────────────────────────────
            let mut buf = Vec::with_capacity(uncompressed_size as usize);
            if let Err(e) = entry.read_to_end(&mut buf) {
                warn!("tar: cannot read {entry_path}: {e}");
                continue;
            }

            if is_binary(&buf) {
                debug!("tar: skipping binary entry {entry_path}");
                continue;
            }

            let mut attrs = HashMap::new();
            attrs.insert(
                "archive_path".to_string(),
                self.path.to_string_lossy().into_owned(),
            );

            fragments.push(Ok(Fragment {
                content: Bytes::from(buf),
                metadata: FragmentMetadata {
                    path: format!("{}:{}", self.path.display(), entry_path),
                    source_type: SourceType::Archive,
                    size: uncompressed_size,
                    attributes: attrs,
                },
            }));
        }

        fragments
    }
}

/// Detect archive format from the file path extension.
fn detect_format(path: &std::path::Path) -> Option<ArchiveFormat> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name.ends_with(".zip") {
        Some(ArchiveFormat::Zip)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some(ArchiveFormat::TarGz)
    } else if name.ends_with(".tar.bz2") {
        Some(ArchiveFormat::TarBz2)
    } else if name.ends_with(".tar.xz") {
        Some(ArchiveFormat::TarXz)
    } else {
        None
    }
}

/// Binary file heuristic: check first 512 bytes for null bytes.
fn is_binary(data: &[u8]) -> bool {
    data[..data.len().min(512)].contains(&0u8)
}

impl SyncSource for ArchiveSource {
    fn name(&self) -> &str {
        "archive"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        let frags = match self.format {
            ArchiveFormat::Zip => self.read_zip(),
            ArchiveFormat::TarGz | ArchiveFormat::TarBz2 | ArchiveFormat::TarXz => self.read_tar(),
        };
        Box::new(frags.into_iter())
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

    /// Build a minimal in-memory ZIP and write it to disk.
    fn write_zip(dir: &TempDir, filename: &str, entries: &[(&str, &[u8])]) -> PathBuf {
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let path = dir.path().join(filename);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = ZipWriter::new(file);
        let opts = SimpleFileOptions::default();

        for (name, content) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    #[test]
    fn test_zip_text_entry_produces_fragment() {
        let dir = TempDir::new().unwrap();
        let content = b"STRIPE_KEY=sk_live_TESTKEY1234567890abcdef";
        let path = write_zip(&dir, "secrets.zip", &[("secrets.env", content)]);

        let source = ArchiveSource::new(path, 50 * 1024 * 1024).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].content.as_ref(), content);
        assert_eq!(fragments[0].metadata.source_type, SourceType::Archive);
    }

    #[test]
    fn test_zip_binary_entry_is_skipped() {
        let dir = TempDir::new().unwrap();
        let mut binary = vec![0u8; 100];
        binary[5] = b'\0';
        let path = write_zip(
            &dir,
            "mixed.zip",
            &[("binary.bin", &binary), ("text.txt", b"plaintext secret")],
        );

        let source = ArchiveSource::new(path, 50 * 1024 * 1024).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1, "binary entry should be skipped");
        assert!(fragments[0].metadata.path.contains("text.txt"));
    }

    #[test]
    fn test_zip_bomb_protection() {
        let dir = TempDir::new().unwrap();
        // Write a large compressible payload that will have a high ratio.
        // We use highly-compressible data (all zeros).
        let payload = vec![b'A'; 10_000];
        let path = write_zip(&dir, "bomb.zip", &[("big.txt", &payload)]);

        // Set max_ratio to 1 so it triggers almost immediately.
        let source = ArchiveSource::new(path, 50 * 1024 * 1024)
            .unwrap()
            .with_max_ratio(1);

        let has_bomb_error = source
            .fragments()
            .any(|r| matches!(r, Err(SquirrelError::CompressionBomb { .. })));

        assert!(has_bomb_error, "zip bomb should be detected");
    }

    #[test]
    fn test_unsupported_extension_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("file.7z");
        std::fs::write(&path, b"dummy").unwrap();
        let result = ArchiveSource::new(path, 1024);
        assert!(result.is_err(), "unsupported format should return an error");
    }

    #[test]
    fn test_oversized_entry_is_skipped() {
        let dir = TempDir::new().unwrap();
        let payload = b"PASSWORD=hunter2"; // 16 bytes
        let path = write_zip(&dir, "sized.zip", &[("secrets.txt", payload)]);

        // Set max_file_size to 5 — entry will be skipped.
        let source = ArchiveSource::new(path, 5).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();
        assert!(fragments.is_empty(), "oversized entry should be skipped");
    }
}
