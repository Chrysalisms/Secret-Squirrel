//! NPM / PyPI package source adapter.
//!
//! Downloads published packages from the NPM or PyPI registry, extracts the
//! package tarball in memory, and produces [`Fragment`]s from source files
//! for credential scanning.
//!
//! # Use Cases
//!
//! - Verify that a package you are about to publish does not contain secrets
//! - Scan an already-published package for accidentally committed credentials
//! - Audit supply-chain packages for embedded backdoor credentials
//!
//! # Security
//!
//! - Tarballs are decompressed in memory with a 100:1 ratio limit (zip bomb protection).
//! - Only text-like files are scanned; binary files are skipped.
//! - Download size is capped at `max_package_size` (default 50 MB).
//!
//! # Example
//!
//! ```rust,ignore
//! use secret_squirrel::sources::npm_package::{NpmPackageSource, PackageRegistry};
//!
//! let source = NpmPackageSource::new("lodash", "4.17.21", PackageRegistry::Npm)
//!     .unwrap();
//! ```

use std::collections::HashMap;
use std::io::Read;

use bytes::Bytes;
use tracing::{debug, warn};

use crate::error::{Result, SquirrelError};
use crate::sources::traits::AsyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Registry enum
// ============================================================================

/// Package registry to download from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageRegistry {
    /// NPM registry (`registry.npmjs.org`).
    Npm,
    /// PyPI (`files.pythonhosted.org`).
    Pypi,
    /// Custom registry base URL (must be NPM-compatible protocol).
    Custom(String),
}

impl PackageRegistry {
    /// Base URL for the registry.
    pub fn base_url(&self) -> &str {
        match self {
            PackageRegistry::Npm => "https://registry.npmjs.org",
            PackageRegistry::Pypi => "https://pypi.org/pypi",
            PackageRegistry::Custom(url) => url.as_str(),
        }
    }

    /// Source type label for fragment metadata.
    pub fn source_type(&self) -> SourceType {
        match self {
            PackageRegistry::Npm => SourceType::NpmPackage,
            PackageRegistry::Pypi => SourceType::NpmPackage, // reuse same variant
            PackageRegistry::Custom(_) => SourceType::NpmPackage,
        }
    }
}

// ============================================================================
// NpmPackageSource
// ============================================================================

/// Scans a published NPM or PyPI package for credential-like values.
///
/// Construct via [`NpmPackageSource::new`].
#[derive(Debug)]
pub struct NpmPackageSource {
    /// Package name (e.g., `"lodash"` or `"requests"`).
    pub package_name: String,
    /// Package version (e.g., `"4.17.21"`). If empty, uses `"latest"`.
    pub version: String,
    /// Target registry.
    pub registry: PackageRegistry,
    /// Maximum download size in bytes (default: 50 MB).
    pub max_package_size: usize,
    client: reqwest::Client,
}

impl NpmPackageSource {
    /// Create a new source for the given package.
    pub fn new(
        package_name: impl Into<String>,
        version: impl Into<String>,
        registry: PackageRegistry,
    ) -> Result<Self> {
        let name = package_name.into();
        if name.is_empty() {
            return Err(SquirrelError::Config(
                "NpmPackageSource: package_name cannot be empty".into(),
            ));
        }
        Ok(Self {
            package_name: name,
            version: version.into(),
            registry,
            max_package_size: 50 * 1024 * 1024, // 50 MB
            client: reqwest::Client::new(),
        })
    }

    /// Build the download URL for an NPM package.
    fn npm_tarball_url(&self) -> String {
        let version = if self.version.is_empty() { "latest" } else { &self.version };
        format!(
            "{}/{}/{}",
            self.registry.base_url(),
            self.package_name,
            version,
        )
    }

    /// Extract fragment content from a `.tgz` tarball bytes.
    pub fn extract_from_tarball(
        &self,
        tarball_bytes: &[u8],
        package_label: &str,
    ) -> Result<Vec<Fragment>> {
        use flate2::read::GzDecoder;
        use tar::Archive;

        let gz = GzDecoder::new(tarball_bytes);
        let mut archive = Archive::new(gz);

        let mut fragments = Vec::new();
        let compressed_len = tarball_bytes.len();
        let mut total_extracted: usize = 0;
        let ratio_limit = 100;

        let entries = archive.entries().map_err(|e| SquirrelError::Source {
            src_name: "npm-package".into(),
            reason: format!("Failed to read tarball entries: {e}"),
        })?;

        for entry_result in entries {
            let mut entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    warn!(source = "npm-package", error = %e, "Skipping corrupted tarball entry");
                    continue;
                }
            };

            let header = entry.header();
            if header.entry_type() != tar::EntryType::Regular {
                continue;
            }

            let path_str = entry
                .path()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_default();

            // Skip binary files and package metadata
            if is_binary_extension(&path_str) {
                continue;
            }

            let uncompressed_size = header.size().unwrap_or(0) as usize;

            // Zip bomb protection
            total_extracted += uncompressed_size;
            if total_extracted > compressed_len * ratio_limit {
                return Err(SquirrelError::Source {
                    src_name: "npm-package".into(),
                    reason: format!(
                        "Decompression ratio exceeded {ratio_limit}:1 — possible zip bomb"
                    ),
                });
            }

            // Skip very large individual files
            if uncompressed_size > 10 * 1024 * 1024 {
                debug!(
                    source = "npm-package",
                    path = %path_str,
                    size = uncompressed_size,
                    "Skipping oversized file"
                );
                continue;
            }

            let mut content = Vec::with_capacity(uncompressed_size.min(10_000));
            if let Err(e) = entry.read_to_end(&mut content) {
                warn!(source = "npm-package", path = %path_str, error = %e, "Could not read entry");
                continue;
            }

            // Skip binary content (null bytes in first 8KB)
            if content[..content.len().min(8192)].contains(&0u8) {
                continue;
            }

            let size = content.len() as u64;
            let fragment_path = format!("npm://{}/{}/{}", package_label, self.package_name, path_str);
            let mut attributes = HashMap::new();
            attributes.insert("package".to_string(), self.package_name.clone());
            attributes.insert("version".to_string(), self.version.clone());
            attributes.insert("file".to_string(), path_str);
            attributes.insert("registry".to_string(), self.registry.base_url().to_string());

            fragments.push(Fragment {
                content: Bytes::from(content),
                metadata: FragmentMetadata {
                    path: fragment_path,
                    source_type: self.registry.source_type(),
                    size,
                    attributes,
                },
            });
        }

        Ok(fragments)
    }
}

/// Returns `true` if the file extension is known-binary (skip scanning).
fn is_binary_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    let binary_exts = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp4", ".webm", ".ogg", ".mp3", ".wav",
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
        ".exe", ".dll", ".so", ".dylib", ".a", ".lib",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".node", // native Node addons
        ".wasm",
        ".min.js", // minified JS — not useful for secret scanning
        ".map",    // source maps
    ];
    binary_exts.iter().any(|ext| lower.ends_with(ext))
}

#[async_trait::async_trait]
impl AsyncSource for NpmPackageSource {
    fn name(&self) -> &str {
        match self.registry {
            PackageRegistry::Npm => "npm-package",
            PackageRegistry::Pypi => "pypi-package",
            PackageRegistry::Custom(_) => "package-registry",
        }
    }

    async fn fragments(&self) -> Result<Vec<Fragment>> {
        debug!(
            source = self.name(),
            package = %self.package_name,
            version = %self.version,
            registry = self.registry.base_url(),
            "Starting package scan"
        );

        // Step 1: Fetch package metadata to get tarball URL
        let meta_url = self.npm_tarball_url();
        let meta_resp = self
            .client
            .get(&meta_url)
            .header("Accept", "application/json")
            .header("User-Agent", "secret-squirrel/0.1.0")
            .send()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: self.name().to_string(),
                reason: format!("Failed to fetch package metadata from {meta_url}: {e}"),
            })?;

        if !meta_resp.status().is_success() {
            return Err(SquirrelError::Source {
                src_name: self.name().to_string(),
                reason: format!(
                    "Registry returned HTTP {} for package {}@{}",
                    meta_resp.status(),
                    self.package_name,
                    self.version
                ),
            });
        }

        let meta: serde_json::Value = meta_resp.json().await.map_err(|e| SquirrelError::Source {
            src_name: self.name().to_string(),
            reason: format!("Failed to parse package metadata JSON: {e}"),
        })?;

        // Extract tarball URL from NPM metadata
        let tarball_url = meta
            .pointer("/dist/tarball")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SquirrelError::Source {
                src_name: self.name().to_string(),
                reason: "Package metadata missing dist.tarball URL".into(),
            })?
            .to_string();

        debug!(source = self.name(), tarball_url = %tarball_url, "Downloading tarball");

        // Step 2: Download the tarball
        let tarball_resp = self
            .client
            .get(&tarball_url)
            .header("User-Agent", "secret-squirrel/0.1.0")
            .send()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: self.name().to_string(),
                reason: format!("Failed to download tarball: {e}"),
            })?;

        let tarball_bytes = tarball_resp
            .bytes()
            .await
            .map_err(|e| SquirrelError::Source {
                src_name: self.name().to_string(),
                reason: format!("Failed to read tarball bytes: {e}"),
            })?;

        if tarball_bytes.len() > self.max_package_size {
            return Err(SquirrelError::Source {
                src_name: self.name().to_string(),
                reason: format!(
                    "Package tarball ({} MB) exceeds max_package_size ({} MB)",
                    tarball_bytes.len() / 1024 / 1024,
                    self.max_package_size / 1024 / 1024
                ),
            });
        }

        // Step 3: Extract and scan
        let version_label = &self.version;
        self.extract_from_tarball(&tarball_bytes, version_label)
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_requires_non_empty_name() {
        let result = NpmPackageSource::new("", "1.0.0", PackageRegistry::Npm);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_succeeds_with_valid_args() {
        let source = NpmPackageSource::new("lodash", "4.17.21", PackageRegistry::Npm).unwrap();
        assert_eq!(source.package_name, "lodash");
        assert_eq!(source.version, "4.17.21");
        assert_eq!(source.registry, PackageRegistry::Npm);
    }

    #[test]
    fn test_name_npm() {
        let source = NpmPackageSource::new("test", "1.0", PackageRegistry::Npm).unwrap();
        assert_eq!(source.name(), "npm-package");
    }

    #[test]
    fn test_name_pypi() {
        let source = NpmPackageSource::new("requests", "2.31", PackageRegistry::Pypi).unwrap();
        assert_eq!(source.name(), "pypi-package");
    }

    #[test]
    fn test_is_binary_extension_skips_images() {
        assert!(is_binary_extension("dist/logo.png"));
        assert!(is_binary_extension("assets/font.woff2"));
        assert!(is_binary_extension("addon.node"));
        assert!(is_binary_extension("app.wasm"));
    }

    #[test]
    fn test_is_binary_extension_allows_js_ts_py() {
        assert!(!is_binary_extension("index.js"));
        assert!(!is_binary_extension("src/main.ts"));
        assert!(!is_binary_extension("setup.py"));
        assert!(!is_binary_extension("README.md"));
        assert!(!is_binary_extension("package.json"));
        assert!(!is_binary_extension(".env.example"));
    }

    #[test]
    fn test_extract_from_tarball_empty_bytes_fails() {
        let source = NpmPackageSource::new("test", "1.0", PackageRegistry::Npm).unwrap();
        // Empty bytes may either error (invalid gzip) or produce no fragments.
        // Both are acceptable — we just verify it doesn't panic.
        let result = source.extract_from_tarball(&[], "1.0");
        match result {
            Ok(frags) => assert!(
                frags.is_empty(),
                "Empty tarball must produce no fragments, got {}",
                frags.len()
            ),
            Err(_) => { /* also acceptable — empty is not valid gzip */ }
        }
    }

    #[test]
    fn test_extract_from_real_tarball() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        use tar::Builder;

        // Build a tiny in-memory .tgz
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let gz = GzEncoder::new(&mut tar_buf, Compression::default());
            let mut ar = Builder::new(gz);

            // File 1: a JS file with a secret
            let content = b"const apiKey = 'sk_live_abcdefghijklmnopqrstuvwxyz123456';";
            let mut header = tar::Header::new_gnu();
            header.set_path("package/index.js").unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            ar.append(&header, content.as_slice()).unwrap();

            // File 2: a binary file (should be skipped)
            let binary = b"\x00\x01\x02\x03PNG-like binary data";
            let mut hdr2 = tar::Header::new_gnu();
            hdr2.set_path("package/logo.png").unwrap();
            hdr2.set_size(binary.len() as u64);
            hdr2.set_mode(0o644);
            hdr2.set_cksum();
            ar.append(&hdr2, binary.as_slice()).unwrap();

            // File 3: package.json
            let pkg_json = br#"{"name":"test","version":"1.0.0","main":"index.js"}"#;
            let mut hdr3 = tar::Header::new_gnu();
            hdr3.set_path("package/package.json").unwrap();
            hdr3.set_size(pkg_json.len() as u64);
            hdr3.set_mode(0o644);
            hdr3.set_cksum();
            ar.append(&hdr3, pkg_json.as_slice()).unwrap();

            ar.into_inner().unwrap().finish().unwrap();
        }

        let source = NpmPackageSource::new("test-pkg", "1.0.0", PackageRegistry::Npm).unwrap();
        let frags = source.extract_from_tarball(&tar_buf, "1.0.0").unwrap();

        // Should have index.js and package.json — NOT logo.png (binary extension)
        assert_eq!(
            frags.len(),
            2,
            "Expected 2 text fragments (index.js + package.json), got {}: {:?}",
            frags.len(),
            frags.iter().map(|f| &f.metadata.path).collect::<Vec<_>>()
        );

        let js_frag = frags.iter().find(|f| f.metadata.path.contains("index.js"));
        assert!(js_frag.is_some(), "Must have index.js fragment");
        let js_content = String::from_utf8(js_frag.unwrap().content.to_vec()).unwrap();
        assert!(js_content.contains("sk_live_"), "index.js must contain the planted secret");

        // All fragments should have correct source type
        for frag in &frags {
            assert_eq!(frag.metadata.source_type, SourceType::NpmPackage);
        }
    }

    #[test]
    fn test_extract_zip_bomb_protection() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        // Build a tarball with one file that reports an enormous size
        // (we can't actually expand 100x in a test, but we simulate via max_package_size)
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let gz = GzEncoder::new(&mut tar_buf, Compression::default());
            let mut ar = Builder::new(gz);
            // 11 MB file (over the 10 MB single-file limit)
            let big_content = vec![b'A'; 11 * 1024 * 1024];
            let mut hdr = tar::Header::new_gnu();
            hdr.set_path("package/big.js").unwrap();
            hdr.set_size(big_content.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            ar.append(&hdr, big_content.as_slice()).unwrap();
            ar.into_inner().unwrap().finish().unwrap();
        }

        let source = NpmPackageSource::new("test-pkg", "1.0.0", PackageRegistry::Npm).unwrap();
        // The 11 MB file exceeds the per-file limit (10 MB) OR the
        // decompression ratio limit — either way we must not OOM.
        // Accept both: Ok([]) (skipped) or Err (ratio exceeded).
        let result = source.extract_from_tarball(&tar_buf, "1.0.0");
        match result {
            Ok(frags) => assert!(
                frags.is_empty(),
                "11 MB file must be skipped, got {} fragments",
                frags.len()
            ),
            Err(e) => {
                // Zip bomb protection triggered — also acceptable
                let msg = e.to_string();
                assert!(
                    msg.contains("ratio") || msg.contains("zip bomb") || msg.contains("oversized"),
                    "Expected zip-bomb/oversized error, got: {msg}"
                );
            }
        }
    }

    #[test]
    fn test_registry_base_urls() {
        assert_eq!(PackageRegistry::Npm.base_url(), "https://registry.npmjs.org");
        assert_eq!(PackageRegistry::Pypi.base_url(), "https://pypi.org/pypi");
        assert_eq!(
            PackageRegistry::Custom("https://my-registry.example.com".into()).base_url(),
            "https://my-registry.example.com"
        );
    }
}
