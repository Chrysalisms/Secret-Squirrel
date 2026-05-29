//! Model download and management for `squirrel model pull`.
//!
//! This module handles the lifecycle of ONNX model files that back the CNN
//! classifier:
//!
//! - [`default_model_dir`] — resolves `~/.squirrel/models` on the current OS.
//! - [`download_model`]    — streams a model from a URL, verifies SHA-256, and
//!   atomically writes it to disk via a `.tmp` rename.
//! - [`list_models`]       — enumerates all `*.onnx` files in a model directory.
//!
//! # Atomic writes
//!
//! [`download_model`] first writes the download to `<dest>.tmp`, then renames
//! it to the final path.  On most operating systems, rename is atomic within the
//! same filesystem, so a crash during download will never leave a half-written
//! model file in place.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Result, SquirrelError};

/// Returns the default directory where model files are stored.
///
/// Resolves to `~/.squirrel/models`. If the home directory cannot be
/// determined, falls back to `./.squirrel/models` relative to the current
/// working directory.
#[must_use]
pub fn default_model_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".squirrel")
        .join("models")
}

/// Download a model from `url` and save it to `dest`.
///
/// # Arguments
///
/// * `url`           — Full HTTPS URL to the ONNX model file.
/// * `dest`          — Destination path (file, not directory). Parent directories
///                     are created automatically.
/// * `expected_sha256` — Optional lowercase hex SHA-256 digest of the expected
///                     file contents.  If provided and the digest does not match,
///                     the file is **not** written and an error is returned.
///
/// # Returns
///
/// The number of bytes written on success.
///
/// # Errors
///
/// * [`SquirrelError::Io`] if a filesystem operation fails.
/// * [`SquirrelError::Source`] if the HTTP request fails or returns a non-2xx status.
/// * [`SquirrelError::Cnn`] if the SHA-256 digest does not match `expected_sha256`.
pub async fn download_model(url: &str, dest: &Path, expected_sha256: Option<&str>) -> Result<u64> {
    use reqwest::Client;

    // Ensure the parent directory exists.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(SquirrelError::Io)?;
    }

    // Build an HTTP client with a descriptive user-agent.
    let client = Client::builder()
        .user_agent("secret-squirrel/0.1.0")
        .build()
        .map_err(|e| SquirrelError::Source {
            src_name: "model".into(),
            reason: e.to_string(),
        })?;

    // Perform the GET request.
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| SquirrelError::Source {
            src_name: "model".into(),
            reason: e.to_string(),
        })?;

    if !resp.status().is_success() {
        return Err(SquirrelError::Source {
            src_name: "model".into(),
            reason: format!("HTTP {} downloading model from {url}", resp.status()),
        });
    }

    // Buffer the full response body in memory.
    // For multi-GB models this would need a streaming approach; the current
    // model sizes (≤260 MB) fit comfortably in RAM on target platforms.
    let bytes = resp.bytes().await.map_err(|e| SquirrelError::Source {
        src_name: "model".into(),
        reason: e.to_string(),
    })?;

    // Verify SHA-256 checksum before touching disk.
    if let Some(expected) = expected_sha256 {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            return Err(SquirrelError::Cnn(format!(
                "Checksum mismatch for {url}: expected {expected}, got {actual}"
            )));
        }
    }

    let size = bytes.len() as u64;

    // Atomic write: write to `.tmp`, then rename.
    let tmp = dest.with_extension("tmp");
    std::fs::write(&tmp, &bytes).map_err(SquirrelError::Io)?;
    std::fs::rename(&tmp, dest).map_err(SquirrelError::Io)?;

    Ok(size)
}

/// Return a list of all `*.onnx` files in `model_dir` with their sizes.
///
/// Returns an empty `Vec` if the directory does not exist or cannot be read.
/// The order of entries is not guaranteed.
#[must_use]
pub fn list_models(model_dir: &Path) -> Vec<(String, u64)> {
    let Ok(entries) = std::fs::read_dir(model_dir) else {
        return Vec::new();
    };

    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "onnx").unwrap_or(false))
        .map(|e| {
            let path = e.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            (name, size)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_model_dir_is_under_squirrel() {
        let dir = default_model_dir();
        let s = dir.to_string_lossy();
        assert!(
            s.contains(".squirrel"),
            "Expected '.squirrel' in path, got: {s}"
        );
        assert!(
            s.ends_with("models"),
            "Expected path to end with 'models', got: {s}"
        );
    }

    #[test]
    fn test_list_models_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let models = list_models(tmp.path());
        assert!(models.is_empty(), "Expected no models in empty dir");
    }

    #[test]
    fn test_list_models_finds_onnx_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("model.onnx"), b"fake onnx").unwrap();
        std::fs::write(tmp.path().join("notes.txt"), b"nope").unwrap();
        std::fs::write(tmp.path().join("other.bin"), b"nope").unwrap();

        let models = list_models(tmp.path());
        assert_eq!(models.len(), 1, "Only the .onnx file should be listed");
        assert_eq!(models[0].0, "model.onnx");
        assert_eq!(models[0].1, 9); // "fake onnx" is 9 bytes
    }

    #[test]
    fn test_list_models_multiple_onnx() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.onnx"), b"aa").unwrap();
        std::fs::write(tmp.path().join("b.onnx"), b"bbb").unwrap();
        std::fs::write(tmp.path().join("c.onnx"), b"cccc").unwrap();

        let mut models = list_models(tmp.path());
        // Sort for deterministic comparison
        models.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(models.len(), 3);
        assert_eq!(models[0].0, "a.onnx");
        assert_eq!(models[1].0, "b.onnx");
        assert_eq!(models[2].0, "c.onnx");
    }

    #[test]
    fn test_list_models_nonexistent_dir() {
        let path = Path::new("/nonexistent/path/that/does/not/exist/models");
        let models = list_models(path);
        assert!(
            models.is_empty(),
            "Non-existent dir should return empty list"
        );
    }
}
