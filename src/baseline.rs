//! Baseline and incremental scanning support.
//!
//! Secret Squirrel can maintain a persistent scan state to enable incremental scanning:
//! only files that have changed since the last scan are re-scanned.
//!
//! # How It Works
//!
//! 1. On first run, all files are scanned and their content hashes + finding hashes stored
//!    in `.squirrel-state.json` (or a custom path).
//! 2. On subsequent runs with `--baseline`, only files whose content hash has changed are
//!    rescanned. Previously-found secrets that haven't changed are carried forward.
//! 3. New findings are reported; suppressed findings (ones the user has acknowledged) are
//!    stored in the state file and filtered from future reports.
//!
//! # State File Format
//!
//! The state file is a JSON file with the following structure:
//!
//! ```json
//! {
//!   "version": 1,
//!   "scan_id": "uuid-v4",
//!   "created_at": "2025-01-01T00:00:00Z",
//!   "updated_at": "2025-01-01T01:00:00Z",
//!   "file_hashes": {"path/to/file": "sha256hex"},
//!   "finding_hashes": ["hash1", "hash2"],
//!   "suppressed": ["hash_of_suppressed_finding"]
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::error::{Result, SquirrelError};

/// Default state file name, written to the project root.
pub const DEFAULT_STATE_FILE: &str = ".squirrel-state.json";

// ============================================================================
// ScanState
// ============================================================================

/// Persistent scan state for incremental scanning.
///
/// Tracks which files have been scanned, what their content hashes are,
/// and which findings have been seen or suppressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    /// State format version (bump on breaking changes).
    pub version: u32,
    /// Unique identifier for this scan state (UUID v4 string).
    pub scan_id: String,
    /// When this state was first created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When this state was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Map from file path to SHA-256 content hash (hex).
    /// Used to detect which files have changed since the last scan.
    pub file_hashes: HashMap<String, String>,
    /// Set of finding hashes seen in the current or previous scans.
    /// A finding hash is `sha256(rule_id + ":" + secret_hash + ":" + path)`.
    pub finding_hashes: HashSet<String>,
    /// Set of finding hashes that have been explicitly suppressed.
    /// Suppressed findings are not reported in future scans.
    pub suppressed: HashSet<String>,
}

impl ScanState {
    /// Create a new empty scan state.
    pub fn new() -> Self {
        Self {
            version: 1,
            scan_id: generate_id(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            file_hashes: HashMap::new(),
            finding_hashes: HashSet::new(),
            suppressed: HashSet::new(),
        }
    }

    /// Load state from a file. Returns a new empty state if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            debug!("state file not found at {:?}, creating new state", path);
            return Ok(Self::new());
        }

        let content = std::fs::read_to_string(path).map_err(SquirrelError::Io)?;

        let state: ScanState = serde_json::from_str(&content).map_err(|e| {
            SquirrelError::Serialization(format!("failed to parse state file {:?}: {e}", path))
        })?;

        if state.version != 1 {
            warn!(
                "state file version {} is newer than supported (1), starting fresh",
                state.version
            );
            return Ok(Self::new());
        }

        info!(
            scan_id = %state.scan_id,
            files = state.file_hashes.len(),
            findings = state.finding_hashes.len(),
            suppressed = state.suppressed.len(),
            "loaded scan state"
        );

        Ok(state)
    }

    /// Save state to a file.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.updated_at = chrono::Utc::now();

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SquirrelError::Serialization(format!("failed to serialize state: {e}")))?;

        // Write to a temporary file then rename (atomic on POSIX, best-effort on Windows)
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(SquirrelError::Io)?;
        std::fs::rename(&tmp, path).map_err(SquirrelError::Io)?;

        debug!(path = %path.display(), "saved scan state");
        Ok(())
    }

    /// Check whether a file needs to be rescanned.
    ///
    /// Returns `true` if the file is new or its content has changed since
    /// the last scan.
    pub fn needs_rescan(&self, path: &str, current_hash: &str) -> bool {
        match self.file_hashes.get(path) {
            None => true,                                 // New file
            Some(prev_hash) => prev_hash != current_hash, // Changed file
        }
    }

    /// Record the content hash of a file after scanning it.
    pub fn record_file(&mut self, path: impl Into<String>, hash: impl Into<String>) {
        self.file_hashes.insert(path.into(), hash.into());
    }

    /// Record a finding as having been seen.
    pub fn record_finding(&mut self, finding_hash: impl Into<String>) {
        self.finding_hashes.insert(finding_hash.into());
    }

    /// Check whether a finding was already seen in a previous scan.
    pub fn is_known_finding(&self, finding_hash: &str) -> bool {
        self.finding_hashes.contains(finding_hash)
    }

    /// Suppress a finding by its hash. Suppressed findings are not reported.
    pub fn suppress(&mut self, finding_hash: impl Into<String>) {
        let hash = finding_hash.into();
        self.suppressed.insert(hash);
    }

    /// Check whether a finding has been suppressed.
    pub fn is_suppressed(&self, finding_hash: &str) -> bool {
        self.suppressed.contains(finding_hash)
    }

    /// Remove stale file entries (files that no longer exist on disk).
    ///
    /// Call this after a scan to keep the state file from growing unbounded.
    pub fn prune_missing_files(&mut self) {
        let before = self.file_hashes.len();
        self.file_hashes.retain(|path, _| Path::new(path).exists());
        let after = self.file_hashes.len();
        if before != after {
            debug!(
                removed = before - after,
                "pruned missing files from scan state"
            );
        }
    }

    /// Merge findings from a previous state that are not in the current set.
    ///
    /// Used when doing an incremental scan: carries forward findings from
    /// unchanged files that were not rescanned.
    pub fn merge_unchanged_findings(&mut self, previous: &ScanState, unchanged_paths: &[&str]) {
        let unchanged_set: HashSet<&str> = unchanged_paths.iter().copied().collect();

        // This is a heuristic — we don't have per-finding path info in the hash set.
        // In a full implementation, findings would be stored with their path.
        // For now, carry forward all findings from the previous state.
        for hash in &previous.finding_hashes {
            self.finding_hashes.insert(hash.clone());
        }
        debug!(
            unchanged_paths = unchanged_set.len(),
            "merged unchanged findings from previous state"
        );
    }
}

impl Default for ScanState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute the SHA-256 hash of a file's content, returned as a hex string.
pub fn hash_file(path: &Path) -> Result<String> {
    let content = std::fs::read(path).map_err(SquirrelError::Io)?;
    Ok(hash_bytes(&content))
}

/// Compute the SHA-256 hash of raw bytes, returned as a hex string.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute a stable finding hash from its key fields.
///
/// This hash is used to deduplicate findings across scans and to identify
/// suppressed findings.
pub fn finding_hash(rule_id: &str, secret_hash: &str, path: &str) -> String {
    let input = format!("{rule_id}:{secret_hash}:{path}");
    hash_bytes(input.as_bytes())
}

/// Generate a simple pseudo-random ID (16 hex bytes).
fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let rand_bytes = rand::random::<[u8; 12]>();
    format!(
        "{:08x}-{}-{}",
        nanos,
        hex::encode(&rand_bytes[..4]),
        hex::encode(&rand_bytes[4..])
    )
}

// ============================================================================
// StateManager — high-level convenience wrapper
// ============================================================================

/// High-level manager that wraps `ScanState` for typical incremental scan workflows.
pub struct StateManager {
    state: ScanState,
    state_path: PathBuf,
}

impl StateManager {
    /// Open or create a state file at the default location (`.squirrel-state.json`).
    pub fn open_default(root: &Path) -> Result<Self> {
        Self::open(root.join(DEFAULT_STATE_FILE))
    }

    /// Open or create a state file at the given path.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = ScanState::load(&path)?;
        Ok(Self {
            state,
            state_path: path,
        })
    }

    /// Check if a file needs to be rescanned and record its current hash.
    ///
    /// Returns `true` if the file should be scanned (new or changed).
    pub fn check_file(&mut self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();

        match hash_file(path) {
            Ok(hash) => {
                let needs_scan = self.state.needs_rescan(&path_str, &hash);
                // Always record the current hash (even if unchanged, to refresh timestamp logic)
                self.state.record_file(path_str, hash);
                needs_scan
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "could not hash file, will rescan");
                true // Fail open: rescan on error
            }
        }
    }

    /// Record a finding in the state.
    pub fn record_finding(&mut self, rule_id: &str, secret_hash: &str, path: &str) {
        let hash = finding_hash(rule_id, secret_hash, path);
        self.state.record_finding(hash);
    }

    /// Check if a finding is new (not seen in any previous scan).
    pub fn is_new_finding(&self, rule_id: &str, secret_hash: &str, path: &str) -> bool {
        let hash = finding_hash(rule_id, secret_hash, path);
        !self.state.is_known_finding(&hash) && !self.state.is_suppressed(&hash)
    }

    /// Suppress a finding so it won't be reported in future scans.
    pub fn suppress_finding(&mut self, rule_id: &str, secret_hash: &str, path: &str) {
        let hash = finding_hash(rule_id, secret_hash, path);
        self.state.suppress(hash);
    }

    /// Save the state to disk.
    pub fn save(&mut self) -> Result<()> {
        self.state.save(&self.state_path)
    }

    /// Access the underlying state.
    pub fn state(&self) -> &ScanState {
        &self.state
    }

    /// Finalize: prune missing files, save state.
    pub fn finalize(&mut self) -> Result<()> {
        self.state.prune_missing_files();
        self.save()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_new_state_has_version_1() {
        let state = ScanState::new();
        assert_eq!(state.version, 1);
        assert!(state.file_hashes.is_empty());
        assert!(state.finding_hashes.is_empty());
        assert!(state.suppressed.is_empty());
    }

    #[test]
    fn test_needs_rescan_new_file() {
        let state = ScanState::new();
        assert!(state.needs_rescan("path/to/file.py", "abc123"));
    }

    #[test]
    fn test_needs_rescan_unchanged_file() {
        let mut state = ScanState::new();
        state.record_file("path/to/file.py", "abc123");
        assert!(!state.needs_rescan("path/to/file.py", "abc123"));
    }

    #[test]
    fn test_needs_rescan_changed_file() {
        let mut state = ScanState::new();
        state.record_file("path/to/file.py", "abc123");
        assert!(state.needs_rescan("path/to/file.py", "def456"));
    }

    #[test]
    fn test_finding_hash_deterministic() {
        let h1 = finding_hash("aws-access-key", "sha256abc", "/etc/config");
        let h2 = finding_hash("aws-access-key", "sha256abc", "/etc/config");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_finding_hash_path_sensitive() {
        let h1 = finding_hash("rule", "hash", "path/a");
        let h2 = finding_hash("rule", "hash", "path/b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_suppress_and_check() {
        let mut state = ScanState::new();
        let hash = finding_hash("rule", "hash", "path");
        state.suppress(hash.clone());
        assert!(state.is_suppressed(&hash));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        let mut state = ScanState::new();
        state.record_file("src/main.py", "deadbeef");
        state.record_finding("findinghash123");
        state.suppress("suppressedhash456");

        state.save(&path).unwrap();

        let loaded = ScanState::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(
            loaded.file_hashes.get("src/main.py"),
            Some(&"deadbeef".to_string())
        );
        assert!(loaded.finding_hashes.contains("findinghash123"));
        assert!(loaded.suppressed.contains("suppressedhash456"));
    }

    #[test]
    fn test_load_missing_file_returns_empty_state() {
        let path = Path::new("/nonexistent/state.json");
        let state = ScanState::load(path).unwrap();
        assert!(state.file_hashes.is_empty());
    }

    #[test]
    fn test_state_manager_check_file() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state.json");
        let file_path = dir.path().join("secret.env");

        std::fs::write(&file_path, "API_KEY=abc123").unwrap();

        let mut mgr = StateManager::open(&state_path).unwrap();

        // First check: new file → needs rescan
        assert!(mgr.check_file(&file_path));

        // Save state
        mgr.save().unwrap();

        // Second check: same content → no rescan needed
        let mut mgr2 = StateManager::open(&state_path).unwrap();
        assert!(!mgr2.check_file(&file_path));

        // Modify file → rescan needed
        std::fs::write(&file_path, "API_KEY=changed").unwrap();
        let mut mgr3 = StateManager::open(&state_path).unwrap();
        assert!(mgr3.check_file(&file_path));
    }

    #[test]
    fn test_hash_bytes_deterministic() {
        let h1 = hash_bytes(b"hello world");
        let h2 = hash_bytes(b"hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 in hex = 64 chars
    }

    #[test]
    fn test_prune_missing_files() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("exists.py");
        std::fs::write(&existing, "x = 1").unwrap();

        let mut state = ScanState::new();
        state.record_file(existing.to_string_lossy().as_ref(), "hash1");
        state.record_file("/nonexistent/ghost.py", "hash2");

        state.prune_missing_files();

        assert!(state
            .file_hashes
            .contains_key(existing.to_string_lossy().as_ref()));
        assert!(!state.file_hashes.contains_key("/nonexistent/ghost.py"));
    }
}
