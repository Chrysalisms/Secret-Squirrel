//! Jupyter Notebook (`.ipynb`) source adapter.
//!
//! Jupyter Notebooks are JSON files whose cells may contain inline secrets
//! — API keys pasted into code cells, tokens printed in output cells, etc.
//!
//! This adapter parses the notebook JSON and extracts:
//!
//! * **Code cell sources** — `cells[*].source` (array of strings joined)
//! * **Cell stream output text** — `cells[*].outputs[*].text` (array, joined)
//! * **Cell plain-text MIME data** — `cells[*].outputs[*].data["text/plain"]`
//!
//! Each cell produces one [`Fragment`] whose path is
//! `notebook://{filename}:cell[{index}]`.
//!
//! Construct via [`NotebookSource::new`] for a single file, or
//! [`NotebookSource::from_dir`] to discover all `.ipynb` files under a
//! directory.
//!
//! # Example
//!
//! ```rust,no_run
//! use secret_squirrel::sources::notebook::NotebookSource;
//! use secret_squirrel::sources::traits::SyncSource as _;
//!
//! let source = NotebookSource::new("analysis.ipynb");
//! for fragment in source.fragments() {
//!     println!("{}", fragment.unwrap().metadata.path);
//! }
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use bytes::Bytes;
use serde::Deserialize;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::error::{Result, SquirrelError};
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};

// ============================================================================
// Notebook JSON schema (partial)
// ============================================================================

/// Top-level `.ipynb` document.
#[derive(Debug, Deserialize)]
struct Notebook {
    #[serde(default)]
    cells: Vec<NotebookCell>,
}

/// A single cell inside a notebook.
#[derive(Debug, Deserialize)]
struct NotebookCell {
    cell_type: String,
    /// Source lines (array of strings, each ending with `\n`).
    #[serde(default)]
    source: Vec<String>,
    /// Cell outputs (may be absent for non-executed cells).
    #[serde(default)]
    outputs: Vec<CellOutput>,
}

/// An output entry within a cell.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CellOutput {
    /// `stream`, `display_data`, `execute_result`, `error`, etc.
    #[serde(default)]
    output_type: String,
    /// Present for `stream` outputs.
    #[serde(default)]
    text: Vec<String>,
    /// Present for `display_data` / `execute_result` outputs.
    #[serde(default)]
    data: HashMap<String, serde_json::Value>,
}

// ============================================================================
// NotebookSource
// ============================================================================

/// A synchronous source that scans a Jupyter Notebook file for credential
/// fragments.
///
/// Construct via [`NotebookSource::new`] (single file) or
/// [`NotebookSource::from_dir`] (directory discovery).
pub struct NotebookSource {
    path: PathBuf,
}

impl NotebookSource {
    /// Create a source targeting a single `.ipynb` file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Discover all `.ipynb` files under `dir` and return a source for each.
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Io`] if `dir` cannot be read.
    pub fn from_dir(dir: PathBuf) -> Result<Vec<Self>> {
        let mut sources = Vec::new();

        for entry in WalkDir::new(&dir).follow_links(false) {
            let entry = entry.map_err(|e| {
                SquirrelError::Source {
                    src_name: "notebook".into(),
                    reason: e.to_string(),
                }
            })?;

            if !entry.file_type().is_file() {
                continue;
            }

            if entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("ipynb"))
                .unwrap_or(false)
            {
                sources.push(NotebookSource::new(entry.path().to_path_buf()));
            }
        }

        Ok(sources)
    }
}

impl SyncSource for NotebookSource {
    fn name(&self) -> &str {
        "notebook"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        // Parse the notebook up front; any failure becomes a single error item.
        let raw = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) => {
                return Box::new(std::iter::once(Err(SquirrelError::Io(e))));
            }
        };

        let notebook: Notebook = match serde_json::from_slice(&raw) {
            Ok(n) => n,
            Err(e) => {
                return Box::new(std::iter::once(Err(SquirrelError::Json(e))));
            }
        };

        let filename = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.to_string_lossy().into_owned());

        let fragments: Vec<Result<Fragment>> = notebook
            .cells
            .into_iter()
            .enumerate()
            .filter(|(_, cell)| cell.cell_type == "code")
            .filter_map(|(idx, cell)| {
                let content = build_cell_content(&cell);
                if content.is_empty() {
                    debug!(
                        source = "notebook",
                        file = %filename,
                        cell = idx,
                        "Empty code cell; skipping"
                    );
                    return None;
                }

                let size = content.len() as u64;
                let path = format!("notebook://{}:cell[{}]", filename, idx);

                let mut attributes = HashMap::new();
                attributes.insert("notebook".to_string(), filename.clone());
                attributes.insert("cell_index".to_string(), idx.to_string());

                Some(Ok(Fragment {
                    content: Bytes::from(content.into_bytes()),
                    metadata: FragmentMetadata {
                        path,
                        source_type: SourceType::Jupyter,
                        size,
                        attributes,
                    },
                }))
            })
            .collect();

        Box::new(fragments.into_iter())
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Concatenate source lines and all extractable output text for a single cell.
fn build_cell_content(cell: &NotebookCell) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Source lines.
    if !cell.source.is_empty() {
        parts.push(cell.source.join(""));
    }

    // Outputs.
    for output in &cell.outputs {
        // Stream text (stdout / stderr).
        if !output.text.is_empty() {
            parts.push(output.text.join(""));
        }

        // MIME data: text/plain.
        if let Some(plain) = output.data.get("text/plain") {
            if let Some(s) = json_lines_to_string(plain) {
                if !s.is_empty() {
                    parts.push(s);
                }
            }
        }
    }

    parts.join("\n")
}

/// Convert a `serde_json::Value` that is either a `String` or an
/// `Array` of strings (as Jupyter uses for multi-line data) into a plain
/// `String`. Returns `None` for unsupported types.
fn json_lines_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            let lines: Vec<String> = arr
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect();
            Some(lines.join(""))
        }
        other => {
            warn!(source = "notebook", value = ?other, "Unexpected text/plain type; skipping");
            None
        }
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

    fn write_notebook(dir: &TempDir, name: &str, json: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        path
    }

    // ── name() ───────────────────────────────────────────────────────────────

    #[test]
    fn test_name_returns_notebook() {
        let dir = TempDir::new().unwrap();
        let path = write_notebook(&dir, "test.ipynb", r#"{"cells":[]}"#);
        let source = NotebookSource::new(path);
        assert_eq!(source.name(), "notebook");
    }

    // ── Minimal notebook with one code cell ──────────────────────────────────

    #[test]
    fn test_parses_minimal_code_cell() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["import os\n", "print(os.getenv('API_KEY'))"]
                }
            ]
        }"#;
        let path = write_notebook(&dir, "minimal.ipynb", json);
        let source = NotebookSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1, "One code cell → one fragment");
        let content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(content.contains("import os"));
        assert!(content.contains("API_KEY"));
        assert_eq!(fragments[0].metadata.source_type, SourceType::Jupyter);
    }

    // ── Extracts source from code cell ────────────────────────────────────────

    #[test]
    fn test_extracts_source_lines() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["token = 'ghp_abcdefg1234567'\n", "auth(token)"]
                }
            ]
        }"#;
        let path = write_notebook(&dir, "source.ipynb", json);
        let source = NotebookSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        let content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(content.contains("ghp_abcdefg1234567"));
    }

    // ── Extracts output text ─────────────────────────────────────────────────

    #[test]
    fn test_extracts_output_text() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["print('hello')"],
                    "outputs": [
                        {
                            "output_type": "stream",
                            "text": ["AKIA1234567890ABCDEF\n", "another line\n"]
                        }
                    ]
                }
            ]
        }"#;
        let path = write_notebook(&dir, "output.ipynb", json);
        let source = NotebookSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        let content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(content.contains("AKIA1234567890ABCDEF"), "Should contain output text");
    }

    // ── Markdown cells are ignored ────────────────────────────────────────────

    #[test]
    fn test_markdown_cells_are_ignored() {
        let dir = TempDir::new().unwrap();
        // Build the JSON string without using \n inside a raw string literal
        // (\n is not valid inside r#"..."# — use a regular string instead).
        let json = "{
            \"cells\": [
                {
                    \"cell_type\": \"markdown\",
                    \"source\": [\"# Title\\n\", \"This is markdown with a fake key AKIA...\"]
                },
                {
                    \"cell_type\": \"code\",
                    \"source\": [\"x = 1\"]
                }
            ]
        }";
        let path = write_notebook(&dir, "mixed.ipynb", json);
        let source = NotebookSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(
            fragments.len(),
            1,
            "Only the code cell should produce a fragment"
        );
    }

    // ── text/plain MIME data ──────────────────────────────────────────────────

    #[test]
    fn test_extracts_text_plain_mime_data() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["x"],
                    "outputs": [
                        {
                            "output_type": "execute_result",
                            "text": [],
                            "data": {
                                "text/plain": ["'secret_value_in_repr'"]
                            }
                        }
                    ]
                }
            ]
        }"#;
        let path = write_notebook(&dir, "repr.ipynb", json);
        let source = NotebookSource::new(path);
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 1);
        let content = String::from_utf8(fragments[0].content.to_vec()).unwrap();
        assert!(
            content.contains("secret_value_in_repr"),
            "Should extract text/plain MIME data"
        );
    }

    // ── from_dir discovers .ipynb files ──────────────────────────────────────

    #[test]
    fn test_from_dir_discovers_notebooks() {
        let dir = TempDir::new().unwrap();
        write_notebook(&dir, "a.ipynb", r#"{"cells":[]}"#);
        write_notebook(&dir, "b.ipynb", r#"{"cells":[]}"#);
        // Non-notebook file should be ignored.
        let txt_path = dir.path().join("readme.txt");
        std::fs::write(&txt_path, "ignored").unwrap();

        let sources = NotebookSource::from_dir(dir.path().to_path_buf()).unwrap();
        assert_eq!(sources.len(), 2, "Should discover 2 .ipynb files");
    }
}
