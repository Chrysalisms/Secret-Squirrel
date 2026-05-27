//! `.env` file parser source — produces one [`Fragment`] per key-value pair.
//!
//! Handles the full range of `.env` file syntax:
//!
//! - `KEY=VALUE` — simple assignment
//! - `export KEY=VALUE` — shell export syntax
//! - `KEY="quoted value"` — double-quoted values (escape sequences not expanded)
//! - `KEY='single quoted'` — single-quoted values (taken verbatim)
//! - `# comment` — lines starting with `#` are skipped
//! - Blank lines are skipped
//! - `KEY=VALUE \` — backslash continuation (multi-line values)
//!
//! Each key-value pair produces a separate [`Fragment`] with a virtual path of
//! `<file_path>:<KEY_NAME>` so downstream rules have full variable name context.

use crate::error::Result;
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};
use bytes::Bytes;
use std::collections::HashMap;
use std::path::PathBuf;

/// A parsed key-value pair from a `.env` file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvEntry {
    key: String,
    value: String,
}

/// A source that parses a `.env` file and produces one [`Fragment`] per
/// key-value pair, preserving the variable name in the fragment path for
/// downstream context.
pub struct DotenvSource {
    /// Path to the `.env` file being parsed.
    path: PathBuf,
    /// All parsed entries (loaded eagerly at construction time).
    entries: Vec<EnvEntry>,
}

impl DotenvSource {
    /// Parse the `.env` file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`SquirrelError::Io`] if the file cannot be read, or
    /// [`SquirrelError::Source`] if the content is not valid UTF-8.
    pub fn new(path: PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(&path)?;
        let entries = parse_dotenv(&raw, &path)?;
        Ok(Self { path, entries })
    }
}

impl SyncSource for DotenvSource {
    fn name(&self) -> &str {
        "dotenv"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        let path_str = self.path.to_string_lossy().into_owned();

        let iter = self.entries.iter().map(move |entry| {
            // Virtual path includes the key name for downstream context.
            let virtual_path = format!("{}:{}", path_str, entry.key);
            // Fragment content is `KEY=VALUE` so pattern rules can match on
            // both the key name and the value.
            let content_str = format!("{}={}", entry.key, entry.value);
            let content = Bytes::from(content_str.into_bytes());
            let size = content.len() as u64;

            let mut attrs = HashMap::new();
            attrs.insert("key".to_string(), entry.key.clone());

            Ok(Fragment {
                content,
                metadata: FragmentMetadata {
                    path: virtual_path,
                    source_type: SourceType::Dotenv,
                    size,
                    attributes: attrs,
                },
            })
        });

        Box::new(iter)
    }
}

// ============================================================================
// Dotenv parser
// ============================================================================

/// Parse a `.env` file's text content into a list of [`EnvEntry`]s.
///
/// This is intentionally lenient — malformed lines are skipped with a warning
/// rather than returning an error, to maximise the chance of finding secrets
/// even in unusual `.env` files.
fn parse_dotenv(content: &str, path: &std::path::Path) -> Result<Vec<EnvEntry>> {
    let mut entries = Vec::new();
    let mut lines = content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Handle `export KEY=VALUE` syntax.
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();

        // Split on the first `=`.
        let eq_pos = match trimmed.find('=') {
            Some(p) => p,
            None => {
                // No `=` — not a valid key-value line (e.g. `unset KEY`).
                continue;
            }
        };

        let key = trimmed[..eq_pos].trim().to_string();
        if key.is_empty() {
            continue;
        }

        let raw_value = &trimmed[eq_pos + 1..];

        // Handle backslash continuation: accumulate lines ending with `\`.
        let mut value_parts = vec![raw_value.to_string()];
        while value_parts.last().map(|l: &String| l.ends_with('\\')).unwrap_or(false) {
            // Remove the trailing backslash.
            if let Some(last) = value_parts.last_mut() {
                last.pop();
            }
            match lines.next() {
                Some(continuation) => value_parts.push(continuation.trim().to_string()),
                None => break,
            }
        }
        let joined = value_parts.join("");

        let value = strip_quotes(joined.trim());

        entries.push(EnvEntry { key, value });
    }

    let _ = path; // Used for error context — reserved for future use.
    Ok(entries)
}

/// Remove surrounding quote characters from a value.
///
/// Handles both `"double"` and `'single'` quotes. The quotes must match and
/// wrap the entire value.
fn strip_quotes(s: &str) -> String {
    if s.len() >= 2 {
        let first = s.chars().next().unwrap();
        let last = s.chars().last().unwrap();
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_dotenv(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    // ── Parser unit tests ────────────────────────────────────────────────────

    #[test]
    fn test_simple_key_value() {
        let entries = parse_dotenv("AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE", std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "AWS_SECRET_KEY");
        assert_eq!(entries[0].value, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_comment_line_is_skipped() {
        let content = "# This is a comment\nKEY=value";
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "KEY");
    }

    #[test]
    fn test_double_quoted_value() {
        let content = r#"DB_URL="postgresql://user:pass@host/db""#;
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "postgresql://user:pass@host/db");
    }

    #[test]
    fn test_single_quoted_value() {
        let content = "API_KEY='s3cr3t_k3y_with_special!chars'";
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "s3cr3t_k3y_with_special!chars");
    }

    #[test]
    fn test_export_syntax() {
        let content = "export DATABASE_PASSWORD=hunter2";
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "DATABASE_PASSWORD");
        assert_eq!(entries[0].value, "hunter2");
    }

    #[test]
    fn test_blank_lines_skipped() {
        let content = "\n\nKEY=val\n\n";
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_multiple_entries() {
        let content = "A=1\n# comment\nB=2\nC=3";
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_value_containing_equals() {
        // Only the FIRST `=` is the separator.
        let content = "URL=https://user:pass@host/db?ssl=true";
        let entries = parse_dotenv(content, std::path::Path::new(".env")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "https://user:pass@host/db?ssl=true");
    }

    // ── DotenvSource integration tests ───────────────────────────────────────

    #[test]
    fn test_source_produces_one_fragment_per_entry() {
        let dir = TempDir::new().unwrap();
        let path = write_dotenv(
            &dir,
            ".env",
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASS=hunter2\n",
        );

        let source = DotenvSource::new(path).unwrap();
        let fragments: Vec<_> = source.fragments().filter_map(|r| r.ok()).collect();

        assert_eq!(fragments.len(), 2);
    }

    #[test]
    fn test_fragment_path_includes_key_name() {
        let dir = TempDir::new().unwrap();
        let path = write_dotenv(&dir, ".env", "API_TOKEN=secret_value\n");

        let source = DotenvSource::new(path.clone()).unwrap();
        let f = source.fragments().next().unwrap().unwrap();

        assert!(
            f.metadata.path.contains("API_TOKEN"),
            "fragment path should include key name: {}",
            f.metadata.path
        );
    }

    #[test]
    fn test_fragment_content_is_key_equals_value() {
        let dir = TempDir::new().unwrap();
        let path = write_dotenv(&dir, ".env", "SECRET=my_secret\n");

        let source = DotenvSource::new(path).unwrap();
        let f = source.fragments().next().unwrap().unwrap();
        let content = std::str::from_utf8(&f.content).unwrap();

        assert_eq!(content, "SECRET=my_secret");
    }

    #[test]
    fn test_fragment_source_type_is_dotenv() {
        let dir = TempDir::new().unwrap();
        let path = write_dotenv(&dir, ".env", "X=y\n");

        let source = DotenvSource::new(path).unwrap();
        let f = source.fragments().next().unwrap().unwrap();
        assert_eq!(f.metadata.source_type, SourceType::Dotenv);
    }
}
