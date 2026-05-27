//! Stdin source — reads all of standard input as a single [`Fragment`].
//!
//! Useful for piping content directly into the scanner:
//!
//! ```sh
//! cat secrets.yaml | squirrel scan -
//! cat dump.sql | squirrel scan --stdin
//! ```
//!
//! The entire stdin is buffered into memory. For very large inputs, consider
//! using the directory or archive sources instead.

use crate::error::Result;
use crate::sources::traits::SyncSource;
use crate::types::{Fragment, FragmentMetadata, SourceType};
use bytes::Bytes;
use std::collections::HashMap;
use std::io::{self, Read};

/// A source that reads all of standard input and produces a single [`Fragment`].
pub struct StdinSource {
    /// Pre-buffered stdin content (read at construction time).
    content: Bytes,
}

impl StdinSource {
    /// Read all of stdin immediately, buffering it into memory.
    ///
    /// This will block until EOF — ensure stdin is closed or piped before
    /// calling this in an async context. In the scan pipeline this is always
    /// called from a Rayon thread so blocking is safe.
    pub fn new() -> Self {
        let mut buf = Vec::new();
        // We ignore read errors here — a partial read is still scannable.
        let _ = io::stdin().lock().read_to_end(&mut buf);
        Self {
            content: Bytes::from(buf),
        }
    }
}

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncSource for StdinSource {
    fn name(&self) -> &str {
        "stdin"
    }

    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_> {
        let size = self.content.len() as u64;
        let fragment = Fragment {
            content: self.content.clone(),
            metadata: FragmentMetadata {
                path: "<stdin>".to_string(),
                source_type: SourceType::Stdin,
                size,
                attributes: HashMap::new(),
            },
        };
        Box::new(std::iter::once(Ok(fragment)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a StdinSource from pre-supplied bytes (bypasses actual stdin).
    fn stdin_from_bytes(data: &[u8]) -> StdinSource {
        StdinSource {
            content: Bytes::copy_from_slice(data),
        }
    }

    #[test]
    fn test_produces_single_fragment() {
        let source = stdin_from_bytes(b"API_KEY=sk-abc123xyz\n");
        let fragments: Vec<_> = source.fragments().collect();
        assert_eq!(fragments.len(), 1, "stdin source must produce exactly one fragment");
    }

    #[test]
    fn test_fragment_path_is_stdin() {
        let source = stdin_from_bytes(b"TOKEN=secret");
        let f = source.fragments().next().unwrap().unwrap();
        assert_eq!(f.metadata.path, "<stdin>");
    }

    #[test]
    fn test_fragment_source_type() {
        let source = stdin_from_bytes(b"data");
        let f = source.fragments().next().unwrap().unwrap();
        assert_eq!(f.metadata.source_type, SourceType::Stdin);
    }

    #[test]
    fn test_fragment_size_matches_content() {
        let data = b"PASSWORD=hunter2";
        let source = stdin_from_bytes(data);
        let f = source.fragments().next().unwrap().unwrap();
        assert_eq!(f.metadata.size, data.len() as u64);
        assert_eq!(f.content.as_ref(), data);
    }

    #[test]
    fn test_empty_stdin_produces_fragment() {
        // An empty stdin is still a valid (empty) fragment.
        let source = stdin_from_bytes(b"");
        let fragments: Vec<_> = source.fragments().collect();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].as_ref().unwrap().metadata.size, 0);
    }
}
