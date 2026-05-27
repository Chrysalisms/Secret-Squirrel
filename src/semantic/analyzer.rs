//! High-level semantic analyzer for Secret Squirrel.
//!
//! [`SemanticAnalyzer`] is the main entry point into the semantic module.
//! Given source bytes, a byte offset, and a file extension it returns a
//! [`CodeContext`] describing the syntactic role of the match site.
//!
//! # Internal routing
//!
//! ```text
//! analyze(source, offset, ext)
//!   ├─ (feature = "semantic") && ext supported?
//!   │    └─ languages::extract_context  (tree-sitter AST walk)
//!   └─ otherwise
//!        └─ languages::fallback_context (pure-regex heuristics)
//! ```
//!
//! Both paths produce the same [`CodeContext`] type so callers need not care
//! which path was taken.

use std::collections::HashMap;

use crate::semantic::context::CodeContext;
use crate::semantic::languages;

// ─────────────────────────────────────────────────────────────────────────────
// ParserEntry
// ─────────────────────────────────────────────────────────────────────────────

/// Internal metadata record stored per supported extension.
#[derive(Clone, Debug)]
struct ParserEntry {
    /// Human-readable language name (e.g. "Python", "TypeScript").
    language_name: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Context-aware semantic analyzer.
///
/// Create a single instance and reuse it across all findings in a scan
/// session — the underlying tree-sitter parsers are allocated once and
/// held in the internal registry.
///
/// # Example
///
/// ```rust,no_run
/// use secret_squirrel::semantic::SemanticAnalyzer;
///
/// let analyzer = SemanticAnalyzer::new();
/// let source = b"api_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
/// let ctx = analyzer.analyze(source, 11, "py");
/// println!("adjustment: {}", ctx.confidence_adjustment());
/// ```
pub struct SemanticAnalyzer {
    /// Extension → metadata map.
    ///
    /// The actual tree-sitter [`Language`](tree_sitter::Language) objects are
    /// looked up lazily via [`languages::language_for_ext`] at analysis time
    /// to avoid holding non-`Send` state here.
    parsers: HashMap<String, ParserEntry>,
}

impl SemanticAnalyzer {
    /// Create a new analyzer, registering all available language parsers.
    ///
    /// When compiled without the `semantic` feature the registry will be empty
    /// and every call to [`analyze`](Self::analyze) will use the regex fallback.
    pub fn new() -> Self {
        let mut parsers: HashMap<String, ParserEntry> = HashMap::new();

        // Populate from the static list of supported extensions.
        for &ext in languages::supported_extensions() {
            let language_name = language_name_for_ext(ext).to_owned();
            parsers.insert(
                ext.to_owned(),
                ParserEntry { language_name },
            );
        }

        Self { parsers }
    }

    /// Analyze the context of `byte_offset` inside `source`.
    ///
    /// `file_ext` should be the bare extension without a leading dot
    /// (e.g. `"py"`, `"rs"`, `"ts"`).
    ///
    /// Returns a [`CodeContext`] that can be used to apply a confidence delta
    /// via [`CodeContext::confidence_adjustment`].
    pub fn analyze(&self, source: &[u8], byte_offset: usize, file_ext: &str) -> CodeContext {
        // Normalise the extension.
        let ext = file_ext.trim_start_matches('.');

        #[cfg(feature = "semantic")]
        if self.parsers.contains_key(ext) {
            if let Some(lang) = languages::language_for_ext(ext) {
                return languages::extract_context(source, byte_offset, lang, ext);
            }
        }

        // Either the extension is not supported or the `semantic` feature is
        // disabled — fall back to the pure-regex path.
        languages::fallback_context(source, byte_offset)
    }

    /// Return a deduplicated, sorted list of all natively supported file
    /// extensions.
    ///
    /// Extensions from the regex-only fallback (which handles *all* files) are
    /// not included here — only those with a dedicated tree-sitter grammar.
    pub fn supported_extensions(&self) -> Vec<&str> {
        let mut exts: Vec<&str> = self.parsers.keys().map(String::as_str).collect();
        exts.sort_unstable();
        exts
    }

    /// Return `true` if the given extension has a native tree-sitter grammar.
    pub fn supports_extension(&self, ext: &str) -> bool {
        let ext = ext.trim_start_matches('.');
        self.parsers.contains_key(ext)
    }
}

impl Default for SemanticAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SemanticContext
// ─────────────────────────────────────────────────────────────────────────────

/// The full semantic context attached to a single finding.
///
/// Produced by [`SemanticAnalyzer::analyze`] and stored alongside the finding
/// so that downstream consumers (reporting, correlation) can inspect the code
/// context without re-parsing.
#[derive(Debug, Clone)]
pub struct SemanticContext {
    /// Bare file extension (no leading dot).
    pub file_ext: String,

    /// Byte offset of the finding within the source fragment.
    pub byte_offset: usize,

    /// The resolved code context at that offset.
    pub context: CodeContext,
}

impl SemanticContext {
    /// Convenience constructor.
    pub fn new(file_ext: impl Into<String>, byte_offset: usize, context: CodeContext) -> Self {
        Self {
            file_ext: file_ext.into(),
            byte_offset,
            context,
        }
    }

    /// Return the confidence adjustment from the embedded [`CodeContext`].
    #[inline]
    pub fn confidence_adjustment(&self) -> f32 {
        self.context.confidence_adjustment()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Map a file extension to a human-readable language name.
fn language_name_for_ext(ext: &str) -> &'static str {
    match ext {
        "js" | "mjs" | "cjs" => "JavaScript",
        "ts" | "mts" | "cts" => "TypeScript",
        "tsx" => "TypeScript TSX",
        "py" | "pyi" => "Python",
        "go" => "Go",
        "rs" => "Rust",
        "java" => "Java",
        "rb" | "rake" | "gemspec" => "Ruby",
        "c" | "h" => "C",
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "C++",
        "cs" => "C#",
        _ => "Unknown",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::context::ContextType;

    fn analyzer() -> SemanticAnalyzer {
        SemanticAnalyzer::new()
    }

    // ── Extension list ──────────────────────────────────────────────────────

    #[test]
    fn supported_extensions_non_empty_with_feature() {
        let a = analyzer();
        let exts = a.supported_extensions();
        // With `semantic` feature: non-empty; without: empty.
        #[cfg(feature = "semantic")]
        assert!(
            !exts.is_empty(),
            "semantic feature enabled — should have at least one extension"
        );
        // Without the feature the parsers map is empty; that's fine.
        let _ = exts;
    }

    #[test]
    fn extensions_are_sorted() {
        let a = analyzer();
        let exts = a.supported_extensions();
        let mut sorted = exts.clone();
        sorted.sort_unstable();
        assert_eq!(exts, sorted, "supported_extensions() must return sorted slice");
    }

    #[test]
    fn supports_extension_dot_prefix_stripped() {
        let a = analyzer();
        // With semantic feature, "py" should be supported.
        #[cfg(feature = "semantic")]
        {
            assert!(a.supports_extension("py"));
            assert!(a.supports_extension(".py"), "leading dot should be stripped");
        }
        #[cfg(not(feature = "semantic"))]
        {
            // Without the feature nothing is registered.
            assert!(!a.supports_extension("py"));
        }
    }

    // ── analyze: fallback path (always works) ───────────────────────────────

    #[test]
    fn analyze_comment_via_fallback() {
        let a = analyzer();
        // Use an unknown extension so the regex fallback is always used.
        let src = b"# api_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        // offset inside the token AKIA...
        let offset = src.iter().position(|&b| b == b'A').unwrap();
        let ctx = a.analyze(src, offset, "unknown_ext");
        assert_eq!(ctx.context_type, ContextType::Comment);
        assert!(
            (ctx.confidence_adjustment() - (-0.80)).abs() < f32::EPSILON
        );
    }

    #[test]
    fn analyze_test_function_via_fallback() {
        let a = analyzer();
        let src = b"def test_connect():\n    token = \"ghp_xxxxxxxxxxxxxxx\"\n";
        let offset = src.iter().position(|&b| b == b't').unwrap() + 20; // inside body
        let ctx = a.analyze(src, offset, "txt"); // unsupported ext → fallback
        assert_eq!(ctx.context_type, ContextType::Test);
        assert!(
            (ctx.confidence_adjustment() - (-0.50)).abs() < f32::EPSILON
        );
    }

    #[test]
    fn analyze_assignment_via_fallback() {
        let a = analyzer();
        let src = b"api_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let offset = src.iter().position(|&b| b == b'"').unwrap() + 1;
        let ctx = a.analyze(src, offset, "txt");
        assert_eq!(ctx.context_type, ContextType::Assignment);
        assert!(
            (ctx.confidence_adjustment() - 0.30).abs() < f32::EPSILON
        );
    }

    // ── SemanticContext wrapper ──────────────────────────────────────────────

    #[test]
    fn semantic_context_delegates_adjustment() {
        use crate::semantic::context::CodeContext;
        let ctx = CodeContext::comment(2);
        let sc = SemanticContext::new("py", 42, ctx);
        assert!(
            (sc.confidence_adjustment() - (-0.80)).abs() < f32::EPSILON
        );
    }

    // ── Tree-sitter path (only compiled and run with the feature) ───────────

    #[cfg(feature = "semantic")]
    mod ts_tests {
        use super::*;
        use crate::semantic::context::ContextType;

        #[test]
        fn python_comment_detected_by_ast() {
            let a = analyzer();
            let src = b"x = 1\n# secret = \"AKIAIOSFODNN7EXAMPLE\"\ny = 2\n";
            let offset = src.iter().position(|&b| b == b'A').unwrap();
            let ctx = a.analyze(src, offset, "py");
            assert_eq!(ctx.context_type, ContextType::Comment);
        }

        #[test]
        fn rust_line_comment_detected() {
            let a = analyzer();
            let src = b"fn main() {\n    // secret = \"hunter2\"\n    let x = 1;\n}\n";
            let offset = src.iter().position(|&b| b == b'h').unwrap();
            let ctx = a.analyze(src, offset, "rs");
            assert_eq!(ctx.context_type, ContextType::Comment);
        }

        #[test]
        fn go_test_function_detected() {
            let a = analyzer();
            let src =
                b"func TestLogin(t *testing.T) {\n    token := \"ghp_xxxxxxxxxxxxx\"\n}\n";
            let offset = src.iter().position(|&b| b == b'g').unwrap();
            let ctx = a.analyze(src, offset, "go");
            assert_eq!(ctx.context_type, ContextType::Test);
        }
    }
}
