//! Language-specific tree-sitter parsers and AST context extractors.
//!
//! # Tree-sitter feature gate
//!
//! When the `semantic` Cargo feature is enabled, each supported language
//! gets a full tree-sitter parser that walks the concrete syntax tree to
//! determine the exact [`ContextType`] at a given byte offset.
//!
//! # Pure-regex fallback
//!
//! [`fallback_context`] is **always** compiled (no feature gate) and provides
//! a best-effort context classification using simple byte-pattern heuristics.
//! It is used automatically by [`crate::semantic::analyzer::SemanticAnalyzer`]
//! when no tree-sitter grammar is available for a given file extension.

use crate::semantic::context::{CodeContext, ContextType};

// ─────────────────────────────────────────────────────────────────────────────
// Tree-sitter helpers (compiled only with the `semantic` feature)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the tree-sitter [`Language`](tree_sitter::Language) for a given file
/// extension, or `None` if the extension is not supported.
#[cfg(feature = "semantic")]
pub fn language_for_ext(ext: &str) -> Option<tree_sitter::Language> {
    match ext {
        "js" | "mjs" | "cjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" | "mts" | "cts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "py" | "pyi" => Some(tree_sitter_python::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "rb" | "rake" | "gemspec" => Some(tree_sitter_ruby::LANGUAGE.into()),
        "c" | "h" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "cs" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Comment node names per language
// ─────────────────────────────────────────────────────────────────────────────

/// Return true if the given tree-sitter node *kind* represents a comment in
/// any of the supported languages.
#[cfg(feature = "semantic")]
fn is_comment_kind(kind: &str) -> bool {
    matches!(
        kind,
        "comment"          // Python, Go, JS, TS, Java, Ruby, C, C++, C#
        | "line_comment"   // Rust
        | "block_comment"  // Rust
        | "template_string" // JS template literals (low-risk context)
    ) || kind.contains("comment")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-scope detection helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if the function name looks like a test function.
///
/// Matches:
/// - Python: `test_*`
/// - Go: `Test*`
/// - JS/TS: commonly inside `describe`/`it`/`test` — handled by node kind
/// - Rust: any function inside `#[test]` or `#[cfg(test)]` — handled by attr check
/// - Generic: contains `_test`, `Test`, `spec`, `Spec`
fn is_test_function_name(name: &str) -> bool {
    name.starts_with("test_")   // Python, shell
        || name.starts_with("Test") // Go
        || name.ends_with("_test") // Go (file-level), some Rust conventions
        || name.contains("spec")
        || name.contains("Spec")
        || name.contains("_test_")
}

/// Returns `true` if the tree-sitter node kind is a test-scope container in
/// JS/TS (e.g. `describe`, `it`, `test`).
#[cfg(feature = "semantic")]
fn is_js_test_call(node: &tree_sitter::Node, source: &[u8]) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let func = node.child_by_field_name("function");
    if let Some(func_node) = func {
        if let Ok(name) = func_node.utf8_text(source) {
            return matches!(name, "describe" | "it" | "test" | "beforeEach" | "afterEach");
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Core tree-sitter context extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Extract a [`CodeContext`] at `byte_offset` inside `source` using a
/// tree-sitter parse tree for `language`.
///
/// The function walks from the innermost node at the offset up toward the
/// root, checking for comment nodes, test scopes, and assignment patterns.
///
/// # Errors
///
/// Returns a default [`CodeContext::unknown()`] if the source cannot be
/// parsed (e.g. binary content, incomplete UTF-8).
#[cfg(feature = "semantic")]
pub fn extract_context(
    source: &[u8],
    byte_offset: usize,
    language: tree_sitter::Language,
    file_ext: &str,
) -> CodeContext {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&language).is_err() {
        return fallback_context(source, byte_offset);
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return fallback_context(source, byte_offset),
    };

    let root = tree.root_node();

    // Find the deepest node that contains the byte offset.
    let target = root.descendant_for_byte_range(byte_offset, byte_offset + 1);

    let target = match target {
        Some(n) => n,
        None => return fallback_context(source, byte_offset),
    };

    let depth = target.start_position().row; // coarse depth proxy
    let mut current = target;
    let mut function_name: Option<String> = None;
    let mut in_test = false;
    let mut context_type = ContextType::Unknown;

    // Walk up the ancestor chain.
    loop {
        let kind = current.kind();

        // ── Comment check ──────────────────────────────────────────────────
        if is_comment_kind(kind) {
            return CodeContext::comment(depth);
        }

        // ── Language-specific test attribute check (Rust) ──────────────────
        // In Rust, `#[test]` appears as an `attribute_item` or `attribute`
        // sibling of a `function_item`.
        if kind == "function_item" && matches!(file_ext, "rs") {
            let name = current
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("")
                .to_owned();
            // Check siblings for #[test] or enclosing mod with #[cfg(test)]
            if has_test_attribute(&current, source) {
                in_test = true;
                function_name = Some(name);
            } else if function_name.is_none() {
                function_name = Some(name);
            }
        }

        // ── Python / Go: function name check ──────────────────────────────
        if matches!(kind, "function_definition" | "method_definition" | "function_declaration") {
            if let Some(name_node) = current.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source) {
                    if is_test_function_name(name) {
                        in_test = true;
                    }
                    if function_name.is_none() {
                        function_name = Some(name.to_owned());
                    }
                }
            }
        }

        // ── JS/TS test call (describe / it / test) ─────────────────────────
        if is_js_test_call(&current, source) {
            in_test = true;
        }

        // ── Assignment detection ───────────────────────────────────────────
        if context_type == ContextType::Unknown
            && matches!(
                kind,
                "assignment_expression"
                    | "assignment"
                    | "variable_declarator"
                    | "short_var_declaration" // Go :=
                    | "let_declaration"       // Rust
                    | "const_item"            // Rust const
                    | "static_item"           // Rust static
            )
        {
            // Only flag as assignment if target sits in the value child.
            if is_in_value_position(&current, target, source) {
                context_type = ContextType::Assignment;
            }
        }

        // ── Dict / map value detection ─────────────────────────────────────
        if context_type == ContextType::Unknown
            && matches!(
                kind,
                "pair"          // Python dict, JSON
                    | "key_value_pair" // Ruby, Go map literal
                    | "shorthand_property_identifier_pattern"
            )
        {
            context_type = ContextType::DictValue;
        }

        // ── Argument detection ─────────────────────────────────────────────
        if context_type == ContextType::Unknown
            && matches!(kind, "argument_list" | "arguments" | "actual_parameters")
        {
            context_type = ContextType::Argument;
        }

        // ── Return value detection ─────────────────────────────────────────
        if context_type == ContextType::Unknown
            && matches!(kind, "return_expression" | "return_statement")
        {
            context_type = ContextType::ReturnValue;
        }

        // ── Ascend ────────────────────────────────────────────────────────
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    // Test context overrides everything except comments (already returned).
    if in_test {
        return CodeContext::test(function_name, depth);
    }

    CodeContext {
        context_type,
        function_name,
        is_exported: false, // TODO: language-specific export detection
        depth,
    }
}

/// Check whether a `function_item` node (Rust) has a `#[test]` or
/// `#[cfg(test)]` attribute in its sibling or parent `mod` attributes.
#[cfg(feature = "semantic")]
fn has_test_attribute(node: &tree_sitter::Node, source: &[u8]) -> bool {
    // Check preceding siblings for attribute items.
    let parent = match node.parent() {
        Some(p) => p,
        None => return false,
    };
    let mut cursor = parent.walk();
    for child in parent.children(&mut cursor) {
        if child.kind() == "attribute_item" {
            if let Ok(text) = child.utf8_text(source) {
                if text.contains("test") {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns `true` if `target` is the *value* (right-hand side) of the
/// `assignment` node — not the variable being assigned to.
#[cfg(feature = "semantic")]
fn is_in_value_position(
    assignment: &tree_sitter::Node,
    target: tree_sitter::Node,
    source: &[u8],
) -> bool {
    // Try the "value" or "right" field names used by most grammars.
    let value_node = assignment
        .child_by_field_name("value")
        .or_else(|| assignment.child_by_field_name("right"));

    if let Some(value) = value_node {
        // target is in the value subtree if its byte range overlaps.
        return value.start_byte() <= target.start_byte()
            && target.end_byte() <= value.end_byte();
    }

    // Fallback: assume RHS if target's text starts after '=' in source.
    let _ = source; // suppress unused warning
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure-regex fallback (always compiled)
// ─────────────────────────────────────────────────────────────────────────────

/// Best-effort context classification using byte-pattern heuristics.
///
/// Used when tree-sitter is not available (feature not enabled) or when no
/// grammar exists for the file extension.
///
/// # Algorithm
///
/// 1. Extract the line that contains `byte_offset`.
/// 2. Check if the line starts with a comment marker (`#`, `//`, `/*`, `--`, `*`).
/// 3. Scan backward from the offset for an enclosing test function.
/// 4. Check if there is an `=` or `:` before the value on the same line.
pub fn fallback_context(source: &[u8], byte_offset: usize) -> CodeContext {
    let offset = byte_offset.min(source.len());
    let before = &source[..offset];

    // ── Find the current line ──────────────────────────────────────────────
    let line_start = before.iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
    let line_end = source[offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(source.len(), |p| offset + p);
    let line = &source[line_start..line_end];
    let trimmed = line.iter().copied().skip_while(|b| b.is_ascii_whitespace());
    let line_prefix: Vec<u8> = trimmed.collect();

    // ── Comment detection ──────────────────────────────────────────────────
    let is_comment = line_prefix.starts_with(b"#")
        || line_prefix.starts_with(b"//")
        || line_prefix.starts_with(b"/*")
        || line_prefix.starts_with(b"*")   // inside /* … */ block
        || line_prefix.starts_with(b"--")  // SQL / Lua
        || line_prefix.starts_with(b"'")   // VB / shell comments
        || line_prefix.starts_with(b"REM"); // batch

    if is_comment {
        return CodeContext::comment(0);
    }

    // ── Test function detection (scan backward up to 4 KB) ─────────────────
    let scan_start = offset.saturating_sub(4096);
    let window = &source[scan_start..offset];
    if let Ok(text) = std::str::from_utf8(window) {
        // Look for function/def/func keywords followed by a test name.
        static TEST_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re = TEST_RE.get_or_init(|| {
            // Matches Python `def test_foo`, Go `func TestFoo`, JS `function testFoo`,
            // or any `it(`, `describe(`, `test(` call.
            regex::Regex::new(
                r"(?x)
                (?:def|func|function|fn)\s+
                (?P<name>[Tt]est\w*|test_\w+|\w+_[Tt]est\w*|spec\w*|Spec\w*)
                |
                (?:it|describe|test)\s*\(
                |
                \#\[(?:test|cfg\(test)
                ",
            )
            .expect("static regex is valid")
        });
        if re.is_match(text) {
            // Extract the function name if we can.
            let fn_name = re
                .captures_iter(text)
                .last()
                .and_then(|c| c.name("name"))
                .map(|m| m.as_str().to_owned());
            return CodeContext::test(fn_name, 0);
        }
    }

    // ── Assignment detection ───────────────────────────────────────────────
    // Look for `=` or `:` before the offset on the same line (excluding `==`).
    let line_before_offset = &source[line_start..offset];
    if let Ok(text) = std::str::from_utf8(line_before_offset) {
        let has_assignment = text.contains('=') && !text.trim_end().ends_with("==");
        let has_colon = text.contains(':') && !text.contains("::");
        if has_assignment || has_colon {
            return CodeContext::assignment(None, false, 0);
        }
    }

    CodeContext::unknown()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public extension list helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return the list of file extensions supported by the tree-sitter path.
///
/// When compiled without the `semantic` feature only the regex fallback is
/// available, so this returns an empty slice.
#[cfg(feature = "semantic")]
pub fn supported_extensions() -> &'static [&'static str] {
    &[
        "js", "mjs", "cjs",
        "ts", "mts", "cts", "tsx",
        "py", "pyi",
        "go",
        "rs",
        "java",
        "rb", "rake", "gemspec",
        "c", "h",
        "cpp", "cc", "cxx", "hpp", "hxx",
        "cs",
    ]
}

/// Fallback (no `semantic` feature): no extensions are natively parsed.
#[cfg(not(feature = "semantic"))]
pub fn supported_extensions() -> &'static [&'static str] {
    &[]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fallback: comment detection ─────────────────────────────────────────

    #[test]
    fn fallback_python_comment() {
        // `# AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"`
        let src = b"x = 1\n# AWS_SECRET = \"AKIAIOSFODNN7EXAMPLE\"\ny = 2\n";
        // offset inside the comment line
        let offset = src.iter().position(|&b| b == b'A').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(
            ctx.context_type,
            ContextType::Comment,
            "Python # comment should be detected"
        );
        assert!(
            (ctx.confidence_adjustment() - (-0.80)).abs() < f32::EPSILON,
            "Comment adjustment must be -0.80"
        );
    }

    #[test]
    fn fallback_cpp_line_comment() {
        let src = b"int x = 0;\n// secret = \"hunter2\"\nint y = 1;\n";
        let offset = src.iter().position(|&b| b == b's').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Comment);
    }

    #[test]
    fn fallback_sql_comment() {
        let src = b"SELECT 1;\n-- password = 'secret'\nSELECT 2;\n";
        let offset = src.iter().position(|&b| b == b'p').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Comment);
    }

    // ── Fallback: test function detection ───────────────────────────────────

    #[test]
    fn fallback_python_test_function() {
        let src = b"def test_login():\n    password = \"hunter2\"\n";
        // offset at the 'p' in password
        let offset = src.iter().position(|&b| b == b'p').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(
            ctx.context_type,
            ContextType::Test,
            "Function named test_login should be Test context"
        );
        assert!(
            (ctx.confidence_adjustment() - (-0.50)).abs() < f32::EPSILON,
            "Test adjustment must be -0.50"
        );
    }

    #[test]
    fn fallback_go_test_function() {
        let src = b"func TestConnectDB(t *testing.T) {\n    secret := \"dbpass123\"\n}\n";
        let offset = src.iter().position(|&b| b == b'd').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Test);
    }

    #[test]
    fn fallback_js_describe_block() {
        let src = b"describe('auth', () => {\n  const key = \"secret\";\n});\n";
        // offset at 'k' in key
        let offset = 27;
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Test);
    }

    #[test]
    fn fallback_rust_test_attr() {
        let src = b"#[test]\nfn should_authenticate() {\n    let key = \"abc123\";\n}\n";
        let offset = src.iter().position(|&b| b == b'k').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Test);
    }

    // ── Fallback: assignment detection ──────────────────────────────────────

    #[test]
    fn fallback_assignment_equals() {
        let src = b"api_key = \"AKIAIOSFODNN7EXAMPLE\"\n";
        let offset = src.iter().position(|&b| b == b'"').unwrap() + 1;
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Assignment);
        assert!(
            (ctx.confidence_adjustment() - 0.30).abs() < f32::EPSILON,
            "Assignment adjustment must be +0.30"
        );
    }

    #[test]
    fn fallback_yaml_colon() {
        let src = b"api_key: AKIAIOSFODNN7EXAMPLE\n";
        let offset = src.iter().position(|&b| b == b'A').unwrap();
        let ctx = fallback_context(src, offset);
        assert_eq!(ctx.context_type, ContextType::Assignment);
    }

    // ── Extension list ──────────────────────────────────────────────────────

    #[test]
    fn supported_extensions_is_correct_per_feature() {
        let exts = supported_extensions();
        // With the `semantic` feature enabled this should be non-empty;
        // without it, it should be empty.  We test whichever branch compiled.
        #[cfg(feature = "semantic")]
        assert!(!exts.is_empty(), "semantic feature: should have extensions");
        #[cfg(not(feature = "semantic"))]
        assert!(exts.is_empty(), "no semantic feature: should have no extensions");
    }
}
