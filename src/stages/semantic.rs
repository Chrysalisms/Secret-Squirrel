//! Semantic AST analysis using Tree-sitter.
//!
//! This stage provides context awareness by parsing files into an Abstract Syntax Tree (AST)
//! and classifying regions of the file (e.g., classifying whether a secret candidate falls
//! inside a string literal, a comment, or executable code).

#[cfg(feature = "semantic")]
use tree_sitter::{Node, Parser};

/// The semantic classification of a specific byte offset in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticContext {
    /// The offset falls within a string literal.
    StringLiteral,
    /// The offset falls within a comment.
    Comment,
    /// The offset falls within executable code / generic AST node.
    Code,
    /// The AST parsing failed or the context is unknown.
    Unknown,
}

/// Computes the semantic context of an offset within the AST.
#[cfg(feature = "semantic")]
pub struct SemanticAnalyzer {
    // We can cache parser instances if needed, but for now we create per request.
}

#[cfg(feature = "semantic")]
impl SemanticAnalyzer {
    /// Create a new SemanticAnalyzer.
    pub fn new() -> Self {
        Self {}
    }

    /// Try to determine the semantic context of a specific byte offset.
    pub fn analyze_offset(&self, content: &[u8], file_ext: &str, offset: usize) -> SemanticContext {
        let language = match file_ext {
            #[cfg(feature = "tree-sitter-json")]
            "json" => tree_sitter_json::LANGUAGE.into(),
            #[cfg(feature = "tree-sitter-javascript")]
            "js" | "jsx" => tree_sitter_javascript::LANGUAGE.into(),
            #[cfg(feature = "tree-sitter-typescript")]
            "ts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            #[cfg(feature = "tree-sitter-typescript")]
            "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
            #[cfg(feature = "tree-sitter-python")]
            "py" => tree_sitter_python::LANGUAGE.into(),
            #[cfg(feature = "tree-sitter-go")]
            "go" => tree_sitter_go::LANGUAGE.into(),
            #[cfg(feature = "tree-sitter-rust")]
            "rs" => tree_sitter_rust::LANGUAGE.into(),
            _ => return SemanticContext::Unknown,
        };

        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            return SemanticContext::Unknown;
        }

        if let Some(tree) = parser.parse(content, None) {
            let root_node = tree.root_node();
            if let Some(node) = root_node.descendant_for_byte_range(offset, offset + 1) {
                return Self::classify_node(node);
            }
        }

        SemanticContext::Unknown
    }

    /// Classify a tree-sitter node based on its kind.
    fn classify_node(node: Node) -> SemanticContext {
        let kind = node.kind();
        
        // This is a simplistic classification. A production-grade one would use tree-sitter queries.
        if kind.contains("string") || kind.contains("template") || kind.contains("char") {
            return SemanticContext::StringLiteral;
        }

        if kind.contains("comment") {
            return SemanticContext::Comment;
        }

        SemanticContext::Code
    }
}

#[cfg(not(feature = "semantic"))]
pub struct SemanticAnalyzer {}

#[cfg(not(feature = "semantic"))]
impl SemanticAnalyzer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze_offset(&self, _content: &[u8], _file_ext: &str, _offset: usize) -> SemanticContext {
        SemanticContext::Unknown
    }
}

#[cfg(test)]
#[cfg(feature = "semantic")]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "tree-sitter-json")]
    fn test_analyze_json_string() {
        let analyzer = SemanticAnalyzer::new();
        let content = b"{\"key\": \"secret_value_here\"}";
        
        // Offset 10 is inside "secret_value_here"
        let ctx = analyzer.analyze_offset(content, "json", 10);
        assert_eq!(ctx, SemanticContext::StringLiteral);
    }
}
