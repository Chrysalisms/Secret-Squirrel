//! Semantic analysis stub — full implementation in Phase 2.
//!
//! When enabled via `--semantic`, this module integrates tree-sitter parsers
//! to adjust finding confidence scores based on AST context:
//!
//! - Comment node: -80% confidence (likely documentation example)
//! - Test file scope: -50% confidence (test credentials)
//! - String assignment: +30% confidence (direct credential exposure)
//! - Function call argument: +20% confidence (credential being used)
//!
//! Supports 10 languages: JS, TS, Python, Go, Rust, Java, Ruby, C, C++, C#

pub mod tree_sitter;
