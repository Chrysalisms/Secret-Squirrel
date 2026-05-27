//! Semantic analysis module for Secret Squirrel.
//!
//! This module uses tree-sitter to parse source code and determine the
//! surrounding code context of a potential secret match.  That context
//! is then expressed as a [`CodeContext`] which carries a
//! [`confidence_adjustment`](context::CodeContext::confidence_adjustment)
//! factor used by the scoring engine to suppress false positives
//! (e.g. secrets inside comments or test functions) and boost true
//! positives (e.g. secrets on the right-hand side of assignments).
//!
//! # Feature gate
//!
//! The entire module is compiled only when the `semantic` Cargo feature
//! is enabled.  A pure regex-based fallback is always available via
//! [`languages::fallback_context`] for environments where tree-sitter
//! grammar C libraries cannot be compiled.

pub mod analyzer;
pub mod context;
pub mod languages;

pub use analyzer::{SemanticAnalyzer, SemanticContext};
pub use context::{CodeContext, ContextType};
