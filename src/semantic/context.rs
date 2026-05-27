//! Context types for semantic code analysis.
//!
//! A [`CodeContext`] captures the syntactic role of a particular byte offset
//! inside a source file.  It is produced by [`crate::semantic::analyzer::SemanticAnalyzer`]
//! and consumed by the scoring engine to apply a confidence delta to findings
//! that appear in low-risk positions (comments, tests) or high-risk positions
//! (direct assignments, dict values).

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// ContextType
// ─────────────────────────────────────────────────────────────────────────────

/// The syntactic role of a byte offset within a source file.
///
/// Produced by tree-sitter AST traversal (or the regex fallback) and used to
/// modulate the confidence score of a potential secret finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextType {
    /// Inside a comment (`//`, `/* … */`, `#`, `--`).
    ///
    /// Most false positives originate here — example credentials in
    /// documentation, API samples in comments, etc.
    Comment,

    /// Inside a test function or test module.
    ///
    /// Test code routinely uses fabricated or well-known fixture credentials
    /// that must not be reported as real findings.
    Test,

    /// Right-hand side of an assignment expression (`x = "secret"`).
    ///
    /// A strong signal — real code rarely assigns a high-entropy literal to a
    /// variable unless it is a genuine credential.
    Assignment,

    /// A function call argument (`connect(password="secret")`).
    ///
    /// Indicates the value is being consumed by a function, which slightly
    /// raises the probability that it is real.
    Argument,

    /// A value inside a dictionary or map literal (`{"api_key": "secret"}`).
    ///
    /// Common in configuration-as-code; treated as a moderate positive signal.
    DictValue,

    /// A return value (`return "secret"`).
    ///
    /// Functions that return high-entropy strings are suspicious.
    ReturnValue,

    /// A string literal whose surrounding context could not be determined.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeContext
// ─────────────────────────────────────────────────────────────────────────────

/// Full semantic context for a single byte offset inside source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeContext {
    /// The syntactic role of the match site.
    pub context_type: ContextType,

    /// Name of the enclosing function, if one could be determined.
    pub function_name: Option<String>,

    /// Whether the enclosing declaration is exported / public.
    pub is_exported: bool,

    /// Nesting depth in the AST (0 = top-level).
    pub depth: usize,
}

impl CodeContext {
    /// Return a confidence delta (–1.0 … +1.0) for this context.
    ///
    /// The adjustment is **additive** — it is applied on top of the base
    /// confidence score produced by the 4-stage pipeline:
    ///
    /// | Context       | Delta  | Rationale                                      |
    /// |---------------|--------|------------------------------------------------|
    /// | `Comment`     | −0.80  | Almost always documentation / example code     |
    /// | `Test`        | −0.50  | Fixture credentials; never deployed            |
    /// | `Assignment`  | +0.30  | Direct literal assignment is a strong signal   |
    /// | `DictValue`   | +0.20  | Config-as-code patterns                        |
    /// | `Argument`    | +0.10  | Credential being passed to a consumer          |
    /// | `ReturnValue` | +0.05  | Mild positive signal                           |
    /// | `Unknown`     |  0.00  | No information — leave score unchanged         |
    pub fn confidence_adjustment(&self) -> f32 {
        match self.context_type {
            ContextType::Comment => -0.80,
            ContextType::Test => -0.50,
            ContextType::Assignment => 0.30,
            ContextType::DictValue => 0.20,
            ContextType::Argument => 0.10,
            ContextType::ReturnValue => 0.05,
            ContextType::Unknown => 0.00,
        }
    }

    /// Construct a simple unknown context (used as a safe default).
    pub fn unknown() -> Self {
        Self {
            context_type: ContextType::Unknown,
            function_name: None,
            is_exported: false,
            depth: 0,
        }
    }

    /// Construct a comment context.
    pub fn comment(depth: usize) -> Self {
        Self {
            context_type: ContextType::Comment,
            function_name: None,
            is_exported: false,
            depth,
        }
    }

    /// Construct a test context.
    pub fn test(function_name: Option<String>, depth: usize) -> Self {
        Self {
            context_type: ContextType::Test,
            function_name,
            is_exported: false,
            depth,
        }
    }

    /// Construct an assignment context.
    pub fn assignment(function_name: Option<String>, is_exported: bool, depth: usize) -> Self {
        Self {
            context_type: ContextType::Assignment,
            function_name,
            is_exported,
            depth,
        }
    }
}

impl Default for CodeContext {
    fn default() -> Self {
        Self::unknown()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_adjustment_is_minus_0_80() {
        let ctx = CodeContext::comment(1);
        assert!(
            (ctx.confidence_adjustment() - (-0.80)).abs() < f32::EPSILON,
            "expected -0.80, got {}",
            ctx.confidence_adjustment()
        );
    }

    #[test]
    fn test_adjustment_is_minus_0_50() {
        let ctx = CodeContext::test(Some("test_auth".into()), 2);
        assert!(
            (ctx.confidence_adjustment() - (-0.50)).abs() < f32::EPSILON,
            "expected -0.50, got {}",
            ctx.confidence_adjustment()
        );
    }

    #[test]
    fn assignment_adjustment_is_plus_0_30() {
        let ctx = CodeContext::assignment(Some("configure".into()), false, 1);
        assert!(
            (ctx.confidence_adjustment() - 0.30).abs() < f32::EPSILON,
            "expected +0.30, got {}",
            ctx.confidence_adjustment()
        );
    }

    #[test]
    fn unknown_adjustment_is_zero() {
        let ctx = CodeContext::unknown();
        assert_eq!(ctx.confidence_adjustment(), 0.00);
    }

    #[test]
    fn dict_value_adjustment_is_plus_0_20() {
        let ctx = CodeContext {
            context_type: ContextType::DictValue,
            function_name: None,
            is_exported: false,
            depth: 1,
        };
        assert!(
            (ctx.confidence_adjustment() - 0.20).abs() < f32::EPSILON,
            "expected +0.20, got {}",
            ctx.confidence_adjustment()
        );
    }

    #[test]
    fn default_context_is_unknown() {
        let ctx = CodeContext::default();
        assert_eq!(ctx.context_type, ContextType::Unknown);
        assert_eq!(ctx.confidence_adjustment(), 0.00);
    }

    #[test]
    fn serialization_round_trip() {
        let ctx = CodeContext::comment(3);
        let json = serde_json::to_string(&ctx).expect("serialize");
        let back: CodeContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.context_type, ContextType::Comment);
        assert_eq!(back.depth, 3);
    }
}
