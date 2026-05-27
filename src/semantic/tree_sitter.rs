//! Tree-sitter AST analysis — Phase 2 implementation placeholder.
//!
//! Provides confidence adjustment based on where in the AST a finding appears.

/// Adjustment result from AST analysis.
pub struct AstAdjustment {
    /// The confidence delta to apply (-1.0 to +1.0)
    pub delta: f64,
    /// Human-readable reason for the adjustment
    pub reason: &'static str,
}

/// Analyze the AST context of a finding and return a confidence adjustment.
/// This is a placeholder — full tree-sitter integration in Phase 2.
pub fn analyze_context(
    _content: &[u8],
    _language: &str,
    _byte_offset: u64,
) -> Option<AstAdjustment> {
    // TODO Phase 2: integrate tree-sitter parsers for 10 languages
    // Apply adjustments:
    //   comment node: -0.80
    //   test scope:   -0.50
    //   assignment:   +0.30
    //   function arg: +0.20
    None
}
