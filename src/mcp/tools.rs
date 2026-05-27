//! MCP tool definitions — Phase 2 implementation placeholder.
//!
//! Security invariant: validate_finding accepts ONLY finding IDs, never raw secret strings.
//! Accepting raw strings would create a credential oracle vulnerability.

use crate::types::Finding;

/// Summary of available rules for the get_rules MCP tool.
#[derive(serde::Serialize)]
pub struct RuleSummary {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub category: String,
}

/// Result from a scan tool invocation.
#[derive(serde::Serialize)]
pub struct ScanToolResult {
    pub findings: Vec<Finding>,
    pub metadata: ScanMetadata,
}

/// Metadata included with scan results.
#[derive(serde::Serialize)]
pub struct ScanMetadata {
    pub duration_ms: u64,
    pub items_scanned: u64,
    pub gpu_used: bool,
}

/// Result from validate_finding tool invocation.
/// Input: finding_id: String (never raw secret strings)
#[derive(serde::Serialize)]
pub struct ValidationToolResult {
    pub finding_id: String,
    pub status: String,
    pub provider: String,
    pub blast_radius: Option<String>,
}
