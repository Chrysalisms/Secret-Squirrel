//! MCP server — Phase 2 implementation placeholder.
//! Will use the `rmcp` crate for stdio and HTTP+SSE transports.

/// Start the MCP server on stdio transport.
/// This is a placeholder — full implementation in Phase 2.
pub async fn run_stdio() -> crate::error::Result<()> {
    tracing::info!("MCP stdio server starting (Phase 2 placeholder)");
    // TODO Phase 2: implement full MCP server using rmcp crate
    // Server will expose: scan_text, scan_file, scan_diff, scan_repo, validate_finding, get_rules
    // Security: HTTP transport binds 127.0.0.1 only, requires bearer token
    Ok(())
}
