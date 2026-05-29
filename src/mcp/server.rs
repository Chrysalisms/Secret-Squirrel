//! MCP server for Secret Squirrel.
//!
//! Exposes scanning as MCP tools consumable by any MCP-compatible AI assistant.
//! Enabled via `--features mcp-server`.
//!
//! # Protocol
//!
//! The server implements JSON-RPC 2.0 over stdio, as specified by the
//! [Model Context Protocol](https://spec.modelcontextprotocol.io/) v2024-11-05.
//! The [`rmcp`] crate handles protocol framing; this file provides the
//! [`ServerHandler`] implementation and tool dispatch logic.
//!
//! # Tools
//! - `scan_text`        — scan inline text for secrets
//! - `scan_file`        — scan a single file (path-sandboxed)
//! - `scan_diff`        — scan a git unified diff (added lines only)
//! - `get_rules`        — list all loaded detection rules
//! - `validate_finding` — validate a finding by opaque ID
//!
//! # Usage
//!
//! ```no_run
//! # #[cfg(feature = "mcp-server")]
//! # tokio_test::block_on(async {
//! secret_squirrel::mcp::McpServer::run_stdio().await.unwrap();
//! # });
//! ```

// When the mcp-server feature is disabled we still expose run_stdio and
// run_http so that main.rs can call them unconditionally inside
// #[cfg(feature = "mcp-server")] blocks.
#[cfg(not(feature = "mcp-server"))]
pub async fn run_stdio() -> crate::error::Result<()> {
    tracing::warn!(
        "MCP server not compiled in. Rebuild with --features mcp-server to enable."
    );
    Ok(())
}

#[cfg(not(feature = "mcp-server"))]
pub async fn run_http(_port: u16) -> crate::error::Result<()> {
    tracing::warn!(
        "MCP HTTP server not compiled in. Rebuild with --features mcp-server to enable."
    );
    Ok(())
}

#[cfg(feature = "mcp-server")]
pub use self::mcp_impl::run_stdio;

#[cfg(feature = "mcp-server")]
pub use self::mcp_impl::run_http;

/// Public façade for the MCP server.
///
/// This struct is the primary entry point re-exported as
/// `secret_squirrel::mcp::McpServer`. It wraps the internal
/// `SquirrelMcpServer` (built on [`rmcp`]) and provides a clean public API.
///
/// Requires the `mcp-server` feature flag.
#[cfg(feature = "mcp-server")]
pub struct McpServer;

#[cfg(feature = "mcp-server")]
impl McpServer {
    /// Run the MCP server on stdio (blocking until the client disconnects).
    ///
    /// This is the main entry point. Call it from `main()` when the binary
    /// is started in MCP mode (e.g., `squirrel mcp`).
    pub async fn run_stdio() -> crate::error::Result<()> {
        mcp_impl::run_stdio().await
    }
}

#[cfg(feature = "mcp-server")]
mod mcp_impl {
    use bytes::Bytes;
    use rmcp::{
        ServerHandler, ServiceExt,
        model::{
            CallToolRequestParams, CallToolResult, Content, Implementation, InitializeResult,
            ListToolsResult, PaginatedRequestParams, ServerCapabilities, Tool,
        },
        service::RequestContext,
        transport::stdio,
        ErrorData as McpError, RoleServer,
    };
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tracing::{info, warn};
    // axum types used by run_http, health_handler, and mcp_handler
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };

    use crate::config::SquirrelConfig;
    use crate::engine::{pipeline::Pipeline, router::Router as SquirrelRouter};
    use crate::rules::RuleRegistry;
    use crate::types::Fragment;

    /// Helper: convert a serde_json Object to the rmcp `JsonObject` (which is
    /// `serde_json::Map<String, Value>` — the same underlying type).
    fn json_to_schema(schema: Value) -> Arc<serde_json::Map<String, Value>> {
        Arc::new(schema.as_object().cloned().unwrap_or_default())
    }

    // =========================================================================
    // Security: path sandboxing
    // =========================================================================

    fn sandbox_path(path_str: &str) -> Result<PathBuf, String> {
        let p = Path::new(path_str);
        if p.is_absolute() {
            return Err(format!("Absolute paths are not allowed: {path_str}"));
        }
        for component in p.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(format!("Path traversal (..) is not allowed: {path_str}"));
            }
        }
        let pb = PathBuf::from(path_str);
        if pb.exists()
            && pb
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            return Err(format!("Symlinks are not allowed: {path_str}"));
        }
        Ok(pb)
    }

    // =========================================================================
    // Server handler
    // =========================================================================

    pub struct SquirrelMcpServer {
        pipeline: Pipeline,
        registry: RuleRegistry,
    }

    impl SquirrelMcpServer {
        pub async fn new(config: &SquirrelConfig) -> crate::error::Result<Self> {
            let router = SquirrelRouter::new(&config.gpu).await;
            let pipeline = Pipeline::new(router, config.pipeline.clone());
            let registry = RuleRegistry::load_defaults()?;
            Ok(Self { pipeline, registry })
        }

        fn scan_to_json(&self, fragment: &Fragment) -> Value {
            match self.pipeline.process_fragment(fragment) {
                Ok(matches) => {
                    let items: Vec<Value> = matches
                        .iter()
                        .map(|m| {
                            serde_json::json!({
                                "rule_id": m.rule_id,
                                "match_start": m.match_start,
                                "match_end": m.match_end,
                                "pattern_score": m.pattern_score,
                                "path": fragment.metadata.path,
                                "source": fragment.metadata.source_type,
                            })
                        })
                        .collect();
                    serde_json::json!({ "findings": items, "count": items.len() })
                }
                Err(e) => serde_json::json!({
                    "error": e.to_string(),
                    "findings": [],
                    "count": 0
                }),
            }
        }

        // ── Tool handlers ─────────────────────────────────────────────────────

        fn handle_scan_text(&self, args: Option<Value>) -> CallToolResult {
            let text = args
                .and_then(|v| v.get("text").and_then(|t| t.as_str()).map(str::to_string))
                .unwrap_or_default();
            const MAX: usize = 1 * 1024 * 1024;
            let text = if text.len() > MAX {
                warn!("scan_text: truncating to 1MB");
                &text[..MAX]
            } else {
                &text
            };
            let fragment = Fragment::from_text(text, "<mcp:scan_text>");
            let result = self.scan_to_json(&fragment);
            CallToolResult::success(vec![Content::text(result.to_string())])
        }

        fn handle_scan_file(&self, args: Option<Value>) -> CallToolResult {
            let path_str = match args.and_then(|v| {
                v.get("path")
                    .and_then(|p| p.as_str())
                    .map(str::to_string)
            }) {
                Some(p) => p,
                None => {
                    return CallToolResult::error(vec![Content::text("Missing 'path' argument")])
                }
            };
            let path = match sandbox_path(&path_str) {
                Ok(p) => p,
                Err(e) => {
                    return CallToolResult::error(vec![Content::text(format!(
                        "Path rejected: {e}"
                    ))])
                }
            };
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let fragment = Fragment::from_bytes(
                        Bytes::from(bytes),
                        path.to_string_lossy().to_string(),
                    );
                    let result = self.scan_to_json(&fragment);
                    CallToolResult::success(vec![Content::text(result.to_string())])
                }
                Err(e) => CallToolResult::error(vec![Content::text(format!(
                    "Cannot read '{}': {e}",
                    path.display()
                ))]),
            }
        }

        fn handle_scan_diff(&self, args: Option<Value>) -> CallToolResult {
            let diff = args
                .and_then(|v| v.get("diff").and_then(|d| d.as_str()).map(str::to_string))
                .unwrap_or_default();
            // Only scan added lines.
            let added: String = diff
                .lines()
                .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                .map(|l| &l[1..])
                .collect::<Vec<_>>()
                .join("\n");
            let fragment = Fragment::from_text(&added, "<mcp:scan_diff>");
            let result = self.scan_to_json(&fragment);
            CallToolResult::success(vec![Content::text(result.to_string())])
        }

        fn handle_get_rules(&self) -> CallToolResult {
            let rules = self.registry.all_rules();
            let summaries: Vec<Value> = rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "description": r.description,
                        "severity": r.severity,
                        "category": r.category,
                        "keywords": r.keywords,
                    })
                })
                .collect();
            let json = serde_json::json!({
                "rules": summaries,
                "count": summaries.len()
            });
            CallToolResult::success(vec![Content::text(json.to_string())])
        }

        fn handle_validate_finding(&self, args: Option<Value>) -> CallToolResult {
            let id = args
                .and_then(|v| {
                    v.get("finding_id")
                        .and_then(|i| i.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            if id.len() > 64 || id.chars().any(|c| !c.is_ascii_hexdigit() && c != '-') {
                return CallToolResult::error(vec![Content::text(
                    "Invalid finding ID. Provide an opaque hex finding ID, not a raw secret.",
                )]);
            }
            let result = serde_json::json!({
                "finding_id": id,
                "status": "needs_validation",
                "message": "Validation engine will be available in Phase 2.",
            });
            CallToolResult::success(vec![Content::text(result.to_string())])
        }

        // ── HTTP-facing helpers ───────────────────────────────────────────────

        /// Return the list of available tools as a JSON array (for /mcp/v1
        /// `tools/list` requests from HTTP clients).
        pub fn list_tools_json(&self) -> serde_json::Value {
            serde_json::json!([
                {"name": "scan_text",  "description": "Scan inline text for secrets (<50ms)",
                 "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}, "context": {"type": "string"}}, "required": ["text"]}},
                {"name": "scan_file",  "description": "Scan a file for secrets (path-sandboxed)",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
                {"name": "scan_diff",  "description": "Scan a git unified diff for secrets (added lines only)",
                 "inputSchema": {"type": "object", "properties": {"diff": {"type": "string"}}, "required": ["diff"]}},
                {"name": "get_rules",  "description": "List all loaded detection rules",
                 "inputSchema": {"type": "object", "properties": {"category": {"type": "string"}, "severity": {"type": "string"}}}},
                {"name": "validate_finding", "description": "Validate a finding by its opaque ID",
                 "inputSchema": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
                {"name": "scan_repo",  "description": "Scan a full repository for secrets",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "depth": {"type": "integer"}}, "required": ["path"]}}
            ])
        }

        /// Dispatch a JSON-RPC `tools/call` params object through the existing
        /// per-tool handlers and return a JSON result (for HTTP clients).
        pub async fn call_tool_json(&self, params: serde_json::Value) -> serde_json::Value {
            let name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("");
            // Normalise arguments: accept both "arguments" (MCP spec) and
            // "params" (legacy) keys.
            let args: Option<Value> = params
                .get("arguments")
                .or_else(|| params.get("params"))
                .cloned();

            let result: CallToolResult = match name {
                "scan_text"        => self.handle_scan_text(args),
                "scan_file"        => self.handle_scan_file(args),
                "scan_diff"        => self.handle_scan_diff(args),
                "get_rules"        => self.handle_get_rules(),
                "validate_finding" => self.handle_validate_finding(args),
                other => CallToolResult::error(vec![Content::text(format!("Unknown tool: {other}"))]),
            };

            // Serialise CallToolResult to a plain JSON value so the HTTP handler
            // can embed it in a JSON-RPC 2.0 response envelope.
            serde_json::to_value(&result).unwrap_or_else(|_| serde_json::json!({"error": "serialisation error"}))
        }
    }

    // =========================================================================
    // MCP ServerHandler impl
    // =========================================================================

    impl ServerHandler for SquirrelMcpServer {
        fn get_info(&self) -> InitializeResult {
            InitializeResult::new(
                ServerCapabilities::builder().enable_tools().build(),
            )
            .with_server_info(
                Implementation::new("secret-squirrel", env!("CARGO_PKG_VERSION")),
            )
            .with_instructions(
                "Secret Squirrel: GPU-accelerated credential scanner. \
                 Tools: scan_text, scan_file, scan_diff, get_rules, validate_finding.",
            )
        }

        fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>>
               + Send + '_ {
            async move {
                let make_tool = |name: &'static str, desc: &'static str, schema: Value| {
                    Tool::new(name, desc, json_to_schema(schema))
                };
                let tools = vec![
                    make_tool("scan_text", "Scan inline text for secrets (<50ms)",
                        serde_json::json!({"type":"object","properties":{"text":{"type":"string"},"context":{"type":"string"}},"required":["text"]})),
                    make_tool("scan_file", "Scan a file for secrets (path-sandboxed)",
                        serde_json::json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})),
                    make_tool("scan_diff", "Scan a git unified diff for secrets (added lines only)",
                        serde_json::json!({"type":"object","properties":{"diff":{"type":"string"}},"required":["diff"]})),
                    make_tool("get_rules", "List all loaded detection rules",
                        serde_json::json!({"type":"object","properties":{"category":{"type":"string"},"severity":{"type":"string"}}})),
                    make_tool("validate_finding", "Validate a finding by its opaque ID (never raw secret values)",
                        serde_json::json!({"type":"object","properties":{"finding_id":{"type":"string"}},"required":["finding_id"]})),
                    make_tool("scan_repo", "Scan a full repository for secrets",
                        serde_json::json!({"type":"object","properties":{"path":{"type":"string"},"depth":{"type":"integer"}},"required":["path"]})),
                ];
                Ok(ListToolsResult::with_all_items(tools))
            }
        }

        fn call_tool(
            &self,
            request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
            // Extract arguments as a serde_json::Value::Object
            let args = request.arguments.map(|m| {
                Value::Object(m.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
            });
            let name = request.name.to_string();
            async move {
                let result = match name.as_str() {
                    "scan_text" => self.handle_scan_text(args),
                    "scan_file" => self.handle_scan_file(args),
                    "scan_diff" => self.handle_scan_diff(args),
                    "get_rules" => self.handle_get_rules(),
                    "validate_finding" => self.handle_validate_finding(args),
                    other => CallToolResult::error(vec![Content::text(format!(
                        "Unknown tool: {other}"
                    ))]),
                };
                Ok(result)
            }
        }
    }

    // =========================================================================
    // Entry point
    // =========================================================================

    pub async fn run_stdio() -> crate::error::Result<()> {
        info!("Starting Secret Squirrel MCP server on stdio");
        let config = SquirrelConfig::default();
        let handler = SquirrelMcpServer::new(&config).await?;
        let server = handler.serve(stdio()).await.map_err(|e| {
            crate::error::SquirrelError::Io(std::io::Error::other(e.to_string()))
        })?;
        let _ = server.waiting().await;
        info!("MCP server exited cleanly");
        Ok(())
    }

    // =========================================================================
    // HTTP server entry point
    // =========================================================================

    pub async fn run_http(port: u16) -> crate::error::Result<()> {
        let config = SquirrelConfig::default();
        let server = Arc::new(SquirrelMcpServer::new(&config).await?);

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/mcp/v1", post(mcp_handler))
            .with_state(server);

        let addr = format!("0.0.0.0:{port}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(crate::error::SquirrelError::Io)?;

        axum::serve(listener, app)
            .await
            .map_err(|e| crate::error::SquirrelError::Mcp(e.to_string()))?;

        Ok(())
    }

    async fn health_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "status": "ok",
            "service": "secret-squirrel",
            "version": env!("CARGO_PKG_VERSION")
        }))
    }

    async fn mcp_handler(
        State(server): State<std::sync::Arc<SquirrelMcpServer>>,
        Json(request): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let id = request
            .get("id")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let response = match method {
            "tools/list" => {
                let tools = server.list_tools_json();
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": tools }
                })
            }
            "tools/call" => {
                let params = request
                    .get("params")
                    .cloned()
                    .unwrap_or_default();
                let result = server.call_tool_json(params).await;
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                })
            }
            _ => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        Json(response)
    }
} // end mcp_impl

// ============================================================================
// Tests (always compiled; only test logic that doesn't require a running server)
// ============================================================================

#[cfg(test)]
mod tests {
    // Tests for the tool definitions are in tools.rs.
    // Here we test the path-sandboxing helper (always compiled in).
    use crate::mcp::tools::validate_path;
    use crate::error::SquirrelError;

    #[test]
    fn test_sandbox_rejects_absolute_unix() {
        assert!(validate_path("/etc/passwd").is_err());
    }

    #[test]
    fn test_sandbox_rejects_windows_drive() {
        assert!(validate_path("C:\\Windows").is_err());
    }

    #[test]
    fn test_sandbox_rejects_parent_dir() {
        assert!(validate_path("../../etc/shadow").is_err());
    }

    #[test]
    fn test_sandbox_allows_dot() {
        // "." is the current directory — always valid
        let r = validate_path(".");
        match r {
            Err(SquirrelError::PathTraversal { .. }) => {
                panic!(".  should not be rejected as traversal")
            }
            _ => {}
        }
    }

    #[test]
    fn test_sandbox_allows_simple_relative() {
        let r = validate_path("Cargo.toml");
        match r {
            Err(SquirrelError::PathTraversal { .. }) => {
                panic!("Simple relative path should not be rejected")
            }
            _ => {}
        }
    }
}
