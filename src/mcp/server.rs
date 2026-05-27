//! MCP server for Secret Squirrel.
//!
//! Exposes scanning as MCP tools consumable by any MCP-compatible AI assistant.
//! Enabled via `--features mcp-server`.
//!
//! # Tools
//! - `scan_text`       — scan inline text for secrets  
//! - `scan_file`       — scan a single file (path-sandboxed)
//! - `scan_diff`       — scan a git unified diff (added lines only)
//! - `get_rules`       — list all loaded detection rules
//! - `validate_finding`— validate a finding by opaque ID

// When the mcp-server feature is disabled we still expose run_stdio so that
// main.rs can call it unconditionally.
#[cfg(not(feature = "mcp-server"))]
pub async fn run_stdio() -> crate::error::Result<()> {
    tracing::warn!(
        "MCP server not compiled in. Rebuild with --features mcp-server to enable."
    );
    Ok(())
}

#[cfg(feature = "mcp-server")]
pub use self::mcp_impl::run_stdio;

#[cfg(feature = "mcp-server")]
mod mcp_impl {
    use bytes::Bytes;
    use rmcp::{
        ServerHandler, ServiceExt,
        model::{
            CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities,
            ServerInfo, Tool,
        },
        transport::stdio,
    };
    use serde_json::Value;
    use std::path::{Path, PathBuf};
    use tracing::{info, warn};

    use crate::config::SquirrelConfig;
    use crate::engine::{pipeline::Pipeline, router::Router};
    use crate::rules::RuleRegistry;
    use crate::types::Fragment;

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
            let router = Router::new(&config.gpu).await;
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
    }

    // =========================================================================
    // MCP ServerHandler impl
    // =========================================================================

    impl ServerHandler for SquirrelMcpServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo {
                protocol_version: ProtocolVersion::V_2024_11_05,
                capabilities: ServerCapabilities::builder().enable_tools().build(),
                server_info: Implementation {
                    name: "secret-squirrel".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                instructions: Some(
                    "Secret Squirrel: GPU-accelerated credential scanner. \
                     Tools: scan_text, scan_file, scan_diff, get_rules, validate_finding."
                        .to_string(),
                ),
            }
        }

        fn list_tools(
            &self,
            _request: rmcp::model::PaginatedRequestParam,
            _context: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> impl std::future::Future<Output = Result<rmcp::model::ListToolsResult, rmcp::Error>>
               + Send + '_ {
            async move {
                let make_tool = |name: &str, desc: &str, schema: Value| Tool {
                    name: name.to_string().into(),
                    description: Some(desc.to_string().into()),
                    input_schema: std::sync::Arc::new(schema.as_object().cloned().unwrap_or_default()),
                    ..Default::default()
                };
                Ok(rmcp::model::ListToolsResult {
                    tools: vec![
                        make_tool("scan_text", "Scan inline text for secrets",
                            serde_json::json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]})),
                        make_tool("scan_file", "Scan a file for secrets (path-sandboxed)",
                            serde_json::json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})),
                        make_tool("scan_diff", "Scan a git unified diff for secrets",
                            serde_json::json!({"type":"object","properties":{"diff":{"type":"string"}},"required":["diff"]})),
                        make_tool("get_rules", "List all loaded detection rules",
                            serde_json::json!({"type":"object","properties":{}})),
                        make_tool("validate_finding", "Validate a finding by its opaque ID",
                            serde_json::json!({"type":"object","properties":{"finding_id":{"type":"string"}},"required":["finding_id"]})),
                    ],
                    next_cursor: None,
                })
            }
        }

        fn call_tool(
            &self,
            request: rmcp::model::CallToolRequestParam,
            _context: rmcp::service::RequestContext<rmcp::RoleServer>,
        ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::Error>> + Send + '_ {
            let args = request.arguments.map(|m| Value::Object(m.into_iter().map(|(k, v)| (k.to_string(), v)).collect()));
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
        server.waiting().await;
        info!("MCP server exited cleanly");
        Ok(())
    }
}
