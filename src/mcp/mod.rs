//! MCP (Model Context Protocol) server for Secret Squirrel.
//!
//! Exposes Secret Squirrel scanning capabilities via JSON-RPC 2.0 over stdio,
//! making them consumable by any MCP-compatible AI coding assistant
//! (Cursor, Claude Code, GitHub Copilot, etc.).
//!
//! # Feature gate
//!
//! This module requires the `mcp-server` feature flag:
//!
//! ```shell
//! cargo build --features mcp-server
//! ```
//!
//! Without the feature the module still compiles (stub `run_stdio` is provided
//! in `server.rs`) but no MCP logic is linked.
//!
//! # MCP Tools
//!
//! | Tool | Description | Target latency |
//! |------|-------------|---------------|
//! | `scan_text`        | Scan inline text for secrets      | <50 ms  |
//! | `scan_file`        | Scan a single file (path-sandboxed) | <100 ms |
//! | `scan_diff`        | Scan a git diff (added lines only)  | <100 ms |
//! | `scan_repo`        | Full repository scan               | varies  |
//! | `get_rules`        | List loaded detection rules        | <10 ms  |
//! | `validate_finding` | Validate a finding by opaque ID    | varies  |

pub mod server;
pub mod tools;

#[cfg(feature = "mcp-server")]
pub use server::McpServer;
