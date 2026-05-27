//! MCP server stub — full implementation in Phase 2
//!
//! This module exposes Secret Squirrel scanning capabilities via the
//! Model Context Protocol (MCP) for integration with AI coding agents
//! like Cursor, Claude Code, and GitHub Copilot.
//!
//! # MCP Tools
//!
//! - `scan_text` — scan inline text (<50ms target)
//! - `scan_file` — scan a single file with path sandboxing (<100ms)
//! - `scan_diff` — scan a git diff, findings on changed lines only (<100ms)
//! - `scan_repo` — full repository scan
//! - `validate_finding` — validate a finding by ID only (prevents credential oracle)
//! - `get_rules` — list loaded rules (<10ms)

pub mod server;
pub mod tools;
