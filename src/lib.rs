//! Secret Squirrel — GPU-accelerated, AI-powered credential scanner.
//!
//! # Overview
//!
//! Secret Squirrel implements a 4-stage inverted pipeline to detect secrets
//! with minimal false positives and maximum performance:
//!
//! 1. **Shannon Entropy Gate** — eliminates ~95% of input instantly
//! 2. **Semantic Proximity** — filters by code shape context
//! 3. **Tri-Stream Decomposition** — separates identifiers, literals, and structure
//! 4. **Pattern Verification** — targeted Aho-Corasick + regex on survivors
//!
//! # Feature Flags
//!
//! - `gpu` — Enable GPU acceleration via wgpu (Vulkan/Metal/DX12)
//! - `cpu-simd` — Enable SIMD-vectorized CPU path (AVX2/NEON)
//! - `mcp-server` — Enable MCP server for AI agent integration
//! - `validate` — Enable credential validation engine
//! - `cnn` — Enable ONNX-based CNN classifier
//! - `semantic` — Enable tree-sitter AST analysis

pub mod baseline;
pub mod config;
pub mod engine;
pub mod error;
pub mod report;
pub mod rules;
pub mod scoring;
pub mod sources;
pub mod stages;
pub mod types;

pub mod mcp;

#[cfg(feature = "semantic")]
pub mod semantic;

pub mod validate;

// Re-export key types for public API consumers
pub use config::SquirrelConfig;
pub use engine::session::ScanSession;
pub use error::{Result, SquirrelError};
pub use types::{Finding, Fragment, Location, Severity};
