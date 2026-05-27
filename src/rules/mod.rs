//! Rule management for Secret Squirrel.
//!
//! This module handles the full lifecycle of detection rules:
//!
//! 1. **Parsing** — Load rules from Squirrel, Betterleaks, or Gitleaks TOML formats
//! 2. **Compilation** — Compile regexes, build the Aho-Corasick automaton
//! 3. **Registry** — Central store with hot-reload support
//! 4. **Remediation** — Provider-specific rotation guides

pub mod compiler;
pub mod parser;
pub mod registry;
pub mod remediation;

pub use compiler::CompiledRule;
pub use parser::{Rule, RuleFormat};
pub use registry::RuleRegistry;
