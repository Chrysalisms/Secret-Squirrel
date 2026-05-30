//! Engine module — GPU/CPU scanning pipeline.
//!
//! This module houses all compute machinery that powers Secret Squirrel's
//! 4-stage inverted pipeline:
//!
//! 1. **entropy gate** (`cpu`/`gpu`) — Shannon entropy on 64-byte chunks
//! 2. **proximity detection** (`cpu`/`gpu`) — semantic context scanning
//! 3. **tri-stream decomposition** (`cpu`/`gpu`) — identifier/literal/structure separation
//! 4. **pattern verification** (`pipeline`) — Aho-Corasick + regex on survivors
//!
//! The [`router`] module selects between GPU and CPU execution based on input
//! size and hardware availability. The [`pipeline`] module coordinates the
//! four stages. The [`session`] module tracks per-scan state, findings, and
//! statistics.

pub mod buffers;
pub mod cpu;
pub mod discovery;
pub mod gpu;
pub mod pipeline;
pub mod router;
pub mod routing;
pub mod session;
pub mod validation;
