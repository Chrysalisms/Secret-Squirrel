//! Pipeline stage modules for Secret Squirrel.
//!
//! The four stages form a filtering funnel that eliminates non-secrets
//! progressively, so expensive operations run only on surviving candidates.
//!
//! | Stage | Type                 | Elimination |
//! |-------|----------------------|-------------|
//! | 1     | [`EntropyGate`]      | ~95% of input |
//! | 2     | [`ProximityDetector`]| ~70% of survivors |
//! | 3     | [`TriStreamDecomposer`] | ~50% of survivors |
//! | 4     | [`PatternVerifier`]  | Final precision match |

pub mod decoder;
pub mod entropy;
pub mod pattern;
pub mod proximity;
pub mod semantic;
pub mod tristream;

pub use entropy::EntropyGate;
pub use pattern::PatternVerifier;
pub use proximity::ProximityDetector;
pub use semantic::{SemanticAnalyzer, SemanticContext};
pub use tristream::TriStreamDecomposer;
