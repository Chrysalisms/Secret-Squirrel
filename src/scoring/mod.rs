//! Scoring modules for Secret Squirrel.
//!
//! The scoring layer fuses signals from all four pipeline stages into a final
//! confidence score and applies post-processing to the resulting findings:
//!
//! | Module            | Responsibility                                        |
//! |-------------------|-------------------------------------------------------|
//! | [`markov`]        | Trigram Markov chain randomness scorer                |
//! | [`fusion`]        | Weighted score fusion engine                          |
//! | [`confidence`]    | Provenance-aware confidence adjustments               |
//! | [`dedup`]         | Finding deduplication by (rule, hash, path)           |
//! | [`correlation`]   | Cross-file credential chain detection                 |
//! | [`cnn`]           | CNN tokenizer, `ModelTier`, and (with `cnn` feature)  |
//! |                   | ONNX-backed `CnnClassifier`                           |

pub mod confidence;
pub mod correlation;
pub mod cnn;
pub mod dedup;
pub mod fusion;
pub mod markov;

pub use correlation::CorrelationEngine;
pub use fusion::FusionEngine;
pub use markov::MarkovScorer;

#[cfg(feature = "cnn")]
pub use cnn::CnnClassifier;
