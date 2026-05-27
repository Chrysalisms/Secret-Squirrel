//! Credential validation engine for Secret Squirrel.
//!
//! This module provides live validation of detected credentials against
//! their respective provider APIs. Validation is always opt-in and requires
//! the `validate` feature flag.
//!
//! # Architecture
//!
//! ```text
//! ValidationEngine
//!   ├── Vec<Box<dyn Validator>>   — provider-specific validators
//!   ├── ProviderRateLimiter       — per-provider token-bucket rate limiting
//!   └── CircuitBreaker            — per-provider circuit breaker
//! ```
//!
//! # Safety
//!
//! Secret values are **never** logged or persisted. Validators receive a
//! [`Finding`] whose `.secret` field is a [`RedactedString`]; they call
//! `.expose()` only within the validation call stack and never store the
//! result.

pub mod blast_radius;
pub mod circuit_breaker;
pub mod engine;
pub mod providers;
pub mod rate_limit;

pub use blast_radius::{BlastRadius, RiskLevel};
pub use engine::{ValidationEngine, ValidationResult, Validator};
