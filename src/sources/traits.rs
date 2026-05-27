//! Source trait definitions for Secret Squirrel.
//!
//! This module defines the two core source abstractions:
//!
//! - [`SyncSource`] — for local/synchronous sources (files, git, archives)
//! - [`AsyncSource`] — for HTTP-backed sources (GitHub, GitLab, S3, etc.)
//!
//! The [`SourceStream`] enum provides a unified way to route between the two.

use crate::error::Result;
use crate::types::Fragment;

// ============================================================================
// SyncSource
// ============================================================================

/// A synchronous source that produces [`Fragment`]s via a blocking iterator.
///
/// Use this trait for sources that do not need async I/O: local filesystem
/// scanning, Git history walking, archive extraction, and stdin reading.
/// The fragments iterator may do blocking I/O internally (e.g., mmap, `git2`
/// calls), but will never `.await`.
///
/// # Thread Safety
///
/// Implementors must be [`Send`] so they can be moved to a Rayon thread pool.
pub trait SyncSource: Send {
    /// Human-readable name of this source (used in logs and error messages).
    fn name(&self) -> &str;

    /// Produce a lazy iterator of [`Fragment`]s.
    ///
    /// Each `Result::Err` in the iterator represents a **recoverable** per-item
    /// error (e.g., a single unreadable file). The caller should log it and
    /// continue rather than aborting the entire scan.
    fn fragments(&self) -> Box<dyn Iterator<Item = Result<Fragment>> + '_>;
}

// ============================================================================
// AsyncSource
// ============================================================================

/// An async source that produces [`Fragment`]s by calling an external API.
///
/// Use this trait for sources that require HTTP calls: GitHub, GitLab, S3,
/// Docker Hub, etc. Implementors must be both [`Send`] and [`Sync`] because
/// they may be held across `.await` points on a multi-threaded Tokio runtime.
///
/// # Implementation note
///
/// `async-trait` is used here because stable Rust (< 1.75 AFIT stabilisation
/// path) cannot express `async fn` in traits with dyn-safe object safety
/// requirements in all edition-2021 contexts. We use the crate to avoid
/// boxing boilerplate.
#[async_trait::async_trait]
pub trait AsyncSource: Send + Sync {
    /// Human-readable name of this source (used in logs and error messages).
    fn name(&self) -> &str;

    /// Fetch and return all fragments from this source.
    ///
    /// Unlike the sync variant, async sources collect all fragments up front
    /// (pagination etc. is handled internally). For very large sources,
    /// implementors should use bounded pagination and stream results via a
    /// channel, returning an empty `Vec` and sending findings directly to the
    /// pipeline — but that is an implementation concern, not part of this API.
    async fn fragments(&self) -> Result<Vec<Fragment>>;
}

// ============================================================================
// SourceStream — unified routing enum
// ============================================================================

/// A unified wrapper around either a sync or async source.
///
/// Used by the pipeline dispatcher to decide whether to handle a source on
/// the Rayon thread pool or the Tokio async runtime.
pub enum SourceStream {
    /// A blocking, iterator-based source (local files, git, archives, stdin).
    Sync(Box<dyn SyncSource>),
    /// An async, API-backed source (GitHub, GitLab, S3, etc.).
    Async(Box<dyn AsyncSource>),
}

impl SourceStream {
    /// Returns the name of the underlying source for logging purposes.
    pub fn name(&self) -> &str {
        match self {
            SourceStream::Sync(s) => s.name(),
            SourceStream::Async(s) => s.name(),
        }
    }

    /// Returns `true` if this stream wraps a synchronous source.
    pub fn is_sync(&self) -> bool {
        matches!(self, SourceStream::Sync(_))
    }

    /// Returns `true` if this stream wraps an asynchronous source.
    pub fn is_async(&self) -> bool {
        matches!(self, SourceStream::Async(_))
    }
}
