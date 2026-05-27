//! Source adapters for Secret Squirrel.
//!
//! Each source adapter implements either [`SyncSource`] (for local/synchronous
//! sources like files, git, archives) or [`AsyncSource`] (for HTTP-backed sources
//! like GitHub, GitLab, S3, etc.) and produces a stream of [`Fragment`]s for the
//! scanning pipeline.
//!
//! # Source Phases
//!
//! **Phase 1 (fully implemented):** Local filesystem, Git history, stdin, archives,
//! and .env files.
//!
//! **Phase 2 (stubbed):** GitHub, GitLab, S3/GCS/R2, Docker images, Kubernetes,
//! and Terraform state.

pub mod archive;
pub mod dir;
pub mod dotenv;
pub mod git;
pub mod stdin;
pub mod traits;

// Phase 2 sources (stub modules — implementation in Phase 2)
pub mod docker;
pub mod github;
pub mod gitlab;
pub mod kubernetes;
pub mod s3;
pub mod terraform;

pub use traits::{AsyncSource, SourceStream, SyncSource};
