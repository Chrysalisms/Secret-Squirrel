//! Report formatters — serialize [`Finding`]s to various output formats.
//!
//! # Traits
//!
//! - [`Reporter`] — writes findings to an [`std::io::Write`] sink (streaming, used by CLI)
//! - [`Formatter`] — returns findings as a [`String`] (used in MCP, tests, and embedding)
//!
//! # Formats
//!
//! | Format  | Type            | Use case                         |
//! |---------|-----------------|----------------------------------|
//! | JSON    | [`JsonReporter`]  | Machine-readable; CI/CD pipelines |
//! | SARIF   | [`SarifReporter`] | GitHub Security tab upload        |
//! | Table   | [`TableReporter`] | Human-readable terminal output    |
//! | CSV     | [`CsvReporter`]   | Spreadsheet import / SIEM ingest  |

pub mod csv;
pub mod json;
pub mod sarif;
pub mod table;

pub use csv::CsvReporter;
pub use json::JsonReporter;
pub use sarif::SarifReporter;
pub use table::TableReporter;

use crate::config::OutputFormat;
use crate::error::Result;
use crate::engine::session::ScanStats;
use crate::types::Finding;
use std::io::Write;

// ============================================================================
// Reporter — streaming write-based trait
// ============================================================================

/// Trait for output formatters that write to an [`std::io::Write`] sink.
///
/// This is the primary trait used by the CLI to stream findings to stdout or
/// a file without building an intermediate `String`.
pub trait Reporter: Send + Sync {
    /// Write all findings to `writer`.
    ///
    /// # Arguments
    ///
    /// * `findings`     — slice of findings to format
    /// * `writer`       — output sink (stdout, file, etc.)
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()>;

    fn write_with_stats(
        &self,
        findings: &[Finding],
        _stats: Option<&ScanStats>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        self.write(findings, writer)
    }
}

// ============================================================================
// Formatter — string-based trait (for MCP, embedding, tests)
// ============================================================================

/// Trait for output formatters that return a [`String`].
///
/// Useful when you need the formatted output as an owned value rather than
/// streaming it to a writer (e.g. MCP tool responses, unit tests).
///
/// When `show_secrets` is `false` the formatter **must** redact the
/// [`Finding::secret`] field before including it in the output.
pub trait Formatter: Send + Sync {
    /// Format findings into an owned [`String`].
    ///
    /// # Arguments
    ///
    /// * `findings`     — slice of findings to format
    /// * `show_secrets` — if `true`, expose raw secret values; otherwise redact
    fn format(&self, findings: &[Finding], show_secrets: bool) -> String;
}

// ============================================================================
// Factory
// ============================================================================

/// Return a boxed [`Reporter`] appropriate for the given [`OutputFormat`].
pub fn get_reporter(format: &OutputFormat) -> Box<dyn Reporter> {
    match format {
        OutputFormat::Json => Box::new(JsonReporter),
        OutputFormat::Sarif => Box::new(SarifReporter),
        OutputFormat::Table => Box::new(TableReporter),
        OutputFormat::Csv => Box::new(CsvReporter),
    }
}

/// Return a boxed [`Formatter`] appropriate for the given [`OutputFormat`].
pub fn get_formatter(format: &OutputFormat) -> Box<dyn Formatter> {
    match format {
        OutputFormat::Json => Box::new(JsonReporter),
        OutputFormat::Sarif => Box::new(SarifReporter),
        OutputFormat::Table => Box::new(TableReporter),
        OutputFormat::Csv => Box::new(CsvReporter),
    }
}
