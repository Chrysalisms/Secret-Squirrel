pub mod csv;
pub mod json;
pub mod sarif;
pub mod table;

pub use json::JsonReporter;
pub use sarif::SarifReporter;
pub use table::TableReporter;
pub use csv::CsvReporter;

use crate::config::OutputFormat;
use crate::error::Result;
use crate::types::Finding;
use std::io::Write;

/// Trait for all output formatters.
pub trait Reporter {
    /// Write findings to the provided output writer.
    fn write(&self, findings: &[Finding], writer: &mut dyn Write) -> Result<()>;
}

/// Get the appropriate reporter for the given format.
pub fn get_reporter(format: &OutputFormat) -> Box<dyn Reporter> {
    match format {
        OutputFormat::Json => Box::new(JsonReporter),
        OutputFormat::Sarif => Box::new(SarifReporter),
        OutputFormat::Table => Box::new(TableReporter),
        OutputFormat::Csv => Box::new(CsvReporter),
    }
}
