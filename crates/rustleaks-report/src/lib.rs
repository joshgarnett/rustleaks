#![forbid(unsafe_code)]
//! Report writers for JSON, CSV, JUnit, SARIF and templates.

mod csv;
mod go_json;
mod json;
mod junit;
mod sarif;
mod template;

use std::collections::TryReserveError;
use std::io;

pub use csv::CsvReporter;
pub use json::JsonReporter;
pub use junit::JunitReporter;
pub use sarif::{ReportRule, SarifReporter};
pub use template::{SAFE_TEMPLATE_PROFILE, TemplateError, TemplateLimits, TemplateReporter};

use rustleaks_core::model::Finding;

/// CWE for hard-coded credentials, for callers that label findings. Reports
/// do not include it.
pub const CWE: &str = "CWE-798";

/// Human-readable description for [`CWE`].
pub const CWE_DESCRIPTION: &str = "Use of Hard-coded Credentials";

/// A reusable synchronous finding writer.
pub trait Reporter {
    /// Writes the complete report without closing or flushing the destination.
    ///
    /// # Errors
    ///
    /// Returns a structured serialization or destination error.
    fn write(&self, writer: &mut dyn io::Write, findings: &[Finding]) -> Result<(), ReportError>;
}

/// A report serialization or output failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReportError {
    /// The destination rejected report bytes.
    #[error("could not write report: {0}")]
    Io(#[from] io::Error),
    /// A report-owned buffer could not be reserved fallibly.
    #[error("could not allocate report buffer")]
    Allocation(#[source] TryReserveError),
    /// Safe-template parsing or rendering failed.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// JSON cannot represent a non-finite entropy value.
    #[error("could not serialize non-finite finding entropy {0}")]
    NonFiniteEntropy(f32),
}
