use std::io::Write;

use rustleaks_core::model::Finding;

use crate::go_json;
use crate::{ReportError, Reporter};

/// Indented JSON report writer.
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn write(&self, writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
        go_json::check_entropy(findings)?;
        go_json::write_findings(writer, findings, b" ")?;
        writer.write_all(b"\n")?;
        Ok(())
    }
}
