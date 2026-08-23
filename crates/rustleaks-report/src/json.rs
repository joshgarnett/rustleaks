use std::io::Write;

use rustleaks_core::model::Finding;

use crate::go_json;
use crate::{ReportError, Reporter};

/// Upstream-compatible indented JSON report writer.
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn write(&self, writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
        if let Some(finding) = findings
            .iter()
            .find(|finding| !finding.entropy().is_finite())
        {
            return Err(ReportError::NonFiniteEntropy(finding.entropy()));
        }
        go_json::write_findings(writer, findings, b" ")?;
        writer.write_all(b"\n")?;
        Ok(())
    }
}
