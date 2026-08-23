use std::io::Write;

use rustleaks_core::config::{CompiledConfig, CompiledRule};
use rustleaks_core::model::{ByteText, Finding};

use crate::go_json::{write_indent, write_string, write_string_body};
use crate::{ReportError, Reporter};

/// Rule metadata retained in `SARIF` configuration order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportRule {
    id: String,
    description: String,
}

impl ReportRule {
    /// Fallibly copies one `SARIF` rule descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Allocation`] if either caller-sized string
    /// cannot be reserved.
    pub fn try_new(id: &str, description: &str) -> Result<Self, ReportError> {
        Ok(Self {
            id: try_copy_string(id)?,
            description: try_copy_string(description)?,
        })
    }

    fn try_from_compiled(rule: &CompiledRule) -> Result<Self, ReportError> {
        Self::try_new(rule.id(), rule.description())
    }
}

/// Upstream-compatible `SARIF` 2.1.0 report writer.
#[derive(Clone, Debug, Default)]
pub struct SarifReporter {
    rules: Vec<ReportRule>,
}

impl SarifReporter {
    /// Creates a reporter with the supplied ordered rule metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Allocation`] if the caller-sized rule vector
    /// cannot grow.
    pub fn try_new(rules: impl IntoIterator<Item = ReportRule>) -> Result<Self, ReportError> {
        let mut collected = Vec::new();
        for rule in rules {
            if collected.len() == collected.capacity() {
                collected.try_reserve(1).map_err(ReportError::Allocation)?;
            }
            collected.push(rule);
        }
        Ok(Self { rules: collected })
    }

    /// Copies rule metadata in the configuration's compatibility order.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Allocation`] if caller-sized rule metadata
    /// cannot be copied or reserved.
    pub fn try_from_config(config: &CompiledConfig) -> Result<Self, ReportError> {
        let mut rules = Vec::new();
        for rule in config.ordered_rules() {
            if rules.len() == rules.capacity() {
                rules.try_reserve(1).map_err(ReportError::Allocation)?;
            }
            rules.push(ReportRule::try_from_compiled(rule)?);
        }
        Ok(Self { rules })
    }
}

fn try_copy_string(value: &str) -> Result<String, ReportError> {
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(ReportError::Allocation)?;
    copied.push_str(value);
    Ok(copied)
}

impl Reporter for SarifReporter {
    fn write(&self, writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
        writer.write_all(b"{")?;
        field(writer, 1, b"$schema")?;
        write_string(writer, b"https://json.schemastore.org/sarif-2.1.0.json")?;
        writer.write_all(b",")?;
        field(writer, 1, b"version")?;
        write_string(writer, b"2.1.0")?;
        writer.write_all(b",")?;
        field(writer, 1, b"runs")?;
        writer.write_all(b"[\n")?;
        write_indent(writer, b" ", 2)?;
        writer.write_all(b"{")?;
        field(writer, 3, b"tool")?;
        writer.write_all(b"{")?;
        field(writer, 4, b"driver")?;
        write_driver(writer, &self.rules)?;
        close_object(writer, 3, true)?;
        field(writer, 3, b"results")?;
        write_results(writer, findings)?;
        close_object(writer, 2, false)?;
        writer.write_all(b"\n ]\n}\n")?;
        Ok(())
    }
}

fn write_driver(writer: &mut dyn Write, rules: &[ReportRule]) -> Result<(), ReportError> {
    writer.write_all(b"{")?;
    text_member(writer, 5, b"name", b"gitleaks", true)?;
    text_member(writer, 5, b"semanticVersion", b"v8.0.0", true)?;
    text_member(
        writer,
        5,
        b"informationUri",
        b"https://github.com/gitleaks/gitleaks",
        true,
    )?;
    field(writer, 5, b"rules")?;
    if rules.is_empty() {
        writer.write_all(b"[]")?;
    } else {
        writer.write_all(b"[\n")?;
        for (index, rule) in rules.iter().enumerate() {
            write_indent(writer, b" ", 6)?;
            writer.write_all(b"{")?;
            text_member(writer, 7, b"id", rule.id.as_bytes(), true)?;
            field(writer, 7, b"shortDescription")?;
            writer.write_all(b"{")?;
            text_member(writer, 8, b"text", rule.description.as_bytes(), false)?;
            close_object(writer, 7, false)?;
            close_object(writer, 6, index + 1 != rules.len())?;
            writer.write_all(b"\n")?;
        }
        write_indent(writer, b" ", 5)?;
        writer.write_all(b"]")?;
    }
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", 4)?;
    writer.write_all(b"}")?;
    Ok(())
}

fn write_results(writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
    if findings.is_empty() {
        writer.write_all(b"[]")?;
        return Ok(());
    }
    writer.write_all(b"[\n")?;
    for (index, finding) in findings.iter().enumerate() {
        write_indent(writer, b" ", 4)?;
        write_result(writer, finding)?;
        if index + 1 != findings.len() {
            writer.write_all(b",")?;
        }
        writer.write_all(b"\n")?;
    }
    write_indent(writer, b" ", 3)?;
    writer.write_all(b"]")?;
    Ok(())
}

fn write_result(writer: &mut dyn Write, finding: &Finding) -> Result<(), ReportError> {
    writer.write_all(b"{")?;
    field(writer, 5, b"message")?;
    writer.write_all(b"{")?;
    field(writer, 6, b"text")?;
    write_message(writer, finding)?;
    close_object(writer, 5, true)?;
    text_member(writer, 5, b"ruleId", finding.rule_id().as_bytes(), true)?;
    field(writer, 5, b"locations")?;
    write_location(writer, finding)?;
    writer.write_all(b",")?;
    field(writer, 5, b"partialFingerprints")?;
    write_partial_fingerprints(writer, finding)?;
    writer.write_all(b",")?;
    field(writer, 5, b"properties")?;
    write_properties(writer, finding.tags())?;
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", 4)?;
    writer.write_all(b"}")?;
    Ok(())
}

fn write_message(writer: &mut dyn Write, finding: &Finding) -> Result<(), ReportError> {
    writer.write_all(b"\"")?;
    write_string_body(writer, finding.rule_id().as_bytes())?;
    writer.write_all(b" has detected secret for file ")?;
    write_string_body(writer, finding.file().as_bytes())?;
    if finding.commit().is_empty() {
        writer.write_all(b".\"")?;
    } else {
        writer.write_all(b" at commit ")?;
        write_string_body(writer, finding.commit().as_bytes())?;
        writer.write_all(b".\"")?;
    }
    Ok(())
}

fn write_location(writer: &mut dyn Write, finding: &Finding) -> Result<(), ReportError> {
    let location = finding.location();
    let uri = if finding.symlink_file().is_empty() {
        finding.file()
    } else {
        finding.symlink_file()
    };
    writer.write_all(b"[\n")?;
    write_indent(writer, b" ", 6)?;
    writer.write_all(b"{")?;
    field(writer, 7, b"physicalLocation")?;
    writer.write_all(b"{")?;
    field(writer, 8, b"artifactLocation")?;
    writer.write_all(b"{")?;
    text_member(writer, 9, b"uri", uri.as_bytes(), false)?;
    close_object(writer, 8, true)?;
    field(writer, 8, b"region")?;
    writer.write_all(b"{")?;
    number_member(writer, 9, b"startLine", location.start_line(), true)?;
    number_member(writer, 9, b"startColumn", location.start_column(), true)?;
    number_member(writer, 9, b"endLine", location.end_line(), true)?;
    number_member(writer, 9, b"endColumn", location.end_column(), true)?;
    field(writer, 9, b"snippet")?;
    writer.write_all(b"{")?;
    text_member(writer, 10, b"text", finding.secret().as_bytes(), false)?;
    close_object(writer, 9, false)?;
    close_object(writer, 8, false)?;
    close_object(writer, 7, false)?;
    close_object(writer, 6, false)?;
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", 5)?;
    writer.write_all(b"]")?;
    Ok(())
}

fn write_partial_fingerprints(
    writer: &mut dyn Write,
    finding: &Finding,
) -> Result<(), ReportError> {
    writer.write_all(b"{")?;
    text_member(writer, 6, b"commitSha", finding.commit().as_bytes(), true)?;
    text_member(writer, 6, b"email", finding.email().as_bytes(), true)?;
    text_member(writer, 6, b"author", finding.author().as_bytes(), true)?;
    text_member(writer, 6, b"date", finding.date().as_bytes(), true)?;
    text_member(
        writer,
        6,
        b"commitMessage",
        finding.message().as_bytes(),
        false,
    )?;
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", 5)?;
    writer.write_all(b"}")?;
    Ok(())
}

fn write_properties(writer: &mut dyn Write, tags: &[ByteText]) -> Result<(), ReportError> {
    writer.write_all(b"{")?;
    field(writer, 6, b"tags")?;
    if tags.is_empty() {
        writer.write_all(b"[]")?;
    } else {
        writer.write_all(b"[\n")?;
        for (index, tag) in tags.iter().enumerate() {
            write_indent(writer, b" ", 7)?;
            write_string(writer, tag.as_bytes())?;
            if index + 1 != tags.len() {
                writer.write_all(b",")?;
            }
            writer.write_all(b"\n")?;
        }
        write_indent(writer, b" ", 6)?;
        writer.write_all(b"]")?;
    }
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", 5)?;
    writer.write_all(b"}")?;
    Ok(())
}

fn field(writer: &mut dyn Write, depth: usize, name: &[u8]) -> Result<(), ReportError> {
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", depth)?;
    write_string(writer, name)?;
    writer.write_all(b": ")?;
    Ok(())
}

fn text_member(
    writer: &mut dyn Write,
    depth: usize,
    name: &[u8],
    value: &[u8],
    comma: bool,
) -> Result<(), ReportError> {
    field(writer, depth, name)?;
    write_string(writer, value)?;
    if comma {
        writer.write_all(b",")?;
    }
    Ok(())
}

fn number_member(
    writer: &mut dyn Write,
    depth: usize,
    name: &[u8],
    value: usize,
    comma: bool,
) -> Result<(), ReportError> {
    field(writer, depth, name)?;
    write!(writer, "{value}")?;
    if comma {
        writer.write_all(b",")?;
    }
    Ok(())
}

fn close_object(writer: &mut dyn Write, depth: usize, comma: bool) -> Result<(), ReportError> {
    writer.write_all(b"\n")?;
    write_indent(writer, b" ", depth)?;
    writer.write_all(b"}")?;
    if comma {
        writer.write_all(b",")?;
    }
    Ok(())
}
