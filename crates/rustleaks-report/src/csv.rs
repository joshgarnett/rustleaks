use std::io::Write;

use rustleaks_core::model::{ByteText, Finding};

use crate::{ReportError, Reporter};

const HEADER: &[&[u8]] = &[
    b"RuleID",
    b"Commit",
    b"File",
    b"SymlinkFile",
    b"Secret",
    b"Match",
    b"StartLine",
    b"EndLine",
    b"StartColumn",
    b"EndColumn",
    b"Author",
    b"Message",
    b"Date",
    b"Email",
    b"Fingerprint",
    b"Tags",
];

/// Upstream-compatible RFC 4180-style CSV report writer.
#[derive(Clone, Copy, Debug, Default)]
pub struct CsvReporter;

impl Reporter for CsvReporter {
    fn write(&self, writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
        let Some(first) = findings.first() else {
            return Ok(());
        };
        let include_link = !first.link().is_empty();
        write_row(
            writer,
            HEADER
                .iter()
                .copied()
                .chain(include_link.then_some(b"Link".as_slice())),
        )?;

        for finding in findings {
            let location = finding.location();
            let start_line = location.start_line().to_string();
            let end_line = location.end_line().to_string();
            let start_column = location.start_column().to_string();
            let end_column = location.end_column().to_string();
            let fields = [
                finding.rule_id().as_bytes(),
                finding.commit().as_bytes(),
                finding.file().as_bytes(),
                finding.symlink_file().as_bytes(),
                finding.secret().as_bytes(),
                finding.match_text().as_bytes(),
                start_line.as_bytes(),
                end_line.as_bytes(),
                start_column.as_bytes(),
                end_column.as_bytes(),
                finding.author().as_bytes(),
                finding.message().as_bytes(),
                finding.date().as_bytes(),
                finding.email().as_bytes(),
                finding.fingerprint().as_bytes(),
            ];
            write_row_prefix(writer, fields)?;
            writer.write_all(b",")?;
            write_tags_field(writer, finding.tags())?;
            if include_link {
                writer.write_all(b",")?;
                write_field(writer, finding.link().as_bytes())?;
            }
            writer.write_all(b"\n")?;
        }
        Ok(())
    }
}

fn write_tags_field(writer: &mut dyn Write, tags: &[ByteText]) -> Result<(), std::io::Error> {
    let quoted = tags_need_quotes(tags);
    if quoted {
        writer.write_all(b"\"")?;
    }
    for (index, tag) in tags.iter().enumerate() {
        if index != 0 {
            writer.write_all(b" ")?;
        }
        write_escaped_bytes(writer, tag.as_bytes())?;
    }
    if quoted {
        writer.write_all(b"\"")?;
    }
    Ok(())
}

fn write_row<'a>(
    writer: &mut dyn Write,
    fields: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), std::io::Error> {
    write_row_prefix(writer, fields)?;
    writer.write_all(b"\n")
}

fn write_row_prefix<'a>(
    writer: &mut dyn Write,
    fields: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), std::io::Error> {
    for (index, field) in fields.into_iter().enumerate() {
        if index != 0 {
            writer.write_all(b",")?;
        }
        write_field(writer, field)?;
    }
    Ok(())
}

fn write_field(writer: &mut dyn Write, field: &[u8]) -> Result<(), std::io::Error> {
    if field_needs_quotes(field) {
        writer.write_all(b"\"")?;
        write_escaped_bytes(writer, field)?;
        writer.write_all(b"\"")
    } else {
        writer.write_all(field)
    }
}

fn write_escaped_bytes(writer: &mut dyn Write, field: &[u8]) -> Result<(), std::io::Error> {
    let mut offset = 0;
    for (index, byte) in field.iter().enumerate() {
        if *byte == b'"' {
            writer.write_all(&field[offset..index])?;
            writer.write_all(b"\"\"")?;
            offset = index + 1;
        }
    }
    writer.write_all(&field[offset..])
}

fn tags_need_quotes(tags: &[ByteText]) -> bool {
    let Some(first) = tags.first() else {
        return false;
    };
    (tags.len() == 1 && first.as_bytes() == br"\.")
        // Joining a leading empty tag adds an initial space to the CSV field.
        || (tags.len() > 1 && first.is_empty())
        || first_rune_is_go_space(first.as_bytes())
        || tags.iter().any(|tag| {
            tag.as_bytes()
                .iter()
                .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'))
        })
}

fn field_needs_quotes(field: &[u8]) -> bool {
    if field.is_empty() {
        return false;
    }
    if field == br"\."
        || field
            .iter()
            .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'))
    {
        return true;
    }
    first_rune_is_go_space(field)
}

/// Whether the field starts with a valid UTF-8 white space character.
fn first_rune_is_go_space(field: &[u8]) -> bool {
    field
        .utf8_chunks()
        .next()
        .and_then(|chunk| chunk.valid().chars().next())
        .is_some_and(char::is_whitespace)
}
