use std::io::Write;

use rustleaks_core::model::Finding;

use crate::go_json;
use crate::{ReportError, Reporter};

/// Upstream-compatible `JUnit` XML report writer.
#[derive(Clone, Copy, Debug, Default)]
pub struct JunitReporter;

impl Reporter for JunitReporter {
    fn write(&self, writer: &mut dyn Write, findings: &[Finding]) -> Result<(), ReportError> {
        if let Some(finding) = findings
            .iter()
            .find(|finding| !finding.entropy().is_finite())
        {
            return Err(ReportError::NonFiniteEntropy(finding.entropy()));
        }
        writer.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n")?;
        write!(
            writer,
            "\t<testsuite failures=\"{}\" name=\"gitleaks\" tests=\"{}\" time=\"\">",
            findings.len(),
            findings.len()
        )?;
        if findings.is_empty() {
            writer.write_all(b"</testsuite>\n</testsuites>")?;
            return Ok(());
        }
        writer.write_all(b"\n")?;
        for finding in findings {
            writer.write_all(b"\t\t<testcase classname=\"")?;
            write_xml(writer, finding.description().as_bytes())?;
            writer.write_all(b"\" file=\"")?;
            write_xml(writer, finding.file().as_bytes())?;
            writer.write_all(b"\" name=\"")?;
            write_message_xml(writer, finding)?;
            writer.write_all(b"\" time=\"\">\n\t\t\t<failure message=\"")?;
            write_message_xml(writer, finding)?;
            writer.write_all(b"\" type=\"")?;
            write_xml(writer, finding.description().as_bytes())?;
            writer.write_all(b"\">")?;
            {
                let mut escaped = XmlEscapingWriter { inner: writer };
                go_json::write_finding(&mut escaped, finding, b"\t", 0)?;
            }
            writer.write_all(b"</failure>\n\t\t</testcase>\n")?;
        }
        writer.write_all(b"\t</testsuite>\n</testsuites>")?;
        Ok(())
    }
}

fn write_message_xml(writer: &mut dyn Write, finding: &Finding) -> Result<(), std::io::Error> {
    write_xml(writer, finding.rule_id().as_bytes())?;
    writer.write_all(b" has detected a secret in file ")?;
    write_xml(writer, finding.file().as_bytes())?;
    write!(writer, ", line {}", finding.location().start_line())?;
    if finding.commit().is_empty() {
        writer.write_all(b".")?;
    } else {
        writer.write_all(b", at commit ")?;
        write_xml(writer, finding.commit().as_bytes())?;
        writer.write_all(b".")?;
    }
    Ok(())
}

struct XmlEscapingWriter<'a> {
    inner: &'a mut dyn Write,
}

impl Write for XmlEscapingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, std::io::Error> {
        write_xml(self.inner, bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.inner.flush()
    }
}

fn write_xml(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if byte < 0x80 {
            match byte {
                b'&' => writer.write_all(b"&amp;")?,
                b'<' => writer.write_all(b"&lt;")?,
                b'>' => writer.write_all(b"&gt;")?,
                b'\'' => writer.write_all(b"&#39;")?,
                b'"' => writer.write_all(b"&#34;")?,
                b'\t' => writer.write_all(b"&#x9;")?,
                b'\n' => writer.write_all(b"&#xA;")?,
                b'\r' => writer.write_all(b"&#xD;")?,
                0x00..=0x1f | 0x7f => writer.write_all("\u{fffd}".as_bytes())?,
                _ => writer.write_all(&[byte])?,
            }
            offset += 1;
            continue;
        }
        let width = match byte {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let candidate = bytes.get(offset..offset.saturating_add(width));
        let valid = candidate
            .and_then(|part| std::str::from_utf8(part).ok())
            .and_then(|text| text.chars().next())
            .filter(|value| is_xml_character(*value));
        if let (Some(part), Some(_)) = (candidate, valid) {
            writer.write_all(part)?;
            offset += width;
        } else {
            writer.write_all("\u{fffd}".as_bytes())?;
            offset += 1;
        }
    }
    Ok(())
}

const fn is_xml_character(value: char) -> bool {
    matches!(value, '\u{0080}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
