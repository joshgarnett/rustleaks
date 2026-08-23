use std::io::Write;

use rustleaks_core::model::{ByteText, CommitMetadata, Finding, Fragment};

use crate::ReportError;

pub(crate) fn write_findings(
    writer: &mut dyn Write,
    findings: &[Finding],
    indent: &[u8],
) -> Result<(), ReportError> {
    if findings.is_empty() {
        writer.write_all(b"[]")?;
        return Ok(());
    }
    writer.write_all(b"[\n")?;
    for (index, finding) in findings.iter().enumerate() {
        write_indent(writer, indent, 1)?;
        write_finding(writer, finding, indent, 1)?;
        if index + 1 != findings.len() {
            writer.write_all(b",")?;
        }
        writer.write_all(b"\n")?;
    }
    writer.write_all(b"]")?;
    Ok(())
}

pub(crate) fn write_finding(
    writer: &mut dyn Write,
    finding: &Finding,
    indent: &[u8],
    depth: usize,
) -> Result<(), ReportError> {
    let location = finding.location();
    let mut fields = 18_usize;
    fields += usize::from(!finding.link().is_empty());
    fields += usize::from(finding.fragment().is_some());
    let mut field = 0_usize;
    writer.write_all(b"{")?;

    macro_rules! member {
        ($name:literal, $body:expr) => {{
            field += 1;
            writer.write_all(b"\n")?;
            write_indent(writer, indent, depth + 1)?;
            writer.write_all(concat!("\"", $name, "\": ").as_bytes())?;
            $body?;
            if field != fields {
                writer.write_all(b",")?;
            }
        }};
    }

    member!("RuleID", write_string(writer, finding.rule_id().as_bytes()));
    member!(
        "Description",
        write_string(writer, finding.description().as_bytes())
    );
    member!("StartLine", write_usize(writer, location.start_line()));
    member!("EndLine", write_usize(writer, location.end_line()));
    member!("StartColumn", write_usize(writer, location.start_column()));
    member!("EndColumn", write_usize(writer, location.end_column()));
    member!(
        "Match",
        write_string(writer, finding.match_text().as_bytes())
    );
    member!("Secret", write_string(writer, finding.secret().as_bytes()));
    member!("File", write_string(writer, finding.file().as_bytes()));
    member!(
        "SymlinkFile",
        write_string(writer, finding.symlink_file().as_bytes())
    );
    member!("Commit", write_string(writer, finding.commit().as_bytes()));
    if !finding.link().is_empty() {
        member!("Link", write_string(writer, finding.link().as_bytes()));
    }
    member!("Entropy", write_float32(writer, finding.entropy()));
    member!("Author", write_string(writer, finding.author().as_bytes()));
    member!("Email", write_string(writer, finding.email().as_bytes()));
    member!("Date", write_string(writer, finding.date().as_bytes()));
    member!(
        "Message",
        write_string(writer, finding.message().as_bytes())
    );
    member!(
        "Tags",
        write_strings(writer, finding.tags(), indent, depth + 1)
    );
    member!(
        "Fingerprint",
        write_string(writer, finding.fingerprint().as_bytes())
    );
    if let Some(fragment) = finding.fragment() {
        member!(
            "Fragment",
            write_fragment(writer, fragment, indent, depth + 1)
        );
    }

    writer.write_all(b"\n")?;
    write_indent(writer, indent, depth)?;
    writer.write_all(b"}")?;
    Ok(())
}

fn write_fragment(
    writer: &mut dyn Write,
    fragment: &Fragment,
    indent: &[u8],
    depth: usize,
) -> Result<(), ReportError> {
    writer.write_all(b"{")?;
    let mut member =
        |name: &[u8],
         comma: bool,
         value: &mut dyn FnMut(&mut dyn Write) -> Result<(), ReportError>| {
            writer.write_all(b"\n")?;
            write_indent(writer, indent, depth + 1)?;
            write_string(writer, name)?;
            writer.write_all(b": ")?;
            value(writer)?;
            if comma {
                writer.write_all(b",")?;
            }
            Ok::<(), ReportError>(())
        };
    member(b"Raw", true, &mut |w| {
        write_string(w, fragment.content().as_bytes())
    })?;
    member(b"Bytes", true, &mut |w| Ok(w.write_all(b"null")?))?;
    member(b"FilePath", true, &mut |w| {
        write_string(w, fragment.file_path().as_bytes())
    })?;
    member(b"SymlinkFile", true, &mut |w| {
        write_string(w, fragment.symlink_file().as_bytes())
    })?;
    member(b"CommitSHA", true, &mut |w| {
        write_string(w, fragment.commit().as_bytes())
    })?;
    member(b"StartLine", true, &mut |w| {
        write_usize(w, fragment.start_line())
    })?;
    member(
        b"CommitInfo",
        true,
        &mut |w| match fragment.commit_metadata() {
            Some(metadata) => write_commit_metadata(w, metadata, indent, depth + 1),
            None => Ok(w.write_all(b"null")?),
        },
    )?;
    member(b"InheritedFromFinding", false, &mut |w| {
        Ok(w.write_all(if fragment.inherited_from_finding() {
            b"true"
        } else {
            b"false"
        })?)
    })?;
    writer.write_all(b"\n")?;
    write_indent(writer, indent, depth)?;
    Ok(writer.write_all(b"}")?)
}

fn write_commit_metadata(
    writer: &mut dyn Write,
    metadata: &CommitMetadata,
    indent: &[u8],
    depth: usize,
) -> Result<(), ReportError> {
    let values: [(&[u8], Option<&ByteText>); 6] = [
        (b"AuthorEmail", Some(metadata.author_email())),
        (b"AuthorName", Some(metadata.author_name())),
        (b"Date", Some(metadata.date())),
        (b"Message", Some(metadata.message())),
        (b"Remote", None),
        (b"SHA", Some(metadata.sha())),
    ];
    writer.write_all(b"{")?;
    for (index, (name, value)) in values.iter().enumerate() {
        writer.write_all(b"\n")?;
        write_indent(writer, indent, depth + 1)?;
        write_string(writer, name)?;
        writer.write_all(b": ")?;
        if let Some(value) = value {
            write_string(writer, value.as_bytes())?;
        } else {
            writer.write_all(b"null")?;
        }
        if index + 1 != values.len() {
            writer.write_all(b",")?;
        }
    }
    writer.write_all(b"\n")?;
    write_indent(writer, indent, depth)?;
    Ok(writer.write_all(b"}")?)
}

fn write_strings(
    writer: &mut dyn Write,
    values: &[ByteText],
    indent: &[u8],
    depth: usize,
) -> Result<(), ReportError> {
    if values.is_empty() {
        return Ok(writer.write_all(b"[]")?);
    }
    writer.write_all(b"[\n")?;
    for (index, value) in values.iter().enumerate() {
        write_indent(writer, indent, depth + 1)?;
        write_string(writer, value.as_bytes())?;
        if index + 1 != values.len() {
            writer.write_all(b",")?;
        }
        writer.write_all(b"\n")?;
    }
    write_indent(writer, indent, depth)?;
    Ok(writer.write_all(b"]")?)
}

fn write_usize(writer: &mut dyn Write, value: usize) -> Result<(), ReportError> {
    Ok(write!(writer, "{value}")?)
}

fn write_float32(writer: &mut dyn Write, value: f32) -> Result<(), ReportError> {
    if !value.is_finite() {
        return Err(ReportError::NonFiniteEntropy(value));
    }
    let formatted = go_float32(value);
    Ok(writer.write_all(formatted.as_bytes())?)
}

fn go_float32(value: f32) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0".to_owned()
        } else {
            "0".to_owned()
        };
    }
    let shortest = value.to_string();
    let shortest = shortest.as_str();
    let negative = shortest.starts_with('-');
    let unsigned = shortest.strip_prefix('-').unwrap_or(shortest);
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0_i32), |(mantissa, exponent)| {
            (mantissa, exponent.parse::<i32>().unwrap_or(0))
        });
    let decimal = mantissa.find('.').unwrap_or(mantissa.len());
    let mut digits = mantissa
        .bytes()
        .filter(|byte| *byte != b'.')
        .collect::<Vec<_>>();
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
    }
    let leading = digits.iter().position(|byte| *byte != b'0').unwrap_or(0);
    let decimal_position = i32::try_from(decimal).unwrap_or(i32::MAX) + exponent
        - i32::try_from(leading).unwrap_or(i32::MAX);
    if leading != 0 {
        digits.drain(..leading);
    }

    let use_exponent = value.abs() < 1e-6_f32 || value.abs() >= 1e21_f32;
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if use_exponent {
        output.push(char::from(digits[0]));
        if digits.len() > 1 {
            output.push('.');
            output.extend(digits[1..].iter().map(|byte| char::from(*byte)));
        }
        let scientific_exponent = decimal_position - 1;
        output.push('e');
        if scientific_exponent >= 0 {
            output.push('+');
        }
        output.push_str(&scientific_exponent.to_string());
        return output;
    }
    if decimal_position <= 0 {
        output.push_str("0.");
        for _ in decimal_position..0 {
            output.push('0');
        }
        output.extend(digits.iter().map(|byte| char::from(*byte)));
    } else if usize::try_from(decimal_position).unwrap_or(usize::MAX) >= digits.len() {
        output.extend(digits.iter().map(|byte| char::from(*byte)));
        for _ in digits.len()..usize::try_from(decimal_position).unwrap_or(digits.len()) {
            output.push('0');
        }
    } else {
        let decimal_position = usize::try_from(decimal_position).unwrap_or(0);
        output.extend(
            digits[..decimal_position]
                .iter()
                .map(|byte| char::from(*byte)),
        );
        output.push('.');
        output.extend(
            digits[decimal_position..]
                .iter()
                .map(|byte| char::from(*byte)),
        );
    }
    output
}

pub(crate) fn write_indent(
    writer: &mut dyn Write,
    indent: &[u8],
    depth: usize,
) -> Result<(), std::io::Error> {
    for _ in 0..depth {
        writer.write_all(indent)?;
    }
    Ok(())
}

pub(crate) fn write_string(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), ReportError> {
    writer.write_all(b"\"")?;
    write_string_body(writer, bytes)?;
    Ok(writer.write_all(b"\"")?)
}

pub(crate) fn write_string_body(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), ReportError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if byte < 0x80 {
            match byte {
                b'"' | b'\\' => writer.write_all(&[b'\\', byte])?,
                b'\x08' => writer.write_all(b"\\b")?,
                b'\x0c' => writer.write_all(b"\\f")?,
                b'\n' => writer.write_all(b"\\n")?,
                b'\r' => writer.write_all(b"\\r")?,
                b'\t' => writer.write_all(b"\\t")?,
                b'<' => writer.write_all(b"\\u003c")?,
                b'>' => writer.write_all(b"\\u003e")?,
                b'&' => writer.write_all(b"\\u0026")?,
                0x00..=0x1f => write!(writer, "\\u{byte:04x}")?,
                _ => writer.write_all(&[byte])?,
            }
            offset += 1;
            continue;
        }
        let width = utf8_width(byte);
        if width == 0 || offset + width > bytes.len() {
            writer.write_all(b"\\ufffd")?;
            offset += 1;
            continue;
        }
        let candidate = &bytes[offset..offset + width];
        match std::str::from_utf8(candidate)
            .ok()
            .and_then(|text| text.chars().next())
        {
            Some('\u{2028}') => writer.write_all(b"\\u2028")?,
            Some('\u{2029}') => writer.write_all(b"\\u2029")?,
            Some(_) => writer.write_all(candidate)?,
            None => {
                writer.write_all(b"\\ufffd")?;
                offset += 1;
                continue;
            }
        }
        offset += width;
    }
    Ok(())
}

const fn utf8_width(first: u8) -> usize {
    match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::go_float32;

    #[test]
    fn float32_format_uses_go_json_cutoffs_and_sign() {
        assert_eq!(go_float32(0.0), "0");
        assert_eq!(go_float32(-0.0), "-0");
        assert_eq!(go_float32(3.5), "3.5");
        assert_eq!(go_float32(1e-6_f32), "0.000001");
        assert_eq!(go_float32(1e21_f32), "1e+21");
        assert_eq!(go_float32(f32::from_bits(1)), "1e-45");
        assert_eq!(go_float32(f32::MAX), "3.4028235e+38");
        assert_eq!(go_float32(16_777_216.0), "16777216");
    }
}
