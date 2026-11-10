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

/// Holds the longest `f32` `Display` text, a sign, `0.`, up to 44 zeros, and the
/// significant digits, and the shorter Go rendering derived from it.
const FLOAT32_TEXT_CAPACITY: usize = 64;

fn write_float32(writer: &mut dyn Write, value: f32) -> Result<(), ReportError> {
    if !value.is_finite() {
        return Err(ReportError::NonFiniteEntropy(value));
    }
    let mut text = [0_u8; FLOAT32_TEXT_CAPACITY];
    let mut unused = text.as_mut_slice();
    go_float32(&mut unused, value)?;
    let length = FLOAT32_TEXT_CAPACITY - unused.len();
    Ok(writer.write_all(&text[..length])?)
}

fn go_float32(output: &mut dyn Write, value: f32) -> Result<(), std::io::Error> {
    if value == 0.0 {
        return output.write_all(if value.is_sign_negative() {
            b"-0"
        } else {
            b"0"
        });
    }
    let mut shortest_text = [0_u8; FLOAT32_TEXT_CAPACITY];
    let mut unused = shortest_text.as_mut_slice();
    write!(unused, "{value}")?;
    let length = FLOAT32_TEXT_CAPACITY - unused.len();
    let shortest = std::str::from_utf8(&shortest_text[..length]).map_err(std::io::Error::other)?;
    let negative = shortest.starts_with('-');
    let unsigned = shortest.strip_prefix('-').unwrap_or(shortest);
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0_i32), |(mantissa, exponent)| {
            (mantissa, exponent.parse::<i32>().unwrap_or(0))
        });
    let decimal = mantissa.find('.').unwrap_or(mantissa.len());
    let mut digit_text = [0_u8; FLOAT32_TEXT_CAPACITY];
    let digit_count = digit_text
        .iter_mut()
        .zip(mantissa.bytes().filter(|byte| *byte != b'.'))
        .fold(0_usize, |count, (slot, byte)| {
            *slot = byte;
            count + 1
        });
    let mut digits = &digit_text[..digit_count];
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits = &digits[..digits.len() - 1];
    }
    let leading = digits.iter().position(|byte| *byte != b'0').unwrap_or(0);
    let decimal_position = i32::try_from(decimal).unwrap_or(i32::MAX) + exponent
        - i32::try_from(leading).unwrap_or(i32::MAX);
    let digits = &digits[leading..];

    let use_exponent = value.abs() < 1e-6_f32 || value.abs() >= 1e21_f32;
    if negative {
        output.write_all(b"-")?;
    }
    if use_exponent {
        output.write_all(&digits[..1])?;
        if digits.len() > 1 {
            output.write_all(b".")?;
            output.write_all(&digits[1..])?;
        }
        let scientific_exponent = decimal_position - 1;
        output.write_all(b"e")?;
        if scientific_exponent >= 0 {
            output.write_all(b"+")?;
        }
        return write!(output, "{scientific_exponent}");
    }
    if decimal_position <= 0 {
        output.write_all(b"0.")?;
        for _ in decimal_position..0 {
            output.write_all(b"0")?;
        }
        output.write_all(digits)?;
    } else if usize::try_from(decimal_position).unwrap_or(usize::MAX) >= digits.len() {
        output.write_all(digits)?;
        for _ in digits.len()..usize::try_from(decimal_position).unwrap_or(digits.len()) {
            output.write_all(b"0")?;
        }
    } else {
        let decimal_position = usize::try_from(decimal_position).unwrap_or(0);
        output.write_all(&digits[..decimal_position])?;
        output.write_all(b".")?;
        output.write_all(&digits[decimal_position..])?;
    }
    Ok(())
}

const INDENT_RUN_LEN: usize = 64;
static SPACE_RUN: [u8; INDENT_RUN_LEN] = [b' '; INDENT_RUN_LEN];
static TAB_RUN: [u8; INDENT_RUN_LEN] = [b'\t'; INDENT_RUN_LEN];

pub(crate) fn write_indent(
    writer: &mut dyn Write,
    indent: &[u8],
    depth: usize,
) -> Result<(), std::io::Error> {
    let run: &[u8] = match indent {
        b" " => &SPACE_RUN,
        b"\t" => &TAB_RUN,
        _ => {
            for _ in 0..depth {
                writer.write_all(indent)?;
            }
            return Ok(());
        }
    };
    let mut remaining = depth;
    while remaining > 0 {
        let count = remaining.min(run.len());
        writer.write_all(&run[..count])?;
        remaining -= count;
    }
    Ok(())
}

pub(crate) fn write_string(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), ReportError> {
    writer.write_all(b"\"")?;
    write_string_body(writer, bytes)?;
    Ok(writer.write_all(b"\"")?)
}

/// Bytes that `write_string_body` cannot copy without further inspection: JSON
/// escapes, Go's HTML-safe escapes, and every byte that is not ASCII. All other
/// bytes, including 0x7f, are copied verbatim.
const NEEDS_INSPECTION: [bool; 256] = needs_inspection_table();

const fn needs_inspection_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut index = 0;
    while index < table.len() {
        table[index] = index < 0x20 || index >= 0x80;
        index += 1;
    }
    table[b'"' as usize] = true;
    table[b'\\' as usize] = true;
    table[b'<' as usize] = true;
    table[b'>' as usize] = true;
    table[b'&' as usize] = true;
    table
}

pub(crate) fn write_string_body(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), ReportError> {
    // `bytes[run_start..offset]` is pending verbatim output. It is written as
    // one slice before each replacement and at the end of the input.
    let mut run_start = 0;
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if !NEEDS_INSPECTION[usize::from(byte)] {
            offset += 1;
            continue;
        }
        if byte >= 0x80 {
            let (replacement, consumed) = non_ascii_replacement(&bytes[offset..]);
            if let Some(replacement) = replacement {
                write_run(writer, &bytes[run_start..offset])?;
                writer.write_all(replacement)?;
                run_start = offset + consumed;
            }
            offset += consumed;
            continue;
        }
        write_run(writer, &bytes[run_start..offset])?;
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
        run_start = offset;
    }
    write_run(writer, &bytes[run_start..])?;
    Ok(())
}

fn write_run(writer: &mut dyn Write, run: &[u8]) -> Result<(), std::io::Error> {
    if run.is_empty() {
        return Ok(());
    }
    writer.write_all(run)
}

/// Classifies the non-ASCII input at the start of `bytes`, returning its
/// replacement, or `None` to copy it, and the input bytes consumed.
fn non_ascii_replacement(bytes: &[u8]) -> (Option<&'static [u8]>, usize) {
    let width = bytes.first().copied().map_or(0, utf8_width);
    if width == 0 || width > bytes.len() {
        return (Some(b"\\ufffd"), 1);
    }
    match std::str::from_utf8(&bytes[..width])
        .ok()
        .and_then(|text| text.chars().next())
    {
        Some('\u{2028}') => (Some(b"\\u2028"), width),
        Some('\u{2029}') => (Some(b"\\u2029"), width),
        Some(_) => (None, width),
        None => (Some(b"\\ufffd"), 1),
    }
}

const fn utf8_width(first: u8) -> usize {
    match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    }
}

/// The per-byte writers and allocating float formatter replaced by run-based
/// and stack-based output, retained verbatim as the oracle for byte equivalence,
/// with the adversarial inputs they are compared on.
#[cfg(test)]
pub(crate) mod reference {
    use std::io::Write;

    use crate::ReportError;

    const CASES: &[&[u8]] = &[
        b"",
        b"plain ascii",
        b"\x7f",
        b"<>&\"\\\x08\x0c\n\r\t\x00\x01\x1f",
        "\u{80}\u{7ff}\u{800}\u{ffff}\u{10000}\u{10ffff}".as_bytes(),
        "\u{2027}\u{2028}\u{2029}\u{202a}".as_bytes(),
        "\u{d7ff}\u{e000}\u{fffd}\u{fffe}\u{ffff}".as_bytes(),
        b"\xe2",
        b"\xe2\x80",
        b"\xe2\x80\xa8\xe2",
        b"\xf0",
        b"\xf0\x9f",
        b"\xf0\x9f\x98",
        b"\xc3",
        b"\xc0\x80",
        b"\xc1\xbf",
        b"\xe0\x80\x80",
        b"\xe0\x9f\xbf",
        b"\xed\xa0\x80",
        b"\xed\xbf\xbf",
        b"\xf0\x80\x80\x80",
        b"\xf0\x8f\xbf\xbf",
        b"\xf4\x90\x80\x80",
        b"\xf5\x80\x80\x80",
        b"\x80\xbf\x80",
        b"\xfe\xff",
    ];

    pub(crate) fn allocating_go_float32(value: f32) -> String {
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

    pub(crate) fn per_depth_write_indent(
        writer: &mut dyn Write,
        indent: &[u8],
        depth: usize,
    ) -> Result<(), std::io::Error> {
        for _ in 0..depth {
            writer.write_all(indent)?;
        }
        Ok(())
    }

    pub(crate) fn per_byte_write_string_body(
        writer: &mut dyn Write,
        bytes: &[u8],
    ) -> Result<(), ReportError> {
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
            let width = match byte {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => 0,
            };
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

    /// Fixed cases and their pairwise concatenations: escapes, UTF-8 width and
    /// range boundaries, truncation, overlong forms, surrogates, and stray bytes.
    pub(crate) fn adversarial_inputs() -> Vec<Vec<u8>> {
        let mut inputs: Vec<Vec<u8>> = CASES.iter().map(|case| case.to_vec()).collect();
        for first in CASES {
            for second in CASES {
                inputs.push([*first, *second].concat());
            }
        }
        inputs
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::reference::{
        adversarial_inputs, allocating_go_float32, per_byte_write_string_body,
        per_depth_write_indent,
    };
    use super::{
        FLOAT32_TEXT_CAPACITY, NEEDS_INSPECTION, write_float32, write_indent, write_string_body,
    };
    use crate::ReportError;

    /// Bytes that combine into every UTF-8 boundary and escape class.
    const INTERESTING: &[u8] =
        b"a<>&\"\\\n\x00\x08\x1f\x7f\x80\x9f\xa0\xa8\xa9\xbf\xc0\xc2\xe0\xe2\xed\xf0\xf4\xf5\xff";

    fn go_float32(value: f32) -> String {
        let mut output = Vec::new();
        super::go_float32(&mut output, value).unwrap();
        String::from_utf8(output).unwrap()
    }

    fn assert_float32_matches_reference(value: f32) {
        if !value.is_finite() {
            return;
        }
        let expected = allocating_go_float32(value);
        let bits = value.to_bits();
        assert_eq!(go_float32(value), expected, "bits {bits:#010x}");
        let mut written = Vec::new();
        write_float32(&mut written, value).unwrap();
        assert_eq!(written, expected.as_bytes(), "bits {bits:#010x}");
        let negated = -value;
        assert_eq!(
            go_float32(negated),
            allocating_go_float32(negated),
            "bits {bits:#010x} negated"
        );
    }

    fn body(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        write_string_body(&mut output, input).unwrap();
        output
    }

    fn reference_body(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        per_byte_write_string_body(&mut output, input).unwrap();
        output
    }

    fn assert_matches_reference(input: &[u8]) {
        assert_eq!(body(input), reference_body(input), "input {input:02x?}");
    }

    #[derive(Default)]
    struct RecordingWriter {
        writes: Vec<Vec<u8>>,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct LimitedWriter {
        bytes: Vec<u8>,
        remaining: usize,
    }

    impl LimitedWriter {
        const fn new(remaining: usize) -> Self {
            Self {
                bytes: Vec::new(),
                remaining,
            }
        }
    }

    impl Write for LimitedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected writer failure"));
            }
            let count = bytes.len().min(self.remaining);
            self.bytes.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn inspection_table_marks_exactly_the_transformed_bytes() {
        for byte in 0_u8..=255 {
            let expected =
                !(0x20..0x80).contains(&byte) || matches!(byte, b'"' | b'\\' | b'<' | b'>' | b'&');
            assert_eq!(NEEDS_INSPECTION[usize::from(byte)], expected, "{byte:#04x}");
        }
    }

    #[test]
    fn string_body_applies_the_documented_escapes() {
        let cases: [(&[u8], &[u8]); 16] = [
            (b"", b""),
            (b"plain \x7f", b"plain \x7f"),
            (b"\"\\", br#"\"\\"#),
            (b"\x08\x0c\n\r\t", br"\b\f\n\r\t"),
            (b"\x00\x01\x1f", br"\u0000\u0001\u001f"),
            (b"<>&", b"\\u003c\\u003e\\u0026"),
            ("\u{2028}".as_bytes(), b"\\u2028"),
            ("\u{2029}".as_bytes(), b"\\u2029"),
            (
                "\u{e9}\u{20ac}\u{1f600}".as_bytes(),
                "\u{e9}\u{20ac}\u{1f600}".as_bytes(),
            ),
            (b"\xff", b"\\ufffd"),
            (b"\xc0\x80", b"\\ufffd\\ufffd"),
            (b"\xe2\x80", b"\\ufffd\\ufffd"),
            (b"\xed\xa0\x80", b"\\ufffd\\ufffd\\ufffd"),
            (b"\xf4\x90\x80\x80", b"\\ufffd\\ufffd\\ufffd\\ufffd"),
            (b"a\xffb", b"a\\ufffdb"),
            (
                "a\u{2028}\u{e9}<".as_bytes(),
                "a\\u2028\u{e9}\\u003c".as_bytes(),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(body(input), expected, "input {input:02x?}");
        }
    }

    #[test]
    fn string_body_matches_the_per_byte_writer_on_all_byte_pairs() {
        for first in 0_u8..=255 {
            assert_matches_reference(&[first]);
            for second in 0_u8..=255 {
                assert_matches_reference(&[first, second]);
            }
        }
    }

    #[test]
    fn string_body_matches_the_per_byte_writer_on_every_scalar() {
        let mut encoded = [0_u8; 4];
        for value in (0..=0xd7ff).chain(0xe000..=0x10_ffff) {
            let scalar = char::from_u32(value).unwrap().encode_utf8(&mut encoded);
            assert_matches_reference(scalar.as_bytes());
            assert_matches_reference(format!("a{scalar}<").as_bytes());
        }
    }

    #[test]
    fn string_body_matches_the_per_byte_writer_on_boundary_combinations() {
        for &first in INTERESTING {
            for &second in INTERESTING {
                for &third in INTERESTING {
                    for &fourth in INTERESTING {
                        assert_matches_reference(&[first, second, third, fourth]);
                    }
                }
            }
        }
    }

    #[test]
    fn string_body_matches_the_per_byte_writer_on_adversarial_strings() {
        for input in adversarial_inputs() {
            assert_matches_reference(&input);
        }
    }

    #[test]
    fn string_body_matches_the_per_byte_writer_on_seeded_sequences() {
        let mut state = 0x9e37_79b9_u32;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize
        };
        for _ in 0..20_000 {
            let length = next() % 96;
            let input = (0..length)
                .map(|_| INTERESTING[next() % INTERESTING.len()])
                .collect::<Vec<_>>();
            assert_matches_reference(&input);
        }
    }

    #[test]
    fn string_body_writes_each_verbatim_run_as_one_slice() {
        let cases: [(&[u8], &[&[u8]]); 6] = [
            (b"", &[]),
            (b"plain ascii", &[b"plain ascii"]),
            (
                "\u{e9}\u{20ac}\u{1f600}x".as_bytes(),
                &["\u{e9}\u{20ac}\u{1f600}x".as_bytes()],
            ),
            (b"ab<cd", &[b"ab", b"\\u003c", b"cd"]),
            ("a\u{2028}b".as_bytes(), &[b"a", b"\\u2028", b"b"]),
            (b"a\xffb\n", &[b"a", b"\\ufffd", b"b", br"\n"]),
        ];
        for (input, expected) in cases {
            let mut writer = RecordingWriter::default();
            write_string_body(&mut writer, input).unwrap();
            assert_eq!(writer.writes, expected, "input {input:02x?}");
        }
    }

    #[test]
    fn string_body_keeps_the_per_byte_prefix_on_destination_failure() {
        let input = "ab<cd\u{2028}ef\u{e9}\u{1f600}\n\x01gh".as_bytes();
        let complete = reference_body(input);
        for limit in 0..complete.len() {
            let mut current = LimitedWriter::new(limit);
            let mut reference = LimitedWriter::new(limit);
            assert!(write_string_body(&mut current, input).is_err(), "{limit}");
            assert!(
                per_byte_write_string_body(&mut reference, input).is_err(),
                "{limit}"
            );
            assert_eq!(current.bytes, reference.bytes, "{limit}");
            assert_eq!(current.bytes, complete[..limit], "{limit}");
        }
    }

    #[test]
    fn indent_repeats_the_indent_at_every_depth() {
        let indents: [&[u8]; 8] = [b"", b" ", b"\t", b"  ", b"\t\t", b"\t ", b"ab", b"\x00"];
        for depth in (0..=200).chain([255, 256, 257, 1_000, 4_096]) {
            for indent in indents {
                let mut output = Vec::new();
                write_indent(&mut output, indent, depth).unwrap();
                assert_eq!(output, indent.repeat(depth), "{indent:?} x {depth}");

                let mut reference = Vec::new();
                per_depth_write_indent(&mut reference, indent, depth).unwrap();
                assert_eq!(output, reference, "{indent:?} x {depth}");
            }
        }
    }

    #[test]
    fn indent_writes_static_runs_and_splits_beyond_their_length() {
        let cases: [(usize, &[usize]); 7] = [
            (0, &[]),
            (1, &[1]),
            (63, &[63]),
            (64, &[64]),
            (65, &[64, 1]),
            (128, &[64, 64]),
            (129, &[64, 64, 1]),
        ];
        for indent in [b" ", b"\t"] {
            for (depth, expected) in cases {
                let mut writer = RecordingWriter::default();
                write_indent(&mut writer, indent, depth).unwrap();
                let lengths = writer.writes.iter().map(Vec::len).collect::<Vec<_>>();
                assert_eq!(lengths, expected, "{indent:?} x {depth}");
                assert_eq!(writer.writes.concat(), indent.repeat(depth));
            }
        }
    }

    #[test]
    fn indent_keeps_the_per_depth_prefix_on_destination_failure() {
        for (indent, depth) in [(&b" "[..], 70), (&b"\t"[..], 70), (&b"ab"[..], 40)] {
            let complete = indent.repeat(depth);
            for limit in 0..complete.len() {
                let mut current = LimitedWriter::new(limit);
                assert!(
                    write_indent(&mut current, indent, depth).is_err(),
                    "{limit}"
                );
                assert_eq!(current.bytes, complete[..limit], "{limit}");
            }
        }
    }

    #[test]
    fn float32_matches_the_allocating_formatter_across_the_bit_space() {
        for bits in (0..=u32::MAX).step_by(65_521) {
            assert_float32_matches_reference(f32::from_bits(bits));
        }
    }

    #[test]
    fn float32_matches_the_allocating_formatter_near_decimal_boundaries() {
        for exponent in -45..=38 {
            let center = 10_f32.powi(exponent).to_bits();
            for offset in 0..=128 {
                assert_float32_matches_reference(f32::from_bits(center.saturating_add(offset)));
                assert_float32_matches_reference(f32::from_bits(center.saturating_sub(offset)));
            }
        }
        for cutoff in [1e-6_f32, 1e21_f32, f32::MIN_POSITIVE, f32::MAX] {
            let center = cutoff.to_bits();
            for offset in 0..=4_096 {
                assert_float32_matches_reference(f32::from_bits(center.saturating_add(offset)));
                assert_float32_matches_reference(f32::from_bits(center.saturating_sub(offset)));
            }
        }
        for bits in 0..=4_096 {
            assert_float32_matches_reference(f32::from_bits(bits));
        }
    }

    #[test]
    fn float32_matches_the_allocating_formatter_on_entropy_values() {
        for step in 0_u16..=32_768 {
            assert_float32_matches_reference(f32::from(step) / 4_096.0);
        }
    }

    #[test]
    fn float32_rejects_non_finite_values_before_writing() {
        let mut output = Vec::new();
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert!(matches!(
                write_float32(&mut output, value),
                Err(ReportError::NonFiniteEntropy(_))
            ));
        }
        assert!(output.is_empty());
    }

    #[test]
    fn float32_text_capacity_exceeds_the_longest_display_form() {
        let longest = [f32::MIN_POSITIVE, f32::from_bits(1), f32::MAX]
            .iter()
            .map(|value| (-value).to_string().len())
            .max()
            .unwrap();
        assert!(longest < FLOAT32_TEXT_CAPACITY, "{longest}");
    }

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
