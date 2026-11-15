//! Byte positions and read partitions are prescribed before scanner execution.

use super::{Fixture, Plant, STANDARD, interval, json, negative, pat};
use base64::Engine as _;

const ANCHORS: &[usize] = &[4_096, 65_536, 100_000, 125_000, 153_672, 182_344];

#[derive(Clone, Copy)]
pub(super) enum Layout {
    NoLf,
    Lf,
    Crlf,
    InvalidBytes,
}

impl Layout {
    const fn name(self) -> &'static str {
        match self {
            Self::NoLf => "no-lf",
            Self::Lf => "lf",
            Self::Crlf => "crlf",
            Self::InvalidBytes => "invalid-bytes",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Mutation {
    Positive,
    Prefix,
    InternalSeparator,
}

impl Mutation {
    const fn name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Prefix => "prefix-negative",
            Self::InternalSeparator => "internal-negative",
        }
    }
}

pub(super) fn boundary(
    anchor: usize,
    split: usize,
    encoded: bool,
    mutation: Mutation,
    layout: Layout,
) -> Fixture {
    let original = pat("boundary", anchor * 100 + split);
    let value = match mutation {
        Mutation::Positive => original,
        Mutation::Prefix => negative(original, true),
        Mutation::InternalSeparator => negative(original, false),
    };
    let token = if encoded {
        STANDARD.encode(&value).into_bytes()
    } else {
        value.clone()
    };
    assert!(split <= token.len() && anchor > split + 2);
    let start = anchor - split;
    let end = start + token.len();
    let mut input = vec![b' '; end + 64];
    match layout {
        Layout::NoLf => {}
        Layout::Lf => {
            for position in (63..input.len()).step_by(64) {
                input[position] = b'\n';
            }
            input[start - 1] = b'\n';
            input[end] = b'\n';
        }
        Layout::Crlf => {
            for position in (63..input.len()).step_by(64) {
                input[position - 1..=position].copy_from_slice(b"\r\n");
            }
            input[start - 2..start].copy_from_slice(b"\r\n");
            input[end..end + 2].copy_from_slice(b"\r\n");
        }
        Layout::InvalidBytes => {
            input[start - 1] = 0xff;
            input[end] = 0xfe;
        }
    }
    input[start..end].copy_from_slice(&token);
    let kind = if encoded { "base64" } else { "raw" };
    let id = format!(
        "boundary-{kind}-{anchor}-{split}-{}-{}",
        mutation.name(),
        layout.name()
    );
    let mut fixture = Fixture::plain(id, "systematic-boundaries", input);
    if matches!(mutation, Mutation::Positive) {
        let span = if encoded { 0..value.len() } else { start..end };
        fixture.plants.push(Plant {
            value: value.clone(),
            span: span.clone(),
            carrier: span,
        });
    }
    if encoded {
        fixture.layers.push(value);
        fixture.outer = Some(start..end);
    }
    fixture.details = json!({
        "anchor_byte": anchor,
        "split_offset_in_carrier": split,
        "carrier_bytes": interval(&(start..end)),
        "carrier_length": token.len(),
        "padding_split_probe": encoded && matches!(split, 54 | 55),
        "layout": layout.name(),
        "class": mutation.name(),
        "source_modes": ["file", "stdin"],
        "anchor_semantics": "prescribed-byte-anchor; actual-reader-fragment-boundaries-are-observations",
        "negative_contract": "mutated-prefix-or-internal-forbidden-separator; no-length-only-negatives",
    });
    fixture
}

pub(super) fn generate(emit: &mut impl FnMut(Fixture) -> Result<(), String>) -> Result<(), String> {
    for &anchor in ANCHORS {
        for encoded in [false, true] {
            let length = if encoded { 56 } else { 40 };
            for split in 0..=length {
                for mutation in [
                    Mutation::Positive,
                    Mutation::Prefix,
                    Mutation::InternalSeparator,
                ] {
                    emit(boundary(anchor, split, encoded, mutation, Layout::NoLf))?;
                }
            }
            // Separate neighbor slices preserve the full no-LF offset sweep.
            let splits: &[usize] = if encoded {
                &[0, 28, 54, 55, 56]
            } else {
                &[0, 20, 40]
            };
            for &split in splits {
                for layout in [Layout::Lf, Layout::Crlf, Layout::InvalidBytes] {
                    emit(boundary(anchor, split, encoded, Mutation::Positive, layout))?;
                }
            }
        }
    }
    Ok(())
}

/// Literal input partitioning is independent of source-reader buffering.
pub(super) fn partition(length: usize, schedule: &[usize]) -> Vec<std::ops::Range<usize>> {
    assert!(!schedule.is_empty() && !schedule.contains(&0));
    let mut result = Vec::new();
    let mut start = 0;
    for size in schedule.iter().cycle() {
        if start == length {
            break;
        }
        let end = start.saturating_add(*size).min(length);
        result.push(start..end);
        start = end;
    }
    result
}

pub(super) fn generate_partitions(
    emit: &mut impl FnMut(Fixture) -> Result<(), String>,
) -> Result<(), String> {
    for encoded in [false, true] {
        let mut fixture = boundary(
            4_096,
            if encoded { 55 } else { 20 },
            encoded,
            Mutation::Positive,
            Layout::NoLf,
        );
        fixture.id = format!(
            "reader-partitions-{}",
            if encoded { "base64" } else { "raw" }
        );
        fixture.family = "reader-partitions";
        let schedules: &[&[usize]] = &[&[1], &[2], &[7], &[4096], &[1, 3, 2, 7, 31, 64, 5]];
        fixture.details["reader_schedules"] = json!(
            schedules
                .iter()
                .map(|sizes| {
                    let partitions = partition(fixture.input.len(), sizes);
                    json!({
                        "cyclic_successful_read_sizes": sizes,
                        "partitions": partitions.iter().map(interval).collect::<Vec<_>>(),
                        "terminal_read": "zero-after-all-input-bytes",
                        "expected_status": "complete-with-exact-planted-occurrences",
                    })
                })
                .collect::<Vec<_>>()
        );
        fixture.details["error_schedules"] = json!([
            {"successful_bytes_before_error": 0, "terminal_read": "io-error", "expected_status": "incomplete"},
            {"successful_bytes_before_error": 4096, "terminal_read": "io-error", "expected_status": "incomplete"},
            {"successful_bytes_before_error": fixture.input.len(), "terminal_read": "io-error-instead-of-clean-eof", "expected_status": "incomplete"}
        ]);
        fixture.details["read_contract"] = json!(
            "Rust Read returns bytes or error per call; error-after-bytes means a subsequent call. Interrupted retries require a separate adapter test. A zero read is EOF, not an invented retryable no-progress signal."
        );
        emit(fixture)?;
    }
    Ok(())
}
