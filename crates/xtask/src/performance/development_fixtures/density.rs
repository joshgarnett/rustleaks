//! Matched density pairs and many plaintext values sharing one encoded span.

use base64::Engine as _;

use super::{Fixture, Plant, STANDARD, json, negative, pat};

const SIZES: &[usize] = &[32_768, 131_072, 524_288, 2_097_152];
const INNER_COUNTS: &[usize] = &[1, 16, 256, 4_096];
const RECORD_BYTES: usize = 64;

#[derive(Clone, Copy)]
pub(super) enum Density {
    Positive,
    Alternating,
    Negative,
}

impl Density {
    const fn name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Alternating => "alternating",
            Self::Negative => "negative",
        }
    }

    const fn accepts(self, ordinal: usize) -> bool {
        match self {
            Self::Positive => true,
            Self::Alternating => ordinal.is_multiple_of(2),
            Self::Negative => false,
        }
    }
}

pub(super) fn dense(size: usize, density: Density, repeated: bool, lf: bool) -> Fixture {
    assert!(size.is_multiple_of(RECORD_BYTES));
    let mut input = Vec::with_capacity(size);
    let mut plants = Vec::new();
    for ordinal in 0..size / RECORD_BYTES {
        let value = pat("density", if repeated { 0 } else { ordinal });
        let value = if density.accepts(ordinal) {
            value
        } else {
            negative(value, false)
        };
        input.extend_from_slice(b"{\"value\":\"");
        let start = input.len();
        input.extend_from_slice(&value);
        let end = input.len();
        input.extend_from_slice(b"\"}");
        input.resize((ordinal + 1) * RECORD_BYTES - 1, b' ');
        input.push(if lf { b'\n' } else { b' ' });
        if density.accepts(ordinal) {
            plants.push(Plant {
                value,
                span: start..end,
                carrier: start..end,
            });
        }
    }
    let id = format!(
        "dense-{size}-{}-{}-{}",
        density.name(),
        if repeated { "repeated" } else { "unique" },
        if lf { "lf" } else { "space" }
    );
    let mut fixture = Fixture::plain(id, "dense-geometric-matrix", input);
    fixture.plants = plants;
    // Freeze the single-line subset before any scanner observation. This bounds
    // line payload to 16 MiB at 512 positive events, instead of quadratic GiB.
    fixture.timing_eligible = lf || size <= SIZES[0];
    fixture.details = json!({
        "records": size / RECORD_BYTES,
        "record_bytes": RECORD_BYTES,
        "class": density.name(),
        "identity_pattern": if repeated { "repeated" } else { "unique" },
        "separator": if lf { "LF" } else { "space" },
        "literal_line_payload_upper_bound_bytes": fixture.plants.len() * if lf { RECORD_BYTES + 1 } else { size },
        "single_line_timing_cap_input_bytes": SIZES[0],
        "untimed_reason": if fixture.timing_eligible { None } else { Some("predeclared-single-line-report-growth-cap; retain-as-unmeasured-quality-input") },
        "pair_contract": "changing-LF-to-space-only-changes-record-final-byte; repeated-and-unique-pairs-preserve-positive-offsets",
    });
    fixture
}

pub(super) fn generate(emit: &mut impl FnMut(Fixture) -> Result<(), String>) -> Result<(), String> {
    for &size in SIZES {
        for density in [Density::Positive, Density::Alternating, Density::Negative] {
            for repeated in [false, true] {
                for lf in [false, true] {
                    emit(dense(size, density, repeated, lf))?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn decoded(count: usize, depth: usize, repeated: bool, positive: bool) -> Fixture {
    assert!(count > 0 && (1..=2).contains(&depth));
    let mut plaintext = Vec::new();
    let mut plants = Vec::new();
    for ordinal in 0..count {
        plaintext.extend_from_slice(b"{\"value\":\"");
        let value = pat("single-carrier", if repeated { 0 } else { ordinal });
        let value = if positive {
            value
        } else {
            negative(value, false)
        };
        let start = plaintext.len();
        plaintext.extend_from_slice(&value);
        let end = plaintext.len();
        plaintext.extend_from_slice(b"\"}\n");
        if positive {
            plants.push(Plant {
                value,
                span: start..end,
                carrier: start..end,
            });
        }
    }
    let mut layers = vec![plaintext];
    for _ in 1..depth {
        layers.push(
            STANDARD
                .encode(layers.last().expect("plaintext layer"))
                .into_bytes(),
        );
    }
    let encoded = STANDARD.encode(layers.last().expect("plaintext layer"));
    let mut input = b"{\"encoded\":\"".to_vec();
    let start = input.len();
    input.extend_from_slice(encoded.as_bytes());
    let end = input.len();
    input.extend_from_slice(b"\"}\n");
    let id = format!(
        "one-carrier-{count}-depth-{depth}-{}-{}",
        if repeated { "repeated" } else { "unique" },
        if positive { "positive" } else { "negative" }
    );
    let mut fixture = Fixture::plain(id, "single-carrier-many-decoded", input);
    fixture.plants = plants;
    fixture.layers = layers;
    fixture.outer = Some(start..end);
    // At 4096 values, each decoded finding may retain the entire outer line.
    // Keep those costs visible as quality inputs, without silently dropping them.
    fixture.timing_eligible = count <= 256;
    fixture.details = json!({
        "inner_records": count,
        "identity_pattern": if repeated { "repeated" } else { "unique" },
        "class": if positive { "positive" } else { "internal-separator-negative" },
        "shared_outer_span": true,
        "required_multiplicity": "preserve-every-plaintext-occurrence-even-when-value-and-outer-span-repeat",
        "literal_line_payload_upper_bound_bytes": fixture.plants.len() * fixture.input.len(),
        "timed_inner_record_cap": 256,
        "untimed_reason": if fixture.timing_eligible { None } else { Some("predeclared-shared-outer-line-report-growth-cap") },
        "encoding_policy": "standard-padded-base64; URL-safe-unpadded-invalid-padding-not-assumed-equivalent",
    });
    fixture
}

pub(super) fn generate_decoded(
    emit: &mut impl FnMut(Fixture) -> Result<(), String>,
) -> Result<(), String> {
    for &count in INNER_COUNTS {
        for depth in 1..=2 {
            for repeated in [false, true] {
                for positive in [false, true] {
                    emit(decoded(count, depth, repeated, positive))?;
                }
            }
        }
    }
    Ok(())
}
