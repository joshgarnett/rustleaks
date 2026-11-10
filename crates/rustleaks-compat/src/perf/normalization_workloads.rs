//! Bounded normalization controls with independently counted scan checkpoints.

use std::error::Error;

use super::Fixture;

const KIB: usize = 1_024;
const MIB: usize = 1_024 * KIB;
const ALLOW_MARKER: &[u8] = b"rustleaks:allow";
const NO_HIT_CONFIG: &str = r#"
[[rules]]
id = "normalization"
regex = '''rustleaks-normalization-no-hit'''
"#;
const EMPTY_CONFIG: &str = r#"
[[rules]]
id = "normalization"
regex = '''(?:)'''
"#;

pub(super) const WORKLOADS: &[&str] = &[
    "core-normalization-ascii-256-kib",
    "core-normalization-ascii-4-mib",
    "core-normalization-sparse-invalid-256-kib",
    "core-normalization-sparse-invalid-4-mib",
    "core-normalization-dense-invalid-256-kib",
    "core-normalization-dense-invalid-4-mib",
    "core-normalization-empty-invalid-8-kib",
    "core-normalization-empty-invalid-64-kib",
    "core-normalization-percent-valid-256-kib-depth-0",
    "core-normalization-percent-valid-256-kib-depth-1",
    "core-normalization-percent-valid-4-mib-depth-0",
    "core-normalization-percent-valid-4-mib-depth-1",
    "core-normalization-percent-invalid-prefix-4-mib-depth-0",
    "core-normalization-percent-invalid-prefix-4-mib-depth-1",
];

#[derive(Clone, Copy)]
enum Shape {
    Ascii,
    SparseInvalid,
    DenseInvalid,
    EmptyInvalid,
    PercentValid,
    PercentInvalidPrefix,
}

pub(super) fn fixture(id: &str) -> Result<Fixture, Box<dyn Error>> {
    let (size, shape, depth) = match id {
        "core-normalization-ascii-256-kib" => (256 * KIB, Shape::Ascii, 0),
        "core-normalization-ascii-4-mib" => (4 * MIB, Shape::Ascii, 0),
        "core-normalization-sparse-invalid-256-kib" => (256 * KIB, Shape::SparseInvalid, 0),
        "core-normalization-sparse-invalid-4-mib" => (4 * MIB, Shape::SparseInvalid, 0),
        "core-normalization-dense-invalid-256-kib" => (256 * KIB, Shape::DenseInvalid, 0),
        "core-normalization-dense-invalid-4-mib" => (4 * MIB, Shape::DenseInvalid, 0),
        "core-normalization-empty-invalid-8-kib" => (8 * KIB, Shape::EmptyInvalid, 0),
        "core-normalization-empty-invalid-64-kib" => (64 * KIB, Shape::EmptyInvalid, 0),
        "core-normalization-percent-valid-256-kib-depth-0" => (256 * KIB, Shape::PercentValid, 0),
        "core-normalization-percent-valid-256-kib-depth-1" => (256 * KIB, Shape::PercentValid, 1),
        "core-normalization-percent-valid-4-mib-depth-0" => (4 * MIB, Shape::PercentValid, 0),
        "core-normalization-percent-valid-4-mib-depth-1" => (4 * MIB, Shape::PercentValid, 1),
        "core-normalization-percent-invalid-prefix-4-mib-depth-0" => {
            (4 * MIB, Shape::PercentInvalidPrefix, 0)
        }
        "core-normalization-percent-invalid-prefix-4-mib-depth-1" => {
            (4 * MIB, Shape::PercentInvalidPrefix, 1)
        }
        _ => return Err("unknown normalization workload".into()),
    };
    Ok(build(size, shape, depth))
}

fn build(size: usize, shape: Shape, depth: usize) -> Fixture {
    let mut config = NO_HIT_CONFIG;
    // Every no-hit scan has one pass checkpoint and one eligible rule.
    // There are no keywords, matches, findings or decode work at depth zero.
    let mut expected_work = 2;
    let mut decoded_bytes = 0;
    let input = match shape {
        Shape::Ascii => vec![b'x'; size],
        Shape::SparseInvalid => {
            let mut input = vec![b'x'; size];
            input[size - 1] = 0xff;
            input
        }
        Shape::DenseInvalid => vec![0xff; size],
        Shape::EmptyInvalid => {
            config = EMPTY_CONFIG;
            let mut input = vec![0xff; size];
            // Put the marker first so each candidate's allow-marker lookup
            // succeeds immediately, rather than rescanning a long line.
            // There are no newlines: every candidate sees this same marker.
            input[..ALLOW_MARKER.len()].copy_from_slice(ALLOW_MARKER);
            // ASCII and invalid source bytes each decode to one Go rune.
            // The empty pattern matches every boundary, including EOF.
            expected_work = size + 3;
            input
        }
        Shape::PercentValid | Shape::PercentInvalidPrefix => {
            // Percent decoding accepts printable ASCII only. %41 decodes to
            // A; %FF would be rejected and would not create a decoded pass.
            // An invalid prefix lies outside the candidate and survives in
            // the decoded output, exercising normalization on both passes.
            let prefix = usize::from(matches!(shape, Shape::PercentInvalidPrefix));
            let encoded_size = size - prefix;
            let mut input = b"%41".repeat(encoded_size / 3);
            if prefix == 1 {
                input.insert(0, 0xff);
            }
            input.resize(size, b' ');
            if depth == 1 {
                decoded_bytes = prefix + encoded_size / 3 + encoded_size % 3;
                // Two pass/rule pairs, one decoder dispatch, one regex
                // candidate, one transform and one segment replacement.
                // One candidate skips overlap filtering and has no ancestors.
                expected_work = 8;
            }
            input
        }
    };
    Fixture {
        input,
        config: config.to_owned(),
        expected: Vec::new(),
        legacy_fingerprint: None,
        expected_rules: 1,
        depth,
        decoded_bytes,
        keyword_count: 0,
        expected_work: Some(expected_work),
    }
}

#[cfg(test)]
mod tests {
    use rustleaks_core::model::{Fragment, ScanOptions};
    use rustleaks_core::{Engine, ScanBudget, ScanControl};

    use super::*;

    #[test]
    fn small_controls_finish_at_the_independent_work_and_decode_limits() {
        for (shape, depth) in [
            (Shape::Ascii, 0),
            (Shape::SparseInvalid, 0),
            (Shape::DenseInvalid, 0),
            (Shape::EmptyInvalid, 0),
            (Shape::PercentValid, 0),
            (Shape::PercentValid, 1),
            (Shape::PercentInvalidPrefix, 0),
            (Shape::PercentInvalidPrefix, 1),
        ] {
            let fixture = build(KIB, shape, depth);
            let engine = Engine::builder(fixture.compile().unwrap()).build().unwrap();
            let outcome = engine.scan_fragment_controlled(
                &Fragment::new(fixture.input.clone()),
                &ScanOptions::builder().max_decode_depth(depth).build(),
                &ScanControl::unlimited().with_budget(
                    ScanBudget::unlimited()
                        .max_work_units(fixture.expected_work.unwrap())
                        .max_decoded_bytes(fixture.decoded_bytes)
                        .max_finding_records(0),
                ),
            );
            fixture.validate(&outcome).unwrap();
        }
    }

    #[test]
    fn declared_controls_keep_full_scan_sizes_out_of_unit_tests() {
        for id in WORKLOADS {
            let fixture = fixture(id).unwrap();
            assert!(fixture.input.len() <= 4 * MIB);
            assert!(fixture.expected.is_empty());
            assert!(fixture.expected_work.is_some());
            assert_eq!(fixture.expected_rules, 1);
        }
        assert!(fixture("unknown").is_err());
    }
}
