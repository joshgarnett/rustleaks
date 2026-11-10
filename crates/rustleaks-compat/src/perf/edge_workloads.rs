//! Bounded repeated-line filtering workloads with no retained findings.

use std::error::Error;

use super::Fixture;

const KIB: usize = 1_024;
const RULE_CONFIG: &str = r#"
[[rules]]
id = "edge-token"
description = "synthetic literal"
regex = '''ZX9'''
"#;
const LINE_ALLOWLIST: &str = r#"
[[allowlists]]
regexTarget = "line"
regexes = ['''ALLOW_SYNTHETIC$''']
"#;
const STOPWORD_RULE_CONFIG: &str = r#"
[[rules]]
id = "edge-stopword"
description = "synthetic repeated symbol"
regex = '''.+'''
"#;

pub(super) const WORKLOADS: &[&str] = &[
    "core-edge-marker-16-kib",
    "core-edge-marker-64-kib",
    "core-edge-marker-256-kib",
    "core-edge-marker-256-kib-64-matches",
    "core-edge-marker-4-mib",
    "core-edge-line-allowlist-16-kib",
    "core-edge-line-allowlist-64-kib",
    "core-edge-line-allowlist-256-kib",
    "core-edge-line-allowlist-256-kib-64-matches",
    "core-edge-line-allowlist-invalid-256-kib",
    "core-edge-stopword-overlap-16-kib",
    "core-edge-stopword-overlap-64-kib",
    "core-edge-stopword-overlap-256-kib",
    "core-edge-tail-location-16-kib",
    "core-edge-tail-location-256-kib",
];

#[derive(Clone, Copy)]
enum Suppressor {
    Marker,
    LineAllowlist,
}

pub(super) fn fixture(id: &str) -> Result<Fixture, Box<dyn Error>> {
    let (bytes, matches, suppressor, invalid) = match id {
        "core-edge-marker-16-kib" => (16 * KIB, 64, Suppressor::Marker, false),
        "core-edge-marker-64-kib" => (64 * KIB, 256, Suppressor::Marker, false),
        "core-edge-marker-256-kib" => (256 * KIB, 1_024, Suppressor::Marker, false),
        "core-edge-marker-256-kib-64-matches" => (256 * KIB, 64, Suppressor::Marker, false),
        "core-edge-marker-4-mib" => (4 * 1_024 * KIB, 4_096, Suppressor::Marker, false),
        "core-edge-line-allowlist-16-kib" => (16 * KIB, 64, Suppressor::LineAllowlist, false),
        "core-edge-line-allowlist-64-kib" => (64 * KIB, 256, Suppressor::LineAllowlist, false),
        "core-edge-line-allowlist-256-kib" => (256 * KIB, 1_024, Suppressor::LineAllowlist, false),
        "core-edge-line-allowlist-256-kib-64-matches" => {
            (256 * KIB, 64, Suppressor::LineAllowlist, false)
        }
        "core-edge-line-allowlist-invalid-256-kib" => {
            (256 * KIB, 1_024, Suppressor::LineAllowlist, true)
        }
        "core-edge-stopword-overlap-16-kib" => return Ok(stopword_fixture(16 * KIB, "a")),
        "core-edge-stopword-overlap-64-kib" => return Ok(stopword_fixture(64 * KIB, "a")),
        "core-edge-stopword-overlap-256-kib" => return Ok(stopword_fixture(256 * KIB, "a")),
        "core-edge-tail-location-16-kib" => return tail_location_fixture(16 * KIB, 64),
        "core-edge-tail-location-256-kib" => return tail_location_fixture(256 * KIB, 1_024),
        _ => return Err(format!("unknown core edge workload {id}").into()),
    };
    build(bytes, matches, suppressor, invalid)
}

fn build(
    bytes: usize,
    matches: usize,
    suppressor: Suppressor,
    invalid: bool,
) -> Result<Fixture, Box<dyn Error>> {
    let (suffix, config): (&[u8], String) = match suppressor {
        Suppressor::Marker => (b"rustleaks:allow", RULE_CONFIG.to_owned()),
        Suppressor::LineAllowlist => (b"ALLOW_SYNTHETIC", format!("{RULE_CONFIG}{LINE_ALLOWLIST}")),
    };
    let mut input = b"ZX9 ".repeat(matches);
    let suffix_start = bytes
        .checked_sub(suffix.len())
        .ok_or("edge input is too short")?;
    if input.len() >= suffix_start {
        return Err("edge fixture must retain padding before its suppressor".into());
    }
    input.resize(suffix_start, b'x');
    if invalid {
        *input.last_mut().ok_or("edge fixture has no padding")? = 0xff;
    }
    input.extend_from_slice(suffix);
    // There are exactly `matches` literal candidates at 4*i..4*i+3.
    // Every candidate is suppressed on the same unbroken source line. The
    // allowlist case contains neither supported allow marker, so its line
    // regex is the sole suppressor even with the default marker option.
    Ok(Fixture {
        input,
        config,
        expected: Vec::new(),
        legacy_fingerprint: None,
        expected_rules: 1,
        depth: 0,
        decoded_bytes: 0,
        keyword_count: 0,
        // One pass, one rule entry, and one checkpoint per literal candidate.
        expected_work: Some(matches + 2),
    })
}

fn stopword_fixture(bytes: usize, symbol: &str) -> Fixture {
    let stopwords = (1..=16)
        .map(|length| format!("\"{}\"", symbol.repeat(length)))
        .collect::<Vec<_>>()
        .join(", ");
    Fixture {
        input: vec![b'a'; bytes],
        config: format!("{STOPWORD_RULE_CONFIG}\n[[allowlists]]\nstopwords = [{stopwords}]\n"),
        expected: Vec::new(),
        legacy_fingerprint: None,
        expected_rules: 1,
        depth: 0,
        decoded_bytes: 0,
        keyword_count: 0,
        // One pass, one rule entry, and one greedy full-fragment match.
        expected_work: Some(3),
    }
}

fn tail_location_fixture(bytes: usize, matches: usize) -> Result<Fixture, Box<dyn Error>> {
    let mut input = b"\nrustleaks:allow".to_vec();
    for _ in 0..matches {
        input.extend_from_slice(b"ZX9 ");
    }
    if input.len() >= bytes {
        return Err("tail-location fixture must retain trailing padding".into());
    }
    input.resize(bytes, b'x');
    // Every literal follows the sole newline. The pinned location helper's
    // no-line-matched branch searches the remaining suffix for CR or LF and
    // exposes the prefix beginning at zero as the finding line. The marker
    // near its beginning suppresses each candidate without a long marker scan.
    Ok(Fixture {
        input,
        config: RULE_CONFIG.to_owned(),
        expected: Vec::new(),
        legacy_fingerprint: None,
        expected_rules: 1,
        depth: 0,
        decoded_bytes: 0,
        keyword_count: 0,
        expected_work: Some(matches + 2),
    })
}

#[cfg(test)]
mod tests {
    use rustleaks_core::model::{
        ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions,
    };
    use rustleaks_core::{Engine, ScanBudget, ScanControl};

    use super::*;

    fn small_positive_findings(input: &[u8]) -> Vec<Finding> {
        (0..4)
            .map(|index| {
                let start = 4 * index;
                let range = FindingRange::Exact(ByteRange::new(start, start + 3).unwrap());
                Finding::builder()
                    .rule_id("edge-token")
                    .description("synthetic literal")
                    .location(Location::new(0, 0, start + 1, start + 3).unwrap())
                    .match_range(range)
                    .secret_range(range)
                    .line(input)
                    .match_text("ZX9")
                    .secret("ZX9")
                    // Three equally frequent ASCII symbols have entropy log2(3).
                    .entropy(f32::from_bits(0x3fca_e00d))
                    .build()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn small_suffix_controls_preserve_literal_spans_and_accounting() {
        for (suppressor, invalid) in [
            (Suppressor::Marker, false),
            (Suppressor::LineAllowlist, false),
            (Suppressor::LineAllowlist, true),
        ] {
            let mut fixture = build(8 * KIB, 4, suppressor, invalid).unwrap();
            let detector = Engine::builder(fixture.compile().unwrap()).build().unwrap();
            let control = ScanControl::unlimited().with_budget(
                ScanBudget::unlimited()
                    .max_work_units(6)
                    .max_finding_records(4)
                    .max_decoded_bytes(0),
            );
            let suppressed = detector.scan_fragment_controlled(
                &Fragment::new(fixture.input.clone()),
                &ScanOptions::default(),
                &control,
            );
            fixture.validate(&suppressed).unwrap();
            assert_eq!(suppressed.usage().work_units(), 6);
            assert_eq!(suppressed.usage().finding_records(), 0);

            *fixture.input.last_mut().unwrap() = b'!';
            let positive = detector.scan_fragment_controlled(
                &Fragment::new(fixture.input.clone()),
                &ScanOptions::default(),
                &control,
            );
            assert!(fixture.validate(&positive).is_err());
            fixture.expected = small_positive_findings(&fixture.input);
            fixture.validate(&positive).unwrap();
            assert_eq!(positive.usage().work_units(), 6);
            assert_eq!(positive.usage().finding_records(), 4);
            assert!(fixture.validate(&suppressed).is_err());
        }
    }

    #[test]
    fn nonmatching_stopwords_expose_one_exact_full_span_finding() {
        let bytes = 8 * KIB;
        let fixture = stopword_fixture(bytes, "a");
        let detector = Engine::builder(fixture.compile().unwrap()).build().unwrap();
        let fragment = Fragment::new(fixture.input.clone());
        let control = ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_work_units(3)
                .max_finding_records(1)
                .max_decoded_bytes(0),
        );
        let suppressed =
            detector.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
        fixture.validate(&suppressed).unwrap();
        assert_eq!(suppressed.usage().work_units(), 3);
        assert_eq!(suppressed.usage().finding_records(), 0);

        let mut nonmatching = stopword_fixture(bytes, "b");
        let detector = Engine::builder(nonmatching.compile().unwrap())
            .build()
            .unwrap();
        let positive =
            detector.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
        assert!(nonmatching.validate(&positive).is_err());
        let range = FindingRange::Exact(ByteRange::new(0, bytes).unwrap());
        nonmatching.expected = vec![
            Finding::builder()
                .rule_id("edge-stopword")
                .description("synthetic repeated symbol")
                .location(Location::new(0, 0, 1, bytes).unwrap())
                .match_range(range)
                .secret_range(range)
                .line(nonmatching.input.as_slice())
                .match_text(nonmatching.input.as_slice())
                .secret(nonmatching.input.as_slice())
                .entropy(0.0)
                .build()
                .unwrap(),
        ];
        nonmatching.validate(&positive).unwrap();
        assert_eq!(positive.usage().work_units(), 3);
        assert_eq!(positive.usage().finding_records(), 1);
        assert!(nonmatching.validate(&suppressed).is_err());
    }

    #[test]
    fn tail_location_control_preserves_empty_results_and_exact_work() {
        let fixture = tail_location_fixture(8 * KIB, 4).unwrap();
        assert_eq!(fixture.input[0], b'\n');
        assert!(
            fixture.input[1..]
                .iter()
                .all(|byte| !matches!(byte, b'\r' | b'\n'))
        );
        let detector = Engine::builder(fixture.compile().unwrap()).build().unwrap();
        let outcome = detector.scan_fragment_controlled(
            &Fragment::new(fixture.input.clone()),
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(
                ScanBudget::unlimited()
                    .max_work_units(6)
                    .max_finding_records(0)
                    .max_decoded_bytes(0),
            ),
        );
        fixture.validate(&outcome).unwrap();
        assert!(outcome.is_complete());
        assert!(outcome.findings().is_empty());
        assert_eq!(outcome.usage().work_units(), 6);
        assert_eq!(outcome.usage().finding_records(), 0);
        assert_eq!(outcome.usage().decoded_bytes(), 0);
    }

    #[test]
    fn empty_results_do_not_hide_skipped_work_or_budget_termination() {
        let fixture = build(8 * KIB, 4, Suppressor::Marker, false).unwrap();
        let detector = Engine::builder(fixture.compile().unwrap()).build().unwrap();
        let skipped = detector.scan_fragment(&Fragment::new(b""), &ScanOptions::default());
        assert!(skipped.is_complete());
        assert!(skipped.findings().is_empty());
        assert_eq!(skipped.usage().work_units(), 2);
        assert!(fixture.validate(&skipped).is_err());

        let partial = detector.scan_fragment_controlled(
            &Fragment::new(fixture.input.clone()),
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(
                ScanBudget::unlimited()
                    .max_work_units(5)
                    .max_finding_records(0)
                    .max_decoded_bytes(0),
            ),
        );
        assert!(!partial.is_complete());
        assert!(partial.findings().is_empty());
        assert_eq!(partial.usage().work_units(), 5);
        assert_eq!(partial.usage().finding_records(), 0);
        assert!(fixture.validate(&partial).is_err());
    }
}
