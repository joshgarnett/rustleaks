//! Construction-derived locations and byte ranges for synthetic fragments.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::fmt::Write as _;
use std::ops::Range;

use base64::Engine as _;
use rustleaks_core::Engine;
use rustleaks_core::config::{ConfigLoader, RawConfig, RuleSpec};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};

const VALUE: &[u8] = b"item=TEST-0123456789";
const OTHER_VALUE: &[u8] = b"item=TEST-9876543210";

fn engine(pattern: &str) -> Engine {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "synthetic-location".into(),
                regex: pattern.into(),
                secret_group: 1,
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap();
    Engine::builder(config).build().unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
    Percent,
    Unicode,
    Hex,
    Base64,
}

impl Encoding {
    const ALL: [Self; 4] = [Self::Percent, Self::Unicode, Self::Hex, Self::Base64];

    // Only encode ASCII fixtures. These encoders do not call the private
    // decoder or its offset mapper, and every wrapper covers the whole value.
    fn encode(self, value: &[u8]) -> Vec<u8> {
        if self == Self::Base64 {
            return base64::engine::general_purpose::STANDARD
                .encode(value)
                .into_bytes();
        }
        let mut encoded = String::new();
        for byte in value {
            match self {
                Self::Percent => write!(encoded, "%{byte:02X}"),
                Self::Unicode => write!(encoded, "\\u{byte:04X}"),
                Self::Hex => write!(encoded, "{byte:02X}"),
                Self::Base64 => unreachable!(),
            }
            .unwrap();
        }
        encoded.into_bytes()
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::Percent => "decoded:percent",
            Self::Unicode => "decoded:unicode",
            Self::Hex => "decoded:hex",
            Self::Base64 => "decoded:base64",
        }
    }
}

fn wrap(value: &[u8], chain: &[Encoding]) -> Vec<u8> {
    chain
        .iter()
        .fold(value.to_vec(), |value, encoding| encoding.encode(&value))
}

fn assert_decoded(
    finding: &Finding,
    value: &[u8],
    location: Location,
    original_line: &[u8],
    chain: &[Encoding],
) {
    assert_eq!(finding.match_text().as_bytes(), value);
    assert_eq!(finding.secret().as_bytes(), &value[b"item=".len()..]);
    assert_eq!(finding.location(), location, "chain: {chain:?}");
    assert_eq!(finding.line().as_bytes(), original_line);
    // A decoded location identifies its original candidate for reporting;
    // it does not authorize rewriting that candidate as an exact byte span.
    assert_eq!(finding.match_range(), FindingRange::Unavailable);
    assert_eq!(finding.secret_range(), FindingRange::Unavailable);
    let mut expected_tags = Encoding::ALL
        .into_iter()
        .filter(|encoding| chain.contains(encoding))
        .map(|encoding| encoding.tag().to_owned())
        .collect::<Vec<_>>();
    expected_tags.push(format!("decode-depth:{}", chain.len()));
    assert_eq!(
        finding
            .tags()
            .iter()
            .map(rustleaks_core::model::ByteText::as_bytes)
            .collect::<Vec<_>>(),
        expected_tags
            .iter()
            .map(String::as_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_three_level_encoding_chain_maps_to_its_outer_candidate() {
    let engine = engine(r"item=(TEST-[0-9]{10})");
    // Explicit line origins retain the pinned convention that a subsequent
    // reported line includes its preceding LF. Columns count original bytes.
    let layouts: &[(&[u8], usize, usize)] = &[
        (b"", 0, 0),
        (b"\xff\x80[\xe2\x82] ", 0, 0),
        (b"head\n[\xff\x80] ", 4, 1),
    ];
    for depth in 1_u32..=3 {
        for mut ordinal in 0..4_usize.pow(depth) {
            let chain = (0..depth)
                .map(|_| {
                    let encoding = Encoding::ALL[ordinal % 4];
                    ordinal /= 4;
                    encoding
                })
                .collect::<Vec<_>>();
            let encoded = wrap(VALUE, &chain);
            for &(prefix, line_origin, relative_line) in layouts {
                let mut raw = prefix.to_vec();
                let candidate_start = raw.len();
                raw.extend_from_slice(&encoded);
                let candidate_end = raw.len();
                raw.extend_from_slice(b" ]");
                let line_end = raw.len();
                raw.extend_from_slice(b"\ntrailer");
                let fragment = Fragment::builder(raw.clone()).start_line(37).build();
                let options = ScanOptions::builder().max_decode_depth(chain.len()).build();
                let outcome = engine.scan_fragment(&fragment, &options);
                assert!(outcome.is_complete());
                assert_eq!(outcome.findings().len(), 1, "chain: {chain:?}");
                assert_decoded(
                    &outcome.findings()[0],
                    VALUE,
                    Location::new(
                        37 + relative_line,
                        37 + relative_line,
                        candidate_start - line_origin + 1,
                        candidate_end - line_origin,
                    )
                    .unwrap(),
                    &raw[line_origin..line_end],
                    &chain,
                );
                let shallow = ScanOptions::builder()
                    .max_decode_depth(chain.len() - 1)
                    .build();
                assert!(
                    engine
                        .scan_fragment(&fragment, &shallow)
                        .findings()
                        .is_empty(),
                    "each wrapper requires its own decode pass: {chain:?}"
                );
            }
        }
    }
}

#[test]
fn nested_siblings_keep_separate_original_locations_after_shrinking() {
    let engine = engine(r"item=(TEST-[0-9]{10})");
    for first in Encoding::ALL {
        for second in Encoding::ALL {
            let left_chain = [first, second];
            let right_chain = [second, first, second];
            let mut raw = b"\xff[".to_vec();
            let left_start = raw.len();
            raw.extend(wrap(VALUE, &left_chain));
            let left_end = raw.len();
            raw.extend_from_slice(b"]");
            let newline = raw.len();
            raw.extend_from_slice(b"\n\x80[");
            let right_start = raw.len();
            raw.extend(wrap(OTHER_VALUE, &right_chain));
            let right_end = raw.len();
            raw.extend_from_slice(b"]");
            let last_newline = raw.len();
            raw.push(b'\n');
            let fragment = Fragment::builder(raw.clone()).start_line(5).build();
            let options = ScanOptions::builder().max_decode_depth(3).build();
            let outcome = engine.scan_fragment(&fragment, &options);
            assert!(outcome.is_complete());
            assert_eq!(outcome.findings().len(), 2, "{first:?}, {second:?}");
            assert_decoded(
                &outcome.findings()[0],
                VALUE,
                Location::new(5, 5, left_start + 1, left_end).unwrap(),
                &raw[..newline],
                &left_chain,
            );
            assert_decoded(
                &outcome.findings()[1],
                OTHER_VALUE,
                Location::new(6, 6, right_start - newline + 1, right_end - newline).unwrap(),
                &raw[newline..last_newline],
                &right_chain,
            );
        }
    }
}

fn assert_raw_range(raw: &[u8], range: FindingRange, expected: Range<usize>, bytes: &[u8]) {
    assert_eq!(
        range,
        FindingRange::Exact(ByteRange::new(expected.start, expected.end).unwrap())
    );
    assert_eq!(&raw[range.exact().unwrap().as_range()], bytes);
}

#[test]
fn malformed_utf8_keeps_exact_raw_match_and_capture_ranges() {
    // Counts are fixture facts, not results from Rustleaks or a lossy decoder.
    // Go regex treats each malformed byte as one RuneError; a valid encoded
    // U+FFFD still occupies three original bytes and one rune.
    let atoms: &[(&[u8], usize)] = &[
        (b"A", 1),
        (b"\xff", 1),
        (b"\x80\x80", 2),
        (b"\xc0\x80", 2),
        (b"\xe0\x80\x80", 3),
        (b"\xed\xa0\x80", 3),
        (b"\xf4\x90\x80\x80", 4),
        (b"\xe2\x82", 2),
        (b"\xf0\x9f\x92", 3),
        ("\u{20ac}".as_bytes(), 1),
        ("\u{1f480}".as_bytes(), 1),
        ("\u{fffd}".as_bytes(), 1),
        (b"\xff\xef\xbf\xbd\x80", 3),
    ];
    let prefixes: &[&[u8]] = &[b"", b"\xff\x80", b"\xe2\x82", "雪".as_bytes()];
    for &(atom, rune_count) in atoms {
        let engine = engine(&format!(r"(?s:\n*v=(.{{{rune_count}}});\n*)"));
        for &prefix in prefixes {
            for padding in 0..=2 {
                let mut raw = prefix.to_vec();
                let mut expected = Vec::new();
                for _ in 0..2 {
                    raw.extend(std::iter::repeat_n(b'\n', padding));
                    let match_start = raw.len();
                    raw.extend_from_slice(b"v=");
                    let secret_start = raw.len();
                    raw.extend_from_slice(atom);
                    let secret_end = raw.len();
                    raw.push(b';');
                    expected.push((match_start..raw.len(), secret_start..secret_end));
                    raw.extend(std::iter::repeat_n(b'\n', padding));
                    raw.extend_from_slice(b"!\xff!");
                }
                let outcome =
                    engine.scan_fragment(&Fragment::new(raw.clone()), &ScanOptions::default());
                assert!(outcome.is_complete());
                assert_eq!(outcome.findings().len(), expected.len());
                for (finding, (matched, secret)) in outcome.findings().iter().zip(expected) {
                    assert_eq!(finding.secret().as_bytes(), atom);
                    assert_raw_range(
                        &raw,
                        finding.match_range(),
                        matched,
                        finding.match_text().as_bytes(),
                    );
                    assert_raw_range(&raw, finding.secret_range(), secret, atom);
                }
            }
        }
    }
}

#[test]
fn target_and_decoded_byte_limits_count_pass_bytes_before_utf8_normalization() {
    use rustleaks_core::{ScanBudget, ScanBudgetKind, ScanControl, ScanTermination};

    let engine = engine(r"v=(AB)");
    let raw = b"\xffv=AB".as_slice();
    let encoded = b"\xff%76%3D%41%42".as_slice();
    // The raw and decoded passes contain five bytes; replacing the invalid
    // prefix with UTF-8 RuneError would require seven. Percent decoding turns
    // the twelve-byte candidate into four ASCII bytes and preserves the prefix.
    let expected = |input: &[u8], end| {
        Finding::builder()
            .rule_id("synthetic-location")
            .location(Location::new(0, 0, 2, end).unwrap())
            .line(input)
            .match_text(b"v=AB".as_slice())
            .secret(b"AB".as_slice())
            .entropy(1.0)
    };
    let direct = expected(raw, 5)
        .match_range(FindingRange::Exact(ByteRange::new(1, 5).unwrap()))
        .secret_range(FindingRange::Exact(ByteRange::new(3, 5).unwrap()))
        .build()
        .unwrap();
    let decoded = expected(encoded, 13)
        .match_range(FindingRange::Unavailable)
        .secret_range(FindingRange::Unavailable)
        .tags(["decoded:percent", "decode-depth:1"])
        .build()
        .unwrap();
    // Work counts: each pass and rule entry costs one; the decode attempt,
    // encoding match, candidate transform and segment splice cost four more;
    // an accepted match costs one. Charging decoded bytes is not a work unit.
    for (input, depth, target, decoded_limit, expected_finding, work, bytes, termination) in [
        (raw, 0, 5, 0, Some(&direct), 3, 0, None),
        (raw, 0, 4, 0, None, 2, 0, None),
        (encoded, 1, 5, 5, Some(&decoded), 9, 5, None),
        (
            encoded,
            1,
            5,
            4,
            None,
            6,
            0,
            Some(ScanTermination::BudgetExceeded {
                kind: ScanBudgetKind::DecodedBytes,
                limit: 4,
                consumed: 0,
                requested: 5,
            }),
        ),
        (encoded, 1, 4, 5, None, 8, 5, None),
    ] {
        let options = ScanOptions::builder()
            .max_decode_depth(depth)
            .max_target_bytes(Some(target))
            .build();
        let control = ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_decoded_bytes(decoded_limit)
                .max_work_units(9)
                .max_finding_records(1),
        );
        let outcome = engine.scan_fragment_controlled(&Fragment::new(input), &options, &control);
        assert_eq!(outcome.is_complete(), termination.is_none());
        assert_eq!(outcome.termination(), termination.as_ref());
        assert_eq!(outcome.usage().work_units(), work);
        assert_eq!(outcome.usage().decoded_bytes(), bytes);
        assert_eq!(
            outcome.usage().finding_records(),
            usize::from(expected_finding.is_some()),
        );
        assert_eq!(
            outcome.findings(),
            expected_finding.map_or(&[][..], std::slice::from_ref),
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the finite geometry/encoding matrix and its independent location assertions together.
fn decoded_match_overlap_geometries_keep_original_envelopes_under_budgets() {
    use rustleaks_core::{ScanBudget, ScanBudgetKind, ScanControl, ScanTermination};
    for encoding in Encoding::ALL {
        for depth in 1..=2 {
            let chain = vec![encoding; depth];
            for geometry in 0..5 {
                let mut raw = b"[L:".to_vec();
                let encoded_start = raw.len();
                raw.extend(wrap(VALUE, &chain));
                if geometry == 4 {
                    raw.push(b'|');
                    raw.extend(wrap(OTHER_VALUE, &chain));
                }
                let encoded_end = raw.len();
                raw.extend_from_slice(b":R]");
                let (pattern, start, end, expected_match, expected_secret) = match geometry {
                    0 => (
                        r"item=(TEST-[0-9]{10})",
                        encoded_start,
                        encoded_end,
                        VALUE.to_vec(),
                        VALUE[5..].to_vec(),
                    ),
                    1 => (
                        r"L:item=(TEST-[0-9]{10})",
                        1,
                        encoded_end,
                        [b"L:", VALUE].concat(),
                        VALUE[5..].to_vec(),
                    ),
                    2 => (
                        r"item=(TEST-[0-9]{10}):R",
                        encoded_start,
                        encoded_end + 2,
                        [VALUE, b":R"].concat(),
                        VALUE[5..].to_vec(),
                    ),
                    3 => (
                        r"L:item=(TEST-[0-9]{10}):R",
                        1,
                        encoded_end + 2,
                        [b"L:", VALUE, b":R"].concat(),
                        VALUE[5..].to_vec(),
                    ),
                    _ => (
                        r"item=(TEST-[0-9]{10}\|item=TEST-[0-9]{10})",
                        encoded_start,
                        encoded_end,
                        [VALUE, b"|", OTHER_VALUE].concat(),
                        [&VALUE[5..], b"|", OTHER_VALUE].concat(),
                    ),
                };
                let engine = engine(pattern);
                let fragment = Fragment::builder(raw.clone()).start_line(1).build();
                let options = ScanOptions::builder().max_decode_depth(depth).build();
                let complete = engine.scan_fragment(&fragment, &options);
                assert!(complete.is_complete());
                assert_eq!(
                    complete.findings().len(),
                    1,
                    "{encoding:?}/{depth}/{geometry}"
                );
                let finding = &complete.findings()[0];
                assert_eq!(finding.match_text().as_bytes(), expected_match);
                assert_eq!(finding.secret().as_bytes(), expected_secret);
                assert_eq!(
                    finding.location(),
                    Location::new(1, 1, start + 1, end).unwrap(),
                    "{encoding:?}/{depth}/{geometry}"
                );
                assert_eq!(finding.match_range(), FindingRange::Unavailable);
                assert_eq!(finding.secret_range(), FindingRange::Unavailable);
                assert_eq!(finding.line().as_bytes(), raw);
                let usage = complete.usage();
                for (kind, consumed) in [
                    (ScanBudgetKind::DecodedBytes, usage.decoded_bytes()),
                    (ScanBudgetKind::WorkUnits, usage.work_units()),
                    (ScanBudgetKind::FindingRecords, usage.finding_records()),
                ] {
                    assert!(consumed > 0);
                    for ceiling in [consumed - 1, consumed, consumed + 1] {
                        let budget = match kind {
                            ScanBudgetKind::DecodedBytes => {
                                ScanBudget::unlimited().max_decoded_bytes(ceiling)
                            }
                            ScanBudgetKind::WorkUnits => {
                                ScanBudget::unlimited().max_work_units(ceiling)
                            }
                            ScanBudgetKind::FindingRecords => {
                                ScanBudget::unlimited().max_finding_records(ceiling)
                            }
                            _ => unreachable!(),
                        };
                        let control = ScanControl::unlimited().with_budget(budget);
                        let outcome =
                            engine.scan_fragment_controlled(&fragment, &options, &control);
                        if ceiling >= consumed {
                            assert_eq!(outcome, complete);
                        } else {
                            assert!(
                                matches!(outcome.termination(), Some(ScanTermination::BudgetExceeded { kind: actual, limit, .. }) if *actual == kind && *limit == ceiling)
                            );
                            assert!(outcome.findings().is_empty());
                            assert!(outcome.usage().decoded_bytes() <= usage.decoded_bytes());
                            assert!(outcome.usage().work_units() <= usage.work_units());
                            assert!(outcome.usage().finding_records() <= usage.finding_records());
                        }
                    }
                }
                let combined = ScanBudget::unlimited()
                    .max_decoded_bytes(usage.decoded_bytes())
                    .max_work_units(usage.work_units())
                    .max_finding_records(usage.finding_records());
                assert_eq!(
                    engine.scan_fragment_controlled(
                        &fragment,
                        &options,
                        &ScanControl::unlimited().with_budget(combined)
                    ),
                    complete
                );
            }
        }
    }
}
