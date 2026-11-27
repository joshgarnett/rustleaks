//! Line and column locations of findings in scanned bytes.
#![forbid(unsafe_code)]

use std::ops::Range;

use rustleaks_core::config::{AllowlistSpec, ConfigLoader, RawConfig, RegexTarget, RuleSpec};
use rustleaks_core::model::{
    ByteRange, Finding, FindingBuilder, FindingRange, Fragment, Location, ScanOptions,
};
use rustleaks_core::{Engine, ScanOutcome};

const PATTERN: &str = r"key=(AAAA)";
const PERCENT: &[u8] = b"%6B%65%79%3D%41%41%41%41";
const BASE64: &[u8] = b"a2V5PUFBQUE7ZW5k";
const NESTED: &[u8] = b"%61%32%56%35%50%55%46%42%51%55%45%37%5A%57%35%6B";
const DECODED_MARKER: &[u8] =
    b"%6B%65%79%3D%41%41%41%41%20%67%69%74%6C%65%61%6B%73%3A%61%6C%6C%6F%77";

fn engine(pattern: &str, allowline: Option<&str>) -> Engine {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "lookup".into(),
                description: "Synthetic location boundary".into(),
                regex: pattern.into(),
                secret_group: 1,
                tags: vec!["synthetic".into(), "location".into()],
                allowlists: allowline
                    .into_iter()
                    .map(|pattern| AllowlistSpec {
                        regex_target: RegexTarget::Line,
                        regexes: vec![pattern.into()],
                        ..AllowlistSpec::default()
                    })
                    .collect(),
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap();
    Engine::builder(config).build().unwrap()
}

fn fragment(raw: &[u8]) -> Fragment {
    Fragment::builder(raw)
        .start_line(37)
        .file_path("synthetic/lookup.txt")
        .symlink_file("synthetic/link.txt")
        .commit("synthetic-commit")
        .build()
}

fn expected(coordinates: [usize; 4], line: &[u8]) -> FindingBuilder {
    let [start_line, end_line, start_column, end_column] = coordinates;
    Finding::builder()
        .rule_id("lookup")
        .description("Synthetic location boundary")
        .location(Location::new(start_line, end_line, start_column, end_column).unwrap())
        .line(line)
        .file("synthetic/lookup.txt")
        .symlink_file("synthetic/link.txt")
        .commit("synthetic-commit")
        .tags(["synthetic", "location"])
}

fn assert_outcome(outcome: &ScanOutcome, findings: &[Finding], usage: [usize; 3]) {
    // Finding equality covers every public field, including absent metadata,
    // retained fragments, required findings, fingerprint, entropy and tag order.
    assert_eq!(outcome.findings(), findings);
    for (observed, expected) in outcome.findings().iter().zip(findings) {
        assert_eq!(observed.entropy().to_bits(), expected.entropy().to_bits());
    }
    assert!(outcome.is_complete());
    assert_eq!(outcome.termination(), None);
    assert_eq!(
        [
            outcome.usage().decoded_bytes(),
            outcome.usage().work_units(),
            outcome.usage().finding_records()
        ],
        usage,
    );
}

struct DirectCase {
    name: &'static str,
    raw: &'static [u8],
    pattern: &'static str,
    coordinates: [usize; 4],
    line: &'static [u8],
    matched: Range<usize>,
    secret: Range<usize>,
    entropy_bits: u32,
}

#[test]
#[allow(clippy::too_many_lines)] // Keep literal byte fixtures beside their complete expectations.
fn direct_locations_keep_byte_columns_line_slices_and_trimmed_ranges() {
    // Coordinates and ranges are literal fixture facts. In particular, a
    // last line without a final newline starts at the newline before it, and
    // trimming leading LF changes the exact ranges without moving the
    // reported match start.
    let cases = [
        DirectCase {
            name: "plain",
            raw: b"key=AAAA",
            pattern: PATTERN,
            coordinates: [37, 37, 1, 8],
            line: b"key=AAAA",
            matched: 0..8,
            secret: 4..8,
            entropy_bits: 0,
        },
        DirectCase {
            name: "CR only",
            raw: b"p\rkey=AAAA\rt",
            pattern: PATTERN,
            coordinates: [37, 37, 3, 10],
            line: b"p\rkey=AAAA\rt",
            matched: 2..10,
            secret: 6..10,
            entropy_bits: 0,
        },
        DirectCase {
            name: "CRLF",
            raw: b"p\r\nkey=AAAA\r\nz",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA\r",
            matched: 3..11,
            secret: 7..11,
            entropy_bits: 0,
        },
        DirectCase {
            name: "LF",
            raw: b"h\nkey=AAAA\nz",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA",
            matched: 2..10,
            secret: 6..10,
            entropy_bits: 0,
        },
        DirectCase {
            name: "tail stops at CR",
            raw: b"h\nkey=AAAA\rt",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA",
            matched: 2..10,
            secret: 6..10,
            entropy_bits: 0,
        },
        DirectCase {
            name: "tail ends at EOF",
            raw: b"h\nkey=AAAA",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA",
            matched: 2..10,
            secret: 6..10,
            entropy_bits: 0,
        },
        DirectCase {
            name: "consecutive LF",
            raw: b"\n\nkey=AAAA\n",
            pattern: PATTERN,
            coordinates: [39, 39, 2, 9],
            line: b"\nkey=AAAA",
            matched: 2..10,
            secret: 6..10,
            entropy_bits: 0,
        },
        DirectCase {
            name: "multiline",
            raw: b"x\nkey=AA\nAA\r\nz",
            pattern: r"key=(A)A\nAA",
            coordinates: [38, 39, 2, 3],
            line: b"\nkey=AA\nAA\r",
            matched: 2..11,
            secret: 6..7,
            entropy_bits: 0,
        },
        DirectCase {
            name: "trim both ends",
            raw: b"p\n\nkey=AAAA\n\nz",
            pattern: r"\n*key=(AAAA)\n*",
            coordinates: [38, 39, 1, 7],
            line: b"\n\nkey=AAAA",
            matched: 3..11,
            secret: 7..11,
            entropy_bits: 0,
        },
        DirectCase {
            name: "trim trailing LF",
            raw: b"key=AAAA\n\nz",
            pattern: r"key=(AAAA)\n*",
            coordinates: [37, 37, 1, 8],
            line: b"key=AAAA",
            matched: 0..8,
            secret: 4..8,
            entropy_bits: 0,
        },
        DirectCase {
            name: "malformed bytes",
            raw: b"\xe9\x9b\xaa\x80 key=\xff\xff\n",
            pattern: r"key=(..)",
            coordinates: [37, 37, 6, 11],
            line: b"\xe9\x9b\xaa\x80 key=\xff\xff",
            matched: 5..11,
            secret: 9..11,
            entropy_bits: 0,
        },
        DirectCase {
            name: "multibyte capture",
            raw: b"key=\xc3\xa9\xc3\xa9\n",
            pattern: r"key=(..)",
            coordinates: [37, 37, 1, 8],
            line: b"key=\xc3\xa9\xc3\xa9",
            matched: 0..8,
            secret: 4..8,
            entropy_bits: 0x3f00_0000,
        },
    ];
    for case in cases {
        let exact = |range: &Range<usize>| {
            FindingRange::Exact(ByteRange::new(range.start, range.end).unwrap())
        };
        let finding = expected(case.coordinates, case.line)
            .match_text(&case.raw[case.matched.clone()])
            .secret(&case.raw[case.secret.clone()])
            .match_range(exact(&case.matched))
            .secret_range(exact(&case.secret))
            .entropy(f32::from_bits(case.entropy_bits))
            .build()
            .unwrap();
        let outcome =
            engine(case.pattern, None).scan_fragment(&fragment(case.raw), &ScanOptions::default());
        assert_eq!(outcome.findings().len(), 1, "{}", case.name);
        // One pass, one rule and one match checkpoint; one admitted finding.
        assert_outcome(&outcome, &[finding], [0, 3, 1]);
    }
}

fn decoded(coordinates: [usize; 4], line: &[u8], matched: &[u8], tags: &[&str]) -> Finding {
    expected(coordinates, line)
        .match_text(matched)
        .secret(b"AAAA".as_slice())
        .match_range(FindingRange::Unavailable)
        .secret_range(FindingRange::Unavailable)
        .tags(
            ["synthetic", "location"]
                .into_iter()
                .chain(tags.iter().copied()),
        )
        .build()
        .unwrap()
}

#[test]
fn nested_and_overlapping_segments_report_the_original_outer_span() {
    let raw = [b"h\r\n[".as_slice(), NESTED, b"]\r\nt"].concat();
    let line = [b"\n[".as_slice(), NESTED, b"]\r"].concat();
    let finding = decoded(
        [38, 38, 3, 50],
        &line,
        b"key=AAAA",
        &["decoded:percent", "decoded:base64", "decode-depth:2"],
    );
    let options = ScanOptions::builder().max_decode_depth(2).build();
    // Decoded passes contain 24 and 20 bytes. The second transform also visits
    // its one predecessor; the final match is the only admitted finding.
    assert_outcome(
        &engine(PATTERN, None).scan_fragment(&fragment(&raw), &options),
        &[finding],
        [44, 16, 1],
    );

    let raw = [b"h\n[".as_slice(), PERCENT, b"|", BASE64, b"]\nt"].concat();
    let line = [b"\n[".as_slice(), PERCENT, b"|", BASE64, b"]"].concat();
    let finding = decoded(
        [38, 38, 3, 43],
        &line,
        b"key=AAAA|key=AAAA",
        &["decoded:percent", "decoded:base64", "decode-depth:1"],
    );
    let options = ScanOptions::builder().max_decode_depth(1).build();
    // One match overlaps two distinct candidates. Both candidate-filter visits
    // and both transforms count, while the reported span covers both encodings.
    assert_outcome(
        &engine(r"key=(AAAA)\|key=AAAA", None).scan_fragment(&fragment(&raw), &options),
        &[finding],
        [27, 14, 1],
    );
}

#[test]
fn allow_markers_use_original_reported_lines_including_the_last_line() {
    let detector = engine(PATTERN, None);
    let options = ScanOptions::builder().max_decode_depth(1).build();
    // The encoded value is on a last line without a final newline. The allow
    // comment on the line before it does not hide it.
    let raw = [b"gitleaks:allow\n".as_slice(), PERCENT].concat();
    let line = [b"\n".as_slice(), PERCENT].concat();
    let finding = decoded(
        [38, 38, 2, 25],
        &line,
        b"key=AAAA",
        &["decoded:percent", "decode-depth:1"],
    );
    assert_outcome(
        &detector.scan_fragment(&fragment(&raw), &options),
        std::slice::from_ref(&finding),
        [23, 9, 1],
    );
    let ignored = ScanOptions::builder()
        .max_decode_depth(1)
        .honor_allow_markers(false)
        .build();
    assert_outcome(
        &detector.scan_fragment(&fragment(&raw), &ignored),
        &[finding],
        [23, 9, 1],
    );
    // An allow comment on that last line still hides it.
    let raw = [b"h\n".as_slice(), PERCENT, b" gitleaks:allow"].concat();
    assert_outcome(
        &detector.scan_fragment(&fragment(&raw), &options),
        &[],
        [25, 9, 0],
    );

    let raw = [b"h\n".as_slice(), PERCENT, b"\ngitleaks:allow"].concat();
    let line = [b"\n".as_slice(), PERCENT].concat();
    let finding = decoded(
        [38, 38, 2, 25],
        &line,
        b"key=AAAA",
        &["decoded:percent", "decode-depth:1"],
    );
    assert_outcome(
        &detector.scan_fragment(&fragment(&raw), &options),
        &[finding],
        [25, 9, 1],
    );

    let raw = [b"h\n".as_slice(), DECODED_MARKER, b"\nt"].concat();
    let line = [b"\n".as_slice(), DECODED_MARKER].concat();
    let finding = decoded(
        [38, 38, 2, 70],
        &line,
        b"key=AAAA",
        &["decoded:percent", "decode-depth:1"],
    );
    assert_outcome(
        &detector.scan_fragment(&fragment(&raw), &options),
        &[finding],
        [27, 9, 1],
    );
}

/// A finding on a last line without a final newline reports only that line.
/// Like every later line, it starts with the newline before it. An allow
/// comment on an earlier line does not hide it; one on the last line does.
#[test]
fn last_line_without_final_newline_reports_only_that_line() {
    struct Case {
        name: &'static str,
        raw: &'static [u8],
        pattern: &'static str,
        coordinates: [usize; 4],
        line: &'static [u8],
        matched: Range<usize>,
        secret: Range<usize>,
    }
    let cases = [
        Case {
            name: "single line",
            raw: b"key=AAAA",
            pattern: PATTERN,
            coordinates: [37, 37, 1, 8],
            line: b"key=AAAA",
            matched: 0..8,
            secret: 4..8,
        },
        Case {
            name: "allow comment on the line before",
            raw: b"gitleaks:allow\nkey=AAAA",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA",
            matched: 15..23,
            secret: 19..23,
        },
        Case {
            name: "allow comment two lines before",
            raw: b"rustleaks:allow\nx\nkey=AAAA",
            pattern: PATTERN,
            coordinates: [39, 39, 2, 9],
            line: b"\nkey=AAAA",
            matched: 18..26,
            secret: 22..26,
        },
        Case {
            name: "text after the match on the last line",
            raw: b"gitleaks:allow\nkey=AAAA end",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA end",
            matched: 15..23,
            secret: 19..23,
        },
        Case {
            name: "CRLF",
            raw: b"gitleaks:allow\r\nkey=AAAA",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA",
            matched: 16..24,
            secret: 20..24,
        },
        Case {
            name: "CRLF with a final CRLF",
            raw: b"gitleaks:allow\r\nkey=AAAA\r\n",
            pattern: PATTERN,
            coordinates: [38, 38, 2, 9],
            line: b"\nkey=AAAA\r",
            matched: 16..24,
            secret: 20..24,
        },
    ];
    for case in cases {
        let exact = |range: &Range<usize>| {
            FindingRange::Exact(ByteRange::new(range.start, range.end).unwrap())
        };
        let finding = expected(case.coordinates, case.line)
            .match_text(&case.raw[case.matched.clone()])
            .secret(&case.raw[case.secret.clone()])
            .match_range(exact(&case.matched))
            .secret_range(exact(&case.secret))
            .build()
            .unwrap();
        let outcome =
            engine(case.pattern, None).scan_fragment(&fragment(case.raw), &ScanOptions::default());
        assert_eq!(outcome.findings(), &[finding], "{}", case.name);
        assert!(outcome.is_complete(), "{}", case.name);
    }

    // The match starts on line 2 and ends on the last line. As `reports.md`
    // documents, `EndLine` is then `StartLine` and `EndColumn` is 0, which
    // `Location::new` does not accept, so the fields are compared one by one.
    // The line does not reach back to the allow comment on line 1.
    let raw = b"gitleaks:allow\nkey=AA\nAA";
    let outcome =
        engine(r"key=(A)A\nAA", None).scan_fragment(&fragment(raw), &ScanOptions::default());
    assert!(outcome.is_complete());
    let [finding] = outcome.findings() else {
        panic!("one finding expected: {:?}", outcome.findings());
    };
    let location = finding.location();
    assert_eq!(
        [
            location.start_line(),
            location.end_line(),
            location.start_column(),
            location.end_column()
        ],
        [38, 38, 2, 0]
    );
    assert_eq!(finding.line().as_bytes(), b"\nkey=AA\nAA");
    assert_eq!(finding.match_text().as_bytes(), b"key=AA\nAA");
    assert_eq!(finding.secret().as_bytes(), b"A");

    for raw in [
        b"key=AAAA gitleaks:allow".as_slice(),
        b"x\nkey=AAAA gitleaks:allow",
        b"x\nkey=AAAA rustleaks:allow",
        b"x\r\nkey=AAAA gitleaks:allow",
        b"x\ngitleaks:allow key=AAAA",
    ] {
        let outcome = engine(PATTERN, None).scan_fragment(&fragment(raw), &ScanOptions::default());
        assert!(outcome.is_complete(), "{raw:?}");
        assert_eq!(outcome.findings(), &[], "{raw:?}");
    }
}

/// A line allowlist sees the same last line as an allow comment.
#[test]
fn line_allowlists_on_the_last_line_see_only_that_line() {
    let raw = b"skip\nkey=AAAA";
    let finding = expected([38, 38, 2, 9], b"\nkey=AAAA")
        .match_text(b"key=AAAA".as_slice())
        .secret(b"AAAA".as_slice())
        .match_range(FindingRange::Exact(ByteRange::new(5, 13).unwrap()))
        .secret_range(FindingRange::Exact(ByteRange::new(9, 13).unwrap()))
        .build()
        .unwrap();
    let outcome =
        engine(PATTERN, Some("skip")).scan_fragment(&fragment(raw), &ScanOptions::default());
    assert_eq!(outcome.findings(), &[finding]);
    let outcome = engine(PATTERN, Some("^\nkey=AAAA$"))
        .scan_fragment(&fragment(raw), &ScanOptions::default());
    assert_eq!(outcome.findings(), &[]);
}

#[test]
fn line_allowlists_use_decoded_line_bytes_and_surrounding_context() {
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let raw = [b"h\n[".as_slice(), BASE64, b"]\nt"].concat();
    let outcome =
        engine(PATTERN, Some(r"^\n\[key=AAAA;end\]$")).scan_fragment(&fragment(&raw), &options);
    assert_outcome(&outcome, &[], [18, 9, 0]);
    let line = [b"\n[".as_slice(), BASE64, b"]"].concat();
    let finding = decoded(
        [38, 38, 3, 18],
        &line,
        b"key=AAAA",
        &["decoded:base64", "decode-depth:1"],
    );
    let outcome =
        engine(PATTERN, Some("a2V5PUFBQUE7ZW5k")).scan_fragment(&fragment(&raw), &options);
    assert_outcome(&outcome, &[finding], [18, 9, 1]);

    let raw = [b"h\n[near ".as_slice(), BASE64, b"]\nt"].concat();
    let outcome = engine(PATTERN, Some("near")).scan_fragment(&fragment(&raw), &options);
    assert_outcome(&outcome, &[], [23, 9, 0]);
}
