#![forbid(unsafe_code)]
#![allow(missing_docs)]

use rustleaks_core::config::{ConfigLoader, ConfigOrigin, VirtualResolver};
use rustleaks_core::model::{ByteRange, ByteText, FindingRange, Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanScratch};

fn assert_send_sync<T: Send + Sync>() {}

fn build_engine(config: &str) -> Engine {
    let config = ConfigLoader::new().load_toml(config).unwrap();
    Engine::builder(config).build().unwrap()
}

#[test]
fn raw_detection_uses_keywords_captures_entropy_and_line_locations() {
    let engine = build_engine(
        r#"
[[rules]]
id = "token"
description = "Token"
regex = '''token\s*=\s*"([^"\n]+)"'''
keywords = ["TOKEN"]
tags = ["credential"]
"#,
    );
    let raw = b"prefix\n token=\"abc123\" tail\n";
    let fragment = Fragment::builder(raw).file_path("src/example.txt").build();
    let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());

    assert_eq!(outcome.findings().len(), 1);
    let finding = &outcome.findings()[0];
    assert_eq!(finding.rule_id().as_bytes(), b"token");
    assert_eq!(finding.match_text().as_bytes(), b"token=\"abc123\"");
    assert_eq!(finding.secret().as_bytes(), b"abc123");
    assert_eq!(finding.line().as_bytes(), b"\n token=\"abc123\" tail");
    assert_eq!(finding.location().start_line(), 2);
    assert_eq!(finding.location().end_line(), 2);
    assert_eq!(finding.location().start_column(), 3);
    assert_eq!(finding.location().end_column(), 16);
    assert_eq!(
        finding.match_range(),
        FindingRange::Exact(ByteRange::new(8, 22).unwrap())
    );
    assert_eq!(
        finding.secret_range(),
        FindingRange::Exact(ByteRange::new(15, 21).unwrap())
    );
    assert_eq!(finding.tags()[0].as_bytes(), b"credential");
    assert!(finding.entropy() > 2.0);
}

#[test]
fn fragments_start_at_line_one_unless_they_set_a_start_line() {
    let engine = build_engine(
        r#"
[[rules]]
id = "token"
regex = '''TOKEN'''
"#,
    );
    let raw = b"TOKEN\nTOKEN\n";
    let lines = |fragment: &Fragment| {
        let outcome = engine.scan_fragment(fragment, &ScanOptions::default());
        assert!(outcome.is_complete());
        outcome
            .findings()
            .iter()
            .map(|finding| {
                let location = finding.location();
                (location.start_line(), location.end_line())
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(Fragment::default().start_line(), 1);
    assert_eq!(Fragment::new(raw).start_line(), 1);
    assert_eq!(Fragment::builder(raw).build().start_line(), 1);
    assert_eq!(lines(&Fragment::new(raw)), [(1, 1), (2, 2)]);
    assert_eq!(
        lines(&Fragment::builder(raw).start_line(0).build()),
        [(0, 0), (1, 1)]
    );
    assert_eq!(
        lines(&Fragment::builder(raw).start_line(10).build()),
        [(10, 10), (11, 11)]
    );
}

#[test]
fn explicit_capture_allow_marker_and_exact_target_limit_are_applied() {
    let engine = build_engine(
        r#"
[[rules]]
id = "pair"
regex = '''(key)=([A-Z0-9]+)'''
secretGroup = 2
entropy = 1.0
keywords = ["key"]
"#,
    );
    let allowed = Fragment::new(b"key=AB12 // gitleaks:allow\n");
    assert!(
        engine
            .scan_fragment(&allowed, &ScanOptions::default())
            .findings()
            .is_empty()
    );
    let native_allowed = Fragment::new(b"key=AB12 // rustleaks:allow\n");
    assert!(
        engine
            .scan_fragment(&native_allowed, &ScanOptions::default())
            .findings()
            .is_empty()
    );

    let ignore_marker = ScanOptions::builder().honor_allow_markers(false).build();
    let findings = engine.scan_fragment(&allowed, &ignore_marker);
    assert_eq!(findings.findings()[0].secret().as_bytes(), b"AB12");
    assert_eq!(
        findings.findings()[0].match_range(),
        FindingRange::Exact(ByteRange::new(0, 8).unwrap())
    );
    assert_eq!(
        findings.findings()[0].secret_range(),
        FindingRange::Exact(ByteRange::new(4, 8).unwrap())
    );
    let findings = engine.scan_fragment(&native_allowed, &ignore_marker);
    assert_eq!(findings.findings()[0].secret().as_bytes(), b"AB12");

    let raw = Fragment::new(b"key=AB12");
    let below = ScanOptions::builder()
        .max_target_bytes(Some(raw.content().len() - 1))
        .build();
    assert!(engine.scan_fragment(&raw, &below).findings().is_empty());
    let exact = ScanOptions::builder()
        .max_target_bytes(Some(raw.content().len()))
        .build();
    assert_eq!(engine.scan_fragment(&raw, &exact).findings().len(), 1);

    let unmatched = build_engine(
        r#"
[[rules]]
id = "unmatched"
regex = '''(?:key=([A-Z0-9]+)|(other))'''
secretGroup = 2
"#,
    );
    let finding = unmatched.scan_fragment(&raw, &ScanOptions::default());
    assert_eq!(finding.findings()[0].secret().as_bytes(), b"");
    assert_eq!(
        finding.findings()[0].secret_range(),
        FindingRange::Unavailable
    );

    let trimmed = build_engine(
        r#"
[[rules]]
id = "trimmed"
regex = '''\nkey=AB12\n'''
"#,
    );
    let finding = trimmed.scan_fragment(&Fragment::new(b"\nkey=AB12\n"), &ScanOptions::default());
    assert_eq!(finding.findings()[0].match_text().as_bytes(), b"key=AB12");
    assert_eq!(finding.findings()[0].secret().as_bytes(), b"key=AB12");
    assert_eq!(
        finding.findings()[0].match_range(),
        FindingRange::Exact(ByteRange::new(1, 9).unwrap())
    );
    assert_eq!(
        finding.findings()[0].secret_range(),
        FindingRange::Exact(ByteRange::new(1, 9).unwrap())
    );
}

#[test]
fn path_only_and_path_plus_content_rules_check_both_path_spellings() {
    let path_only = build_engine(
        r#"
[[rules]]
id = "private-file"
path = '''(?i)secret\.txt$'''
"#,
    );
    let fragment = Fragment::builder(b"")
        .file_path("src/public.txt")
        .windows_file_path(r"C:\src\secret.txt")
        .build();
    let findings = path_only.scan_fragment(&fragment, &ScanOptions::default());
    assert_eq!(findings.findings().len(), 1);
    assert_eq!(
        findings.findings()[0].match_text().as_bytes(),
        b"file detected: src/public.txt"
    );
    assert_eq!(
        findings.findings()[0].match_range(),
        FindingRange::Unavailable
    );
    assert_eq!(
        findings.findings()[0].secret_range(),
        FindingRange::Unavailable
    );

    let both = build_engine(
        r#"
[[rules]]
id = "path-and-content"
path = '''\.env$'''
regex = '''secret=([a-z]+)'''
"#,
    );
    let mismatch = Fragment::builder(b"secret=value")
        .file_path("config.txt")
        .build();
    assert!(
        both.scan_fragment(&mismatch, &ScanOptions::default())
            .findings()
            .is_empty()
    );
    let matched = Fragment::builder(b"secret=value")
        .file_path("config.env")
        .build();
    assert_eq!(
        both.scan_fragment(&matched, &ScanOptions::default())
            .findings()
            .len(),
        1
    );

    assert_send_sync::<Engine>();
}

#[test]
fn an_empty_keyword_never_activates_its_rule() {
    let engine = build_engine(
        r#"
[[rules]]
id = "empty-keyword"
regex = '''TOKEN'''
keywords = [""]
"#,
    );
    assert!(
        engine
            .scan_fragment(&Fragment::new(b"TOKEN"), &ScanOptions::default())
            .findings()
            .is_empty()
    );
}

#[test]
fn shared_scans_are_deterministic_and_arbitrary_bytes_do_not_panic() {
    let engine = build_engine(
        r#"
[[rules]]
id = "bytes"
regex = '''(?s:.*?)'''
"#,
    );
    let bytes = (0_u8..=u8::MAX).collect::<Vec<_>>();
    let fragment = Fragment::builder(bytes.clone())
        .file_path(bytes.clone())
        .windows_file_path(bytes)
        .start_line(usize::MAX)
        .build();
    let expected =
        std::panic::catch_unwind(|| engine.scan_fragment(&fragment, &ScanOptions::default()))
            .expect("arbitrary fragment bytes must not panic");

    std::thread::scope(|scope| {
        let handles = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    (0..16)
                        .map(|_| engine.scan_fragment(&fragment, &ScanOptions::default()))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            for outcome in handle.join().unwrap() {
                assert_eq!(outcome, expected);
            }
        }
    });
}

#[test]
fn warmed_engine_and_clone_reuse_caches_across_distinct_haystacks() {
    type ExpectedSpans = (usize, usize, usize, usize);
    let engine = build_engine(
        r#"
[[rules]]
id = "token"
regex = '''token=([A-Z]+|\p{Greek}+)'''
secretGroup = 1
"#,
    );
    let assert_case = |engine: &Engine, raw: &[u8], expected: &[ExpectedSpans]| {
        // One pass, one rule entry, and one work unit per match candidate.
        let work = expected.len() + 2;
        let control = ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_work_units(work)
                .max_finding_records(expected.len())
                .max_decoded_bytes(0),
        );
        let outcome =
            engine.scan_fragment_controlled(&Fragment::new(raw), &ScanOptions::default(), &control);
        assert!(outcome.is_complete());
        assert_eq!(outcome.termination(), None);
        assert_eq!(outcome.usage().work_units(), work);
        assert_eq!(outcome.usage().finding_records(), expected.len());
        assert_eq!(outcome.usage().decoded_bytes(), 0);
        assert_eq!(outcome.findings().len(), expected.len());
        for (finding, &(start, end, secret_start, secret_end)) in
            outcome.findings().iter().zip(expected)
        {
            assert_eq!(finding.rule_id().as_bytes(), b"token");
            assert_eq!(
                finding.match_range(),
                FindingRange::Exact(ByteRange::new(start, end).unwrap())
            );
            assert_eq!(
                finding.secret_range(),
                FindingRange::Exact(ByteRange::new(secret_start, secret_end).unwrap())
            );
            assert_eq!(finding.match_text().as_bytes(), &raw[start..end]);
            assert_eq!(finding.secret().as_bytes(), &raw[secret_start..secret_end]);
        }
    };

    assert_case(&engine, b"token=ALPHA", &[(0, 11, 6, 11)]);
    let cloned = engine.clone();
    let cases: &[(&[u8], &[ExpectedSpans])] = &[
        (
            b"xx token=BETA yy token=GAMMA",
            &[(3, 13, 9, 13), (17, 28, 23, 28)],
        ),
        (b"\xfftoken=DELTA\x80", &[(1, 12, 7, 12)]),
        ("token=αβ".as_bytes(), &[(0, 10, 6, 10)]),
        (b"nothing useful here", &[]),
    ];
    for _ in 0..3 {
        for ((raw, expected), (other_raw, other_expected)) in cases.iter().zip(cases.iter().rev()) {
            assert_case(&engine, raw, expected);
            assert_case(&cloned, other_raw, other_expected);
        }
    }
}

#[test]
fn exact_ranges_preserve_invalid_source_bytes() {
    let engine = build_engine(
        r#"
[[rules]]
id = "invalid-bytes"
regex = '''(?s:token=(.+))'''
secretGroup = 1
keywords = ["token"]
"#,
    );
    let raw = b"token=\xffA";
    let outcome = engine.scan_fragment(&Fragment::new(raw), &ScanOptions::default());
    let finding = &outcome.findings()[0];

    assert_eq!(finding.match_text().as_bytes(), raw);
    assert_eq!(finding.secret().as_bytes(), b"\xffA");
    assert_eq!(
        finding.match_range(),
        FindingRange::Exact(ByteRange::new(0, 8).unwrap())
    );
    assert_eq!(
        finding.secret_range(),
        FindingRange::Exact(ByteRange::new(6, 8).unwrap())
    );
}

#[test]
fn decoded_findings_keep_decoded_text_and_original_location() {
    let engine = build_engine(
        r#"
[[rules]]
id = "decoded"
regex = '''secret=(decoded-secret)'''
secretGroup = 1
keywords = ["secret"]
tags = ["credential"]
"#,
    );
    let fragment = Fragment::builder(b"prefix\nsecret=ZGVjb2RlZC1zZWNyZXQ=\nsuffix")
        .file_path("encoded.txt")
        .build();
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let outcome = engine.scan_fragment(&fragment, &options);

    assert_eq!(outcome.findings().len(), 1);
    let finding = &outcome.findings()[0];
    assert_eq!(finding.match_text().as_bytes(), b"secret=decoded-secret");
    assert_eq!(finding.secret().as_bytes(), b"decoded-secret");
    assert_eq!(finding.line().as_bytes(), b"\nsecret=ZGVjb2RlZC1zZWNyZXQ=");
    assert_eq!(finding.location().start_line(), 2);
    assert_eq!(finding.location().end_line(), 2);
    assert_eq!(finding.location().start_column(), 2);
    assert_eq!(finding.location().end_column(), 28);
    assert_eq!(finding.match_range(), FindingRange::Unavailable);
    assert_eq!(finding.secret_range(), FindingRange::Unavailable);
    assert_eq!(
        finding
            .tags()
            .iter()
            .map(ByteText::as_bytes)
            .collect::<Vec<_>>(),
        vec![
            b"credential".as_slice(),
            b"decoded:base64",
            b"decode-depth:1"
        ]
    );

    let repeated = engine.scan_fragment(&fragment, &options);
    assert_eq!(repeated, outcome);
    assert_eq!(
        repeated.findings()[0]
            .tags()
            .iter()
            .map(ByteText::as_bytes)
            .collect::<Vec<_>>(),
        vec![
            b"credential".as_slice(),
            b"decoded:base64",
            b"decode-depth:1"
        ]
    );
}

#[test]
fn decode_depth_and_decoded_line_allowlist_are_applied_per_pass() {
    let engine = build_engine(
        r#"
[[rules]]
id = "decoded"
regex = '''secret=(decoded-secret)'''
secretGroup = 1
keywords = ["secret"]
"#,
    );
    let nested = Fragment::new(b"c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFE9");
    let one_pass = ScanOptions::builder().max_decode_depth(1).build();
    assert!(
        engine
            .scan_fragment(&nested, &one_pass)
            .findings()
            .is_empty()
    );
    let two_passes = ScanOptions::builder().max_decode_depth(2).build();
    let outcome = engine.scan_fragment(&nested, &two_passes);
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(
        outcome.findings()[0]
            .tags()
            .iter()
            .map(ByteText::as_bytes)
            .collect::<Vec<_>>(),
        vec![b"decoded:base64".as_slice(), b"decode-depth:2"]
    );

    let allowed = build_engine(
        r#"
[[rules]]
id = "decoded-line"
regex = '''password="([^"]*please-ignore-me[^"]*)"'''
secretGroup = 1
keywords = ["password"]

[[rules.allowlists]]
regexTarget = "line"
regexes = ['''please-ignore-me''']
"#,
    );
    let encoded =
        Fragment::new(b"password=\"bFJxQkstejVrZjQtcGxlYXNlLWlnbm9yZS1tZS1YLVhJSk0yUGRkdw==\"");
    assert!(
        allowed
            .scan_fragment(&encoded, &one_pass)
            .findings()
            .is_empty()
    );
}

#[test]
fn required_projection_and_inherited_decoding_are_preserved() {
    let composite = build_engine(
        r#"
[[rules]]
id = "primary"
regex = '''PRIMARY-VALUE'''
  [[rules.required]]
  id = "auxiliary"

[[rules]]
id = "auxiliary"
regex = '''AUXILIARY-VALUE'''
skipReport = true
"#,
    );
    let same_pass = Fragment::new(b"PRIMARY-VALUE AUXILIARY-VALUE");
    let projected = composite.scan_fragment(&same_pass, &ScanOptions::default());
    assert_eq!(projected.findings().len(), 1);
    assert_eq!(projected.findings()[0].rule_id().as_bytes(), b"primary");
    assert_eq!(projected.findings()[0].required_findings().len(), 1);
    assert_eq!(
        projected.findings()[0].required_findings()[0]
            .rule_id()
            .as_bytes(),
        b"auxiliary"
    );
    assert_eq!(
        projected.findings()[0].match_range(),
        FindingRange::Exact(ByteRange::new(0, 13).unwrap())
    );
    assert_eq!(
        projected.findings()[0].required_findings()[0].match_range(),
        FindingRange::Exact(ByteRange::new(14, 29).unwrap())
    );

    let inherited = Fragment::builder(b"%41UXILIARY-VALUE")
        .inherited_from_finding(true)
        .build();
    let decoded = ScanOptions::builder().max_decode_depth(1).build();
    let outcome = composite.scan_fragment(&inherited, &decoded);
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(outcome.findings()[0].rule_id().as_bytes(), b"auxiliary");
    assert_eq!(
        outcome.findings()[0].match_text().as_bytes(),
        b"AUXILIARY-VALUE"
    );
    assert_eq!(
        outcome.findings()[0]
            .tags()
            .iter()
            .map(ByteText::as_bytes)
            .collect::<Vec<_>>(),
        vec![b"decoded:percent".as_slice(), b"decode-depth:1"]
    );
}

#[test]
fn composite_auxiliaries_ignore_keywords_stop_recursion_and_preserve_multiplicity() {
    let composite = build_engine(
        r#"
[[rules]]
id = "primary"
regex = '''PRIMARY'''
  [[rules.required]]
  id = "auxiliary"
  withinLines = 0
  withinColumns = 4
  [[rules.required]]
  id = "auxiliary"
  withinLines = 0
  withinColumns = 4

[[rules]]
id = "auxiliary"
regex = '''AUX'''
keywords = ["keyword-that-is-absent"]
skipReport = true
  [[rules.required]]
  id = "deep"

[[rules]]
id = "deep"
regex = '''DEEP'''
skipReport = true
"#,
    );
    let outcome = composite.scan_fragment(&Fragment::new(b"AUX PRIMARY"), &ScanOptions::default());
    assert_eq!(outcome.findings().len(), 1);
    let required = outcome.findings()[0].required_findings();
    assert_eq!(required.len(), 2, "duplicate required specs append twice");
    assert!(
        required
            .iter()
            .all(|finding| finding.rule_id().as_bytes() == b"auxiliary")
    );

    let outside = build_engine(
        r#"
[[rules]]
id = "primary"
regex = '''PRIMARY'''
  [[rules.required]]
  id = "auxiliary"
  withinColumns = 3

[[rules]]
id = "auxiliary"
regex = '''AUX'''
skipReport = true
"#,
    );
    assert!(
        outside
            .scan_fragment(&Fragment::new(b"AUX PRIMARY"), &ScanOptions::default())
            .findings()
            .is_empty()
    );
}

const COMPOSITE_BASE: &str = r#"
[[rules]]
id = "primary"
regex = '''PRIMARY'''
  [[rules.required]]
  id = "secondary"

[[rules]]
id = "secondary"
regex = '''SECONDARY'''
"#;

/// Rule IDs of the findings and of their required findings.
fn composite_ids(engine: &Engine, input: &[u8]) -> Vec<(String, Vec<String>)> {
    engine
        .scan_fragment(&Fragment::new(input), &ScanOptions::default())
        .findings()
        .iter()
        .map(|finding| {
            (
                finding.rule_id().as_str().unwrap().to_owned(),
                finding
                    .required_findings()
                    .iter()
                    .map(|required| required.rule_id().as_str().unwrap().to_owned())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn extension_keeps_a_disabled_required_rule_as_a_helper() {
    let resolver = VirtualResolver::new().with_file("base.toml", COMPOSITE_BASE);
    let config = ConfigLoader::new()
        .with_resolver(resolver)
        .load_toml_at(
            "[extend]\npath='base.toml'\ndisabledRules=['secondary']\n",
            Some(ConfigOrigin::virtual_path("root.toml")),
        )
        .unwrap();
    // `secondary` stays for `primary` but does not report on its own.
    assert!(config.rule("secondary").unwrap().skip_report());
    let engine = Engine::builder(config).build().unwrap();
    assert_eq!(
        composite_ids(&engine, b"PRIMARY SECONDARY"),
        [("primary".to_owned(), vec!["secondary".to_owned()])]
    );
    assert!(composite_ids(&engine, b"SECONDARY").is_empty());
}

#[test]
fn selection_keeps_a_required_rule_as_a_helper() {
    let config = ConfigLoader::new().load_toml(COMPOSITE_BASE).unwrap();
    let selected = config.select_rules(["primary"]).unwrap();
    assert_eq!(selected.ordered_rule_ids(), ["primary"]);
    assert!(selected.rule("secondary").unwrap().skip_report());
    let engine = Engine::builder(selected).build().unwrap();
    assert_eq!(
        composite_ids(&engine, b"PRIMARY SECONDARY"),
        [("primary".to_owned(), vec!["secondary".to_owned()])]
    );
    assert!(composite_ids(&engine, b"PRIMARY").is_empty());
    assert!(composite_ids(&engine, b"SECONDARY").is_empty());

    // A selected required rule alone reports, as it does in the full set.
    let engine = Engine::builder(config.select_rules(["secondary"]).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        composite_ids(&engine, b"PRIMARY SECONDARY"),
        [("secondary".to_owned(), vec![])]
    );
}

#[test]
fn generic_suppression_precedes_partial_redaction() {
    let engine = build_engine(
        r#"
[[rules]]
id = "GeNeRiC-token"
regex = '''token=([a-z]+)'''
secretGroup = 1

[[rules]]
id = "specific"
regex = '''pair=(xx[a-z]+xx)'''
secretGroup = 1
"#,
    );
    let options = ScanOptions::builder().redaction_percent(75).build();
    let same_line = engine.scan_fragment(&Fragment::new(b"token=abc pair=xxabcxx"), &options);
    assert_eq!(same_line.findings().len(), 1);
    assert_eq!(same_line.findings()[0].rule_id().as_bytes(), b"specific");
    assert_eq!(same_line.findings()[0].secret().as_bytes(), b"xx...");

    let different_lines =
        engine.scan_fragment(&Fragment::new(b"token=abc\npair=xxabcxx"), &options);
    assert_eq!(different_lines.findings().len(), 2);
    assert!(different_lines.findings().iter().any(|finding| {
        finding.rule_id().as_bytes() == b"GeNeRiC-token" && finding.secret().as_bytes() == b"a..."
    }));
}

/// Standard padded base64, so that the test needs no encoder crate.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |value, (index, byte)| {
                value | (u32::from(*byte) << (16 - 8 * index))
            });
        for index in 0..4 {
            if index <= chunk.len() {
                let sextet = (value >> (18 - 6 * index)) & 0x3f;
                encoded.push(char::from(ALPHABET[sextet as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Synthetic fragments that reach many built-in rules, the decoder, captures
/// and the non-ASCII paths. Values are built at run time so that no literal
/// in this file looks like a credential.
fn varied_fragments() -> Vec<Vec<u8>> {
    let body = |seed: u8, length: usize| -> String {
        (0..length)
            .map(|index| {
                let value = u8::try_from(index % 256)
                    .unwrap()
                    .wrapping_mul(31)
                    .wrapping_add(seed)
                    % 62;
                char::from(match value {
                    0..=9 => b'0' + value,
                    10..=35 => b'a' + value - 10,
                    _ => b'A' + value - 36,
                })
            })
            .collect()
    };
    let mut fragments = vec![
        format!("api_{} = \"{}\"\n", "key", body(1, 32)).into_bytes(),
        format!("export AWS_SECRET_ACCESS_{}={}\n", "KEY", body(2, 40)).into_bytes(),
        format!(
            "password: {}\nauth_token = '{}'\n",
            body(3, 20),
            body(4, 36)
        )
        .into_bytes(),
        format!(
            "curl -H 'Authorization: Bearer {}' https://example.test\n",
            body(5, 48)
        )
        .into_bytes(),
        format!("postgres://user:{}@db.example.test:5432/app\n", body(6, 16)).into_bytes(),
        format!("ПАРОЛЬ token = \"{}\" ключ\n", body(7, 30)).into_bytes(),
        b"plain text without any secret, just words and numbers 12345\n".to_vec(),
    ];
    let mut invalid = format!("secret = \"{}\"", body(8, 24)).into_bytes();
    invalid.extend_from_slice(b"\xff\xfe\x80 trailing");
    fragments.push(invalid);
    // A base64 layer that the decoder opens.
    let inner = format!("client_{} = \"{}\"", "secret", body(9, 32));
    fragments.push(format!("data: {}\n", base64(inner.as_bytes())).into_bytes());
    // A large fragment, so that the kept buffers are trimmed.
    let mut large = Vec::new();
    while large.len() < 600 << 10 {
        large.extend_from_slice(
            format!("value_{} = \"{}\"\n", large.len(), body(10, 24)).as_bytes(),
        );
    }
    fragments.push(large);
    fragments
}

#[test]
fn scans_with_scratch_match_scans_without() {
    let engine = Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap();
    let fragments = varied_fragments();
    let options = ScanOptions::default();
    let control = ScanControl::unlimited();
    let expected: Vec<_> = fragments
        .iter()
        .map(|raw| {
            engine.scan_fragment_controlled(&Fragment::new(raw.as_slice()), &options, &control)
        })
        .collect();
    assert!(
        expected
            .iter()
            .any(|outcome| !outcome.findings().is_empty()),
        "the fragments must reach some rules"
    );
    // A limit of one byte drops every cache at each size update.
    for mut scratch in [ScanScratch::new(), ScanScratch::with_cache_limit(1)] {
        for round in 0..40 {
            for (index, raw) in fragments.iter().enumerate() {
                let outcome = engine.scan_fragment_with_scratch(
                    &Fragment::new(raw.as_slice()),
                    &options,
                    &control,
                    &mut scratch,
                );
                assert_eq!(outcome.usage(), expected[index].usage());
                assert!(
                    outcome == expected[index],
                    "fragment {index} differs in round {round}"
                );
            }
        }
    }
}

#[test]
fn one_scratch_serves_engines_with_different_keywords() {
    let first = build_engine(
        r#"
[[rules]]
id = "alpha"
regex = '''alpha=([a-z]{4})'''
keywords = ["alpha"]
"#,
    );
    let second = build_engine(
        r#"
[[rules]]
id = "beta"
regex = '''beta=([a-z]{4})'''
keywords = ["beta"]

[[rules]]
id = "gamma"
regex = '''gamma=([a-z]{4})'''
keywords = ["gamma"]

[[rules]]
id = "delta"
regex = '''delta=([a-z]{4})'''
keywords = ["delta"]
"#,
    );
    let options = ScanOptions::default();
    let control = ScanControl::unlimited();
    let mut scratch = ScanScratch::new();
    let raw: &[u8] = b"alpha=abcd beta=efgh gamma=ijkl delta=mnop";
    for _ in 0..3 {
        for engine in [&first, &second] {
            let expected = engine.scan_fragment_controlled(&Fragment::new(raw), &options, &control);
            let outcome = engine.scan_fragment_with_scratch(
                &Fragment::new(raw),
                &options,
                &control,
                &mut scratch,
            );
            assert!(outcome == expected);
        }
    }
    let findings = second
        .scan_fragment_with_scratch(&Fragment::new(raw), &options, &control, &mut scratch)
        .findings()
        .len();
    assert_eq!(findings, 3);
}

#[test]
fn scratch_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<ScanScratch>();
}
