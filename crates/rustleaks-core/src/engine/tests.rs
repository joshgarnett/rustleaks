use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

use base64::Engine as _;
use serde_json::Value;

use super::*;
use crate::config::ConfigLoader;

fn engine(config: &str) -> Engine {
    Engine::builder(ConfigLoader::new().load_toml(config).unwrap())
        .build()
        .unwrap()
}

fn upstream_location(newlines: &[usize], raw: &[u8], start: usize, end: usize) -> SourceLocation {
    super::upstream_location(newlines, raw, start, end, &Cell::new(None))
}

// Frozen capture-first extraction, retained only as differential evidence.
// The explicit table below states the expected results independently.
fn frozen_extract_secret<'a>(
    regex: &GoRegex,
    matched: &'a [u8],
    secret_group: i64,
) -> Option<ExtractedSecret<'a>> {
    let Some(captures) = regex.captures(matched) else {
        return Some(ExtractedSecret {
            bytes: matched,
            span: Some(ByteSpan {
                start: 0,
                end: matched.len(),
            }),
        });
    };
    if captures.spans().len() < 2 {
        return Some(ExtractedSecret {
            bytes: matched,
            span: Some(ByteSpan {
                start: 0,
                end: matched.len(),
            }),
        });
    }
    if secret_group > 0 {
        let index = usize::try_from(secret_group).ok()?;
        let span = captures.spans().get(index)?;
        return match span {
            Some(span) => Some(ExtractedSecret {
                bytes: matched.get(span.start..span.end)?,
                span: Some(*span),
            }),
            None => Some(ExtractedSecret {
                bytes: matched.get(..0)?,
                span: None,
            }),
        };
    }
    let span = captures
        .spans()
        .iter()
        .skip(1)
        .flatten()
        .find(|span| span.start != span.end)
        .copied()
        .unwrap_or(ByteSpan {
            start: 0,
            end: matched.len(),
        });
    Some(ExtractedSecret {
        bytes: matched.get(span.start..span.end)?,
        span: Some(span),
    })
}

type ExtractedView<'a> = Option<(&'a [u8], Option<(usize, usize)>)>;

fn extracted_view(extracted: Option<ExtractedSecret<'_>>) -> ExtractedView<'_> {
    extracted.map(|secret| (secret.bytes, secret.span.map(|span| (span.start, span.end))))
}

#[test]
fn extract_secret_preserves_every_group_and_search_branch() {
    const WHOLE_ABC: ExtractedView<'static> = Some((b"abc", Some((0, 3))));
    const INNER_B: ExtractedView<'static> = Some((b"b", Some((1, 2))));
    let cases: &[(&str, &[u8], i64, ExtractedView<'static>)] = &[
        // Without a group, a hit and a miss both yield the whole slice and
        // no secret-group value is consulted.
        ("abc", b"abc", 0, WHOLE_ABC),
        ("abc", b"abc", 1, WHOLE_ABC),
        ("abc", b"abc", 99, WHOLE_ABC),
        ("abc", b"abc", -1, WHOLE_ABC),
        ("^zzz$", b"abc", 0, WHOLE_ABC),
        ("^zzz$", b"abc", 1, WHOLE_ABC),
        ("(?:a)(?:b)c", b"abc", 1, WHOLE_ABC),
        (".", b"\xff\xfe", 0, Some((b"\xff\xfe", Some((0, 2))))),
        ("", b"", 0, Some((b"", Some((0, 0))))),
        ("^x$", b"", 3, Some((b"", Some((0, 0))))),
        // A group makes the search and every secret-group branch reachable.
        ("a(b)c", b"abc", 0, INNER_B),
        ("a(b)c", b"abc", 1, INNER_B),
        ("a(b)c", b"abc", -1, INNER_B),
        ("a(b)c", b"abc", 2, None),
        // A failed search returns before the secret group is validated.
        ("^(a)$", b"abc", 0, WHOLE_ABC),
        ("^(a)$", b"abc", 7, WHOLE_ABC),
        // Nonparticipating groups are empty without a span.
        ("a(b)?c", b"ac", 1, Some((b"", None))),
        ("a(b)?c", b"ac", 0, Some((b"ac", Some((0, 2))))),
        // Empty participating groups keep their span, and are skipped by
        // the first-nonempty fallback.
        ("a()c", b"ac", 1, Some((b"", Some((1, 1))))),
        ("a()c", b"ac", 0, Some((b"ac", Some((0, 2))))),
        ("(x?)(y)", b"y", 1, Some((b"", Some((0, 0))))),
        ("(x?)(y)", b"y", 0, Some((b"y", Some((0, 1))))),
        ("(x?)(y)", b"y", 2, Some((b"y", Some((0, 1))))),
        // Offsets are reported in the original source bytes.
        ("(.)x", b"\xffx", 1, Some((b"\xff", Some((0, 1))))),
        ("(.)x", b"\xc3\xa9x", 1, Some((b"\xc3\xa9", Some((0, 2))))),
    ];
    // A scratch is reused only by repeated searches of one expression.
    let regexes = cases
        .iter()
        .map(|(pattern, ..)| (*pattern, GoRegex::compile(pattern).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let mut scratches = BTreeMap::<&str, Option<CaptureScratch>>::new();
    for &(pattern, matched, group_index, expected) in cases.iter().chain(cases.iter().rev()) {
        let regex = &regexes[pattern];
        let label = format!("{pattern} on {matched:?}, group {group_index}");
        assert_eq!(
            extracted_view(frozen_extract_secret(regex, matched, group_index)),
            expected,
            "frozen {label}",
        );
        assert_eq!(
            extracted_view(extract_secret(regex, matched, group_index, &mut None)),
            expected,
            "fresh {label}",
        );
        let shared = scratches.entry(pattern).or_default();
        for attempt in ["first", "repeated"] {
            assert_eq!(
                extracted_view(extract_secret(regex, matched, group_index, shared)),
                expected,
                "{attempt} shared {label}",
            );
        }
    }
}

#[test]
fn groupless_extraction_does_not_allocate_capture_scratch() {
    let groupless = GoRegex::compile("(?:a)bc").unwrap();
    let mut scratch = None;
    assert!(extract_secret(&groupless, b"abc", 1, &mut scratch).is_some());
    assert!(scratch.is_none());
    let grouped = GoRegex::compile("a(b)c").unwrap();
    assert!(extract_secret(&grouped, b"abc", 1, &mut scratch).is_some());
    assert!(scratch.is_some());
}

#[test]
fn candidates_in_one_rule_pass_do_not_share_capture_results() {
    let detector = engine(
        r#"
[[rules]]
id = "probe"
regex = "(a)|(b)"
secretGroup = 2
"#,
    );
    let outcome = detector.scan_fragment(&Fragment::new(b"a b a"), &ScanOptions::default());
    assert!(outcome.is_complete());
    let observed = outcome
        .findings()
        .iter()
        .map(|finding| {
            (
                finding.match_text().as_bytes(),
                finding.secret().as_bytes(),
                finding.secret_range(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        [
            (b"a".as_slice(), b"".as_slice(), FindingRange::Unavailable),
            (
                b"b".as_slice(),
                b"b".as_slice(),
                FindingRange::Exact(ByteRange::new(2, 3).unwrap()),
            ),
            (b"a".as_slice(), b"".as_slice(), FindingRange::Unavailable),
        ]
    );
}

#[test]
fn groupless_rules_keep_trimmed_whole_match_secrets_and_ranges() {
    let detector = engine(
        r"
[[rules]]
id = 'probe'
regex = '''(?s)\A\nZX9\n\z'''
",
    );
    let outcome = detector.scan_fragment(&Fragment::new(b"\nZX9\n"), &ScanOptions::default());
    assert!(outcome.is_complete());
    let [finding] = outcome.findings() else {
        panic!("expected one finding, got {}", outcome.findings().len());
    };
    // The search over the trimmed slice misses; the secret stays trimmed.
    assert_eq!(finding.secret().as_bytes(), b"ZX9");
    assert_eq!(
        finding.secret_range(),
        FindingRange::Exact(ByteRange::new(1, 4).unwrap())
    );
    assert_eq!(
        finding.match_range(),
        FindingRange::Exact(ByteRange::new(1, 4).unwrap())
    );
}

// Frozen per-rule map lookup, retained only as differential evidence.
fn frozen_keyword_gate_open(
    rule: &CompiledRule,
    keyword_ids: &BTreeMap<String, usize>,
    matched_keywords: &[bool],
) -> bool {
    rule.keywords.is_empty()
        || rule.keywords.iter().any(|keyword| {
            keyword_ids
                .get(keyword)
                .is_some_and(|index| matched_keywords[*index])
        })
}

fn prefilter_keyword_ids(config: &CompiledConfig) -> BTreeMap<String, usize> {
    config
        .keywords
        .iter()
        .filter(|keyword| !keyword.is_empty())
        .cloned()
        .enumerate()
        .map(|(index, keyword)| (keyword, index))
        .collect()
}

#[test]
fn keyword_indexes_match_the_frozen_lookup_for_every_matched_subset() {
    let detector = engine(
        r#"
[[rules]]
id = "a-two"
regex = "A"
keywords = ["Alpha", "beta"]
[[rules]]
id = "b-repeated"
regex = "B"
keywords = ["beta", "beta"]
[[rules]]
id = "c-none"
regex = "C"
[[rules]]
id = "d-empty"
regex = "D"
keywords = [""]
[[rules]]
id = "e-empty-and-real"
regex = "E"
keywords = ["", "gamma"]
[[rules]]
id = "f-go-lowercase"
regex = "F"
keywords = ["\U0000212Aey", "\U00000130x"]
"#,
    );
    let keyword_ids = prefilter_keyword_ids(&detector.config);
    assert_eq!(
        keyword_ids.keys().map(String::as_str).collect::<Vec<_>>(),
        ["alpha", "beta", "gamma", "ix", "key"]
    );
    assert_eq!(detector.keyword_count, keyword_ids.len());
    assert_eq!(
        detector.rule_keyword_indexes.len(),
        detector.config.rules.len()
    );
    for mask in 0_u32..(1 << keyword_ids.len()) {
        let matched = (0..keyword_ids.len())
            .map(|index| mask & (1 << index) != 0)
            .collect::<Vec<_>>();
        for (rule, indexes) in detector
            .config
            .rules
            .values()
            .zip(&detector.rule_keyword_indexes)
        {
            assert_eq!(
                keyword_gate_open(rule, indexes, &matched),
                frozen_keyword_gate_open(rule, &keyword_ids, &matched),
                "rule {}, mask {mask:b}",
                rule.id,
            );
        }
    }
    // Stated independently of both implementations.
    let rules = &detector.config.rules;
    let indexes = |id: &str| {
        let ordinal = rules.keys().position(|rule| rule == id).unwrap();
        &*detector.rule_keyword_indexes[ordinal]
    };
    assert_eq!(indexes("a-two"), [0, 1]);
    assert_eq!(indexes("b-repeated"), [1, 1]);
    assert!(indexes("c-none").is_empty());
    assert!(indexes("d-empty").is_empty());
    assert_eq!(indexes("e-empty-and-real"), [2]);
    assert_eq!(indexes("f-go-lowercase"), [4, 3]);
    let none = [false; 5];
    assert!(keyword_gate_open(
        &rules["c-none"],
        indexes("c-none"),
        &none
    ));
    assert!(!keyword_gate_open(
        &rules["d-empty"],
        indexes("d-empty"),
        &[true; 5]
    ));
}

#[test]
fn default_rule_keyword_indexes_match_the_frozen_lookup() {
    let detector = Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap();
    let keyword_ids = prefilter_keyword_ids(&detector.config);
    assert_eq!(detector.keyword_count, keyword_ids.len());
    assert_eq!(
        detector.rule_keyword_indexes.len(),
        detector.config.rules.len()
    );
    for (rule, indexes) in detector
        .config
        .rules
        .values()
        .zip(&detector.rule_keyword_indexes)
    {
        let expected = rule
            .keywords
            .iter()
            .filter_map(|keyword| keyword_ids.get(keyword).copied())
            .collect::<Vec<_>>();
        assert_eq!(&**indexes, expected.as_slice(), "rule {}", rule.id);
    }
}

fn explained_keyword_events(
    detector: &Engine,
    fragment: &Fragment,
    options: &ScanOptions,
) -> (ScanOutcome, Vec<(Option<usize>, usize, ExplanationReason)>) {
    let (outcome, log) = detector.scan_fragment_explained(
        fragment,
        options,
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
        false,
    );
    assert!(!log.is_truncated());
    let events = log
        .events()
        .iter()
        .filter(|event| {
            matches!(
                event.reason(),
                ExplanationReason::RuleSelected
                    | ExplanationReason::KeywordMatched
                    | ExplanationReason::KeywordMissed
                    | ExplanationReason::KeywordNotRequired
            )
        })
        .map(|event| (event.rule_ordinal(), event.decoded_pass(), event.reason()))
        .collect();
    (outcome, events)
}

#[test]
fn keyword_gate_explanations_and_work_units_are_pinned() {
    use ExplanationReason::{KeywordMatched, KeywordMissed, KeywordNotRequired, RuleSelected};

    let detector = engine(
        r#"
[[rules]]
id = "a-two"
regex = "TOK"
keywords = ["alpha", "beta"]
[[rules]]
id = "b-one"
regex = "TOK"
keywords = ["beta"]
[[rules]]
id = "c-none"
regex = "TOK"
[[rules]]
id = "d-empty"
regex = "TOK"
keywords = [""]
[[rules]]
id = "e-miss"
regex = "TOK"
keywords = ["gamma"]
"#,
    );
    let (outcome, events) = explained_keyword_events(
        &detector,
        &Fragment::new(b"beta TOK"),
        &ScanOptions::default(),
    );
    assert!(outcome.is_complete());
    assert_eq!(
        events,
        [
            (Some(0), 0, RuleSelected),
            (Some(0), 0, KeywordMatched),
            (Some(1), 0, RuleSelected),
            (Some(1), 0, KeywordMatched),
            (Some(2), 0, RuleSelected),
            (Some(2), 0, KeywordNotRequired),
            (Some(3), 0, RuleSelected),
            (Some(3), 0, KeywordMissed),
            (Some(4), 0, RuleSelected),
            (Some(4), 0, KeywordMissed),
        ]
    );
    assert_eq!(
        outcome
            .findings()
            .iter()
            .map(|finding| finding.rule_id().as_bytes())
            .collect::<Vec<_>>(),
        [
            b"a-two".as_slice(),
            b"b-one".as_slice(),
            b"c-none".as_slice()
        ]
    );
    // One pass start, one emitted keyword, three admitted rules, and one
    // content match for each admitted rule.
    assert_eq!(outcome.usage().work_units(), 1 + 1 + 3 + 3);
}

#[test]
fn extended_base64_options_preserve_defaults_and_decoded_byte_admission() {
    use crate::Base64Mode;

    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Base64Mode>();
    assert_send_sync::<ScanOptions>();
    assert_eq!(Base64Mode::default(), Base64Mode::Compatible);
    assert_eq!(ScanOptions::default().base64_mode(), Base64Mode::Compatible);
    let detector = engine(
        r#"
[[rules]]
id = "binary-base64"
regex = 'token=(AB12)'
secretGroup = 1
"#,
    );
    let fragment = Fragment::new(b"+///AHRva2VuPUFCMTIhIQ==");
    let compatible = ScanOptions::builder().max_decode_depth(1).build();
    assert!(
        detector
            .scan_fragment(&fragment, &compatible)
            .findings()
            .is_empty()
    );
    let disabled = ScanOptions::builder()
        .base64_mode(Base64Mode::Extended)
        .build();
    assert!(
        detector
            .scan_fragment(&fragment, &disabled)
            .findings()
            .is_empty()
    );
    let options = ScanOptions::builder()
        .base64_mode(Base64Mode::Extended)
        .max_decode_depth(1)
        .build();
    let admitted = detector.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_decoded_bytes(16)),
    );
    assert!(admitted.is_complete());
    assert_eq!(admitted.usage().decoded_bytes(), 16);
    assert_eq!(admitted.findings().len(), 1);
    assert_eq!(admitted.findings()[0].secret().as_bytes(), b"AB12");
    assert_eq!(
        admitted.findings()[0].match_text().as_bytes(),
        b"token=AB12"
    );
    let rejected = detector.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_decoded_bytes(15)),
    );
    assert!(rejected.findings().is_empty());
    assert_eq!(rejected.usage().decoded_bytes(), 0);
    assert!(matches!(
        rejected.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::DecodedBytes,
            limit: 15,
            consumed: 0,
            requested: 16,
        })
    ));
    let cancelled =
        detector.scan_fragment_controlled(&fragment, &options, &ScanControl::cancellable(&|| true));
    assert!(cancelled.findings().is_empty());
    assert_eq!(cancelled.termination(), Some(&ScanTermination::Cancelled));
}

#[test]
fn keyword_flags_from_one_pass_do_not_admit_a_later_decoded_pass() {
    use ExplanationReason::{KeywordMatched, KeywordMissed, KeywordNotRequired, RuleSelected};

    // The keyword exists only in the encoded spelling, so it is absent from
    // the decoded pass where the rule's expression would otherwise match.
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello world, hello");
    assert!(encoded.to_ascii_lowercase().contains("agvsbg8g"));
    let detector = engine(
        r#"
[[rules]]
id = "control"
regex = "hello"
[[rules]]
id = "encoded-keyword"
regex = "hello"
keywords = ["agvsbg8g"]
"#,
    );
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let (outcome, events) =
        explained_keyword_events(&detector, &Fragment::new(encoded.as_bytes()), &options);
    assert!(outcome.is_complete());
    assert_eq!(
        events,
        [
            (Some(0), 0, RuleSelected),
            (Some(0), 0, KeywordNotRequired),
            (Some(1), 0, RuleSelected),
            (Some(1), 0, KeywordMatched),
            (Some(0), 1, RuleSelected),
            (Some(0), 1, KeywordNotRequired),
            (Some(1), 1, RuleSelected),
            (Some(1), 1, KeywordMissed),
        ]
    );
    assert_eq!(outcome.findings().len(), 2);
    for finding in outcome.findings() {
        assert_eq!(finding.rule_id().as_bytes(), b"control");
    }
}

// Frozen ordered-map computation, retained only as differential evidence.
fn frozen_shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = BTreeMap::<char, usize>::new();
    for character in go_chars(bytes) {
        *counts.entry(character).or_default() += 1;
    }
    let inverse_length = 1.0 / usize_to_f64(bytes.len());
    counts.values().fold(0.0, |entropy, count| {
        let frequency = usize_to_f64(*count) * inverse_length;
        entropy - frequency * frequency.log2()
    })
}

/// The defining sum over counts given in ascending symbol order.
fn entropy_of_ordered_counts(counts: &[usize], byte_length: usize) -> f64 {
    let inverse_length = 1.0 / usize_to_f64(byte_length);
    counts.iter().fold(0.0, |entropy, count| {
        let frequency = usize_to_f64(*count) * inverse_length;
        entropy - frequency * frequency.log2()
    })
}

#[test]
fn entropy_values_are_specified_by_exact_bits() {
    for (input, expected_bits) in [
        // Empty, and every single-symbol input, has zero entropy.
        (b"".as_slice(), 0_u64),
        (b"a".as_slice(), 0),
        (b"aaaa".as_slice(), 0),
        (b"\x00".as_slice(), 0),
        (b"\x7f\x7f".as_slice(), 0),
        // Equal frequencies with exact powers of two.
        (b"ab".as_slice(), 1.0_f64.to_bits()),
        (b"abcd".as_slice(), 2.0_f64.to_bits()),
        (b"\x00\x7f".as_slice(), 1.0_f64.to_bits()),
        // Non-ASCII input divides by byte length, not symbol count.
        ("\u{e9}".as_bytes(), 0.5_f64.to_bits()),
        // Each invalid byte is one replacement symbol.
        (b"\xff\xfe".as_slice(), 0),
        (b"\xffa".as_slice(), 1.0_f64.to_bits()),
    ] {
        let actual = shannon_entropy(input);
        assert_eq!(actual.to_bits(), expected_bits, "{input:?}");
        assert_eq!(frozen_shannon_entropy(input).to_bits(), expected_bits);
    }
    let every_ascii = (0_u8..128).collect::<Vec<_>>();
    assert_eq!(
        shannon_entropy(&every_ascii).to_bits(),
        7.0_f64.to_bits(),
        "all 128 ASCII symbols with equal frequency",
    );
}

#[test]
fn ascii_entropy_sums_counts_in_ascending_symbol_order() {
    // The input lists the most frequent symbol first. These counts make
    // the sum depend on its order, so the expected bits take the counts
    // in ascending symbol order, independent of how the input is arranged.
    let counts = [1, 3, 5_usize];
    let mut input = Vec::new();
    for (symbol, count) in (b'a'..=b'c').zip(&counts).rev() {
        input.extend(std::iter::repeat_n(symbol, *count));
    }
    let expected = entropy_of_ordered_counts(&counts, input.len());
    assert_eq!(shannon_entropy(&input).to_bits(), expected.to_bits());
    assert_eq!(frozen_shannon_entropy(&input).to_bits(), expected.to_bits());
}

#[test]
fn entropy_histogram_is_bit_identical_to_the_frozen_map() {
    let check = |input: &[u8]| {
        assert_eq!(
            shannon_entropy(input).to_bits(),
            frozen_shannon_entropy(input).to_bits(),
            "{input:?}",
        );
    };
    check(b"");
    for first in 0_u8..=255 {
        check(&[first]);
        for second in 0_u8..=255 {
            check(&[first, second]);
        }
    }
    for prefix in [b"".as_slice(), "\u{212a}".as_bytes(), "\u{130}".as_bytes()] {
        for tail in [b"".as_slice(), b"a", b"\xff", b"\xe2\x82"] {
            let mut input = prefix.to_vec();
            input.extend_from_slice(tail);
            check(&input);
        }
    }
    // Deterministic ASCII inputs over several alphabet and length sizes.
    let mut state = 0x9e37_79b9_u32;
    for alphabet in [1_u32, 2, 8, 64, 128] {
        for length in [1_usize, 2, 7, 31, 32, 33, 128, 1024] {
            for _ in 0..4 {
                let input = (0..length)
                    .map(|_| {
                        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        u8::try_from((state >> 8) % alphabet).unwrap()
                    })
                    .collect::<Vec<_>>();
                check(&input);
            }
        }
    }
}

#[test]
fn deferred_entropy_keeps_decisions_explanations_and_finding_values() {
    use ExplanationReason::{
        AllowlistMatched, AllowlistNotMatched, CandidateAccepted, EntropyAccepted,
        EntropyNotRequired, EntropyRejected, KeywordNotRequired, PatternMatched, RuleSelected,
    };

    let detector = engine(
        r#"
[[rules]]
id = "threshold"
regex = "x(ab)x|y(abc)y"
entropy = 1.0
[[rules]]
id = "zero"
regex = "abcd"
[[rules]]
id = "zero-allowed"
regex = "abcd"
[[rules.allowlists]]
stopwords = ["abcd"]
"#,
    );
    let (outcome, log) = detector.scan_fragment_explained(
        &Fragment::new(b"xabx yabcy abcd"),
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
        false,
    );
    assert!(outcome.is_complete());
    let reasons = |ordinal: usize| {
        log.events()
            .iter()
            .filter(|event| event.rule_ordinal() == Some(ordinal))
            .map(|event| event.reason())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        reasons(0),
        [
            RuleSelected,
            KeywordNotRequired,
            AllowlistNotMatched,
            PatternMatched,
            EntropyRejected,
            PatternMatched,
            EntropyAccepted,
            AllowlistNotMatched,
            CandidateAccepted,
        ]
    );
    assert_eq!(
        reasons(1),
        [
            RuleSelected,
            KeywordNotRequired,
            AllowlistNotMatched,
            PatternMatched,
            EntropyNotRequired,
            AllowlistNotMatched,
            CandidateAccepted,
        ]
    );
    assert_eq!(
        reasons(2),
        [
            RuleSelected,
            KeywordNotRequired,
            AllowlistNotMatched,
            PatternMatched,
            EntropyNotRequired,
            AllowlistMatched,
        ]
    );

    let findings = outcome
        .findings()
        .iter()
        .map(|finding| {
            (
                finding.rule_id().as_bytes().to_vec(),
                finding.secret().as_bytes().to_vec(),
                finding.entropy().to_bits(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        findings,
        [
            (
                b"threshold".to_vec(),
                b"abc".to_vec(),
                entropy_to_f32(frozen_shannon_entropy(b"abc")).to_bits(),
            ),
            (b"zero".to_vec(), b"abcd".to_vec(), 2.0_f32.to_bits()),
        ]
    );
}

#[test]
fn canonical_entropy_is_one_proven_go_admissible_value() {
    let mut bytes = Vec::new();
    for (index, byte) in (b'a'..=b'j').enumerate() {
        bytes.extend(std::iter::repeat_n(byte, index + 1));
    }
    let entropy = shannon_entropy(&bytes);
    assert_eq!(entropy.to_bits(), 0x4008_d443_070e_ac15);
    assert_eq!(entropy_to_f32(entropy).to_bits(), 0x4046_a218);
    assert!(entropy <= f64::from_bits(0x4008_d443_070e_ac15));
}

#[test]
fn newline_indices_preserve_literal_byte_boundaries() {
    for (raw, expected) in [
        (b"".as_slice(), vec![]),
        (b"\n".as_slice(), vec![0]),
        (b"\r".as_slice(), vec![]),
        (b"\r\n".as_slice(), vec![1]),
        (b"\xff\n\x80\r\xfe\n\0".as_slice(), vec![1, 5]),
        (b"1234567\n\x0b\n\x0b\r\n".as_slice(), vec![7, 9, 12]),
        (b"\x0b\n\x0b\n\x0b\n\x0b\n".as_slice(), vec![1, 3, 5, 7]),
        (b"\n\x0b\n\x0b\n\x0b\n\x0b".as_slice(), vec![0, 2, 4, 6]),
    ] {
        assert_eq!(newline_indices(raw), expected, "raw {raw:?}");
    }
    assert_eq!(newline_indices(&[b'\n'; 129]), (0..129).collect::<Vec<_>>());
}

#[test]
fn newline_indices_cover_every_byte_alignment_and_remainder() {
    for byte in 0..=u8::MAX {
        for alignment in 0..8 {
            for remainder in 0..8 {
                let length = 24 + remainder;
                let backing = vec![byte; alignment + length];
                let expected = if byte == b'\n' {
                    (0..length).collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                assert_eq!(
                    newline_indices(&backing[alignment..]),
                    expected,
                    "byte {byte}, alignment {alignment}, remainder {remainder}",
                );
            }
        }
    }
}

#[test]
fn newline_indices_keep_only_the_lf_in_every_chunk_position() {
    for length in 1..=40 {
        for newline in 0..length {
            // XOR with LF makes each neighbor 0x01. Borrowing during the
            // word test can mark it too, but it is not another newline.
            let mut raw = vec![0x0b; length];
            raw[newline] = b'\n';
            assert_eq!(newline_indices(&raw), vec![newline]);
        }
    }
}

#[test]
fn upstream_location_matches_pinned_helper_assertions() {
    let raw = vec![b'x'; 57];
    let first = upstream_location(&[0, 40, 56], &raw, 35, 38);
    assert_eq!(
        (
            first.start_line,
            first.start_column,
            first.end_line,
            first.end_column,
            first.start_line_index,
            first.end_line_index,
        ),
        (1, 36, 1, 38, 0, 40)
    );
    let second = upstream_location(&[0, 40, 56], &raw, 40, 44);
    assert_eq!(
        (
            second.start_line,
            second.start_column,
            second.end_line,
            second.end_column,
            second.start_line_index,
            second.end_line_index,
        ),
        (2, 1, 2, 4, 40, 56)
    );
}

#[test]
fn upstream_location_preserves_newline_and_empty_span_edges() {
    let raw = b"a\nbc\nd\r";
    for (start, end, expected) in [
        (0, 0, (0, 0, 1, 0, 0, 1)),
        (0, 1, (0, 0, 1, 1, 0, 1)),
        (1, 1, (1, 1, 1, 1, 1, 4)),
        (1, 4, (1, 1, 1, 3, 1, 4)),
        (4, 4, (2, 2, 1, 0, 0, 4)),
        (4, 5, (2, 2, 1, 1, 0, 6)),
        (5, 6, (2, 2, 2, 2, 0, 6)),
        (0, 6, (0, 0, 1, 0, 0, 6)),
    ] {
        let location = upstream_location(&[1, 4], raw, start, end);
        assert_eq!(
            (
                location.start_line,
                location.end_line,
                location.start_column,
                location.end_column,
                location.start_line_index,
                location.end_line_index
            ),
            expected,
            "span {start}..{end}",
        );
    }
    assert_eq!(
        upstream_location(&[], b"", 0, 0),
        SourceLocation {
            start_line: 1,
            end_line: 1,
            start_column: 1,
            end_column: 0,
            start_line_index: 0,
            end_line_index: 0,
        }
    );
    assert_eq!(
        upstream_location(&[], b"ab", 0, 0),
        SourceLocation {
            start_line: 0,
            end_line: 0,
            start_column: 1,
            end_column: 0,
            start_line_index: 0,
            end_line_index: 2,
        }
    );
    assert_eq!(
        upstream_location(&[], b"ab", 2, 2),
        SourceLocation {
            start_line: 1,
            end_line: 1,
            start_column: 1,
            end_column: 0,
            start_line_index: 0,
            end_line_index: 2,
        }
    );
}

#[test]
fn indexed_location_matches_the_previous_loop_for_all_small_spans() {
    for length in 0..=8 {
        for mask in 0..(1 << length) {
            let raw = (0..length)
                .map(|index| {
                    if mask & (1 << index) == 0 {
                        b'x'
                    } else {
                        b'\n'
                    }
                })
                .collect::<Vec<_>>();
            let newlines = raw
                .iter()
                .enumerate()
                .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
                .collect::<Vec<_>>();
            let indexed = newline_indices(&raw);
            assert_eq!(indexed, newlines);
            for start in 0..=length {
                for end in start..=length {
                    assert_eq!(
                        upstream_location(&indexed, &raw, start, end),
                        linear_upstream_location(&newlines, &raw, start, end),
                        "length {length}, newline mask {mask}, span {start}..{end}"
                    );
                }
            }
        }
    }
}

// Frozen previous helper used only as differential evidence. The explicit
// edge cases above specify expected results independently of this loop.
fn linear_upstream_location(
    newlines: &[usize],
    raw: &[u8],
    start: usize,
    end: usize,
) -> SourceLocation {
    let fallback;
    let newlines = if newlines.is_empty() {
        fallback = [raw.len()];
        &fallback[..]
    } else {
        newlines
    };
    let mut previous = 0;
    let mut location = SourceLocation {
        start_line: 0,
        end_line: 0,
        start_column: 0,
        end_column: 0,
        start_line_index: 0,
        end_line_index: 0,
    };
    let mut line_set = false;
    let mut last_line = 0;
    for (line_number, &newline) in newlines.iter().enumerate() {
        last_line = line_number;
        if previous <= start && start < newline {
            line_set = true;
            location.start_line = line_number;
            location.end_line = line_number;
            location.start_column = start - previous + 1;
            location.start_line_index = previous;
            location.end_line_index = newline;
        }
        if previous < end && end <= newline {
            location.end_line = line_number;
            location.end_column = end - previous;
            location.end_line_index = newline;
        }
        previous = newline;
    }
    if !line_set {
        location.start_column = start - previous + 1;
        location.end_column = end - previous;
        location.start_line = last_line + 1;
        location.end_line = last_line + 1;
        location.end_line_index = raw[end..]
            .iter()
            .position(|byte| matches!(byte, b'\n' | b'\r'))
            .map_or(raw.len(), |distance| end + distance);
    }
    if end > location.end_line_index {
        location.end_line_index = end;
    }
    location
}

#[test]
fn shared_line_cache_is_exact_bounded_and_weak() {
    let context = OriginalFragmentContext::default();
    let raw = vec![0xff; 8192];
    let first = context.admitted_line(&raw[..4096], 0, 4096);
    let again = context.admitted_line(&raw[..4096], 0, 4096);
    assert_eq!(first.as_bytes().as_ptr(), again.as_bytes().as_ptr());
    let weak = context.line.borrow().as_ref().unwrap().bytes.clone();
    let other = context.admitted_line(&raw[4096..], 4096, 8192);
    assert_ne!(first.as_bytes().as_ptr(), other.as_bytes().as_ptr());
    let other_fragment = OriginalFragmentContext::default();
    let independent = other_fragment.admitted_line(&raw[..4096], 0, 4096);
    assert_ne!(first.as_bytes().as_ptr(), independent.as_bytes().as_ptr());
    drop(first);
    drop(again);
    assert!(weak.upgrade().is_none());
    let weak = context.line.borrow().as_ref().unwrap().bytes.clone();
    drop(other);
    assert!(weak.upgrade().is_none());
    let short = context.admitted_line(b"short", 0, 5);
    assert_eq!(short.as_bytes(), b"short");
    assert!(
        context
            .line
            .borrow()
            .as_ref()
            .unwrap()
            .bytes
            .upgrade()
            .is_none()
    );
}

#[test]
fn decoded_and_raw_findings_share_only_the_original_line() {
    let detector = engine("[[rules]]\nid = 'r'\nregex = 'abcdefghijkl'\n");
    let mut raw = vec![b'.'; 4096];
    raw.extend_from_slice(b"abcdefghijkl YWJjZGVmZ2hpamts");
    let fragment = Fragment::new(raw);
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let outcome = detector.scan_fragment(&fragment, &options);
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings().len(), 2);
    for finding in outcome.findings() {
        assert_eq!(finding.line().as_bytes(), fragment.content().as_bytes());
        assert_eq!(finding.secret().as_bytes(), b"abcdefghijkl");
    }
    assert_eq!(
        outcome.findings()[0].line().as_bytes().as_ptr(),
        outcome.findings()[1].line().as_bytes().as_ptr()
    );
}

#[test]
fn cached_marker_results_use_exact_original_source_bounds() {
    let context = OriginalFragmentContext::default();
    let raw = b"Xrustleaks:allowY\nZgitleaks:allowQ\r\n\xff";
    for (start, end, expected) in [(1, 16, true), (1, 15, false), (2, 16, false), (0, 0, false)] {
        assert_eq!(
            context.has_allow_marker(&raw[start..end], start, end),
            expected
        );
    }
    for start in (0..=raw.len()).rev() {
        for end in start..=raw.len() {
            let line = &raw[start..end];
            let expected = contains_bytes(line, RUSTLEAKS_ALLOW_SIGNATURE)
                || contains_bytes(line, ALLOW_SIGNATURE);
            assert_eq!(context.has_allow_marker(line, start, end), expected);
            assert_eq!(context.has_allow_marker(line, start, end), expected);
        }
    }
}

#[test]
fn tail_search_reuses_only_its_inclusive_covered_interval() {
    let raw = b"\nAB\rCD\rEF";
    let cache = Cell::new(None);
    for (from, expected, interval) in [
        (1, 3, (1, 3)),
        (2, 3, (1, 3)),
        (3, 3, (1, 3)),
        (4, 6, (4, 6)),
        (6, 6, (4, 6)),
        (7, 9, (7, 9)),
        (9, 9, (7, 9)),
        (2, 3, (2, 3)),
        (0, 0, (0, 0)),
        (5, 6, (5, 6)),
    ] {
        assert_eq!(next_line_break(raw, from, &cache), expected);
        assert_eq!(cache.get(), Some(interval));
    }
}

#[test]
fn cached_locations_match_pinned_loop_for_reordered_crlf_and_empty_spans() {
    for raw in [b"".as_slice(), b"abc\rdef", b"\nAB\rCD\rEF", b"a\r\nb\nc\r"] {
        let newlines = raw
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
            .collect::<Vec<_>>();
        let spans = (0..=raw.len())
            .flat_map(|start| (start..=raw.len()).map(move |end| (start, end)))
            .collect::<Vec<_>>();
        let cache = Cell::new(None);
        for &(start, end) in spans.iter().chain(spans.iter().rev()) {
            assert_eq!(
                super::upstream_location(&newlines, raw, start, end, &cache),
                linear_upstream_location(&newlines, raw, start, end),
                "raw {raw:?}, span {start}..{end}",
            );
        }
    }
}

#[test]
fn marker_cache_retains_pinned_prefix_and_disabled_option_behavior() {
    let detector = engine("[[rules]]\nid = 'probe'\nregex = 'ZX9'\n");
    let disabled = ScanOptions::builder().honor_allow_markers(false).build();
    for (raw, suppressed_count, offsets) in [
        (b"ZX9 rustleaks:allow ZX9".as_slice(), 0, vec![0, 20]),
        (b"rustleaks:allow\nZX9".as_slice(), 0, vec![16]),
        (b"rustleaks:allow\nZX9\n".as_slice(), 1, vec![16]),
    ] {
        let fragment = Fragment::new(raw);
        let honored = detector.scan_fragment(&fragment, &ScanOptions::default());
        assert!(honored.is_complete());
        assert_eq!(honored.findings().len(), suppressed_count);
        assert_eq!(honored.usage().finding_records(), suppressed_count);
        assert_eq!(honored.usage().work_units(), offsets.len() + 2);
        let ignored = detector.scan_fragment(&fragment, &disabled);
        assert!(ignored.is_complete());
        assert_eq!(ignored.usage().work_units(), offsets.len() + 2);
        assert_eq!(ignored.usage().finding_records(), offsets.len());
        for (finding, start) in ignored.findings().iter().zip(offsets) {
            assert_eq!(
                finding.match_range().exact().unwrap().as_range(),
                start..start + 3
            );
        }
    }
}

#[test]
fn line_regex_memo_preserves_slice_length_invalid_bytes_and_multiline_anchors() {
    let detector = engine(
        r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[allowlists]]
regexTarget = "line"
regexes = ['''^\x{FFFD}x$''', '''(?s)^A\nB\r\n$''']
"#,
    );
    let allowlist = &detector.config.allowlists[0];
    let malformed = b"\xffxx";
    let multiline = b"A\nB\r\n";
    let mut cache = Vec::new();
    for (line, expected) in [
        (&malformed[..2], true),
        (&malformed[..], false),
        (&multiline[..], true),
        (&multiline[..4], false),
        (&malformed[..2], true),
        (b"\xffx".as_slice(), true),
    ] {
        assert_eq!(
            line_regex_allowed(allowlist, line, 0, 1, &mut cache),
            expected
        );
        assert_eq!(allowlist.regex_allowed(line), expected);
        assert!(std::ptr::eq(cache[0].unwrap().line, line));
    }
    let mut empty = Vec::new();
    assert!(!line_regex_allowed(allowlist, b"", 0, 1, &mut empty));
    assert!(empty.is_empty());
}

#[test]
fn line_regex_memo_keeps_global_and_rule_predicates_and_conditions_separate() {
    let detector = engine(
        r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[rules.allowlists]]
condition = "AND"
regexTarget = "line"
regexes = ['''RULE$''']
stopwords = ["accepted"]
commits = ["abc"]
paths = ['''^ok$''']
[[allowlists]]
condition = "OR"
regexTarget = "line"
regexes = ['''GLOBAL$''']
stopwords = ["override"]
"#,
    );
    let global = &detector.config.allowlists;
    let rule = &detector.config.rules["probe"].allowlists;
    let good = Fragment::builder(b"").file_path("ok").commit("ABC").build();
    let bad_path = Fragment::builder(b"")
        .file_path("other")
        .commit("ABC")
        .build();
    let bad_commit = Fragment::builder(b"")
        .file_path("ok")
        .commit("other")
        .build();
    let mut memo = LineAllowlistMemo::default();
    for (fragment, secret, line, expected) in [
        (
            &good,
            b"accepted".as_slice(),
            b"RULE".as_slice(),
            (false, true),
        ),
        (
            &good,
            b"other".as_slice(),
            b"RULE".as_slice(),
            (false, false),
        ),
        (
            &bad_path,
            b"accepted".as_slice(),
            b"RULE".as_slice(),
            (false, false),
        ),
        (
            &bad_commit,
            b"accepted".as_slice(),
            b"RULE".as_slice(),
            (false, false),
        ),
        (
            &good,
            b"override".as_slice(),
            b"RULE".as_slice(),
            (true, false),
        ),
        (
            &good,
            b"other".as_slice(),
            b"GLOBAL".as_slice(),
            (true, false),
        ),
        (
            &good,
            b"other".as_slice(),
            b"none".as_slice(),
            (false, false),
        ),
        (
            &good,
            b"accepted".as_slice(),
            b"RULE".as_slice(),
            (false, true),
        ),
    ] {
        let global_result =
            finding_allowed(fragment, b"ZX9", secret, line, global, &mut memo.global);
        let rule_result = finding_allowed(fragment, b"ZX9", secret, line, rule, &mut memo.rule);
        assert_eq!((global_result, rule_result), expected);
        assert_eq!(
            global_result,
            uncached_finding_allowed(fragment, b"ZX9", secret, line, global)
        );
        assert_eq!(
            rule_result,
            uncached_finding_allowed(fragment, b"ZX9", secret, line, rule)
        );
    }
    assert_eq!(memo.global.len(), 1);
    assert_eq!(memo.rule.len(), 1);
    assert!(!std::ptr::eq(
        memo.global[0].unwrap().allowlist,
        memo.rule[0].unwrap().allowlist
    ));
}

#[test]
fn non_line_allowlists_do_not_allocate_line_memo_slots() {
    let detector = engine(
        r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[allowlists]]
regexTarget = "match"
regexes = ['''ZX9''']
"#,
    );
    let mut cache = Vec::new();
    assert!(finding_allowed(
        &Fragment::new(b""),
        b"ZX9",
        b"ZX9",
        b"line",
        &detector.config.allowlists,
        &mut cache,
    ));
    assert!(cache.is_empty());
}

#[test]
fn decoded_line_memo_uses_decoded_slices_and_does_not_escape_a_scan() {
    let config = r#"
[[rules]]
id = "probe"
regex = "ZX9"
[[allowlists]]
regexTarget = "line"
regexes = ['''^ZX9(?: ZX9){3}$''']
"#;
    let detector = engine(config);
    let decoded = b"ZX9 ZX9 ZX9 ZX9";
    let encoded = base64::engine::general_purpose::STANDARD.encode(decoded);
    let fragment = Fragment::new(encoded.as_bytes());
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let suppressed = detector.scan_fragment(&fragment, &options);
    assert!(suppressed.is_complete());
    assert!(suppressed.findings().is_empty());
    assert_eq!(suppressed.usage().finding_records(), 0);
    assert_eq!(suppressed.usage().decoded_bytes(), decoded.len());
    let negative = engine(&config.replace("^ZX9(?: ZX9){3}$", "^ABSENT$"));
    let visible = negative.scan_fragment(&fragment, &options);
    assert!(visible.is_complete());
    assert_eq!(visible.findings().len(), 4);
    assert_eq!(visible.usage().finding_records(), 4);
    for finding in visible.findings() {
        assert_eq!(finding.match_text().as_bytes(), b"ZX9");
        assert_eq!(finding.secret().as_bytes(), b"ZX9");
        assert_eq!(finding.match_range(), FindingRange::Unavailable);
        assert_eq!(finding.secret_range(), FindingRange::Unavailable);
    }
    let next = detector.scan_fragment(&Fragment::new(b"ZX9"), &ScanOptions::default());
    assert!(next.is_complete());
    assert_eq!(next.findings().len(), 1);
}

// Frozen uncached predicate used only for comparison with the local memo.
fn uncached_finding_allowed(
    fragment: &Fragment,
    full_match: &[u8],
    secret: &[u8],
    current_line: &[u8],
    allowlists: &[CompiledAllowlist],
) -> bool {
    allowlists.iter().any(|allowlist| {
        let target = match allowlist.regex_target {
            RegexTarget::Secret | RegexTarget::Unknown(_) => secret,
            RegexTarget::Match => full_match,
            RegexTarget::Line => current_line,
        };
        let regex = allowlist.regex_allowed(target);
        let stopword = allowlist.contains_stop_word(secret);
        match allowlist.condition {
            Condition::Or => regex || stopword,
            Condition::And => {
                let commit = allowlist.commit_allowed(fragment.commit().as_bytes());
                let path = allowlist.path_allowed(fragment.file_path().as_bytes())
                    || (!fragment.windows_file_path().is_empty()
                        && allowlist.path_allowed(fragment.windows_file_path().as_bytes()));
                (!allowlist.commits.is_empty())
                    .then_some(commit)
                    .into_iter()
                    .chain((!allowlist.paths.is_empty()).then_some(path))
                    .chain((!allowlist.regexes.is_empty()).then_some(regex))
                    .chain((!allowlist.stop_words.is_empty()).then_some(stopword))
                    .all(|check| check)
            }
            Condition::Unknown(_) => false,
        }
    })
}

#[test]
fn joined_allowlist_flags_and_stopword_presence_match_go() {
    let config = ConfigLoader::new()
        .load_toml(
            r#"
[[rules]]
id = "probe"
regex = '''.+'''

[[allowlists]]
paths = ['''(?i)foo''', '''BAR''']
regexes = ['''(?i)foo''', '''BAR''']
stopwords = ["he", "she", "FaKe", "ÉCOLE", "�"]
"#,
        )
        .unwrap();
    let allowlist = &config.allowlists[0];
    assert!(allowlist.path_allowed(b"bar"));
    assert!(allowlist.regex_allowed(b"bar"));
    assert!(allowlist.contains_stop_word(b"she"));
    assert!(allowlist.contains_stop_word(b"prefix FAKE suffix"));
    assert!(allowlist.contains_stop_word("prefix ÉCOLE suffix".as_bytes()));
    assert!(allowlist.contains_stop_word(b"\xff"));
    assert!(!allowlist.contains_stop_word(b"real"));

    let empty = ConfigLoader::new()
        .load_toml(
            r#"
[[rules]]
id = "probe"
regex = '''.+'''

[[allowlists]]
stopwords = [""]
"#,
        )
        .unwrap();
    assert!(!empty.allowlists[0].contains_stop_word(b"nonempty"));
}

#[test]
fn allowlist_phases_path_only_bypass_and_windows_guard_are_explicit() {
    let path_only = engine(
        r#"
[[rules]]
id = "path-only"
path = '''secret\.txt$'''

[[rules.allowlists]]
regexes = ['''.*''']
"#,
    );
    assert_eq!(
        path_only
            .scan_fragment(
                &Fragment::builder(b"ignored".to_vec())
                    .file_path("secret.txt")
                    .build(),
                &ScanOptions::default(),
            )
            .findings()
            .len(),
        1
    );

    let path_and_stopword = engine(
        r#"
[[rules]]
id = "path-only"
path = '''secret\.txt$'''

[[rules.allowlists]]
condition = "AND"
paths = ['''secret\.txt$''']
stopwords = ["ignored"]
"#,
    );
    assert_eq!(
        path_and_stopword
            .scan_fragment(
                &Fragment::builder(b"ignored".to_vec())
                    .file_path("secret.txt")
                    .build(),
                &ScanOptions::default(),
            )
            .findings()
            .len(),
        1
    );

    let path_early = engine(
        r#"
[[rules]]
id = "path-only"
path = '''secret\.txt$'''

[[rules.allowlists]]
condition = "AND"
paths = ['''secret\.txt$''']
"#,
    );
    assert!(
        path_early
            .scan_fragment(
                &Fragment::builder(b"ignored".to_vec())
                    .file_path("secret.txt")
                    .build(),
                &ScanOptions::default(),
            )
            .findings()
            .is_empty()
    );

    let windows_guard = engine(
        r#"
[[rules]]
id = "content"
regex = '''TOKEN'''

[[allowlists]]
paths = ['''C:\\secret\.txt$''']
"#,
    );
    let windows_only = Fragment::builder(b"TOKEN".to_vec())
        .windows_file_path(r"C:\secret.txt")
        .build();
    assert_eq!(
        windows_guard
            .scan_fragment(&windows_only, &ScanOptions::default())
            .findings()
            .len(),
        1
    );
    let dual = Fragment::builder(b"TOKEN".to_vec())
        .file_path("secret.txt")
        .windows_file_path(r"C:\secret.txt")
        .build();
    assert!(
        windows_guard
            .scan_fragment(&dual, &ScanOptions::default())
            .findings()
            .is_empty()
    );
}

#[test]
fn generic_filter_ignores_file_columns_and_end_geometry() {
    let generic = Finding::builder()
        .rule_id("preGeNeRiCpost")
        .location(Location::new(7, 7, 90, 99).unwrap())
        .file("generic.txt")
        .commit("same")
        .match_text("abc")
        .secret("abc")
        .build()
        .unwrap();
    let specific = Finding::builder()
        .rule_id("specific")
        .location(Location::new(7, 8, 1, 1).unwrap())
        .file("specific.txt")
        .commit("same")
        .match_text("xxabcxx")
        .secret("xxabcxx")
        .build()
        .unwrap();

    let filtered = filter_findings(vec![generic, specific], 100);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule_id().as_bytes(), b"specific");
    assert_eq!(filtered[0].secret().as_bytes(), b"REDACTED");
}

// Frozen quadratic filters, retained only as differential evidence. The
// explicit cases below state the expected results independently.
fn frozen_filter_findings(findings: Vec<Finding>, redact: usize) -> Vec<Finding> {
    let include = frozen_include(&findings);
    apply_finding_filter(findings, include, redact)
}

fn frozen_include(findings: &[Finding]) -> Vec<bool> {
    findings
        .iter()
        .map(|finding| {
            if !contains_bytes(
                &go_lowercase_bytes(finding.rule_id().as_bytes()),
                b"generic",
            ) {
                return true;
            }
            !findings.iter().any(|other| {
                finding.location().start_line() == other.location().start_line()
                    && finding.commit() == other.commit()
                    && finding.rule_id() != other.rule_id()
                    && contains_bytes(other.secret().as_bytes(), finding.secret().as_bytes())
                    && !contains_bytes(&go_lowercase_bytes(other.rule_id().as_bytes()), b"generic")
            })
        })
        .collect()
}

/// The expected poll schedule of the cancellable filter, stated from its
/// contract rather than its code: one poll per finding classified, one
/// per finding indexed when any finding is generic, then per finding one
/// poll plus, for a generic finding, one poll per bucket candidate
/// compared up to and including the first suppressor. Returns the polls
/// spent on the index and, for each finding, the poll count after which
/// it is decided.
fn expected_filter_polls(findings: &[Finding]) -> (usize, Vec<usize>) {
    let is_generic = |finding: &Finding| {
        contains_bytes(
            &go_lowercase_bytes(finding.rule_id().as_bytes()),
            b"generic",
        )
    };
    let any_generic = findings.iter().any(is_generic);
    let index = findings.len() * if any_generic { 2 } else { 1 };
    let mut polls = index;
    let mut decided = Vec::new();
    for finding in findings {
        polls += 1;
        if is_generic(finding) {
            for other in findings.iter().filter(|other| {
                !is_generic(other)
                    && other.location().start_line() == finding.location().start_line()
                    && other.commit() == finding.commit()
            }) {
                polls += 1;
                if other.rule_id() != finding.rule_id()
                    && contains_bytes(other.secret().as_bytes(), finding.secret().as_bytes())
                {
                    break;
                }
            }
        }
        decided.push(polls);
    }
    (index, decided)
}

fn filter_probe(rule_id: &[u8], start_line: usize, commit: &[u8], secret: &[u8]) -> Finding {
    Finding::builder()
        .rule_id(rule_id)
        .location(Location::new(start_line, start_line, 1, 1).unwrap())
        .commit(commit)
        .match_text(secret)
        .secret(secret)
        .build()
        .unwrap()
}

fn generic_filter_prototypes() -> Vec<Finding> {
    vec![
        filter_probe(b"generic-a", 1, b"c", b"ab"),
        filter_probe(b"GENERIC-Upper", 1, b"c", b"ab"),
        // U+0130 lowercases to one ASCII i under Go's simple mapping.
        filter_probe("gener\u{130}c-dot".as_bytes(), 1, b"c", b"xaby"),
        // Invalid rule-ID bytes still lowercase around their replacement.
        filter_probe(b"\xffGeneric", 1, b"c", b""),
        filter_probe(b"specific-1", 1, b"c", b"xaby"),
        filter_probe(b"specific-2", 1, b"c", b"ab"),
        filter_probe(b"specific-line", 2, b"c", b"xaby"),
        filter_probe(b"specific-commit", 1, b"d", b"xaby"),
        filter_probe(b"specific-miss", 1, b"c", b"zz"),
    ]
}

fn assert_generic_filters_match_frozen(findings: &[Finding]) {
    for redact in [0, 100] {
        assert_eq!(
            filter_findings(findings.to_vec(), redact),
            frozen_filter_findings(findings.to_vec(), redact),
            "{findings:?}",
        );
    }
    let complete = frozen_filter_findings(findings.to_vec(), 0);
    assert_eq!(
        filter_findings_cancellable(findings.to_vec(), 0, ScanControl::unlimited()),
        (complete.clone(), None),
        "{findings:?}",
    );
    // The retained flags of the complete frozen filter, by list index.
    let retained = frozen_include(findings);
    let (index_polls, decided) = expected_filter_polls(findings);
    let total = decided.last().copied().unwrap_or(index_polls);
    let run = |limit: usize| {
        let polls = AtomicUsize::new(0);
        let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= limit;
        let outcome =
            filter_findings_cancellable(findings.to_vec(), 0, ScanControl::cancellable(&cancel));
        (outcome, polls.load(Ordering::SeqCst))
    };
    for limit in (0..=total + 1).chain([usize::MAX]) {
        let ((filtered, termination), polls) = run(limit);
        if limit >= total {
            assert_eq!(
                termination,
                None,
                "limit {limit}, {} findings",
                findings.len()
            );
            assert_eq!(polls, total, "limit {limit}, {} findings", findings.len());
            assert_eq!(
                filtered,
                complete,
                "limit {limit}, {} findings",
                findings.len()
            );
            continue;
        }
        assert_eq!(
            termination,
            Some(ScanTermination::Cancelled),
            "limit {limit}, {} findings",
            findings.len()
        );
        // The poll numbered `limit` cancels, so it is the last one made.
        assert_eq!(
            polls,
            limit + 1,
            "limit {limit}, {} findings",
            findings.len()
        );
        let prefix = decided.iter().filter(|&&after| after <= limit).count();
        let expected = findings[..prefix]
            .iter()
            .zip(&retained)
            .filter(|(_, kept)| **kept)
            .map(|(finding, _)| finding.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            filtered,
            expected,
            "limit {limit}, {} findings",
            findings.len()
        );
    }
}

#[test]
fn generic_buckets_match_the_frozen_quadratic_filter_exhaustively() {
    let prototypes = generic_filter_prototypes();
    assert_generic_filters_match_frozen(&[]);
    for first in &prototypes {
        assert_generic_filters_match_frozen(std::slice::from_ref(first));
        for second in &prototypes {
            assert_generic_filters_match_frozen(&[first.clone(), second.clone()]);
            for third in &prototypes {
                assert_generic_filters_match_frozen(&[
                    first.clone(),
                    second.clone(),
                    third.clone(),
                ]);
            }
        }
    }
    // Deterministic longer lists exercise bucket order across repeated keys.
    let mut state = 0x2545_f491_u32;
    for _ in 0..32 {
        let list = (0..6)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let choice = usize::try_from(state >> 24).unwrap() % prototypes.len();
                prototypes[choice].clone()
            })
            .collect::<Vec<_>>();
        assert_generic_filters_match_frozen(&list);
    }
}

#[test]
fn generic_filter_polls_before_each_comparison_and_stops_work_on_cancellation() {
    let mut findings = vec![
        filter_probe(b"plain", 1, b"", b"p"),
        filter_probe(b"generic", 7, b"same", b"absent"),
    ];
    findings.extend((0..32).map(|_| filter_probe(b"specific", 7, b"same", b"other")));

    // Polls 0 to 67 classify and index the 34 findings, 68 and 69 enter
    // the plain and generic findings, and 70 onward precede comparisons.
    let first_comparison = 2 * findings.len() + 2;
    assert_eq!(first_comparison, 70);
    for cancel_at in 0..first_comparison + 8 {
        let polls = AtomicUsize::new(0);
        let comparisons = AtomicUsize::new(0);
        let cancel = || {
            let poll = polls.fetch_add(1, Ordering::SeqCst);
            // Each comparison poll must precede its comparison, including
            // the poll that cancels. No bucket may be searched in advance.
            assert_eq!(
                comparisons.load(Ordering::SeqCst),
                poll.saturating_sub(first_comparison)
            );
            poll == cancel_at
        };
        let (filtered, termination) = filter_findings_with_cancellation(
            findings.clone(),
            100,
            ScanControl::cancellable(&cancel),
            |finding, other| {
                comparisons.fetch_add(1, Ordering::SeqCst);
                suppresses_generic_finding(finding, other)
            },
        );
        assert_eq!(termination, Some(ScanTermination::Cancelled));
        assert_eq!(polls.load(Ordering::SeqCst), cancel_at + 1);
        assert_eq!(
            comparisons.load(Ordering::SeqCst),
            cancel_at.saturating_sub(first_comparison)
        );
        if cancel_at <= first_comparison - 2 {
            assert!(filtered.is_empty());
        } else {
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].rule_id().as_bytes(), b"plain");
            assert_eq!(filtered[0].secret().as_bytes(), b"REDACTED");
        }
    }
}

#[test]
fn cancellable_generic_filter_polls_grow_linearly_and_match_the_plain_filter() {
    // `lines` lines, each with one generic finding, one specific finding
    // that contains its secret, and one plain finding that does not, in
    // the rule-grouped order a scan produces.
    let findings = |lines: usize| {
        let mut findings = Vec::new();
        for (rule, secret) in [
            (b"generic-a".as_slice(), b"ab".as_slice()),
            (b"specific", b"xaby"),
            (b"plain", b"zz"),
        ] {
            findings.extend((1..=lines).map(|line| filter_probe(rule, line, b"c", secret)));
        }
        findings
    };
    for lines in [64, 128] {
        let findings = findings(lines);
        let polls = AtomicUsize::new(0);
        let count = || {
            polls.fetch_add(1, Ordering::SeqCst);
            false
        };
        let (filtered, termination) =
            filter_findings_cancellable(findings.clone(), 0, ScanControl::cancellable(&count));
        assert_eq!(termination, None);
        assert_eq!(filtered, filter_findings(findings, 0));
        assert_eq!(filtered.len(), 2 * lines);
        // 3 * lines findings: two index polls and one outer poll each,
        // plus one comparison per generic finding, whose bucket starts
        // with its suppressor. A full-list search would instead compare
        // each generic finding with every finding before its suppressor.
        assert_eq!(polls.load(Ordering::SeqCst), 10 * lines, "{lines} lines");
    }
}

#[test]
fn generic_suppression_outcomes_and_poll_counts_are_explicit() {
    // Findings, retained rule IDs, and polls with a counting signal.
    type Case = (Vec<Finding>, Vec<&'static [u8]>, usize);

    let generic = || filter_probe(b"generic-a", 7, b"same", b"abc");
    let specific = || filter_probe(b"specific", 7, b"same", b"xxabcxx");
    let other_line = || filter_probe(b"specific", 8, b"same", b"xxabcxx");
    let other_commit = || filter_probe(b"specific", 7, b"other", b"xxabcxx");
    let another_generic = || filter_probe(b"GENERIC-b", 7, b"same", b"xxabcxx");
    let empty_secret = || filter_probe(b"generic-empty", 7, b"same", b"");

    let ids = |findings: &[Finding]| {
        findings
            .iter()
            .map(|finding| finding.rule_id().as_bytes().to_vec())
            .collect::<Vec<_>>()
    };
    // Each case first spends 2 polls per finding on the index (classify,
    // then bucket), because each contains a generic finding.
    let cases: Vec<Case> = vec![
        // Suppressor after the generic finding: 4 index + 1 outer
        // + 1 compared + 1 outer.
        (vec![generic(), specific()], vec![b"specific".as_slice()], 7),
        // Suppressor before the generic finding: 4 index + 1 outer
        // + 1 outer + 1 compared.
        (vec![specific(), generic()], vec![b"specific".as_slice()], 7),
        // No suppressor on the same line and commit: the bucket is empty,
        // so 6 index + 3 outer and nothing is compared.
        (
            vec![generic(), other_line(), other_commit()],
            vec![
                b"generic-a".as_slice(),
                b"specific".as_slice(),
                b"specific".as_slice(),
            ],
            9,
        ),
        // Generic findings do not suppress each other, by either
        // direction, and are never bucket candidates: 4 index + 2 outer.
        (
            vec![generic(), another_generic()],
            vec![b"generic-a".as_slice(), b"GENERIC-b".as_slice()],
            6,
        ),
        // An empty generic secret is contained in every other secret:
        // 4 index + 1 outer + 1 compared + 1 outer.
        (
            vec![empty_secret(), specific()],
            vec![b"specific".as_slice()],
            7,
        ),
    ];
    for (findings, retained, expected_polls) in cases {
        let polls = AtomicUsize::new(0);
        let count = || {
            polls.fetch_add(1, Ordering::SeqCst);
            false
        };
        let (filtered, termination) =
            filter_findings_cancellable(findings.clone(), 0, ScanControl::cancellable(&count));
        assert_eq!(termination, None);
        assert_eq!(polls.load(Ordering::SeqCst), expected_polls, "{findings:?}");
        assert_eq!(ids(&filtered), retained, "{findings:?}");
        assert_eq!(ids(&filter_findings(findings, 0)), retained);
    }

    // Polls are numbered from zero: 0 through 5 classify and index the
    // three findings, 6 and 7 are the outer checks for the first two
    // findings, 8 compares the generic finding with its only bucket
    // candidate, and 9 is the outer check for the last finding.
    let findings = vec![filter_probe(b"plain", 1, b"", b"p"), generic(), specific()];
    let plain = vec![b"plain".to_vec()];
    for (limit, expected) in [
        (0, Vec::new()),
        (3, Vec::new()),
        (5, Vec::new()),
        (6, Vec::new()),
        (7, plain.clone()),
        (8, plain.clone()),
        // The generic finding is finalized as suppressed; the specific one
        // is not yet finalized, so it is outside the returned prefix.
        (9, plain.clone()),
    ] {
        let polls = AtomicUsize::new(0);
        let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= limit;
        let (filtered, termination) =
            filter_findings_cancellable(findings.clone(), 0, ScanControl::cancellable(&cancel));
        assert_eq!(
            termination,
            Some(ScanTermination::Cancelled),
            "limit {limit}"
        );
        assert_eq!(ids(&filtered), expected, "limit {limit}");
    }
    let polls = AtomicUsize::new(0);
    let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= 10;
    let (filtered, termination) =
        filter_findings_cancellable(findings, 0, ScanControl::cancellable(&cancel));
    assert_eq!(termination, None);
    assert_eq!(ids(&filtered), [b"plain".to_vec(), b"specific".to_vec()]);
}

#[test]
fn private_filter_replays_the_composite_corpus() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/composite-corpus");
    let requests = json_lines(&corpus.join("requests-v1.jsonl"))
        .into_iter()
        .filter(|value| string(value, "operation") == "filter_probe")
        .collect::<Vec<_>>();
    let responses = json_lines(&corpus.join("outcomes-v1.jsonl"))
        .into_iter()
        .map(|value| (string(&value, "id").to_owned(), value))
        .collect::<BTreeMap<_, _>>();
    assert!(!requests.is_empty());
    for request in requests {
        let id = string(&request, "id");
        let response = responses.get(id).unwrap_or_else(|| panic!("missing {id}"));
        let inputs = request["filter_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(finding_from_json)
            .collect();
        let redact = usize::try_from(request["redact_percent"].as_u64().unwrap()).unwrap();
        let actual = filter_findings(inputs, redact);
        let expected = response["findings"].as_array().unwrap();
        assert_eq!(actual.len(), expected.len(), "{id}");
        for (finding, value) in actual.iter().zip(expected) {
            assert_finding_matches_json(finding, value);
        }
    }
}

fn finding_from_json(value: &Value) -> Finding {
    let mut builder = Finding::builder()
        .rule_id(string(value, "rule_id"))
        .description(decode(string(value, "description_base64")))
        .location(
            Location::new(
                integer(value, "start_line"),
                integer(value, "end_line"),
                integer(value, "start_column"),
                integer(value, "end_column"),
            )
            .unwrap(),
        )
        .line(decode(string(value, "line_base64")))
        .match_text(decode(string(value, "match_base64")))
        .secret(decode(string(value, "secret_base64")))
        .file(decode(string(value, "file_base64")))
        .symlink_file(decode(string(value, "symlink_file_base64")))
        .commit(decode(string(value, "commit_base64")))
        .link(decode(string(value, "link_base64")))
        .entropy(f32::from_bits(
            u32::try_from(value["entropy_bits"].as_u64().unwrap()).unwrap(),
        ))
        .author(decode(string(value, "author_base64")))
        .email(decode(string(value, "email_base64")))
        .date(decode(string(value, "date_base64")))
        .message(decode(string(value, "message_base64")))
        .tags(
            value["tags_base64"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tag| decode(tag.as_str().unwrap())),
        )
        .fingerprint(decode(string(value, "fingerprint_base64")));
    if let Some(required_findings) = value["required_findings"].as_array() {
        builder = builder.required_findings(required_findings.iter().map(|required| {
            RequiredFinding::builder()
                .rule_id(string(required, "rule_id"))
                .location(
                    Location::new(
                        integer(required, "start_line"),
                        integer(required, "end_line"),
                        integer(required, "start_column"),
                        integer(required, "end_column"),
                    )
                    .unwrap(),
                )
                .line(decode(string(required, "line_base64")))
                .match_text(decode(string(required, "match_base64")))
                .secret(decode(string(required, "secret_base64")))
                .build()
                .unwrap()
        }));
    }
    builder.build().unwrap()
}

fn assert_finding_matches_json(finding: &Finding, value: &Value) {
    assert_eq!(
        finding.rule_id().as_bytes(),
        string(value, "rule_id").as_bytes()
    );
    for (actual, key) in [
        (finding.description().as_bytes(), "description_base64"),
        (finding.line().as_bytes(), "line_base64"),
        (finding.match_text().as_bytes(), "match_base64"),
        (finding.secret().as_bytes(), "secret_base64"),
        (finding.file().as_bytes(), "file_base64"),
        (finding.symlink_file().as_bytes(), "symlink_file_base64"),
        (finding.commit().as_bytes(), "commit_base64"),
        (finding.link().as_bytes(), "link_base64"),
        (finding.author().as_bytes(), "author_base64"),
        (finding.email().as_bytes(), "email_base64"),
        (finding.date().as_bytes(), "date_base64"),
        (finding.message().as_bytes(), "message_base64"),
        (finding.fingerprint().as_bytes(), "fingerprint_base64"),
    ] {
        assert_eq!(actual, decode(string(value, key)));
    }
    assert_eq!(
        finding.location().start_line(),
        integer(value, "start_line")
    );
    assert_eq!(finding.location().end_line(), integer(value, "end_line"));
    assert_eq!(
        finding.location().start_column(),
        integer(value, "start_column")
    );
    assert_eq!(
        finding.location().end_column(),
        integer(value, "end_column")
    );
    assert_eq!(
        finding.entropy().to_bits(),
        u32::try_from(value["entropy_bits"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(
        finding
            .tags()
            .iter()
            .map(crate::model::ByteText::as_bytes)
            .collect::<Vec<_>>(),
        value["tags_base64"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tag| decode(tag.as_str().unwrap()))
            .collect::<Vec<_>>()
    );
    assert!(finding.fragment().is_none());
    let expected_required = value["required_findings"].as_array().unwrap();
    assert_eq!(finding.required_findings().len(), expected_required.len());
    for (required, expected) in finding.required_findings().iter().zip(expected_required) {
        assert_eq!(
            required.rule_id().as_bytes(),
            string(expected, "rule_id").as_bytes()
        );
        assert_eq!(
            required.location().start_line(),
            integer(expected, "start_line")
        );
        assert_eq!(
            required.location().end_line(),
            integer(expected, "end_line")
        );
        assert_eq!(
            required.location().start_column(),
            integer(expected, "start_column")
        );
        assert_eq!(
            required.location().end_column(),
            integer(expected, "end_column")
        );
        for (actual, key) in [
            (required.line().as_bytes(), "line_base64"),
            (required.match_text().as_bytes(), "match_base64"),
            (required.secret().as_bytes(), "secret_base64"),
        ] {
            assert_eq!(actual, decode(string(expected, key)));
        }
    }
}

fn json_lines(path: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn integer(value: &Value, key: &str) -> usize {
    usize::try_from(value[key].as_i64().unwrap()).unwrap()
}

fn decode(encoded: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap()
}
