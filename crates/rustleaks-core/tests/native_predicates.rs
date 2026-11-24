#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::explanation::{ExplanationOptions, ExplanationReason};
use rustleaks_core::model::{ByteRange, Fragment, ScanOptions};
use rustleaks_core::native::{NativePolicy, NativePolicyError};
use rustleaks_core::{Engine, ScanBudget, ScanBudgetKind, ScanControl, ScanTermination};

const MAPBOX: &str = r#"
[[rules]]
id = "rustleaks.mapbox-predicate-test"
regex = { dialect = "bytes-v1", pattern = '''(pk\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)(?:[^A-Za-z0-9_-]|$)''' }
secretGroup = 1
predicate = { algorithm = "base64url-segment-go-regex-v1", parts = 3, separator = ".", segment = 1, encodedMin = 23, encodedMax = 308, decodedMax = 231, regex = '''^\{"u":"[^"\\\x00-\x1f]+"\s*,\s*"a"\s*:\s*"[A-Za-z0-9]+"\s*\}$''' }
"#;

const VERCEL: &str = r#"
[[rules]]
id = "rustleaks.vercel-predicate-test"
regex = { dialect = "bytes-v1", pattern = '''(?i)\b(vck_[A-Za-z0-9_-]{56})(?:[^A-Za-z0-9_-]|$)''' }
secretGroup = 1
entropy = { algorithm = "byte-shannon-f64-v1", reject = "lt", threshold = 3.5 }
predicate = { algorithm = "vercel-cl100k-ratio-v1" }
"#;

const REJECT_24: &[u8] = b"vck_0123456789012a45678901234567B901234567890123456789012345";
const ACCEPT_25: &[u8] = b"vck_0123456789012a45678901234567B90123456789012d456789012345";

fn selected(pack: &str) -> Engine {
    let (config, _) = NativePolicy::builder()
        .with_pack("predicate-test-v1", pack)
        .unwrap()
        .compile()
        .unwrap();
    let ids = config
        .ordered_rule_ids()
        .iter()
        .filter(|id| id.starts_with("rustleaks."))
        .collect::<Vec<_>>();
    let config = config
        .select_rules(ids.iter().map(|id| id.as_str()))
        .unwrap();
    Engine::builder(config.clone()).build().unwrap()
}

fn mapbox(payload: &[u8]) -> Vec<u8> {
    format!(
        "pk.{}.Z7nqM5xT2pR8dW4cK9jH6f",
        URL_SAFE_NO_PAD.encode(payload)
    )
    .into_bytes()
}

#[test]
fn native_descriptors_fail_closed_and_reject_invalid_parameters() {
    for pack in [MAPBOX, VERCEL] {
        assert!(ConfigLoader::new().load_toml(pack).is_err());
    }
    for invalid in [
        MAPBOX.replace("parts = 3", "parts = 4"),
        MAPBOX.replace("parts = 3", "parts = 3.0"),
        MAPBOX.replace("segment = 1", "segment = 0"),
        MAPBOX.replace("segment = 1", "segment = -1"),
        MAPBOX.replace("separator = \".\"", "separator = \"..\""),
        MAPBOX.replace("encodedMin = 23", "encodedMin = 0"),
        MAPBOX.replace("encodedMin = 23", "encodedMin = 309"),
        MAPBOX.replace("encodedMax = 308", "encodedMax = 309"),
        MAPBOX.replace("encodedMax = 308", "encodedMax = 308.0"),
        MAPBOX.replace("decodedMax = 231", "decodedMax = 232"),
        MAPBOX.replace("decodedMax = 231", "decodedMax = 0"),
        MAPBOX.replace("decodedMax = 231", "decodedMax = -1"),
        MAPBOX.replace("parts = 3", "parts = 3, extra = true"),
        MAPBOX.replace("parts = 3", "parts = 3, Parts = 3"),
        MAPBOX.replace("base64url-segment-go-regex-v1", "base64url-segment-go-regex-v2"),
        MAPBOX.replace("regex = '''^", "regex = '''(?=bad)^"),
        MAPBOX.replace("regex = { dialect = \"bytes-v1\", pattern = '''(pk\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)(?:[^A-Za-z0-9_-]|$)''' }", "regex = '''anything'''"),
        VERCEL.replace("algorithm = \"vercel-cl100k-ratio-v1\"", "algorithm = \"vercel-cl100k-ratio-v1\", threshold = 24"),
        VERCEL.replace("vercel-cl100k-ratio-v1", "vercel-cl100k-ratio-v2"),
        VERCEL.replace("predicate = { algorithm = \"vercel-cl100k-ratio-v1\" }", "predicate = true"),
    ] {
        assert!(NativePolicy::builder().with_pack("invalid", &invalid).is_err());
    }
    assert!(matches!(
        NativePolicy::builder().with_pack(
            "invalid",
            &VERCEL.replace(
                "predicate = { algorithm = \"vercel-cl100k-ratio-v1\" }",
                "predicate = true"
            )
        ),
        Err(NativePolicyError::InvalidNativePredicate)
    ));
}

#[test]
fn mapbox_preserves_raw_findings_and_rejects_malformed_candidates_then_continues() {
    let engine = selected(MAPBOX);
    let valid = mapbox(br#"{"u":"audit-user","a":"Az09"}"#);
    let malformed = mapbox(&[0xff; 24]);
    let bytes = [malformed.as_slice(), b" ", valid.as_slice()].concat();
    let scan = engine.scan_fragment_controlled(
        &Fragment::new(bytes),
        &ScanOptions::default(),
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_decoded_bytes(0)),
    );
    assert!(scan.is_complete());
    assert_eq!(scan.usage().decoded_bytes(), 0);
    assert_eq!(scan.findings().len(), 1);
    let finding = &scan.findings()[0];
    assert_eq!(finding.secret().as_bytes(), valid);
    assert_eq!(finding.match_text().as_bytes(), valid);
    assert_eq!(
        finding.secret_range().exact(),
        Some(ByteRange::new(malformed.len() + 1, malformed.len() + 1 + valid.len()).unwrap())
    );
    assert!(finding.tags().is_empty());
    for invalid in [
        br#"{"a":"Az09","u":"audit-user"}"#.as_slice(),
        br#"{"u":"","a":"Az09"}"#,
        br#"{"u":"audit-user","a":"A-09"}"#,
        br#" {"u":"audit-user","a":"Az09"}"#,
        br#"{"u":"audit-user","a":"Az09","extra":1}"#,
        b"{\"u\":\"audit-user\",\x0b\"a\":\"Az09\"}",
    ] {
        let scan = engine.scan_fragment(&Fragment::new(mapbox(invalid)), &ScanOptions::default());
        assert!(scan.is_complete() && scan.findings().is_empty());
    }
    for valid in [
        "{\"u\":\"λ-user\",\t\"a\":\"Az09\"}",
        "{\"u\":\"audit-user\",\n\"a\":\"Az09\"}",
    ] {
        assert_eq!(
            engine
                .scan_fragment(
                    &Fragment::new(mapbox(valid.as_bytes())),
                    &ScanOptions::default()
                )
                .findings()
                .len(),
            1
        );
    }
    for delimiter in [b'\n', b'\r', 0xff] {
        let bytes = [valid.as_slice(), &[delimiter]].concat();
        let scan = engine.scan_fragment(&Fragment::new(bytes), &ScanOptions::default());
        assert_eq!(scan.findings().len(), 1);
        assert_eq!(
            scan.findings()[0].secret_range().exact(),
            Some(ByteRange::new(0, valid.len()).unwrap())
        );
        let end = valid.len() + usize::from(delimiter != b'\n');
        assert_eq!(
            scan.findings()[0].match_range().exact(),
            Some(ByteRange::new(0, end).unwrap())
        );
    }
}

#[test]
fn vercel_boundary_clone_projection_and_exact_identity_remain_bound() {
    let (config, identity) = NativePolicy::builder()
        .with_pack("ratio-v1", VERCEL)
        .unwrap()
        .compile()
        .unwrap();
    assert_eq!(
        config
            .rule("rustleaks.vercel-predicate-test")
            .unwrap()
            .native_predicate_algorithm(),
        Some("vercel-cl100k-ratio-v1")
    );
    assert!(
        config
            .rule("github-pat")
            .unwrap()
            .native_predicate_algorithm()
            .is_none()
    );
    let projection = config
        .clone()
        .select_rules(["rustleaks.vercel-predicate-test"])
        .unwrap();
    let engine = Engine::builder(projection).build().unwrap();
    assert!(
        engine
            .scan_fragment(&Fragment::new(REJECT_24), &ScanOptions::default())
            .findings()
            .is_empty()
    );
    let scan = engine.scan_fragment(&Fragment::new(ACCEPT_25), &ScanOptions::default());
    assert!(scan.is_complete());
    assert_eq!(scan.findings().len(), 1);
    assert_eq!(scan.findings()[0].secret().as_bytes(), ACCEPT_25);
    assert_eq!(
        scan.findings()[0].secret_range().exact(),
        Some(ByteRange::new(0, 60).unwrap())
    );
    let different = NativePolicy::builder()
        .with_pack("ratio-v1", &format!("{VERCEL}\n"))
        .unwrap()
        .compile()
        .unwrap()
        .1;
    assert_ne!(identity, different);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let engine = &engine;
            scope.spawn(move || {
                assert_eq!(
                    engine
                        .scan_fragment(&Fragment::new(ACCEPT_25), &ScanOptions::default())
                        .findings()
                        .len(),
                    1
                );
            });
        }
    });
}

struct CancelAt {
    poll: AtomicUsize,
    limit: usize,
}
impl rustleaks_core::ScanCancellation for CancelAt {
    fn is_cancelled(&self) -> bool {
        self.poll.fetch_add(1, Ordering::SeqCst) >= self.limit
    }
}

#[test]
fn predicate_work_and_cancel_limits_keep_completed_rule_prefixes() {
    for (pack, secret) in [
        (MAPBOX, mapbox(br#"{"u":"audit-user","a":"Az09"}"#)),
        (VERCEL, ACCEPT_25.to_vec()),
    ] {
        let first = "[[rules]]\nid = \"rustleaks.aaa-first\"\nregex = '''FIRST123'''\n";
        let engine = selected(&format!("{first}\n{pack}"));
        let bytes = [b"FIRST123 ".as_slice(), secret.as_slice()].concat();
        let fragment = Fragment::new(bytes);
        let options = ScanOptions::default();
        let complete = engine.scan_fragment(&fragment, &options);
        assert!(complete.is_complete());
        assert_eq!(complete.findings().len(), 2);
        let mut saw_completed_prefix = false;
        for limit in 0..complete.usage().work_units() {
            let control =
                ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(limit));
            let partial = engine.scan_fragment_controlled(&fragment, &options, &control);
            assert!(matches!(
                partial.termination(),
                Some(ScanTermination::BudgetExceeded {
                    kind: ScanBudgetKind::WorkUnits,
                    ..
                })
            ));
            assert_eq!(partial.usage().work_units(), limit);
            if !partial.findings().is_empty() {
                saw_completed_prefix = true;
                assert_eq!(partial.findings().len(), 1);
                assert_eq!(partial.findings()[0].secret().as_bytes(), b"FIRST123");
            }
        }
        assert!(saw_completed_prefix);
        let counter = CancelAt {
            poll: AtomicUsize::new(0),
            limit: usize::MAX,
        };
        assert!(
            engine
                .scan_fragment_controlled(&fragment, &options, &ScanControl::cancellable(&counter))
                .is_complete()
        );
        let total_polls = counter.poll.load(Ordering::SeqCst);
        let mut interrupted_with_prefix = false;
        for limit in 0..total_polls {
            let cancel = CancelAt {
                poll: AtomicUsize::new(0),
                limit,
            };
            let partial = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::cancellable(&cancel),
            );
            assert_eq!(partial.termination(), Some(&ScanTermination::Cancelled));
            // Cancellation in final aggregate filtering may retain both
            // completed rules. Only unfinished-rule findings are forbidden.
            if partial.findings().len() == 1 {
                interrupted_with_prefix = true;
                assert_eq!(partial.findings()[0].secret().as_bytes(), b"FIRST123");
            }
        }
        assert!(interrupted_with_prefix);
    }
}

#[test]
fn predicates_keep_existing_rule_and_global_allowlists() {
    let allowed = selected(&format!(
        "{VERCEL}\n[[rules.allowlists]]\nregexes = ['''^vck_''']\n"
    ));
    assert!(
        allowed
            .scan_fragment(&Fragment::new(ACCEPT_25), &ScanOptions::default())
            .findings()
            .is_empty()
    );
    let engine = selected(VERCEL);
    let excluded = Fragment::builder(ACCEPT_25)
        .file_path("node_modules/settings.txt")
        .build();
    assert!(
        engine
            .scan_fragment(&excluded, &ScanOptions::default())
            .findings()
            .is_empty()
    );
}

#[test]
fn rejected_predicates_do_not_consume_finding_admission_budgets() {
    for (pack, rejected, accepted) in [
        (
            MAPBOX,
            mapbox(br#"{"u":"audit-user","a":"bad-value"}"#),
            mapbox(br#"{"u":"audit-user","a":"Az09"}"#),
        ),
        (VERCEL, REJECT_24.to_vec(), ACCEPT_25.to_vec()),
    ] {
        let engine = selected(pack);
        for (budget, kind) in [
            (
                ScanBudget::unlimited().max_finding_records(0),
                ScanBudgetKind::FindingRecords,
            ),
            (
                ScanBudget::unlimited().max_finding_payload_bytes(0),
                ScanBudgetKind::FindingPayloadBytes,
            ),
        ] {
            let control = ScanControl::unlimited().with_budget(budget);
            let rejected = engine.scan_fragment_controlled(
                &Fragment::new(rejected.clone()),
                &ScanOptions::default(),
                &control,
            );
            assert!(rejected.is_complete());
            assert!(rejected.findings().is_empty());
            assert_eq!(rejected.usage().finding_records(), 0);
            assert_eq!(rejected.usage().finding_payload_bytes(), 0);
            let accepted = engine.scan_fragment_controlled(
                &Fragment::new(accepted.clone()),
                &ScanOptions::default(),
                &control,
            );
            assert!(
                matches!(accepted.termination(), Some(ScanTermination::BudgetExceeded { kind: actual, .. }) if *actual == kind)
            );
            assert!(accepted.findings().is_empty());
        }
    }
}

#[test]
fn predicate_explanations_are_bounded_source_omitting_and_follow_entropy() {
    // A custom prefix isolates this mechanism test from the default rules.
    let pack = MAPBOX.replace("(pk\\.", "(zz\\.");
    let native = NativePolicy::builder()
        .with_pack("explanation-v1", &pack)
        .unwrap()
        .build()
        .unwrap();
    let ordinal = native
        .engine()
        .config()
        .rules()
        .keys()
        .position(|id| id == "rustleaks.mapbox-predicate-test")
        .unwrap();
    for (payload, expected) in [
        (
            br#"{"u":"DECODED_SENTINEL_719","a":"Az09"}"#.as_slice(),
            ExplanationReason::NativePredicateAccepted,
        ),
        (
            br#"{"u":"DECODED_SENTINEL_719","a":"bad-value"}"#,
            ExplanationReason::NativePredicateRejected,
        ),
    ] {
        let secret = format!("zz.{}.RAW_SENTINEL_382", URL_SAFE_NO_PAD.encode(payload));
        let fragment = Fragment::new(secret.as_bytes());
        let complete = native.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(4096),
        );
        assert!(complete.scan().is_complete());
        assert!(
            complete
                .explanations()
                .events()
                .iter()
                .any(|event| event.rule_ordinal() == Some(ordinal) && event.reason() == expected)
        );
        let debug = format!("{complete:?}");
        let serialized = serde_json::to_string(complete.explanations()).unwrap();
        for sentinel in ["DECODED_SENTINEL_719", "RAW_SENTINEL_382", secret.as_str()] {
            assert!(!debug.contains(sentinel));
            assert!(!serialized.contains(sentinel));
        }
        let bounded = native.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(1),
        );
        assert_eq!(bounded.scan(), complete.scan());
        assert_eq!(bounded.explanations().events().len(), 1);
        assert!(bounded.explanations().is_truncated());
    }
    let native = NativePolicy::builder()
        .with_pack(
            "entropy-first-v1",
            &VERCEL.replace("threshold = 3.5", "threshold = 8.0"),
        )
        .unwrap()
        .build()
        .unwrap();
    let ordinal = native
        .engine()
        .config()
        .rules()
        .keys()
        .position(|id| id == "rustleaks.vercel-predicate-test")
        .unwrap();
    let result = native.scan_fragment_controlled(
        &Fragment::new(ACCEPT_25),
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(4096),
    );
    let reasons = result
        .explanations()
        .events()
        .iter()
        .filter(|event| event.rule_ordinal() == Some(ordinal))
        .map(|event| event.reason())
        .collect::<Vec<_>>();
    assert!(reasons.contains(&ExplanationReason::EntropyRejected));
    assert!(!reasons.contains(&ExplanationReason::NativePredicateAccepted));
    assert!(!reasons.contains(&ExplanationReason::NativePredicateRejected));
}
