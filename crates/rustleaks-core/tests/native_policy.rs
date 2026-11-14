#![allow(missing_docs)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::explanation::{
    ExplanationOptions, ExplanationReason, ValidationReason, ValidationState,
};
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::native::{NativeExtension, NativePolicy, NativePolicyError};
use rustleaks_core::validation::{OfflineCheck, github_classic_pat};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

const PACK: &str = r#"
[[rules]]
id = "rustleaks.sample"
regex = '''marker=([A-Z0-9]{8})'''
keywords = ["marker="]
entropy = 1.5
[[rules.allowlists]]
regexes = ['''^ABCD0000$''']
"#;

#[test]
fn composition_is_explicit_and_base_outcomes_remain_equal() {
    let legacy = Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap();
    let native = NativePolicy::builder().build().unwrap();
    let fragment = Fragment::new(b"\xff AKIALALEMEL33243OLIB\n");
    for maximum in [0, 1, 10_000] {
        let control =
            ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(maximum));
        let left = legacy.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
        for limit in [0, 1, 4_096] {
            let right = native.scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &control,
                ExplanationOptions::bounded(limit),
            );
            assert_eq!(left.findings(), right.scan().findings());
            assert_eq!(left.usage(), right.scan().usage());
            assert_eq!(left.termination(), right.scan().termination());
            assert_eq!(
                serde_json::to_value(left.findings()).unwrap(),
                serde_json::to_value(right.scan().findings()).unwrap()
            );
        }
    }
    let composed = NativePolicy::builder()
        .with_pack("sample-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    assert!(legacy.config().rule("rustleaks.sample").is_none());
    assert!(
        composed
            .engine()
            .config()
            .rule("rustleaks.sample")
            .is_some()
    );
}

#[test]
fn exact_identity_detects_text_order_and_extension_changes_without_debug_disclosure() {
    let first = NativePolicy::builder()
        .with_pack("sample-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    let same = NativePolicy::builder()
        .with_pack("sample-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(first.identity(), same.identity());
    let changed = NativePolicy::builder()
        .with_pack("sample-v1", &format!("{PACK}\n# sentinel-private-config\n"))
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(first.identity(), changed.identity());
    assert!(!format!("{:?}", changed.identity()).contains("sentinel-private-config"));
    assert_ne!(
        first.identity().sensitive_exact_bytes(),
        changed.identity().sensitive_exact_bytes()
    );
    let extended = NativePolicy::builder()
        .with_pack("sample-v1", PACK)
        .unwrap()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    assert_ne!(first.identity(), extended.identity());
    let a = NativePolicy::builder()
        .with_pack("a-v1", "")
        .unwrap()
        .with_pack("b-v1", "")
        .unwrap()
        .build()
        .unwrap();
    let b = NativePolicy::builder()
        .with_pack("b-v1", "")
        .unwrap()
        .with_pack("a-v1", "")
        .unwrap()
        .build()
        .unwrap();
    assert_ne!(a.identity(), b.identity());
}

#[test]
fn empty_rule_tables_preserve_the_default_configuration() {
    let baseline = ConfigLoader::new().load_default().unwrap();
    for pack in ["rules = {}", "[rules]\n"] {
        let (config, _) = NativePolicy::builder()
            .with_pack("empty-v1", pack)
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(config.ordered_rule_ids(), baseline.ordered_rule_ids());
        assert_eq!(config.rules().len(), baseline.rules().len());
        assert!(
            config
                .rules()
                .values()
                .all(|rule| rule.native_entropy().is_none())
        );
    }
}

#[test]
fn replacements_and_implicit_base_mutations_are_rejected() {
    assert!(matches!(
        NativePolicy::builder().with_pack("bad id", PACK),
        Err(NativePolicyError::InvalidPackId)
    ));
    assert!(matches!(
        NativePolicy::builder()
            .with_pack("v1", PACK)
            .unwrap()
            .with_pack("v1", PACK),
        Err(NativePolicyError::DuplicatePackId)
    ));
    assert!(matches!(
        NativePolicy::builder()
            .with_pack("v1", PACK)
            .unwrap()
            .with_pack("v2", PACK)
            .unwrap()
            .build(),
        Err(NativePolicyError::RuleCollision)
    ));
    let duplicate = format!("{PACK}\n{PACK}");
    assert!(matches!(
        NativePolicy::builder()
            .with_pack("v1", &duplicate)
            .unwrap()
            .build(),
        Err(NativePolicyError::RuleCollision)
    ));
    assert!(matches!(
        NativePolicy::builder().with_pack("v1", &PACK.replace("rustleaks.sample", "github-pat")),
        Err(NativePolicyError::InvalidRuleId)
    ));
    for directive in [
        "[extend]\nuseDefault = true",
        "[extend]\npath = 'local.toml'",
        "[extend]\nurl = 'https://example.invalid/x'",
        "[[allowlists]]\nregexes = ['.*']",
        "minVersion = '99.0.0'",
    ] {
        assert!(matches!(
            NativePolicy::builder().with_pack("v1", directive),
            Err(NativePolicyError::UnsupportedPackDirective)
        ));
    }
    assert!(matches!(
        NativePolicy::builder().with_pack("v1", &" ".repeat(NativePolicy::MAX_PACK_BYTES + 1)),
        Err(NativePolicyError::LimitExceeded)
    ));
}

#[test]
fn diagnostic_reasons_cover_positive_negative_allowlist_and_partial_decisions() {
    let engine = NativePolicy::builder()
        .with_pack("sample-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    let options = ScanOptions::default();
    let cases: &[(&[u8], ExplanationReason)] = &[
        (b"unrelated", ExplanationReason::KeywordMissed),
        (b"marker=AB12CD34", ExplanationReason::KeywordMatched),
        (b"marker=no", ExplanationReason::PatternMissed),
        (b"marker=AB12CD34", ExplanationReason::PatternMatched),
        (b"marker=AB12CD34", ExplanationReason::EntropyAccepted),
        (b"marker=00000000", ExplanationReason::EntropyRejected),
        (b"marker=ABCD0000", ExplanationReason::AllowlistMatched),
        (
            b"marker=AB12CD34 # gitleaks:allow",
            ExplanationReason::AllowMarkerMatched,
        ),
    ];
    let ordinal = engine
        .engine()
        .config()
        .rules()
        .keys()
        .position(|id| id == "rustleaks.sample")
        .unwrap();
    for (bytes, reason) in cases {
        let outcome = engine.scan_fragment_controlled(
            &Fragment::new(*bytes),
            &options,
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(4_096),
        );
        assert!(
            outcome
                .explanations()
                .events()
                .iter()
                .any(|event| event.rule_ordinal() == Some(ordinal) && event.reason() == *reason),
            "missing {reason:?}"
        );
    }
    let partial = engine.scan_fragment_controlled(
        &Fragment::new(b"marker=AB12CD34"),
        &options,
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
        ExplanationOptions::bounded(10),
    );
    assert!(!partial.scan().is_complete());
    assert!(
        partial
            .explanations()
            .events()
            .iter()
            .any(|event| event.reason() == ExplanationReason::WorkBudgetExceeded)
    );
}

#[test]
fn logs_are_bounded_and_never_copy_input_even_with_decoding_or_redaction() {
    let engine = NativePolicy::builder()
        .with_pack("sample-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    let raw = b"marker=ZX91QW82";
    let encoded = STANDARD.encode(raw);
    let options = ScanOptions::builder()
        .max_decode_depth(2)
        .redaction_percent(100)
        .build();
    let fragment = Fragment::builder(raw.repeat(200))
        .file_path("private-source-name")
        .build();
    for cap in [0, 1, 7, 31] {
        let outcome = engine.scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(cap),
        );
        assert!(outcome.explanations().events().len() <= cap);
        assert_eq!(outcome.explanations().is_truncated(), cap != 0);
        let serialized = serde_json::to_string(outcome.explanations()).unwrap();
        for sensitive in ["ZX91QW82", "marker=", "private-source-name"] {
            assert!(!serialized.contains(sensitive));
        }
    }
    let decoded = engine.scan_fragment_controlled(
        &Fragment::new(encoded.as_bytes()),
        &options,
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(4_096),
    );
    assert_eq!(decoded.options(), options);
    assert_eq!(decoded.budget(), ScanBudget::unlimited());
    assert!(decoded.explanations().is_enabled());
    assert!(
        decoded
            .scan()
            .findings()
            .iter()
            .any(|finding| finding.rule_id().as_bytes() == b"rustleaks.sample")
    );
    assert!(decoded.explanations().events().iter().any(
        |event| event.decoded_pass() > 0 && event.reason() == ExplanationReason::PatternMatched
    ));
    let serialized = serde_json::to_string(decoded.explanations()).unwrap();
    assert!(!serialized.contains("ZX91QW82"));
    assert!(!serialized.contains(&encoded));
    assert_eq!(
        ExplanationOptions::bounded(usize::MAX).record_limit(),
        ExplanationOptions::MAX_RECORDS
    );
}

#[test]
fn unsupported_or_unspecified_checksum_formats_remain_visible_and_unknown() {
    let engine = NativePolicy::builder()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    // Deliberately synthetic. No live token is created or contacted.
    let token = format!("ghp_{}", "A1b2C3d4E5f6".repeat(3));
    let fragment = Fragment::new(token.as_bytes());
    let legacy = engine
        .engine()
        .scan_fragment(&fragment, &ScanOptions::default());
    let outcome = engine.scan_fragment_controlled(
        &fragment,
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(4_096),
    );
    assert!(!legacy.findings().is_empty());
    assert_eq!(outcome.scan().findings(), legacy.findings());
    assert!(
        outcome
            .explanations()
            .events()
            .iter()
            .any(|event| event.reason()
                == ExplanationReason::OfflineValidation {
                    check: OfflineCheck::GithubClassicPatChecksumV1,
                    state: ValidationState::Unknown,
                    reason: ValidationReason::UnspecifiedChecksumContract
                })
    );
    let disabled = engine.scan_fragment_controlled(
        &fragment,
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::disabled(),
    );
    assert!(disabled.explanations().events().is_empty());
    assert!(!disabled.explanations().is_enabled());
    assert!(!disabled.offline_annotations_enabled());
    assert!(outcome.offline_annotations_enabled());
    assert_eq!(outcome.scan().findings(), disabled.scan().findings());
}

#[test]
fn issuer_layout_is_assessed_separately_from_checksum_and_activity() {
    let token = format!("ghp_{}", "A1b2C3d4E5f6".repeat(3));
    let result = github_classic_pat(token.as_bytes());
    assert_eq!(result[0].state(), ValidationState::Valid);
    assert_eq!(
        result[0].reason(),
        ValidationReason::HistoricalLayoutMatched
    );
    assert_eq!(result[1].check(), OfflineCheck::GithubClassicPatChecksumV1);
    assert_eq!(result[1].state(), ValidationState::Unknown);
    let mut invalid = token.as_bytes().to_vec();
    invalid[10] = 0xff;
    assert_eq!(
        github_classic_pat(&invalid)[0].state(),
        ValidationState::Invalid
    );
    invalid[10] = b'_';
    assert_eq!(
        github_classic_pat(&invalid)[0].reason(),
        ValidationReason::HistoricalAlphabetMismatch
    );
    for unsupported in [
        b"ghp_short".as_slice(),
        b"github_pat_123456789",
        b"ghs_123_JWT",
        b"0123456789012345678901234567890123456789",
    ] {
        assert!(
            github_classic_pat(unsupported)
                .iter()
                .all(|assessment| assessment.state() == ValidationState::Unknown)
        );
    }
    assert_eq!(
        github_classic_pat(&token.as_bytes()[..39])[0].state(),
        ValidationState::Unknown
    );
    let longer = format!("{token}0");
    assert_eq!(
        github_classic_pat(longer.as_bytes())[0].state(),
        ValidationState::Unknown
    );
}

#[test]
fn captured_prefix_of_a_longer_token_has_unknown_structure() {
    let engine = NativePolicy::builder()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    let token = format!("ghp_{}EXTRA", "A1b2C3d4E5f6".repeat(3));
    let outcome = engine.scan_fragment_controlled(
        &Fragment::new(token.as_bytes()),
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(4_096),
    );
    assert!(!outcome.scan().findings().is_empty());
    assert!(
        outcome
            .explanations()
            .events()
            .iter()
            .any(|event| event.reason()
                == ExplanationReason::OfflineValidation {
                    check: OfflineCheck::GithubClassicPatLayoutV1,
                    state: ValidationState::Unknown,
                    reason: ValidationReason::AmbiguousBoundary
                })
    );
}

#[test]
fn persistent_builtin_reference_never_accepts_custom_pack_labels() {
    let base = NativePolicy::builder().build().unwrap();
    assert!(
        base.identity()
            .builtin_review_reference()
            .unwrap()
            .contains("extra-sha256:none")
    );
    let custom = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    assert!(custom.identity().builtin_review_reference().is_none());
    let changed = NativePolicy::builder()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    assert_ne!(
        base.identity().builtin_review_reference(),
        changed.identity().builtin_review_reference()
    );
}

#[test]
fn invalid_layout_annotation_preserves_findings_and_partial_results() {
    let pack = r#"
[[rules]]
id = "rustleaks.pat-candidate"
regex = '''ghp_.{36}'''
keywords = ["ghp_"]
"#;
    let engine = NativePolicy::builder()
        .with_pack("pat-candidate-v1", pack)
        .unwrap()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    let mut token = format!("ghp_{}", "A1b2C3d4E5f6".repeat(3)).into_bytes();
    token[10] = b'!';
    let fragment = Fragment::new(token);
    let options = ScanOptions::builder().redaction_percent(100).build();
    for control in [
        ScanControl::unlimited(),
        ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(0)),
    ] {
        let legacy = engine
            .engine()
            .scan_fragment_controlled(&fragment, &options, &control);
        let annotated = engine.scan_fragment_controlled(
            &fragment,
            &options,
            &control,
            ExplanationOptions::bounded(4_096),
        );
        assert_eq!(legacy.findings(), annotated.scan().findings());
        assert_eq!(legacy.termination(), annotated.scan().termination());
        assert!(
            annotated
                .explanations()
                .events()
                .iter()
                .any(|event| event.reason()
                    == ExplanationReason::OfflineValidation {
                        check: OfflineCheck::GithubClassicPatLayoutV1,
                        state: ValidationState::Invalid,
                        reason: ValidationReason::HistoricalAlphabetMismatch
                    })
        );
        let serialized = serde_json::to_string(annotated.explanations()).unwrap();
        assert!(!serialized.contains("A1b2C3d4E5f6"));
    }
}

#[test]
fn native_objects_remain_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<rustleaks_core::native::NativeEngine>();
    assert_send_sync::<rustleaks_core::native::NativePolicyIdentity>();
    assert_send_sync::<rustleaks_core::native::NativeScanOutcome>();
}

#[test]
fn composition_and_diagnostic_limits_are_inclusive() {
    use std::fmt::Write as _;

    let mut policy = NativePolicy::builder();
    for index in 0..NativePolicy::MAX_PACKS {
        policy = policy.with_pack(&format!("pack-{index}"), "").unwrap();
    }
    assert!(matches!(
        policy.with_pack("one-too-many", ""),
        Err(NativePolicyError::LimitExceeded)
    ));
    let mut rules = String::new();
    for index in 0..=NativePolicy::MAX_NATIVE_RULES {
        writeln!(
            rules,
            "[[rules]]\nid = 'rustleaks.r{index}'\nregex = 'sample'"
        )
        .unwrap();
    }
    assert!(matches!(
        NativePolicy::builder().with_pack("too-many-rules", &rules),
        Err(NativePolicyError::LimitExceeded)
    ));
}

#[test]
fn native_unknown_fields_fail_before_the_legacy_loader_can_discard_them() {
    const RULE: &str = "[[rules]]\nid = 'rustleaks.strict'\nregex = 'marker=([A-Z0-9]{8})'\n";
    const PRIVATE_FIELD: &str = "private_field_sentinel = 'private_value_sentinel'\n";
    let cases = [
        format!("{PRIVATE_FIELD}{RULE}"),
        format!("{RULE}{PRIVATE_FIELD}"),
        format!("{RULE}[[rules.required]]\nid = 'rustleaks.strict'\n{PRIVATE_FIELD}"),
        format!("{RULE}[[rules.allowlists]]\nregexes = ['ignored']\n{PRIVATE_FIELD}"),
        format!("{RULE}[rules.allowlist]\nregexes = ['ignored']\n{PRIVATE_FIELD}"),
        format!("[extend]\n{PRIVATE_FIELD}{RULE}"),
        format!("[allowlist]\nregexes = ['ignored']\n{PRIVATE_FIELD}{RULE}"),
        format!("[[allowlists]]\nregexes = ['ignored']\n{PRIVATE_FIELD}{RULE}"),
        format!(
            "{RULE}required = [{{ id = 'rustleaks.strict', private_field_sentinel = 'private_value_sentinel' }}]"
        ),
    ];
    for contents in cases {
        assert!(ConfigLoader::new().parse_toml(&contents, None).is_ok());
        let error = NativePolicy::builder()
            .with_pack("strict-v1", &contents)
            .unwrap_err();
        assert!(matches!(error, NativePolicyError::UnknownPackField));
        assert_eq!(error.to_string(), "unknown native pack field");
        assert!(!format!("{error:?}").contains("private_"));
    }
}

#[test]
fn native_rejects_case_collisions_and_positional_structs() {
    for contents in [
        "title = 'first'\nTITLE = 'second'",
        "[[rules]]\nid = 'rustleaks.first'\nID = 'rustleaks.second'\nregex = 'marker'",
        "[[rules]]\nid = 'rustleaks.first'\nregex = 'marker'\n[[rules.required]]\nid = 'rustleaks.first'\nwithinLines = 1\nwithinlines = 2",
        "[[rules]]\nid = 'rustleaks.first'\nregex = 'marker'\n[rules.allowlist]\nregexTarget = 'secret'\nREGEXTARGET = 'line'\nregexes = ['ignored']",
    ] {
        assert!(matches!(
            NativePolicy::builder().with_pack("ambiguous-v1", contents),
            Err(NativePolicyError::AmbiguousPackField)
        ));
    }
    for contents in [
        "rules = [[]]",
        "[[rules]]\nid = 'rustleaks.first'\nregex = 'marker'\nrequired = [[]]",
        "[[rules]]\nid = 'rustleaks.first'\nregex = 'marker'\nallowlists = [[]]",
    ] {
        assert!(matches!(
            NativePolicy::builder().with_pack("positional-v1", contents),
            Err(NativePolicyError::InvalidPackStructure)
        ));
    }
}

#[test]
fn native_known_fields_and_compatibility_aliases_keep_their_effect() {
    let contents = r#"
TITLE = "Native strict aliases"
Description = "Known field coverage"
[[RULES]]
ID = "rustleaks.alias-main"
Description = "Main rule"
Path = 'fixture'
Regex = 'marker=([A-Z0-9]{8})'
secretGroup = 1
Entropy = 1.5
Keywords = ["marker="]
Tags = ["native"]
skipReport = false
[[RULES.REQUIRED]]
ID = "rustleaks.alias-aux"
withinLines = 1
withinColumns = 32
[[RULES.ALLOWLISTS]]
Description = "Known allowlist fields"
Condition = "OR"
Commits = ["deadbeef"]
Paths = ['ignored']
regexTarget = "secret"
Regexes = ['^ABCD0000$']
stopWords = ["fixture-placeholder"]
[[RULES]]
ID = "rustleaks.alias-aux"
Regex = 'auxiliary'
skipreport = true
[RULES.ALLOWLIST]
regextarget = "line"
regexes = ['ignored']
stopwords = ["placeholder"]
"#;
    let engine = NativePolicy::builder()
        .with_pack("aliases-v1", contents)
        .unwrap()
        .build()
        .unwrap();
    let main = engine
        .engine()
        .config()
        .rule("rustleaks.alias-main")
        .unwrap();
    assert_eq!(main.secret_group(), 1);
    assert_eq!(main.entropy().to_bits(), 1.5_f64.to_bits());
    assert_eq!(main.required_rules()[0].within_lines, Some(1));
    assert_eq!(main.required_rules()[0].within_columns, Some(32));
    assert_eq!(
        main.allowlists()[0].stop_words().collect::<Vec<_>>(),
        ["fixture-placeholder"]
    );
    assert!(
        engine
            .engine()
            .config()
            .rule("rustleaks.alias-aux")
            .unwrap()
            .skip_report()
    );
    // The compatibility loader's named-table shorthand remains supported.
    let shorthand = "[rules]\nid = 'rustleaks.shorthand'\nregex = 'sample'\n[rules.allowlists]\nregexes = ['ignored']";
    assert!(
        NativePolicy::builder()
            .with_pack("shorthand-v1", shorthand)
            .unwrap()
            .build()
            .is_ok()
    );
    // Known but disallowed composition directives still receive their own error.
    for directive in [
        "[extend]\nuseDefault = true",
        "[extend]\ndisabledRules = ['github-pat']",
        "minVersion = '8.0.0'",
    ] {
        assert!(matches!(
            NativePolicy::builder().with_pack("known-v1", directive),
            Err(NativePolicyError::UnsupportedPackDirective)
        ));
    }
}

#[test]
fn omitted_final_annotations_mark_exact_cap_truncation() {
    let engine = NativePolicy::builder()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    assert_eq!(
        engine.engine().config().rules().keys().next_back().unwrap(),
        "zendesk-secret-key"
    );
    let input = format!("zendesk = {}", "ab12".repeat(10));
    let fragment = Fragment::new(input.as_bytes());
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let full = engine.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
    );
    assert!(full.scan().is_complete());
    assert_eq!(full.scan().findings().len(), 1);
    assert!(!full.explanations().is_truncated());
    let total = full.explanations().events().len();
    assert!(
        full.explanations().events()[total - 2..]
            .iter()
            .all(|event| { matches!(event.reason(), ExplanationReason::OfflineValidation { .. }) })
    );
    for cap in [0, total - 2, total - 1, total] {
        let bounded = engine.scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::unlimited(),
            ExplanationOptions::bounded(cap),
        );
        assert_eq!(bounded.explanations().events().len(), cap.min(total));
        assert_eq!(
            bounded.explanations().is_truncated(),
            cap != 0 && cap < total
        );
        assert_eq!(bounded.scan().findings(), full.scan().findings());
        assert_eq!(bounded.scan().usage(), full.scan().usage());
        assert_eq!(bounded.scan().termination(), full.scan().termination());
    }
}

mod byte_entropy {
    use super::*;
    use rustleaks_core::config::{CompiledConfig, ConfigError, VirtualResolver};
    use rustleaks_core::model::{ByteRange, FindingRange};

    fn pack(entropy: &str) -> String {
        format!(
            "[[rules]]\nid='rustleaks.byte-entropy-test'\nregex='''ent=([^\\n]+)'''\nsecretGroup=1\nkeywords=['ent=']\nentropy={entropy}\n"
        )
    }

    fn table(reject: &str, threshold: f64) -> String {
        format!("{{ algorithm='byte-shannon-f64-v1', reject='{reject}', threshold={threshold:?} }}")
    }

    fn compiled(entropy: &str) -> CompiledConfig {
        NativePolicy::builder()
            .with_pack("entropy-v1", &pack(entropy))
            .unwrap()
            .compile()
            .unwrap()
            .0
            .select_rules(["rustleaks.byte-entropy-test"])
            .unwrap()
    }

    fn engine(entropy: &str) -> Engine {
        Engine::builder(compiled(entropy)).build().unwrap()
    }

    fn input(secret: &[u8]) -> Vec<u8> {
        [b"ent=".as_slice(), secret].concat()
    }

    #[test]
    fn strict_comparators_zero_and_adjacent_thresholds_are_independent() {
        // Eight symbols with p=1/16 and four with p=1/8 give exactly 3.5.
        let secret = b"ABCDEFGHIIJJKKLL";
        for (reject, threshold, expected) in [
            ("lt", 3.5, 1),
            ("le", 3.5, 0),
            ("lt", 3.5_f64.next_down(), 1),
            ("le", 3.5_f64.next_down(), 1),
            ("lt", 3.5_f64.next_up(), 0),
            ("le", 3.5_f64.next_up(), 0),
        ] {
            let engine = engine(&table(reject, threshold));
            let scan = engine.scan_fragment(&Fragment::new(input(secret)), &ScanOptions::default());
            assert!(scan.is_complete());
            assert_eq!(scan.findings().len(), expected, "{reject} {threshold:?}");
            if let Some(finding) = scan.findings().first() {
                assert_eq!(finding.entropy().to_bits(), 0x4060_0000);
                assert_eq!(finding.secret().as_bytes(), secret);
                assert_eq!(
                    finding.secret_range(),
                    FindingRange::Exact(ByteRange::new(4, 20).unwrap())
                );
                assert_eq!(
                    finding.match_range(),
                    FindingRange::Exact(ByteRange::new(0, 20).unwrap())
                );
            }
        }
        for (predicate, count) in [
            (table("lt", 0.0), 1),
            (table("le", 0.0), 0),
            ("0.0".to_owned(), 1),
        ] {
            let scan = engine(&predicate)
                .scan_fragment(&Fragment::new(b"ent=0000"), &ScanOptions::default());
            assert!(scan.is_complete());
            assert_eq!(scan.findings().len(), count);
        }
    }

    #[test]
    fn division_witness_is_accepted_at_exact_three_and_three_point_five() {
        for (counts, threshold) in [
            (vec![49; 8], 3.0),
            ([vec![49; 8], vec![98; 4]].concat(), 3.5),
        ] {
            let secret: Vec<u8> = (b'A'..)
                .zip(counts)
                .flat_map(|(byte, count)| std::iter::repeat_n(byte, count))
                .collect();
            let scan = engine(&table("lt", threshold))
                .scan_fragment(&Fragment::new(input(&secret)), &ScanOptions::default());
            assert!(scan.is_complete());
            assert_eq!(scan.findings().len(), 1);
            #[allow(clippy::cast_possible_truncation)]
            let expected = threshold as f32;
            assert_eq!(scan.findings()[0].entropy().to_bits(), expected.to_bits());
            // This also checks the comparator cannot be bypassed through Engine.
            let scan = engine(&table("le", threshold))
                .scan_fragment(&Fragment::new(input(&secret)), &ScanOptions::default());
            assert!(scan.is_complete());
            assert!(scan.findings().is_empty());
        }
    }

    #[test]
    fn bytes_include_utf8_and_invalid_sequences_without_character_conversion() {
        for secret in ["éé".as_bytes(), b"\xff\xfe\xff\xfe".as_slice()] {
            // Both byte histograms have two equally frequent symbols, H=1.
            let scan = engine(&table("lt", 1.0))
                .scan_fragment(&Fragment::new(input(secret)), &ScanOptions::default());
            assert!(scan.is_complete());
            assert_eq!(scan.findings().len(), 1);
            assert_eq!(scan.findings()[0].secret().as_bytes(), secret);
            assert_eq!(scan.findings()[0].entropy().to_bits(), 0x3f80_0000);
            let scan = engine(&table("le", 1.0))
                .scan_fragment(&Fragment::new(input(secret)), &ScanOptions::default());
            assert!(scan.is_complete());
            assert!(scan.findings().is_empty());
        }
    }

    #[test]
    fn native_compilation_projection_and_rebuilding_retain_typed_metadata() {
        let policy = NativePolicy::builder()
            .with_pack("entropy-v1", &pack(&table("lt", 3.5)))
            .unwrap();
        let (full, identity) = policy.clone().compile().unwrap();
        let native = policy.build().unwrap();
        assert_eq!(&identity, native.identity());
        assert_eq!(full, *native.engine().config());
        for config in [
            full.clone(),
            full.select_rules(["rustleaks.byte-entropy-test"]).unwrap(),
        ] {
            let cloned = config.clone();
            let rule = cloned.rule("rustleaks.byte-entropy-test").unwrap();
            assert_eq!(rule.entropy().to_bits(), 0.0_f64.to_bits());
            assert_eq!(
                rule.native_entropy(),
                Some(("byte-shannon-f64-v1", "lt", 3.5))
            );
            let rebuilt = Engine::builder(cloned).build().unwrap();
            let result =
                rebuilt.scan_fragment(&Fragment::new(b"ent=0000"), &ScanOptions::default());
            assert!(result.is_complete());
            assert!(
                !result
                    .findings()
                    .iter()
                    .any(|finding| finding.rule_id().as_bytes() == b"rustleaks.byte-entropy-test")
            );
        }
        for changed in [table("le", 3.5), table("lt", 3.0)] {
            let (_, other) = NativePolicy::builder()
                .with_pack("entropy-v1", &pack(&changed))
                .unwrap()
                .compile()
                .unwrap();
            assert_ne!(identity, other);
        }
    }

    #[test]
    fn entropy_rejection_precedes_finding_admission_and_preserves_cancellation() {
        let engine = engine(&table("lt", 3.5));
        let options = ScanOptions::default();
        let control =
            ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(0));
        let rejected =
            engine.scan_fragment_controlled(&Fragment::new(b"ent=0000"), &options, &control);
        assert!(rejected.is_complete());
        assert_eq!(rejected.usage().finding_records(), 0);
        let accepted = engine.scan_fragment_controlled(
            &Fragment::new(b"ent=ABCDEFGHIIJJKKLL"),
            &options,
            &control,
        );
        assert!(!accepted.is_complete());
        assert!(accepted.findings().is_empty());
        let cancelled = engine.scan_fragment_controlled(
            &Fragment::new(b"ent=ABCDEFGHIIJJKKLL"),
            &options,
            &ScanControl::cancellable(&|| true),
        );
        assert!(!cancelled.is_complete());
        assert_eq!(cancelled.usage().finding_records(), 0);
        let work = ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0));
        let stopped = engine.scan_fragment_controlled(
            &Fragment::new(b"ent=ABCDEFGHIIJJKKLL"),
            &options,
            &work,
        );
        assert!(!stopped.is_complete());
        assert_eq!(stopped.usage().work_units(), 0);
    }

    #[test]
    fn rejected_native_candidate_does_not_suppress_a_generic_finding() {
        let source = format!(
            "{}\n[[rules]]\nid='rustleaks.generic-entropy-control'\nregex='''ent=([^\\n]+)'''\nsecretGroup=1\n",
            pack(&table("lt", 3.5))
        );
        let config = NativePolicy::builder()
            .with_pack("entropy-v1", &source)
            .unwrap()
            .compile()
            .unwrap()
            .0
            .select_rules([
                "rustleaks.byte-entropy-test",
                "rustleaks.generic-entropy-control",
            ])
            .unwrap();
        let engine = Engine::builder(config).build().unwrap();
        let scan = engine.scan_fragment(&Fragment::new(b"ent=0011"), &ScanOptions::default());
        assert!(scan.is_complete());
        assert_eq!(scan.findings().len(), 1);
        assert_eq!(
            scan.findings()[0].rule_id().as_bytes(),
            b"rustleaks.generic-entropy-control"
        );
    }

    #[test]
    fn malformed_tables_are_rejected_without_source_disclosure() {
        for entropy in [
            "{}",
            "{ algorithm='byte-shannon-f64-v1', reject='lt' }",
            "{ algorithm='byte-shannon-f64-v1', threshold=3.5 }",
            "{ reject='lt', threshold=3.5 }",
            "{ algorithm='SECRET_MARKER', reject='lt', threshold=3.5 }",
            "{ algorithm='byte-shannon-f64-v1', reject='SECRET_MARKER', threshold=3.5 }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold='SECRET_MARKER' }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=true }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=nan }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=inf }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=-0.1 }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=8.1 }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=9 }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=[] }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold={} }",
            "{ algorithm='byte-shannon-f64-v1', reject='lt', threshold=3.5, SECRET_MARKER=1 }",
            "{ Algorithm='byte-shannon-f64-v1', reject='lt', threshold=3.5 }",
            "{ algorithm='byte-shannon-f64-v1', Algorithm='SECRET_MARKER', reject='lt', threshold=3.5 }",
        ] {
            let source = format!("{}\n# SECRET_MARKER\n", pack(entropy));
            let error = NativePolicy::builder()
                .with_pack("entropy-v1", &source)
                .unwrap_err();
            assert!(matches!(
                error,
                NativePolicyError::InvalidNativeEntropy | NativePolicyError::AmbiguousPackField
            ));
            assert!(!error.to_string().contains("SECRET_MARKER"));
            assert!(!format!("{error:?}").contains("SECRET_MARKER"));
        }
        let path_only = "[[rules]]\nid='rustleaks.entropy'\npath='x'\nentropy={algorithm='byte-shannon-f64-v1',reject='lt',threshold=0}\n";
        assert!(matches!(
            NativePolicy::builder().with_pack("entropy-v1", path_only),
            Err(NativePolicyError::InvalidNativeEntropy)
        ));
        for threshold in ["0", "8", "0.0", "8.0"] {
            let source = pack(&format!(
                "{{algorithm='byte-shannon-f64-v1',reject='lt',threshold={threshold}}}"
            ));
            assert!(
                NativePolicy::builder()
                    .with_pack("entropy-v1", &source)
                    .is_ok()
            );
        }
    }

    #[test]
    fn compatibility_loader_fails_closed_directly_inline_and_through_extension() {
        let source = pack(&table("lt", 3.5));
        assert!(matches!(
            ConfigLoader::new().parse_toml(&source, None),
            Err(ConfigError::Decode { .. })
        ));
        assert!(ConfigLoader::new().load_toml(&source).is_err());
        assert!(
            ConfigLoader::new()
                .load_toml(&format!("[extend]\nuseDefault=true\n{source}"))
                .is_err()
        );
        let resolver = VirtualResolver::new().with_file("native.toml", source);
        assert!(
            ConfigLoader::new()
                .with_resolver(resolver)
                .load_toml("[extend]\npath='native.toml'\n")
                .is_err()
        );
    }

    #[test]
    fn legacy_scalar_rules_and_reports_retain_exact_values() {
        for scalar in ["0.0", "1.0", "3.5"] {
            let legacy = Engine::builder(ConfigLoader::new().load_toml(&pack(scalar)).unwrap())
                .build()
                .unwrap();
            let native = engine(scalar);
            assert!(
                native
                    .config()
                    .rule("rustleaks.byte-entropy-test")
                    .unwrap()
                    .native_entropy()
                    .is_none()
            );
            for secret in [
                b"ABCDEFGHIIJJKKLL".as_slice(),
                b"0000",
                "éé".as_bytes(),
                b"\xff\xfe\xff\xfe",
            ] {
                let bytes = input(secret);
                let left =
                    legacy.scan_fragment(&Fragment::new(bytes.as_slice()), &ScanOptions::default());
                let right =
                    native.scan_fragment(&Fragment::new(bytes.as_slice()), &ScanOptions::default());
                assert!(left.is_complete() && right.is_complete());
                assert_eq!(left.findings(), right.findings());
            }
        }
        let loader = ConfigLoader::new();
        let legacy = loader
            .compile(
                loader
                    .parse_toml(rustleaks_core::config::DEFAULT_CONFIG, None)
                    .unwrap(),
            )
            .unwrap();
        let native = NativePolicy::builder().compile().unwrap().0;
        assert_eq!(legacy, native);
    }
}
