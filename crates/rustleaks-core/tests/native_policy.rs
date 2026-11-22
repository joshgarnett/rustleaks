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

/// One budget dimension: its kind, observed complete usage, and builder setter.
type BudgetDimension = (
    rustleaks_core::ScanBudgetKind,
    usize,
    fn(ScanBudget, usize) -> ScanBudget,
);

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
    let legacy = Engine::builder(default_rules_alone().load_default().unwrap())
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
    let baseline = default_rules_alone().load_default().unwrap();
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

mod buffer_relations {
    use super::*;
    use rustleaks_core::config::ConfigError;
    use rustleaks_core::model::{ByteRange, Finding, FindingRange};
    use rustleaks_core::{ScanBudgetKind, ScanTermination};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TUPLES: &str = r#"
[[rules]]
id = "rustleaks.parent"
regex = '''pair=(GOOD|BAD):([A-Z]{4})'''
secretGroup = 2
[rules.required]
contract = "buffer-v1"
edges = [{ id = "rustleaks.helper", relation = "same-candidate" }]
[[rules]]
id = "rustleaks.helper"
regex = '''pair=(GOOD|BAD):([A-Z]{4})'''
secretGroup = 1
skipReport = true
[[rules.allowlists]]
regexes = ['''^BAD$''']
"#;

    fn selected(pack: &str) -> Engine {
        let (config, _) = NativePolicy::builder()
            .with_pack("buffer-test", pack)
            .unwrap()
            .compile()
            .unwrap();
        let ids = config
            .ordered_rule_ids()
            .iter()
            .filter(|id| id.starts_with("rustleaks."))
            .collect::<Vec<_>>();
        Engine::builder(
            config
                .select_rules(ids.iter().map(|id| id.as_str()))
                .unwrap(),
        )
        .build()
        .unwrap()
    }

    fn encoded(bytes: &[u8], depth: usize) -> Vec<u8> {
        let mut result = bytes.to_vec();
        for _ in 0..depth {
            result = STANDARD.encode(result).into_bytes();
        }
        result
    }

    fn scan(engine: &Engine, bytes: &[u8], depth: usize) -> Vec<Finding> {
        let outcome = engine.scan_fragment(
            &Fragment::new(bytes),
            &ScanOptions::builder().max_decode_depth(depth).build(),
        );
        assert!(outcome.is_complete());
        outcome.findings().to_vec()
    }

    fn window_pack(parent: &str, helper: &str, window: &str) -> String {
        format!(
            r#"
[[rules]]
id = "rustleaks.parent"
regex = '''{parent}'''
[rules.required]
contract = "buffer-v1"
edges = [{{ id = "rustleaks.helper", relation = "full-match-window", window = "{window}" }}]
[[rules]]
id = "rustleaks.helper"
regex = '''{helper}'''
skipReport = true
"#
        )
    }

    #[test]
    fn native_tables_fail_ordinary_compilation_and_validate_every_relation_field() {
        assert!(matches!(
            ConfigLoader::new().load_toml(TUPLES),
            Err(ConfigError::EmptyRequiredRuleId { .. })
        ));
        for invalid in [
            TUPLES.replace("buffer-v1", "buffer-v2"),
            TUPLES.replace("same-candidate", "nearest"),
            TUPLES.replace("relation = \"same-candidate\"", "relation = \"same-candidate\", window = \"0\""),
            TUPLES.replace("contract = \"buffer-v1\"", "contract = \"buffer-v1\"\nContract = \"buffer-v1\""),
            TUPLES.replace("contract = \"buffer-v1\"", "contract = \"buffer-v1\"\nunknown = true"),
            TUPLES.replace("relation = \"same-candidate\"", "relation = \"same-candidate\", Relation = \"same-candidate\""),
            TUPLES.replace("edges = [{ id = \"rustleaks.helper\", relation = \"same-candidate\" }]", "edges = []"),
            TUPLES.replace("edges = [{ id = \"rustleaks.helper\", relation = \"same-candidate\" }]", "edges = [{ id = \"rustleaks.helper\", relation = \"same-candidate\" }, { id = \"rustleaks.helper\", relation = \"same-candidate\" }]"),
            TUPLES.replace("edges = [", "id = \"rustleaks.helper\"\nedges = ["),
            TUPLES.replace("relation = \"same-candidate\"", "relation = \"full-match-window\""),
        ] {
            assert!(NativePolicy::builder().with_pack("malformed", &invalid).is_err());
        }
        for invalid in [
            "",
            "00",
            "0L",
            "01L",
            "-1L",
            "1",
            "5l",
            "5C",
            "5.0L",
            " 5L",
            "184467440737095516160L",
        ] {
            assert!(
                NativePolicy::builder()
                    .with_pack("malformed", &window_pack("P", "H", invalid))
                    .is_err()
            );
        }
        for valid in ["0", "1L", "5L", "8L", "10L", "20L", "30L"] {
            assert!(
                NativePolicy::builder()
                    .with_pack("valid", &window_pack("P", "H", valid))
                    .is_ok()
            );
        }
    }

    #[test]
    fn tuple_predicates_bind_exact_spans_in_raw_decoded_and_nested_buffers() {
        let engine = selected(TUPLES);
        for bytes in [
            b"pair=BAD:WXYZ pair=GOOD:ABCD".as_slice(),
            b"pair=GOOD:ABCD pair=BAD:WXYZ",
        ] {
            for depth in 0..=2 {
                let findings = scan(&engine, &encoded(bytes, depth), depth);
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].secret().as_bytes(), b"ABCD");
                assert_eq!(findings[0].required_findings().len(), 1);
                assert_eq!(
                    findings[0].required_findings()[0].secret().as_bytes(),
                    b"GOOD"
                );
                assert_eq!(
                    findings[0].required_findings()[0].match_text().as_bytes(),
                    b"pair=GOOD:ABCD"
                );
                if depth > 0 {
                    assert_eq!(findings[0].match_range(), FindingRange::Unavailable);
                    assert_eq!(findings[0].secret_range(), FindingRange::Unavailable);
                }
            }
        }
        let different_end = TUPLES.replacen(
            "regex = '''pair=(GOOD|BAD):([A-Z]{4})'''\nsecretGroup = 1",
            "regex = '''pair=(GOOD|BAD):([A-Z]{3})'''\nsecretGroup = 1",
            1,
        );
        assert!(scan(&selected(&different_end), b"pair=GOOD:ABCD", 0).is_empty());
        let raw = scan(&engine, b"pair=GOOD:ABCD", 0);
        assert_eq!(
            raw[0].match_range(),
            FindingRange::Exact(ByteRange::new(0, 14).unwrap())
        );
        assert_eq!(
            raw[0].secret_range(),
            FindingRange::Exact(ByteRange::new(10, 14).unwrap())
        );
        let inherited = engine.scan_fragment(
            &Fragment::builder(b"pair=BAD:WXYZ")
                .inherited_from_finding(true)
                .build(),
            &ScanOptions::default(),
        );
        assert!(inherited.findings().is_empty());
        assert_eq!(
            raw[0].clone().redacted(100).required_findings()[0]
                .secret()
                .as_bytes(),
            b"GOOD"
        );
        let removed = raw[0].clone().without_detected_secrets();
        assert!(!serde_json::to_string(&removed).unwrap().contains("ABCD"));
        assert!(!serde_json::to_string(&removed).unwrap().contains("GOOD"));
    }

    #[test]
    fn same_candidate_entropy_and_mixed_relations_cannot_borrow_acceptance() {
        let entropy = TUPLES.replace("[[rules.allowlists]]\nregexes = ['''^BAD$''']\n", "")
            .replace("secretGroup = 1\nskipReport = true", "secretGroup = 2\nskipReport = true\nentropy = { algorithm = \"byte-shannon-f64-v1\", reject = \"lt\", threshold = 1.0 }");
        let engine = selected(&entropy);
        let without_entropy = selected(&entropy.replace(
            "\nentropy = { algorithm = \"byte-shannon-f64-v1\", reject = \"lt\", threshold = 1.0 }",
            "",
        ));
        // AABA has a 3:1 histogram, below the helper's one-bit floor. It is
        // not a uniform-letter value suppressed by the inherited allowlist.
        for bytes in [
            b"pair=GOOD:AABA pair=GOOD:ABCD".as_slice(),
            b"pair=GOOD:ABCD pair=GOOD:AABA",
        ] {
            for depth in 0..=2 {
                let input = encoded(bytes, depth);
                let control_findings = scan(&without_entropy, &input, depth);
                assert_eq!(control_findings.len(), 2);
                let expected: [&[u8]; 2] = if bytes.starts_with(b"pair=GOOD:AABA") {
                    [b"AABA", b"ABCD"]
                } else {
                    [b"ABCD", b"AABA"]
                };
                for (finding, expected) in control_findings.iter().zip(expected) {
                    assert_eq!(finding.secret().as_bytes(), expected);
                    assert_eq!(finding.required_findings().len(), 1);
                    assert_eq!(finding.required_findings()[0].secret().as_bytes(), expected);
                }
                let findings = scan(&engine, &input, depth);
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].secret().as_bytes(), b"ABCD");
                assert_eq!(findings[0].required_findings().len(), 1);
                assert_eq!(
                    findings[0].required_findings()[0].secret().as_bytes(),
                    b"ABCD"
                );
            }
        }
        let mixed = TUPLES.replace("relation = \"same-candidate\" }]", "relation = \"same-candidate\" }, { id = \"rustleaks.context\", relation = \"full-match-window\", window = \"1L\" }]");
        let mixed = format!(
            "{mixed}\n[[rules]]\nid = \"rustleaks.context\"\nregex = 'CONTEXT'\nskipReport = true\n"
        );
        let engine = selected(&mixed);
        assert!(scan(&engine, b"pair=GOOD:ABCD", 0).is_empty());
        assert!(scan(&engine, b"pair=BAD:WXYZ CONTEXT", 0).is_empty());
        let findings = scan(&engine, b"pair=GOOD:ABCD CONTEXT", 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].required_findings().len(), 2);
        assert!(scan(&engine, b"pair=GOOD:ABCD\nCONTEXT", 0).is_empty());
    }

    #[test]
    fn line_windows_use_full_match_exclusive_end_and_helper_start() {
        for lines in [1, 5, 8, 10, 20, 30] {
            let engine = selected(&window_pack("PRIMARY", "HELPER", &format!("{lines}L")));
            for distance in [lines - 1, lines] {
                for reverse in [false, true] {
                    let gap = "\n".repeat(distance);
                    let bytes = if reverse {
                        format!("HELPER{gap}PRIMARY")
                    } else {
                        format!("PRIMARY{gap}HELPER")
                    };
                    assert_eq!(
                        scan(&engine, bytes.as_bytes(), 0).len(),
                        usize::from(distance < lines)
                    );
                }
            }
            let engine = selected(&window_pack(
                r"BEGIN\r?\ncapture=([A-Z]{4})\r?\nEND\r?\n",
                "HELPER",
                &format!("{lines}L"),
            ));
            for newline in ["\n", "\r\n"] {
                for extra in [lines - 1, lines] {
                    // The primary begins on line 1 and ends exclusively on 4.
                    // The helper begins at line 4+extra, regardless of capture.
                    let bytes = format!(
                        "é BEGIN{newline}capture=ABCD{newline}END{newline}{}HELPER",
                        newline.repeat(extra)
                    );
                    let findings = scan(&engine, bytes.as_bytes(), 0);
                    assert_eq!(findings.len(), usize::from(extra < lines));
                    if extra < lines {
                        assert_eq!(findings[0].secret().as_bytes(), b"ABCD");
                    }
                }
            }
        }
        let helper_end = selected(&window_pack("PRIMARY", r"HELPER\nTAIL", "2L"));
        assert!(scan(&helper_end, b"HELPER\nTAIL\nPRIMARY", 0).is_empty());
        assert_eq!(
            scan(
                &selected(&window_pack("PRIMARY", "HELPER", "0")),
                format!("PRIMARY{}HELPER", "\n".repeat(100)).as_bytes(),
                0
            )
            .len(),
            1
        );
    }

    #[test]
    fn carriers_and_nested_siblings_cannot_supply_each_others_helpers() {
        let engine = selected(&window_pack("PRIMARY", "HELPER", "0"));
        let one = b"PRIMARY xx HELPER";
        for depth in 0..=2 {
            assert_eq!(scan(&engine, &encoded(one, depth), depth).len(), 1);
        }
        let separate = format!(
            "{} {}",
            STANDARD.encode(b"PRIMARY filler"),
            STANDARD.encode(b"HELPER filler")
        );
        assert!(scan(&engine, separate.as_bytes(), 1).is_empty());
        assert!(scan(&engine, &encoded(separate.as_bytes(), 1), 2).is_empty());
        let cross = format!("HELPER {}", STANDARD.encode(b"PRIMARY filler"));
        assert!(scan(&engine, cross.as_bytes(), 1).is_empty());
        let outer_sibling = format!("HELPER {}", STANDARD.encode(b"PRIMARY filler"));
        assert!(scan(&engine, &encoded(outer_sibling.as_bytes(), 1), 2).is_empty());
    }

    #[test]
    fn anchors_greedy_enumeration_and_keywords_are_buffer_local() {
        let anchored = selected(&window_pack(r"\APAIR=([A-Z]{4});HELP\z", "HELP", "0"));
        let bytes = format!("prefix {} suffix", STANDARD.encode(b"PAIR=ABCD;HELP"));
        assert_eq!(scan(&anchored, bytes.as_bytes(), 1).len(), 1);
        let greedy = selected(&window_pack(r"START(?s:.*)END", "HELP", "0"));
        let bytes = format!(
            "{} {}",
            STANDARD.encode(b"START without stop"),
            STANDARD.encode(b"START HELP END")
        );
        let findings = scan(&greedy, bytes.as_bytes(), 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_text().as_bytes(), b"START HELP END");
        let keywords = window_pack("PRIMARY", "HELPER", "0").replace(
            "skipReport = true",
            "skipReport = true\nkeywords = [\"gate\"]",
        );
        let engine = selected(&keywords);
        let bytes = format!(
            "{} {}",
            STANDARD.encode(b"PRIMARY HELPER"),
            STANDARD.encode(b"gate unrelated")
        );
        assert!(scan(&engine, bytes.as_bytes(), 1).is_empty());
        assert_eq!(
            scan(&engine, &encoded(b"PRIMARY HELPER gate", 1), 1).len(),
            1
        );
        let uppercase = keywords.replace("gate", "ÉTAG");
        assert_eq!(
            scan(&selected(&uppercase), "PRIMARY HELPER étag".as_bytes(), 0).len(),
            1
        );
    }

    #[test]
    fn capture_context_and_untrimmed_spans_survive_projection_and_rebuild() {
        // At A7B's start, preceding x makes \\B true. Searching a sliced A7B
        // would select group 1. A7 avoids the inherited uniform-letter allowlist.
        let pack = window_pack(r"\b(A7)B|\B(A7)B", "HELP", "0").replace(
            "regex = '''\\b(A7)B|\\B(A7)B'''",
            "regex = '''\\b(A7)B|\\B(A7)B'''\nsecretGroup = 2",
        );
        let engine = selected(&pack);
        let findings = scan(&engine, b"xA7B HELP", 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret().as_bytes(), b"A7");
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(1, 3).unwrap())
        );
        let rebuilt = Engine::builder(
            engine
                .config()
                .clone()
                .select_rules(["rustleaks.helper", "rustleaks.parent"])
                .unwrap(),
        )
        .build()
        .unwrap();
        assert_eq!(scan(&rebuilt, b"xA7B HELP", 0), findings);
        for prefix in [b"\xff\x80".as_slice(), "é".as_bytes()] {
            let pack = window_pack(r"\nBEGIN\n(value=ABCD)\n", "HELP", "1L");
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(b"\nBEGIN\nvalue=ABCD\nHELP");
            let findings = scan(&selected(&pack), &bytes, 0);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].secret().as_bytes(), b"value=ABCD");
            assert_eq!(findings[0].match_text().as_bytes(), b"BEGIN\nvalue=ABCD");
            assert_eq!(
                findings[0].match_range(),
                FindingRange::Exact(ByteRange::new(prefix.len() + 1, prefix.len() + 17).unwrap())
            );
            assert_eq!(
                findings[0].secret_range(),
                FindingRange::Exact(ByteRange::new(prefix.len() + 7, prefix.len() + 17).unwrap())
            );
        }
        let arbitrary = selected(&window_pack("P(.)", "HELP", "0"));
        let findings = scan(&arbitrary, b"P\xff HELP", 0);
        assert_eq!(findings[0].secret().as_bytes(), b"\xff");
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(1, 2).unwrap())
        );
        let capture_lf = selected(&window_pack(r"BEGIN(\nABCD\n)END", "HELP", "0"));
        let findings = scan(&capture_lf, b"BEGIN\nABCD\nEND HELP", 0);
        assert_eq!(findings[0].secret().as_bytes(), b"\nABCD\n");
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(5, 11).unwrap())
        );
        let empty = window_pack("P()", "HELP", "0")
            .replace("regex = '''P()'''", "regex = '''P()'''\nsecretGroup = 1");
        let findings = scan(&selected(&empty), b"P HELP", 0);
        assert_eq!(findings[0].secret().as_bytes(), b"");
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(1, 1).unwrap())
        );
        // Explicit nonparticipating capture fails rather than taking whole P.
        let absent = empty.replace("P()", "P(X)?");
        assert!(scan(&selected(&absent), b"P HELP", 0).is_empty());
    }

    #[test]
    fn parent_and_helper_path_and_allowlist_predicates_are_enforced() {
        for target in ["rustleaks.parent", "rustleaks.helper"] {
            let with_path = TUPLES.replace(
                &format!("[[rules]]\nid = \"{target}\"\n"),
                &format!("[[rules]]\nid = \"{target}\"\npath = '''allowed\\.txt$'''\n"),
            );
            let engine = selected(&with_path);
            assert!(scan(&engine, b"pair=GOOD:ABCD", 0).is_empty());
            let fragment = Fragment::builder(b"pair=GOOD:ABCD")
                .file_path("allowed.txt")
                .build();
            assert_eq!(
                engine
                    .scan_fragment(&fragment, &ScanOptions::default())
                    .findings()
                    .len(),
                1
            );
        }
        let engine = selected(TUPLES);
        assert!(scan(&engine, b"pair=GOOD:ABCD # gitleaks:allow", 0).is_empty());
        let path_allowed =
            TUPLES.replace("regexes = ['''^BAD$''']", "paths = ['''blocked\\.txt$''']");
        let engine = selected(&path_allowed);
        let fragment = Fragment::builder(b"pair=GOOD:ABCD")
            .file_path("blocked.txt")
            .build();
        assert!(
            engine
                .scan_fragment(&fragment, &ScanOptions::default())
                .findings()
                .is_empty()
        );
    }

    #[test]
    fn legacy_required_arrays_and_native_composition_keep_equal_results_and_usage() {
        let legacy = TUPLES.replace("[rules.required]\ncontract = \"buffer-v1\"\nedges = [{ id = \"rustleaks.helper\", relation = \"same-candidate\" }]", "[[rules.required]]\nid = \"rustleaks.helper\"\nwithinLines = 0\nwithinColumns = 0");
        let direct = Engine::builder(ConfigLoader::new().load_toml(&legacy).unwrap())
            .build()
            .unwrap();
        let native = selected(&legacy);
        for depth in 0..=2 {
            let fragment = Fragment::new(encoded(b"pair=BAD:WXYZ pair=GOOD:ABCD", depth));
            let options = ScanOptions::builder().max_decode_depth(depth).build();
            for budget in [
                ScanBudget::unlimited(),
                ScanBudget::unlimited().max_work_units(7),
                ScanBudget::unlimited().max_finding_records(2),
            ] {
                let control = ScanControl::unlimited().with_budget(budget);
                assert_eq!(
                    direct.scan_fragment_controlled(&fragment, &options, &control),
                    native.scan_fragment_controlled(&fragment, &options, &control)
                );
            }
        }
    }

    #[test]
    fn target_byte_gate_applies_to_each_native_input_buffer() {
        let engine = selected(TUPLES);
        let tuple = b"pair=GOOD:ABCD";
        let bytes = format!("pair=GOOD:WXYZ prefix {} suffix", STANDARD.encode(tuple));
        assert!(bytes.len() > tuple.len());
        let fragment = Fragment::new(bytes.as_bytes());
        let raw_options = ScanOptions::builder()
            .max_target_bytes(Some(tuple.len()))
            .build();
        assert!(
            engine
                .scan_fragment(&fragment, &raw_options)
                .findings()
                .is_empty()
        );
        let decoded_options = ScanOptions::builder()
            .max_decode_depth(1)
            .max_target_bytes(Some(tuple.len()))
            .build();
        let decoded = engine.scan_fragment(&fragment, &decoded_options);
        assert!(decoded.is_complete());
        assert_eq!(decoded.findings().len(), 1);
        assert_eq!(decoded.findings()[0].secret().as_bytes(), b"ABCD");
        assert_eq!(decoded.findings()[0].required_findings().len(), 1);
        assert_eq!(
            decoded.findings()[0].required_findings()[0]
                .secret()
                .as_bytes(),
            b"GOOD"
        );
        assert_eq!(
            decoded.findings()[0].secret_range(),
            FindingRange::Unavailable
        );
        let too_small = ScanOptions::builder()
            .max_decode_depth(1)
            .max_target_bytes(Some(tuple.len() - 1))
            .build();
        assert!(
            engine
                .scan_fragment(&fragment, &too_small)
                .findings()
                .is_empty()
        );
    }

    #[test]
    fn a_native_rule_does_not_publish_its_first_buffer_when_its_second_is_interrupted() {
        let engine = selected(TUPLES);
        let bytes = format!(
            "{} {}",
            STANDARD.encode(b"pair=GOOD:ABCD"),
            STANDARD.encode(b"pair=GOOD:WXYZ")
        );
        let fragment = Fragment::new(bytes.as_bytes());
        let options = ScanOptions::builder().max_decode_depth(1).build();
        let complete = engine.scan_fragment(&fragment, &options);
        assert!(complete.is_complete());
        assert_eq!(complete.findings().len(), 2);
        assert_eq!(complete.findings()[0].secret().as_bytes(), b"ABCD");
        assert_eq!(complete.findings()[1].secret().as_bytes(), b"WXYZ");
        // Each independent buffer admits one primary, one helper and one
        // projection. Limit four stops during the second buffer's helper.
        assert_eq!(complete.usage().finding_records(), 6);
        let limited = engine.scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(4)),
        );
        assert!(matches!(
            limited.termination(),
            Some(ScanTermination::BudgetExceeded {
                kind: ScanBudgetKind::FindingRecords,
                ..
            })
        ));
        assert_eq!(limited.usage().finding_records(), 4);
        assert!(limited.findings().is_empty());
        let mut cancelled_in_second_buffer = false;
        for threshold in 0..=complete.usage().work_units() + 30 {
            let polls = AtomicUsize::new(0);
            let signal = || polls.fetch_add(1, Ordering::Relaxed) >= threshold;
            let outcome = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::cancellable(&signal),
            );
            if !outcome.is_complete() {
                assert_eq!(outcome.termination(), Some(&ScanTermination::Cancelled));
                if outcome.usage().finding_records() < 6 {
                    assert!(outcome.findings().is_empty());
                }
                cancelled_in_second_buffer |= matches!(outcome.usage().finding_records(), 4 | 5);
            }
        }
        assert!(cancelled_in_second_buffer);
    }

    #[test]
    fn native_budget_boundaries_and_cancellation_never_publish_unfinished_rules() {
        let engine = selected(TUPLES);
        let mut bytes = b"\xff ".to_vec();
        bytes.extend(encoded(b"pair=GOOD:ABCD pair=GOOD:WXYZ", 2));
        let fragment = Fragment::new(bytes);
        let options = ScanOptions::builder().max_decode_depth(2).build();
        let complete = engine.scan_fragment(&fragment, &options);
        assert_eq!(complete.findings().len(), 2);
        let usage = complete.usage();
        let dimensions: [BudgetDimension; 6] = [
            (
                ScanBudgetKind::DecodedBytes,
                usage.decoded_bytes(),
                ScanBudget::max_decoded_bytes,
            ),
            (
                ScanBudgetKind::WorkUnits,
                usage.work_units(),
                ScanBudget::max_work_units,
            ),
            (
                ScanBudgetKind::FindingRecords,
                usage.finding_records(),
                ScanBudget::max_finding_records,
            ),
            (
                ScanBudgetKind::FindingPayloadBytes,
                usage.finding_payload_bytes(),
                ScanBudget::max_finding_payload_bytes,
            ),
            (
                ScanBudgetKind::CollectedSpans,
                usage.collected_spans(),
                ScanBudget::max_collected_spans,
            ),
            (
                ScanBudgetKind::NormalizationBytes,
                usage.normalization_bytes(),
                ScanBudget::max_normalization_bytes,
            ),
        ];
        for (kind, used, set) in dimensions {
            for limit in [0, used.saturating_sub(1), used] {
                let control =
                    ScanControl::unlimited().with_budget(set(ScanBudget::unlimited(), limit));
                let outcome = engine.scan_fragment_controlled(&fragment, &options, &control);
                if limit == used {
                    assert!(outcome.is_complete());
                    assert_eq!(outcome.findings(), complete.findings());
                } else {
                    assert!(
                        matches!(outcome.termination(), Some(ScanTermination::BudgetExceeded { kind: found, .. }) if *found == kind)
                    );
                    assert_eq!(
                        outcome.findings(),
                        &complete.findings()[..outcome.findings().len()]
                    );
                    if !outcome.findings().is_empty() {
                        assert_eq!(outcome.usage().finding_records(), usage.finding_records());
                    }
                }
            }
        }
        let earlier = format!("{TUPLES}\n[[rules]]\nid = \"rustleaks.a-prior\"\nregex = 'PRIOR'\n");
        let earlier = selected(&earlier);
        let partial = earlier.scan_fragment_controlled(
            &Fragment::new(b"PRIOR pair=GOOD:ABCD pair=GOOD:WXYZ"),
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(2)),
        );
        assert!(!partial.is_complete());
        assert_eq!(partial.findings().len(), 1);
        assert_eq!(
            partial.findings()[0].rule_id().as_bytes(),
            b"rustleaks.a-prior"
        );
        // Sweep cooperative checkpoints through decoder scope enumeration,
        // capture enumeration and required projection, using only synthetic bytes.
        for threshold in 0..=usage.work_units() + 30 {
            let polls = AtomicUsize::new(0);
            let signal = || polls.fetch_add(1, Ordering::Relaxed) >= threshold;
            let outcome = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::cancellable(&signal),
            );
            if !outcome.is_complete() {
                assert_eq!(outcome.termination(), Some(&ScanTermination::Cancelled));
            }
            assert_eq!(
                outcome.findings(),
                &complete.findings()[..outcome.findings().len()]
            );
            if !outcome.findings().is_empty() {
                assert_eq!(outcome.usage().finding_records(), usage.finding_records());
            }
        }
    }

    /// `count` pairs. Pair `index` has its helper on line `2 * index` and its
    /// primary on line `2 * index + 1`, counting from 0.
    fn dense_pairs(count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|index| format!("id={index:06}\ntok={index:06}\n").into_bytes())
            .collect()
    }

    fn scan_pairs(engine: &Engine, count: usize) -> (Vec<Finding>, [usize; 2]) {
        let bytes = dense_pairs(count);
        let outcome = engine.scan_fragment(&Fragment::new(bytes), &ScanOptions::default());
        assert!(outcome.is_complete());
        let usage = [
            outcome.usage().work_units(),
            outcome.usage().finding_records(),
        ];
        (outcome.findings().to_vec(), usage)
    }

    /// Usage for 64, 128 and 192 pairs grows by the same amount at each step.
    /// A cost for each primary and helper combination would grow faster.
    fn assert_linear(usage: &[[usize; 2]]) {
        for field in 0..2 {
            assert_eq!(
                usage[2][field] - usage[1][field],
                usage[1][field] - usage[0][field],
                "{usage:?}"
            );
        }
    }

    fn helper_secrets(finding: &Finding) -> Vec<String> {
        finding
            .required_findings()
            .iter()
            .map(|required| required.secret().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn unlimited_windows_attach_every_helper_with_linear_work_and_records() {
        let engine = selected(&window_pack("tok=([0-9]{6})", "id=([0-9]{6})", "0"));
        let mut usage = Vec::new();
        for count in [64, 128, 192] {
            let (findings, used) = scan_pairs(&engine, count);
            // Every helper in the buffer relates to every primary.
            let all = (0..count)
                .map(|index| format!("{index:06}"))
                .collect::<Vec<_>>();
            assert_eq!(findings.len(), count);
            for finding in &findings {
                assert_eq!(helper_secrets(finding), all);
                // All primaries share one helper list instead of a copy each.
                assert_eq!(
                    finding.required_findings().as_ptr(),
                    findings[0].required_findings().as_ptr()
                );
            }
            // Each primary and each helper candidate is one record, and the
            // shared list is projected once: one record per helper.
            assert_eq!(used[1], 3 * count);
            usage.push(used);
        }
        assert_linear(&usage);
    }

    #[test]
    fn line_windows_visit_only_nearby_helpers_with_linear_work_and_records() {
        // A 2L window admits helpers that start one line before the primary
        // through one line after it: helpers `index` and `index + 1`.
        let engine = selected(&window_pack("tok=([0-9]{6})", "id=([0-9]{6})", "2L"));
        let mut usage = Vec::new();
        for count in [64, 128, 192] {
            let (findings, used) = scan_pairs(&engine, count);
            assert_eq!(findings.len(), count);
            for (index, finding) in findings.iter().enumerate() {
                let expected = (index..count.min(index + 2))
                    .map(|helper| format!("{helper:06}"))
                    .collect::<Vec<_>>();
                assert_eq!(helper_secrets(finding), expected, "primary {index}");
            }
            // Primaries, helper candidates, and 2 projections for every
            // primary except the last, which has 1.
            assert_eq!(used[1], count + count + 2 * count - 1);
            usage.push(used);
        }
        assert_linear(&usage);
    }

    #[test]
    fn two_unlimited_edges_list_helpers_by_edge_then_occurrence() {
        // The pack contract orders required findings by edge and occurrence,
        // also when the helpers of the two edges alternate in the input.
        let engine = selected(
            r#"
[[rules]]
id = "rustleaks.parent"
regex = '''tok=([0-9]{6})'''
[rules.required]
contract = "buffer-v1"
edges = [
  { id = "rustleaks.first", relation = "full-match-window", window = "0" },
  { id = "rustleaks.second", relation = "full-match-window", window = "0" },
]
[[rules]]
id = "rustleaks.first"
regex = '''a=([0-9]{6})'''
skipReport = true
[[rules]]
id = "rustleaks.second"
regex = '''b=([0-9]{6})'''
skipReport = true
"#,
        );
        let input = b"a=000001\nb=000002\ntok=111111\na=000003\nb=000004\ntok=222222\n";
        let findings = scan(&engine, input, 0);
        assert_eq!(findings.len(), 2);
        for finding in &findings {
            assert_eq!(
                helper_secrets(finding),
                ["000001", "000003", "000002", "000004"]
            );
            let ids = finding
                .required_findings()
                .iter()
                .map(|required| required.rule_id().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                ids,
                [
                    "rustleaks.first",
                    "rustleaks.first",
                    "rustleaks.second",
                    "rustleaks.second"
                ]
            );
        }
        // Without any helper of the second edge, no primary qualifies.
        assert!(scan(&engine, b"a=000001\ntok=111111\n", 0).is_empty());
    }

    #[test]
    fn same_candidate_needs_the_same_start_and_end() {
        // A same-candidate helper must have the same whole match. One that
        // starts at the same byte but ends earlier does not relate.
        let pack = |helper: &str| {
            format!(
                r#"
[[rules]]
id = "rustleaks.parent"
regex = '''pair=([A-Z]{{4}}):([A-Z]{{4}})'''
secretGroup = 2
[rules.required]
contract = "buffer-v1"
edges = [{{ id = "rustleaks.helper", relation = "same-candidate" }}]
[[rules]]
id = "rustleaks.helper"
regex = '''{helper}'''
skipReport = true
"#
            )
        };
        let input = b"pair=GOOD:ABCD pair=FINE:WXYZ";
        let shorter = selected(&pack("pair=([A-Z]{4})"));
        assert!(scan(&shorter, input, 0).is_empty());
        let same = selected(&pack("pair=([A-Z]{4}):[A-Z]{4}"));
        let findings = scan(&same, input, 0);
        assert_eq!(findings.len(), 2);
        assert_eq!(helper_secrets(&findings[0]), ["GOOD"]);
        assert_eq!(helper_secrets(&findings[1]), ["FINE"]);
    }
}

mod native_bytes {
    use super::*;
    use rustleaks_core::config::{ConfigError, VirtualResolver};
    use rustleaks_core::model::{ByteRange, Finding, FindingRange};
    use rustleaks_core::{ScanBudgetKind, ScanTermination};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pack(pattern: &str, keywords: &[&str]) -> String {
        let keywords = toml::Value::Array(
            keywords
                .iter()
                .map(|keyword| toml::Value::String((*keyword).to_owned()))
                .collect(),
        );
        format!(
            "[[rules]]\nid='rustleaks.bytes'\nregex = {{ dialect='bytes-v1', pattern='''{pattern}''' }}\nkeywords={keywords}\n"
        )
    }

    fn selected(source: &str) -> Engine {
        let (config, _) = NativePolicy::builder()
            .with_pack("bytes-test", source)
            .unwrap()
            .compile()
            .unwrap();
        let ids = config
            .ordered_rule_ids()
            .iter()
            .filter(|id| id.starts_with("rustleaks."))
            .map(String::as_str);
        Engine::builder(config.clone().select_rules(ids).unwrap())
            .build()
            .unwrap()
    }

    fn scan(engine: &Engine, bytes: &[u8], depth: usize) -> Vec<Finding> {
        let outcome = engine.scan_fragment(
            &Fragment::new(bytes),
            &ScanOptions::builder().max_decode_depth(depth).build(),
        );
        assert!(outcome.is_complete());
        outcome.findings().to_vec()
    }

    #[test]
    fn keyword_classification_uses_original_text_on_short_and_long_raw_buffers() {
        for (keywords, input, matched) in [
            (
                vec!["accesskey"],
                "access\u{212a}ey marker=ABCD".as_bytes(),
                false,
            ),
            (vec!["accesskey"], b"AcCeSsKeY marker=ABCD".as_slice(), true),
            (vec!["\u{212a}ey"], b"KEY marker=ABCD".as_slice(), true),
            (
                vec!["\u{212a}ey"],
                "\u{212a}EY marker=ABCD".as_bytes(),
                true,
            ),
            (vec![""], b"marker=ABCD".as_slice(), true),
            (
                vec!["missing", "\u{212a}ey"],
                b"KEY marker=ABCD".as_slice(),
                true,
            ),
            (vec!["İ"], "i\u{307} marker=ABCD".as_bytes(), true),
            (vec!["İ"], b"i marker=ABCD".as_slice(), false),
            (vec!["ΟΣ"], "ΟΣ marker=ABCD".as_bytes(), true),
            (vec!["ΟΣ"], "οσ marker=ABCD".as_bytes(), false),
            (vec!["�"], b"\xe2\x82 marker=ABCD".as_slice(), true),
            (vec!["��"], b"\xe2\x82 marker=ABCD".as_slice(), false),
        ] {
            let engine = selected(&pack(r"marker=([A-Z]{4})", &keywords));
            for padding in [0, 300] {
                let bytes = [vec![b' '; padding], input.to_vec()].concat();
                let findings = scan(&engine, &bytes, 0);
                assert_eq!(
                    findings.len(),
                    usize::from(matched),
                    "{keywords:?}, padding={padding}"
                );
                if matched {
                    assert_eq!(findings[0].secret().as_bytes(), b"ABCD");
                    assert_eq!(
                        findings[0].secret_range(),
                        FindingRange::Exact(ByteRange::new(bytes.len() - 4, bytes.len()).unwrap())
                    );
                }
            }
        }
    }

    #[test]
    fn typed_regex_validation_and_ordinary_loaders_fail_closed() {
        let source = pack(r"([AB]{16,2048})", &[]);
        assert!(matches!(
            ConfigLoader::new().load_toml(&source),
            Err(ConfigError::Decode { .. })
        ));
        let resolver = VirtualResolver::new().with_file("bytes.toml", &source);
        assert!(
            ConfigLoader::new()
                .with_resolver(resolver)
                .load_toml("[extend]\npath='bytes.toml'\n")
                .is_err()
        );
        let engine = selected(&source);
        assert_eq!(
            engine.config().rule("rustleaks.bytes").unwrap().regex(),
            Some(r"([AB]{16,2048})")
        );
        // The inherited default allowlist suppresses uniform-letter secrets.
        // Alternating bytes independently exercise the full native repeat bound.
        let input = b"AB".repeat(1024);
        let findings = scan(&engine, &input, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret().as_bytes(), input);
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(0, 2048).unwrap())
        );
        for regex in [
            "{dialect='bytes-v2',pattern='A'}",
            "{pattern='A'}",
            "{dialect='bytes-v1'}",
            "{dialect='bytes-v1',pattern=3}",
            "{dialect='bytes-v1',pattern='A',extra=true}",
            "{dialect='bytes-v1',Dialect='bytes-v1',pattern='A'}",
            "{dialect='bytes-v1',pattern='A',Pattern='A'}",
            "['bytes-v1','A']",
        ] {
            let source = format!("[[rules]]\nid='rustleaks.bytes'\nregex={regex}\n");
            assert!(
                NativePolicy::builder()
                    .with_pack("invalid", &source)
                    .and_then(NativePolicy::compile)
                    .is_err(),
                "{regex}"
            );
        }
        for source in [
            pack("(", &[]),
            format!("{}secretGroup=2\n", pack("(A)", &[])),
        ] {
            assert!(
                NativePolicy::builder()
                    .with_pack("invalid", &source)
                    .unwrap()
                    .compile()
                    .is_err()
            );
        }
        let byte = NativePolicy::builder()
            .with_pack("identity", &pack("A", &[]))
            .unwrap()
            .compile()
            .unwrap();
        let string = NativePolicy::builder()
            .with_pack("identity", "[[rules]]\nid='rustleaks.bytes'\nregex='A'\n")
            .unwrap()
            .compile()
            .unwrap();
        assert_ne!(byte.1, string.1);
        assert_ne!(
            byte.0.rule("rustleaks.bytes"),
            string.0.rule("rustleaks.bytes")
        );
    }

    #[test]
    fn raw_invalid_bytes_are_not_normalized_and_captures_keep_buffer_context() {
        // Multibyte and malformed bytes in whole matches require no content
        // normalization. Invalid captured bytes still reach the two default
        // global secret allowlists, the Gitleaks one and the Rustleaks vendor
        // examples, and each owns its separately charged buffer.
        // Varied ASCII captures avoid its uniform-letter suppression.
        let invalid_secret_normalization = 2 * (2 + 2 * (2 + size_of::<usize>()));
        for (pattern, input, whole, secret, normalization) in [
            (r"a(?s:.{0,2})(X0)", "aéaX0".as_bytes(), (3, 6), (4, 6), 0),
            (r"[^X](X0)", "éX0".as_bytes(), (1, 4), (2, 4), 0),
            (r"\b(A0)B|\B(A0)B", b"xA0B".as_slice(), (1, 4), (1, 3), 0),
            (
                r"(?s:\xFF.)(AB)",
                b"\0\xff\x80AB".as_slice(),
                (1, 5),
                (3, 5),
                0,
            ),
            (
                r"(?s:(\xFF.))",
                b"\0\xff\x80".as_slice(),
                (1, 3),
                (1, 3),
                invalid_secret_normalization,
            ),
            (r"^(AB)|(AB)$", "éAB".as_bytes(), (2, 4), (2, 4), 0),
        ] {
            let engine = selected(&pack(pattern, &[]));
            let fragment = Fragment::new(input);
            let outcome = engine.scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited()
                    .with_budget(ScanBudget::unlimited().max_normalization_bytes(normalization)),
            );
            assert!(outcome.is_complete(), "pattern {pattern}");
            assert_eq!(outcome.findings().len(), 1, "pattern {pattern}");
            let finding = &outcome.findings()[0];
            assert_eq!(finding.match_text().as_bytes(), &input[whole.0..whole.1]);
            assert_eq!(
                finding.match_range(),
                FindingRange::Exact(ByteRange::new(whole.0, whole.1).unwrap())
            );
            assert_eq!(
                finding.secret_range(),
                FindingRange::Exact(ByteRange::new(secret.0, secret.1).unwrap())
            );
            assert_eq!(finding.secret().as_bytes(), &input[secret.0..secret.1]);
            assert_eq!(
                outcome.usage().normalization_bytes(),
                normalization,
                "pattern {pattern}"
            );
        }
    }

    #[test]
    fn byte_rules_keep_keyword_and_helper_ownership_across_decoded_siblings() {
        let source = format!(
            "{}[rules.required]\ncontract='buffer-v1'\nedges=[{{id='rustleaks.helper',relation='full-match-window',window='0'}}]\n[[rules]]\nid='rustleaks.helper'\nregex={{dialect='bytes-v1',pattern='HELP'}}\nkeywords=['key']\nskipReport=true\n",
            pack("marker=(ABCD)", &["accesskey"])
        );
        let engine = selected(&source);
        let good = b"accesskey marker=ABCD key HELP";
        assert_eq!(scan(&engine, good, 0).len(), 1);
        for depth in [1, 2] {
            let mut input = good.to_vec();
            for _ in 0..depth {
                input = STANDARD.encode(input).into_bytes();
            }
            let findings = scan(&engine, &input, depth);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].required_findings().len(), 1);
        }
        for pieces in [
            [b"accesskey marker=ABCD".as_slice(), b"key HELP".as_slice()],
            [b"marker=ABCD key HELP".as_slice(), b"accesskey".as_slice()],
            [
                "access\u{212a}ey marker=ABCD key HELP".as_bytes(),
                b"accesskey".as_slice(),
            ],
        ] {
            let bytes = format!(
                "{} {}",
                STANDARD.encode(pieces[0]),
                STANDARD.encode(pieces[1])
            );
            assert!(scan(&engine, bytes.as_bytes(), 1).is_empty());
        }
    }

    #[test]
    fn native_helper_keywords_use_original_classification_for_legacy_string_helpers() {
        let source = format!(
            "{}[rules.required]\ncontract='buffer-v1'\nedges=[{{id='rustleaks.helper',relation='same-candidate'}}]\n[[rules]]\nid='rustleaks.helper'\nregex='marker=(ABCD)'\nkeywords=['accesskey']\nskipReport=true\n",
            pack("marker=(ABCD)", &[])
        );
        let engine = selected(&source);
        assert!(scan(&engine, "access\u{212a}ey marker=ABCD".as_bytes(), 0).is_empty());
        assert_eq!(scan(&engine, b"ACCESSKEY marker=ABCD", 0).len(), 1);
        let empty = selected(&source.replace("['accesskey']", "['']"));
        assert_eq!(scan(&empty, b"marker=ABCD", 0).len(), 1);
    }

    #[test]
    fn byte_budget_boundaries_and_cancellation_preserve_completed_rule_atomicity() {
        let engine = selected(&pack(r"marker=(\xFF[A-Z]{4})", &["\u{212a}ey", "missing"]));
        let fragment = Fragment::new(b"KEY marker=\xffABCD marker=\xffWXYZ");
        // No decoder or later rule can add checkpoints after this rule completes.
        let options = ScanOptions::builder().max_decode_depth(0).build();
        let complete = engine.scan_fragment(&fragment, &options);
        assert!(complete.is_complete());
        assert_eq!(complete.findings().len(), 2);
        for (finding, (secret, start, end)) in complete.findings().iter().zip([
            (b"\xffABCD".as_slice(), 11, 16),
            (b"\xffWXYZ".as_slice(), 24, 29),
        ]) {
            assert_eq!(finding.secret().as_bytes(), secret);
            assert_eq!(
                finding.secret_range(),
                FindingRange::Exact(ByteRange::new(start, end).unwrap())
            );
        }
        // Each of the two five-byte secrets has one malformed byte. Only the
        // two default global secret allowlists, the Gitleaks one and the
        // Rustleaks vendor examples, normalize, each T + (2 + usize) * I.
        let allowlist_normalization = 2 * 2 * (5 + 2 + size_of::<usize>());
        assert_eq!(
            complete.usage().normalization_bytes(),
            allowlist_normalization
        );
        let usage = complete.usage();
        let dimensions: [BudgetDimension; 5] = [
            (
                ScanBudgetKind::WorkUnits,
                usage.work_units(),
                ScanBudget::max_work_units,
            ),
            (
                ScanBudgetKind::CollectedSpans,
                usage.collected_spans(),
                ScanBudget::max_collected_spans,
            ),
            (
                ScanBudgetKind::FindingRecords,
                usage.finding_records(),
                ScanBudget::max_finding_records,
            ),
            (
                ScanBudgetKind::FindingPayloadBytes,
                usage.finding_payload_bytes(),
                ScanBudget::max_finding_payload_bytes,
            ),
            (
                ScanBudgetKind::NormalizationBytes,
                allowlist_normalization,
                ScanBudget::max_normalization_bytes,
            ),
        ];
        for (kind, used, set) in dimensions {
            for limit in [0, used - 1, used] {
                let result = engine.scan_fragment_controlled(
                    &fragment,
                    &options,
                    &ScanControl::unlimited().with_budget(set(ScanBudget::unlimited(), limit)),
                );
                if limit == used {
                    assert_eq!(result, complete);
                } else {
                    assert!(
                        matches!(result.termination(), Some(ScanTermination::BudgetExceeded {kind: found, ..}) if *found == kind)
                    );
                    assert!(result.findings().is_empty());
                }
            }
        }
        // With unlimited resource counters, cancellation polls once initially,
        // once per work unit, and once before each of the two finding admissions.
        // The last work units are the second candidate's line-coordinate scan.
        // The rule then publishes both candidates with no intervening poll.
        let rule_completion_polls = 1 + usage.work_units() + 2;
        let mut cancelled_after_both_admissions = false;
        for threshold in 0..=rule_completion_polls + 4 {
            let polls = AtomicUsize::new(0);
            let signal = || polls.fetch_add(1, Ordering::Relaxed) >= threshold;
            let result = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::cancellable(&signal),
            );
            if threshold < rule_completion_polls {
                assert_eq!(result.termination(), Some(&ScanTermination::Cancelled));
                assert!(result.findings().is_empty());
                assert!(result.usage().work_units() < usage.work_units());
                cancelled_after_both_admissions |= result.usage().finding_records() == 2;
            } else if threshold < rule_completion_polls + 4 {
                // Final filtering polls once to classify each finding, then
                // once before each non-generic finding. All rule work is
                // complete, so cancellation exposes exactly the already
                // finalized prefix: zero findings three times, then one.
                assert_eq!(result.termination(), Some(&ScanTermination::Cancelled));
                assert_eq!(result.usage(), usage);
                let finalized = (threshold - rule_completion_polls).saturating_sub(2);
                assert_eq!(result.findings(), &complete.findings()[..finalized]);
            } else {
                assert_eq!(result, complete);
            }
        }
        assert!(cancelled_after_both_admissions);
    }
    #[test]
    fn utf8_azure_comment_keeps_the_source_byte_bridge_and_exact_helper_spans() {
        let source = r"
[[rules]]
id='rustleaks.bytes'
regex={dialect='bytes-v1',pattern='''(?i)\b(?:AccountKey|(?:azure[_\s.-]*)?(?:storage[_\s.-]*)?(?:account[_\s.-]*)?(?:access[_\s.-]*)?key)\b(?s:.{0,24}?)([A-Za-z0-9+/]{86}==)'''}
keywords=['accountkey','storage','accesskey','access_key','access-key']
entropy={algorithm='byte-shannon-f64-v1',reject='lt',threshold=4.0}
[rules.required]
contract='buffer-v1'
edges=[{id='rustleaks.helper',relation='full-match-window',window='8L'}]
[[rules]]
id='rustleaks.helper'
regex={dialect='bytes-v1',pattern='''(?i)(?:\bAccountName\s*=\s*([a-z0-9]{3,24})\b|https://([a-z0-9]{3,24})\.blob\.core\.windows\.net\b|\b(?:azure[_\s.-]*storage[_\s.-]*(?:account[_\s.-]*)?name|storage[_\s.-]*account[_\s.-]*name)\b(?s:.{0,24}?)([a-z0-9]{3,24})\b)'''}
keywords=['accountname','blob.core.windows.net','storage']
skipReport=true
";
        // Synthetic 64-byte value defined independently as (37*i+251) mod 256.
        let key = STANDARD.encode(
            (0u8..64)
                .map(|i| i.wrapping_mul(37).wrapping_add(251))
                .collect::<Vec<_>>(),
        );
        let input = format!(
            "const endpoint = \"https://scopeaudit.blob.core.windows.net\";\nconst AccountKey /*é*/ = \"{key}\";"
        );
        let findings = scan(&selected(source), input.as_bytes(), 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].match_range(),
            FindingRange::Exact(ByteRange::new(67, 176).unwrap())
        );
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(88, 176).unwrap())
        );
        assert_eq!(findings[0].secret().as_bytes(), key.as_bytes());
        let helper = &findings[0].required_findings()[0];
        assert_eq!(
            helper.match_range(),
            FindingRange::Exact(ByteRange::new(18, 58).unwrap())
        );
        assert_eq!(
            helper.secret_range(),
            FindingRange::Exact(ByteRange::new(26, 36).unwrap())
        );
        assert_eq!(helper.secret().as_bytes(), b"scopeaudit");
    }

    #[test]
    fn trailing_lf_relation_coordinates_are_distinct_from_trimmed_report_spans() {
        let source = format!(
            "{}[rules.required]\ncontract='buffer-v1'\nedges=[{{id='rustleaks.helper',relation='full-match-window',window='1L'}}]\n[[rules]]\nid='rustleaks.helper'\nregex={{dialect='bytes-v1',pattern='HZ'}}\nskipReport=true\n",
            pack(r"P(XY)\n", &[])
        );
        let findings = scan(&selected(&source), b"PXY\nHZ", 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_text().as_bytes(), b"PXY");
        assert_eq!(
            findings[0].match_range(),
            FindingRange::Exact(ByteRange::new(0, 3).unwrap())
        );
        assert_eq!(
            findings[0].secret_range(),
            FindingRange::Exact(ByteRange::new(1, 3).unwrap())
        );
        assert_eq!(
            findings[0].required_findings()[0].match_range(),
            FindingRange::Exact(ByteRange::new(4, 6).unwrap())
        );
        assert!(scan(&selected(&source), b"PXY\n\nHZ", 0).is_empty());
    }

    #[test]
    fn native_line_coordinates_charge_each_counted_byte_once() {
        let engine = selected(&pack("TOK[0-9]{4}", &["tok"]));
        let mut totals = Vec::new();
        for lines in [64, 128] {
            let bytes = b"x=TOK0123\n".repeat(lines);
            let outcome = engine.scan_fragment(&Fragment::new(bytes), &ScanOptions::default());
            assert!(outcome.is_complete());
            assert_eq!(outcome.findings().len(), lines);
            // With 10 bytes per line and the match at bytes 2..9 of each:
            // 1 pass start, 1 prefilter hit per line, 1 rule entry, 1 for the
            // one keyword plus 10 per line for its search, 2 per candidate,
            // and line coordinates counted once up to the last match end,
            // 10 * lines - 1 bytes. Recounting each prefix would instead add
            // the sum of every match end, 5 * lines * lines + 4 * lines.
            assert_eq!(
                outcome.usage().work_units(),
                23 * lines + 2,
                "{lines} lines"
            );
            totals.push(outcome.usage().work_units());
        }
        assert_eq!(totals, [1474, 2946]);
        assert_eq!(totals[1] - 2, 2 * (totals[0] - 2));
    }

    #[test]
    fn same_line_windows_pair_only_on_their_own_line_across_many_candidates() {
        let source = format!(
            "{}[rules.required]\ncontract='buffer-v1'\nedges=[{{id='rustleaks.helper',relation='full-match-window',window='1L'}}]\n[[rules]]\nid='rustleaks.helper'\nregex={{dialect='bytes-v1',pattern='H[0-9]{{3}}'}}\nskipReport=true\n",
            pack("P[0-9]{3}", &[])
        );
        let engine = selected(&source);
        // Every line has a primary match; only even lines have a helper.
        let mut bytes = Vec::new();
        for line in 0..64 {
            bytes.extend_from_slice(format!("P{line:03}").as_bytes());
            if line % 2 == 0 {
                bytes.extend_from_slice(format!(" H{line:03}").as_bytes());
            }
            bytes.push(b'\n');
        }
        let findings = scan(&engine, &bytes, 0);
        let pairs = findings
            .iter()
            .map(|finding| {
                assert_eq!(finding.required_findings().len(), 1);
                (
                    finding.secret().to_string_lossy().into_owned(),
                    finding.required_findings()[0]
                        .secret()
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect::<Vec<_>>();
        let expected = (0..64)
            .step_by(2)
            .map(|line| (format!("P{line:03}"), format!("H{line:03}")))
            .collect::<Vec<_>>();
        assert_eq!(pairs, expected);
    }

    #[test]
    fn line_cursor_advances_past_a_newline_inside_an_admitted_match() {
        // Each helper match ends with its line's LF, so the next counted
        // line must start after it. A helper placed one line too early
        // would pair with the odd-line primary that has no helper.
        let source = format!(
            "{}[rules.required]\ncontract='buffer-v1'\nedges=[{{id='rustleaks.helper',relation='full-match-window',window='1L'}}]\n[[rules]]\nid='rustleaks.helper'\nregex={{dialect='bytes-v1',pattern='H[0-9]{{3}}\\n'}}\nskipReport=true\n",
            pack("P[0-9]{3}", &[])
        );
        let engine = selected(&source);
        let mut bytes = Vec::new();
        for line in 0..64 {
            bytes.extend_from_slice(format!("P{line:03}").as_bytes());
            if line % 2 == 0 {
                bytes.extend_from_slice(format!(" H{line:03}").as_bytes());
            }
            bytes.push(b'\n');
        }
        let pairs = scan(&engine, &bytes, 0)
            .iter()
            .map(|finding| {
                assert_eq!(finding.required_findings().len(), 1);
                (
                    finding.secret().to_string_lossy().into_owned(),
                    finding.required_findings()[0]
                        .secret()
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect::<Vec<_>>();
        let expected = (0..64)
            .step_by(2)
            .map(|line| (format!("P{line:03}"), format!("H{line:03}\n")))
            .collect::<Vec<_>>();
        assert_eq!(pairs, expected);
    }

    #[test]
    fn byte_rules_retain_path_allowlist_entropy_and_allow_marker_filters() {
        let source = format!(
            "{}path='allowed'\nentropy={{algorithm='byte-shannon-f64-v1',reject='lt',threshold=1.0}}\n[[rules.allowlists]]\nregexes=['^AAAA$']\n",
            pack(r"marker=([A-Z]{4})", &[])
        );
        let engine = selected(&source);
        for (path, bytes, count) in [
            ("allowed.txt", b"marker=ABCD".as_slice(), 1),
            ("other.txt", b"marker=ABCD".as_slice(), 0),
            ("allowed.png", b"marker=ABCD".as_slice(), 0),
            ("allowed.txt", b"marker=AAAA".as_slice(), 0),
            (
                "allowed.txt",
                b"marker=ABCD # rustleaks:allow".as_slice(),
                0,
            ),
        ] {
            let result = engine.scan_fragment(
                &Fragment::builder(bytes).file_path(path).build(),
                &ScanOptions::default(),
            );
            assert!(result.is_complete());
            assert_eq!(result.findings().len(), count);
        }
        let source = format!(
            "{}[[rules.allowlists]]\nregexes=['.+']\n",
            pack(r"marker=(\xFF)", &[])
        );
        let engine = selected(&source);
        let fragment = Fragment::new(b"marker=\xff");
        let complete = engine.scan_fragment(&fragment, &ScanOptions::default());
        assert!(complete.findings().is_empty());
        assert!(complete.usage().normalization_bytes() > 0);
        let limited = engine.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_normalization_bytes(0)),
        );
        assert!(matches!(
            limited.termination(),
            Some(ScanTermination::BudgetExceeded {
                kind: ScanBudgetKind::NormalizationBytes,
                ..
            })
        ));
    }
}

// A synthetic value of `prefix` and `length` mixed ASCII letters and digits,
// built at run time so that no token-shaped literal is in the source.
fn synthetic(prefix: &str, length: usize) -> String {
    let body: String = "Q7m2Z9v4L1c8R5s0N6b3X"
        .chars()
        .cycle()
        .take(length)
        .collect();
    format!("{prefix}{body}")
}

fn groq() -> String {
    synthetic("gsk_", 52)
}

fn rule_ids_found(config: rustleaks_core::config::CompiledConfig, input: &str) -> Vec<String> {
    let engine = Engine::builder(config).build().unwrap();
    engine
        .scan_fragment(&Fragment::new(input.as_bytes()), &ScanOptions::default())
        .findings()
        .iter()
        .map(|finding| finding.rule_id().as_str().unwrap().to_owned())
        .collect()
}

// The default rules without the Rustleaks rule files.
fn default_rules_alone() -> ConfigLoader {
    ConfigLoader::new().with_default_config(rustleaks_core::config::DEFAULT_CONFIG)
}

#[test]
fn the_library_default_is_the_default_rules_plus_every_rule_file() {
    let line = format!("{}\n", groq());

    let gitleaks = default_rules_alone().load_default().unwrap();
    let builtin = ConfigLoader::new().load_default().unwrap();
    assert_eq!(
        builtin.ordered_rule_ids(),
        ConfigLoader::default()
            .load_default()
            .unwrap()
            .ordered_rule_ids()
    );
    let (composed, _) = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", rustleaks_core::native::EXTRA_RULES_V1)
        .unwrap()
        .with_pack(
            "rustleaks-providers-v1",
            rustleaks_core::native::PROVIDER_RULES_V1,
        )
        .unwrap()
        .with_pack(
            "rustleaks-connections-v1",
            rustleaks_core::native::CONNECTION_RULES_V1,
        )
        .unwrap()
        .compile()
        .unwrap();
    assert_eq!(builtin.ordered_rule_ids(), composed.ordered_rule_ids());
    for id in gitleaks.ordered_rule_ids() {
        assert!(builtin.rule(id).is_some(), "{id}");
    }
    assert!(builtin.rule("rustleaks.groq-api-key").is_some());
    assert!(gitleaks.rule("rustleaks.groq-api-key").is_none());

    assert_eq!(rule_ids_found(builtin, &line), ["rustleaks.groq-api-key"]);
    assert!(rule_ids_found(gitleaks, &line).is_empty());
}

#[test]
fn extending_the_default_includes_the_builtin_rules() {
    let line = format!("{}\n", groq());
    let extend = "[extend]\nuseDefault = true\n";
    let builtin = ConfigLoader::new().load_toml(extend).unwrap();
    assert_eq!(rule_ids_found(builtin, &line), ["rustleaks.groq-api-key"]);
    let gitleaks = default_rules_alone().load_toml(extend).unwrap();
    assert!(rule_ids_found(gitleaks, &line).is_empty());

    let disabled = ConfigLoader::new()
        .load_toml("[extend]\nuseDefault = true\ndisabledRules = [\"rustleaks.groq-api-key\"]\n")
        .unwrap();
    assert!(disabled.rule("rustleaks.groq-api-key").is_none());
    assert!(rule_ids_found(disabled, &line).is_empty());

    // A configuration without an extension gets only its own rules.
    let own = ConfigLoader::new()
        .load_toml("[[rules]]\nid = \"own\"\nregex = '''own=([a-z]{8})'''\n")
        .unwrap();
    assert_eq!(own.ordered_rule_ids(), ["own"]);
}

#[test]
fn replaced_default_text_ignores_the_builtin_rules() {
    let text = "[[rules]]\nid = \"only\"\nregex = '''only=([a-z]{8})'''\n";
    let loader = ConfigLoader::new().with_default_config(text);
    assert_eq!(loader.load_default().unwrap().ordered_rule_ids(), ["only"]);
    let extended = loader.load_toml("[extend]\nuseDefault = true\n").unwrap();
    assert_eq!(extended.ordered_rule_ids(), ["only"]);
}

#[test]
fn an_extending_rule_replaces_a_builtin_entropy_predicate() {
    // `rustleaks.dockerhub-personal-access-token` has a structured byte
    // entropy predicate. A Gitleaks-format regex and entropy in an extending
    // config replace the built-in matcher and predicate. Keywords are merged,
    // so the override adds its own.
    let id = "rustleaks.dockerhub-personal-access-token";
    let builtin = ConfigLoader::new().load_default().unwrap();
    assert!(builtin.rule(id).unwrap().native_entropy().is_some());
    let config = ConfigLoader::new()
        .load_toml(&format!(
            "[extend]\nuseDefault = true\n[[rules]]\nid = \"{id}\"\n\
             regex = \'\'\'docker=([a-z]{{8}})\'\'\'\nentropy = 1.0\nkeywords = [\"docker=\"]\n"
        ))
        .unwrap();
    assert!(config.rule(id).unwrap().native_entropy().is_none());
    assert_eq!(rule_ids_found(config.clone(), "docker=abcdefgh\n"), [id]);
    let original = format!("{}\n", synthetic("dckr_pat_", 27));
    assert!(rule_ids_found(config, &original).is_empty());
    assert_eq!(rule_ids_found(builtin, &original), [id]);
}

#[test]
fn required_byte_rules_find_decoded_values_with_or_without_explanations() {
    // The primary rule's literal `marker=` is outside the decoded value, so
    // the required rule must be gated by its own literals, not the primary
    // rule's.
    const COMPOSITE: &str = r#"
[[rules]]
id = "rustleaks.test-primary"
regex = '''marker=(\S+)'''
keywords = ["marker", "mark2"]
[[rules.required]]
id = "rustleaks.test-helper"

[[rules]]
id = "rustleaks.test-helper"
regex = { dialect = "bytes-v1", pattern = "(AIK_CLIENT_[A-Za-z0-9]{24})" }
keywords = ["aik_client_"]
"#;
    let policy = NativePolicy::builder()
        .with_pack("test-pack-v1", COMPOSITE)
        .unwrap()
        .build()
        .unwrap();
    let value = ["AIK_CLIENT_", "Qx7Lm2Pz9Rk4Tw8Vb3Nc6Hj1"].concat();
    let encoded = STANDARD.encode(&value);
    let options = ScanOptions::builder().max_decode_depth(2).build();
    for input in [format!("marker={encoded}\n"), format!("marker={value}\n")] {
        let fragment = Fragment::new(input.as_bytes());
        let plain = policy
            .engine()
            .scan_fragment_controlled(&fragment, &options, &ScanControl::unlimited());
        let mut ids = plain
            .findings()
            .iter()
            .map(|finding| finding.rule_id().to_string())
            .collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids,
            ["rustleaks.test-helper", "rustleaks.test-primary"],
            "{input:?}"
        );
        for limit in [0, 1, 4_096] {
            let explained = policy.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::unlimited(),
                ExplanationOptions::bounded(limit),
            );
            assert_eq!(plain.findings(), explained.scan().findings(), "{input:?}");
        }
    }
}
