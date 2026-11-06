//! Optional larger structured cases; routine tests check only profile contracts.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[allow(dead_code)]
#[path = "support/campaign_profile.rs"]
mod campaign_profile;

use base64::Engine as _;
use campaign_profile::{DEEP_INPUT_BYTES, Profile, TARGETS, deep_seed};
use rustleaks_core::config::{CompiledConfig, ConfigLoader, RawConfig, RuleSpec};
use rustleaks_core::model::{Finding, Fragment, Location, ScanOptions};
use rustleaks_core::session::{Baseline, SessionPolicy, SuppressionReason};
use rustleaks_core::{Engine, ScanBudget, ScanBudgetKind, ScanControl, ScanTermination};
use serde_json::json;

fn engine(regex: &str) -> Engine {
    Engine::builder(
        ConfigLoader::new()
            .compile(RawConfig {
                rules: vec![RuleSpec {
                    id: "structured".into(),
                    regex: regex.into(),
                    ..RuleSpec::default()
                }],
                ..RawConfig::default()
            })
            .expect("fixed rule compiles"),
    )
    .build()
    .expect("fixed engine builds")
}

#[test]
fn profiles_keep_smoke_caps_and_reject_unknown_names() {
    assert_eq!(Profile::from_name(None), Ok(Profile::Smoke));
    assert_eq!(Profile::from_name(Some("extended")), Ok(Profile::Smoke));
    assert_eq!(Profile::from_name(Some("deep")), Ok(Profile::Deep));
    assert!(Profile::from_name(Some("arbitrary")).is_err());
    for (target, smoke) in TARGETS
        .iter()
        .zip([4096, 8192, 8192, 16384, 8192, 4096, 16384, 8192])
    {
        assert_eq!(Profile::Smoke.input_limit(target), Some(smoke));
        assert_eq!(Profile::Deep.input_limit(target), Some(DEEP_INPUT_BYTES));
        let seed = deep_seed(target).expect("every target has a large seed");
        assert!(seed.len() > smoke);
        assert!(seed.len() <= DEEP_INPUT_BYTES);
    }
    assert_eq!(Profile::Deep.input_limit("unknown"), None);
    assert!(deep_seed("unknown").is_none());
    assert_eq!(Profile::Smoke.fragment().decode_depth, 2);
    assert_eq!(Profile::Deep.fragment().decode_depth, 4);
}

#[test]
fn large_config_seed_places_its_rule_past_the_smoke_boundary() {
    let seed = deep_seed("config").expect("known target");
    let text = std::str::from_utf8(&seed).expect("synthetic UTF-8");
    assert_eq!(
        ConfigLoader::new().load_toml(text).unwrap().rules().len(),
        1
    );
    let smoke = Profile::Smoke.input_limit("config").unwrap();
    assert!(
        ConfigLoader::new()
            .load_toml(&text[..smoke])
            .unwrap()
            .rules()
            .is_empty()
    );
}

#[test]
#[ignore = "optional larger-input driver, invoked by the deep-security operator"]
fn security_stress_driver() {
    regex_tail_is_scanned();
    fragment_tail_is_scanned();
    nested_decode_budget_boundary();
    many_findings_budget_boundary();
    configuration_selection_boundaries();
    session_retains_large_metadata();
}

fn regex_tail_is_scanned() {
    let input = deep_seed("go_regex").unwrap();
    let (pattern, haystack) = campaign_profile::regex_parts(&input, Profile::Deep).unwrap();
    let engine = engine(std::str::from_utf8(pattern).unwrap());
    let outcome = engine.scan_fragment(&Fragment::new(haystack), &ScanOptions::default());
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(
        outcome.findings()[0].match_range().exact().unwrap().end(),
        haystack.len()
    );
    let (_, small) = campaign_profile::regex_parts(&input, Profile::Smoke).unwrap();
    assert!(
        engine
            .scan_fragment(&Fragment::new(small), &ScanOptions::default())
            .findings()
            .is_empty()
    );
    println!(
        "{}",
        json!({"kind":"security-stress","case":"regex-long-haystack","status":"pass","input_bytes":input.len(),"haystack_bytes":haystack.len(),"smoke_input_bytes":Profile::Smoke.input_limit("go_regex").unwrap(),"last_match_end":haystack.len(),"termination":"complete"})
    );
}

fn session_retains_large_metadata() {
    let input = deep_seed("session").unwrap();
    let (baseline, ignore, body) = campaign_profile::session_parts(&input, Profile::Deep);
    assert!(Baseline::from_go_json(baseline).is_ok());
    assert!(ignore.is_empty());
    let body = &body[1..];
    let candidate = Finding::builder()
        .rule_id("structured")
        .description(body)
        .secret(body)
        .location(Location::new(1, 1, 1, body.len() + 1).unwrap())
        .build()
        .unwrap();
    assert_eq!(candidate.description().len(), body.len());
    let policy = SessionPolicy::builder()
        .baseline(Baseline::from_findings(std::slice::from_ref(&candidate)))
        .build();
    assert_eq!(
        policy.classify(candidate).outcome().suppression_reason(),
        Some(SuppressionReason::Baseline)
    );
    assert!(body.len() > Profile::Smoke.input_limit("session").unwrap());
    println!(
        "{}",
        json!({"kind":"security-stress","case":"session-large-metadata","status":"pass","input_bytes":input.len(),"retained_description_bytes":body.len(),"smoke_input_bytes":Profile::Smoke.input_limit("session").unwrap(),"classification":"baseline-suppressed"})
    );
}

fn fragment_tail_is_scanned() {
    let content = deep_seed("fragment_scan").unwrap();
    let engine = engine("DEEPVALUE");
    let fragment = Fragment::new(content.clone());
    let options = ScanOptions::builder()
        .max_target_bytes(Some(DEEP_INPUT_BYTES))
        .build();
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(100_000)
            .max_finding_records(16),
    );
    let outcome = engine.scan_fragment_controlled(&fragment, &options, &control);
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings().len(), 1);
    let range = outcome.findings()[0]
        .match_range()
        .exact()
        .expect("raw match has an exact range");
    assert_eq!(range.end(), content.len() - 1);
    let smoke = Profile::Smoke.input_limit("fragment_scan").unwrap();
    let truncated = engine.scan_fragment(&Fragment::new(&content[..smoke]), &options);
    assert!(truncated.findings().is_empty());
    println!(
        "{}",
        json!({"kind":"security-stress","case":"core-full-fragment","status":"pass","input_bytes":content.len(),"smoke_input_bytes":smoke,"last_match_end":range.end(),"findings":1,"termination":"complete"})
    );
}

fn nested_decode_budget_boundary() {
    let mut content = b"padding ".repeat(2048);
    content.extend_from_slice(b"marker=VALUE");
    for _ in 0..3 {
        content = base64::engine::general_purpose::STANDARD
            .encode(&content)
            .into_bytes();
    }
    assert!(content.len() > Profile::Smoke.fragment().input_bytes);
    assert!(content.len() <= DEEP_INPUT_BYTES);
    let engine = engine("marker=(VALUE)");
    let fragment = Fragment::new(content);
    let options = ScanOptions::builder().max_decode_depth(3).build();
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_decoded_bytes(1024 * 1024)
            .max_work_units(1_000_000)
            .max_finding_records(16),
    );
    let probe = engine.scan_fragment_controlled(&fragment, &options, &control);
    assert!(probe.is_complete());
    assert_eq!(probe.findings().len(), 1);
    let decoded = probe.usage().decoded_bytes();
    assert!(decoded > Profile::Smoke.fragment().decoded_bytes);
    let exact = engine.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_decoded_bytes(decoded)
                .max_work_units(1_000_000)
                .max_finding_records(16),
        ),
    );
    assert_eq!(exact, probe);
    let below = engine.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_decoded_bytes(decoded - 1)
                .max_work_units(1_000_000)
                .max_finding_records(16),
        ),
    );
    assert!(matches!(
        below.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::DecodedBytes,
            ..
        })
    ));
    assert!(below.usage().decoded_bytes() < decoded);
    println!(
        "{}",
        json!({"kind":"security-stress","case":"core-nested-decode","status":"pass","input_bytes":fragment.content().len(),"smoke_input_bytes":Profile::Smoke.fragment().input_bytes,"decoded_bytes":decoded,"smoke_decoded_bytes":Profile::Smoke.fragment().decoded_bytes,"depth":3,"boundary":"exact-complete-one-less-partial"})
    );
}

fn many_findings_budget_boundary() {
    let count = 8192;
    let content = b"marker=ABCD\n".repeat(count);
    let engine = engine("marker=(ABCD)");
    let fragment = Fragment::new(content);
    let options = ScanOptions::default();
    let scan = |maximum| {
        engine.scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::unlimited().with_budget(
                ScanBudget::unlimited()
                    .max_work_units(1_000_000)
                    .max_finding_records(maximum),
            ),
        )
    };
    let exact = scan(count);
    assert!(exact.is_complete());
    assert_eq!(exact.findings().len(), count);
    assert_eq!(exact.usage().finding_records(), count);
    let below = scan(count - 1);
    assert!(matches!(
        below.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::FindingRecords,
            ..
        })
    ));
    assert!(
        below.findings().is_empty(),
        "partial top-level rule must be rolled back"
    );
    assert_eq!(below.usage().finding_records(), count - 1);
    println!(
        "{}",
        json!({"kind":"security-stress","case":"core-many-findings","status":"pass","input_bytes":fragment.content().len(),"smoke_input_bytes":Profile::Smoke.fragment().input_bytes,"finding_records":count,"smoke_finding_records":Profile::Smoke.fragment().finding_records,"boundary":"exact-complete-one-less-partial"})
    );
}

fn configuration_selection_boundaries() {
    let loader = ConfigLoader::new();
    let small = loader
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "r".into(),
                regex: "x".into(),
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap();
    let limit = CompiledConfig::MAX_SELECTED_RULES;
    let exact = small.select_rules(std::iter::repeat_n("r", limit)).unwrap();
    assert_eq!(exact.ordered_rule_ids().len(), limit);
    assert!(
        small
            .select_rules(std::iter::repeat_n("r", limit + 1))
            .is_err()
    );
    let bytes = CompiledConfig::MAX_SELECTED_BYTES;
    for extra in [0, 1] {
        let config = loader
            .compile(RawConfig {
                rules: vec![RuleSpec {
                    id: "r".into(),
                    regex: "x".into(),
                    description: ".".repeat(bytes - 2 + extra),
                    ..RuleSpec::default()
                }],
                ..RawConfig::default()
            })
            .unwrap();
        let selected = config.select_rules(["r"]);
        assert_eq!(selected.is_ok(), extra == 0);
        if let Err(error) = selected {
            assert!(error.to_string().contains("byte safety limit"));
        }
    }
    println!(
        "{}",
        json!({"kind":"security-stress","case":"core-config-selection","status":"pass","selected_rules":limit,"selected_source_bytes":bytes,"smoke_input_bytes":Profile::Smoke.input_limit("config").unwrap(),"boundary":"inclusive-limit-accepted-one-more-rejected"})
    );
}
