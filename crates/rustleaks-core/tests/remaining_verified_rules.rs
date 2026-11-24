//! Cases for the Mapbox, Vercel and Bitwarden rules.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{Finding, Fragment, ScanOptions};
use rustleaks_core::native::{NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanTermination};
use serde::Deserialize;

#[allow(dead_code)] // Each test uses part of the shared module.
#[path = "support/native_harness.rs"]
mod native_harness;

use native_harness::{
    base64_bytes as bytes, byte_entropy, coordinates, optional_range as range, scan_with_depth,
    shipped_config, without_rules,
};

#[derive(Deserialize)]
struct Fixture {
    selected_rule_ids: Vec<String>,
    primary_names: Vec<String>,
    cases: Vec<Case>,
    source_paths: Vec<String>,
    source_secret_samples: Vec<SecretSample>,
    source_stopwords: Vec<String>,
    source_secret_regexes: Vec<String>,
    predicates: Vec<Predicate>,
}
#[derive(Deserialize)]
#[allow(clippy::struct_field_names)] // Field names mirror fixture JSON keys.
struct Case {
    name: String,
    rule: String,
    input_base64: String,
    path: String,
    decode_depth: usize,
    expected: Vec<Record>,
    #[serde(default)]
    budget_case: bool,
    remove_field_control: Option<RemoveField>,
}
#[derive(Deserialize)]
struct RemoveField {
    field: String,
    count: usize,
}
#[derive(Deserialize)]
struct Record {
    id: String,
    secret_base64: String,
    match_base64: String,
    line_base64: String,
    secret_range: Option<[usize; 2]>,
    match_range: Option<[usize; 2]>,
    location: [usize; 4],
}
#[derive(Deserialize)]
struct SecretSample {
    value: String,
    regex_index: usize,
}
#[derive(Deserialize)]
struct Predicate {
    rule: String,
    algorithm: Option<String>,
    entropy: Entropy,
}
#[derive(Deserialize)]
struct Entropy {
    algorithm: String,
    reject: String,
    threshold: f64,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!("support/remaining_verified_rules.json")).unwrap()
    })
}
fn config() -> &'static CompiledConfig {
    static CONFIG: OnceLock<CompiledConfig> = OnceLock::new();
    CONFIG.get_or_init(shipped_config)
}
fn scan(engine: &Engine, case: &Case) -> Vec<Finding> {
    scan_with_depth(
        engine,
        &bytes(&case.input_base64),
        &case.path,
        case.decode_depth,
    )
}
fn engines() -> &'static BTreeMap<String, Engine> {
    static ENGINES: OnceLock<BTreeMap<String, Engine>> = OnceLock::new();
    ENGINES.get_or_init(|| {
        fixture()
            .selected_rule_ids
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    Engine::builder(config().select_rules([id.as_str()]).unwrap())
                        .build()
                        .unwrap(),
                )
            })
            .collect()
    })
}
fn assert_case(case: &Case, findings: &[Finding]) {
    let mut actual: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id().as_bytes() == case.rule.as_bytes())
        .collect();
    assert_eq!(actual.len(), case.expected.len(), "{}", case.name);
    for e in &case.expected {
        let index = actual
            .iter()
            .position(|f| {
                f.rule_id().as_bytes() == e.id.as_bytes()
                    && f.secret().as_bytes() == bytes(&e.secret_base64)
                    && f.secret_range() == range(e.secret_range)
                    && coordinates(f.location()) == e.location
            })
            .unwrap_or_else(|| panic!("missing expected occurrence: {}", case.name));
        let f = actual.remove(index);
        assert_eq!(
            f.match_text().as_bytes(),
            bytes(&e.match_base64),
            "{}",
            case.name
        );
        assert_eq!(f.match_range(), range(e.match_range), "{}", case.name);
        assert_eq!(f.line().as_bytes(), bytes(&e.line_base64), "{}", case.name);
        assert!(f.required_findings().is_empty(), "{}", case.name);
    }
}
fn selected_rules() -> Vec<toml::Value> {
    let source: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    source["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            fixture()
                .selected_rule_ids
                .iter()
                .any(|id| Some(id.as_str()) == r["id"].as_str())
        })
        .cloned()
        .collect()
}
fn rule(id: &str) -> toml::Value {
    selected_rules()
        .into_iter()
        .find(|r| r["id"].as_str() == Some(id))
        .unwrap()
}
fn custom(rule: toml::Value) -> Engine {
    let id = rule["id"].as_str().unwrap().to_owned();
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(vec![rule]));
    let text = toml::to_string(&source).unwrap();
    let (compiled, _) = NativePolicy::builder()
        .with_pack("remaining-contract-v1", &text)
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(compiled.select_rules([id.as_str()]).unwrap())
        .build()
        .unwrap()
}
fn primary() -> impl Iterator<Item = &'static Case> {
    fixture()
        .cases
        .iter()
        .filter(|c| fixture().primary_names.contains(&c.name))
}

#[test]
fn every_source_case_preserves_exact_report_secret_and_original_byte_geometry() {
    assert_eq!(config().rules().len(), 547);
    assert_eq!(fixture().selected_rule_ids.len(), 3);
    assert_eq!(
        fixture()
            .cases
            .iter()
            .filter(|c| c.name.starts_with("mapbox-")
                && c.decode_depth == 0
                && !c.name.ends_with("-allow-marker"))
            .count(),
        56
    );
    assert_eq!(
        fixture()
            .cases
            .iter()
            .filter(|c| c.name.starts_with("bitwarden-")
                && c.decode_depth == 0
                && !c.name.ends_with("-allow-marker"))
            .count(),
        44
    );
    for case in &fixture().cases {
        assert_case(case, &scan(&engines()[&case.rule], case));
        if let Some(control) = &case.remove_field_control {
            let mut modified = rule(&case.rule);
            assert!(
                modified
                    .as_table_mut()
                    .unwrap()
                    .remove(&control.field)
                    .is_some()
            );
            assert_eq!(
                scan(&custom(modified), case).len(),
                control.count,
                "{} isolated {}",
                case.name,
                control.field
            );
        }
    }
}

#[test]
fn each_primary_case_is_reported_only_by_its_own_rule() {
    let shipped = Engine::builder(config().clone()).build().unwrap();
    let selected = fixture().selected_rule_ids.iter().map(String::as_str);
    let others = Engine::builder(without_rules(config(), selected))
        .build()
        .unwrap();
    for case in primary() {
        assert!(scan(&others, case).is_empty(), "{}", case.name);
        let findings = scan(&shipped, case);
        assert_case(case, &findings);
        assert_eq!(findings.len(), 1, "{}", case.name);
    }
}

#[test]
fn keywords_and_projection_keep_actual_predicates() {
    for p in &fixture().predicates {
        let selected = config().select_rules([p.rule.as_str()]).unwrap();
        let rule = selected.rule(&p.rule).unwrap();
        assert_eq!(rule.native_predicate_algorithm(), p.algorithm.as_deref());
        assert_eq!(
            rule.native_entropy(),
            Some((
                p.entropy.algorithm.as_str(),
                p.entropy.reject.as_str(),
                p.entropy.threshold
            ))
        );
    }
    for case in primary() {
        let mut changed = rule(&case.rule);
        changed["keywords"] = toml::Value::Array(vec![toml::Value::String(
            "missing-synthetic-keyword".into(),
        )]);
        assert!(scan(&custom(changed.clone()), case).is_empty());
        changed["keywords"] = toml::Value::Array(vec![]);
        assert_case(case, &scan(&custom(changed), case));
        let mut changed = rule(&case.rule);
        let allow = toml::from_str::<toml::Value>(
            "description='synthetic rule control'\nregexTarget='secret'\nregexes=['.*']",
        )
        .unwrap();
        changed
            .as_table_mut()
            .unwrap()
            .entry("allowlists")
            .or_insert_with(|| toml::Value::Array(vec![]))
            .as_array_mut()
            .unwrap()
            .push(allow);
        assert!(scan(&custom(changed), case).is_empty());
    }
}

fn ordinary_rule_engine(rule: toml::Value) -> Engine {
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(vec![rule]));
    Engine::builder(
        ConfigLoader::new()
            .load_toml(&toml::to_string(&source).unwrap())
            .unwrap(),
    )
    .build()
    .unwrap()
}
fn local_count(rule: toml::Value, value: &str, path: &str) -> usize {
    let engine = ordinary_rule_engine(rule);
    let input = format!("probe:{value}END");
    let fragment = Fragment::builder(input.as_bytes()).file_path(path).build();
    let result = engine.scan_fragment(&fragment, &ScanOptions::default());
    assert!(result.is_complete());
    result.findings().len()
}
fn source_probe(mut rule: toml::Value) -> toml::Value {
    let t = rule.as_table_mut().unwrap();
    t.remove("entropy");
    t.remove("predicate");
    t.insert(
        "regex".into(),
        toml::Value::String("(?s)probe:(.*)END".into()),
    );
    t.insert("secretGroup".into(), toml::Value::Integer(1));
    t.insert("keywords".into(), toml::Value::Array(vec![]));
    rule
}

#[test]
fn source_filters_are_unmasked_and_bound_to_the_exact_fields() {
    for id in [
        "rustleaks.mapbox-secret-token",
        "rustleaks.vercel-ai-gateway-key",
    ] {
        let source = source_probe(rule(id));
        assert_eq!(
            source["allowlists"][0]["regexes"].as_array().unwrap().len(),
            13
        );
        assert_eq!(
            source["allowlists"][1]["paths"].as_array().unwrap().len(),
            23
        );
        for (index, sample) in fixture().source_secret_samples.iter().enumerate() {
            assert_eq!(
                local_count(source.clone(), &sample.value, "src/settings.txt"),
                0,
                "{id} sample {index}"
            );
            let mut changed = source.clone();
            let regexes = changed["allowlists"][0]["regexes"].as_array_mut().unwrap();
            assert_eq!(
                regexes[sample.regex_index].as_str(),
                Some(fixture().source_secret_regexes[sample.regex_index].as_str())
            );
            regexes.remove(sample.regex_index);
            assert_eq!(
                local_count(changed, &sample.value, "src/settings.txt"),
                1,
                "{id} sample {index}"
            );
        }
        for value in &fixture().source_stopwords {
            assert_eq!(local_count(source.clone(), value, "src/settings.txt"), 0);
            let mut changed = source.clone();
            changed["allowlists"][0]
                .as_table_mut()
                .unwrap()
                .remove("stopwords");
            assert_eq!(local_count(changed, value, "src/settings.txt"), 1);
        }
        assert_eq!(
            local_count(source, "DatabaseXrefactorlog", "src/settings.txt"),
            1
        );
    }
}

#[test]
fn actual_rules_keep_every_source_path_filter() {
    assert_eq!(fixture().source_paths.len(), 23);
    for case in primary().filter(|c| c.rule != "rustleaks.bitwarden-cli-client-secret") {
        let probe = source_probe(rule(&case.rule));
        for path in &fixture().source_paths {
            assert_eq!(local_count(probe.clone(), "Q7z9b2N4c6", path), 0);
            let mut changed = probe.clone();
            changed["allowlists"].as_array_mut().unwrap().remove(1);
            assert_eq!(local_count(changed, "Q7z9b2N4c6", path), 1);
            let raw = bytes(&case.input_base64);
            let fragment = Fragment::builder(raw.as_slice())
                .file_path(path.as_str())
                .build();
            let out = engines()[&case.rule].scan_fragment(&fragment, &ScanOptions::default());
            assert!(out.is_complete());
            assert!(out.findings().is_empty());
        }
    }
}

#[test]
fn real_secret_entropy_comparators_keep_equality_behavior() {
    for case in primary() {
        let entropy = byte_entropy(&bytes(&case.expected[0].secret_base64));
        let inclusive = case.rule == "rustleaks.bitwarden-cli-client-secret";
        for (threshold, count) in [
            (entropy.next_down(), 1),
            (entropy, usize::from(!inclusive)),
            (entropy.next_up(), 0),
        ] {
            let mut changed = rule(&case.rule);
            changed["entropy"]["threshold"] = toml::Value::Float(threshold);
            assert_eq!(
                scan(&custom(changed), case).len(),
                count,
                "{} {threshold}",
                case.name
            );
        }
    }
}

#[test]
fn actual_rules_keep_controlled_resource_contracts() {
    for case in fixture()
        .cases
        .iter()
        .filter(|c| c.budget_case || fixture().primary_names.contains(&c.name))
    {
        let input = bytes(&case.input_base64);
        let fragment = Fragment::builder(input.as_slice())
            .file_path(case.path.as_str())
            .build();
        let engine = &engines()[&case.rule];
        let options = ScanOptions::builder()
            .max_decode_depth(case.decode_depth)
            .build();
        let complete =
            engine.scan_fragment_controlled(&fragment, &options, &ScanControl::unlimited());
        assert!(complete.is_complete());
        assert_case(case, complete.findings());
        let exact = ScanBudget::unlimited().max_work_units(complete.usage().work_units());
        let repeated = engine.scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::unlimited().with_budget(exact),
        );
        assert!(repeated.is_complete());
        assert_case(case, repeated.findings());
        for budget in [
            ScanBudget::unlimited().max_work_units(0),
            ScanBudget::unlimited().max_collected_spans(0),
            ScanBudget::unlimited().max_finding_records(0),
            ScanBudget::unlimited().max_finding_payload_bytes(1),
        ] {
            let outcome = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!outcome.is_complete(), "{}", case.name);
            assert!(outcome.findings().is_empty(), "{}", case.name);
        }
        let cancel = AtomicBool::new(true);
        let outcome = engine.scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::cancellable(&cancel),
        );
        assert_eq!(outcome.termination(), Some(&ScanTermination::Cancelled));
        assert!(outcome.findings().is_empty());
    }
}
