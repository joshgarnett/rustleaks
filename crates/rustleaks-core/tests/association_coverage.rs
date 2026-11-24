//! Cases for the association rules (a secret with a nearby helper value) and
//! the Packagist rules.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{Finding, FindingRange, Fragment, RequiredFinding, ScanOptions};
use rustleaks_core::native::{NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
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
    graphs: Vec<Graph>,
    primary: Vec<Case>,
    cases: Vec<Case>,
    buffers: Vec<Case>,
    unicode_invalid: Vec<Case>,
    packagist: Vec<Case>,
    source_bytes: Vec<Case>,
    helper_entropy: Vec<HelperEntropy>,
    source_filter_samples: Vec<String>,
    source_paths: Vec<String>,
    entropy: Vec<Entropy>,
}
#[derive(Deserialize)]
struct Graph {
    source_id: String,
    parent: String,
    helpers: Vec<String>,
    windows: Vec<String>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    source_id: String,
    rule: String,
    input_base64: String,
    path: String,
    decode_depth: usize,
    expected: Vec<Record>,
    #[serde(default)]
    custom_allowlist: bool,
    #[serde(default)]
    finite_budgets: bool,
    control: Option<Control>,
}
#[derive(Deserialize)]
struct Control {
    rule: String,
    field: String,
    count: usize,
    regex: Option<String>,
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
    nested: Vec<Record>,
}
#[derive(Deserialize)]
struct Entropy {
    rule: String,
    algorithm: String,
    reject: String,
    threshold: f64,
}
#[derive(Deserialize)]
struct Predicate {
    algorithm: String,
    reject: String,
    threshold: f64,
}
#[derive(Deserialize)]
struct HelperEntropy {
    parent: String,
    helper: String,
    input_base64: String,
    secret_base64: String,
    predicate: Predicate,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!("support/association_coverage.json")).unwrap()
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
fn graph_engines() -> &'static BTreeMap<String, Engine> {
    static ENGINES: OnceLock<BTreeMap<String, Engine>> = OnceLock::new();
    ENGINES.get_or_init(|| {
        fixture()
            .graphs
            .iter()
            .map(|g| {
                let ids =
                    std::iter::once(g.parent.as_str()).chain(g.helpers.iter().map(String::as_str));
                (
                    g.source_id.clone(),
                    Engine::builder(config().select_rules(ids).unwrap())
                        .build()
                        .unwrap(),
                )
            })
            .collect()
    })
}
fn shipped() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::builder(config().clone()).build().unwrap())
}
/// The shipped rules without this file's selected rules.
fn without_selected_rules() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let selected = fixture().selected_rule_ids.iter().map(String::as_str);
        Engine::builder(without_rules(config(), selected))
            .build()
            .unwrap()
    })
}
fn packagist() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(
            config()
                .select_rules([
                    "rustleaks.packagist-api-secret",
                    "rustleaks.packagist-api-key",
                ])
                .unwrap(),
        )
        .build()
        .unwrap()
    })
}
fn parents<'a>(findings: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|f| f.rule_id().as_bytes() == id.as_bytes())
        .collect()
}
fn assert_support(expected: &Record, actual: &RequiredFinding, name: &str) {
    assert_eq!(
        actual.rule_id().as_bytes(),
        expected.id.as_bytes(),
        "{name}"
    );
    assert_eq!(
        actual.secret().as_bytes(),
        bytes(&expected.secret_base64),
        "{name}"
    );
    assert_eq!(
        actual.match_text().as_bytes(),
        bytes(&expected.match_base64),
        "{name}"
    );
    assert_eq!(
        actual.line().as_bytes(),
        bytes(&expected.line_base64),
        "{name}"
    );
    assert_eq!(
        actual.secret_range(),
        range(expected.secret_range),
        "{name}"
    );
    assert_eq!(actual.match_range(), range(expected.match_range), "{name}");
    assert_eq!(coordinates(actual.location()), expected.location, "{name}");
}
fn assert_finding(expected: &Record, actual: &Finding, name: &str) {
    assert_eq!(
        actual.rule_id().as_bytes(),
        expected.id.as_bytes(),
        "{name}"
    );
    assert_eq!(
        actual.secret().as_bytes(),
        bytes(&expected.secret_base64),
        "{name}"
    );
    assert_eq!(
        actual.match_text().as_bytes(),
        bytes(&expected.match_base64),
        "{name}"
    );
    assert_eq!(
        actual.line().as_bytes(),
        bytes(&expected.line_base64),
        "{name}"
    );
    assert_eq!(
        actual.secret_range(),
        range(expected.secret_range),
        "{name}"
    );
    assert_eq!(actual.match_range(), range(expected.match_range), "{name}");
    assert_eq!(coordinates(actual.location()), expected.location, "{name}");
    assert_eq!(
        actual.required_findings().len(),
        expected.nested.len(),
        "{name}"
    );
    for (expected, actual) in expected.nested.iter().zip(actual.required_findings()) {
        assert_support(expected, actual, name);
    }
}
fn assert_case(case: &Case, findings: &[Finding]) {
    let mut actual: Vec<_> = if case.rule.is_empty() {
        findings
            .iter()
            .filter(|f| {
                [
                    b"rustleaks.packagist-api-secret".as_slice(),
                    b"rustleaks.packagist-api-key".as_slice(),
                ]
                .contains(&f.rule_id().as_bytes())
            })
            .collect()
    } else {
        parents(findings, &case.rule)
    };
    assert_eq!(actual.len(), case.expected.len(), "{}", case.name);
    for expected in &case.expected {
        let index = actual
            .iter()
            .position(|f| {
                f.rule_id().as_bytes() == expected.id.as_bytes()
                    && f.secret().as_bytes() == bytes(&expected.secret_base64)
                    && f.secret_range() == range(expected.secret_range)
                    && coordinates(f.location()) == expected.location
            })
            .unwrap_or_else(|| panic!("missing expected occurrence: {}", case.name));
        assert_finding(expected, actual.remove(index), &case.name);
    }
    assert!(
        findings.iter().all(|f| !f
            .rule_id()
            .as_bytes()
            .starts_with(b"rustleaks.association.helper.")),
        "{}",
        case.name
    );
}

#[test]
fn every_concrete_family_case_checks_independent_geometry() {
    assert_eq!(fixture().selected_rule_ids.len(), 58);
    assert_eq!(fixture().graphs.len(), 26);
    assert_eq!(fixture().primary.len(), 26);
    assert_eq!(fixture().source_paths.len(), 23);
    for case in fixture().cases.iter().chain(&fixture().unicode_invalid) {
        assert_case(case, &scan(&graph_engines()[&case.source_id], case));
        if let Some(control) = &case.control {
            let mut rules = selected_rules();
            let rule = rules
                .iter_mut()
                .find(|r| r["id"].as_str() == Some(control.rule.as_str()))
                .unwrap();
            if let Some(regex) = &control.regex {
                let mut removed = 0;
                for allowlist in rule["allowlists"].as_array_mut().unwrap() {
                    if let Some(regexes) = allowlist
                        .get_mut("regexes")
                        .and_then(toml::Value::as_array_mut)
                    {
                        let before = regexes.len();
                        regexes.retain(|value| value.as_str() != Some(regex.as_str()));
                        removed += before - regexes.len();
                    }
                }
                assert_eq!(removed, 1);
            } else {
                rule.as_table_mut().unwrap().remove(&control.field);
            }
            let graph = fixture()
                .graphs
                .iter()
                .find(|g| g.source_id == case.source_id)
                .unwrap();
            let ids = std::iter::once(graph.parent.as_str())
                .chain(graph.helpers.iter().map(String::as_str));
            assert_eq!(
                scan(&custom(rules, ids), case).len(),
                control.count,
                "{} isolated {}",
                case.name,
                control.field
            );
        }
    }
    for expected in &fixture().entropy {
        assert_eq!(
            config().rule(&expected.rule).unwrap().native_entropy(),
            Some((
                expected.algorithm.as_str(),
                expected.reject.as_str(),
                expected.threshold
            ))
        );
    }
}

#[test]
fn exact_source_byte_patterns_preserve_bridges_bounds_guards_and_capture_policy() {
    let rules = selected_rules();
    let associations: Vec<_> = rules
        .iter()
        .filter(|r| {
            r["id"]
                .as_str()
                .unwrap()
                .starts_with("rustleaks.association.")
        })
        .collect();
    assert_eq!(associations.len(), 56);
    for rule in associations {
        assert_eq!(rule["regex"]["dialect"].as_str(), Some("bytes-v1"));
        assert!(
            rule["regex"]["pattern"]
                .as_str()
                .is_some_and(|pattern| !pattern.is_empty())
        );
    }
    assert_eq!(fixture().source_bytes.len(), 182);
    for case in &fixture().source_bytes {
        let selected = &graph_engines()[&case.source_id];
        for engine in [selected, shipped()] {
            assert_case(case, &scan(engine, case));
        }
        let input = bytes(&case.input_base64);
        let fragment = Fragment::builder(input.as_slice())
            .file_path(case.path.as_str())
            .build();
        let result = selected.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_normalization_bytes(0)),
        );
        assert!(result.is_complete(), "{}", case.name);
        assert_case(case, result.findings());
    }
}

#[test]
fn full_match_windows_multiline_keywords_and_input_buffers_keep_exact_records() {
    assert_eq!(fixture().buffers.len(), 206);
    for case in &fixture().buffers {
        for engine in [&graph_engines()[&case.source_id], shipped()] {
            assert_case(case, &scan(engine, case));
        }
    }
}

#[test]
fn packagist_roles_are_independent_bounded_occurrences_without_pair_selection() {
    assert_eq!(fixture().packagist.len(), 81);
    for case in &fixture().packagist {
        for engine in [packagist(), shipped()] {
            assert_case(case, &scan(engine, case));
        }
        if case.custom_allowlist {
            let expected = &case.expected[0];
            let mut rules = selected_rules();
            let rule = rules
                .iter_mut()
                .find(|r| r["id"].as_str() == Some(expected.id.as_str()))
                .unwrap();
            rule.as_table_mut().unwrap().insert(
                "allowlists".into(),
                toml::Value::Array(vec![
                    toml::from_str(&format!(
                        "regexTarget = 'secret'\nstopWords = [{}]",
                        serde_json::to_string(
                            &String::from_utf8(bytes(&expected.secret_base64)).unwrap()
                        )
                        .unwrap()
                    ))
                    .unwrap(),
                ]),
            );
            assert!(
                scan(
                    &custom(
                        rules,
                        [
                            "rustleaks.packagist-api-secret",
                            "rustleaks.packagist-api-key"
                        ]
                    ),
                    case
                )
                .is_empty()
            );
        }
        if case.finite_budgets {
            check_resource_limits(packagist(), case);
        }
    }
}

#[test]
fn shipped_rules_keep_what_other_rules_find() {
    for case in fixture().primary.iter().chain(
        fixture()
            .packagist
            .iter()
            .filter(|c| c.name.ends_with("/standalone")),
    ) {
        let before = scan(without_selected_rules(), case);
        let after = scan(shipped(), case);
        assert_case(case, &after);
        for f in &before {
            // Generic findings can be suppressed by an exact specific rule.
            // Other rules keep their exact occurrence and bytes.
            if f.rule_id().as_bytes() == b"generic-api-key" {
                continue;
            }
            assert!(
                after.iter().any(|g| g.rule_id() == f.rule_id()
                    && g.secret() == f.secret()
                    && g.match_text() == f.match_text()
                    && g.secret_range() == f.secret_range()
                    && g.match_range() == f.match_range()
                    && g.location() == f.location()),
                "{}",
                case.name
            );
        }
    }
}

fn selected_rules() -> Vec<toml::Value> {
    static RULES: OnceLock<Vec<toml::Value>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            let value: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
            value["rules"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|rule| {
                    fixture()
                        .selected_rule_ids
                        .iter()
                        .any(|id| Some(id.as_str()) == rule["id"].as_str())
                })
                .cloned()
                .collect()
        })
        .clone()
}
fn custom<'a>(mut rules: Vec<toml::Value>, ids: impl IntoIterator<Item = &'a str>) -> Engine {
    let ids: Vec<_> = ids.into_iter().collect();
    // Mutation cases select one complete graph. Exclude unrelated native
    // rules before compilation, retaining original IDs, edges and fields.
    // NativePolicy still supplies the same embedded default/global policy.
    rules.retain(|rule| ids.contains(&rule["id"].as_str().unwrap()));
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(rules));
    let text = toml::to_string(&source).unwrap();
    let (compiled, _) = NativePolicy::builder()
        .with_pack("association-contract-v1", &text)
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(compiled.select_rules(ids).unwrap())
        .build()
        .unwrap()
}
/// Builds mutation variants with fewer embedded default-policy compilations.
///
/// Each variant keeps only its own complete graph, as in [`custom`]. Variants
/// that share a compilation have disjoint rule IDs, so selecting a variant's
/// IDs yields an engine with exactly that variant's rules beside the same
/// embedded default/global policy. The projection is checked against
/// [`custom`] by `batched_mutation_compilation_matches_isolated_compilation`.
fn custom_batch(variants: Vec<(Vec<toml::Value>, Vec<&str>)>) -> Vec<Engine> {
    struct Group<'a> {
        ids: BTreeSet<String>,
        bytes: usize,
        rules: Vec<toml::Value>,
        members: Vec<(usize, Vec<&'a str>)>,
    }
    let count = variants.len();
    let mut groups: Vec<Group<'_>> = Vec::new();
    for (index, (mut rules, ids)) in variants.into_iter().enumerate() {
        rules.retain(|rule| ids.contains(&rule["id"].as_str().unwrap()));
        let rule_ids: BTreeSet<String> = rules
            .iter()
            .map(|rule| rule["id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(rule_ids.len(), rules.len());
        let mut source = toml::Table::new();
        source.insert("rules".into(), toml::Value::Array(rules.clone()));
        let bytes = toml::to_string(&source).unwrap().len();
        // Half the aggregate limit leaves room for combined table framing.
        let group = groups.iter_mut().find(|group| {
            group.ids.is_disjoint(&rule_ids)
                && group.bytes + bytes <= NativePolicy::MAX_PACK_BYTES / 2
                && group.ids.len() + rule_ids.len() <= NativePolicy::MAX_NATIVE_RULES
        });
        let group = if let Some(group) = group {
            group
        } else {
            groups.push(Group {
                ids: BTreeSet::new(),
                bytes: 0,
                rules: Vec::new(),
                members: Vec::new(),
            });
            groups.last_mut().unwrap()
        };
        group.ids.extend(rule_ids);
        group.bytes += bytes;
        group.rules.extend(rules);
        group.members.push((index, ids));
    }
    let mut engines: Vec<Option<Engine>> = (0..count).map(|_| None).collect();
    for group in groups {
        let mut source = toml::Table::new();
        source.insert("rules".into(), toml::Value::Array(group.rules));
        let text = toml::to_string(&source).unwrap();
        let (compiled, _) = NativePolicy::builder()
            .with_pack("association-contract-v1", &text)
            .unwrap()
            .compile()
            .unwrap();
        for (index, ids) in group.members {
            engines[index] = Some(
                Engine::builder(compiled.select_rules(ids).unwrap())
                    .build()
                    .unwrap(),
            );
        }
    }
    engines.into_iter().map(Option::unwrap).collect()
}
fn graph_ids(graph: &Graph) -> Vec<&str> {
    std::iter::once(graph.parent.as_str())
        .chain(graph.helpers.iter().map(String::as_str))
        .collect()
}
fn primary(graph: &Graph) -> &Case {
    fixture()
        .primary
        .iter()
        .find(|c| c.source_id == graph.source_id)
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)] // One graph loop keeps every selection control beside its case.
fn every_graph_keeps_its_helpers_under_selection_and_accounts_for_support_multiplicity() {
    assert!(ConfigLoader::new().load_toml(PROVIDER_RULES_V1).is_err());
    for graph in &fixture().graphs {
        assert_eq!(graph.helpers.len(), graph.windows.len());
        let case = primary(graph);
        let ids: Vec<_> = std::iter::once(graph.parent.as_str())
            .chain(graph.helpers.iter().map(String::as_str))
            .collect();
        // A selected parent keeps the helpers that are not selected, as rules
        // that do not report.
        for omitted in &graph.helpers {
            let selected = config()
                .select_rules(ids.iter().copied().filter(|id| *id != omitted))
                .unwrap();
            assert!(selected.rule(omitted).unwrap().skip_report());
            let engine = Engine::builder(selected).build().unwrap();
            assert_case(case, &scan(&engine, case));
        }
        let engine = Engine::builder(config().select_rules([graph.parent.as_str()]).unwrap())
            .build()
            .unwrap();
        assert_case(case, &scan(&engine, case));
        let engine = Engine::builder(
            config()
                .select_rules(graph.helpers.iter().map(String::as_str))
                .unwrap(),
        )
        .build()
        .unwrap();
        assert!(scan(&engine, case).is_empty(), "{}", case.name);
        assert_case(case, &scan(&graph_engines()[&graph.source_id], case));
        let mut repeated = bytes(&case.input_base64);
        for helper in &case.expected[0].nested {
            let matched = bytes(&helper.match_base64);
            for _ in 0..7 {
                repeated.extend_from_slice(b" ; ");
                repeated.extend_from_slice(&matched);
            }
        }
        let fragment = Fragment::builder(repeated.as_slice())
            .file_path(case.path.as_str())
            .build();
        let result =
            graph_engines()[&graph.source_id].scan_fragment(&fragment, &ScanOptions::default());
        assert!(result.is_complete(), "{}", case.name);
        let findings = parents(result.findings(), &graph.parent);
        assert_eq!(findings.len(), 1, "{}", case.name);
        let supports = findings[0].required_findings();
        assert_eq!(supports.len(), graph.helpers.len() * 8, "{}", case.name);
        for helper in &graph.helpers {
            let found: Vec<_> = supports
                .iter()
                .filter(|f| f.rule_id().as_bytes() == helper.as_bytes())
                .collect();
            assert_eq!(found.len(), 8, "{} {helper}", case.name);
            let mut last_start = None;
            for support in found {
                let FindingRange::Exact(secret_range) = support.secret_range() else {
                    panic!("raw support range missing");
                };
                let FindingRange::Exact(match_range) = support.match_range() else {
                    panic!("raw support match range missing");
                };
                assert_eq!(
                    &repeated[secret_range.start()..secret_range.end()],
                    support.secret().as_bytes()
                );
                assert_eq!(
                    &repeated[match_range.start()..match_range.end()],
                    support.match_text().as_bytes()
                );
                assert!(last_start.is_none_or(|previous| previous < match_range.start()));
                last_start = Some(match_range.start());
            }
        }
        // Parent plus admitted helpers fit. Copying supports into a parent
        // consumes additional record capacity and must fail atomically.
        let budget = ScanBudget::unlimited().max_finding_records(supports.len() + 1);
        let limited = graph_engines()[&graph.source_id].scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(budget),
        );
        assert!(!limited.is_complete(), "{}", case.name);
        assert!(limited.findings().is_empty(), "{}", case.name);
        let mut stress = bytes(&case.input_base64);
        for helper in &case.expected[0].nested {
            let matched = bytes(&helper.match_base64);
            for _ in 0..1000 {
                stress.extend_from_slice(b" ; ");
                stress.extend_from_slice(&matched);
            }
        }
        let fragment = Fragment::builder(stress.as_slice())
            .file_path(case.path.as_str())
            .build();
        for budget in [
            ScanBudget::unlimited().max_work_units(1),
            ScanBudget::unlimited().max_collected_spans(1),
            ScanBudget::unlimited().max_finding_records(1),
            ScanBudget::unlimited().max_finding_payload_bytes(1),
        ] {
            let limited = graph_engines()[&graph.source_id].scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!limited.is_complete(), "{}", case.name);
            assert!(limited.findings().is_empty(), "{}", case.name);
        }
    }
}

fn check_resource_limits(engine: &Engine, case: &Case) {
    let input = bytes(&case.input_base64);
    let fragment = Fragment::builder(input.as_slice())
        .file_path(case.path.as_str())
        .build();
    for budget in [
        ScanBudget::unlimited().max_work_units(0),
        ScanBudget::unlimited().max_collected_spans(0),
        ScanBudget::unlimited().max_finding_records(0),
        ScanBudget::unlimited().max_finding_payload_bytes(1),
    ] {
        let result = engine.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(budget),
        );
        assert!(!result.is_complete(), "{}", case.name);
        assert!(result.findings().is_empty(), "{}", case.name);
    }
    for (maximum, expected) in [(input.len() - 1, 0), (input.len(), case.expected.len())] {
        let result = engine.scan_fragment(
            &fragment,
            &ScanOptions::builder()
                .max_target_bytes(Some(maximum))
                .build(),
        );
        assert!(result.is_complete());
        assert_eq!(result.findings().len(), expected, "{}", case.name);
    }
}
#[test]
fn every_graph_enforces_independent_resource_limits() {
    for case in &fixture().primary {
        check_resource_limits(&graph_engines()[&case.source_id], case);
    }
    for case in fixture()
        .cases
        .iter()
        .filter(|c| c.name.contains("/source-length-"))
    {
        let engine = &graph_engines()[&case.source_id];
        if case.expected.is_empty() {
            let input = bytes(&case.input_base64);
            let result = engine.scan_fragment_controlled(
                &Fragment::new(input.as_slice()),
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
            );
            assert!(!result.is_complete(), "{}", case.name);
            assert!(result.findings().is_empty());
        } else {
            check_resource_limits(engine, case);
        }
    }
}

#[test]
fn real_graph_source_filters_and_keywords_gate_each_component() {
    let mut checks = Vec::new();
    let mut variants = Vec::new();
    for graph in &fixture().graphs {
        let case = primary(graph);
        let ids: Vec<_> = std::iter::once(graph.parent.as_str())
            .chain(graph.helpers.iter().map(String::as_str))
            .collect();
        for record in std::iter::once(&case.expected[0]).chain(&case.expected[0].nested) {
            for kind in ["keyword", "path", "secret", "match", "commit"] {
                let mut rules = selected_rules();
                let rule = rules
                    .iter_mut()
                    .find(|r| r["id"].as_str() == Some(record.id.as_str()))
                    .unwrap();
                let table = rule.as_table_mut().unwrap();
                if kind == "keyword" {
                    table.insert(
                        "keywords".into(),
                        toml::Value::Array(vec![toml::Value::String(
                            "absent-association-keyword-97".into(),
                        )]),
                    );
                } else if kind == "path" {
                    table.insert(
                        "path".into(),
                        toml::Value::String("^absent-association-path-97$".into()),
                    );
                } else {
                    let value = if kind == "commit" {
                        "commits = ['fixture-association-commit']".to_owned()
                    } else {
                        let target = if kind == "secret" {
                            &record.secret_base64
                        } else {
                            &record.match_base64
                        };
                        let token = String::from_utf8(bytes(target)).unwrap();
                        if kind == "secret" {
                            format!(
                                "regexTarget = 'secret'\nstopWords = [{}]",
                                serde_json::to_string(&token).unwrap()
                            )
                        } else {
                            format!(
                                "regexTarget = 'match'\nregexes = [{}]",
                                serde_json::to_string(&regex_literal(&token)).unwrap()
                            )
                        }
                    };
                    table
                        .entry("allowlists")
                        .or_insert(toml::Value::Array(vec![]))
                        .as_array_mut()
                        .unwrap()
                        .push(toml::from_str(&value).unwrap());
                }
                variants.push((rules, ids.clone()));
                checks.push((case, record, kind));
            }
        }
    }
    for ((case, record, kind), engine) in checks.into_iter().zip(custom_batch(variants)) {
        if kind == "commit" {
            let input = bytes(&case.input_base64);
            for (commit, count) in [
                ("fixture-association-commit", 0),
                ("fixture-association-neighbor", 1),
            ] {
                let fragment = Fragment::builder(input.as_slice())
                    .file_path(case.path.as_str())
                    .commit(commit)
                    .build();
                let result = engine.scan_fragment(&fragment, &ScanOptions::default());
                assert!(result.is_complete());
                assert_eq!(
                    result.findings().len(),
                    count,
                    "{} {}",
                    case.name,
                    record.id
                );
            }
        } else {
            assert!(
                scan(&engine, case).is_empty(),
                "{} {} {kind}",
                case.name,
                record.id
            );
        }
    }
}
fn regex_literal(value: &str) -> String {
    let mut out = String::from("^");
    for ch in value.chars() {
        if r"\.+*?()|[]{}^$".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('$');
    out
}

#[test]
fn source_filters_are_preserved_and_exercised_without_detector_language_masking() {
    for mut rule in selected_rules().into_iter().filter(|r| {
        r["id"]
            .as_str()
            .unwrap()
            .starts_with("rustleaks.association.")
            && r["allowlists"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.get("regexTarget").and_then(toml::Value::as_str) == Some("secret"))
    }) {
        let id = rule["id"].as_str().unwrap().to_owned();
        let table = rule.as_table_mut().unwrap();
        table.remove("required");
        table.remove("entropy");
        table.insert("skipReport".into(), toml::Value::Boolean(false));
        table.insert(
            "regex".into(),
            toml::Value::String("(?s)probe:(.*)END".into()),
        );
        table.insert("secretGroup".into(), toml::Value::Integer(1));
        table.insert("keywords".into(), toml::Value::Array(vec![]));
        let mut source = toml::Table::new();
        source.insert("rules".into(), toml::Value::Array(vec![rule]));
        let config = ConfigLoader::new()
            .load_toml(&toml::to_string(&source).unwrap())
            .unwrap();
        let engine = Engine::builder(config).build().unwrap();
        for (value, expected) in fixture()
            .source_filter_samples
            .iter()
            .map(|s| (s.as_str(), 0))
            .chain(std::iter::once(("Q7z9b2N4c6", 1)))
        {
            let input = format!("probe:{value}END");
            let result =
                engine.scan_fragment(&Fragment::new(input.as_bytes()), &ScanOptions::default());
            assert!(result.is_complete());
            assert_eq!(result.findings().len(), expected, "{id} {value}");
        }
    }
}

#[test]
fn source_path_predicates_are_isolated_from_embedded_global_policy() {
    let mut checked = 0;
    for mut rule in selected_rules().into_iter().filter(|r| {
        r["id"]
            .as_str()
            .unwrap()
            .starts_with("rustleaks.association.")
    }) {
        let id = rule["id"].as_str().unwrap().to_owned();
        let table = rule.as_table_mut().unwrap();
        table.remove("required");
        table.remove("entropy");
        table.insert("skipReport".into(), toml::Value::Boolean(false));
        table.insert(
            "regex".into(),
            toml::Value::String("probe:(Q7z9b2N4c6)".into()),
        );
        table.insert("secretGroup".into(), toml::Value::Integer(1));
        table.insert("keywords".into(), toml::Value::Array(vec![]));
        let paths = table.get_mut("allowlists").unwrap().as_array_mut().unwrap();
        paths.retain(|allowlist| allowlist.get("paths").is_some());
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0]["paths"].as_array().unwrap().len(), 23);
        let mut source = toml::Table::new();
        source.insert("rules".into(), toml::Value::Array(vec![rule]));
        // Ordinary ConfigLoader starts with this isolated source, with neither
        // extend.useDefault nor a top-level inherited allowlist.
        let config = ConfigLoader::new()
            .load_toml(&toml::to_string(&source).unwrap())
            .unwrap();
        let engine = Engine::builder(config).build().unwrap();
        assert_eq!(engine.config().rules().len(), 1);
        let paths = fixture()
            .source_paths
            .iter()
            .map(|path| (path.as_str(), 0))
            .chain([
                ("bun.lock", 0),
                ("bun.lockb", 0),
                ("src/bun.lock", 0),
                ("src/bun.lockb", 0),
                ("src/settings.txt", 1),
                ("bun.lockx", 1),
                ("src/bun.lockx", 1),
            ]);
        for (path, count) in paths {
            let fragment = Fragment::builder(b"probe:Q7z9b2N4c6".as_slice())
                .file_path(path)
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert_eq!(result.findings().len(), count, "{id} {path}");
        }
        checked += 1;
    }
    assert_eq!(checked, 56);
}

#[test]
fn actual_helper_captures_preserve_strict_and_inclusive_entropy_comparators() {
    assert_eq!(fixture().helper_entropy.len(), 26);
    let mut checks = Vec::new();
    let mut variants = Vec::new();
    for case in &fixture().helper_entropy {
        let graph = fixture()
            .graphs
            .iter()
            .find(|g| g.parent == case.parent)
            .unwrap();
        let ids: Vec<_> = std::iter::once(graph.parent.as_str())
            .chain(graph.helpers.iter().map(String::as_str))
            .collect();
        assert_eq!(
            config().rule(&case.helper).unwrap().native_entropy(),
            Some((
                case.predicate.algorithm.as_str(),
                case.predicate.reject.as_str(),
                case.predicate.threshold
            ))
        );
        let input = bytes(&case.input_base64);
        let entropy = byte_entropy(&bytes(&case.secret_base64));
        for (threshold, expected) in [
            (entropy.next_down(), 1),
            (entropy, usize::from(case.predicate.reject == "lt")),
            (entropy.next_up(), 0),
        ] {
            let mut rules = selected_rules();
            let rule = rules
                .iter_mut()
                .find(|r| r["id"].as_str() == Some(case.helper.as_str()))
                .unwrap();
            rule["entropy"]["threshold"] = toml::Value::Float(threshold);
            variants.push((rules, ids.clone()));
            checks.push((case, input.clone(), threshold, expected));
        }
    }
    for ((case, input, threshold, expected), engine) in
        checks.into_iter().zip(custom_batch(variants))
    {
        let result =
            engine.scan_fragment(&Fragment::new(input.as_slice()), &ScanOptions::default());
        assert!(result.is_complete());
        assert_eq!(
            result.findings().len(),
            expected,
            "{} {threshold}",
            case.helper
        );
    }
}

#[test]
fn batched_mutation_compilation_matches_isolated_compilation() {
    let graphs = &fixture().graphs;
    let unchanged: Vec<_> = graphs
        .iter()
        .map(|graph| (selected_rules(), graph_ids(graph)))
        .collect();
    for (graph, engine) in graphs.iter().zip(custom_batch(unchanged)) {
        // The shipped configuration also records that it is the embedded
        // default, so compare its parts and not its origin.
        let batched = engine.config();
        let shipped = config().select_rules(graph_ids(graph)).unwrap();
        assert_eq!(batched.rules(), shipped.rules(), "{}", graph.source_id);
        assert_eq!(
            batched.ordered_rule_ids(),
            shipped.ordered_rule_ids(),
            "{}",
            graph.source_id
        );
        assert_eq!(
            batched.keywords(),
            shipped.keywords(),
            "{}",
            graph.source_id
        );
        assert_eq!(
            batched.allowlists(),
            shipped.allowlists(),
            "{}",
            graph.source_id
        );
    }
    // Mutate every graph parent in one shared compilation and compare the
    // first and last projections with isolated compilations of their variant.
    let changed = |graph: &Graph| {
        let mut rules = selected_rules();
        let rule = rules
            .iter_mut()
            .find(|r| r["id"].as_str() == Some(graph.parent.as_str()))
            .unwrap();
        rule.as_table_mut().unwrap().insert(
            "keywords".into(),
            toml::Value::Array(vec![toml::Value::String(
                "absent-association-keyword-97".into(),
            )]),
        );
        rules
    };
    let engines = custom_batch(
        graphs
            .iter()
            .map(|graph| (changed(graph), graph_ids(graph)))
            .collect(),
    );
    for index in [0, graphs.len() - 1] {
        let graph = &graphs[index];
        assert_eq!(
            engines[index].config(),
            custom(changed(graph), graph_ids(graph)).config(),
            "{}",
            graph.source_id
        );
    }
}

#[test]
fn parent_reports_omit_supports_while_core_redaction_preserves_its_contract() {
    for case in &fixture().primary {
        let findings = scan(&graph_engines()[&case.source_id], case);
        let finding = &findings[0];
        let serialized = serde_json::to_value(finding).unwrap();
        assert!(
            serialized
                .as_object()
                .unwrap()
                .keys()
                .all(|key| !key.to_ascii_lowercase().contains("required"))
        );
        let redacted = finding.clone().redacted(100);
        assert_eq!(redacted.required_findings(), finding.required_findings());
        let removed = finding.clone().without_detected_secrets();
        for (support, cleaned) in finding
            .required_findings()
            .iter()
            .zip(removed.required_findings())
        {
            let explicit = serde_json::to_value(support).unwrap();
            assert_eq!(
                explicit["Secret"].as_str().unwrap().as_bytes(),
                support.secret().as_bytes()
            );
            for remaining in [
                cleaned.secret().as_bytes(),
                cleaned.match_text().as_bytes(),
                cleaned.line().as_bytes(),
            ] {
                assert!(
                    !remaining
                        .windows(support.secret().as_bytes().len())
                        .any(|value| value == support.secret().as_bytes())
                );
            }
        }
    }
}
