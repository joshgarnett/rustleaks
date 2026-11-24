//! Cases for provider rules in rustleaks-providers-v1.toml, with expectations
//! in support/additional_coverage.json.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{Finding, Fragment, Location, ScanOptions};
use rustleaks_core::native::{CONNECTION_RULES_V1, NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde::Deserialize;

#[allow(dead_code)] // Each test uses part of the shared module.
#[path = "support/native_harness.rs"]
mod native_harness;

use native_harness::{all_packs_config, exact_range as range, scan};

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)] // Field names mirror fixture JSON keys.
struct Cases {
    baseline_rule_ids: Vec<String>,
    primary: Vec<Case>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    rule: String,
    name: String,
    input_base64: String,
    path: String,
    count: usize,
    secret: Option<String>,
    #[serde(rename = "match")]
    matched: Option<String>,
    secret_range: Option<[usize; 2]>,
    match_range: Option<[usize; 2]>,
    secret_ranges: Option<Vec<[usize; 2]>>,
    location: Option<Position>,
    before_occurrence: Option<bool>,
    before_secret: Option<String>,
    before_secret_range: Option<[usize; 2]>,
}

#[derive(Deserialize)]
struct Position {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
}

fn cases() -> &'static Cases {
    static CASES: OnceLock<Cases> = OnceLock::new();
    CASES.get_or_init(|| {
        serde_json::from_str(include_str!("support/additional_coverage.json")).unwrap()
    })
}

fn config() -> &'static CompiledConfig {
    static CONFIG: OnceLock<CompiledConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        all_packs_config()
            .select_rules(cases().baseline_rule_ids.iter().map(String::as_str))
            .unwrap()
    })
}

fn selected() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let ids = cases().primary.iter().map(|case| case.rule.as_str());
        Engine::builder(config().select_rules(ids).unwrap())
            .build()
            .unwrap()
    })
}

fn composed() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::builder(config().clone()).build().unwrap())
}

// The rules in `config()` without this file's primary rules.
fn without_primary_rules() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let added: BTreeSet<_> = cases()
            .primary
            .iter()
            .map(|case| case.rule.as_str())
            .collect();
        let ids = config()
            .rules()
            .keys()
            .map(String::as_str)
            .filter(|id| !added.contains(id));
        let without = config().select_rules(ids).unwrap();
        assert_eq!(without.rules().len(), 335);
        Engine::builder(without).build().unwrap()
    })
}

fn selected_findings(findings: &[Finding], rule: &str) -> Vec<Finding> {
    findings
        .iter()
        .filter(|finding| finding.rule_id().as_bytes() == rule.as_bytes())
        .cloned()
        .collect()
}

fn assert_case(case: &Case, findings: &[Finding]) {
    let findings = selected_findings(findings, &case.rule);
    assert_eq!(findings.len(), case.count, "{} {}", case.rule, case.name);
    if let Some(ranges) = &case.secret_ranges {
        assert_eq!(findings.len(), ranges.len(), "{} {}", case.rule, case.name);
        for expected in ranges {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.secret_range() == range(*expected)),
                "{} {}",
                case.rule,
                case.name
            );
        }
    }
    if findings.len() != 1 {
        return;
    }
    let finding = &findings[0];
    if let Some(secret) = &case.secret {
        assert_eq!(
            finding.secret().as_bytes(),
            secret.as_bytes(),
            "{} {}",
            case.rule,
            case.name
        );
    }
    if let Some(matched) = &case.matched {
        assert_eq!(
            finding.match_text().as_bytes(),
            matched.as_bytes(),
            "{} {}",
            case.rule,
            case.name
        );
    }
    if let Some(expected) = case.secret_range {
        assert_eq!(
            finding.secret_range(),
            range(expected),
            "{} {}",
            case.rule,
            case.name
        );
    }
    if let Some(expected) = case.match_range {
        assert_eq!(
            finding.match_range(),
            range(expected),
            "{} {}",
            case.rule,
            case.name
        );
    }
    if let Some(position) = &case.location {
        assert_eq!(
            finding.location(),
            Location::new(
                position.start_line,
                position.end_line,
                position.start_column,
                position.end_column
            )
            .unwrap(),
            "{} {}",
            case.rule,
            case.name
        );
    }
}

#[test]
fn reviewed_primary_shapes_have_exact_independent_geometry() {
    assert_eq!(cases().primary.len(), 105);
    assert_eq!(config().rules().len(), 440);
    assert_eq!(selected().config().rules().len(), 105);
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert_case(case, &scan(selected(), &input, &case.path));
    }
}

#[test]
fn authored_near_misses_filters_bounds_paths_and_byte_scopes_hold() {
    for case in &cases().cases {
        if case.name == "primary" {
            continue;
        }
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert_case(case, &scan(selected(), &input, &case.path));
    }
}

fn has_occurrence(findings: &[Finding], secret: &[u8], expected: [usize; 2]) -> bool {
    findings.iter().any(|finding| {
        finding.secret().as_bytes() == secret && finding.secret_range() == range(expected)
    })
}

#[test]
fn full_composition_distinguishes_occurrences_from_provider_attribution() {
    for case in cases()
        .cases
        .iter()
        .filter(|case| case.before_occurrence.is_some())
    {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let secret = case.secret.as_ref().unwrap().as_bytes();
        let expected = case.secret_range.unwrap();
        let prior = scan(without_primary_rules(), &input, &case.path);
        assert_eq!(
            has_occurrence(&prior, secret, expected),
            case.before_occurrence.unwrap(),
            "{} {} before",
            case.rule,
            case.name
        );
        if let Some(prior_secret) = &case.before_secret {
            assert!(
                has_occurrence(
                    &prior,
                    prior_secret.as_bytes(),
                    case.before_secret_range.unwrap()
                ),
                "{} {} prior extraction",
                case.rule,
                case.name
            );
        }
        assert_case(case, &scan(composed(), &input, &case.path));
        if case.count > 0 {
            assert!(
                has_occurrence(&scan(composed(), &input, &case.path), secret, expected),
                "{} {} after",
                case.rule,
                case.name
            );
        }
    }
}

#[test]
fn every_added_rule_retains_invalid_prefix_bytes_and_exact_secret_ranges() {
    for case in &cases().primary {
        let original = STANDARD.decode(&case.input_base64).unwrap();
        let mut input = vec![0xff, b' '];
        input.extend_from_slice(&original);
        let findings = selected_findings(&scan(selected(), &input, &case.path), &case.rule);
        assert_eq!(findings.len(), 1, "{}", case.rule);
        let [start, end] = case.secret_range.unwrap();
        assert_eq!(
            findings[0].secret_range(),
            range([start + 2, end + 2]),
            "{}",
            case.rule
        );
        assert_eq!(
            findings[0].secret().as_bytes(),
            case.secret.as_ref().unwrap().as_bytes(),
            "{}",
            case.rule
        );
    }
}

#[test]
fn selected_ascii_secrets_never_expand_into_unicode_or_invalid_bytes() {
    for case in &cases().primary {
        let original = STANDARD.decode(&case.input_base64).unwrap();
        let [start, end] = case.secret_range.unwrap();
        let offset = start + (end - start) / 2;
        for replacement in [
            "é".as_bytes(),
            "ſ".as_bytes(),
            "\u{212a}".as_bytes(),
            &[0xff],
        ] {
            let mut input = original[..offset].to_vec();
            input.extend_from_slice(replacement);
            input.extend_from_slice(&original[offset + 1..]);
            for finding in selected_findings(&scan(selected(), &input, &case.path), &case.rule) {
                // Some source expressions intentionally allow finite prefix
                // captures; only ASCII captured bytes remain in the selection.
                assert!(finding.secret().as_bytes().is_ascii(), "{}", case.rule);
            }
        }
    }
}

fn added_rules() -> Vec<toml::Value> {
    [PROVIDER_RULES_V1, CONNECTION_RULES_V1]
        .into_iter()
        .flat_map(|text| {
            let pack: toml::Value = toml::from_str(text).unwrap();
            pack["rules"].as_array().unwrap().clone()
        })
        .filter(|rule| {
            cases()
                .primary
                .iter()
                .any(|case| Some(case.rule.as_str()) == rule["id"].as_str())
        })
        .collect()
}

fn engine_with_allowlist(specification: &toml::Value) -> Engine {
    let mut rules = added_rules();
    for rule in &mut rules {
        let fields = rule.as_table_mut().unwrap();
        fields
            .entry("allowlists")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(specification.clone());
    }
    let mut pack = toml::Table::new();
    pack.insert("rules".into(), toml::Value::Array(rules));
    let (compiled, _) = NativePolicy::builder()
        .with_pack("allowlist-controls-v1", &toml::to_string(&pack).unwrap())
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(
        compiled
            .select_rules(cases().primary.iter().map(|case| case.rule.as_str()))
            .unwrap(),
    )
    .build()
    .unwrap()
}

#[test]
fn native_rule_allowlists_and_inherited_global_policy_remain_effective() {
    for specification in [
        "regexTarget='secret'\nregexes=['.']",
        "regexTarget='match'\nregexes=['.']",
        "regexTarget='line'\nregexes=['.']",
        "commits=['synthetic-additional-coverage']",
        "paths=['.']",
    ] {
        let engine = engine_with_allowlist(&toml::from_str(specification).unwrap());
        for case in &cases().primary {
            let input = STANDARD.decode(&case.input_base64).unwrap();
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit("synthetic-additional-coverage")
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert!(
                selected_findings(result.findings(), &case.rule).is_empty(),
                "{}",
                case.rule
            );
        }
    }
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let path = format!("node_modules/{}", case.path);
        assert!(scan(selected(), &input, &path).is_empty(), "{}", case.rule);
    }
}

#[test]
fn every_added_rule_preserves_case_insensitive_secret_stopwords() {
    let words = cases()
        .primary
        .iter()
        .map(|case| {
            let secret = case.secret.as_ref().unwrap();
            let middle = secret.len() / 2;
            toml::Value::String(secret[middle..middle + 4].to_ascii_uppercase())
        })
        .collect();
    let mut allowlist = toml::Table::new();
    allowlist.insert("stopwords".into(), toml::Value::Array(words));
    let engine = engine_with_allowlist(&toml::Value::Table(allowlist));
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert!(
            scan(&engine, &input, &case.path).is_empty(),
            "{}",
            case.rule
        );
    }
}

#[test]
fn strict_and_inclusive_byte_entropy_keep_their_equality_boundary() {
    // Four byte values with equal frequency have exact Shannon entropy 2.
    for (reject, threshold, count) in [
        ("lt", 2.0_f64, 1),
        ("le", 2.0_f64, 0),
        ("lt", f64::from_bits(2.0_f64.to_bits() + 1), 0),
        ("le", f64::from_bits(2.0_f64.to_bits() - 1), 1),
    ] {
        let source = format!(
            "[[rules]]\nid='rustleaks.byte-boundary-control'\nregex='probe=([0-3]{{8}})'\nsecretGroup=1\nentropy={{algorithm='byte-shannon-f64-v1',reject='{reject}',threshold={threshold:?}}}\n"
        );
        let (compiled, _) = NativePolicy::builder()
            .with_pack("byte-boundary-control-v1", &source)
            .unwrap()
            .compile()
            .unwrap();
        let compiled = compiled
            .select_rules(["rustleaks.byte-boundary-control"])
            .unwrap();
        assert_eq!(
            compiled
                .rule("rustleaks.byte-boundary-control")
                .unwrap()
                .native_entropy(),
            Some(("byte-shannon-f64-v1", reject, threshold))
        );
        let engine = Engine::builder(compiled).build().unwrap();
        assert_eq!(
            scan(&engine, b"probe=00112233", "credentials.txt").len(),
            count
        );
    }
}

#[test]
fn every_added_rule_remains_subject_to_explicit_resource_limits() {
    for case in &cases().primary {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let fragment = Fragment::builder(input.as_slice())
            .file_path(case.path.as_str())
            .build();
        for budget in [
            ScanBudget::unlimited().max_finding_payload_bytes(1),
            ScanBudget::unlimited().max_finding_records(0),
            ScanBudget::unlimited().max_work_units(0),
        ] {
            let result = selected().scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!result.is_complete(), "{}", case.rule);
            assert!(result.findings().is_empty(), "{}", case.rule);
        }
        let options = ScanOptions::builder()
            .max_target_bytes(Some(input.len() - 1))
            .build();
        assert!(
            selected()
                .scan_fragment(&fragment, &options)
                .findings()
                .is_empty(),
            "{}",
            case.rule
        );
    }
}

fn repeated(alphabet: &str, length: usize) -> String {
    alphabet.chars().cycle().take(length).collect()
}

fn long_input(rule: &str, length: usize) -> (String, String, [usize; 2]) {
    let alphabet = "A0b1C2d3E4f5G6h7J8k9L0m1N2p3Q4r5S6t7U8v9W0x1Y2z3";
    let case = cases()
        .primary
        .iter()
        .find(|case| case.rule == rule)
        .unwrap();
    let input = String::from_utf8(STANDARD.decode(&case.input_base64).unwrap()).unwrap();
    let original = case.secret.as_ref().unwrap();
    let secret = match rule {
        "rustleaks.datastax-astra-application-token" => {
            format!("AstraCS:{}", repeated(alphabet, length))
        }
        "rustleaks.fullstory-api-key" => format!("na1.{}", repeated(alphabet, length)),
        "rustleaks.canadian-digital-service-notify-api-key" => {
            original.replacen("svc7", &repeated(alphabet, length), 1)
        }
        "rustleaks.workato-developer-api-token" | "rustleaks.temporal-cloud-api-key" => {
            let (prefix, _) = original.rsplit_once('.').unwrap();
            format!("{prefix}.{}", repeated(alphabet, length))
        }
        _ => unreachable!(),
    };
    let start = case.secret_range.unwrap()[0];
    (
        input.replacen(original, &secret, 1),
        case.path.clone(),
        [start, start + secret.len()],
    )
}

#[test]
fn unbounded_source_bodies_preserve_large_payloads_and_explicit_limits() {
    for rule in [
        "rustleaks.datastax-astra-application-token",
        "rustleaks.fullstory-api-key",
        "rustleaks.workato-developer-api-token",
        "rustleaks.temporal-cloud-api-key",
        "rustleaks.canadian-digital-service-notify-api-key",
    ] {
        let engine = Engine::builder(config().select_rules([rule]).unwrap())
            .build()
            .unwrap();
        for length in [8_192, 262_144] {
            assert_long_input(&engine, long_input(rule, length), rule, length);
        }
    }
}

fn assert_long_input(
    engine: &Engine,
    (input, path, expected): (String, String, [usize; 2]),
    rule: &str,
    length: usize,
) {
    let findings = scan(engine, input.as_bytes(), &path);
    assert_eq!(findings.len(), 1, "{rule} {length}");
    assert_eq!(
        findings[0].secret_range(),
        range(expected),
        "{rule} {length}"
    );
    assert_eq!(
        findings[0].secret().as_bytes(),
        &input.as_bytes()[expected[0]..expected[1]],
        "{rule} {length}"
    );
    let fragment = Fragment::builder(input.as_bytes())
        .file_path(path.as_str())
        .build();
    for budget in [
        ScanBudget::unlimited().max_finding_payload_bytes(1_024),
        ScanBudget::unlimited().max_work_units(0),
    ] {
        let result = engine.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(budget),
        );
        assert!(!result.is_complete(), "{rule} {length}");
        assert!(result.findings().is_empty(), "{rule} {length}");
    }
    let skipped = engine.scan_fragment(
        &fragment,
        &ScanOptions::builder().max_target_bytes(Some(1_024)).build(),
    );
    assert!(skipped.findings().is_empty(), "{rule} {length}");
}

#[test]
fn notify_unbounded_whitespace_and_service_name_remain_resource_controlled() {
    let rule = "rustleaks.canadian-digital-service-notify-api-key";
    let engine = Engine::builder(config().select_rules([rule]).unwrap())
        .build()
        .unwrap();
    for length in [8_192, 262_144] {
        let (input, path, expected) = long_input(rule, length);
        let whitespace = repeated("\t\n\u{b}\u{c}\r ", length);
        let input = input.replacen("ApiKey-v1 ", &format!("ApiKey-v1{whitespace}"), 1);
        // A varied service name grows alongside whitespace so the complete
        // source-shaped credential remains above its entropy threshold.
        assert_long_input(
            &engine,
            (input, path, [expected[0], expected[1] + length - 1]),
            rule,
            length,
        );
    }
}
