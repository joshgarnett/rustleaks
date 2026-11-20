//! Independently specified optional connection, YAML and credential-context contracts.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rustleaks_core::config::{CompiledConfig, ConfigLoader, RawConfig};
use rustleaks_core::model::{ByteText, Finding, Fragment, ScanOptions};
use rustleaks_core::native::{CONNECTION_RULES_V1, NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde::Deserialize;

#[allow(dead_code)]
#[path = "support/native_harness.rs"]
mod native_harness;

use native_harness::{
    all_packs_config, baseline_rule_ids, coordinates, for_rule, optional_range as range, scan,
};

#[derive(Deserialize)]
#[allow(clippy::struct_field_names)] // Field names mirror fixture JSON keys.
struct Cases {
    baseline_rule_ids: Vec<String>,
    selected_rule_ids: Vec<String>,
    primary: Vec<Case>,
    cases: Vec<Case>,
    tuples: Vec<TupleCase>,
    entropy: Vec<Entropy>,
}

#[derive(Deserialize)]
struct Entropy {
    rule: String,
    algorithm: String,
    reject: String,
    threshold: f64,
}

#[derive(Deserialize)]
struct Case {
    rule: String,
    name: String,
    input_base64: String,
    path: String,
    count: usize,
    expected: Vec<Record>,
    before_exact: Option<bool>,
    before_required: Option<Prior>,
    category: Option<String>,
}

#[derive(Deserialize)]
struct TupleCase {
    rule: String,
    helper: String,
    name: String,
    input_base64: String,
    path: String,
    max_decode_depth: usize,
    expected: Vec<Record>,
}

#[derive(Clone, Deserialize)]
struct Record {
    secret: String,
    #[serde(rename = "match")]
    matched: String,
    secret_range: Option<[usize; 2]>,
    match_range: Option<[usize; 2]>,
    location: Position,
    nested_secret: Option<String>,
    nested_match: Option<String>,
    #[serde(default)]
    nested_count: usize,
    nested_secret_range: Option<[usize; 2]>,
    nested_match_range: Option<[usize; 2]>,
    nested_location: Option<Position>,
}

#[derive(Deserialize)]
struct Prior {
    rule: String,
    secret: String,
    secret_range: [usize; 2],
}

#[derive(Clone, Deserialize)]
struct Position {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
}

impl Position {
    fn coordinates(&self) -> [usize; 4] {
        [
            self.start_line,
            self.end_line,
            self.start_column,
            self.end_column,
        ]
    }
}

fn cases() -> &'static Cases {
    static CASES: OnceLock<Cases> = OnceLock::new();
    CASES.get_or_init(|| {
        serde_json::from_str(include_str!("support/special_coverage.json")).unwrap()
    })
}

/// The rules before the association batch, a frozen comparison set. Its only
/// copy is `baseline_rule_ids` in `support/association_coverage.json`.
fn rules_before_association_batch() -> Vec<String> {
    baseline_rule_ids(include_str!("support/association_coverage.json"))
}

fn config() -> &'static CompiledConfig {
    static CONFIG: OnceLock<CompiledConfig> = OnceLock::new();
    CONFIG.get_or_init(|| {
        all_packs_config()
            .select_rules(rules_before_association_batch().iter().map(String::as_str))
            .unwrap()
    })
}

fn selected() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(
            config()
                .select_rules(cases().selected_rule_ids.iter().map(String::as_str))
                .unwrap(),
        )
        .build()
        .unwrap()
    })
}

fn composed() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| Engine::builder(config().clone()).build().unwrap())
}

fn previous() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let config = config()
            .select_rules(cases().baseline_rule_ids.iter().map(String::as_str))
            .unwrap();
        assert_eq!(config.rules().len(), 467);
        Engine::builder(config).build().unwrap()
    })
}

fn assert_record(rule: &str, expected: &Record, finding: &Finding, name: &str) {
    assert_eq!(
        finding.secret().as_bytes(),
        expected.secret.as_bytes(),
        "{name}"
    );
    assert_eq!(
        finding.match_text().as_bytes(),
        expected.matched.as_bytes(),
        "{name}"
    );
    assert_eq!(
        finding.secret_range(),
        range(expected.secret_range),
        "{name}"
    );
    assert_eq!(finding.match_range(), range(expected.match_range), "{name}");
    assert_eq!(
        coordinates(finding.location()),
        expected.location.coordinates(),
        "{name}"
    );
    assert_eq!(
        finding.required_findings().len(),
        expected.nested_count,
        "{name}"
    );
    if expected.nested_count == 1 {
        let nested = &finding.required_findings()[0];
        assert_eq!(
            nested.rule_id().as_bytes(),
            format!("{rule}-tuple").as_bytes(),
            "{name}"
        );
        assert_eq!(
            nested.secret().as_bytes(),
            expected.nested_secret.as_ref().unwrap().as_bytes(),
            "{name}"
        );
        assert_eq!(
            nested.match_text().as_bytes(),
            expected.nested_match.as_ref().unwrap().as_bytes(),
            "{name}"
        );
        assert_eq!(
            nested.secret_range(),
            range(expected.nested_secret_range),
            "{name}"
        );
        assert_eq!(
            nested.match_range(),
            range(expected.nested_match_range),
            "{name}"
        );
        assert_eq!(
            coordinates(nested.location()),
            expected.nested_location.as_ref().unwrap().coordinates(),
            "{name}"
        );
    }
}

fn assert_records(rule: &str, expected: &[Record], findings: &[Finding], name: &str) {
    let mut actual = for_rule(findings, rule);
    assert_eq!(actual.len(), expected.len(), "{name}");
    for record in expected {
        let index = actual
            .iter()
            .position(|finding| {
                finding.secret().as_bytes() == record.secret.as_bytes()
                    && finding.match_text().as_bytes() == record.matched.as_bytes()
                    && finding.secret_range() == range(record.secret_range)
                    && coordinates(finding.location()) == record.location.coordinates()
            })
            .unwrap_or_else(|| panic!("missing exact finding: {name}"));
        assert_record(rule, record, actual.remove(index), name);
    }
}

#[test]
fn every_concrete_family_case_and_endpoint_has_exact_independent_expectations() {
    assert_eq!(config().rules().len(), 476);
    assert_eq!(selected().config().rules().len(), 9);
    assert_eq!(cases().primary.len(), 18);
    assert_eq!(cases().cases.len(), 217);
    assert_eq!(
        cases()
            .cases
            .iter()
            .filter(|case| case.category.as_deref() == Some("document_boundary"))
            .count(),
        48
    );
    assert_eq!(
        cases()
            .cases
            .iter()
            .filter(|case| case.category.as_deref() == Some("non_marker_boundary_controls"))
            .count(),
        12
    );
    for case in cases().primary.iter().chain(&cases().cases) {
        assert_eq!(case.count, case.expected.len(), "{}", case.name);
        let findings = scan(
            selected(),
            &STANDARD.decode(&case.input_base64).unwrap(),
            &case.path,
        );
        assert_records(&case.rule, &case.expected, &findings, &case.name);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.rule_id().as_bytes().ends_with(b"-tuple"))
        );
    }
}

#[test]
fn native_tuple_identity_retains_each_parent_and_only_its_own_helper() {
    assert_eq!(cases().tuples.len(), 22);
    for case in &cases().tuples {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let fragment = Fragment::builder(input.as_slice())
            .file_path(case.path.as_str())
            .build();
        let options = ScanOptions::builder()
            .max_decode_depth(case.max_decode_depth)
            .build();
        for engine in [selected(), composed()] {
            let result = engine.scan_fragment(&fragment, &options);
            assert!(result.is_complete(), "{}", case.name);
            assert_records(&case.rule, &case.expected, result.findings(), &case.name);
            assert!(for_rule(result.findings(), &case.helper).is_empty());
        }
    }
}

#[test]
fn helper_selection_and_native_entropy_cannot_be_bypassed() {
    assert_eq!(cases().entropy.len(), 5);
    for expected in &cases().entropy {
        assert_eq!(
            config().rule(&expected.rule).unwrap().native_entropy(),
            Some((
                expected.algorithm.as_str(),
                expected.reject.as_str(),
                expected.threshold
            ))
        );
    }
    for rule in [
        "rustleaks.azure-servicebus-key-comma",
        "rustleaks.mongodb-password-comma",
    ] {
        let helper = format!("{rule}-tuple");
        let case = cases()
            .primary
            .iter()
            .find(|case| case.rule == rule)
            .unwrap();
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let parent_only = Engine::builder(config().select_rules([rule]).unwrap())
            .build()
            .unwrap();
        assert!(scan(&parent_only, &input, &case.path).is_empty());
        let helper_only = Engine::builder(config().select_rules([helper.as_str()]).unwrap())
            .build()
            .unwrap();
        assert!(scan(&helper_only, &input, &case.path).is_empty());
        let pair = Engine::builder(config().select_rules([rule, helper.as_str()]).unwrap())
            .build()
            .unwrap();
        assert_records(
            rule,
            &case.expected,
            &scan(&pair, &input, &case.path),
            &case.name,
        );
    }
    assert!(ConfigLoader::new().load_toml(PROVIDER_RULES_V1).is_err());
    assert!(ConfigLoader::new().load_toml(CONNECTION_RULES_V1).is_err());
}

#[test]
fn complete_composition_preserves_prior_occurrences_and_accounts_for_new_secrets() {
    for case in cases().primary.iter().chain(
        cases()
            .cases
            .iter()
            .filter(|case| case.before_required.is_some()),
    ) {
        let input = STANDARD.decode(&case.input_base64).unwrap();
        let prior = scan(previous(), &input, &case.path);
        let after = scan(composed(), &input, &case.path);
        assert_records(&case.rule, &case.expected, &after, &case.name);
        if let Some(exact_before) = case.before_exact {
            let expected = &case.expected[0];
            let exact = |finding: &&Finding| {
                finding.secret().as_bytes() == expected.secret.as_bytes()
                    && finding.secret_range() == range(expected.secret_range)
            };
            assert_eq!(
                prior.iter().filter(exact).count() > 0,
                exact_before,
                "{}",
                case.name
            );
            assert_eq!(after.iter().filter(exact).count(), 1, "{}", case.name);
        }
        if let Some(required) = &case.before_required {
            for findings in [&prior, &after] {
                assert!(
                    findings.iter().any(|finding| finding.rule_id().as_bytes()
                        == required.rule.as_bytes()
                        && finding.secret().as_bytes() == required.secret.as_bytes()
                        && finding.secret_range() == range(Some(required.secret_range))),
                    "{}",
                    case.name
                );
            }
        }
        for finding in &prior {
            if finding.rule_id().as_bytes() == b"generic-api-key" {
                continue;
            }
            assert!(
                after.iter().any(|next| next.rule_id() == finding.rule_id()
                    && next.secret() == finding.secret()
                    && next.secret_range() == finding.secret_range()
                    && next.match_range() == finding.match_range()),
                "{}",
                case.name
            );
        }
    }
}

fn added_rules() -> Vec<toml::Value> {
    [PROVIDER_RULES_V1, CONNECTION_RULES_V1]
        .into_iter()
        .flat_map(|source| {
            let source: toml::Value = toml::from_str(source).unwrap();
            source["rules"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|rule| {
                    cases()
                        .selected_rule_ids
                        .iter()
                        .any(|id| Some(id.as_str()) == rule["id"].as_str())
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect()
}

fn local_allowlist(predicate: &toml::Value) -> Engine {
    let mut rules = added_rules();
    for rule in &mut rules {
        rule.as_table_mut()
            .unwrap()
            .entry("allowlists")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(predicate.clone());
    }
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(rules));
    let (config, _) = NativePolicy::builder()
        .with_pack(
            "special-allowlist-controls",
            &toml::to_string(&source).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(
        config
            .select_rules(cases().selected_rule_ids.iter().map(String::as_str))
            .unwrap(),
    )
    .build()
    .unwrap()
}

fn exact_pattern(value: &str) -> String {
    use std::fmt::Write as _;
    let mut pattern = String::from("^");
    for byte in value.bytes() {
        write!(pattern, "\\x{byte:02x}").unwrap();
    }
    pattern.push('$');
    pattern
}

#[test]
fn local_allowlists_preserve_targets_stopwords_commit_neighbors_and_markers() {
    for target in ["secret", "match", "line"] {
        let engine = local_allowlist(
            &toml::from_str(&format!("regexTarget='{target}'\nregexes=['.']")).unwrap(),
        );
        for case in &cases().primary {
            assert!(
                scan(
                    &engine,
                    &STANDARD.decode(&case.input_base64).unwrap(),
                    &case.path
                )
                .is_empty()
            );
        }
    }
    for case in &cases().primary {
        let expected = &case.expected[0];
        let middle = expected.secret.len() / 2;
        let mut predicate = toml::Table::new();
        predicate.insert(
            "stopwords".into(),
            toml::Value::Array(vec![toml::Value::String(
                expected.secret[middle..middle + 4].to_ascii_uppercase(),
            )]),
        );
        let engine = local_allowlist(&toml::Value::Table(predicate));
        let input = STANDARD.decode(&case.input_base64).unwrap();
        assert!(for_rule(&scan(&engine, &input, &case.path), &case.rule).is_empty());
        let engine =
            local_allowlist(&toml::from_str("commits=['synthetic-special-commit']").unwrap());
        for (commit, count) in [
            ("synthetic-special-commit", 0),
            ("synthetic-special-neighbor", 1),
        ] {
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit(commit)
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert_eq!(
                for_rule(result.findings(), &case.rule).len(),
                count,
                "{}",
                case.name
            );
        }
        // Markers are line-scoped; YAML's multi-line match is exercised by
        // explicit local predicates above rather than a trailing-line marker.
        if !input.contains(&b'\n') {
            let mut marked = input.clone();
            marked.extend_from_slice(b" # rustleaks:allow");
            let mut marker_expected = case.expected.clone();
            if case.rule == "rustleaks.service-uri-password" {
                // The source URI path greedily includes the final semicolon.
                // Appending the marker replaces the EOF terminal with one
                // consumed space; the password capture remains unchanged.
                for expected in &mut marker_expected {
                    let [start, end] = expected.match_range.unwrap();
                    assert_eq!(end, input.len());
                    assert!(expected.matched.ends_with(';'));
                    expected.matched.push(' ');
                    expected.match_range = Some([start, end + 1]);
                    expected.location.end_column += 1;
                }
            }
            assert!(for_rule(&scan(selected(), &marked, &case.path), &case.rule).is_empty());
            let fragment = Fragment::builder(marked.as_slice())
                .file_path(case.path.as_str())
                .build();
            let result = selected().scan_fragment(
                &fragment,
                &ScanOptions::builder().honor_allow_markers(false).build(),
            );
            assert!(result.is_complete());
            assert_records(&case.rule, &marker_expected, result.findings(), &case.name);
        }
    }
}

#[test]
fn global_target_and_commit_controls_keep_their_unrelated_positive_cases() {
    // Native packs cannot add global predicates. This ordinary-config control
    // retains each reporting expression and local filters while removing
    // native entropy/association metadata. It isolates global semantics; the
    // native tuple and entropy contracts are checked separately above.
    for case in &cases().primary {
        let mut rule = added_rules()
            .into_iter()
            .find(|rule| rule["id"].as_str() == Some(case.rule.as_str()))
            .unwrap();
        rule.as_table_mut().unwrap().remove("entropy");
        rule.as_table_mut().unwrap().remove("required");
        for (target, count) in [(case.rule.as_str(), 0), ("unrelated-special-control", 1)] {
            let mut source = toml::Table::new();
            let neighbor: toml::Value = toml::from_str(
                "id='unrelated-special-control'\nregex='NEVER_A_SPECIAL_CREDENTIAL'",
            )
            .unwrap();
            source.insert(
                "rules".into(),
                toml::Value::Array(vec![rule.clone(), neighbor]),
            );
            let mut predicate = toml::Table::new();
            predicate.insert(
                "targetRules".into(),
                toml::Value::Array(vec![toml::Value::String(target.into())]),
            );
            predicate.insert("regexTarget".into(), toml::Value::String("secret".into()));
            predicate.insert(
                "regexes".into(),
                toml::Value::Array(vec![toml::Value::String(exact_pattern(
                    &case.expected[0].secret,
                ))]),
            );
            source.insert(
                "allowlists".into(),
                toml::Value::Array(vec![toml::Value::Table(predicate)]),
            );
            let raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
            let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                .build()
                .unwrap();
            assert_eq!(
                scan(
                    &engine,
                    &STANDARD.decode(&case.input_base64).unwrap(),
                    &case.path
                )
                .len(),
                count,
                "{}",
                case.name
            );
        }
        let mut source = toml::Table::new();
        source.insert("rules".into(), toml::Value::Array(vec![rule]));
        source.insert(
            "allowlists".into(),
            toml::Value::Array(vec![
                toml::from_str("commits=['synthetic-special-commit']").unwrap(),
            ]),
        );
        let raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        let input = STANDARD.decode(&case.input_base64).unwrap();
        for (commit, count) in [
            ("synthetic-special-commit", 0),
            ("synthetic-special-neighbor", 1),
        ] {
            let fragment = Fragment::builder(input.as_slice())
                .file_path(case.path.as_str())
                .commit(commit)
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert_eq!(result.findings().len(), count);
        }
    }
}

#[test]
fn every_special_family_obeys_work_record_payload_and_target_limits() {
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
            assert!(!result.is_complete(), "{}", case.name);
            assert!(result.findings().is_empty());
        }
        for (size, count) in [(input.len() - 1, 0), (input.len(), 1)] {
            let result = selected().scan_fragment(
                &fragment,
                &ScanOptions::builder().max_target_bytes(Some(size)).build(),
            );
            assert!(result.is_complete());
            assert_eq!(
                for_rule(result.findings(), &case.rule).len(),
                count,
                "{}",
                case.name
            );
        }
        for repetitions in [100, 10_000] {
            let mut repeated = Vec::new();
            for _ in 0..repetitions {
                repeated.extend_from_slice(&input);
                repeated.push(b'\n');
            }
            let fragment = Fragment::builder(repeated.as_slice())
                .file_path(case.path.as_str())
                .build();
            let result = selected().scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(1)),
            );
            assert!(!result.is_complete(), "{}", case.name);
            if repetitions == 100 {
                let result = selected().scan_fragment(&fragment, &ScanOptions::default());
                assert!(result.is_complete());
                let findings = for_rule(result.findings(), &case.rule);
                assert_eq!(findings.len(), repetitions, "{}", case.name);
                let [start, end] = case.expected[0].secret_range.unwrap();
                for index in 0..repetitions {
                    let offset = index * (input.len() + 1);
                    assert!(
                        findings.iter().any(|finding| finding.secret().as_bytes()
                            == case.expected[0].secret.as_bytes()
                            && finding.secret_range()
                                == range(Some([offset + start, offset + end]))),
                        "{}",
                        case.name
                    );
                }
            }
        }
    }
}

#[test]
fn long_valid_json_payloads_and_uri_tails_keep_exact_secrets_and_budget_failures() {
    for length in [8_192, 262_144] {
        let token = ["9Z7q2M8v4R1x6B5", "n3T0DkWcYpSgJfUa"]
            .concat()
            .chars()
            .cycle()
            .take(length)
            .collect::<String>();
        let payload = serde_json::json!({"iss":"https://identity.internal","sub":"service-27","aud":"deployment-api","jti":token});
        let secret = format!(
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{}.",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let jwt = format!("Authorization: Bearer {secret}\\\"");
        let uri_secret = ["A7q2M9z4", "B6w8C3v5"].concat();
        let uri = format!(
            "redis://alice:{uri_secret}@cache.internal/{};",
            "path7".repeat(length / 5)
        );
        for (rule, input, expected_secret, start) in [
            (
                "rustleaks.jwt-unsigned-bearer-escaped",
                jwt.as_str(),
                secret.as_str(),
                22,
            ),
            (
                "rustleaks.service-uri-password",
                uri.as_str(),
                uri_secret.as_str(),
                14,
            ),
        ] {
            let findings = scan(selected(), input.as_bytes(), "runtime/service.conf");
            let findings = for_rule(&findings, rule);
            assert_eq!(findings.len(), 1, "{rule} {length}");
            assert_eq!(findings[0].secret().as_bytes(), expected_secret.as_bytes());
            assert_eq!(
                findings[0].secret_range(),
                range(Some([start, start + expected_secret.len()]))
            );
            assert_eq!(findings[0].match_range(), range(Some([0, input.len()])));
            let fragment = Fragment::new(input.as_bytes());
            for budget in [
                ScanBudget::unlimited().max_finding_payload_bytes(1_024),
                ScanBudget::unlimited().max_work_units(0),
            ] {
                let result = selected().scan_fragment_controlled(
                    &fragment,
                    &ScanOptions::default(),
                    &ScanControl::unlimited().with_budget(budget),
                );
                assert!(!result.is_complete(), "{rule} {length}");
                assert!(result.findings().is_empty());
            }
        }
    }
}

#[test]
fn mongodb_whole_tuple_entropy_rejection_is_not_masked_by_source_filters() {
    let rule = "rustleaks.mongodb-password-comma";
    let helper = "rustleaks.mongodb-password-comma-tuple";
    let negative = cases()
        .cases
        .iter()
        .find(|case| case.rule == rule && case.name.contains("entropy_reject"))
        .unwrap();
    let positive = cases()
        .cases
        .iter()
        .find(|case| case.name == "mongodb-tuple-entropy-positive-neighbor")
        .unwrap();
    let input = STANDARD.decode(&negative.input_base64).unwrap();
    assert!(for_rule(&scan(selected(), &input, &negative.path), rule).is_empty());
    assert_records(
        rule,
        &positive.expected,
        &scan(
            selected(),
            &STANDARD.decode(&positive.input_base64).unwrap(),
            &positive.path,
        ),
        &positive.name,
    );

    // Remove exactly the helper entropy predicate. All parent/helper regexes,
    // source filters, association and inherited policy remain active.
    let mut rules = added_rules();
    let tuple = rules
        .iter_mut()
        .find(|value| value["id"].as_str() == Some(helper))
        .unwrap();
    assert!(tuple.as_table_mut().unwrap().remove("entropy").is_some());
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(rules));
    let (config, _) = NativePolicy::builder()
        .with_pack(
            "special-entropy-control",
            &toml::to_string(&source).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    assert_eq!(config.rule(helper).unwrap().native_entropy(), None);
    let engine = Engine::builder(config.select_rules([rule, helper]).unwrap())
        .build()
        .unwrap();
    let findings = scan(&engine, &input, &negative.path);
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.rule_id().as_bytes(), rule.as_bytes());
    assert_eq!(finding.secret().as_bytes(), b"A7q2M9z4B6w8C3v5");
    assert_eq!(finding.secret_range(), range(Some([16, 32])));
    assert_eq!(finding.match_text().as_bytes(), input.as_slice());
    assert_eq!(finding.match_range(), range(Some([0, input.len()])));
    assert_eq!(coordinates(finding.location()), [0, 0, 1, input.len()]);
    assert_eq!(finding.required_findings().len(), 1);
    let nested = &finding.required_findings()[0];
    assert_eq!(nested.rule_id().as_bytes(), helper.as_bytes());
    assert_eq!(nested.secret().as_bytes(), &input[..input.len() - 2]);
    assert_eq!(nested.secret_range(), range(Some([0, input.len() - 2])));
    assert_eq!(nested.match_text().as_bytes(), input.as_slice());
    assert_eq!(nested.match_range(), range(Some([0, input.len()])));
    assert_eq!(coordinates(nested.location()), [0, 0, 1, input.len()]);
}

fn ordinary_single_rule(rule: toml::Value) -> Engine {
    let mut source = toml::Table::new();
    source.insert("rules".into(), toml::Value::Array(vec![rule]));
    let raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
    Engine::builder(ConfigLoader::new().compile(raw).unwrap())
        .build()
        .unwrap()
}

#[test]
fn yaml_source_and_inherited_paths_are_independent_of_its_required_suffix() {
    let id = "rustleaks.kubernetes-secret-yaml-long-context";
    let original = added_rules()
        .into_iter()
        .find(|rule| rule["id"].as_str() == Some(id))
        .unwrap();
    let local = ordinary_single_rule(original.clone());
    let mut without_local_paths = original;
    let predicates = without_local_paths["allowlists"].as_array_mut().unwrap();
    let before = predicates.len();
    predicates.retain(|predicate| !predicate.as_table().unwrap().contains_key("paths"));
    assert_eq!(predicates.len() + 1, before);
    // Preserve the positive .yaml/.yml requirement and every non-path filter.
    assert_eq!(without_local_paths["path"].as_str(), Some(r"(?i)\.ya?ml$"));
    let lexical = ordinary_single_rule(without_local_paths.clone());
    let mut source = toml::Table::new();
    source.insert(
        "rules".into(),
        toml::Value::Array(vec![without_local_paths]),
    );
    let (config, _) = NativePolicy::builder()
        .with_pack(
            "special-yaml-path-control",
            &toml::to_string(&source).unwrap(),
        )
        .unwrap()
        .compile()
        .unwrap();
    let inherited = Engine::builder(config.select_rules([id]).unwrap())
        .build()
        .unwrap();
    let case = cases()
        .cases
        .iter()
        .find(|case| case.name == "kubernetes-path-positive-neighbor")
        .unwrap();
    let input = STANDARD.decode(&case.input_base64).unwrap();
    for path in [
        "vendor/github.com/fixture/secret.yaml",
        "node_modules/runtime/service.yaml",
    ] {
        assert!(
            scan(&local, &input, path).is_empty(),
            "local source filter: {path}"
        );
        assert_records(id, &case.expected, &scan(&lexical, &input, path), path);
        assert!(
            scan(&inherited, &input, path).is_empty(),
            "inherited global filter: {path}"
        );
    }
    for engine in [&local, &lexical, &inherited] {
        assert_records(
            id,
            &case.expected,
            &scan(engine, &input, "runtime/service.yaml"),
            "path neighbor",
        );
    }
}

#[test]
fn kubernetes_long_context_location_is_the_whole_match_and_decoding_adds_a_finding() {
    // The provider pack documents the secret as the data item, while report
    // lines and columns describe the whole match (docs/user/reports.md). The
    // match starts at `kind`, so it starts on line 0 at column 1, not on the
    // line of the data item. A fragment without a start line counts from 0.
    let id = "rustleaks.kubernetes-secret-yaml-long-context";
    let engine = Engine::builder(config().select_rules([id]).unwrap())
        .build()
        .unwrap();
    let value = b"U3ludGhldGljVmFsdWUyMDI2"; // Base64 of "SyntheticValue2026".
    let mut body = b"kind: Secret\n#".to_vec();
    body.extend([b'x'; 230]);
    body.extend(b"\ndata:\n  opaque: ");
    body.extend(value);
    // LF bytes are at 12, 244 and 250; the data item is at 253..285.
    assert_eq!(body.len(), 285);
    let secret = b"opaque: U3ludGhldGljVmFsdWUyMDI2";

    // With a final LF, the match ends on line 3. Its last byte is at position
    // 34 of that line, and a later line adds 1 to the column.
    let mut terminated = body.clone();
    terminated.push(b'\n');
    // Without a final LF, the match ends after the last line break. The pinned
    // location helper then keeps the start line as the end line and leaves
    // the end column at 0.
    for (name, input, end) in [
        ("final LF", &terminated, [3, 35]),
        ("no final LF", &body, [0, 0]),
    ] {
        let findings = scan(&engine, input, "deploy/secret.yaml");
        assert_eq!(findings.len(), 1, "{name}");
        let finding = &findings[0];
        assert_eq!(finding.secret().as_bytes(), secret, "{name}");
        assert_eq!(finding.match_text().as_bytes(), &body[..], "{name}");
        assert_eq!(finding.secret_range(), range(Some([253, 285])), "{name}");
        assert_eq!(finding.match_range(), range(Some([0, 285])), "{name}");
        assert_eq!(
            coordinates(finding.location()),
            [0, end[0], 1, end[1]],
            "{name}"
        );
        assert!(finding.tags().is_empty(), "{name}");
    }

    // Decoding also scans the decoded value, as for the default rules. The
    // decoded finding is reported next to the raw one, and its columns cover
    // the encoded text in the input.
    let fragment = Fragment::builder(terminated.as_slice())
        .file_path("deploy/secret.yaml")
        .build();
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let outcome = engine.scan_fragment(&fragment, &options);
    assert!(outcome.is_complete());
    let (raw, decoded): (Vec<&Finding>, Vec<&Finding>) = outcome
        .findings()
        .iter()
        .partition(|finding| finding.tags().is_empty());
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].secret().as_bytes(), secret);
    assert_eq!(decoded.len(), 1);
    assert_eq!(
        decoded[0].secret().as_bytes(),
        b"opaque: SyntheticValue2026"
    );
    let tags = decoded[0]
        .tags()
        .iter()
        .map(ByteText::as_bytes)
        .collect::<Vec<_>>();
    assert_eq!(tags, [&b"decoded:base64"[..], b"decode-depth:1"]);
    assert_eq!(coordinates(decoded[0].location()), [0, 3, 1, 35]);
}
