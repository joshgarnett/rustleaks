//! Cases for the provider delimiter rules that share a prefix with a default
//! rule.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;

use rustleaks_core::config::{ConfigLoader, RawConfig};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::native::{EXTRA_RULES_V1, NativeEngine, NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

#[allow(dead_code)] // `positives` serves the all-rules precedence test.
#[path = "support/shared_delta_cases.rs"]
mod shared_delta_cases;
use shared_delta_cases::{CASES, Case, secret};

// CASES is inserted from an independently authored fixture table, not regexes
// or a scanner's findings. The source grammar is the specification.
const IDS: [&str; 24] = [
    "rustleaks.aws-amazon-bedrock-api-key-long-lived-delimiter",
    "rustleaks.digitalocean-access-token-delimiter",
    "rustleaks.gcp-api-key-delimiter",
    "rustleaks.huggingface-access-token-delimiter",
    "rustleaks.huggingface-organization-api-token-delimiter",
    "rustleaks.infracost-api-token-delimiter",
    "rustleaks.intra42-client-secret-delimiter",
    "rustleaks.maxmind-license-key-delimiter",
    "rustleaks.notion-api-token-delimiter",
    "rustleaks.octopus-deploy-api-key-delimiter",
    "rustleaks.planetscale-oauth-token-delimiter",
    "rustleaks.planetscale-password-delimiter",
    "rustleaks.prefect-api-token-delimiter",
    "rustleaks.pulumi-api-token-delimiter",
    "rustleaks.readme-api-token-delimiter",
    "rustleaks.rubygems-api-token-delimiter",
    "rustleaks.scalingo-api-token-delimiter",
    "rustleaks.settlemint-application-access-token-delimiter",
    "rustleaks.settlemint-personal-access-token-delimiter",
    "rustleaks.settlemint-service-access-token-delimiter",
    "rustleaks.shippo-api-token-delimiter",
    "rustleaks.square-access-token-delimiter",
    "rustleaks.vault-batch-token-delimiter",
    "rustleaks.vault-service-token-delimiter",
];

fn exact(start: usize, end: usize) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

fn selected() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let (config, _) = NativePolicy::builder()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .compile()
            .unwrap();
        Engine::builder(config.select_rules(IDS).unwrap())
            .build()
            .unwrap()
    })
}

fn base() -> &'static NativeEngine {
    static ENGINE: OnceLock<NativeEngine> = OnceLock::new();
    ENGINE.get_or_init(|| NativePolicy::builder().build().unwrap())
}

fn composed() -> &'static NativeEngine {
    static ENGINE: OnceLock<NativeEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        NativePolicy::builder()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .build()
            .unwrap()
    })
}

fn both_packs() -> &'static NativeEngine {
    static ENGINE: OnceLock<NativeEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        NativePolicy::builder()
            .with_pack("rustleaks-extras-v1", EXTRA_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .build()
            .unwrap()
    })
}

fn scan(engine: &Engine, bytes: &[u8]) -> Vec<Finding> {
    let result = engine.scan_fragment(
        &Fragment::builder(bytes).start_line(0).build(),
        &ScanOptions::default(),
    );
    assert!(result.is_complete());
    result.findings().to_vec()
}

fn rule_value(id: &str) -> toml::Value {
    let pack: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    pack["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"].as_str() == Some(id))
        .unwrap()
        .clone()
}

fn one_rule(rule: toml::Value) -> Engine {
    let id = rule["id"].as_str().unwrap().to_owned();
    let mut pack: toml::Value = toml::from_str("title='delimiter test'\n").unwrap();
    pack.as_table_mut()
        .unwrap()
        .insert("rules".into(), toml::Value::Array(vec![rule]));
    let text = toml::to_string(&pack).unwrap();
    let (config, _) = NativePolicy::builder()
        .with_pack("delimiter-test", &text)
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(config.select_rules([id.as_str()]).unwrap())
        .build()
        .unwrap()
}

#[test]
fn delimiter_increments_have_exact_independent_bytes_spans_and_locations() {
    for case in CASES {
        for length in [case.min, case.max] {
            let secret = secret(case, length);
            for delimiter in ["\\'", "\\\"", "\\`", "\u{b}"] {
                let input = format!("lead\nx {}{secret}{delimiter}", case.context);
                // No assignment label is present. Every expected occurrence is
                // missing from the unchanged base, not just new attribution.
                assert!(
                    scan(base().engine(), input.as_bytes()).is_empty(),
                    "{}",
                    case.id
                );
                for engine in [selected(), composed().engine(), both_packs().engine()] {
                    let findings = scan(engine, input.as_bytes());
                    assert_eq!(findings.len(), 1, "{}, {length}, {delimiter:?}", case.id);
                    let finding = &findings[0];
                    let start = 7 + case.context.len();
                    assert_eq!(finding.rule_id().as_bytes(), case.id.as_bytes());
                    assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
                    assert_eq!(
                        finding.match_text().as_bytes(),
                        format!("{secret}{delimiter}").as_bytes()
                    );
                    assert_eq!(finding.secret_range(), exact(start, start + secret.len()));
                    assert_eq!(
                        finding.match_range(),
                        exact(start, start + secret.len() + delimiter.len())
                    );
                    assert_eq!(
                        finding.location(),
                        Location::new(
                            1,
                            1,
                            4 + case.context.len(),
                            3 + case.context.len() + secret.len() + delimiter.len()
                        )
                        .unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn ordinary_delimiters_remain_with_the_base_without_companion_duplicates() {
    for case in CASES {
        let secret = secret(case, case.min);
        for delimiter in [
            "", "'", "\"", "`", ";", " ", "\t", "\n", "\r", "\u{c}", "\\n", "\\r",
        ] {
            let input = format!("{}{}{}", case.context, secret, delimiter);
            assert!(
                scan(selected(), input.as_bytes()).is_empty(),
                "{}, {delimiter:?}",
                case.id
            );
            let before = scan(base().engine(), input.as_bytes());
            assert_eq!(before.len(), 1, "{}, {delimiter:?}", case.id);
            assert_eq!(before[0].secret().as_bytes(), secret.as_bytes());
            assert_eq!(scan(composed().engine(), input.as_bytes()), before);
            assert_eq!(scan(both_packs().engine(), input.as_bytes()), before);
        }
    }
}

#[test]
fn delimiters_body_bounds_ascii_and_malformed_bytes_reject_near_misses() {
    for case in CASES {
        let value = secret(case, case.min);
        for length in [case.min - 1, case.max + 1] {
            let input = format!("{}{}\\\"", case.context, secret(case, length));
            assert!(
                scan(selected(), input.as_bytes()).is_empty(),
                "{}, length {length}",
                case.id
            );
        }
        for delimiter in ["\\\\\"", "\\x", "\\", "?", "\u{a0}", "\u{2028}"] {
            let input = format!("{}{value}{delimiter}", case.context);
            assert!(
                scan(selected(), input.as_bytes()).is_empty(),
                "{}, {delimiter:?}",
                case.id
            );
        }
        let embedded = format!("{}_{value}\\\"", case.context);
        assert!(scan(selected(), embedded.as_bytes()).is_empty());
        for replacement in ["!", "\u{17f}", "\u{212a}", "\u{e9}"] {
            let at = case.prefix.len() + 2;
            let invalid = format!(
                "{}{}{replacement}{}\\\"",
                case.context,
                &value[..at],
                &value[at + 1..]
            );
            assert!(
                scan(selected(), invalid.as_bytes()).is_empty(),
                "{}, {replacement:?}",
                case.id
            );
        }
        let mut invalid = format!("{}{value}\\\"", case.context).into_bytes();
        invalid[case.context.len() + case.prefix.len() + 2] = 0xff;
        assert!(scan(selected(), &invalid).is_empty(), "{}", case.id);
        let upper = format!("{}{}\\\"", case.context, value.to_ascii_uppercase());
        // The Bedrock prefix is already uppercase and its body permits both
        // ASCII cases. Uppercasing this value preserves the source grammar.
        let expected = usize::from(
            case.id == "rustleaks.planetscale-password-delimiter"
                || case.prefix == "ABSK"
                || case.prefix == "API-"
                || case.prefix == "EAAA",
        );
        assert_eq!(
            scan(selected(), upper.as_bytes()).len(),
            expected,
            "{}",
            case.id
        );
        if case.prefix == "ABSK" {
            let lower_prefix = format!("absk{}\\\"", &value[4..]);
            assert!(scan(selected(), lower_prefix.as_bytes()).is_empty());
        }
    }
}

#[test]
fn retained_alternatives_and_character_classes_have_explicit_controls() {
    for (id, value) in [
        (
            "rustleaks.aws-amazon-bedrock-api-key-long-lived-delimiter",
            format!("ABSK{}+/==", "Q7m2Z9v4L1c8R5s0N6b3X".repeat(6)),
        ),
        (
            "rustleaks.intra42-client-secret-delimiter",
            format!("s-s4t2af-{}", "A7F2B9E4C1D80563".repeat(4)),
        ),
        (
            "rustleaks.planetscale-oauth-token-delimiter",
            format!("pscale_oauth_{}_=.-", "Q7m2Z9v4L1c8R5s0N6b3X".repeat(2)),
        ),
        (
            "rustleaks.planetscale-password-delimiter",
            format!("PSCALE_PW_{}_=.-", "Q7m2Z9v4L1c8R5s0N6b3X".repeat(2)),
        ),
        (
            "rustleaks.shippo-api-token-delimiter",
            format!(
                "shippo_test_{}",
                "A7F2B9E4C1D80563"
                    .chars()
                    .cycle()
                    .take(40)
                    .collect::<String>()
            ),
        ),
    ] {
        let input = format!("{value}\\\"");
        let findings = scan(selected(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{id}");
        assert_eq!(findings[0].rule_id().as_bytes(), id.as_bytes());
        assert_eq!(findings[0].secret().as_bytes(), value.as_bytes());
    }
    let bedrock = format!("ABSK{}===\\\"", "Q7m2Z9v4L1c8R5s0N6b3X".repeat(6));
    assert!(scan(selected(), bedrock.as_bytes()).is_empty());
    let legacy = format!(
        "s.{}",
        "Q7m2Z9v4L1c8R5s0N6b3X"
            .chars()
            .cycle()
            .take(24)
            .collect::<String>()
    );
    assert!(scan(selected(), format!("{legacy}\\\"").as_bytes()).is_empty());
    assert_eq!(
        scan(selected(), format!("vault {legacy}\\\"").as_bytes()).len(),
        1
    );
    // The source letter-only exclusion is retained for the legacy Vault form.
    let excluded = format!(
        "vault s.{}\\\"",
        "QmZvLcRsNbXhYpTfJgWd"
            .chars()
            .cycle()
            .take(24)
            .collect::<String>()
    );
    assert!(scan(selected(), excluded.as_bytes()).is_empty());
    // Reviewed upstream example exclusion, not a live credential.
    let gcp = b"AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs\\\"";
    assert!(scan(selected(), gcp).is_empty());
    let mut no_gcp_exclusions = rule_value("rustleaks.gcp-api-key-delimiter");
    no_gcp_exclusions
        .as_table_mut()
        .unwrap()
        .remove("allowlists");
    assert_eq!(scan(&one_rule(no_gcp_exclusions), gcp).len(), 1);
}

#[test]
fn repeated_and_adjacent_occurrences_preserve_raw_byte_geometry() {
    for case in CASES {
        let value = secret(case, case.min);
        let mut input = b"\xff\n".to_vec();
        input.extend_from_slice(case.context.as_bytes());
        let first = input.len();
        input.extend_from_slice(value.as_bytes());
        input.extend_from_slice(b"\\\"");
        // Adjacent next token starts after the consumed quote. The byte word
        // boundary is valid and no lookaround or shared delimiter is needed.
        let second = input.len();
        input.extend_from_slice(value.as_bytes());
        input.extend_from_slice(b"\x0b\xfe");
        let findings = scan(selected(), &input);
        assert_eq!(findings.len(), 2, "{}", case.id);
        for (index, (start, width)) in [(first, 2), (second, 1)].into_iter().enumerate() {
            assert_eq!(
                findings[index].secret_range(),
                exact(start, start + value.len())
            );
            assert_eq!(
                findings[index].match_range(),
                exact(start, start + value.len() + width)
            );
            assert_eq!(findings[index].secret().as_bytes(), value.as_bytes());
            assert_eq!(findings[index].rule_id().as_bytes(), case.id.as_bytes());
        }
        let collision = format!("api_key = '{value}\\\"'");
        // Compare occurrence geometry rather than treating any attribution as
        // a new secret. The companion and inherited generic may cover one span.
        let composed_findings = scan(composed().engine(), collision.as_bytes());
        if case.context.is_empty() {
            assert!(
                composed_findings
                    .iter()
                    .any(|f| f.rule_id().as_bytes() == case.id.as_bytes()
                        && f.secret_range() == exact(11, 11 + value.len()))
            );
            let occurrences: std::collections::BTreeSet<_> = composed_findings
                .iter()
                .map(|f| f.secret_range().exact().unwrap().as_range().start)
                .collect();
            assert_eq!(occurrences, std::collections::BTreeSet::from([11]));
        }
    }
}

#[test]
fn source_le_entropy_rejects_exact_threshold_and_preserves_selected_metadata() {
    let (config, _) = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .compile()
        .unwrap();
    for id in IDS {
        let mut rule = rule_value(id);
        let threshold = rule["entropy"]["threshold"].as_float().unwrap();
        let expected = Some(("byte-shannon-f64-v1", "le", threshold));
        assert_eq!(config.rule(id).unwrap().native_entropy(), expected);
        assert_eq!(
            config
                .select_rules([id])
                .unwrap()
                .rule(id)
                .unwrap()
                .native_entropy(),
            expected
        );
        rule["regex"] = toml::Value::String("([A-Z]{4,800})".into());
        rule["keywords"] = toml::Value::Array(vec![]);
        rule.as_table_mut().unwrap().remove("allowlists");
        let engine = one_rule(rule);
        let (equal, above) = match threshold {
            2.0 => ("ABCD", "ABCDE"),
            3.0 => ("ABCDEFGH", "ABCDEFGHI"),
            3.5 => ("ABCDEFGHIIJJKKLL", "ABCDEFGHIMJJKKLL"),
            4.0 => ("ABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOPQ"),
            _ => panic!("unreviewed threshold"),
        };
        assert!(scan(&engine, b"AAAAAAAAAAAAAAAA").is_empty());
        assert!(scan(&engine, equal.as_bytes()).is_empty(), "{id}");
        assert_eq!(scan(&engine, above.as_bytes()).len(), 1, "{id}");
        if threshold.to_bits() == 3.0_f64.to_bits() {
            let witness: String = ('A'..='H')
                .flat_map(|c| std::iter::repeat_n(c, 49))
                .collect();
            assert_eq!(witness.len(), 392);
            assert!(scan(&engine, witness.as_bytes()).is_empty());
        }
    }
}

#[test]
fn independently_scoped_source_predicates_preserve_case_and_go_whitespace() {
    for id in IDS {
        let mut rule = rule_value(id);
        let regexes = rule["allowlists"][0]["regexes"].as_array().unwrap();
        let local = if id == "rustleaks.gcp-api-key-delimiter" {
            16
        } else {
            usize::from(id == "rustleaks.vault-service-token-delimiter")
        };
        assert_eq!(regexes.len(), 13 + local);
        assert!(
            regexes
                .iter()
                .all(|value| value.as_str().unwrap().starts_with("(?:"))
        );
        assert_eq!(
            rule["allowlists"][0]["stopwords"].as_array().unwrap().len(),
            2
        );
        // Isolate the source predicates from the inherited native global
        // policy. Deliberately broaden the fixture capture and remove entropy;
        // this tests each predicate's semantics, not an extra token language.
        rule["regex"] = toml::Value::String("(.+)".into());
        rule["keywords"] = toml::Value::Array(vec![]);
        rule.as_table_mut().unwrap().remove("entropy");
        let mut pack: toml::Value = toml::from_str("title='predicate fixture'\n").unwrap();
        pack.as_table_mut()
            .unwrap()
            .insert("rules".into(), toml::Value::Array(vec![rule]));
        let raw: RawConfig = toml::from_str(&toml::to_string(&pack).unwrap()).unwrap();
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        for rejected in [
            "/Users/synthetic/project",
            "/bin/synthetic",
            "{{ A B }}",
            "FALSE",
            "abcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(
                scan(&engine, rejected.as_bytes()).is_empty(),
                "{id}, {rejected}"
            );
        }
        for retained in [
            "/users/synthetic/project",
            "/BIN/synthetic",
            "{{ A\u{b}B }}",
            "ordinary_synthetic_value",
        ] {
            assert_eq!(
                scan(&engine, retained.as_bytes()).len(),
                1,
                "{id}, {retained}"
            );
        }
    }
}

fn assert_rule_allowlists_reject(case: Case, input: &str) {
    for condition in [
        "regexTarget='secret'\nregexes=['.']",
        "regexTarget='match'\nregexes=['.']",
        "regexTarget='line'\nregexes=['.']",
        "stopwords=['q7m2']",
        "paths=['^synthetic[.]conf$']",
        "commits=['synthetic-commit']",
    ] {
        let mut rule = rule_value(case.id);
        // The stopword is taken from the independent positive alphabet so
        // hex-only and letters-only cases receive a meaningful control.
        let condition = condition.replace("q7m2", &case.alphabet[..4].to_ascii_lowercase());
        let allowlist: toml::Value = toml::from_str(&condition).unwrap();
        rule.as_table_mut()
            .unwrap()
            .insert("allowlists".into(), toml::Value::Array(vec![allowlist]));
        let engine = one_rule(rule);
        let fragment = Fragment::builder(input.as_bytes())
            .start_line(0)
            .file_path("synthetic.conf")
            .commit("synthetic-commit")
            .build();
        assert!(
            engine
                .scan_fragment(&fragment, &ScanOptions::default())
                .findings()
                .is_empty()
        );
    }
}

#[test]
fn exclusions_keyword_selection_and_finite_budgets_apply_before_admission() {
    for case in CASES {
        let value = secret(case, case.min);
        let input = format!("{}{value}\\\"", case.context);
        for path in [
            "synthetic.pdf",
            "node_modules/synthetic.js",
            "gitleaks.toml",
        ] {
            let fragment = Fragment::builder(input.as_bytes())
                .start_line(0)
                .file_path(path)
                .build();
            assert!(
                selected()
                    .scan_fragment(&fragment, &ScanOptions::default())
                    .findings()
                    .is_empty()
            );
        }
        let bun = Fragment::builder(input.as_bytes())
            .start_line(0)
            .file_path("bun.lock")
            .build();
        assert_eq!(
            selected()
                .scan_fragment(&bun, &ScanOptions::default())
                .findings()
                .len(),
            1
        );
        assert!(scan(selected(), format!("{input} # rustleaks:allow").as_bytes()).is_empty());
        let mut keyword = rule_value(case.id);
        keyword["keywords"] =
            toml::Value::Array(vec![toml::Value::String("required_context_marker".into())]);
        let keyword_engine = one_rule(keyword);
        assert!(scan(&keyword_engine, input.as_bytes()).is_empty());
        assert_eq!(
            scan(
                &keyword_engine,
                format!("required_context_marker {input}").as_bytes()
            )
            .len(),
            1
        );
        assert_rule_allowlists_reject(case, &input);
        let mut global = rule_value(case.id);
        global["regex"] = toml::Value::String("(false[A-Za-z0-9]{64})".into());
        global["keywords"] = toml::Value::Array(vec![]);
        let global_engine = one_rule(global);
        let excluded = format!(
            "false{}",
            "Q7m2Z9v4L1c8R5s0N6b3X"
                .chars()
                .cycle()
                .take(64)
                .collect::<String>()
        );
        assert!(scan(&global_engine, excluded.as_bytes()).is_empty());
        for budget in [
            ScanBudget::unlimited().max_finding_records(0),
            ScanBudget::unlimited().max_work_units(1),
            ScanBudget::unlimited().max_finding_payload_bytes(1),
        ] {
            let result = selected().scan_fragment_controlled(
                &Fragment::builder(input.as_bytes()).start_line(0).build(),
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!result.is_complete());
            assert!(result.findings().is_empty());
        }
        let ordinary = format!("{}{value};", case.context);
        let result = selected().scan_fragment_controlled(
            &Fragment::builder(ordinary.as_bytes()).start_line(0).build(),
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(0)),
        );
        assert!(result.is_complete());
        assert_eq!(result.usage().finding_records(), 0);
    }
}
