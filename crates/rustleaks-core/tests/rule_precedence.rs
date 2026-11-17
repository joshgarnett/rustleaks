//! Every reviewed positive rule case keeps its exact finding when the pinned
//! default rules and every packaged native pack are active together.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, ScanOptions};
use rustleaks_core::native::{
    CONNECTION_RULES_V1, EXTRA_RULES_V1, NativeEngine, NativePolicy, PROVIDER_RULES_V1,
};
use serde_json::Value;

struct Expected {
    rule: String,
    secret: Vec<u8>,
    matched: Option<Vec<u8>>,
    secret_range: Option<[usize; 2]>,
}

struct Positive {
    name: String,
    rule: String,
    input: Vec<u8>,
    path: Option<Vec<u8>>,
    decode_depth: usize,
    expected: Vec<Expected>,
}

fn all_rules() -> &'static NativeEngine {
    static ENGINE: OnceLock<NativeEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        NativePolicy::builder()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap()
            .build()
            .unwrap()
    })
}

fn decode(text: &str) -> Vec<u8> {
    STANDARD.decode(text).unwrap()
}

fn range(value: &Value) -> Option<[usize; 2]> {
    let pair = value.as_array()?;
    Some([
        usize::try_from(pair[0].as_u64().unwrap()).unwrap(),
        usize::try_from(pair[1].as_u64().unwrap()).unwrap(),
    ])
}

fn default_positives() -> Vec<Positive> {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/generator-corpus/samples-v1.jsonl");
    fs::read_to_string(corpus)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|sample| {
            matches!(
                sample["polarity"].as_str().unwrap(),
                "ordinary_true" | "path_true"
            )
        })
        .map(|sample| {
            let rule = sample["rule_id"].as_str().unwrap().to_owned();
            Positive {
                name: sample["case_id"].as_str().unwrap().to_owned(),
                input: decode(sample["input_base64"].as_str().unwrap()),
                path: sample["path_base64"].as_str().map(decode),
                decode_depth: 0,
                expected: sample["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|finding| Expected {
                        rule: rule.clone(),
                        secret: decode(finding["secret_base64"].as_str().unwrap()),
                        matched: Some(decode(finding["match_base64"].as_str().unwrap())),
                        secret_range: None,
                    })
                    .collect(),
                rule,
            }
        })
        .collect()
}

fn flat_positive(case: &Value) -> Positive {
    let rule = case["rule"].as_str().unwrap().to_owned();
    Positive {
        name: case["name"].as_str().unwrap().to_owned(),
        input: decode(case["input_base64"].as_str().unwrap()),
        path: Some(case["path"].as_str().unwrap().as_bytes().to_vec()),
        decode_depth: 0,
        expected: vec![Expected {
            rule: rule.clone(),
            secret: case["secret"].as_str().unwrap().as_bytes().to_vec(),
            matched: Some(case["match"].as_str().unwrap().as_bytes().to_vec()),
            secret_range: range(&case["secret_range"]),
        }],
        rule,
    }
}

fn record_positive(case: &Value) -> Positive {
    let rule = case["rule"].as_str().unwrap().to_owned();
    let expected = case["expected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            let encoded = record.get("secret_base64").and_then(Value::as_str);
            Expected {
                rule: record
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or(&rule)
                    .to_owned(),
                secret: encoded.map_or_else(
                    || record["secret"].as_str().unwrap().as_bytes().to_vec(),
                    decode,
                ),
                matched: record
                    .get("match_base64")
                    .and_then(Value::as_str)
                    .map(decode)
                    .or_else(|| {
                        record
                            .get("match")
                            .and_then(Value::as_str)
                            .map(|text| text.as_bytes().to_vec())
                    }),
                secret_range: range(&record["secret_range"]),
            }
        })
        .collect();
    Positive {
        name: case["name"].as_str().unwrap().to_owned(),
        input: decode(case["input_base64"].as_str().unwrap()),
        path: Some(case["path"].as_str().unwrap().as_bytes().to_vec()),
        decode_depth: case
            .get("decode_depth")
            .and_then(Value::as_u64)
            .map_or(0, |depth| usize::try_from(depth).unwrap()),
        expected,
        rule,
    }
}

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn pack_positives() -> Vec<Positive> {
    let mut positives = Vec::new();
    let additional = fixture(include_str!("support/additional_coverage.json"));
    positives.extend(
        additional["primary"]
            .as_array()
            .unwrap()
            .iter()
            .map(flat_positive),
    );
    let format = fixture(include_str!("support/format_coverage.json"));
    positives.extend(
        format["primary"]
            .as_array()
            .unwrap()
            .iter()
            .map(flat_positive),
    );
    let special = fixture(include_str!("support/special_coverage.json"));
    positives.extend(
        special["primary"]
            .as_array()
            .unwrap()
            .iter()
            .map(record_positive),
    );
    let association = fixture(include_str!("support/association_coverage.json"));
    positives.extend(
        association["primary"]
            .as_array()
            .unwrap()
            .iter()
            .map(record_positive),
    );
    let remaining = fixture(include_str!("support/remaining_verified_rules.json"));
    let names = remaining["primary_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    positives.extend(
        remaining["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| names.contains(case["name"].as_str().unwrap()))
            .map(record_positive),
    );
    positives
}

fn exact(range: [usize; 2]) -> FindingRange {
    FindingRange::Exact(ByteRange::new(range[0], range[1]).unwrap())
}

fn satisfies(finding: &Finding, expected: &Expected) -> bool {
    finding.rule_id().as_bytes() == expected.rule.as_bytes()
        && finding.secret().as_bytes() == expected.secret.as_slice()
        && expected
            .matched
            .as_ref()
            .is_none_or(|matched| finding.match_text().as_bytes() == matched.as_slice())
        && expected
            .secret_range
            .is_none_or(|range| finding.secret_range() == exact(range))
}

fn scan(positive: &Positive) -> Vec<Finding> {
    let mut fragment = Fragment::builder(positive.input.clone());
    if let Some(path) = &positive.path {
        fragment = fragment.file_path(path.clone());
    }
    let outcome = all_rules().engine().scan_fragment(
        &fragment.build(),
        &ScanOptions::builder()
            .max_decode_depth(positive.decode_depth)
            .build(),
    );
    assert!(outcome.is_complete(), "{}", positive.name);
    outcome.findings().to_vec()
}

/// Reviewed rule pairs that may both report on one positive case. The first
/// rule owns the case. The second rule adds its own finding next to the
/// owner's exact finding; it never replaces it.
const INTENDED_OVERLAPS: &[(&str, &str, &str)] = &[
    // Pinned default rules whose patterns accept the same token shape.
    (
        "artifactory-api-key",
        "jfrog-api-key",
        "default rules for one JFrog key format",
    ),
    (
        "artifactory-reference-token",
        "jfrog-identity-token",
        "default rules for one JFrog token format",
    ),
    (
        "bittrex-access-key",
        "bittrex-secret-key",
        "identical default patterns",
    ),
    (
        "bittrex-secret-key",
        "bittrex-access-key",
        "identical default patterns",
    ),
    ("curl-auth-header", "jwt", "the header value is a JWT"),
    (
        "curl-auth-header",
        "openai-api-key",
        "the header value is an OpenAI key",
    ),
    (
        "curl-auth-header",
        "openshift-user-token",
        "the header value is an OpenShift token",
    ),
    (
        "flutterwave-secret-key",
        "flutterwave-encryption-key",
        "the encryption key pattern also accepts the secret key sample",
    ),
    (
        "generic-api-key",
        "clojars-api-token",
        "the generic sample value is a Clojars token",
    ),
    (
        "gitlab-pat-routable",
        "gitlab-pat",
        "a routable token starts with a classic token",
    ),
    (
        "gitlab-runner-authentication-token-routable",
        "gitlab-runner-authentication-token",
        "a routable token starts with a classic token",
    ),
    ("jwt", "curl-auth-header", "the JWT sample is a curl header"),
    // Opt-in pack rules that widen a default rule. Both findings are kept.
    (
        "alibaba-access-key-id",
        "rustleaks.alibaba-access-key-id-boundary",
        "pack boundary variant of the default rule",
    ),
    (
        "flyio-access-token",
        "rustleaks.flyio-flyv1",
        "pack rule for the FlyV1 form",
    ),
    (
        "grafana-api-key",
        "rustleaks.grafana-api-key-base64",
        "pack rule for standard Base64 bodies",
    ),
    (
        "rustleaks.association.aws-session-token",
        "aws-access-token",
        "the session token sample also holds an access key ID",
    ),
    (
        "rustleaks.gitlab-pat-routable-versioned",
        "gitlab-pat",
        "a versioned token starts with a classic token",
    ),
    (
        "rustleaks.monday-api-token",
        "jwt",
        "a Monday token is a JWT",
    ),
    (
        "rustleaks.slack-config-refresh-token-147",
        "slack-config-refresh-token",
        "the default rule matches a prefix of the longer body",
    ),
];

/// Reviewed cases where another rule's finding replaces the owner's finding.
/// Upstream drops a finding of a rule whose ID contains `generic` when a
/// finding of a non-generic rule starts on the same line and its secret
/// contains the generic secret.
const INTENDED_OVERRIDES: &[(&str, &str)] = &[("generic-api-key", "clojars-api-token")];

fn is_generic(rule: &[u8]) -> bool {
    rule.to_ascii_lowercase()
        .windows(b"generic".len())
        .any(|window| window == b"generic")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The upstream generic suppression predicate, written from its definition.
fn suppresses(specific: &Finding, rule: &str, secret: &[u8], start_line: usize) -> bool {
    !is_generic(specific.rule_id().as_bytes())
        && specific.rule_id().as_bytes() != rule.as_bytes()
        && specific.location().start_line() == start_line
        && contains(specific.secret().as_bytes(), secret)
}

fn rule_text(finding: &Finding) -> String {
    String::from_utf8_lossy(finding.rule_id().as_bytes()).into_owned()
}

#[test]
fn every_positive_case_keeps_its_exact_finding_with_all_rules_active() {
    let defaults = default_positives();
    let packs = pack_positives();
    assert_eq!(defaults.len(), 6_396);
    assert_eq!(packs.len(), 179);
    assert_eq!(
        all_rules().engine().config().rules().len(),
        222 + 303 + 14 + 3
    );

    let overlaps = INTENDED_OVERLAPS
        .iter()
        .map(|(owner, other, _)| (*owner, *other))
        .collect::<BTreeSet<_>>();
    assert_eq!(overlaps.len(), INTENDED_OVERLAPS.len());
    let mut seen_overlaps = BTreeSet::new();
    let mut seen_overrides = BTreeSet::new();
    let mut failures = Vec::new();
    for positive in defaults.iter().chain(&packs) {
        assert!(!positive.expected.is_empty(), "{}", positive.name);
        let findings = scan(positive);
        let mut claimed = vec![false; findings.len()];
        for expected in &positive.expected {
            if let Some(index) = (0..findings.len())
                .find(|index| !claimed[*index] && satisfies(&findings[*index], expected))
            {
                claimed[index] = true;
                continue;
            }
            // The owner's finding is absent. Accept only a reviewed override
            // whose replacement reports the same secret.
            let replacement = findings.iter().position(|finding| {
                INTENDED_OVERRIDES.contains(&(expected.rule.as_str(), rule_text(finding).as_str()))
                    && finding.secret().as_bytes() == expected.secret.as_slice()
            });
            match replacement {
                Some(index) if is_generic(expected.rule.as_bytes()) => {
                    claimed[index] = true;
                    seen_overrides.insert(expected.rule.clone());
                }
                _ => failures.push(format!(
                    "{}: {} finding is missing",
                    positive.name, expected.rule
                )),
            }
        }
        for (index, finding) in findings.iter().enumerate() {
            let rule = rule_text(finding);
            if is_generic(rule.as_bytes()) {
                // A generic rule reports beside specific rules unless the
                // upstream suppression applies, which must have removed it.
                if findings.iter().any(|other| {
                    suppresses(
                        other,
                        &rule,
                        finding.secret().as_bytes(),
                        finding.location().start_line(),
                    )
                }) {
                    failures.push(format!(
                        "{}: {rule} finding was not suppressed",
                        positive.name
                    ));
                }
                continue;
            }
            if claimed[index] {
                continue;
            }
            if overlaps.contains(&(positive.rule.as_str(), rule.as_str())) {
                seen_overlaps.insert((positive.rule.clone(), rule));
            } else {
                failures.push(format!("{}: unreviewed {rule} finding", positive.name));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    // Every reviewed entry is still needed.
    assert_eq!(seen_overlaps.len(), overlaps.len());
    assert_eq!(seen_overrides.len(), INTENDED_OVERRIDES.len());
}
