//! Reviewed rule overlaps: when two rules report the same secret at the same
//! place, only one finding is reported. Covers the `[[overlaps]]` loader
//! checks, the engine filter, and each reviewed pair in the built-in rules.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, ScanOptions};
use rustleaks_core::native::{
    CONNECTION_RULES_V1, EXTRA_RULES_V1, NativePolicy, NativePolicyError, PROVIDER_RULES_V1,
};
use rustleaks_core::{Engine, ScanControl};

const KEEP: &str = "rustleaks.example-keep";
const DROP: &str = "rustleaks.example-drop";

/// Two rules that accept the same token: `keep` needs a `use=` prefix.
const RULES: &str = r#"
[[rules]]
id = "rustleaks.example-keep"
regex = '''use=(tok_[A-Z0-9]{8})\b'''
secretGroup = 1
keywords = ["tok_"]

[[rules.allowlists]]
regexTarget = "secret"
regexes = ['''ALLOWED''']

[[rules]]
id = "rustleaks.example-drop"
regex = '''\b(tok_[A-Z0-9]{8})\b'''
secretGroup = 1
keywords = ["tok_"]
"#;

const OVERLAP: &str = r#"
[[overlaps]]
description = "The keep rule names the same token"
keep = "rustleaks.example-keep"
drop = "rustleaks.example-drop"
"#;

fn pack(extra: &str) -> String {
    format!("{RULES}{extra}")
}

fn engine(contents: &str) -> Engine {
    NativePolicy::builder()
        .with_pack("example-v1", contents)
        .unwrap()
        .build()
        .unwrap()
        .engine()
        .clone()
}

fn scan(engine: &Engine, input: &str) -> Vec<Finding> {
    let outcome = engine.scan_fragment(&Fragment::new(input.as_bytes()), &ScanOptions::default());
    assert!(outcome.is_complete());
    outcome.findings().to_vec()
}

fn exact(start: usize, end: usize) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

/// Rule ID, secret and secret range of each finding, in report order.
fn summary(findings: &[Finding]) -> Vec<(String, String, FindingRange)> {
    findings
        .iter()
        .map(|finding| {
            (
                String::from_utf8(finding.rule_id().as_bytes().to_vec()).unwrap(),
                String::from_utf8(finding.secret().as_bytes().to_vec()).unwrap(),
                finding.secret_range(),
            )
        })
        .collect()
}

fn found(rule: &str, secret: &str, start: usize) -> (String, String, FindingRange) {
    (
        rule.to_owned(),
        secret.to_owned(),
        exact(start, start + secret.len()),
    )
}

#[test]
fn without_an_overlap_both_rules_report_the_same_secret() {
    let findings = scan(&engine(&pack("")), "use=tok_AB12CD34");
    assert_eq!(
        summary(&findings),
        [
            found(DROP, "tok_AB12CD34", 4),
            found(KEEP, "tok_AB12CD34", 4)
        ]
    );
}

#[test]
fn an_overlap_keeps_one_finding_for_the_same_secret_at_the_same_place() {
    let engine = engine(&pack(OVERLAP));
    assert_eq!(
        summary(&scan(&engine, "use=tok_AB12CD34")),
        [found(KEEP, "tok_AB12CD34", 4)]
    );
    // Where only the dropped rule matches, it still reports.
    assert_eq!(
        summary(&scan(&engine, "tok_AB12CD34")),
        [found(DROP, "tok_AB12CD34", 0)]
    );
    // The same secret at another place is a separate occurrence.
    assert_eq!(
        summary(&scan(&engine, "use=tok_AB12CD34 tok_AB12CD34")),
        [
            found(DROP, "tok_AB12CD34", 17),
            found(KEEP, "tok_AB12CD34", 4)
        ]
    );
    // A cancellable scan that is not cancelled gives the same result.
    let cancel = AtomicBool::new(false);
    let outcome = engine.scan_fragment_controlled(
        &Fragment::new(b"use=tok_AB12CD34 tok_ZZ99YY88"),
        &ScanOptions::default(),
        &ScanControl::cancellable(&cancel),
    );
    assert!(outcome.is_complete());
    assert_eq!(
        summary(outcome.findings()),
        [
            found(DROP, "tok_ZZ99YY88", 17),
            found(KEEP, "tok_AB12CD34", 4)
        ]
    );
}

#[test]
fn an_overlap_never_hides_a_secret_that_the_kept_rule_does_not_report() {
    let engine = engine(&pack(OVERLAP));
    // The kept rule's allowlist drops its finding, so the other rule reports.
    assert_eq!(
        summary(&scan(&engine, "use=tok_ALLOWED1")),
        [found(DROP, "tok_ALLOWED1", 4)]
    );
    // A selection without the kept rule reports the dropped rule.
    let (config, _) = NativePolicy::builder()
        .with_pack("example-v1", &pack(OVERLAP))
        .unwrap()
        .compile()
        .unwrap();
    let selected = Engine::builder(config.select_rules([DROP]).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        summary(&scan(&selected, "use=tok_AB12CD34")),
        [found(DROP, "tok_AB12CD34", 4)]
    );
    // With redaction, the comparison still uses the original secrets.
    let outcome = engine.scan_fragment(
        &Fragment::new(b"use=tok_AB12CD34"),
        &ScanOptions::builder().redaction_percent(100).build(),
    );
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(outcome.findings()[0].rule_id().as_bytes(), KEEP.as_bytes());
}

#[test]
fn an_overlap_can_name_a_default_rule_and_needs_reporting_rules() {
    // `stripe-access-token` is a default rule.
    let stripe = r#"
[[rules]]
id = "rustleaks.example-issuer"
regex = '''issuer=(sk_live_[A-Za-z0-9]{24})\b'''
secretGroup = 1
keywords = ["issuer="]

[[overlaps]]
keep = "rustleaks.example-issuer"
drop = "stripe-access-token"
"#;
    // Built at run time so the source holds no key-shaped literal.
    let secret = &format!("sk_live_{}", body(24));
    let findings = scan(&engine(stripe), &format!("issuer={secret}\n"));
    assert_eq!(
        summary(&findings),
        [found("rustleaks.example-issuer", secret, 7)]
    );
    let findings = scan(&engine(stripe), &format!("other={secret}\n"));
    assert_eq!(
        summary(&findings),
        [found("stripe-access-token", secret, 6)]
    );

    let helper = r#"
[[rules]]
id = "rustleaks.example-helper"
regex = '''(tok_[A-Z0-9]{8})'''
skipReport = true
"#;
    let skipped = format!(
        "{RULES}{helper}\n[[overlaps]]\nkeep = \"rustleaks.example-helper\"\ndrop = \"{DROP}\"\n"
    );
    assert!(matches!(
        NativePolicy::builder()
            .with_pack("example-v1", &skipped)
            .unwrap()
            .build(),
        Err(NativePolicyError::InvalidNativeOverlap)
    ));
}

#[test]
fn overlap_entries_are_checked_when_a_pack_is_added() {
    let add = |overlaps: &str| {
        // A top-level key must come before the first table header.
        let contents = if overlaps.starts_with("overlaps") {
            format!("{overlaps}{RULES}")
        } else {
            pack(overlaps)
        };
        NativePolicy::builder()
            .with_pack("example-v1", &contents)
            .map(|_| ())
    };
    let entry = |body: &str| format!("\n[[overlaps]]\n{body}\n");
    for (overlaps, expected) in [
        (
            entry("keep = \"rustleaks.example-keep\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            entry("keep = \"rustleaks.example-keep\"\ndrop = \"rustleaks.example-keep\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            entry("keep = \"jwt\"\ndrop = \"stripe-access-token\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            entry("keep = 1\ndrop = \"rustleaks.example-drop\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            entry("keep = \"bad id\"\ndrop = \"rustleaks.example-drop\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        // The generic filter could remove the kept finding, so a rule with
        // `generic` in its ID takes no part in an overlap.
        (
            entry("keep = \"rustleaks.Generic-keep\"\ndrop = \"rustleaks.example-drop\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            entry("keep = \"rustleaks.example-keep\"\ndrop = \"generic-api-key\""),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            format!("{OVERLAP}{OVERLAP}"),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            "overlaps = \"rustleaks.example-keep\"\n".to_owned(),
            NativePolicyError::InvalidNativeOverlap,
        ),
        (
            entry(
                "keep = \"rustleaks.example-keep\"\ndrop = \"rustleaks.example-drop\"\nreason = \"x\"",
            ),
            NativePolicyError::UnknownPackField,
        ),
        (
            entry(
                "keep = \"rustleaks.example-keep\"\nKeep = \"rustleaks.example-keep\"\ndrop = \"rustleaks.example-drop\"",
            ),
            NativePolicyError::AmbiguousPackField,
        ),
    ] {
        let error = add(&overlaps).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected),
            "{overlaps}"
        );
    }
    add(OVERLAP).unwrap();
}

#[test]
fn overlap_entries_are_checked_against_the_whole_composition() {
    let build = |overlaps: &str| {
        NativePolicy::builder()
            .with_pack("example-v1", &pack(overlaps))
            .unwrap()
            .build()
            .map(|_| ())
    };
    // A rule that is not in the composition.
    assert!(matches!(
        build("\n[[overlaps]]\nkeep = \"rustleaks.missing\"\ndrop = \"rustleaks.example-drop\"\n"),
        Err(NativePolicyError::InvalidNativeOverlap)
    ));
    // A dropped rule cannot keep its finding over a third rule.
    assert!(matches!(
        build(&format!(
            "{OVERLAP}\n[[overlaps]]\nkeep = \"rustleaks.example-drop\"\ndrop = \"jwt\"\n"
        )),
        Err(NativePolicyError::InvalidNativeOverlap)
    ));
    // The same pair from two packs, each holding one of the rules.
    let half = |id: &str| {
        format!("[[rules]]\nid = \"rustleaks.example-{id}\"\nregex = '''tok_{id}'''\n{OVERLAP}")
    };
    assert!(matches!(
        NativePolicy::builder()
            .with_pack("example-v1", &half("keep"))
            .unwrap()
            .with_pack("example-v2", &half("drop"))
            .unwrap()
            .build(),
        Err(NativePolicyError::InvalidNativeOverlap)
    ));
}

#[test]
fn a_disabled_kept_rule_takes_its_overlaps_with_it() {
    let secret = format!("eyJrIjoi{}", body(80));
    let input = format!("x {secret}\n");
    // A user rule reuses the ID of the disabled default rule.
    let config = ConfigLoader::new()
        .load_toml(
            r#"
[extend]
useDefault = true
disabledRules = ["grafana-api-key"]

[[rules]]
id = "grafana-api-key"
regex = '''\b(eyJrIjoi[A-Za-z0-9]{70,400})'''
secretGroup = 1
keywords = ["eyjrijoi"]
"#,
        )
        .unwrap();
    let engine = Engine::builder(config).build().unwrap();
    assert_eq!(
        rules_at(&engine, &input, &secret),
        sorted(&["grafana-api-key", "rustleaks.grafana-api-key-base64"])
    );
}

#[test]
fn a_configuration_file_cannot_declare_overlaps() {
    // The normal loader ignores an unknown top-level key, so both findings stay.
    let contents = format!(
        "{}{OVERLAP}",
        RULES.replace("rustleaks.example-", "example-")
    );
    let config = ConfigLoader::new().load_toml(&contents).unwrap();
    let engine = Engine::builder(config).build().unwrap();
    assert_eq!(scan(&engine, "use=tok_AB12CD34").len(), 2);
}

fn builtin() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(ConfigLoader::new().load_default().unwrap())
            .build()
            .unwrap()
    })
}

/// The built-in rules with the provider rule file's `[[overlaps]]` removed.
fn without_overlaps() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut providers: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
        assert!(
            providers
                .as_table_mut()
                .unwrap()
                .remove("overlaps")
                .is_some()
        );
        NativePolicy::builder()
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap()
            .with_pack(
                "rustleaks-providers-v1",
                &toml::to_string(&providers).unwrap(),
            )
            .unwrap()
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .build()
            .unwrap()
            .engine()
            .clone()
    })
}

/// The sorted rule IDs that report `secret` at its first place in `input`.
fn rules_at(engine: &Engine, input: &str, secret: &str) -> Vec<String> {
    let start = input.find(secret).unwrap();
    let mut rules: Vec<_> = summary(&scan(engine, input))
        .into_iter()
        .filter(|(_, found, range)| found == secret && *range == exact(start, start + secret.len()))
        .map(|(rule, _, _)| rule)
        .collect();
    rules.sort();
    rules
}

fn sorted(rules: &[&str]) -> Vec<String> {
    let mut rules: Vec<_> = rules.iter().map(|rule| (*rule).to_owned()).collect();
    rules.sort();
    rules
}

/// Checks that the built-in rules report `secret` at its first place in
/// `input` only from `kept`, and that without the reviewed overlaps
/// `dropped` also reports it there.
fn assert_replaced(input: &str, secret: &str, kept: &[&str], dropped: &str) {
    assert_eq!(rules_at(builtin(), input, secret), sorted(kept), "{input}");
    let mut both = kept.to_vec();
    both.push(dropped);
    assert_eq!(
        rules_at(without_overlaps(), input, secret),
        sorted(&both),
        "{input}"
    );
}

/// Checks that the built-in rules report `secret` at its first place in
/// `input` only from `rule`, with or without the reviewed overlaps.
fn assert_alone(input: &str, secret: &str, rule: &str) {
    for engine in [builtin(), without_overlaps()] {
        assert_eq!(rules_at(engine, input, secret), [rule], "{input}");
    }
}

fn body(length: usize) -> String {
    "H7q2M9v4R1x8B5n3T6z0DkWcYpSgJfUa"
        .chars()
        .cycle()
        .take(length)
        .collect()
}

fn lower(length: usize) -> String {
    "h7q2m9v4r1x8b5n3t6z0dkwcypsgjfua"
        .chars()
        .cycle()
        .take(length)
        .collect()
}

#[test]
fn the_default_rule_keeps_its_finding_for_the_same_credential() {
    let grafana = format!("eyJrIjoi{}", body(80));
    assert_replaced(
        &format!("x {grafana}\n"),
        &grafana,
        &["grafana-api-key"],
        "rustleaks.grafana-api-key-base64",
    );
    // `+` is outside the default rule's body.
    let grafana_plus = format!("eyJrIjoi{}+{}", body(40), body(39));
    assert_alone(
        &format!("x {grafana_plus}\n"),
        &grafana_plus,
        "rustleaks.grafana-api-key-base64",
    );

    let alibaba = format!("LTAI{}", body(20));
    assert_replaced(
        &format!("key={alibaba} "),
        &alibaba,
        &["alibaba-access-key-id"],
        "rustleaks.alibaba-access-key-id-boundary",
    );
    // The default rule needs exactly 20 bytes after `LTAI`.
    let alibaba_short = format!("LTAI{}", body(19));
    assert_alone(
        &format!("key={alibaba_short} "),
        &alibaba_short,
        "rustleaks.alibaba-access-key-id-boundary",
    );

    let planetscale = format!("pscale_tkn_{}", body(40));
    assert_replaced(
        &format!(
            "PLANETSCALE_USER={}\nPLANETSCALE_TOKEN={planetscale}\n",
            lower(12)
        ),
        &planetscale,
        &["planetscale-api-token"],
        "rustleaks.association.planetscale-api-token",
    );

    let artifactory = format!("AKCp{}", body(69));
    assert_replaced(
        &format!("url = https://acme.jfrog.io\napi = {artifactory}\n"),
        &artifactory,
        &["artifactory-api-key"],
        "rustleaks.association.artifactory-api-key",
    );
    // The default rule needs exactly 69 bytes after `AKCp`.
    let artifactory_70 = format!("AKCp{}", body(70));
    assert_alone(
        &format!("url = https://acme.jfrog.io\napi = {artifactory_70}\n"),
        &artifactory_70,
        "rustleaks.association.artifactory-api-key",
    );
    // The default JFrog rule takes 73 letters and digits after a JFrog name.
    // Both default rules then report the key; they are not a reviewed pair.
    let jfrog = format!("AKCp{}", lower(69));
    assert_replaced(
        &format!("url = https://acme.jfrog.io\njfrog_key = {jfrog}\n"),
        &jfrog,
        &["artifactory-api-key", "jfrog-api-key"],
        "rustleaks.association.artifactory-api-key",
    );

    let reference = format!("cmVmd{}", body(59));
    assert_replaced(
        &format!("url = https://acme.jfrog.io\ntoken = {reference}\n"),
        &reference,
        &["artifactory-reference-token"],
        "rustleaks.association.artifactory-reference-token",
    );
    let identity = format!("cmVmd{}", lower(59));
    assert_replaced(
        &format!("url = https://acme.jfrog.io\nartifactory_token = {identity}\n"),
        &identity,
        &["artifactory-reference-token", "jfrog-identity-token"],
        "rustleaks.association.artifactory-reference-token",
    );

    let incoming = format!("glimt-{}", lower(25));
    assert_replaced(
        &format!("reply to incoming+acme-42-{incoming}-issue@example.com\n"),
        &incoming,
        &["gitlab-incoming-mail-token"],
        "rustleaks.gitlab-incoming-mail-address-token",
    );

    let slack = format!("xoxe.xoxp-1-{}", body(166));
    assert_replaced(
        &format!("x {slack}\n"),
        &slack,
        &["slack-config-access-token"],
        "rustleaks.slack-config-access-token-166",
    );
    // The default rule allows one digit after `xoxp-`.
    let slack_two = format!("xoxe.xoxp-12-{}", body(166));
    assert_alone(
        &format!("x {slack_two}\n"),
        &slack_two,
        "rustleaks.slack-config-access-token-166",
    );

    let xai = format!("xai-{}", body(80));
    assert_replaced(
        &format!("key={xai};"),
        &xai,
        &["rustleaks.xai-api-key-delimiter"],
        "rustleaks.xai-api-key-80",
    );
}

#[test]
fn the_provider_rule_keeps_its_finding_over_a_broader_pattern() {
    let key = format!("sk_live_a2V5Xz{}", body(69));
    assert_replaced(
        &format!("WORKOS_API_KEY=\"{key}\"\n"),
        &key,
        &["rustleaks.workos-production-api-key"],
        "stripe-access-token",
    );
    assert_replaced(
        &format!("HIGHNOTE_SECRET_KEY=\"{key}\"\n"),
        &key,
        &["rustleaks.highnote-secret-live-key"],
        "stripe-access-token",
    );
    // Without the provider name, the Stripe rule still reports the key.
    assert_alone(
        &format!("OTHER_KEY=\"{key}\"\n"),
        &key,
        "stripe-access-token",
    );

    let clerk = format!("sk_live_{}", body(32));
    assert_replaced(
        &format!("CLERK_SECRET_KEY='{clerk}\\'\n"),
        &clerk,
        &["rustleaks.clerk-secret-key-delimiter"],
        "rustleaks.stripe-access-token-delimiter",
    );
    assert_alone(
        &format!("OTHER_KEY='{clerk}\\'\n"),
        &clerk,
        "rustleaks.stripe-access-token-delimiter",
    );

    // Base64url segments of a synthetic Temporal Cloud key.
    let temporal = [
        "eyJhbGciOiJFUzI1NiIsImtpZCI6Ikg3cTJNOXY0In0",
        ".eyJhY2NvdW50X2lkIjoiaDdxMm05IiwiaXNzIjoiInRlbXBvcmFsLmlvIiwia2V5X2lkIjoiSDdxMk05djRSMXg4QjVuMyJ9",
        ".H7q2M9v4R1x8B5n3T6z0DkWcYpSgJfUaH7q2M9v4R1x",
    ]
    .concat();
    assert_replaced(
        &format!("token: {temporal}\n"),
        &temporal,
        &["rustleaks.temporal-cloud-api-key"],
        "jwt",
    );

    let monday = [
        "eyJhbGciOiJIUzI1NiJ9",
        ".eyJ0aWQiOjQyLCJ1aWQiOjc3LCJpYWQiOiIyMDI2LTExLTIxVDAwOjAwOjAwWiIsInBlciI6Im1lOndyaXRlIn0",
        ".H7q2M9v4R1x8B5n3T6z0DkWcYpSgJfUaH7q2M9v4R1x",
    ]
    .concat();
    assert_replaced(
        &format!("MONDAY_API_TOKEN={monday}\n"),
        &monday,
        &["rustleaks.monday-api-token"],
        "jwt",
    );
    assert_alone(&format!("OTHER_TOKEN={monday}\n"), &monday, "jwt");
}
