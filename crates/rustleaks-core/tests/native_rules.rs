//! Provider-grounded synthetic controls for the opt-in native pack.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use rustleaks_core::config::{ConfigLoader, RawConfig};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::{Engine, ScanControl};

const PACK: &str = rustleaks_core::native::EXTRA_RULES_V1;
const KEY: &str = "B7p4K9x2N6v1Q8s3T5w0Y4z7A2c6D9f1G8h3J5k0L4M=";

fn engine() -> Engine {
    Engine::builder(ConfigLoader::new().load_toml(PACK).unwrap())
        .build()
        .unwrap()
}

fn scan(engine: &Engine, bytes: &[u8]) -> Vec<Finding> {
    let outcome = engine.scan_fragment(
        &Fragment::builder(bytes).start_line(1).build(),
        &ScanOptions::default(),
    );
    assert!(outcome.is_complete());
    outcome.findings().to_vec()
}

fn assert_secret(finding: &Finding, input: &[u8], expected: &[u8], rule: &str) {
    let offset = input
        .windows(expected.len())
        .position(|value| value == expected)
        .unwrap();
    assert_eq!(finding.rule_id().as_bytes(), rule.as_bytes());
    assert_eq!(finding.secret().as_bytes(), expected);
    assert_eq!(
        finding.secret_range(),
        FindingRange::Exact(ByteRange::new(offset, offset + expected.len()).unwrap())
    );
    assert_eq!(finding.location().start_line(), 1);
    assert_eq!(finding.location().end_line(), 1);
}

#[test]
fn azure_field_order_preserves_only_the_key_capture() {
    let engine = engine();
    for (rule, fields) in [
        (
            "rustleaks.azure-servicebus-key",
            [
                "Endpoint=sb://synthetic.servicebus.windows.net/".to_owned(),
                "SharedAccessKeyName=synthetic".to_owned(),
                format!("SharedAccessKey={KEY}"),
            ],
        ),
        (
            "rustleaks.azure-app-configuration-key",
            [
                "Endpoint=https://synthetic.azconfig.io".to_owned(),
                "Id=synthetic-id".to_owned(),
                format!("Secret={KEY}"),
            ],
        ),
    ] {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let input = format!(
                "{};{};{}",
                fields[order[0]], fields[order[1]], fields[order[2]]
            );
            let findings = scan(&engine, input.as_bytes());
            assert_eq!(findings.len(), 1, "rule {rule}, order {order:?}");
            assert_secret(&findings[0], input.as_bytes(), KEY.as_bytes(), rule);
            assert_eq!(findings[0].match_text().as_bytes(), input.as_bytes());
            assert_eq!(
                findings[0].location(),
                Location::new(1, 1, 1, input.len()).unwrap()
            );
        }
    }
}

#[test]
fn mongodb_extracts_password_without_user_or_host_and_retains_percent_bytes() {
    let engine = engine();
    for (uri, password) in [
        ("mongodb://synthetic:m7!@db.example.invalid/", "m7!"),
        (
            "mongodb+srv://synthetic:p8%40Q%3A9@cluster.example.invalid/",
            "p8%40Q%3A9",
        ),
        (
            "mongodb://synthetic:p8-Q9@one.example.invalid:27017,two.example.invalid:27018/",
            "p8-Q9",
        ),
    ] {
        let findings = scan(&engine, uri.as_bytes());
        assert_eq!(findings.len(), 1);
        assert_secret(
            &findings[0],
            uri.as_bytes(),
            password.as_bytes(),
            "rustleaks.mongodb-password",
        );
        assert_eq!(findings[0].match_text().as_bytes(), uri.as_bytes());
        assert_eq!(
            findings[0].location(),
            Location::new(1, 1, 1, uri.len()).unwrap()
        );
    }
}

#[test]
fn pack_rejects_context_and_boundary_near_misses() {
    let engine = engine();
    for value in [
        format!(
            "Endpoint=sb://synthetic.example.invalid/;SharedAccessKeyName=policy;SharedAccessKey={KEY}"
        ),
        format!(
            "Endpoint=sb://synthetic.servicebus.windows.net/;SharedAccessKeyName=policy;SharedAccessKey={KEY}A"
        ),
        format!("Endpoint=sb://synthetic.servicebus.windows.net/;SharedAccessKey={KEY}"),
        format!("Endpoint=https://synthetic.example.invalid;Id=synthetic;Secret={KEY}"),
        format!("Endpoint=https://synthetic.azconfig.io;Id=;Secret={KEY}"),
        format!("Endpoint=https://synthetic.azconfig.io;Id=synthetic;Secret={KEY}_"),
        "mongodb://synthetic:@db.example.invalid/".into(),
        "mongodb://synthetic:bad%ZZ@db.example.invalid/".into(),
        "mongodb://synthetic:raw@at@db.example.invalid/".into(),
        "mongodb://synthetic:raw:colon@db.example.invalid/".into(),
        "mongodb+srv://synthetic:placeholder@db.example.invalid:27017/".into(),
        "mongodb+srv://synthetic:placeholder@one.example.invalid,two.example.invalid/".into(),
        "mongodb://${USER}:${PASSWORD}@db.example.invalid/".into(),
        "mongodb+srv://<user>:<password>@cluster.example.invalid/".into(),
    ] {
        assert!(scan(&engine, value.as_bytes()).is_empty());
    }
}

#[test]
fn invalid_bytes_and_encoded_envelopes_preserve_existing_mapping_contract() {
    let engine = engine();
    let uri = b"mongodb://synthetic:m7!@db.example.invalid/";
    let input = [b"\xff\0\"".as_slice(), uri, b"\"\xfe"].concat();
    let findings = scan(&engine, &input);
    assert_eq!(findings.len(), 1);
    assert_secret(&findings[0], &input, b"m7!", "rustleaks.mongodb-password");
    let encoded: Vec<u8> = uri
        .iter()
        .flat_map(|byte| format!("%{byte:02X}").into_bytes())
        .collect();
    let outcome = engine.scan_fragment(
        &Fragment::new(encoded),
        &ScanOptions::builder().max_decode_depth(1).build(),
    );
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(outcome.findings()[0].secret().as_bytes(), b"m7!");
    assert_eq!(
        outcome.findings()[0].secret_range(),
        FindingRange::Unavailable
    );
    assert_eq!(
        outcome.findings()[0].match_range(),
        FindingRange::Unavailable
    );
}

#[test]
fn explicit_rule_and_global_allowlists_apply_without_default_mutation() {
    for (rule, text, secret) in [
        (
            "rustleaks.mongodb-password",
            "mongodb://synthetic:m7!@db.example.invalid/".to_owned(),
            "m7!",
        ),
        (
            "rustleaks.azure-servicebus-key",
            format!(
                "Endpoint=sb://synthetic.servicebus.windows.net/;SharedAccessKeyName=synthetic;SharedAccessKey={KEY}"
            ),
            KEY,
        ),
        (
            "rustleaks.azure-app-configuration-key",
            format!("Endpoint=https://synthetic.azconfig.io;Id=synthetic;Secret={KEY}"),
            KEY,
        ),
    ] {
        for global in [false, true] {
            for condition in [
                format!("stopwords = ['{secret}']"),
                format!("regexes = ['^{secret}$']"),
                "paths = ['^allowed[.]conf$']".into(),
                "commits = ['synthetic-commit']".into(),
            ] {
                let mut raw: RawConfig = toml::from_str(PACK).unwrap();
                if global {
                    let entry = format!("[[allowlists]]\nregexTarget = 'secret'\n{condition}\n");
                    let extra: RawConfig = toml::from_str(&entry).unwrap();
                    raw.allowlists = extra.allowlists;
                } else {
                    let entry = format!(
                        "[[rules]]\nid = 'allowlist-source'\n[[rules.allowlists]]\nregexTarget = 'secret'\n{condition}\n"
                    );
                    let extra: RawConfig = toml::from_str(&entry).unwrap();
                    raw.rules
                        .iter_mut()
                        .find(|value| value.id == rule)
                        .unwrap()
                        .allowlists = extra.rules[0].allowlists.clone();
                }
                let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                    .build()
                    .unwrap();
                let fragment = Fragment::builder(text.as_bytes())
                    .file_path("allowed.conf")
                    .commit("synthetic-commit")
                    .build();
                assert!(
                    engine
                        .scan_fragment(&fragment, &ScanOptions::default())
                        .findings()
                        .is_empty(),
                    "{rule}: {condition}"
                );
            }
        }
    }
}

#[test]
fn targeted_global_allowlist_does_not_suppress_other_native_rules() {
    let input = format!(
        "Endpoint=sb://synthetic.servicebus.windows.net/;SharedAccessKeyName=synthetic;SharedAccessKey={KEY}\nmongodb://synthetic:m7!@db.example.invalid/"
    );
    let mut raw: RawConfig = toml::from_str(PACK).unwrap();
    let extra: RawConfig = toml::from_str("[[allowlists]]\ntargetRules = ['rustleaks.azure-servicebus-key']\npaths = ['^allowed[.]conf$']\n").unwrap();
    raw.allowlists = extra.allowlists;
    let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
        .build()
        .unwrap();
    let fragment = Fragment::builder(input.into_bytes())
        .file_path("allowed.conf")
        .build();
    let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(
        outcome.findings()[0].rule_id().as_bytes(),
        b"rustleaks.mongodb-password"
    );
}

#[test]
fn native_composition_is_explicit_and_keeps_legacy_outcomes() {
    use rustleaks_core::explanation::ExplanationOptions;
    use rustleaks_core::native::{EXTRA_RULES_V1, NativePolicy};
    let native = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    let fragment = Fragment::new(b"mongodb://synthetic:m7!@db.example.invalid/".as_slice());
    let default = Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap();
    assert!(
        default
            .scan_fragment(&fragment, &ScanOptions::default())
            .findings()
            .is_empty()
    );
    let options = ScanOptions::default();
    let control = ScanControl::unlimited();
    let wrapped = native.scan_fragment_controlled(
        &fragment,
        &options,
        &control,
        ExplanationOptions::disabled(),
    );
    let plain = native
        .engine()
        .scan_fragment_controlled(&fragment, &options, &control);
    assert_eq!(wrapped.scan(), &plain);
    assert_eq!(wrapped.scan().findings().len(), 1);
}
