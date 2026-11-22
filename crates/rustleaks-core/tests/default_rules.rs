//! The allowlists that Rustleaks adds to the default rules.
//!
//! `default/gitleaks.toml` started from the Gitleaks default configuration.
//! Rustleaks adds five allowlists to `generic-api-key` and one global
//! allowlist. The first test names them. The other tests check what they do.
//! Each case is a line that the default rules report when the added
//! allowlists are removed. The expectation comes from the allowlist
//! definitions:
//! - a filtered case is reported without the added allowlists and hidden by
//!   the default rules;
//! - a kept case gives the same findings with and without them.
//!
//! Values are built at run time from a seeded generator or from pieces, so
//! this source file holds no credential-shaped string.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::BTreeSet;

use rustleaks_core::config::{CompiledConfig, ConfigLoader, DEFAULT_CONFIG, RawConfig};
use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::native::NativePolicy;
use rustleaks_core::{Engine, ScanControl};

const GENERIC: &str = "generic-api-key";

struct Values(u64);

impl Values {
    fn next(&mut self) -> u64 {
        // SplitMix64, so the values are fixed for a given seed.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn from(&mut self, alphabet: &[u8], length: usize) -> String {
        let modulus = u64::try_from(alphabet.len()).unwrap();
        (0..length)
            .map(|_| {
                let index = usize::try_from(self.next() % modulus).unwrap();
                char::from(alphabet[index])
            })
            .collect()
    }

    fn hex(&mut self, length: usize) -> String {
        self.from(b"0123456789abcdef", length)
    }

    fn base62(&mut self, length: usize) -> String {
        self.from(
            b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            length,
        )
    }

    fn uuid(&mut self) -> String {
        [8, 4, 4, 4, 12].map(|length| self.hex(length)).join("-")
    }
}

fn engine(config: CompiledConfig) -> Engine {
    Engine::builder(config).build().unwrap()
}

/// Descriptions of the allowlists that Rustleaks adds to `generic-api-key`.
const GENERIC_ADDITIONS: [&str; 5] = [
    "Hex digests assigned to hash-like names",
    "Git object IDs assigned to commit or revision names",
    "Subresource Integrity values",
    "Stripe publishable keys, which Stripe documents as safe to expose",
    "UUIDs assigned to identifier names. Names that contain secret, such as secret_id, are not matched.",
];

/// Descriptions of the global allowlists that Rustleaks adds.
const GLOBAL_ADDITIONS: [&str; 1] = ["Published vendor documentation examples"];

/// The default rules as written, parsed.
fn shipped() -> RawConfig {
    ConfigLoader::new()
        .parse_toml(DEFAULT_CONFIG, None)
        .unwrap()
}

/// The default rules without the allowlists that Rustleaks adds.
fn without_additions() -> Engine {
    let mut raw = shipped();
    let generic = raw
        .rules
        .iter_mut()
        .find(|rule| rule.id == GENERIC)
        .unwrap();
    generic
        .allowlists
        .retain(|allowlist| !GENERIC_ADDITIONS.contains(&allowlist.description.as_str()));
    raw.allowlists
        .retain(|allowlist| !GLOBAL_ADDITIONS.contains(&allowlist.allowlist.description.as_str()));
    engine(ConfigLoader::new().compile(raw).unwrap())
}

#[test]
fn the_default_rules_have_the_added_allowlists() {
    let shipped = shipped();
    let generic = shipped
        .rules
        .iter()
        .find(|rule| rule.id == GENERIC)
        .unwrap();
    let descriptions = generic
        .allowlists
        .iter()
        .map(|allowlist| allowlist.description.as_str())
        .collect::<Vec<_>>();
    // The first four allowlists came with the rule; three have no
    // description.
    let mut expected = vec!["", "Allowlist for Generic API Keys", "", ""];
    expected.extend(GENERIC_ADDITIONS);
    assert_eq!(descriptions, expected);
    let globals = shipped
        .allowlists
        .iter()
        .map(|allowlist| allowlist.allowlist.description.as_str())
        .collect::<Vec<_>>();
    let mut expected = vec!["global allow lists"];
    expected.extend(GLOBAL_ADDITIONS);
    assert_eq!(globals, expected);
    assert!(
        shipped
            .allowlists
            .iter()
            .all(|allowlist| allowlist.target_rules.is_empty())
    );
    assert_eq!(shipped.rules.len(), 222);
}

fn default_rules() -> Engine {
    engine(
        ConfigLoader::new()
            .with_default_config(DEFAULT_CONFIG)
            .load_default()
            .unwrap(),
    )
}

fn options() -> ScanOptions {
    ScanOptions::builder().max_decode_depth(5).build()
}

fn findings(engine: &Engine, line: &str) -> BTreeSet<(String, String)> {
    let outcome = engine.scan_fragment(&Fragment::new(line.as_bytes()), &options());
    assert!(outcome.is_complete());
    outcome
        .findings()
        .iter()
        .map(|finding| {
            (
                finding.rule_id().to_string_lossy().into_owned(),
                finding.secret().to_string_lossy().into_owned(),
            )
        })
        .collect()
}

/// Draws values until the rules without the added allowlists report one, so
/// that each case starts from a reported finding. Random values can fall below the entropy check or
/// contain a stopword. Returns the line and the secret.
fn draw(case: &str, mut make: impl FnMut() -> String, template: &str) -> (String, String) {
    let without = without_additions();
    for _ in 0..64 {
        let secret = make();
        let line = template.replace("{}", &secret);
        if findings(&without, &line)
            .iter()
            .any(|(_, value)| *value == secret)
        {
            return (line, secret);
        }
    }
    panic!("{case}: the rules without the added allowlists report no drawn value");
}

/// Asserts that the rules without the added allowlists report `secret` under
/// `rule` and that the default rules report the same findings without it. Messages name the case,
/// never the synthetic value.
fn assert_filtered(case: &str, make: impl FnMut() -> String, template: &str, rule: &str) {
    let (line, secret) = draw(case, make, template);
    let mut expected = findings(&without_additions(), &line);
    assert!(
        expected.remove(&(rule.to_owned(), secret)),
        "{case}: the rules without the added allowlists must report the value under {rule}"
    );
    assert_eq!(findings(&default_rules(), &line), expected, "{case}");
}

fn assert_kept(case: &str, make: impl FnMut() -> String, template: &str) {
    let (line, _) = draw(case, make, template);
    assert_eq!(
        findings(&default_rules(), &line),
        findings(&without_additions(), &line),
        "{case}"
    );
}

#[test]
fn hex_digests_under_hash_like_names_are_hidden() {
    let mut values = Values(1);
    for (case, length, template) in [
        ("md5 snake case", 32, "token_md5 = {}"),
        ("sha256 constant", 64, "export const TOKEN_SHA256 = \"{}\";"),
        ("dotted fingerprint", 64, "api.key.fingerprint={}"),
        ("sha1 checksum", 40, "token_checksum: '{}'"),
        ("sha512 digest", 128, "\"tokenDigest\": \"{}\""),
    ] {
        assert_filtered(case, || values.hex(length), template, GENERIC);
    }
}

#[test]
fn hex_values_under_other_names_are_still_reported() {
    let mut values = Values(2);
    for (case, length, template) in [
        ("api token", 64, "api_token = \"{}\""),
        ("secret key", 40, "secret_key = {}"),
        ("digest length 48", 48, "token_sha256 = {}"),
        ("secret version", 40, "secret_version = \"{}\""),
    ] {
        assert_kept(case, || values.hex(length), template);
    }
}

#[test]
fn git_object_ids_under_commit_or_revision_names_are_hidden() {
    let mut values = Values(3);
    for (case, template) in [
        ("commit", "token_commit = \"{}\""),
        ("revision", "AUTH_REVISION={}"),
        ("rev", "api_rev: '{}'"),
    ] {
        assert_filtered(case, || values.hex(40), template, GENERIC);
    }
}

#[test]
fn subresource_integrity_values_are_hidden() {
    let mut values = Values(4);
    // The generic rule reports Base64 values only when they hold no `+` or
    // `/`, so the drawn digests use letters and digits.
    for (case, length) in [("sha384", 64), ("sha512", 86)] {
        assert_filtered(
            case,
            || format!("{case}-{}", values.base62(length)),
            "export const AUTH_SDK_INTEGRITY = \"{}\";",
            GENERIC,
        );
    }
}

#[test]
fn stripe_publishable_keys_are_hidden_and_secret_keys_are_not() {
    let mut values = Values(5);
    for mode in ["live", "test"] {
        assert_filtered(
            mode,
            || format!("pk_{mode}_{}", values.base62(30)),
            "const publishableKey = '{}';",
            GENERIC,
        );
    }
    assert_kept(
        "secret key",
        || format!("sk_{}_{}", "live", values.base62(24)),
        "stripe_key = \"{}\"",
    );
}

#[test]
fn uuids_under_identifier_names_are_hidden() {
    let mut values = Values(6);
    for (case, template) in [
        ("snake token id", "token_id = {}"),
        ("upper token id", "TOKEN_ID: {}"),
        ("php token id", "'token_id' => '{}',"),
        ("camel token id", "\"tokenId\": \"{}\","),
        ("dotted client id", "keycloak.client-id: {}"),
    ] {
        assert_filtered(case, || values.uuid(), template, GENERIC);
    }
}

#[test]
fn uuids_under_secret_or_key_names_are_still_reported() {
    let mut values = Values(7);
    for (case, template) in [
        ("vault approle secret id", "secret_id: {}"),
        ("secret version id", "'secret_version_id' => '{}',"),
        ("uuid api key", "api_key = \"{}\""),
        ("uuid auth token", "auth_token={}"),
    ] {
        assert_kept(case, || values.uuid(), template);
    }
}

#[test]
fn github_tokens_are_still_reported() {
    let mut values = Values(8);
    assert_kept(
        "ghp token",
        || format!("gh{}_{}", "p", values.base62(36)),
        "github_token = \"{}\"",
    );
}

fn vendor_examples() -> [(&'static str, String); 5] {
    [
        (
            "discord",
            [
                "MTk4Nj", "IyNDgz", "NDcxOT", "I1MjQ4", ".Cl2FM", "Q.ZnCj", "m1XVW7", "vRze4b",
                "7Cq4se", "7kKWs",
            ]
            .concat(),
        ),
        (
            "azurite",
            [
                "Eby8vd", "M02xNO", "cqFlqU", "wJPLlm", "EtlCDX", "J1OUzF", "T50uSR", "Z6IFsu",
                "Fq2UVE", "rCz4I6", "tq/K1S", "ZFPTOt", "r/KBHB", "eksoGM", "Gw==",
            ]
            .concat(),
        ),
        (
            "telegram",
            [
                "123456", ":ABC-D", "EF1234", "ghIkl-", "zyx57W", "2v1u12", "3ew11",
            ]
            .concat(),
        ),
        (
            "slack",
            [
                "xoxp-1", "11-222", "-333-d", "6bc768", "406e5c", "2e6958", "cfc399", "b43800", "4",
            ]
            .concat(),
        ),
        (
            "google",
            [
                "AIzaSy", "DaGmWK", "a4JsXZ", "-HjGw7", "ISLn_3", "namBGe", "wQe",
            ]
            .concat(),
        ),
    ]
}

#[test]
fn published_vendor_examples_are_hidden_from_every_rule() {
    for (case, example) in vendor_examples() {
        let line = format!("{case}_token = \"{example}\"");
        // No rule reports the Telegram example in this form; the
        // allowlist still covers it where a rule would.
        assert!(
            case == "telegram" || !findings(&without_additions(), &line).is_empty(),
            "{case}: the rules without the added allowlists must report the example"
        );
        let shown = findings(&default_rules(), &line);
        assert!(shown.is_empty(), "{case}: {} findings remain", shown.len());
    }
}

#[test]
fn values_that_differ_from_a_vendor_example_are_still_reported() {
    for (case, example) in vendor_examples() {
        if case == "slack" || case == "telegram" {
            // These examples have no rule that reports a changed copy.
            continue;
        }
        let mut changed = example.clone();
        changed.replace_range(8..9, if &example[8..9] == "Q" { "R" } else { "Q" });
        let line = format!("{case}_token = \"{changed}\"");
        let expected = findings(&without_additions(), &line);
        assert!(
            !expected.is_empty(),
            "{case}: the rules without the added allowlists must report the value"
        );
        assert_eq!(findings(&default_rules(), &line), expected, "{case}");
    }
}

#[test]
fn extending_the_default_gets_the_allowlists() {
    let mut values = Values(9);
    let (line, secret) = draw("extend", || values.hex(32), "token_md5 = {}");
    let extended = engine(
        ConfigLoader::new()
            .load_toml("[extend]\nuseDefault = true\n")
            .unwrap(),
    );
    assert!(findings(&without_additions(), &line).contains(&(GENERIC.to_owned(), secret)));
    assert!(findings(&extended, &line).is_empty());
}

#[test]
fn disabling_the_generic_rule_still_loads() {
    let config = ConfigLoader::new()
        .load_toml("[extend]\nuseDefault = true\ndisabledRules = [\"generic-api-key\"]\n")
        .unwrap();
    assert!(!config.rules().contains_key(GENERIC));
}

/// A configuration with only a `generic-api-key` rule and no allowlists.
const STANDALONE: &str = "[[rules]]\nid = \"generic-api-key\"\nregex = '''token_md5 = ([0-9a-f]{32})'''\nsecretGroup = 1\n";

#[test]
fn a_replaced_default_and_a_standalone_config_are_unchanged() {
    let mut values = Values(10);
    let (line, secret) = draw("replaced", || values.hex(32), "token_md5 = {}");
    let expected = BTreeSet::from([(GENERIC.to_owned(), secret.clone())]);
    // A caller-supplied default without the allowlists is used as given.
    let replaced = engine(
        ConfigLoader::new()
            .with_default_config(STANDALONE)
            .load_toml("[extend]\nuseDefault = true\n")
            .unwrap(),
    );
    assert_eq!(findings(&replaced, &line), expected);
    // A configuration that does not extend the default gets no allowlists.
    let standalone = engine(ConfigLoader::new().load_toml(STANDALONE).unwrap());
    assert_eq!(findings(&standalone, &line), expected);
}

#[test]
fn native_packs_on_the_default_use_the_allowlists() {
    let mut values = Values(11);
    let (line, secret) = draw("native", || values.hex(32), "token_md5 = {}");
    let native = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", rustleaks_core::native::EXTRA_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    let outcome = native.scan_fragment_controlled(
        &Fragment::new(line.as_bytes()),
        &options(),
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(0),
    );
    assert!(outcome.scan().is_complete());
    assert!(outcome.scan().findings().is_empty());
    assert!(findings(&without_additions(), &line).contains(&(GENERIC.to_owned(), secret)));
}
