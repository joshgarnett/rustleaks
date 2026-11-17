//! Recall probes for the default `generic-api-key` rule: synthetic random
//! 40-byte keys, some with an embedded dictionary word, under credential-like
//! names. Each expectation is computed from the pinned rule and its filters,
//! so a change to the stopwords, the allowlists or the entropy check shows up
//! as a change in which probes are reported.
//!
//! The pinned rule (in `compat/config-corpus/default-gitleaks.toml`) reports
//! the first capture group when all of these hold:
//! - the secret's Shannon entropy over its bytes is above 3.5;
//! - the secret is not only ASCII letters, `_`, `.` and `-`;
//! - the full match does not match the rule's `regexTarget = "match"` regex;
//! - the lowercase secret contains none of the rule's stopwords; and
//! - the secret passes the global allowlist, here its unanchored `false`
//!   alternative, its `true` prefix and `null` suffix, and its stopwords.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::fs;
use std::path::PathBuf;

use regex_automata::meta::Regex;
use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{ByteRange, FindingRange, Fragment, ScanOptions};

struct Filters {
    rule_stopwords: Vec<String>,
    global_stopwords: Vec<String>,
    match_allowlist: Regex,
}

fn pinned_config() -> toml::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/config-corpus/default-gitleaks.toml");
    toml::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn filters(config: &toml::Value) -> Filters {
    let strings = |value: &toml::Value| {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    let rule = config["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"].as_str() == Some("generic-api-key"))
        .unwrap();
    let allowlists = rule["allowlists"].as_array().unwrap();
    let with_match = allowlists
        .iter()
        .find(|allowlist| {
            allowlist.get("regexTarget").and_then(toml::Value::as_str) == Some("match")
        })
        .unwrap();
    let [pattern] = strings(&with_match["regexes"]).try_into().unwrap();
    Filters {
        rule_stopwords: strings(&with_match["stopwords"]),
        global_stopwords: strings(&config["allowlist"]["stopwords"]),
        match_allowlist: Regex::new(&pattern).unwrap(),
    }
}

fn shannon(bytes: &[u8]) -> f64 {
    let mut counts = [0_u32; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let length = f64::from(u32::try_from(bytes.len()).unwrap());
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let share = f64::from(*count) / length;
            -share * share.log2()
        })
        .sum()
}

/// A deterministic key of 40 bytes without vowels, so that no dictionary word
/// appears by chance, with `word` placed at `offset`.
fn key(seed: u64, word: &str, offset: usize) -> String {
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZbcdfghjkmnpqrstvwxz23456789";
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut bytes = (0..40 - word.len())
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ALPHABET[usize::try_from(state % u64::try_from(ALPHABET.len()).unwrap()).unwrap()]
        })
        .collect::<Vec<_>>();
    bytes.splice(offset..offset, word.bytes());
    String::from_utf8(bytes).unwrap()
}

fn reported(filters: &Filters, matched: &str, secret: &str) -> bool {
    let lower = secret.to_ascii_lowercase();
    shannon(secret.as_bytes()) > 3.5
        && !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'.' | b'-'))
        && !filters.match_allowlist.is_match(matched)
        && !filters
            .rule_stopwords
            .iter()
            .chain(&filters.global_stopwords)
            .any(|word| lower.contains(word.as_str()))
        && !lower.starts_with("true")
        && !lower.contains("false")
        && !lower.ends_with("null")
}

// Credential-like names with a rule keyword and no match-allowlist phrase.
const NAMES: [&str; 6] = [
    "api_key",
    "secret",
    "auth_token",
    "password",
    "client_secret",
    "access_token",
];

// Common words. Some are rule stopwords, so their probes are not reported.
const WORDS: [&str; 18] = [
    "", "admin", "about", "account", "table", "house", "river", "dragon", "pepper", "alpha",
    "cloud", "zebra", "orange", "user", "test", "data", "file", "server",
];

#[test]
fn generic_rule_reports_exactly_the_probes_its_filters_allow() {
    let config = pinned_config();
    let filters = filters(&config);
    assert!(filters.rule_stopwords.len() > 1_000);
    let engine = Engine::builder(
        ConfigLoader::new()
            .load_default()
            .unwrap()
            .select_rules(["generic-api-key"])
            .unwrap(),
    )
    .build()
    .unwrap();
    let mut seed = 0_u64;
    let (mut total, mut kept) = (0_usize, 0_usize);
    let mut failures = Vec::new();
    for name in NAMES {
        for word in WORDS {
            for offset in [0, 17, 40 - word.len()] {
                seed += 1;
                let secret = key(seed, word, offset);
                let line = format!("{name} = \"{secret}\"");
                let start = name.len() + 4;
                let expected = reported(&filters, &line, &secret);
                let outcome =
                    engine.scan_fragment(&Fragment::new(line.as_bytes()), &ScanOptions::default());
                assert!(outcome.is_complete());
                let findings = outcome.findings();
                let actual = match findings {
                    [] => false,
                    [finding] => {
                        assert_eq!(finding.secret().as_bytes(), secret.as_bytes(), "{line}");
                        assert_eq!(
                            finding.secret_range(),
                            FindingRange::Exact(ByteRange::new(start, start + 40).unwrap()),
                            "{line}"
                        );
                        true
                    }
                    _ => panic!("{line}: {} findings", findings.len()),
                };
                if actual != expected {
                    failures.push(format!("{name} {word:?} at {offset}: expected {expected}"));
                }
                total += 1;
                kept += usize::from(expected);
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(total, NAMES.len() * WORDS.len() * 3);
    // Both outcomes occur, so the probes measure the filters in both ways.
    assert!(kept > 0 && kept < total, "{kept} of {total}");
}
