//! Cases for the provider rules that add delimiter and context forms of other
//! rules (`-delimiter`, `-context-vt` and `-vt` rules).
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::native::{EXTRA_RULES_V1, NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use std::sync::OnceLock;

#[allow(dead_code)] // `positives` serves the all-rules precedence test.
#[path = "support/contextual_delta_cases.rs"]
mod contextual_delta_cases;
use contextual_delta_cases::{Case, body, cases, hex, legacy_openai_tokens, residual_vt_tokens};

const IDS: [&str; 44] = [
    "rustleaks.beamer-api-token-delimiter",
    "rustleaks.beamer-api-token-context-vt",
    "rustleaks.defined-networking-api-token-delimiter",
    "rustleaks.defined-networking-api-token-context-vt",
    "rustleaks.hashicorp-tf-password-delimiter",
    "rustleaks.hashicorp-tf-password-context-vt",
    "rustleaks.heroku-api-key-delimiter",
    "rustleaks.heroku-api-key-context-vt",
    "rustleaks.hubspot-api-key-delimiter",
    "rustleaks.hubspot-api-key-context-vt",
    "rustleaks.lob-api-key-delimiter",
    "rustleaks.lob-api-key-context-vt",
    "rustleaks.mailchimp-api-key-delimiter",
    "rustleaks.mailchimp-api-key-context-vt",
    "rustleaks.mailgun-private-api-token-delimiter",
    "rustleaks.mailgun-private-api-token-context-vt",
    "rustleaks.mailgun-signing-key-delimiter",
    "rustleaks.mailgun-signing-key-context-vt",
    "rustleaks.okta-access-token-delimiter",
    "rustleaks.okta-access-token-context-vt",
    "rustleaks.plaid-api-token-delimiter",
    "rustleaks.plaid-api-token-context-vt",
    "rustleaks.sidekiq-secret-delimiter",
    "rustleaks.sidekiq-secret-context-vt",
    "rustleaks.snyk-api-token-delimiter",
    "rustleaks.snyk-api-token-context-vt",
    "rustleaks.sonar-api-token-delimiter",
    "rustleaks.sonar-api-token-context-vt",
    "rustleaks.squarespace-access-token-delimiter",
    "rustleaks.squarespace-access-token-context-vt",
    "rustleaks.telegram-bot-api-token-delimiter",
    "rustleaks.telegram-bot-api-token-context-vt",
    "rustleaks.typeform-api-token-delimiter",
    "rustleaks.typeform-api-token-context-vt",
    "rustleaks.yandex-access-token-delimiter",
    "rustleaks.yandex-access-token-context-vt",
    "rustleaks.yandex-api-key-delimiter",
    "rustleaks.yandex-api-key-context-vt",
    "rustleaks.yandex-aws-access-token-delimiter",
    "rustleaks.yandex-aws-access-token-context-vt",
    "rustleaks.anthropic-api-key-vt",
    "rustleaks.anthropic-admin-api-key-vt",
    "rustleaks.digitalocean-refresh-token-vt",
    "rustleaks.openai-api-key-legacy-delimiter",
];

fn scan(engine: &Engine, bytes: &[u8], path: &str) -> Vec<Finding> {
    let result = engine.scan_fragment(
        &Fragment::builder(bytes).file_path(path).build(),
        &ScanOptions::default(),
    );
    assert!(result.is_complete());
    result.findings().to_vec()
}
fn exact(start: usize, end: usize) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}
fn build(selected: bool, extras: bool, without_ids: bool) -> Engine {
    let mut pack: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    if without_ids {
        pack["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|rule| !IDS.contains(&rule["id"].as_str().unwrap()));
        // Keep only the reviewed overlaps whose pack rules remain.
        let kept = pack["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| rule["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        pack["overlaps"].as_array_mut().unwrap().retain(|overlap| {
            ["keep", "drop"].iter().all(|field| {
                let id = overlap[*field].as_str().unwrap();
                !id.starts_with("rustleaks.") || kept.iter().any(|rule| rule == id)
            })
        });
    }
    let text = toml::to_string(&pack).unwrap();
    let mut policy = NativePolicy::builder();
    if extras {
        policy = policy
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap();
    }
    let (config, _) = policy
        .with_pack("provider-fixture", &text)
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(if selected {
        config.select_rules(IDS).unwrap()
    } else {
        config
    })
    .build()
    .unwrap()
}
fn selected() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| build(true, false, false))
}
fn composed() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| build(false, false, false))
}
fn both() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| build(false, true, false))
}
// The provider rules without the rules in `IDS`.
fn without_companions() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| build(false, false, true))
}
fn rule(id: &str) -> toml::Value {
    let pack: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    pack["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"].as_str() == Some(id))
        .unwrap()
        .clone()
}
fn single(rule: toml::Value) -> Engine {
    let id = rule["id"].as_str().unwrap().to_owned();
    let mut pack: toml::Value = toml::from_str("title='context fixture'").unwrap();
    pack.as_table_mut()
        .unwrap()
        .insert("rules".into(), toml::Value::Array(vec![rule]));
    let text = toml::to_string(&pack).unwrap();
    let (config, _) = NativePolicy::builder()
        .with_pack("context-fixture", &text)
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(config.select_rules([id.as_str()]).unwrap())
        .build()
        .unwrap()
}

#[test]
fn terminal_and_context_vt_classes_are_disjoint_with_exact_spans() {
    for c in cases() {
        let mut contexts = vec![(String::new(), String::new(), false)];
        // Quotes cannot migrate into the separate 0..20 label-tail class.
        for width in 1..=3 {
            for position in 0..width {
                contexts.push((
                    format!(
                        "{}\u{b}{}",
                        "\"".repeat(position),
                        "\"".repeat(width - position - 1)
                    ),
                    String::new(),
                    true,
                ));
            }
        }
        for width in 1..=5 {
            for position in 0..width {
                contexts.push((
                    String::new(),
                    format!(
                        "{}\u{b}{}",
                        "'".repeat(position),
                        "'".repeat(width - position - 1)
                    ),
                    true,
                ));
            }
        }
        contexts.push((
            "\u{b}\u{b}\u{b}".into(),
            "\u{b}\u{b}\u{b}\u{b}\u{b}".into(),
            true,
        ));
        for (pre, post, vt) in contexts {
            for ending in ["\\\"", "\\'", "\\`", "\u{b}", ";"] {
                if !vt && ending == ";" {
                    continue;
                }
                let text = format!("lead\nx {}{pre}={post}{}{ending}", c.label, c.secret);
                let id = format!(
                    "rustleaks.{}-{}",
                    c.source,
                    if vt { "context-vt" } else { "delimiter" }
                );
                let start = 7 + c.label.len() + pre.len() + 1 + post.len();
                let found = scan(selected(), text.as_bytes(), c.path);
                assert_eq!(
                    found.len(),
                    1,
                    "{}, {pre:?}, {post:?}, {ending:?}",
                    c.source
                );
                let f = &found[0];
                assert_eq!(f.rule_id().as_bytes(), id.as_bytes());
                assert_eq!(f.secret().as_bytes(), c.secret.as_bytes());
                assert_eq!(f.secret_range(), exact(start, start + c.secret.len()));
                assert_eq!(f.match_range(), exact(7, text.len()));
                assert_eq!(f.match_text().as_bytes(), &text.as_bytes()[7..]);
                assert_eq!(
                    f.location(),
                    Location::new(1, 1, 4, text.len() - 4).unwrap()
                );
                // Full composition is checked for one representative of each
                // region, keeping the exhaustive positional loop focused.
                if pre.len() <= 1 && post.len() <= 1 {
                    for engine in [composed(), both()] {
                        let full = scan(engine, text.as_bytes(), c.path);
                        assert_eq!(full, found, "{} composition", c.source);
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_ascii_assignment_whitespace_has_exact_multiline_locations() {
    let secret = format!("b_{}", body(44));
    assert_eq!(secret.len(), 46);
    // Fragment lines start at 0, only LF ends a line, and columns count from
    // the LF before the line. The
    // trailing LF after ';' bounds the final matched line. These constants
    // come from the literal layouts below, not scanner-produced locations:
    // start=7, preceding LF=4; inner LFs are at 14, 16, or 14 and 17.
    for (pre, post, secret_start, match_end, end_line, end_column) in [
        ("\u{b}\n\r", "\u{c}", 18, 65, 2, 51),
        ("\r\u{c}", "\n\u{b}\r\u{c}", 20, 67, 2, 51),
        ("\u{b}\n", "\r\n\u{c}", 19, 66, 3, 49),
        ("\u{b}\r\u{c}", "", 17, 64, 1, 60),
    ] {
        let matched = format!("beamer{pre}={post}{secret};");
        let input = format!("lead\nx {matched}\ntail");
        assert_eq!(
            &input.as_bytes()[secret_start..secret_start + 46],
            secret.as_bytes()
        );
        assert_eq!(&input.as_bytes()[7..match_end], matched.as_bytes());
        for engine in [selected(), composed(), both()] {
            let findings = scan(engine, input.as_bytes(), "source.txt");
            assert_eq!(findings.len(), 1);
            let finding = &findings[0];
            assert_eq!(
                finding.rule_id().as_bytes(),
                b"rustleaks.beamer-api-token-context-vt"
            );
            assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
            assert_eq!(
                finding.secret_range(),
                exact(secret_start, secret_start + 46)
            );
            assert_eq!(finding.match_text().as_bytes(), matched.as_bytes());
            assert_eq!(finding.match_range(), exact(7, match_end));
            assert_eq!(
                finding.location(),
                Location::new(1, end_line, 4, end_column).unwrap()
            );
        }
    }
    // Another valid VT must not make non-ASCII whitespace acceptable in
    // either bounded assignment region or the separate label-tail region.
    for unicode_space in ["\u{a0}", "\u{2003}", "\u{2028}"] {
        for (pre, post) in [
            (format!("\u{b}{unicode_space}"), String::new()),
            ("\u{b}".into(), unicode_space.into()),
            (unicode_space.into(), "\u{b}".into()),
            (String::new(), format!("\u{b}{unicode_space}")),
            (format!("a{unicode_space}Z\u{b}"), String::new()),
        ] {
            let input = format!("beamer{pre}={post}{secret};");
            assert!(
                scan(selected(), input.as_bytes(), "source.txt").is_empty(),
                "{pre:?}, {post:?}"
            );
        }
    }
}

#[test]
fn ordinary_occurrences_and_quoted_password_overlap_are_distinguished() {
    for c in cases() {
        for end in ["", ";", "'", "\"", "`", " ", "\t", "\n", "\\n", "\\r"] {
            let text = format!("{}={}{end}", c.label, c.secret);
            assert!(scan(selected(), text.as_bytes(), c.path).is_empty());
            let without = scan(without_companions(), text.as_bytes(), c.path);
            assert!(!without.is_empty(), "{}", c.source);
            assert_eq!(scan(composed(), text.as_bytes(), c.path), without);
        }
        let text = format!("{}={}\\\"", c.label, c.secret);
        let without = scan(without_companions(), text.as_bytes(), c.path);
        if c.source == "hashicorp-tf-password" && c.secret.len() == 22 {
            assert_eq!(without.len(), 1);
            assert_eq!(without[0].rule_id().as_bytes(), b"generic-api-key");
            assert_eq!(
                without[0].secret().as_bytes(),
                &c.secret.as_bytes()[1..c.secret.len() - 1]
            );
            // This is capture/attribution coverage, not a wholly unseen body.
        } else {
            // The eight/nine-character quoted bodies fail the generic length
            // minimum; the ten-symbol body has H=log2(10), below its 3.5 gate.
            assert!(without.is_empty(), "{} must add an occurrence", c.source);
        }
    }
}

fn assert_body_mutations_rejected(c: &Case) {
    let at = c.secret.len() / 2;
    for replacement in ["!", "\u{17f}", "\u{212a}"] {
        let text = format!(
            "{}={}{}{}\\\"",
            c.label,
            &c.secret[..at],
            replacement,
            &c.secret[at + 1..]
        );
        assert!(
            scan(selected(), text.as_bytes(), c.path).is_empty(),
            "{} body mutation",
            c.source
        );
    }
    let mut invalid = format!("{}={}\\\"", c.label, c.secret).into_bytes();
    invalid[c.label.len() + 1 + at] = 0xff;
    assert!(scan(selected(), &invalid, c.path).is_empty());
}

#[test]
fn context_bounds_separators_case_resets_and_body_mutations_are_independent() {
    for c in cases() {
        for sep in ["=", ">", ":=", "::=", ":::=", "||", ":", "=>", "?=", ","] {
            let text = format!("{}\u{b}{sep}{};", c.label, c.secret);
            assert_eq!(
                scan(selected(), text.as_bytes(), c.path).len(),
                1,
                "{}, {sep}",
                c.source
            );
        }
        for text in [
            format!("{}\u{b}\"\"\"={};", c.label, c.secret),
            format!("{}=\u{b}'''''{};", c.label, c.secret),
            format!("{}a\u{b}Z={};", c.label, c.secret),
            format!("{}{}\u{b}={};", c.label, "Z".repeat(21), c.secret),
            format!("{}={}\\\\\"", c.label, c.secret),
        ] {
            assert!(
                scan(selected(), text.as_bytes(), c.path).is_empty(),
                "{} invalid context",
                c.source
            );
        }
        let bounded = format!("{}{}\u{b}={};", c.label, "Z".repeat(20), c.secret);
        assert_eq!(scan(selected(), bounded.as_bytes(), c.path).len(), 1);
        let upper = format!(
            "{}={}\\\"",
            c.label.to_ascii_uppercase(),
            c.secret.to_ascii_uppercase()
        );
        assert_eq!(
            scan(selected(), upper.as_bytes(), c.path).len(),
            1,
            "{} uppercase",
            c.source
        );
        assert_body_mutations_rejected(&c);
    }
    for label in ["oKtA", "OKTa", "OkTA"] {
        assert!(
            scan(
                selected(),
                format!("{label}=00{}\\\"", body(40)).as_bytes(),
                "source.txt"
            )
            .is_empty()
        );
    }
    assert!(
        scan(
            selected(),
            format!("telegr=19283:a{}\\\"", body(34)).as_bytes(),
            "source.txt"
        )
        .is_empty()
    );
    for n in [4, 17] {
        assert!(
            scan(
                selected(),
                format!("telegr={}:A{}\\\"", "1".repeat(n), body(34)).as_bytes(),
                "source.txt"
            )
            .is_empty()
        );
    }
    for n in [7, 21] {
        assert!(
            scan(
                selected(),
                format!("password=\"{}\"\\\"", body(n)).as_bytes(),
                "source.tf"
            )
            .is_empty()
        );
    }
    for path in ["source.tf", "source.TF", "source.hcl", "source.HcL"] {
        assert_eq!(
            scan(selected(), b"password=\"Q7m2Z9v4\"\\\"", path).len(),
            1
        );
    }
    for path in ["source.txt", "source.tf.bak", ""] {
        assert!(scan(selected(), b"password=\"Q7m2Z9v4\"\\\"", path).is_empty());
    }
}

#[test]
fn independently_specified_token_lengths_reject_adjacent_outside_values() {
    let mut negatives = Vec::new();
    for n in [43, 45] {
        negatives.push(("beamer", format!("b_{}", body(n)), "source.txt"));
    }
    for n in [25, 27] {
        negatives.push((
            "dnkey",
            format!("dnkey-{}-{}", body(n), body(52)),
            "source.txt",
        ));
    }
    for n in [51, 53] {
        negatives.push((
            "dnkey",
            format!("dnkey-{}-{}", body(26), body(n)),
            "source.txt",
        ));
    }
    for n in [7, 9] {
        let bad_uuid = format!("{}-c1d8-0563-a7f2-b9e4c1d80563", hex(n));
        for label in ["heroku", "hubspot", "snyk_token", "squarespace"] {
            negatives.push((label, bad_uuid.clone(), "source.txt"));
        }
        negatives.push((
            "plaid",
            format!("access-production-{bad_uuid}"),
            "source.txt",
        ));
        negatives.push((
            "BUNDLE_GEMS__CONTRIBSYS__COM",
            format!("{}:{}", hex(n), hex(8)),
            "source.txt",
        ));
    }
    for n in [34, 36] {
        negatives.push(("lob", format!("live_{}", hex(n)), "source.txt"));
    }
    for n in [31, 33] {
        negatives.push(("mailchimp", format!("{}-us42", hex(n)), "source.txt"));
        negatives.push(("mailgun", format!("key-{}", hex(n)), "source.txt"));
        negatives.push((
            "mailgun",
            format!("{}-a7g2b9h4-h4c1d805", hex(n)),
            "source.txt",
        ));
    }
    for n in [39, 41] {
        negatives.push(("Okta", format!("00{}", body(n)), "source.txt"));
        negatives.push(("sonar_token", format!("squ_{}", body(n)), "source.txt"));
    }
    for n in [33, 35] {
        negatives.push(("telegr", format!("19283:A{}", body(n)), "source.txt"));
    }
    for n in [58, 60] {
        negatives.push(("typeform", format!("tfp_{}", body(n)), "source.txt"));
    }
    for n in [85, 87] {
        negatives.push((
            "yandex",
            format!("t1.{}.{}", body(12), body(n)),
            "source.txt",
        ));
    }
    negatives.push(("yandex", format!("t1..{}", body(86)), "source.txt"));
    negatives.push((
        "yandex",
        format!("t1.{}===.{}", body(12), body(86)),
        "source.txt",
    ));
    negatives.push((
        "yandex",
        format!("t1.{}.{}===", body(12), body(86)),
        "source.txt",
    ));
    for n in [34, 39] {
        negatives.push(("yandex", format!("AQVN{}", body(n)), "source.txt"));
    }
    for n in [37, 39] {
        negatives.push(("yandex", format!("YC{}", body(n)), "source.txt"));
    }
    negatives.push(("mailchimp", format!("{}-us４２", hex(32)), "source.txt"));
    for (label, secret, path) in negatives {
        for post in ["", "\u{b}"] {
            assert!(
                scan(
                    selected(),
                    format!("{label}={post}{secret}\\\"").as_bytes(),
                    path
                )
                .is_empty(),
                "{label} length/alphabet"
            );
        }
    }
}

#[test]
fn context_vt_retains_source_endings_and_newline_trimming() {
    for c in cases() {
        for end in [
            "", "'", "\"", "`", " ", "\t", "\u{c}", "\\n", "\\r", "\\N", "\\R",
        ] {
            let text = format!("{}=\u{b}{}{end}", c.label, c.secret);
            let findings = scan(selected(), text.as_bytes(), c.path);
            if c.source == "okta-access-token" && matches!(end, "\\N" | "\\R") {
                assert!(findings.is_empty());
            } else {
                assert_eq!(findings.len(), 1, "{}, {end:?}", c.source);
                assert_eq!(findings[0].match_range(), exact(0, text.len()));
            }
        }
        for end in ["\n", "\r\n"] {
            let text = format!("{}=\u{b}{}{end}", c.label, c.secret);
            let findings = scan(selected(), text.as_bytes(), c.path);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].match_range(), exact(0, text.len() - 1));
        }
    }
}

#[test]
fn full_match_preambles_and_repeated_raw_occurrences_remain_explicit() {
    for c in cases() {
        for width in [0, 1, 50, 51, 100, 101] {
            let pre = "z".repeat(width);
            let text = format!("{pre}{}={}\\\"", c.label, c.secret);
            let findings = scan(selected(), text.as_bytes(), c.path);
            assert_eq!(findings.len(), 1);
            let retained = width.min(if c.source == "okta-access-token" {
                100
            } else {
                50
            });
            assert_eq!(
                findings[0].match_range(),
                exact(width - retained, text.len())
            );
            assert_eq!(
                findings[0].secret_range(),
                exact(
                    width + c.label.len() + 1,
                    width + c.label.len() + 1 + c.secret.len()
                )
            );
        }
        let first = format!("{}={}\\\"", c.label, c.secret);
        let second = format!("{}=\u{b}{};", c.label, c.secret);
        let mut input = b"\xff\n".to_vec();
        input.extend_from_slice(first.as_bytes());
        input.extend_from_slice(b"\xfe\n");
        let second_start = input.len();
        input.extend_from_slice(second.as_bytes());
        let found = scan(selected(), &input, c.path);
        assert_eq!(found.len(), 2);
        for (prefix, post, expected_id) in [(2, 0, "delimiter"), (second_start, 1, "context-vt")] {
            let id = format!("rustleaks.{}-{expected_id}", c.source);
            let f = found
                .iter()
                .find(|f| f.rule_id().as_bytes() == id.as_bytes())
                .unwrap();
            let start = prefix + c.label.len() + 1 + post;
            assert_eq!(f.secret_range(), exact(start, start + c.secret.len()));
        }
        let id = format!("rustleaks.{}-delimiter", c.source);
        let mut value = rule(&id);
        let al: toml::Value = toml::from_str("regexTarget='match'\nregexes=['^zz']").unwrap();
        value["allowlists"] = toml::Value::Array(vec![al]);
        assert!(
            scan(
                &single(value),
                format!("zz{}={}\\\"", c.label, c.secret).as_bytes(),
                c.path
            )
            .is_empty()
        );
    }
}

#[test]
fn residual_vt_and_old_openai_languages_do_not_duplicate_existing_companions() {
    for (source, token) in residual_vt_tokens() {
        let text = format!("{token}\u{b}");
        assert!(scan(without_companions(), text.as_bytes(), "source.txt").is_empty());
        let f = scan(selected(), text.as_bytes(), "source.txt");
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].rule_id().as_bytes(),
            format!("rustleaks.{source}-vt").as_bytes()
        );
        assert_eq!(f[0].secret_range(), exact(0, token.len()));
        assert_eq!(f[0].match_range(), exact(0, token.len() + 1));
        for end in ["", ";", "\\\"", "\\'", "\\`"] {
            let text = format!("{token}{end}");
            assert!(scan(selected(), text.as_bytes(), "source.txt").is_empty());
            assert_eq!(
                scan(composed(), text.as_bytes(), "source.txt"),
                scan(without_companions(), text.as_bytes(), "source.txt")
            );
        }
    }
    for token in legacy_openai_tokens() {
        for end in ["\\\"", "\\'", "\\`", "\u{b}"] {
            let text = format!("{token}{end}");
            assert!(scan(without_companions(), text.as_bytes(), "source.txt").is_empty());
            let f = scan(selected(), text.as_bytes(), "source.txt");
            assert_eq!(f.len(), 1);
            assert_eq!(
                f[0].rule_id().as_bytes(),
                b"rustleaks.openai-api-key-legacy-delimiter"
            );
            assert_eq!(f[0].secret_range(), exact(0, token.len()));
            assert_eq!(f[0].match_range(), exact(0, text.len()));
        }
        let ordinary = format!("{token};");
        assert!(scan(selected(), ordinary.as_bytes(), "source.txt").is_empty());
        assert_eq!(
            scan(composed(), ordinary.as_bytes(), "source.txt"),
            scan(without_companions(), ordinary.as_bytes(), "source.txt")
        );
    }
    for role in ["proj", "svcacct", "admin"] {
        for (left, right) in [(20, 20), (20, 58), (20, 74), (58, 20), (74, 20)] {
            let text = format!("sk-{role}-{}T3BlbkFJ{}\\\"", body(left), body(right));
            assert!(scan(selected(), text.as_bytes(), "source.txt").is_empty());
            assert_eq!(
                scan(composed(), text.as_bytes(), "source.txt"),
                scan(without_companions(), text.as_bytes(), "source.txt")
            );
        }
    }
    let terminal_hyphen = format!("sk-proj-{}T3BlbkFJ{}-\\\"", body(58), body(57));
    assert!(scan(selected(), terminal_hyphen.as_bytes(), "source.txt").is_empty());
}

fn assert_source_predicate_and_entropy_metadata() {
    let (config, _) = NativePolicy::builder()
        .with_pack("provider", PROVIDER_RULES_V1)
        .unwrap()
        .compile()
        .unwrap();
    for id in IDS {
        let mut value = rule(id);
        assert_eq!(
            value["allowlists"][0]["regexes"].as_array().unwrap().len(),
            13
        );
        assert!(
            value["allowlists"][0]["regexes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r.as_str().unwrap().starts_with("(?:"))
        );
        assert_eq!(
            value["allowlists"][0]["stopwords"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        if let Some(entropy) = value.get("entropy") {
            let threshold = entropy["threshold"].as_float().unwrap();
            assert_eq!(
                config.rule(id).unwrap().native_entropy(),
                Some(("byte-shannon-f64-v1", "le", threshold))
            );
            assert_eq!(
                config
                    .select_rules([id])
                    .unwrap()
                    .rule(id)
                    .unwrap()
                    .native_entropy(),
                config.rule(id).unwrap().native_entropy()
            );
            value["regex"] = toml::Value::String("([A-Z]{4,800})".into());
            value["keywords"] = toml::Value::Array(vec![]);
            value.as_table_mut().unwrap().remove("path");
            let engine = single(value);
            let (equal, above) = match threshold {
                2.0 => ("ABCD", "ABCDE"),
                3.0 => ("ABCDEFGH", "ABCDEFGHI"),
                4.0 => ("ABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOPQ"),
                _ => panic!("unreviewed threshold"),
            };
            assert!(scan(&engine, equal.as_bytes(), "source.txt").is_empty());
            assert_eq!(scan(&engine, above.as_bytes(), "source.txt").len(), 1);
        } else {
            assert!(config.rule(id).unwrap().native_entropy().is_none());
        }
    }
}

#[test]
fn source_predicates_paths_keywords_and_byte_entropy_stay_attached() {
    assert_source_predicate_and_entropy_metadata();
    let mut seen = std::collections::BTreeSet::new();
    for c in cases().into_iter().filter(|c| seen.insert(c.source)) {
        let id = format!("rustleaks.{}-context-vt", c.source);
        let text = format!("{}=\u{b}{};", c.label, c.secret);
        for predicate in [
            "regexTarget='secret'\nregexes=['.']",
            "regexTarget='match'\nregexes=['.']",
            "regexTarget='line'\nregexes=['.']",
            "paths=['source[.](txt|tf)$']",
            "commits=['synthetic-commit']",
        ] {
            let mut value = rule(&id);
            let al: toml::Value = toml::from_str(predicate).unwrap();
            value["allowlists"] = toml::Value::Array(vec![al]);
            let engine = single(value);
            let fragment = Fragment::builder(text.as_bytes())
                .file_path(c.path)
                .commit("synthetic-commit")
                .build();
            assert!(
                engine
                    .scan_fragment(&fragment, &ScanOptions::default())
                    .findings()
                    .is_empty()
            );
        }
        let mut value = rule(&id);
        let mut allowlist: toml::Value = toml::from_str("stopwords=[]").unwrap();
        allowlist["stopwords"] = toml::Value::Array(vec![toml::Value::String(
            c.secret[..2].to_ascii_lowercase(),
        )]);
        value["allowlists"] = toml::Value::Array(vec![allowlist]);
        assert!(scan(&single(value), text.as_bytes(), c.path).is_empty());
        let mut value = rule(&id);
        value["keywords"] = toml::Value::Array(vec![toml::Value::String("required_marker".into())]);
        let engine = single(value);
        assert!(scan(&engine, text.as_bytes(), c.path).is_empty());
        assert_eq!(
            scan(
                &engine,
                format!("required_marker {text}").as_bytes(),
                c.path
            )
            .len(),
            1
        );
        for path in ["source.pdf", "node_modules/source.js", "gitleaks.toml"] {
            assert!(scan(selected(), text.as_bytes(), path).is_empty());
        }
        assert!(
            scan(
                selected(),
                format!("{text} # rustleaks:allow").as_bytes(),
                c.path
            )
            .is_empty()
        );
    }
}

#[test]
fn unbounded_yandex_segment_remains_bounded_by_caller_controls() {
    for first_length in [1, 8192, 65536] {
        for context in ["yandex=", "yandex=\u{b}"] {
            let secret = format!("t1.{}.{}", body(first_length), body(86));
            let input = format!("{context}{secret}\\\"");
            let f = scan(selected(), input.as_bytes(), "source.txt");
            assert_eq!(f.len(), 1);
            assert_eq!(
                f[0].secret_range(),
                exact(context.len(), context.len() + secret.len())
            );
            if first_length >= 8192 {
                let skipped = selected().scan_fragment(
                    &Fragment::new(input.as_bytes()),
                    &ScanOptions::builder().max_target_bytes(Some(1024)).build(),
                );
                assert!(skipped.findings().is_empty());
            }
            for budget in [
                ScanBudget::unlimited().max_finding_records(0),
                ScanBudget::unlimited().max_work_units(1),
                ScanBudget::unlimited().max_finding_payload_bytes(1),
            ] {
                let result = selected().scan_fragment_controlled(
                    &Fragment::new(input.as_bytes()),
                    &ScanOptions::default(),
                    &ScanControl::unlimited().with_budget(budget),
                );
                assert!(!result.is_complete());
                assert!(result.findings().is_empty());
            }
        }
    }
    let low = b"password=\"aaaaaaaa\"\\\"";
    let result = selected().scan_fragment_controlled(
        &Fragment::builder(low).file_path("source.tf").build(),
        &ScanOptions::default(),
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(0)),
    );
    assert!(result.is_complete());
    assert_eq!(result.usage().finding_records(), 0);
}
