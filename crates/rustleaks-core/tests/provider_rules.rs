//! Independent synthetic controls for the explicitly selected provider pack.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::sync::OnceLock;

use rustleaks_core::config::{ConfigLoader, RawConfig};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::native::{
    EXTRA_RULES_V1, NativeEngine, NativePolicy, PROVIDER_RULES_V1, PROVIDER_RULES_V1_SHA256,
};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

// These bounds are independently specified detector scopes, not read from the
// configuration under test. All values are synthetic and are never validated.
const CASES: [(&str, &str, usize); 5] = [
    ("rustleaks.groq-api-key", "gsk_", 52),
    ("rustleaks.cerebras-api-key", "csk-", 48),
    ("rustleaks.replicate-api-token", "r8_", 37),
    ("rustleaks.nvidia-api-key", "nvapi-", 60),
    ("rustleaks.nvidia-api-key", "nvapi-", 70),
];

fn body(length: usize) -> String {
    "Q7m2Z9v4L1c8R5s0N6b3X"
        .chars()
        .cycle()
        .take(length)
        .collect()
}

fn token(prefix: &str, length: usize) -> String {
    format!("{prefix}{}", body(length))
}

fn isolated() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(
            ConfigLoader::new()
                .compile(scalar_provider_config())
                .unwrap(),
        )
        .build()
        .unwrap()
    })
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

fn scan(engine: &Engine, bytes: &[u8]) -> Vec<Finding> {
    let result = engine.scan_fragment(&Fragment::new(bytes), &ScanOptions::default());
    assert!(result.is_complete());
    result.findings().to_vec()
}

fn range(start: usize, end: usize) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

#[test]
fn synthetic_positives_have_independent_exact_spans_and_locations() {
    for (id, prefix, length) in CASES {
        let secret = token(prefix, length);
        let input = format!("lead\nx {secret};");
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{id}");
        let finding = &findings[0];
        assert_eq!(finding.rule_id().as_bytes(), id.as_bytes());
        assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
        assert_eq!(
            finding.match_text().as_bytes(),
            format!("{secret};").as_bytes()
        );
        assert_eq!(finding.secret_range(), range(7, 7 + secret.len()));
        assert_eq!(finding.match_range(), range(7, 8 + secret.len()));
        // Fragment::new has start_line=0. Frozen M4-LOCATION-003 includes
        // the preceding LF in the byte-column origin.
        assert_eq!(
            finding.location(),
            Location::new(1, 1, 4, 4 + secret.len()).unwrap()
        );
    }
}

#[test]
fn body_bounds_alphabets_and_prefixes_reject_near_misses() {
    for (id, prefix, minimum, maximum) in [
        ("groq", "gsk_", 52, 52),
        ("cerebras", "csk-", 48, 48),
        ("replicate", "r8_", 37, 37),
        ("nvidia", "nvapi-", 60, 70),
    ] {
        for length in [minimum - 1, maximum + 1] {
            assert!(
                scan(isolated(), format!("{};", token(prefix, length)).as_bytes()).is_empty(),
                "{id}, length {length}"
            );
        }
        let secret = token(prefix, minimum);
        for input in [
            format!("_{secret};"),
            format!("{secret}!,"),
            format!("{secret}?;"),
            format!("{};", secret.replacen(prefix, "wrong_", 1)),
            format!(
                "{prefix}{}!{};",
                body(minimum / 2),
                body(minimum - minimum / 2 - 1)
            ),
        ] {
            assert!(scan(isolated(), input.as_bytes()).is_empty(), "{id}");
        }
    }
    let nvidia = format!("nvapi-{}_{}-{};", body(20), body(20), body(18));
    assert_eq!(scan(isolated(), nvidia.as_bytes()).len(), 1);
}

#[test]
fn ascii_case_and_delimiters_do_not_enable_unicode_folds() {
    for (id, prefix, length) in CASES {
        let secret = token(prefix, length);
        assert_eq!(
            scan(isolated(), secret.to_ascii_uppercase().as_bytes()).len(),
            1,
            "{id}"
        );
        for suffix in [
            "", ";", " ", "\t", "\u{b}", "\u{c}", "\"", "'", "`", "\\\"", "\\'", "\\`", "\\n",
            "\\N", "\\r", "\\R",
        ] {
            let input = format!("{secret}{suffix}");
            let findings = scan(isolated(), input.as_bytes());
            assert_eq!(findings.len(), 1, "{id}, suffix {suffix:?}");
            assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
            assert_eq!(findings[0].secret_range(), range(0, secret.len()));
            assert_eq!(findings[0].match_range(), range(0, input.len()));
        }
        // Unicode case-insensitive [A-Z] would accept these non-ASCII folds.
        for fold in ["\u{17f}", "\u{212a}"] {
            let input = format!("{prefix}{fold}{};", body(length - 1));
            assert!(
                scan(isolated(), input.as_bytes()).is_empty(),
                "{id}, {fold}"
            );
        }
    }
}

#[test]
fn invalid_bytes_repeats_and_newlines_preserve_source_geometry() {
    for (id, prefix, length) in CASES {
        let secret = token(prefix, length);
        let mut input = b"\xff\n".to_vec();
        input.extend_from_slice(secret.as_bytes());
        input.extend_from_slice(b";\xfe\n");
        input.extend_from_slice(secret.as_bytes());
        input.extend_from_slice(b"\r\n");
        let findings = scan(isolated(), &input);
        assert_eq!(findings.len(), 2, "{id}");
        assert_eq!(findings[0].secret_range(), range(2, 2 + secret.len()));
        assert_eq!(findings[0].match_range(), range(2, 3 + secret.len()));
        let second = 5 + secret.len();
        assert_eq!(
            findings[1].secret_range(),
            range(second, second + secret.len())
        );
        // Frozen M4-TRIM-003 trims LF only, retaining the consumed CR. The
        // following LF is not part of the single-delimiter expression.
        assert_eq!(
            findings[1].match_range(),
            range(second, second + secret.len() + 1)
        );
        assert_eq!(
            findings[1].match_text().as_bytes(),
            format!("{secret}\r").as_bytes()
        );
        assert_eq!(
            findings[1].location(),
            Location::new(2, 2, 2, secret.len() + 2).unwrap()
        );
    }
}

#[test]
fn inherited_entropy_thresholds_reject_equal_and_lower_values() {
    let raw: RawConfig = scalar_provider_config();
    for (id, threshold, equal, above) in [
        (
            "rustleaks.groq-api-key",
            3.5_f64,
            "ABCDEFGHIIJJKKLL",
            "ABCDEFGHIJKLMNOP",
        ),
        ("rustleaks.cerebras-api-key", 3.0, "ABCDEFGH", "ABCDEFGHI"),
        (
            "rustleaks.replicate-api-token",
            3.0,
            "ABCDEFGH",
            "ABCDEFGHI",
        ),
        (
            "rustleaks.nvidia-api-key",
            3.5,
            "ABCDEFGHIIJJKKLL",
            "ABCDEFGHIJKLMNOP",
        ),
        (
            "rustleaks.openai-api-key-20-segment",
            3.0,
            "ABCDEFGH",
            "ABCDEFGHI",
        ),
        (
            "rustleaks.flyio-flyv1",
            4.0,
            "ABCDEFGHIJKLMNOP",
            "ABCDEFGHIJKLMNOPQ",
        ),
    ] {
        let mut rule = raw.rules.iter().find(|rule| rule.id == id).unwrap().clone();
        assert_eq!(rule.entropy.to_bits(), threshold.to_bits());
        assert_eq!(rule.secret_group, 1);
        // Probe the configured threshold independently of the provider format.
        // Eight equally likely symbols have entropy 3. The 16-byte 3.5 case
        // has eight frequency-one symbols and four frequency-two symbols.
        rule.regex = "([A-Z]{8,32})".into();
        rule.keywords.clear();
        let config = RawConfig {
            rules: vec![rule],
            ..RawConfig::default()
        };
        let engine = Engine::builder(ConfigLoader::new().compile(config).unwrap())
            .build()
            .unwrap();
        assert!(scan(&engine, b"AABBCCDD").is_empty());
        assert!(scan(&engine, equal.as_bytes()).is_empty());
        assert_eq!(scan(&engine, above.as_bytes()).len(), 1);
    }
    for (_, prefix, length) in CASES {
        assert!(
            scan(
                isolated(),
                format!("{prefix}{};", "A".repeat(length)).as_bytes()
            )
            .is_empty()
        );
    }
}

#[test]
fn inherited_allowlists_and_allow_markers_remain_effective() {
    let engine = composed().engine();
    let secret = token("gsk_", 52);
    for path in ["settings.pdf", "node_modules/example.js", "gitleaks.toml"] {
        let fragment = Fragment::builder(secret.as_bytes()).file_path(path).build();
        let result = engine.scan_fragment(&fragment, &ScanOptions::default());
        assert!(result.is_complete());
        assert!(result.findings().is_empty(), "{path}");
    }
    // Bun is excluded in the pinned Betterleaks source but not the inherited
    // Rustleaks default. This is a declared source-policy difference.
    let fragment = Fragment::builder(secret.as_bytes())
        .file_path("bun.lock")
        .build();
    assert_eq!(
        engine
            .scan_fragment(&fragment, &ScanOptions::default())
            .findings()
            .len(),
        1
    );
    for body in [
        format!("false{}", body(47)),
        format!("abcdefghijklmnopqrstuvwxyz{}", body(26)),
    ] {
        assert!(scan(engine, format!("gsk_{body};").as_bytes()).is_empty());
    }
    let marked = format!("{secret}; # rustleaks:allow");
    assert!(scan(engine, marked.as_bytes()).is_empty());
    let options = ScanOptions::builder().honor_allow_markers(false).build();
    assert_eq!(
        engine
            .scan_fragment(&Fragment::new(marked.as_bytes()), &options)
            .findings()
            .len(),
        1
    );
}

#[test]
fn rule_local_and_targeted_global_allowlists_only_suppress_the_selected_rule() {
    for global in [false, true] {
        let mut raw: RawConfig = scalar_provider_config();
        let allowlist: RawConfig = toml::from_str(
            "[[rules]]\nid='allowlist-source'\n[[rules.allowlists]]\nregexTarget='secret'\nregexes=['^gsk_']\n[[allowlists]]\ntargetRules=['rustleaks.groq-api-key']\npaths=['^synthetic[.]conf$']\n"
        ).unwrap();
        if global {
            raw.allowlists = allowlist.allowlists;
        } else {
            raw.rules
                .iter_mut()
                .find(|rule| rule.id == "rustleaks.groq-api-key")
                .unwrap()
                .allowlists
                .clone_from(&allowlist.rules[0].allowlists);
        }
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        let input = format!("{};\n{};", token("gsk_", 52), token("r8_", 37));
        let fragment = Fragment::builder(input.as_bytes())
            .file_path("synthetic.conf")
            .build();
        let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
        assert!(outcome.is_complete());
        assert_eq!(outcome.findings().len(), 1);
        assert_eq!(
            outcome.findings()[0].rule_id().as_bytes(),
            b"rustleaks.replicate-api-token"
        );
    }
}

#[test]
fn explicit_composition_preserves_specific_alerts_and_reports_generic_attribution() {
    let base = NativePolicy::builder().build().unwrap();
    let old_secret = format!("ghp_{}", body(36));
    let new_secret = token("r8_", 37);
    let input = format!("{old_secret};\napi_key = '{new_secret}';\n");
    let old = scan(base.engine(), input.as_bytes());
    let new = scan(composed().engine(), input.as_bytes());
    let old_provider = old
        .iter()
        .find(|finding| finding.rule_id().as_bytes() == b"github-pat")
        .unwrap();
    assert!(new.contains(old_provider));
    assert!(
        old.iter()
            .any(|finding| finding.rule_id().as_bytes() == b"generic-api-key"
                && finding.secret().as_bytes() == new_secret.as_bytes())
    );
    assert!(new.iter().any(|finding| finding.rule_id().as_bytes()
        == b"rustleaks.replicate-api-token"
        && finding.secret().as_bytes() == new_secret.as_bytes()));
    assert!(
        !new.iter()
            .any(|finding| finding.rule_id().as_bytes() == b"generic-api-key")
    );
    assert!(scan(base.engine(), new_secret.as_bytes()).is_empty());
    assert_eq!(scan(composed().engine(), new_secret.as_bytes()).len(), 1);
    assert!(
        base.engine()
            .config()
            .rule("rustleaks.replicate-api-token")
            .is_none()
    );
}

#[test]
fn pack_identity_binds_exact_bytes_and_composition_order() {
    let providers = composed().identity().builtin_review_reference().unwrap();
    assert!(providers.contains(PROVIDER_RULES_V1_SHA256));
    let both = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .build()
        .unwrap()
        .identity()
        .clone();
    let reversed = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .unwrap()
        .build()
        .unwrap()
        .identity()
        .clone();
    assert_ne!(both, reversed);
    assert_ne!(
        both.builtin_review_reference(),
        reversed.builtin_review_reference()
    );
    let changed = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", &format!("{PROVIDER_RULES_V1}\n"))
        .unwrap()
        .build()
        .unwrap();
    assert!(changed.identity().builtin_review_reference().is_none());
    let mislabeled = NativePolicy::builder()
        .with_pack("custom-providers", PROVIDER_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    assert!(mislabeled.identity().builtin_review_reference().is_none());
}

#[test]
fn dense_provider_candidates_respect_existing_finding_and_work_budgets() {
    let input = format!("{};\n", token("gsk_", 52)).repeat(32);
    let fragment = Fragment::new(input.as_bytes());
    let options = ScanOptions::default();
    let full = isolated().scan_fragment(&fragment, &options);
    assert!(full.is_complete());
    assert_eq!(full.findings().len(), 32);
    assert_eq!(full.usage().finding_records(), 32);
    let bounded = isolated().scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(3)),
    );
    assert!(!bounded.is_complete());
    assert_eq!(bounded.usage().finding_records(), 3);
    assert!(bounded.findings().is_empty());
    let exact = isolated().scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited()
            .with_budget(ScanBudget::unlimited().max_work_units(full.usage().work_units())),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.findings(), full.findings());
    assert_eq!(exact.usage(), full.usage());
    for text in ["ordinary text ".repeat(512), "gsk_! ".repeat(512)] {
        assert!(scan(isolated(), text.as_bytes()).is_empty());
    }
}

// These companion expectations are independently specified from the pinned
// source grammars. Physical source coordinates are not Finding::location:
// Fragment::new starts at line 0, and the frozen column origin includes LF.
const ESCAPED_CASES: [(&str, &str, &str, usize, &str); 3] = [
    (
        "rustleaks.anthropic-api-key-escaped",
        "anthropic-api-key",
        "sk-ant-api03-",
        93,
        "AA",
    ),
    (
        "rustleaks.anthropic-admin-api-key-escaped",
        "anthropic-admin-api-key",
        "sk-ant-admin01-",
        93,
        "AA",
    ),
    (
        "rustleaks.digitalocean-refresh-token-escaped",
        "digitalocean-refresh-token",
        "dor_v1_",
        64,
        "",
    ),
];

fn companion_body(prefix: &str, length: usize) -> String {
    if prefix == "dor_v1_" {
        "a7f2b9e4c1d80563".chars().cycle().take(length).collect()
    } else {
        body(length)
    }
}

fn openai(role: &str, left: usize, right: usize) -> String {
    format!("sk-{role}-{}T3BlbkFJ{}", body(left), body(right))
}

fn base() -> &'static NativeEngine {
    static ENGINE: OnceLock<NativeEngine> = OnceLock::new();
    ENGINE.get_or_init(|| NativePolicy::builder().build().unwrap())
}

fn both_packs() -> &'static NativeEngine {
    static ENGINE: OnceLock<NativeEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        NativePolicy::builder()
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .build()
            .unwrap()
    })
}

fn assert_companion_geometry(finding: &Finding, id: &str, secret: &str, suffix: &str) {
    assert_eq!(finding.rule_id().as_bytes(), id.as_bytes());
    assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
    assert_eq!(finding.secret_range(), range(7, 7 + secret.len()));
    assert_eq!(
        finding.match_text().as_bytes(),
        format!("{secret}{suffix}").as_bytes()
    );
    assert_eq!(
        finding.match_range(),
        range(7, 7 + secret.len() + suffix.len())
    );
    assert_eq!(
        finding.location(),
        Location::new(1, 1, 4, 3 + secret.len() + suffix.len()).unwrap()
    );
}

#[test]
fn escaped_companions_add_only_three_delimiters_and_preserve_old_findings() {
    for (id, old_id, prefix, length, tail) in ESCAPED_CASES {
        let secret = format!("{prefix}{}{tail}", companion_body(prefix, length));
        for suffix in ["\\\"", "\\'", "\\`"] {
            let input = format!("lead\nx {secret}{suffix}");
            assert!(
                scan(base().engine(), input.as_bytes()).is_empty(),
                "{old_id}"
            );
            for engine in [isolated(), composed().engine(), both_packs().engine()] {
                let findings = scan(engine, input.as_bytes());
                assert_eq!(findings.len(), 1, "{id}, {suffix:?}");
                assert_companion_geometry(&findings[0], id, &secret, suffix);
            }
        }
        for suffix in ["", "\"", "'", "`", ";", " ", "\t", "\u{c}", "\\n", "\\r"] {
            let input = format!("lead\nx {secret}{suffix}");
            assert!(scan(isolated(), input.as_bytes()).is_empty(), "{id}");
            let previous = scan(base().engine(), input.as_bytes());
            assert_eq!(previous.len(), 1, "{old_id}, {suffix:?}");
            assert_companion_geometry(&previous[0], old_id, &secret, suffix);
            assert_eq!(scan(composed().engine(), input.as_bytes()), previous);
            assert_eq!(scan(both_packs().engine(), input.as_bytes()), previous);
        }
        // The existing escaped-only rule remains unchanged; a separate
        // explicitly selected companion owns the missing VT occurrence.
        let vt_input = format!("lead\nx {secret}\u{b}");
        assert!(scan(isolated(), vt_input.as_bytes()).is_empty());
        assert!(scan(base().engine(), vt_input.as_bytes()).is_empty());
        for engine in [composed().engine(), both_packs().engine()] {
            let findings = scan(engine, vt_input.as_bytes());
            assert_eq!(findings.len(), 1);
            assert_companion_geometry(
                &findings[0],
                &format!("rustleaks.{old_id}-vt"),
                &secret,
                "\u{b}",
            );
        }
        for length in [length - 1, length + 1] {
            let input = format!("{prefix}{}{tail}\\\"", companion_body(prefix, length));
            assert!(
                scan(composed().engine(), input.as_bytes()).is_empty(),
                "{id}"
            );
        }
        for input in [
            format!("_{secret}\\\""),
            format!("{secret}\\\\\""),
            format!("{secret}\\x"),
            format!("{secret}!\\\""),
        ] {
            assert!(
                scan(composed().engine(), input.as_bytes()).is_empty(),
                "{id}"
            );
        }
    }
}

#[test]
fn openai_simple_new_and_existing_tokens_select_their_respective_rules() {
    let id = "rustleaks.openai-api-key-20-segment";
    for role in ["proj", "svcacct", "admin"] {
        for left in [20, 58, 74] {
            for right in [20, 58, 74] {
                let secret = openai(role, left, right);
                let new_pair = left == 20 || right == 20;
                for suffix in [";", "", "\"", "'", "`", "\\n", "\\r"] {
                    let input = format!("lead\nx {secret}{suffix}");
                    let old = scan(base().engine(), input.as_bytes());
                    assert_eq!(old.len(), usize::from(!new_pair));
                    assert_eq!(
                        scan(isolated(), input.as_bytes()).len(),
                        usize::from(new_pair)
                    );
                    for engine in [composed().engine(), both_packs().engine()] {
                        let findings = scan(engine, input.as_bytes());
                        assert_eq!(findings.len(), 1, "{role}/{left}/{right}");
                        assert_companion_geometry(
                            &findings[0],
                            if new_pair { id } else { "openai-api-key" },
                            &secret,
                            suffix,
                        );
                        if !new_pair {
                            assert_eq!(findings, old);
                        }
                    }
                }
                for suffix in ["\\\"", "\\'", "\\`", "\u{b}"] {
                    let input = format!("lead\nx {secret}{suffix}");
                    assert!(scan(base().engine(), input.as_bytes()).is_empty());
                    assert_eq!(
                        scan(isolated(), input.as_bytes()).len(),
                        usize::from(new_pair)
                    );
                    for engine in [composed().engine(), both_packs().engine()] {
                        let findings = scan(engine, input.as_bytes());
                        assert_eq!(findings.len(), 1);
                        assert_companion_geometry(
                            &findings[0],
                            if new_pair {
                                id
                            } else {
                                "rustleaks.openai-api-key-legacy-delimiter"
                            },
                            &secret,
                            suffix,
                        );
                    }
                }
            }
        }
        for length in [19, 21, 57, 59, 73, 75] {
            for secret in [openai(role, length, 20), openai(role, 20, length)] {
                for suffix in [";", "\\\""] {
                    assert!(
                        scan(composed().engine(), format!("{secret}{suffix}").as_bytes())
                            .is_empty()
                    );
                }
            }
        }
    }
    let legacy = format!("sk-{}T3BlbkFJ{};", body(20), body(20));
    let old = scan(base().engine(), legacy.as_bytes());
    assert_eq!(old.len(), 1);
    assert!(scan(isolated(), legacy.as_bytes()).is_empty());
    assert_eq!(scan(composed().engine(), legacy.as_bytes()), old);
    for secret in [
        openai("user", 20, 20),
        openai("proj", 20, 20).replace("T3BlbkFJ", "T3BLBKFJ"),
        openai("proj", 20, 20).to_ascii_uppercase(),
        format!("_{}", openai("proj", 20, 20)),
        format!("{}-", &openai("proj", 20, 20)[..55]),
    ] {
        assert!(scan(composed().engine(), format!("{secret};").as_bytes()).is_empty());
    }
}

#[test]
fn nested_openai_shapes_retain_both_specific_candidates_at_distinct_spans() {
    let short = openai("proj", 20, 20);
    assert_eq!(short.len(), 56);
    // Old (58,58): the right segment contains Q- plus a new 56-byte key.
    let old_outer = format!("sk-proj-{}T3BlbkFJQ-{short}", body(58));
    assert_eq!(old_outer.len(), 132);
    // New (74,20): the last 23 left-segment bytes start an old unscoped key.
    let new_outer = format!("sk-proj-{}-sk-{}T3BlbkFJ{}", body(50), body(20), body(20));
    assert_eq!(new_outer.len(), 110);

    for (secret, old_start, new_start, end) in [(old_outer, 0, 76, 132), (new_outer, 59, 0, 110)] {
        let input = format!("{secret};");
        for (engine, id, start) in [
            (base().engine(), "openai-api-key", old_start),
            (isolated(), "rustleaks.openai-api-key-20-segment", new_start),
        ] {
            let findings = scan(engine, input.as_bytes());
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].rule_id().as_bytes(), id.as_bytes());
            assert_eq!(
                findings[0].secret().as_bytes(),
                &input.as_bytes()[start..end]
            );
            assert_eq!(findings[0].secret_range(), range(start, end));
            assert_eq!(findings[0].match_range(), range(start, end + 1));
        }
        let previous = scan(base().engine(), input.as_bytes());
        for engine in [composed().engine(), both_packs().engine()] {
            let findings = scan(engine, input.as_bytes());
            assert_eq!(findings.len(), 2);
            assert_eq!(findings[0], previous[0]);
            assert_eq!(
                findings[1].rule_id().as_bytes(),
                b"rustleaks.openai-api-key-20-segment"
            );
            assert_eq!(findings[1].secret_range(), range(new_start, end));
            assert_eq!(findings[1].match_range(), range(new_start, end + 1));
        }
    }
}

#[test]
fn flyv1_preserves_legacy_fly_forms_and_exact_new_capture() {
    for (prefix, length) in [("fo1_", 43), ("fm1a_", 100), ("fm1r_", 100), ("fm2_", 100)] {
        let secret = token(prefix, length);
        let input = format!("lead\nx {secret};");
        let old = scan(base().engine(), input.as_bytes());
        assert_eq!(old.len(), 1, "{prefix}");
        assert_companion_geometry(&old[0], "flyio-access-token", &secret, ";");
        assert!(scan(isolated(), input.as_bytes()).is_empty());
        assert_eq!(scan(composed().engine(), input.as_bytes()), old);
        assert_eq!(scan(both_packs().engine(), input.as_bytes()), old);
    }
    for length in [99, 100, 101] {
        for separator in [" ", "\t", "\u{b}", "\u{c}", "\r"] {
            let secret = format!("FlyV1{separator}{}", body(length));
            for suffix in [";", "", "\"", "'", "`", "\\\"", "\\'", "\\`", "\\n", "\\r"] {
                let input = format!("lead\nx {secret}{suffix}");
                assert!(scan(base().engine(), input.as_bytes()).is_empty());
                let findings = scan(composed().engine(), input.as_bytes());
                assert_eq!(findings.len(), usize::from(length >= 100));
                if length >= 100 {
                    assert_companion_geometry(
                        &findings[0],
                        "rustleaks.flyio-flyv1",
                        &secret,
                        suffix,
                    );
                }
            }
        }
    }
    let secret = format!("FlyV1 {}=_-,/+", body(100));
    assert_eq!(scan(isolated(), secret.as_bytes()).len(), 1);
    for input in [
        format!("FlyV1{};", body(100)),
        format!("FlyV1  {};", body(100)),
        format!("flyv1 {};", body(100)),
        format!("FlyV1\u{a0}{};", body(100)),
        format!("FlyV1 {};", "A".repeat(100)),
        format!("FlyV1 {}!{};", body(50), body(49)),
    ] {
        assert!(scan(composed().engine(), input.as_bytes()).is_empty());
    }
}

fn companion_samples() -> Vec<(&'static str, String, &'static str)> {
    let mut samples: Vec<_> = ESCAPED_CASES
        .into_iter()
        .map(|(id, _, prefix, length, tail)| {
            (
                id,
                format!("{prefix}{}{tail}", companion_body(prefix, length)),
                "\\\"",
            )
        })
        .collect();
    samples.push((
        "rustleaks.openai-api-key-20-segment",
        openai("proj", 20, 20),
        ";",
    ));
    samples.push(("rustleaks.flyio-flyv1", format!("FlyV1 {}", body(100)), ";"));
    samples
}

#[test]
fn companion_bytes_case_repeats_and_locations_are_explicit() {
    for (id, secret, suffix) in companion_samples() {
        let upper = format!("{}{suffix}", secret.to_ascii_uppercase());
        assert_eq!(
            scan(isolated(), upper.as_bytes()).len(),
            usize::from(id.contains("digitalocean"))
        );
        let mut invalid = secret.as_bytes().to_vec();
        invalid[secret.len() - 5] = 0xff;
        invalid.extend_from_slice(suffix.as_bytes());
        assert!(scan(isolated(), &invalid).is_empty(), "{id}");
        for fold in ["\u{17f}", "\u{212a}"] {
            let split = secret.len() - 5;
            let input = format!("{}{fold}{}{suffix}", &secret[..split], &secret[split + 1..]);
            assert!(scan(isolated(), input.as_bytes()).is_empty(), "{id}");
        }
        let mut input = b"\xff\n".to_vec();
        input.extend_from_slice(format!("{secret}{suffix}").as_bytes());
        input.extend_from_slice(b"\xfe\n");
        input.extend_from_slice(format!("{secret}{suffix}").as_bytes());
        let findings = scan(isolated(), &input);
        assert_eq!(findings.len(), 2, "{id}");
        for (index, start) in [2, 4 + secret.len() + suffix.len()].into_iter().enumerate() {
            let finding = &findings[index];
            assert_eq!(finding.rule_id().as_bytes(), id.as_bytes());
            assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
            assert_eq!(finding.secret_range(), range(start, start + secret.len()));
            assert_eq!(
                finding.match_range(),
                range(start, start + secret.len() + suffix.len())
            );
            assert_eq!(
                finding.location(),
                Location::new(index + 1, index + 1, 2, 1 + secret.len() + suffix.len()).unwrap()
            );
        }
    }
}

#[test]
fn companion_allowlists_and_finite_limits_apply_to_each_increment() {
    for (id, secret, suffix) in companion_samples() {
        let text = format!("{secret}{suffix}");
        let fragment = Fragment::builder(text.as_bytes())
            .file_path("synthetic.pdf")
            .build();
        let outcome = composed()
            .engine()
            .scan_fragment(&fragment, &ScanOptions::default());
        assert!(outcome.is_complete());
        assert!(outcome.findings().is_empty());
        assert!(
            scan(
                composed().engine(),
                format!("{text} # rustleaks:allow").as_bytes()
            )
            .is_empty()
        );
        for global in [false, true] {
            for predicate in [
                "regexTarget='secret'\nregexes=['.']",
                "regexTarget='match'\nregexes=['.']",
                "regexTarget='line'\nregexes=['.']",
                "stopwords=['Q7m2', 'a7f2']",
                "paths=['^synthetic[.]conf$']",
                "commits=['synthetic-commit']",
            ] {
                let mut raw: RawConfig = scalar_provider_config();
                let allowlist: RawConfig = toml::from_str(&format!(
                    "[[rules]]\nid='source'\n[[rules.allowlists]]\n{predicate}\n[[allowlists]]\ntargetRules=['{id}']\n{predicate}\n"
                )).unwrap();
                if global {
                    raw.allowlists = allowlist.allowlists;
                } else {
                    raw.rules
                        .iter_mut()
                        .find(|rule| rule.id == id)
                        .unwrap()
                        .allowlists
                        .clone_from(&allowlist.rules[0].allowlists);
                }
                let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                    .build()
                    .unwrap();
                let fragment = Fragment::builder(text.as_bytes())
                    .file_path("synthetic.conf")
                    .commit("synthetic-commit")
                    .build();
                let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
                assert!(outcome.is_complete());
                assert!(outcome.findings().is_empty(), "{id}, {global}, {predicate}");
                let control = token("gsk_", 52);
                assert_eq!(scan(&engine, control.as_bytes()).len(), 1);
            }
        }
        let dense = format!("{text}\n").repeat(12);
        let fragment = Fragment::new(dense.as_bytes());
        let full = isolated().scan_fragment(&fragment, &ScanOptions::default());
        assert!(full.is_complete());
        assert_eq!(full.findings().len(), 12);
        let bounded = isolated().scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(2)),
        );
        assert!(!bounded.is_complete());
        assert!(bounded.findings().is_empty());
        assert_eq!(bounded.usage().finding_records(), 2);
        let exact = isolated().scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_work_units(full.usage().work_units())),
        );
        assert!(exact.is_complete());
        assert_eq!(exact.findings(), full.findings());
    }
}

#[test]
fn companion_source_filters_and_multiline_capture_are_preserved() {
    let raw: RawConfig = scalar_provider_config();
    for (id, _, prefix, length, tail) in ESCAPED_CASES {
        let rule = raw.rules.iter().find(|rule| rule.id == id).unwrap();
        assert_eq!(rule.entropy.to_bits(), 0.0_f64.to_bits());
        assert_eq!(rule.secret_group, 1);
        let low_entropy = format!("{prefix}{}{tail}\\\"", "a".repeat(length));
        assert_eq!(scan(isolated(), low_entropy.as_bytes()).len(), 1);
        if prefix.starts_with("sk-ant-") {
            let rejected = format!("{prefix}false{}{tail}\\\"", body(length - 5));
            assert_eq!(scan(isolated(), rejected.as_bytes()).len(), 1);
            assert!(scan(composed().engine(), rejected.as_bytes()).is_empty());
            let wrong_tail = format!("{prefix}{}Aa\\\"", body(length));
            assert!(scan(isolated(), wrong_tail.as_bytes()).is_empty());
        }
    }
    let low_openai = format!("sk-proj-{}T3BlbkFJ{};", "A".repeat(20), "A".repeat(20));
    assert!(scan(isolated(), low_openai.as_bytes()).is_empty());
    let allowed_alphabet = format!("sk-proj-_-{}T3BlbkFJ{}_;", body(18), body(19));
    assert_eq!(scan(isolated(), allowed_alphabet.as_bytes()).len(), 1);
    for secret in [openai("proj", 20, 20), format!("FlyV1 {}", body(100))] {
        for suffix in ["\\N", "\\R", "?", "\\\\\""] {
            assert!(scan(isolated(), format!("{secret}{suffix}").as_bytes()).is_empty());
        }
    }
    // Final LF supplies the ending line to the frozen location helper; the
    // inner LF is part of capture 1 and must not be normalized to a space.
    let secret = format!("FlyV1\n{}", body(100));
    let input = format!("lead\nx {secret};\n");
    let findings = scan(composed().engine(), input.as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
    assert_eq!(findings[0].secret_range(), range(7, 113));
    assert_eq!(findings[0].match_range(), range(7, 114));
    assert_eq!(
        findings[0].match_text().as_bytes(),
        format!("{secret};").as_bytes()
    );
    assert_eq!(findings[0].location(), Location::new(1, 2, 4, 102).unwrap());
}

// Distinct standalone provider forms selected from the pinned MIT source.
// Lengths and expected roles are authored independently of the pack TOML.
const STANDALONE_CASES: [(&str, &str, usize, usize, bool); 6] = [
    ("rustleaks.cloudsmith-api-key", "csa_", 36, 36, false),
    ("rustleaks.minimax-api-key", "sk-api-", 119, 119, true),
    ("rustleaks.posthog-personal-api-key", "phx_", 41, 49, true),
    (
        "rustleaks.figma-personal-access-token",
        "figd_",
        38,
        42,
        true,
    ),
    ("rustleaks.togetherai-api-key", "tgp_v1_", 43, 43, true),
    ("rustleaks.gcp-gemini-api", "AQ.Ab8RN6", 44, 44, false),
];

fn standalone_secret(prefix: &str, length: usize) -> String {
    if prefix == "csa_" {
        let hex: String = "a7f2b9e4c1d80563".chars().cycle().take(30).collect();
        format!("{prefix}{hex}{}", body(length - 30))
    } else {
        token(prefix, length)
    }
}

#[test]
fn standalone_provider_bounds_delimiters_and_geometry_are_independent() {
    for (id, prefix, minimum, maximum, folded) in STANDALONE_CASES {
        for length in minimum..=maximum {
            let secret = standalone_secret(prefix, length);
            for suffix in [
                "", ";", " ", "\t", "\u{b}", "\u{c}", "\"", "'", "`", "\\\"", "\\'", "\\`", "\\n",
                "\\r",
            ] {
                let input = format!("lead\nx {secret}{suffix}");
                for engine in [isolated(), composed().engine(), both_packs().engine()] {
                    let findings = scan(engine, input.as_bytes());
                    assert_eq!(
                        findings.len(),
                        1,
                        "{id}, length {length}, suffix {suffix:?}"
                    );
                    assert_companion_geometry(&findings[0], id, &secret, suffix);
                }
            }
            for suffix in ["\\N", "\\R"] {
                let input = format!("lead\nx {secret}{suffix}");
                let findings = scan(isolated(), input.as_bytes());
                assert_eq!(findings.len(), usize::from(folded));
                if folded {
                    assert_companion_geometry(&findings[0], id, &secret, suffix);
                }
            }
            let upper = format!("{};", secret.to_ascii_uppercase());
            assert_eq!(
                scan(isolated(), upper.as_bytes()).len(),
                usize::from(folded)
            );
        }
        for length in [minimum - 1, maximum + 1] {
            let text = format!("{};", standalone_secret(prefix, length));
            assert!(
                scan(composed().engine(), text.as_bytes()).is_empty(),
                "{id}, {length}"
            );
        }
        let secret = standalone_secret(prefix, minimum);
        for text in [
            format!("_{secret};"),
            format!("{secret}?;"),
            format!("{secret}\\\\\""),
            format!("{secret}\\x"),
        ] {
            assert!(scan(isolated(), text.as_bytes()).is_empty(), "{id}");
        }
        for (suffix, retained) in [("\n", ""), ("\r\n", "\r")] {
            let input = format!("lead\nx {secret}{suffix}");
            let findings = scan(isolated(), input.as_bytes());
            assert_eq!(findings.len(), 1);
            assert_companion_geometry(&findings[0], id, &secret, retained);
        }
    }
    let cloudsmith = standalone_secret("csa_", 36);
    let invalid_hex = format!("csa_A{};", &cloudsmith[5..]);
    assert!(scan(isolated(), invalid_hex.as_bytes()).is_empty());
    let invalid_tail = format!("{}_;", &cloudsmith[..cloudsmith.len() - 1]);
    assert!(scan(isolated(), invalid_tail.as_bytes()).is_empty());
    assert!(scan(isolated(), token("aq.ab8rn6", 44).as_bytes()).is_empty());
    assert!(scan(isolated(), token("AQXAb8RN6", 44).as_bytes()).is_empty());
    for (id, prefix, minimum, _, _) in STANDALONE_CASES.into_iter().skip(1) {
        let secret = format!("{prefix}{}_-", body(minimum - 2));
        let findings = scan(isolated(), format!("{secret};").as_bytes());
        assert_eq!(findings.len(), 1, "{id}");
        assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
    }
}

#[test]
fn standalone_provider_occurrences_and_generic_attribution_are_distinct() {
    for (id, prefix, minimum, _, _) in STANDALONE_CASES {
        let secret = standalone_secret(prefix, minimum);
        // Bare values have no generic assignment trigger. This is an expected
        // occurrence increment, independently specified before execution.
        let bare = format!("{secret};");
        assert!(scan(base().engine(), bare.as_bytes()).is_empty(), "{id}");
        let added = scan(composed().engine(), bare.as_bytes());
        assert_eq!(added.len(), 1, "{id}");
        assert_eq!(added[0].rule_id().as_bytes(), id.as_bytes());
        assert_eq!(added[0].secret_range(), range(0, secret.len()));
        let assigned = format!("api_key = '{secret}';");
        let old = scan(base().engine(), assigned.as_bytes());
        assert_eq!(old.len(), 1, "{id}");
        assert_eq!(old[0].rule_id().as_bytes(), b"generic-api-key");
        assert_eq!(old[0].secret().as_bytes(), secret.as_bytes());
        assert_eq!(old[0].secret_range(), range(11, 11 + secret.len()));
        for engine in [composed().engine(), both_packs().engine()] {
            let new = scan(engine, assigned.as_bytes());
            assert_eq!(new.len(), 1, "{id}");
            assert_eq!(new[0].rule_id().as_bytes(), id.as_bytes());
            assert_eq!(new[0].secret().as_bytes(), secret.as_bytes());
            assert_eq!(new[0].secret_range(), old[0].secret_range());
            assert_eq!(new[0].match_range(), range(11, 12 + secret.len()));
        }
    }
    let google = token("AIza", 35);
    let old_google = scan(base().engine(), google.as_bytes());
    assert_eq!(old_google.len(), 1);
    assert_eq!(old_google[0].rule_id().as_bytes(), b"gcp-api-key");
    assert_eq!(scan(composed().engine(), google.as_bytes()), old_google);
    assert!(scan(isolated(), google.as_bytes()).is_empty());
    for length in [41, 49] {
        let public = token("phc_", length);
        assert!(scan(isolated(), public.as_bytes()).is_empty());
        assert!(scan(composed().engine(), public.as_bytes()).is_empty());
        // Exclusion from the new personal rule does not change inherited
        // generic findings for an explicitly secret-labelled assignment.
        let input = format!("api_key = '{public}';");
        let old = scan(base().engine(), input.as_bytes());
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].rule_id().as_bytes(), b"generic-api-key");
        assert_eq!(scan(composed().engine(), input.as_bytes()), old);
    }
}

#[test]
fn standalone_provider_invalid_bytes_and_repeats_keep_exact_ranges() {
    for (id, prefix, minimum, _, _) in STANDALONE_CASES {
        let secret = standalone_secret(prefix, minimum);
        let body_start = prefix.len();
        let mut invalid = secret.as_bytes().to_vec();
        invalid[body_start + 3] = 0xff;
        invalid.push(b';');
        assert!(scan(isolated(), &invalid).is_empty(), "{id}");
        for fold in ["\u{17f}", "\u{212a}"] {
            let text = format!(
                "{}{fold}{};",
                &secret[..body_start + 3],
                &secret[body_start + 4..]
            );
            assert!(scan(isolated(), text.as_bytes()).is_empty(), "{id}");
        }
        let mut input = b"\xff\n".to_vec();
        input.extend_from_slice(secret.as_bytes());
        input.extend_from_slice(b";\xfe\n");
        input.extend_from_slice(secret.as_bytes());
        input.push(b';');
        let findings = scan(isolated(), &input);
        assert_eq!(findings.len(), 2, "{id}");
        for (index, start) in [2, 5 + secret.len()].into_iter().enumerate() {
            let finding = &findings[index];
            assert_eq!(finding.rule_id().as_bytes(), id.as_bytes());
            assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
            assert_eq!(finding.secret_range(), range(start, start + secret.len()));
            assert_eq!(
                finding.match_range(),
                range(start, start + secret.len() + 1)
            );
            assert_eq!(
                finding.location(),
                Location::new(index + 1, index + 1, 2, secret.len() + 2).unwrap()
            );
        }
    }
}

#[test]
fn standalone_provider_entropy_and_keyword_contracts_are_explicit() {
    let raw: RawConfig = scalar_provider_config();
    for (id, threshold, equal, above) in [
        (
            "rustleaks.minimax-api-key",
            3.5_f64,
            "ABCDEFGHIIJJKKLL",
            "ABCDEFGHIJKLMNOP",
        ),
        (
            "rustleaks.posthog-personal-api-key",
            3.0,
            "ABCDEFGH",
            "ABCDEFGHI",
        ),
        (
            "rustleaks.figma-personal-access-token",
            3.5,
            "ABCDEFGHIIJJKKLL",
            "ABCDEFGHIJKLMNOP",
        ),
        ("rustleaks.togetherai-api-key", 3.0, "ABCDEFGH", "ABCDEFGHI"),
        (
            "rustleaks.gcp-gemini-api",
            4.0,
            "ABCDEFGHIJKLMNOP",
            "ABCDEFGHIJKLMNOPQ",
        ),
    ] {
        let mut rule = raw.rules.iter().find(|rule| rule.id == id).unwrap().clone();
        assert_eq!(rule.entropy.to_bits(), threshold.to_bits());
        assert_eq!(rule.secret_group, 1);
        rule.regex = "([A-Z]{8,32})".into();
        rule.keywords.clear();
        let config = RawConfig {
            rules: vec![rule],
            ..RawConfig::default()
        };
        let engine = Engine::builder(ConfigLoader::new().compile(config).unwrap())
            .build()
            .unwrap();
        assert!(scan(&engine, b"AABBCCDD").is_empty());
        assert!(scan(&engine, equal.as_bytes()).is_empty());
        assert_eq!(scan(&engine, above.as_bytes()).len(), 1);
    }
    for (id, prefix, minimum, _, _) in STANDALONE_CASES {
        let rule = raw.rules.iter().find(|rule| rule.id == id).unwrap();
        let expected_keywords: Vec<String> = if prefix == "sk-api-" {
            vec!["sk-api-".into(), "minimax".into()]
        } else {
            vec![prefix.to_ascii_lowercase()]
        };
        assert_eq!(rule.keywords, expected_keywords);
        let low = format!("{prefix}{};", "0".repeat(minimum));
        assert_eq!(
            scan(isolated(), low.as_bytes()).len(),
            usize::from(prefix == "csa_"),
            "{id}"
        );
        if prefix == "csa_" {
            assert_eq!(rule.entropy.to_bits(), 0.0_f64.to_bits());
        }
    }
    let mut minimax = raw
        .rules
        .iter()
        .find(|rule| rule.id == "rustleaks.minimax-api-key")
        .unwrap()
        .clone();
    minimax.keywords = vec!["minimax".into()];
    let config = RawConfig {
        rules: vec![minimax],
        ..RawConfig::default()
    };
    let engine = Engine::builder(ConfigLoader::new().compile(config).unwrap())
        .build()
        .unwrap();
    let secret = standalone_secret("sk-api-", 119);
    assert!(scan(&engine, secret.as_bytes()).is_empty());
    assert_eq!(
        scan(&engine, format!("minimax {secret}").as_bytes()).len(),
        1
    );
    assert!(scan(&engine, format!("minimax other-{};", body(119)).as_bytes()).is_empty());
}

#[test]
fn standalone_provider_allowlists_and_long_input_limits_are_preserved() {
    for (id, prefix, minimum, maximum, _) in STANDALONE_CASES {
        let secret = standalone_secret(prefix, minimum);
        for path in ["synthetic.pdf", "node_modules/synthetic.js"] {
            let fragment = Fragment::builder(secret.as_bytes()).file_path(path).build();
            let outcome = composed()
                .engine()
                .scan_fragment(&fragment, &ScanOptions::default());
            assert!(outcome.is_complete());
            assert!(outcome.findings().is_empty());
        }
        assert!(
            scan(
                composed().engine(),
                format!("{secret}; # rustleaks:allow").as_bytes()
            )
            .is_empty()
        );
        let false_value = if prefix == "csa_" {
            format!("{}falseQ;", &secret[..secret.len() - 6])
        } else {
            format!("{prefix}false{};", body(minimum - 5))
        };
        assert_eq!(scan(isolated(), false_value.as_bytes()).len(), 1);
        assert!(scan(composed().engine(), false_value.as_bytes()).is_empty());
        for global in [false, true] {
            let mut raw: RawConfig = scalar_provider_config();
            let allowlist: RawConfig = toml::from_str(&format!(
                "[[rules]]\nid='source'\n[[rules.allowlists]]\nregexTarget='secret'\nregexes=['.']\n[[allowlists]]\ntargetRules=['{id}']\npaths=['^synthetic[.]conf$']\n"
            )).unwrap();
            if global {
                raw.allowlists = allowlist.allowlists;
            } else {
                raw.rules
                    .iter_mut()
                    .find(|rule| rule.id == id)
                    .unwrap()
                    .allowlists
                    .clone_from(&allowlist.rules[0].allowlists);
            }
            let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                .build()
                .unwrap();
            let fragment = Fragment::builder(secret.as_bytes())
                .file_path("synthetic.conf")
                .build();
            let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(outcome.is_complete());
            assert!(outcome.findings().is_empty());
            assert_eq!(scan(&engine, token("gsk_", 52).as_bytes()).len(), 1);
        }
        for text in [
            format!("{prefix}! ").repeat(512),
            format!("{prefix}{};", body(maximum + 4096)),
        ] {
            assert!(scan(isolated(), text.as_bytes()).is_empty(), "{id}");
            let limited = isolated().scan_fragment_controlled(
                &Fragment::new(text.as_bytes()),
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(1)),
            );
            assert!(!limited.is_complete());
            assert!(limited.findings().is_empty());
        }
        let dense = format!("{secret};\n").repeat(12);
        let fragment = Fragment::new(dense.as_bytes());
        let full = isolated().scan_fragment(&fragment, &ScanOptions::default());
        assert!(full.is_complete());
        assert_eq!(full.findings().len(), 12);
        let exact = isolated().scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_work_units(full.usage().work_units())),
        );
        assert!(exact.is_complete());
        assert_eq!(exact.findings(), full.findings());
        let bounded = isolated().scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(2)),
        );
        assert!(!bounded.is_complete());
        assert_eq!(bounded.usage().finding_records(), 2);
        assert!(bounded.findings().is_empty());
    }
}

// Expected syntax and role scopes authored from reviewed source definitions.
// These cases deliberately distinguish source matches from provider validity.
struct FollowupCase {
    id: &'static str,
    context: &'static str,
    secret: String,
    suffix: &'static str,
    folded: bool,
    contextual: bool,
}

fn hex_body(length: usize) -> String {
    "a7f2b9e4c1d80563".chars().cycle().take(length).collect()
}

fn contextual_followup_cases() -> Vec<FollowupCase> {
    let contexts = [
        (
            "checkout-secret-key",
            "checkout",
            format!(
                "sk_{}-{}-{}-{}-{}",
                hex_body(8),
                hex_body(4),
                hex_body(4),
                hex_body(4),
                hex_body(12)
            ),
        ),
        ("crates-io-api-key", "crates.io", format!("cio{}", body(32))),
        ("cursor-api-key", "cursor", format!("key_{}", hex_body(64))),
        ("databento-api-key", "databento", format!("db-{}", body(29))),
        (
            "elevenlabs-api-key",
            "elevenlabs",
            format!("sk_{}", hex_body(48)),
        ),
        (
            "figma-personal-access-header-token",
            "x-figma-token",
            format!(
                "{}-{}-{}-{}-{}-{}",
                hex_body(4),
                hex_body(8),
                hex_body(4),
                hex_body(4),
                hex_body(4),
                hex_body(12)
            ),
        ),
        (
            "ollama-api-key",
            "ollama",
            format!("{}.{}", hex_body(32), body(24)),
        ),
        (
            "polymarket-private-key",
            "poly_private_key",
            format!("0x{}", hex_body(64)),
        ),
        (
            "stability-ai-api-key",
            "stability",
            format!("sk-{}", body(48)),
        ),
    ];
    contexts
        .into_iter()
        .map(|(id, context, secret)| FollowupCase {
            id: match id {
                "checkout-secret-key" => "rustleaks.checkout-secret-key",
                "crates-io-api-key" => "rustleaks.crates-io-api-key",
                "cursor-api-key" => "rustleaks.cursor-api-key",
                "databento-api-key" => "rustleaks.databento-api-key",
                "elevenlabs-api-key" => "rustleaks.elevenlabs-api-key",
                "figma-personal-access-header-token" => {
                    "rustleaks.figma-personal-access-header-token"
                }
                "ollama-api-key" => "rustleaks.ollama-api-key",
                "polymarket-private-key" => "rustleaks.polymarket-private-key",
                "stability-ai-api-key" => "rustleaks.stability-ai-api-key",
                _ => unreachable!(),
            },
            context,
            secret,
            suffix: ";",
            folded: id != "polymarket-private-key",
            contextual: true,
        })
        .collect()
}

fn followup_cases() -> Vec<FollowupCase> {
    let mut cases = contextual_followup_cases();
    for (id, secret, suffix) in [
        (
            "rustleaks.slack-session-cookie",
            format!("xoxd-{}", body(100)),
            "!",
        ),
        (
            "rustleaks.slack-session-token",
            format!("xoxc-174285963-963852741-582716349-{}", hex_body(64)),
            "",
        ),
        (
            "rustleaks.circleci-project-token",
            format!("CCIPRJ_{}_{}", body(22), hex_body(40)),
            "",
        ),
        (
            "rustleaks.deno-organization-token",
            format!("ddo_{}", body(36)),
            "",
        ),
        ("rustleaks.xai-api-key-80", format!("xai-{}", body(80)), ""),
        (
            "rustleaks.postman-collection-token",
            format!("PMAT-{}", body(26)),
            "",
        ),
    ] {
        cases.push(FollowupCase {
            id,
            context: "",
            secret,
            suffix,
            folded: false,
            contextual: false,
        });
    }
    cases
}

fn followup_text(case: &FollowupCase) -> String {
    if case.contextual {
        format!("{}={}", case.context, case.secret)
    } else {
        case.secret.clone()
    }
}

#[test]
fn followup_exact_match_secret_locations_and_invalid_bytes_are_independent() {
    for case in followup_cases() {
        let text = followup_text(&case);
        let input = format!("lead\nx {text}{}", case.suffix);
        let secret_start = 7 + text.len() - case.secret.len();
        for engine in [isolated(), composed().engine(), both_packs().engine()] {
            let findings = scan(engine, input.as_bytes());
            assert_eq!(findings.len(), 1, "{}", case.id);
            let finding = &findings[0];
            assert_eq!(finding.rule_id().as_bytes(), case.id.as_bytes());
            assert_eq!(finding.secret().as_bytes(), case.secret.as_bytes());
            assert_eq!(
                finding.match_text().as_bytes(),
                format!("{text}{}", case.suffix).as_bytes()
            );
            assert_eq!(
                finding.secret_range(),
                range(secret_start, secret_start + case.secret.len())
            );
            assert_eq!(finding.match_range(), range(7, input.len()));
            assert_eq!(
                finding.location(),
                Location::new(1, 1, 4, 3 + text.len() + case.suffix.len()).unwrap()
            );
        }
        let mut invalid = b"\xff\n".to_vec();
        invalid.extend_from_slice(text.as_bytes());
        invalid.extend_from_slice(case.suffix.as_bytes());
        invalid.extend_from_slice(b"\xfe\n");
        invalid.extend_from_slice(text.as_bytes());
        invalid.extend_from_slice(case.suffix.as_bytes());
        let findings = scan(isolated(), &invalid);
        assert_eq!(findings.len(), 2, "{}", case.id);
        for (index, start) in [2, 4 + text.len() + case.suffix.len()]
            .into_iter()
            .enumerate()
        {
            let offset = text.len() - case.secret.len();
            assert_eq!(
                findings[index].secret_range(),
                range(start + offset, start + text.len())
            );
            assert_eq!(
                findings[index].match_range(),
                range(start, start + text.len() + case.suffix.len())
            );
        }
        // A non-ASCII fold or invalid byte inside the initial body cannot be
        // reinterpreted as an ASCII token byte. Use byte 10 for every shape.
        for replacement in [
            vec![0xff],
            "\u{17f}".as_bytes().to_vec(),
            "\u{212a}".as_bytes().to_vec(),
        ] {
            let mut changed = case.secret.as_bytes().to_vec();
            drop(changed.splice(10..11, replacement));
            let mut candidate = if case.contextual {
                format!("{}=", case.context).into_bytes()
            } else {
                Vec::new()
            };
            candidate.extend(changed);
            candidate.extend_from_slice(case.suffix.as_bytes());
            assert!(scan(isolated(), &candidate).is_empty(), "{}", case.id);
        }
    }
}

fn assert_contextual_labels_delimiters_and_case(case: &FollowupCase) {
    assert!(
        scan(isolated(), case.secret.as_bytes()).is_empty(),
        "{}",
        case.id
    );
    for label in ["unrelated", "api_key", "public_address", "kimi"] {
        assert!(
            scan(isolated(), format!("{label}={};", case.secret).as_bytes()).is_empty(),
            "{}",
            case.id
        );
    }
    for suffix in [
        "", ";", "\t", "\u{b}", "\u{c}", "'", "\"", "`", "\\'", "\\\"", "\\`", "\\n", "\\r",
    ] {
        let input = format!("{}={}{suffix}", case.context, case.secret);
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{}, {suffix:?}", case.id);
        assert_eq!(findings[0].secret().as_bytes(), case.secret.as_bytes());
        assert_eq!(findings[0].match_range(), range(0, input.len()));
    }
    for suffix in ["?", "\\x", "\\\\\"", "\u{a0}"] {
        assert!(
            scan(
                isolated(),
                format!("{}={}{suffix}", case.context, case.secret).as_bytes()
            )
            .is_empty()
        );
    }
    for suffix in ["\\N", "\\R"] {
        let findings = scan(
            isolated(),
            format!("{}={}{suffix}", case.context, case.secret).as_bytes(),
        );
        assert_eq!(findings.len(), usize::from(case.folded));
    }
    let upper = format!("{}={};", case.context, case.secret).to_ascii_uppercase();
    assert_eq!(
        scan(isolated(), upper.as_bytes()).len(),
        usize::from(case.folded)
    );
}

fn assert_contextual_separators_and_bounds(case: &FollowupCase) {
    for separator in ["=", ">", ":=", "::=", ":::=", "||", ":", "=>", "?=", ","] {
        let input = format!("{}{separator}{};", case.context, case.secret);
        assert_eq!(
            scan(isolated(), input.as_bytes()).len(),
            1,
            "{}, {separator}",
            case.id
        );
    }
    for count in [0, 3] {
        let input = format!("{}{}={};", case.context, "'".repeat(count), case.secret);
        assert_eq!(scan(isolated(), input.as_bytes()).len(), 1);
    }
    assert!(
        scan(
            isolated(),
            format!("{}''''={};", case.context, case.secret).as_bytes()
        )
        .is_empty()
    );
    for count in [0, 5] {
        let input = format!("{}={}{};", case.context, "'".repeat(count), case.secret);
        assert_eq!(scan(isolated(), input.as_bytes()).len(), 1);
    }
    assert!(
        scan(
            isolated(),
            format!("{}=''''''{};", case.context, case.secret).as_bytes()
        )
        .is_empty()
    );
    let multiline = format!("{}\n='{}';", case.context, case.secret);
    let findings = scan(isolated(), multiline.as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].match_range(), range(0, multiline.len() - 1));
    assert_eq!(
        findings[0].secret_range(),
        range(
            case.context.len() + 3,
            case.context.len() + 3 + case.secret.len()
        )
    );
    for (ascii, fold) in [('s', "\u{17f}"), ('k', "\u{212a}")] {
        if case.context.contains(ascii) {
            let altered = case.context.replacen(ascii, fold, 1);
            // Include the literal keyword elsewhere so this is a regex
            // case-fold control independently of keyword preselection.
            let input = format!("{} note\n{altered}={};", case.context, case.secret);
            assert!(scan(isolated(), input.as_bytes()).is_empty());
        }
    }
    for extension in ["", ".", "_", "-", " ", "\t"] {
        let candidate = format!("{}{}={};", case.context, extension.repeat(20), case.secret);
        assert_eq!(scan(isolated(), candidate.as_bytes()).len(), 1);
    }
    assert!(
        scan(
            isolated(),
            format!("{}{}={};", case.context, "z".repeat(21), case.secret).as_bytes()
        )
        .is_empty()
    );
    for candidate in [
        format!(
            "{}={};",
            case.context,
            &case.secret[..case.secret.len() - 1]
        ),
        format!("{}={}A;", case.context, case.secret),
        format!("{}@={};", case.context, case.secret),
        format!("{}\u{17f}={};", case.context, case.secret),
    ] {
        assert!(
            scan(isolated(), candidate.as_bytes()).is_empty(),
            "{}",
            case.id
        );
    }
    // The source has no leading boundary on context. Keep substring
    // matching explicit rather than accidentally imposing a label parser.
    assert_eq!(
        scan(
            isolated(),
            format!("prefix{}={};", case.context, case.secret).as_bytes()
        )
        .len(),
        1
    );
}

#[test]
fn contextual_provider_labels_bounds_delimiters_and_case_are_preserved() {
    for case in followup_cases().into_iter().filter(|case| case.contextual) {
        assert_contextual_labels_delimiters_and_case(&case);
        assert_contextual_separators_and_bounds(&case);
    }
    let crates = format!("cio{}", body(32));
    for label in ["crates", "cratesio", "crates.io", "crates_io", "crates-io"] {
        assert_eq!(
            scan(isolated(), format!("{label}={crates};").as_bytes()).len(),
            1
        );
    }
    let figma = followup_cases()
        .into_iter()
        .find(|c| c.id.ends_with("header-token"))
        .unwrap()
        .secret;
    for label in ["x-figma-token", "xfigmatoken", "x_figma_token"] {
        assert_eq!(
            scan(isolated(), format!("{label}={figma};").as_bytes()).len(),
            1
        );
    }
    let private = format!("0x{}", hex_body(64));
    for separator in ["", "_", "\u{212a}"] {
        assert_eq!(
            scan(
                isolated(),
                format!("poly{separator}private{separator}key={private};").as_bytes()
            )
            .len(),
            1
        );
    }
    for label in [
        "poly_public_key",
        "poly_private_address",
        "poly\nprivate_key",
    ] {
        assert!(scan(isolated(), format!("{label}={private};").as_bytes()).is_empty());
    }
    // Each dot interval counts runes, not UTF-8 bytes. Neither filler contains
    // a context word, so the rejection cannot find an alternative context.
    for filler in ["q", "\u{754c}"] {
        for interval in [0, 1] {
            let accepted_fill = filler.repeat(20);
            let rejected_fill = filler.repeat(21);
            for (fill, accepted) in [(accepted_fill, true), (rejected_fill, false)] {
                let context = if interval == 0 {
                    format!("poly{fill}private_key")
                } else {
                    format!("poly_private{fill}key")
                };
                let input = format!("{context}={private};");
                let findings = scan(isolated(), input.as_bytes());
                assert_eq!(findings.len(), usize::from(accepted));
                if accepted {
                    let finding = &findings[0];
                    assert_eq!(
                        finding.rule_id().as_bytes(),
                        b"rustleaks.polymarket-private-key"
                    );
                    assert_eq!(finding.match_text().as_bytes(), input.as_bytes());
                    assert_eq!(finding.secret().as_bytes(), private.as_bytes());
                    assert_eq!(finding.match_range(), range(0, input.len()));
                    assert_eq!(
                        finding.secret_range(),
                        range(context.len() + 1, context.len() + 1 + private.len())
                    );
                }
            }
        }
    }
}

#[test]
fn slack_session_bounds_padding_and_boundary_contracts_are_explicit() {
    for digits in [9, 15] {
        let segment: String = "1742859630".chars().cycle().take(digits).collect();
        let secret = format!("xoxc-{segment}-{segment}-{segment}-{}", hex_body(64));
        for prefix in ["", "_"] {
            let findings = scan(isolated(), format!("{prefix}{secret}!").as_bytes());
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
        }
        for suffix in ["_", "a", "0"] {
            assert!(scan(isolated(), format!("{secret}{suffix}").as_bytes()).is_empty());
        }
        for position in 0..3 {
            for bad_length in [8, 16] {
                let mut segments = [segment.clone(), segment.clone(), segment.clone()];
                segments[position] = "7".repeat(bad_length);
                let candidate = format!(
                    "xoxc-{}-{}-{}-{}",
                    segments[0],
                    segments[1],
                    segments[2],
                    hex_body(64)
                );
                assert!(scan(isolated(), candidate.as_bytes()).is_empty());
            }
        }
        assert!(scan(isolated(), secret.to_ascii_uppercase().as_bytes()).is_empty());
    }
    for hexadecimal_length in [63, 65] {
        let input = format!(
            "xoxc-174285963-963852741-582716349-{}",
            hex_body(hexadecimal_length)
        );
        assert!(scan(isolated(), input.as_bytes()).is_empty());
    }
    assert!(scan(isolated(), format!("xoxd-{}", body(99)).as_bytes()).is_empty());
    for length in [100, 101, 8192] {
        for padding in ["", "=", "=="] {
            let secret = format!("xoxd-{}{padding}", body(length));
            for suffix in ["", "!", ";", "\u{212a}"] {
                let input = format!("{secret}{suffix}");
                let findings = scan(isolated(), input.as_bytes());
                assert_eq!(findings.len(), 1);
                assert_eq!(findings[0].secret_range(), range(0, secret.len()));
                assert_eq!(findings[0].match_range(), range(0, input.len()));
            }
        }
    }
    for suffix in ["===!", "=A", "==_"] {
        assert!(scan(isolated(), format!("xoxd-{}{suffix}", body(100)).as_bytes()).is_empty());
    }
    let alphabet = format!("xoxd-{}_/\\+-==", body(100));
    let findings = scan(isolated(), format!("{alphabet}!").as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret().as_bytes(), alphabet.as_bytes());
    // Backslash is a valid body byte and also a source delimiter. At EOF the
    // greedy body owns it; before padding plus backslash the delimiter owns it.
    let greedy = format!("xoxd-{}\\", body(100));
    assert_eq!(
        scan(isolated(), greedy.as_bytes())[0].secret().as_bytes(),
        greedy.as_bytes()
    );
    let padded = format!("xoxd-{}=", body(100));
    let findings = scan(isolated(), format!("{padded}\\").as_bytes());
    assert_eq!(findings[0].secret().as_bytes(), padded.as_bytes());
    assert_eq!(findings[0].match_range(), range(0, padded.len() + 1));
}

#[test]
fn finite_apache_formats_preserve_prefix_matches_without_invented_delimiters() {
    for (id, prefix, length, lower_hex_tail) in [
        ("rustleaks.circleci-project-token", "CCIPRJ_", 22, true),
        ("rustleaks.deno-organization-token", "ddo_", 36, false),
        ("rustleaks.xai-api-key-80", "xai-", 80, false),
        ("rustleaks.postman-collection-token", "PMAT-", 26, false),
    ] {
        let secret = if lower_hex_tail {
            format!("{prefix}{}_{}", body(length), hex_body(40))
        } else {
            token(prefix, length)
        };
        assert!(scan(isolated(), &secret.as_bytes()[..secret.len() - 1]).is_empty());
        for (leading, trailing) in [("", ""), ("_", "A"), ("before", "after"), ("!", "?")] {
            let text = format!("{leading}{secret}{trailing}");
            let findings = scan(isolated(), text.as_bytes());
            assert_eq!(findings.len(), 1, "{id}");
            assert_eq!(findings[0].rule_id().as_bytes(), id.as_bytes());
            assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
            assert_eq!(
                findings[0].match_range(),
                range(leading.len(), leading.len() + secret.len())
            );
        }
        let doubled = format!("{secret}{secret}");
        assert_eq!(scan(isolated(), doubled.as_bytes()).len(), 2);
        let low = if lower_hex_tail {
            format!("{prefix}{}_{}", "0".repeat(length), "0".repeat(40))
        } else {
            format!("{prefix}{}", "0".repeat(length))
        };
        assert_eq!(scan(isolated(), low.as_bytes()).len(), 1);
        let changed_prefix: String = prefix
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        assert!(
            scan(
                isolated(),
                secret.replacen(prefix, &changed_prefix, 1).as_bytes()
            )
            .is_empty()
        );
    }
    assert!(
        scan(
            isolated(),
            format!("CCIPRJ_{}_{}", body(22), hex_body(40).to_ascii_uppercase()).as_bytes()
        )
        .is_empty()
    );
    for secret in [
        token("xai-token-", 80),
        token("ddp_", 36),
        token("PMAK-", 26),
        token("xai-", 79),
    ] {
        assert!(scan(isolated(), secret.as_bytes()).is_empty());
    }
    // A length-81 xAI run still contains the finite source's 80-body match.
    assert_eq!(
        scan(isolated(), token("xai-", 81).as_bytes())[0]
            .secret()
            .as_bytes()
            .len(),
        84
    );
}

#[test]
fn followup_raw_occurrences_and_generic_attribution_are_separate() {
    for case in followup_cases() {
        let raw = format!("{}{}", followup_text(&case), case.suffix);
        let old = scan(base().engine(), raw.as_bytes());
        let raw_generic = case.id == "rustleaks.polymarket-private-key";
        assert_eq!(old.len(), usize::from(raw_generic), "{}", case.id);
        if raw_generic {
            assert_eq!(old[0].rule_id().as_bytes(), b"generic-api-key");
            assert_eq!(old[0].secret().as_bytes(), case.secret.as_bytes());
        }
        let raw_after = scan(composed().engine(), raw.as_bytes());
        assert_eq!(raw_after.len(), 1, "{}", case.id);
        assert_eq!(raw_after[0].rule_id().as_bytes(), case.id.as_bytes());
        assert_eq!(raw_after[0].secret().as_bytes(), case.secret.as_bytes());
        let label = if case.contextual {
            format!("{}_api_key", case.context)
        } else {
            "api_key".to_owned()
        };
        let assigned = format!("{label} = '{}';", case.secret);
        let before = scan(base().engine(), assigned.as_bytes());
        // Restarting the hex stream in each Figma group yields entropy
        // 3.366119309697485. The generic rule rejects it at <= 3.5, whereas
        // the provider rule deliberately has no entropy floor.
        let assigned_generic = case.id != "rustleaks.figma-personal-access-header-token";
        assert_eq!(before.len(), usize::from(assigned_generic), "{}", case.id);
        let expected = range(label.len() + 4, label.len() + 4 + case.secret.len());
        if assigned_generic {
            assert_eq!(before[0].rule_id().as_bytes(), b"generic-api-key");
            assert_eq!(before[0].secret().as_bytes(), case.secret.as_bytes());
            assert_eq!(before[0].secret_range(), expected);
        }
        let after = scan(composed().engine(), assigned.as_bytes());
        assert_eq!(after.len(), 1, "{}", case.id);
        assert_eq!(after[0].rule_id().as_bytes(), case.id.as_bytes());
        assert_eq!(after[0].secret_range(), expected);
    }
    // Continuing the hex stream across the groups yields entropy
    // 4.0251327245427015: a,7,f,2 occur three times; twelve other hex symbols
    // occur twice; '-' occurs five times. This is an attribution-only pair.
    let high = "a7f2-b9e4c1d8-0563-a7f2-b9e4-c1d80563a7f2";
    for (input, start) in [
        (format!("x-figma-token={high};"), 14),
        (format!("x-figma-token_api_key = '{high}';"), 25),
    ] {
        let before = scan(base().engine(), input.as_bytes());
        let after = scan(composed().engine(), input.as_bytes());
        assert_eq!(before.len(), 1);
        assert_eq!(after.len(), 1);
        assert_eq!(before[0].rule_id().as_bytes(), b"generic-api-key");
        assert_eq!(
            after[0].rule_id().as_bytes(),
            b"rustleaks.figma-personal-access-header-token"
        );
        for finding in [&before[0], &after[0]] {
            assert_eq!(finding.secret().as_bytes(), high.as_bytes());
            assert_eq!(finding.secret_range(), range(start, start + 41));
        }
    }
}

fn assert_followup_entropy_and_keywords(original: &RawConfig, case: &FollowupCase) {
    let rule = original.rules.iter().find(|r| r.id == case.id).unwrap();
    let entropy = matches!(
        case.id,
        "rustleaks.cursor-api-key"
            | "rustleaks.elevenlabs-api-key"
            | "rustleaks.ollama-api-key"
            | "rustleaks.polymarket-private-key"
            | "rustleaks.stability-ai-api-key"
            | "rustleaks.slack-session-cookie"
            | "rustleaks.slack-session-token"
    );
    let expected_entropy = if entropy { 3.5_f64 } else { 0.0_f64 };
    assert_eq!(rule.entropy.to_bits(), expected_entropy.to_bits());
    assert_eq!(rule.secret_group, 1);
    let expected_keywords: Vec<&str> = match case.id {
        "rustleaks.checkout-secret-key" => vec!["checkout"],
        "rustleaks.crates-io-api-key" => vec!["crates"],
        "rustleaks.cursor-api-key" => vec!["cursor"],
        "rustleaks.databento-api-key" => vec!["databento"],
        "rustleaks.elevenlabs-api-key" => vec!["elevenlabs"],
        "rustleaks.figma-personal-access-header-token" => {
            vec!["x-figma-token", "xfigmatoken", "x_figma_token"]
        }
        "rustleaks.ollama-api-key" => vec!["ollama"],
        "rustleaks.polymarket-private-key" => vec!["poly"],
        "rustleaks.stability-ai-api-key" => vec!["stability"],
        "rustleaks.slack-session-cookie" => vec!["xoxd-"],
        "rustleaks.slack-session-token" => vec!["xoxc-"],
        _ => vec![],
    };
    assert_eq!(rule.keywords, expected_keywords);
    if entropy {
        let mut probe = rule.clone();
        probe.regex = "([A-Z]{8,32})".into();
        probe.keywords.clear();
        let engine = Engine::builder(
            ConfigLoader::new()
                .compile(RawConfig {
                    rules: vec![probe],
                    ..RawConfig::default()
                })
                .unwrap(),
        )
        .build()
        .unwrap();
        assert!(scan(&engine, b"ABCDEFGHIIJJKKLL").is_empty());
        assert_eq!(scan(&engine, b"ABCDEFGHIJKLMNOP").len(), 1);
    }
}

fn assert_followup_allowlists(original: &RawConfig, case: &FollowupCase, text: &str) {
    for path in ["synthetic.pdf", "node_modules/synthetic.js"] {
        let fragment = Fragment::builder(text.as_bytes()).file_path(path).build();
        assert!(
            composed()
                .engine()
                .scan_fragment(&fragment, &ScanOptions::default())
                .findings()
                .is_empty()
        );
    }
    assert!(
        scan(
            composed().engine(),
            format!("{text} # rustleaks:allow").as_bytes()
        )
        .is_empty()
    );
    for global in [false, true] {
        for predicate in [
            "regexTarget='secret'\nregexes=['.']",
            "regexTarget='match'\nregexes=['.']",
            "regexTarget='line'\nregexes=['.']",
            "stopwords=['Q7m2','a7f2']",
            "paths=['^synthetic[.]conf$']",
            "commits=['synthetic-commit']",
        ] {
            let mut raw = original.clone();
            raw.rules
                .retain(|r| r.id == case.id || r.id == "rustleaks.groq-api-key");
            let allowlist:RawConfig=toml::from_str(&format!("[[rules]]\nid='source'\n[[rules.allowlists]]\n{predicate}\n[[allowlists]]\ntargetRules=['{}']\n{predicate}\n",case.id)).unwrap();
            if global {
                raw.allowlists = allowlist.allowlists;
            } else {
                raw.rules
                    .iter_mut()
                    .find(|r| r.id == case.id)
                    .unwrap()
                    .allowlists
                    .clone_from(&allowlist.rules[0].allowlists);
            }
            let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                .build()
                .unwrap();
            let fragment = Fragment::builder(text.as_bytes())
                .file_path("synthetic.conf")
                .commit("synthetic-commit")
                .build();
            assert!(
                engine
                    .scan_fragment(&fragment, &ScanOptions::default())
                    .findings()
                    .is_empty(),
                "{}, {global}, {predicate}",
                case.id
            );
            assert_eq!(scan(&engine, token("gsk_", 52).as_bytes()).len(), 1);
        }
    }
}

#[test]
fn followup_entropy_keywords_allowlists_and_resource_caps_remain_effective() {
    let original: RawConfig = scalar_provider_config();
    for low in [
        format!(
            "checkout=sk_{}-{}-{}-{}-{};",
            "0".repeat(8),
            "0".repeat(4),
            "0".repeat(4),
            "0".repeat(4),
            "0".repeat(12)
        ),
        format!("crates=cio{};", "0".repeat(32)),
        format!("databento=db-{};", "0".repeat(29)),
        format!(
            "xfigmatoken={}-{}-{}-{}-{}-{};",
            "0".repeat(4),
            "0".repeat(8),
            "0".repeat(4),
            "0".repeat(4),
            "0".repeat(4),
            "0".repeat(12)
        ),
    ] {
        assert_eq!(scan(isolated(), low.as_bytes()).len(), 1);
    }
    for low in [
        format!("cursor=key_{};", "0".repeat(64)),
        format!("elevenlabs=sk_{};", "0".repeat(48)),
        format!("ollama={}.{};", "0".repeat(32), "0".repeat(24)),
        format!("poly_private_key=0x{};", "0".repeat(64)),
        format!("stability=sk-{};", "0".repeat(48)),
        format!("xoxd-{}!", "0".repeat(100)),
        format!("xoxc-000000000-000000000-000000000-{}", "0".repeat(64)),
    ] {
        assert!(scan(isolated(), low.as_bytes()).is_empty());
    }
    for case in followup_cases() {
        assert_followup_entropy_and_keywords(&original, &case);
        let text = format!("{}{}", followup_text(&case), case.suffix);
        assert_followup_allowlists(&original, &case, &text);
        let dense = format!("{text}\n").repeat(6);
        let fragment = Fragment::new(dense.as_bytes());
        let full = isolated().scan_fragment(&fragment, &ScanOptions::default());
        assert!(full.is_complete());
        assert_eq!(full.findings().len(), 6);
        for budget in [
            ScanBudget::unlimited().max_finding_records(2),
            ScanBudget::unlimited().max_work_units(1),
            ScanBudget::unlimited().max_finding_payload_bytes(16),
        ] {
            let result = isolated().scan_fragment_controlled(
                &fragment,
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!result.is_complete());
            assert!(result.findings().is_empty());
        }
        let exact = isolated().scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_work_units(full.usage().work_units())),
        );
        assert!(exact.is_complete());
        assert_eq!(exact.findings(), full.findings());
    }
    let long = format!("xoxd-{}==!", body(256 * 1024));
    let fragment = Fragment::new(long.as_bytes());
    let result = isolated().scan_fragment_controlled(
        &fragment,
        &ScanOptions::default(),
        &ScanControl::unlimited()
            .with_budget(ScanBudget::unlimited().max_finding_payload_bytes(1024)),
    );
    assert!(!result.is_complete());
    assert!(result.findings().is_empty());
    let skipped = isolated().scan_fragment(
        &fragment,
        &ScanOptions::builder().max_target_bytes(Some(1024)).build(),
    );
    assert!(skipped.findings().is_empty());
    let full = isolated().scan_fragment(&fragment, &ScanOptions::default());
    assert!(full.is_complete());
    assert_eq!(full.findings().len(), 1);
    assert_eq!(full.findings()[0].secret_range(), range(0, long.len() - 1));
}

// This exact inventory separates the established scalar-only test fixture
// from the native consumers. Never drop arbitrary structured entropy rows.
const NATIVE_BYTE_IDS: [&str; 6] = [
    "rustleaks.dockerhub-personal-access-token",
    "rustleaks.dockerhub-organization-access-token",
    "rustleaks.neon-api-key",
    "rustleaks.render-api-key",
    "rustleaks.deno-account-token",
    "rustleaks.apify-api-token",
];

fn native_byte_predicate() -> toml::Value {
    toml::from_str("algorithm='byte-shannon-f64-v1'\nreject='lt'\nthreshold=3.5\n").unwrap()
}

fn scalar_provider_config() -> RawConfig {
    let mut pack: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    let rules = pack["rules"].as_array_mut().unwrap();
    assert_eq!(rules.len(), 300);
    rules.truncate(104);
    assert_eq!(
        rules[60..]
            .iter()
            .map(|rule| rule["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        CONTEXTUAL_ADDITION_IDS
    );
    for rule in &rules[60..] {
        let id = rule["id"].as_str().unwrap();
        let threshold = match id {
            "rustleaks.hashicorp-tf-password-delimiter"
            | "rustleaks.hashicorp-tf-password-context-vt" => Some(2.0),
            "rustleaks.okta-access-token-delimiter" | "rustleaks.okta-access-token-context-vt" => {
                Some(4.0)
            }
            "rustleaks.openai-api-key-legacy-delimiter" => Some(3.0),
            _ => None,
        };
        if let Some(threshold) = threshold {
            assert_eq!(
                rule["entropy"]["algorithm"].as_str(),
                Some("byte-shannon-f64-v1")
            );
            assert_eq!(rule["entropy"]["reject"].as_str(), Some("le"));
            assert_eq!(rule["entropy"]["threshold"].as_float(), Some(threshold));
        } else {
            assert!(rule.get("entropy").is_none());
        }
    }
    rules.truncate(60);
    assert_eq!(rules.len(), 60);
    let structured_ids: Vec<_> = rules
        .iter()
        .filter(|rule| rule.get("entropy").is_some_and(toml::Value::is_table))
        .map(|rule| {
            let id = rule["id"].as_str().unwrap();
            if DELIMITER_BYTE_IDS.contains(&id) {
                assert_eq!(
                    rule["entropy"]["algorithm"].as_str(),
                    Some("byte-shannon-f64-v1")
                );
                assert_eq!(rule["entropy"]["reject"].as_str(), Some("le"));
                assert!(matches!(
                    rule["entropy"]["threshold"].as_float(),
                    Some(2.0 | 3.0 | 3.5 | 4.0)
                ));
            } else {
                assert_eq!(rule["entropy"], native_byte_predicate());
            }
            rule["id"].as_str().unwrap().to_owned()
        })
        .collect();
    let expected_ids: Vec<String> = NATIVE_BYTE_IDS
        .into_iter()
        .chain(DELIMITER_BYTE_IDS)
        .map(str::to_owned)
        .collect();
    assert_eq!(structured_ids, expected_ids);
    rules.retain(|rule| {
        let id = rule["id"].as_str().unwrap();
        !NATIVE_BYTE_IDS.contains(&id) && !DELIMITER_BYTE_IDS.contains(&id)
    });
    assert_eq!(rules.len(), 30);
    // Existing isolated/scalar tests intentionally omit global allowlists.
    // Preserve that fixture and its old expectations; native_selected below
    // compiles the six consumers with their full native base policy instead.
    toml::from_str(&toml::to_string(&pack).unwrap()).unwrap()
}

fn native_selected() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let (full, _) = NativePolicy::builder()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .compile()
            .unwrap();
        let selected = full.select_rules(NATIVE_BYTE_IDS).unwrap();
        Engine::builder(selected).build().unwrap()
    })
}

fn byte_rule(id: &str) -> toml::Value {
    let pack: toml::Value = toml::from_str(PROVIDER_RULES_V1).unwrap();
    pack["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"].as_str() == Some(id))
        .unwrap()
        .clone()
}

fn native_single_rule(rule: toml::Value) -> Engine {
    let id = rule["id"].as_str().unwrap().to_owned();
    let mut pack: toml::Value = toml::from_str("title='native consumer test'\n").unwrap();
    pack.as_table_mut()
        .unwrap()
        .insert("rules".into(), toml::Value::Array(vec![rule]));
    let source = toml::to_string(&pack).unwrap();
    let (full, _) = NativePolicy::builder()
        .with_pack("native-consumer-test", &source)
        .unwrap()
        .compile()
        .unwrap();
    Engine::builder(full.select_rules([id.as_str()]).unwrap())
        .build()
        .unwrap()
}

const BYTE_CASES: [(&str, &str, usize, usize); 6] = [
    (
        "rustleaks.dockerhub-personal-access-token",
        "dckr_pat_",
        27,
        27,
    ),
    (
        "rustleaks.dockerhub-organization-access-token",
        "dckr_oat_",
        32,
        32,
    ),
    ("rustleaks.neon-api-key", "napi_", 64, 64),
    ("rustleaks.render-api-key", "rnd_", 28, 28),
    ("rustleaks.deno-account-token", "ddp_", 36, 36),
    ("rustleaks.apify-api-token", "apify_api_", 34, 38),
];

#[test]
fn native_provider_pack_requires_native_loading_and_preserves_selected_metadata() {
    assert!(ConfigLoader::new().load_toml(PROVIDER_RULES_V1).is_err());
    assert!(toml::from_str::<RawConfig>(PROVIDER_RULES_V1).is_err());
    assert_eq!(scalar_provider_config().rules.len(), 30);
    let (full, _) = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .compile()
        .unwrap();
    for (id, prefix, _, _) in BYTE_CASES {
        let rule = full.rule(id).unwrap();
        assert_eq!(
            rule.native_entropy(),
            Some(("byte-shannon-f64-v1", "lt", 3.5))
        );
        assert_eq!(
            byte_rule(id)["keywords"].as_array().unwrap(),
            &[toml::Value::String(prefix.into())]
        );
        assert_eq!(byte_rule(id)["secretGroup"].as_integer(), Some(1));
        let selected = full.select_rules([id]).unwrap();
        assert_eq!(
            selected.rule(id).unwrap().native_entropy(),
            rule.native_entropy()
        );
    }
    for rule in scalar_provider_config().rules {
        assert_eq!(full.rule(&rule.id).unwrap().native_entropy(), None);
    }
}

#[test]
fn byte_provider_source_allowlist_scopes_do_not_leak_case_or_expand_whitespace() {
    for id in NATIVE_BYTE_IDS {
        let mut rule = byte_rule(id);
        let regexes = rule["allowlists"][0]["regexes"].as_array().unwrap();
        assert_eq!(regexes.len(), 13);
        assert!(regexes.iter().all(|value| {
            let pattern = value.as_str().unwrap();
            pattern.starts_with("(?:") && pattern.ends_with(')')
        }));
        // Probe only the retained source predicates with a broad test regex.
        // Actual provider prefixes cannot intersect these path/template forms.
        // Omitting the inherited base here makes flag leakage observable.
        rule["regex"] = toml::Value::String("(.+)".into());
        rule["keywords"] = toml::Value::Array(vec![]);
        rule["entropy"] = toml::Value::Float(0.0);
        let mut pack: toml::Value = toml::from_str("title='source predicate probe'\n").unwrap();
        pack.as_table_mut()
            .unwrap()
            .insert("rules".into(), toml::Value::Array(vec![rule]));
        let raw: RawConfig = toml::from_str(&toml::to_string(&pack).unwrap()).unwrap();
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        for preserved in [
            "/users/Q7m2Z9v4/file",
            "/USERS/Q7m2Z9v4/file",
            "/BIN/Q7m2Z9v4",
            "{{\u{b}Q7m2}}",
        ] {
            assert_eq!(
                scan(&engine, preserved.as_bytes()).len(),
                1,
                "{id}, {preserved:?}"
            );
        }
        for excluded in [
            "/Users/Q7m2Z9v4/file",
            "/bin/Q7m2Z9v4",
            "{{\tQ7m2}}",
            "synthetic-FaLsE-tail",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ] {
            assert!(
                scan(&engine, excluded.as_bytes()).is_empty(),
                "{id}, {excluded:?}"
            );
        }
    }
}

#[test]
fn byte_provider_predicate_comparator_participates_in_exact_policy_identity() {
    let original =
        r#"entropy = { algorithm = "byte-shannon-f64-v1", reject = "lt", threshold = 3.5 }"#;
    let replacement =
        r#"entropy = { algorithm = "byte-shannon-f64-v1", reject = "le", threshold = 3.5 }"#;
    assert_eq!(
        PROVIDER_RULES_V1
            .split("# Maintained additional coverage;")
            .next()
            .unwrap()
            .matches(original)
            .count(),
        6
    );
    let changed = PROVIDER_RULES_V1.replacen(original, replacement, 1);
    let (_, identity) = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .compile()
        .unwrap();
    let (changed_config, changed_identity) = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", &changed)
        .unwrap()
        .compile()
        .unwrap();
    assert_ne!(identity, changed_identity);
    assert!(identity.builtin_review_reference().is_some());
    assert!(changed_identity.builtin_review_reference().is_none());
    assert_eq!(
        changed_config
            .rule(NATIVE_BYTE_IDS[0])
            .unwrap()
            .native_entropy(),
        Some(("byte-shannon-f64-v1", "le", 3.5))
    );
    for id in &NATIVE_BYTE_IDS[1..] {
        assert_eq!(
            changed_config.rule(id).unwrap().native_entropy(),
            Some(("byte-shannon-f64-v1", "lt", 3.5))
        );
    }
}

#[test]
fn byte_provider_formats_have_independent_bounds_delimiters_and_exact_spans() {
    for (id, prefix, minimum, maximum) in BYTE_CASES {
        let apify = prefix == "apify_api_";
        for length in minimum..=maximum {
            let secret = token(prefix, length);
            for suffix in [
                "", ";", " ", "\t", "\u{b}", "\u{c}", "'", "\"", "`", "\\'", "\\\"", "\\`", "\\n",
                "\\r",
            ] {
                let input = format!("lead\nx {secret}{suffix}");
                for engine in [
                    native_selected(),
                    composed().engine(),
                    both_packs().engine(),
                ] {
                    let findings = scan(engine, input.as_bytes());
                    assert_eq!(findings.len(), 1, "{id}, {length}, {suffix:?}");
                    let finding = &findings[0];
                    let consumed = if apify { "" } else { suffix };
                    assert_companion_geometry(finding, id, &secret, consumed);
                }
            }
            for suffix in ["?", "\\N", "\\R", "\u{a0}"] {
                let findings = scan(native_selected(), format!("{secret}{suffix}").as_bytes());
                assert_eq!(findings.len(), usize::from(apify), "{id}, {suffix:?}");
            }
            assert!(scan(native_selected(), secret.to_ascii_uppercase().as_bytes()).is_empty());
            assert!(scan(native_selected(), format!("_{secret};").as_bytes()).is_empty());
        }
        for length in [minimum - 1, maximum + 1] {
            assert!(
                scan(
                    native_selected(),
                    format!("{};", token(prefix, length)).as_bytes()
                )
                .is_empty(),
                "{id}, {length}"
            );
        }
        let secret = token(prefix, minimum);
        for replacement in [
            vec![0xff],
            "\u{17f}".as_bytes().to_vec(),
            "\u{212a}".as_bytes().to_vec(),
        ] {
            let mut input = secret.as_bytes().to_vec();
            drop(input.splice(prefix.len() + 3..prefix.len() + 4, replacement));
            input.push(b';');
            assert!(scan(native_selected(), &input).is_empty(), "{id}");
        }
        let mut repeated = b"\xff\n".to_vec();
        repeated.extend_from_slice(secret.as_bytes());
        repeated.extend_from_slice(b";\xfe\n");
        repeated.extend_from_slice(secret.as_bytes());
        repeated.push(b';');
        let findings = scan(native_selected(), &repeated);
        assert_eq!(findings.len(), 2);
        for (index, start) in [2, 5 + secret.len()].into_iter().enumerate() {
            assert_eq!(
                findings[index].secret_range(),
                range(start, start + secret.len())
            );
            assert_eq!(
                findings[index].match_range(),
                range(start, start + secret.len() + usize::from(!apify))
            );
        }
        let with_symbols = format!("{prefix}{}_-;", body(minimum - 2));
        assert_eq!(
            scan(native_selected(), with_symbols.as_bytes()).len(),
            usize::from(prefix.starts_with("dckr_"))
        );
    }
    let apify = token("apify_api_", 38);
    assert!(scan(native_selected(), format!("{apify}_").as_bytes()).is_empty());
    assert_eq!(
        scan(native_selected(), format!("{apify}-").as_bytes()).len(),
        1
    );
}

#[test]
fn byte_provider_predicates_accept_exact_threshold_with_source_arithmetic() {
    for id in NATIVE_BYTE_IDS {
        let mut rule = byte_rule(id);
        rule["regex"] = toml::Value::String("([A-Z]{8,800})".into());
        rule["keywords"] = toml::Value::Array(vec![]);
        let engine = native_single_rule(rule);
        // Fixed histogram controls: 3.375, 3.5 and 3.625 bits, respectively.
        // The exact 3.5 control must be accepted by reject=lt.
        assert!(scan(&engine, b"BBCDEFGHIIJJKKLL").is_empty());
        for (input, expected) in [
            ("ABCDEFGHIIJJKKLL", 3.5_f32),
            ("ABCDEFGHIMJJKKLL", 3.625_f32),
        ] {
            let findings = scan(&engine, input.as_bytes());
            assert_eq!(findings.len(), 1, "{id}");
            assert_eq!(findings[0].entropy().to_bits(), expected.to_bits());
            assert_eq!(findings[0].secret_range(), range(0, input.len()));
        }
        // Eight symbols occur 49 times and four symbols occur 98 times.
        // Per-count division yields exact 1/16 and 1/8 probabilities, hence
        // exact 3.5. Reciprocal multiplication can round below that boundary.
        let witness: String = ('A'..='L')
            .enumerate()
            .flat_map(|(index, c)| std::iter::repeat_n(c, if index < 8 { 49 } else { 98 }))
            .collect();
        assert_eq!(witness.len(), 784);
        let findings = scan(&engine, witness.as_bytes());
        assert_eq!(findings.len(), 1, "{id}");
        assert_eq!(findings[0].entropy().to_bits(), 3.5_f32.to_bits());
        assert_eq!(findings[0].secret_range(), range(0, 784));
    }
}

#[test]
fn byte_provider_occurrence_increments_and_generic_attribution_are_distinct() {
    for (id, prefix, minimum, _) in BYTE_CASES {
        let secret = token(prefix, minimum);
        assert!(scan(base().engine(), secret.as_bytes()).is_empty(), "{id}");
        assert_eq!(scan(composed().engine(), secret.as_bytes()).len(), 1);
        let assigned = format!("api_key = '{secret}';");
        let before = scan(base().engine(), assigned.as_bytes());
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].rule_id().as_bytes(), b"generic-api-key");
        assert_eq!(before[0].secret().as_bytes(), secret.as_bytes());
        let after = scan(composed().engine(), assigned.as_bytes());
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].rule_id().as_bytes(), id.as_bytes());
        assert_eq!(after[0].secret_range(), before[0].secret_range());
        let low = format!("{prefix}{};", "A".repeat(minimum));
        assert!(scan(native_selected(), low.as_bytes()).is_empty());
    }
    let personal = token("ddp_", 36);
    let organization = token("ddo_", 36);
    let findings = scan(
        composed().engine(),
        format!("{personal};\n{organization}").as_bytes(),
    );
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(
        |f| f.rule_id().as_bytes() == b"rustleaks.deno-account-token"
            && f.secret().as_bytes() == personal.as_bytes()
    ));
    assert!(findings.iter().any(|f| f.rule_id().as_bytes()
        == b"rustleaks.deno-organization-token"
        && f.secret().as_bytes() == organization.as_bytes()));
}

fn assert_byte_provider_rule_allowlists(id: &str, input: &str) {
    for predicate in [
        "regexTarget='secret'\nregexes=['.']",
        "regexTarget='match'\nregexes=['.']",
        "regexTarget='line'\nregexes=['.']",
        "stopwords=['Q7m2']",
        "paths=['^synthetic[.]conf$']",
        "commits=['synthetic-commit']",
    ] {
        let mut rule = byte_rule(id);
        let allowlist: toml::Value = toml::from_str(predicate).unwrap();
        rule.as_table_mut()
            .unwrap()
            .insert("allowlists".into(), toml::Value::Array(vec![allowlist]));
        let engine = native_single_rule(rule);
        let fragment = Fragment::builder(input.as_bytes())
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
fn byte_provider_allowlists_decoding_and_budget_accounting_preserve_native_predicates() {
    use base64::Engine as _;
    for (id, prefix, minimum, _) in BYTE_CASES {
        let secret = token(prefix, minimum);
        let input = format!("{secret};");
        for path in [
            "synthetic.pdf",
            "node_modules/synthetic.js",
            "gitleaks.toml",
        ] {
            let fragment = Fragment::builder(input.as_bytes()).file_path(path).build();
            assert!(
                native_selected()
                    .scan_fragment(&fragment, &ScanOptions::default())
                    .findings()
                    .is_empty()
            );
        }
        let bun = Fragment::builder(input.as_bytes())
            .file_path("bun.lock")
            .build();
        assert_eq!(
            native_selected()
                .scan_fragment(&bun, &ScanOptions::default())
                .findings()
                .len(),
            1
        );
        assert!(
            scan(
                native_selected(),
                format!("{input} # rustleaks:allow").as_bytes()
            )
            .is_empty()
        );
        let excluded = format!("{prefix}false{};", body(minimum - 5));
        assert!(scan(native_selected(), excluded.as_bytes()).is_empty());
        assert_byte_provider_rule_allowlists(id, &input);
        let encoded = base64::engine::general_purpose::STANDARD.encode(input.as_bytes());
        let decoded = native_selected().scan_fragment(
            &Fragment::new(encoded.as_bytes()),
            &ScanOptions::builder().max_decode_depth(1).build(),
        );
        assert!(decoded.is_complete());
        assert!(
            decoded
                .findings()
                .iter()
                .any(|f| f.rule_id().as_bytes() == id.as_bytes()
                    && f.secret().as_bytes() == secret.as_bytes())
        );
        let low = format!("{prefix}{};\n", "A".repeat(minimum));
        let low_fragment = Fragment::new(low.as_bytes());
        let rejected = native_selected().scan_fragment_controlled(
            &low_fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(0)),
        );
        assert!(rejected.is_complete());
        assert!(rejected.findings().is_empty());
        assert_eq!(rejected.usage().finding_records(), 0);
        let mixed = format!("{}{input}", low.repeat(8));
        let admitted = native_selected().scan_fragment_controlled(
            &Fragment::new(mixed.as_bytes()),
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(1)),
        );
        assert!(admitted.is_complete());
        assert_eq!(admitted.findings().len(), 1);
        assert_eq!(admitted.usage().finding_records(), 1);
        for budget in [
            ScanBudget::unlimited().max_finding_records(0),
            ScanBudget::unlimited().max_work_units(1),
            ScanBudget::unlimited().max_finding_payload_bytes(1),
        ] {
            let result = native_selected().scan_fragment_controlled(
                &Fragment::new(input.as_bytes()),
                &ScanOptions::default(),
                &ScanControl::unlimited().with_budget(budget),
            );
            assert!(!result.is_complete());
            assert!(result.findings().is_empty());
        }
    }
}

const DELIMITER_BYTE_IDS: [&str; 24] = [
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

const CONTEXTUAL_ADDITION_IDS: [&str; 44] = [
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
