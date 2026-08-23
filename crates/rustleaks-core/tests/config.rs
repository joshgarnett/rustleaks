#![allow(missing_docs)]
#![allow(
    clippy::float_cmp,
    clippy::format_collect,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rustleaks_core::UPSTREAM_REVISION;
use rustleaks_core::config::{
    AllowlistSpec, CompiledAllowlist, CompiledConfig, Condition, ConfigError, ConfigExtension,
    ConfigLoader, ConfigOrigin, DEFAULT_CONFIG, DEFAULT_CONFIG_BYTES, DEFAULT_CONFIG_REVISION,
    DEFAULT_CONFIG_SHA256, FileSystemResolver, RawConfig, RawGlobalAllowlist, RegexTarget,
    RequiredRuleSpec, RuleSpec, VirtualResolver,
};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/fixtures/upstream/testdata/config")
}

fn fixture(relative: &str) -> String {
    fs::read_to_string(fixture_root().join(relative)).unwrap()
}

fn fixture_resolver() -> VirtualResolver {
    let root = fixture_root();
    let mut resolver = VirtualResolver::new();
    let mut directories = vec![root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let contents = fs::read_to_string(entry.path()).unwrap();
            resolver.insert(relative.clone(), contents.clone());
            resolver.insert(format!("../testdata/config/{relative}"), contents);
        }
    }
    resolver
}

fn load_fixture(relative: &str) -> Result<CompiledConfig, String> {
    ConfigLoader::new()
        .with_resolver(fixture_resolver())
        .load_toml_at(
            &fixture(relative),
            Some(ConfigOrigin::virtual_path(format!(
                "../testdata/config/{relative}"
            ))),
        )
        .map_err(|error| error.to_string())
}

fn sha256_hex(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64) * 8;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut hash = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big_s1)
                .wrapping_add(choose)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big_s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in hash.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    hash.iter().map(|word| format!("{word:08x}")).collect()
}

fn decode_base64(input: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ if byte.is_ascii_whitespace() => continue,
            _ => panic!("invalid base64 byte {byte}"),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(u8::try_from((accumulator >> bits) & 0xff).unwrap());
            accumulator &= (1 << bits) - 1;
        }
    }
    output
}

fn canonical_allowlist(allowlist: &CompiledAllowlist) -> serde_json::Value {
    serde_json::json!({
        "description": allowlist.description(),
        "condition": allowlist.condition().to_string(),
        "commits": allowlist.commits().collect::<Vec<_>>(),
        "paths": allowlist.paths(),
        "regex_target": allowlist.regex_target().as_str(),
        "regexes": allowlist.regexes(),
        "stop_words": allowlist.stop_words().collect::<Vec<_>>(),
    })
}

fn canonical_config(config: &CompiledConfig) -> serde_json::Value {
    let mut duplicate_positions: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (position, id) in config.ordered_rule_ids().iter().enumerate() {
        duplicate_positions.entry(id).or_default().push(position);
    }
    let duplicate_rule_ids = duplicate_positions
        .into_iter()
        .filter(|(_, positions)| positions.len() > 1)
        .map(|(id, positions)| {
            serde_json::json!({"id": id, "count": positions.len(), "positions": positions})
        })
        .collect::<Vec<_>>();
    let rules = config
        .rules()
        .values()
        .map(|rule| {
            let entropy = if rule.entropy().is_nan() {
                serde_json::json!("NaN")
            } else if rule.entropy() == f64::INFINITY {
                serde_json::json!("+Inf")
            } else if rule.entropy() == f64::NEG_INFINITY {
                serde_json::json!("-Inf")
            } else if rule.entropy().fract() == 0.0
                && rule.entropy() >= -9_223_372_036_854_775_808.0
                && rule.entropy() < 9_223_372_036_854_775_808.0
            {
                serde_json::json!(rule.entropy().to_string().parse::<i64>().unwrap())
            } else {
                serde_json::json!(rule.entropy())
            };
            serde_json::json!({
                "id": rule.id(),
                "description": rule.description(),
                "path": rule.path(),
                "regex": rule.regex(),
                "secret_group": rule.secret_group(),
                "entropy": entropy,
                "entropy_bits": rule.entropy().to_bits(),
                "keywords": rule.keywords(),
                "tags": rule.tags(),
                "required": rule.required_rules().iter().map(|required| serde_json::json!({
                    "id": required.id,
                    "within_lines": required.within_lines,
                    "within_columns": required.within_columns,
                })).collect::<Vec<_>>(),
                "allowlists": rule.allowlists().iter().map(canonical_allowlist).collect::<Vec<_>>(),
                "skip_report": rule.skip_report(),
            })
        })
        .collect::<Vec<_>>();
    let path = match config.origin() {
        Some(ConfigOrigin::Path(path)) => path.to_string_lossy().into_owned(),
        Some(ConfigOrigin::Virtual(path)) => path.clone(),
        Some(ConfigOrigin::EmbeddedDefault) | None => String::new(),
    };
    serde_json::json!({
        "title": config.title(),
        "description": config.description(),
        "path": path,
        "min_version": config.min_version(),
        "extend": {
            "path": config.extension().path,
            "url": config.extension().url,
            "use_default": config.extension().use_default,
            "disabled_rules": config.extension().disabled_rules,
        },
        "ordered_rule_ids": config.ordered_rule_ids(),
        "duplicate_rule_ids": duplicate_rule_ids,
        "rules": rules,
        "global_allowlists": config.allowlists().iter().map(canonical_allowlist).collect::<Vec<_>>(),
        "normalized_keywords": config.keywords().iter().collect::<Vec<_>>(),
    })
}

fn config_error_class(error: &ConfigError) -> &'static str {
    match error {
        ConfigError::Parse { .. } => "parse",
        ConfigError::Decode { .. } => "unmarshal",
        ConfigError::Resolve(_) | ConfigError::ConflictingExtension => "extension",
        ConfigError::Extended(source) => config_error_class(source),
        ConfigError::GlobalAllowlistConflict
        | ConfigError::RuleAllowlistConflict { .. }
        | ConfigError::EmptyAllowlist { .. }
        | ConfigError::InvalidAllowlistCondition { .. }
        | ConfigError::InvalidRegexTarget { .. }
        | ConfigError::MissingTargetRuleId { .. } => "allowlist",
        ConfigError::EmptyRequiredRuleId { .. } | ConfigError::MissingRequiredRuleId { .. } => {
            "required-rule"
        }
        ConfigError::InvalidPattern { .. } => "panic",
        ConfigError::EmptyRuleId { .. }
        | ConfigError::MissingRulePattern { .. }
        | ConfigError::InvalidSecretGroup { .. } => "rule",
        ConfigError::InvalidMinVersion { .. } => "version",
    }
}

fn assert_canonical_config_eq(id: &str, actual: &serde_json::Value, expected: &serde_json::Value) {
    for field in [
        "title",
        "description",
        "path",
        "min_version",
        "extend",
        "ordered_rule_ids",
        "duplicate_rule_ids",
        "global_allowlists",
        "normalized_keywords",
    ] {
        assert_eq!(actual[field], expected[field], "{id}: effective.{field}");
    }
    let actual_rules = actual["rules"].as_array().unwrap();
    let expected_rules = expected["rules"].as_array().unwrap();
    assert_eq!(actual_rules.len(), expected_rules.len(), "{id}: rule count");
    for (actual_rule, expected_rule) in actual_rules.iter().zip(expected_rules) {
        let rule_id = expected_rule["id"].as_str().unwrap();
        for field in [
            "id",
            "description",
            "path",
            "regex",
            "secret_group",
            "entropy",
            "entropy_bits",
            "keywords",
            "tags",
            "required",
            "allowlists",
            "skip_report",
        ] {
            assert_eq!(
                actual_rule[field], expected_rule[field],
                "{id}: rule {rule_id}.{field}"
            );
        }
    }
}

#[test]
fn config_raw_001_is_constructible_permissive_and_serializable() {
    // CONFIG-RAW-001; TM-0034..TM-0041.
    let text = r#"
        TITLE = "case insensitive"
        unknownTopLevel = 42
        MinVERSION = "v8.25.0"
        [[RuLeS]]
        ID = "example"
        ReGeX = "(secret)"
        SecretGROUP = 1
        KeyWORDS = ["AWS"]
        unknownRuleField = true
    "#;
    let loader = ConfigLoader::new();
    let raw = loader.parse_toml(text, None).unwrap();
    assert_eq!(raw.title, "case insensitive");
    assert_eq!(raw.min_version, "v8.25.0");
    assert_eq!(raw.rules[0].secret_group, 1);
    assert!(raw.rules[0].tags.is_empty());
    let serialized = toml::to_string(&raw).unwrap();
    let reparsed = loader.parse_toml(&serialized, None).unwrap();
    assert_eq!(raw, reparsed);

    let constructed = RawConfig {
        title: "constructed".into(),
        rules: vec![RuleSpec {
            id: "r".into(),
            path: ".rs".into(),
            ..RuleSpec::default()
        }],
        ..RawConfig::default()
    };
    assert_eq!(loader.compile(constructed).unwrap().rules().len(), 1);
}

#[test]
fn config_compile_002_validates_and_normalizes_rules() {
    // CONFIG-COMPILE-002; TM-0035..TM-0041 and TM-0072.
    let generic = load_fixture("generic.toml").unwrap();
    let rule = generic.rule("generic-api-key").unwrap();
    assert_eq!(rule.entropy(), 3.5);
    assert!(rule.tags().is_empty());
    assert!(generic.keywords().contains("api"));

    let entropy = load_fixture("valid/rule_entropy_group.toml").unwrap();
    assert_eq!(entropy.rule("discord-api-key").unwrap().secret_group(), 3);
    assert!(load_fixture("valid/rule_path_only.toml").is_ok());
    assert!(load_fixture("valid/rule_regex_escaped_character_group.toml").is_ok());

    let missing = load_fixture("invalid/rule_missing_id.toml").unwrap_err();
    assert!(missing.starts_with("rule |id| is missing or empty, description:"));
    assert_eq!(
        load_fixture("invalid/rule_no_regex_or_path.toml").unwrap_err(),
        "discord-api-key: both |regex| and |path| are empty, this rule will have no effect"
    );
    assert_eq!(
        load_fixture("invalid/rule_bad_entropy_group.toml").unwrap_err(),
        "discord-api-key: invalid regex secret group 5, max regex secret group 3"
    );

    let normalized = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "r".into(),
                regex: "x".into(),
                allowlists: vec![AllowlistSpec {
                    commits: vec![" CommitA ".into(), "commita".into()],
                    stop_words: vec!["StopWord".into(), "stopword".into()],
                    ..AllowlistSpec::default()
                }],
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap();
    let allowlist = &normalized.rule("r").unwrap().allowlists()[0];
    assert_eq!(allowlist.commits().collect::<Vec<_>>(), ["commita"]);
    assert_eq!(allowlist.stop_words().collect::<Vec<_>>(), ["stopword"]);

    let empty = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "empty-allowlist".into(),
                regex: "x".into(),
                allowlists: vec![AllowlistSpec::default()],
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap_err();
    assert_eq!(
        empty.to_string(),
        "empty-allowlist: [[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords"
    );
}

#[test]
fn config_compile_002_preserves_duplicate_order_and_final_lookup() {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![
                RuleSpec {
                    id: "same".into(),
                    regex: "first".into(),
                    keywords: vec!["EARLIER".into()],
                    ..RuleSpec::default()
                },
                RuleSpec {
                    id: "same".into(),
                    regex: "second".into(),
                    keywords: vec!["Later".into()],
                    ..RuleSpec::default()
                },
            ],
            ..RawConfig::default()
        })
        .unwrap();
    assert_eq!(config.ordered_rule_ids(), ["same", "same"]);
    assert_eq!(config.rule("same").unwrap().regex(), Some("second"));
    assert_eq!(
        config
            .keywords()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["earlier", "later"]
    );
    assert_eq!(
        config
            .ordered_rules()
            .map(|rule| rule.regex().unwrap())
            .collect::<Vec<_>>(),
        ["second", "second"]
    );
}

#[test]
fn config_compile_002_handles_required_and_targeted_allowlists() {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![
                RuleSpec {
                    id: "base".into(),
                    regex: "base".into(),
                    ..RuleSpec::default()
                },
                RuleSpec {
                    id: "dependent".into(),
                    regex: "dependent".into(),
                    required: vec![RequiredRuleSpec {
                        id: "base".into(),
                        within_lines: Some(2),
                        within_columns: None,
                    }],
                    ..RuleSpec::default()
                },
            ],
            allowlists: vec![RawGlobalAllowlist {
                target_rules: vec!["dependent".into()],
                allowlist: AllowlistSpec {
                    regexes: vec!["fake".into()],
                    regex_target: RegexTarget::Match,
                    ..AllowlistSpec::default()
                },
            }],
            ..RawConfig::default()
        })
        .unwrap();
    assert_eq!(config.rule("dependent").unwrap().allowlists().len(), 1);
    assert_eq!(
        config.rule("dependent").unwrap().required_rules()[0].within_lines,
        Some(2)
    );

    let error = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "dependent".into(),
                regex: "x".into(),
                required: vec![RequiredRuleSpec {
                    id: "missing".into(),
                    ..RequiredRuleSpec::default()
                }],
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("rule ID 'missing' does not exist")
    );
}

#[test]
fn source_path_pruning_uses_only_global_path_expressions() {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "rule".into(),
                regex: "secret".into(),
                ..RuleSpec::default()
            }],
            allowlists: vec![
                RawGlobalAllowlist {
                    target_rules: Vec::new(),
                    allowlist: AllowlistSpec {
                        condition: Condition::And,
                        paths: vec![r"(^|/)generated/".into(), r"\\vendor\\".into()],
                        stop_words: vec!["generated".into()],
                        ..AllowlistSpec::default()
                    },
                },
                RawGlobalAllowlist {
                    target_rules: vec!["rule".into()],
                    allowlist: AllowlistSpec {
                        paths: vec![r"(^|/)targeted/".into()],
                        ..AllowlistSpec::default()
                    },
                },
            ],
            ..RawConfig::default()
        })
        .unwrap();

    assert!(config.source_path_allowed(b"src/generated/file.txt", None));
    assert!(config.source_path_allowed(
        b"C:/work/vendor/file.txt",
        Some(br"C:\work\vendor\file.txt")
    ));
    assert!(!config.source_path_allowed(b"src/targeted/file.txt", None));
    assert!(!config.source_path_allowed(b"src/main.rs", None));
}

#[test]
fn config_allowlist_fixtures_match_error_categories() {
    // CONFIG-RAW-001 / CONFIG-COMPILE-002; TM-0042..TM-0057.
    for relative in [
        "valid/allowlist_global_multiple.toml",
        "valid/allowlist_global_old_compat.toml",
        "valid/allowlist_global_regex.toml",
        "valid/allowlist_global_target_rules.toml",
        "valid/allowlist_rule_commit.toml",
        "valid/allowlist_rule_old_compat.toml",
        "valid/allowlist_rule_path.toml",
        "valid/allowlist_rule_regex.toml",
    ] {
        assert!(load_fixture(relative).is_ok(), "{relative}");
    }
    let invalid = [
        (
            "invalid/allowlist_global_empty.toml",
            "must contain at least one check",
        ),
        (
            "invalid/allowlist_global_old_and_new.toml",
            "[allowlist] is deprecated",
        ),
        (
            "invalid/allowlist_global_regextarget.toml",
            "unknown allowlist |regexTarget| 'mtach'",
        ),
        (
            "invalid/allowlist_global_target_rule_id.toml",
            "target rule ID 'github-pat' does not exist",
        ),
        (
            "invalid/allowlist_rule_empty.toml",
            "must contain at least one check",
        ),
        (
            "invalid/allowlist_rule_old_and_new.toml",
            "[rules.allowlist] is deprecated",
        ),
        (
            "invalid/allowlist_rule_regextarget.toml",
            "unknown allowlist |regexTarget| 'mtach'",
        ),
    ];
    for (relative, message) in invalid {
        let error = load_fixture(relative).unwrap_err();
        assert!(error.contains(message), "{relative}: {error}");
    }
}

#[test]
fn config_extend_003_matches_merge_matrix_and_is_reentrant() {
    // CONFIG-EXTEND-003; TM-0029..TM-0031 and TM-0058..TM-0071.
    let extended = load_fixture("valid/extend.toml").unwrap();
    assert_eq!(extended.rules().len(), 3);
    assert_eq!(
        extended.ordered_rule_ids(),
        ["aws-access-key", "aws-secret-key", "aws-secret-key-again"]
    );
    assert!(extended.rule("aws-secret-key-again-again").is_none());

    let disabled = load_fixture("valid/extend_disabled.toml").unwrap();
    assert!(disabled.rule("custom-rule1").is_none());
    assert!(disabled.rule("aws-secret-key").is_some());

    let cases = [
        (
            "valid/extend_rule_override_description.toml",
            "Puppy Doggy",
            None,
            0.0,
            0,
        ),
        (
            "valid/extend_rule_override_entropy.toml",
            "AWS Access Key",
            None,
            999.0,
            0,
        ),
        (
            "valid/extend_rule_override_path.toml",
            "AWS Access Key",
            Some("(?:puppy)"),
            0.0,
            0,
        ),
        (
            "valid/extend_rule_override_secret_group.toml",
            "AWS Access Key",
            None,
            0.0,
            2,
        ),
    ];
    for (relative, description, path, entropy, group) in cases {
        let config = load_fixture(relative).unwrap();
        let rule = config.rule("aws-access-key").unwrap();
        assert_eq!(rule.description(), description, "{relative}");
        assert_eq!(rule.path(), path, "{relative}");
        assert_eq!(rule.entropy(), entropy, "{relative}");
        assert_eq!(rule.secret_group(), group, "{relative}");
    }
    assert_eq!(
        load_fixture("valid/extend_rule_override_regex.toml")
            .unwrap()
            .rule("aws-access-key")
            .unwrap()
            .regex(),
        Some("(?:a)")
    );
    let keywords = load_fixture("valid/extend_rule_override_keywords.toml").unwrap();
    assert_eq!(
        keywords.rule("aws-access-key").unwrap().keywords(),
        ["puppy"]
    );
    let tags = load_fixture("valid/extend_rule_override_tags.toml").unwrap();
    assert_eq!(
        tags.rule("aws-access-key").unwrap().tags(),
        ["key", "AWS", "puppy"]
    );
    for relative in [
        "valid/extend_rule_allowlist_and.toml",
        "valid/extend_rule_allowlist_or.toml",
    ] {
        assert_eq!(
            load_fixture(relative)
                .unwrap()
                .rule("aws-secret-key-again-again")
                .unwrap()
                .allowlists()
                .len(),
            2
        );
    }
    assert!(load_fixture("valid/extend_rule_no_regexpath.toml").is_ok());

    let loader = ConfigLoader::new().with_resolver(fixture_resolver());
    let text = fixture("valid/extend.toml");
    for _ in 0..4 {
        assert_eq!(
            loader
                .load_toml_at(
                    &text,
                    Some(ConfigOrigin::virtual_path(
                        "../testdata/config/valid/extend.toml",
                    )),
                )
                .unwrap()
                .rules()
                .len(),
            3
        );
    }
    assert!(
        load_fixture("invalid/extend_invalid_ruleid.toml")
            .unwrap_err()
            .contains("rule |id| is missing or empty")
    );
}

#[test]
fn config_extend_003_rejects_conflicts_and_missing_paths_but_retains_urls() {
    let conflict = RawConfig {
        extend: ConfigExtension {
            path: "base.toml".into(),
            use_default: true,
            ..ConfigExtension::default()
        },
        ..RawConfig::default()
    };
    assert_eq!(
        ConfigLoader::new()
            .compile(conflict)
            .unwrap_err()
            .to_string(),
        "unable to load config due to extend.path and extend.useDefault being set"
    );
    let url = RawConfig {
        extend: ConfigExtension {
            url: "https://example.invalid/config.toml".into(),
            ..ConfigExtension::default()
        },
        ..RawConfig::default()
    };
    let url = ConfigLoader::new().compile(url).unwrap();
    assert_eq!(url.extension().url, "https://example.invalid/config.toml");
    assert!(
        load_fixture("invalid/extend_invalid_base.toml")
            .unwrap_err()
            .contains("virtual config was not found")
    );
}

#[test]
fn config_extend_003_resolvers_are_explicit_and_origin_aware() {
    let extending = "[extend]\npath='simple.toml'\n";
    let no_io_error = ConfigLoader::new().load_toml(extending).unwrap_err();
    assert!(
        no_io_error
            .to_string()
            .contains("external configuration I/O is disabled")
    );

    let origin = fixture_root().join("in-memory-top.toml");
    let config = ConfigLoader::new()
        .with_resolver(FileSystemResolver::new())
        .load_toml_at(extending, Some(ConfigOrigin::path(origin)))
        .unwrap();
    assert!(config.rule("aws-access-key").is_some());

    let resolver = VirtualResolver::new()
        .with_file("base.toml", "[[rules]]\nid='root'\nregex='root'\n")
        .with_file(
            "dir/base.toml",
            "[[rules]]\nid='relative'\nregex='relative'\n",
        );
    let config = ConfigLoader::new()
        .with_resolver(resolver)
        .load_toml_at(
            "[extend]\npath='base.toml'\n",
            Some(ConfigOrigin::virtual_path("dir/root.toml")),
        )
        .unwrap();
    assert!(config.rule("relative").is_some());
    assert!(config.rule("root").is_none());

    let parent_resolver = VirtualResolver::new()
        .with_file("base.toml", "[[rules]]\nid='wrong'\nregex='wrong'\n")
        .with_file("../base.toml", "[[rules]]\nid='parent'\nregex='parent'\n");
    let parent = ConfigLoader::new()
        .with_resolver(parent_resolver)
        .load_toml_at(
            "[extend]\npath='../base.toml'\n",
            Some(ConfigOrigin::virtual_path("../dir/root.toml")),
        )
        .unwrap();
    assert!(parent.rule("parent").is_some());
    assert!(parent.rule("wrong").is_none());

    let separator_resolver = VirtualResolver::new()
        .with_file("base.toml", "[[rules]]\nid='wrong'\nregex='wrong'\n")
        .with_file(
            "dir/base.toml",
            "[[rules]]\nid='portable'\nregex='portable'\n",
        );
    let portable = ConfigLoader::new()
        .with_resolver(separator_resolver)
        .load_toml_at(
            "[extend]\npath='base.toml'\n",
            Some(ConfigOrigin::virtual_path(r"dir\root.toml")),
        )
        .unwrap();
    assert!(portable.rule("portable").is_some());
    assert!(portable.rule("wrong").is_none());

    let unc_resolver = VirtualResolver::new()
        .with_file("base.toml", "[[rules]]\nid='wrong'\nregex='wrong'\n")
        .with_file(
            "//server/share/dir/base.toml",
            "[[rules]]\nid='unc'\nregex='unc'\n",
        );
    let unc = ConfigLoader::new()
        .with_resolver(unc_resolver)
        .load_toml_at(
            "[extend]\npath='base.toml'\n",
            Some(ConfigOrigin::virtual_path("//server/share/dir/root.toml")),
        )
        .unwrap();
    assert!(unc.rule("unc").is_some());
    assert!(unc.rule("wrong").is_none());

    let colon_resolver = VirtualResolver::new()
        .with_file("1:/base.toml", "[[rules]]\nid='wrong'\nregex='wrong'\n")
        .with_file(
            "dir/1:/base.toml",
            "[[rules]]\nid='relative-colon'\nregex='relative-colon'\n",
        );
    let relative_colon = ConfigLoader::new()
        .with_resolver(colon_resolver)
        .load_toml_at(
            "[extend]\npath='1:/base.toml'\n",
            Some(ConfigOrigin::virtual_path("dir/root.toml")),
        )
        .unwrap();
    assert!(relative_colon.rule("relative-colon").is_some());
    assert!(relative_colon.rule("wrong").is_none());

    let registered_backslash = VirtualResolver::new()
        .with_file("base.toml", "[[rules]]\nid='wrong'\nregex='wrong'\n")
        .with_file(
            r"dir\base.toml",
            "[[rules]]\nid='registered-backslash'\nregex='registered-backslash'\n",
        )
        .with_file(
            r"\\server\share\dir\base.toml",
            "[[rules]]\nid='registered-unc'\nregex='registered-unc'\n",
        );
    let ordinary_registration = ConfigLoader::new()
        .with_resolver(registered_backslash.clone())
        .load_toml_at(
            "[extend]\npath='base.toml'\n",
            Some(ConfigOrigin::virtual_path(r"dir\root.toml")),
        )
        .unwrap();
    assert!(ordinary_registration.rule("registered-backslash").is_some());
    let unc_registration = ConfigLoader::new()
        .with_resolver(registered_backslash)
        .load_toml_at(
            "[extend]\npath='base.toml'\n",
            Some(ConfigOrigin::virtual_path(r"\\server\share\dir\root.toml")),
        )
        .unwrap();
    assert!(unc_registration.rule("registered-unc").is_some());
}

#[test]
fn config_default_004_is_exact_and_effective() {
    // CONFIG-DEFAULT-004.
    assert_eq!(DEFAULT_CONFIG_REVISION, UPSTREAM_REVISION);
    assert_eq!(
        DEFAULT_CONFIG_SHA256,
        "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
    );
    assert_eq!(DEFAULT_CONFIG.as_bytes(), DEFAULT_CONFIG_BYTES);
    assert_eq!(sha256_hex(DEFAULT_CONFIG_BYTES), DEFAULT_CONFIG_SHA256);
    let default = ConfigLoader::new().load_default().unwrap();
    assert_eq!(default.rules().len(), 222);
    assert_eq!(default.ordered_rule_ids().len(), 222);
    assert_eq!(default.keywords().len(), 244);
    assert_eq!(default.min_version(), "v8.25.0");
}

#[test]
fn all_copied_config_fixtures_are_exercised() {
    let root = fixture_root();
    let top_level_valid = [
        "archives.toml",
        "composite.toml",
        "encoded.toml",
        "generic.toml",
        "generic_with_py_path.toml",
        "simple.toml",
    ];
    for relative in top_level_valid {
        assert!(load_fixture(relative).is_ok(), "{relative}");
    }
    let mut count = 0;
    let mut directories = vec![root];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
            } else if entry.path().extension().and_then(|value| value.to_str()) == Some("toml") {
                count += 1;
                let contents = fs::read_to_string(entry.path()).unwrap();
                ConfigLoader::new()
                    .parse_toml(&contents, None)
                    .unwrap_or_else(|error| panic!("{}: {error}", entry.path().display()));
            }
        }
    }
    assert_eq!(count, 50);
}

#[test]
fn canonical_config_corpus_matches_all_112_fresh_go_outcomes() {
    // CONFIG-RAW-001 / CONFIG-COMPILE-002 / CONFIG-EXTEND-003 /
    // CONFIG-DEFAULT-004; TM-0029..TM-0031 and TM-0034..TM-0072.
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/config-corpus");
    let mut resolver = VirtualResolver::new();
    for line in fs::read_to_string(corpus.join("inputs-v1.jsonl"))
        .unwrap()
        .lines()
    {
        let input: serde_json::Value = serde_json::from_str(line).unwrap();
        let path = input["path"].as_str().unwrap();
        let contents =
            String::from_utf8(decode_base64(input["config_base64"].as_str().unwrap())).unwrap();
        resolver.insert(path, contents.clone());
        resolver.insert(format!("../testdata/config/{path}"), contents);
    }
    let loader = ConfigLoader::new().with_resolver(resolver);
    let outcomes = fs::read_to_string(corpus.join("outcomes-v1.jsonl"))
        .unwrap()
        .lines()
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            (value["id"].as_str().unwrap().to_owned(), value)
        })
        .collect::<BTreeMap<_, _>>();

    let mut checked = 0;
    for line in fs::read_to_string(corpus.join("requests-v1.jsonl"))
        .unwrap()
        .lines()
    {
        let request: serde_json::Value = serde_json::from_str(line).unwrap();
        let id = request["id"].as_str().unwrap();
        let expected = &outcomes[id];
        let source = &request["source"];
        let kind = source["kind"].as_str().unwrap();
        let result = if kind == "default" {
            loader.load_default()
        } else {
            let contents =
                String::from_utf8(decode_base64(source["config_base64"].as_str().unwrap()))
                    .unwrap();
            match kind {
                "inline" => loader.load_toml(&contents),
                "origin" => loader.load_toml_at(
                    &contents,
                    Some(ConfigOrigin::virtual_path(
                        source["origin"].as_str().unwrap(),
                    )),
                ),
                "path" => loader.load_toml_at(
                    &contents,
                    Some(ConfigOrigin::virtual_path(source["path"].as_str().unwrap())),
                ),
                other => panic!("unexpected corpus source kind {other}"),
            }
        };

        if expected["error"].is_null() {
            let config = result.unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_canonical_config_eq(id, &canonical_config(&config), &expected["effective"]);
        } else {
            let Err(error) = result else {
                panic!("{id}: expected an error");
            };
            let expected_class = expected["error"]["class"].as_str().unwrap();
            assert_eq!(config_error_class(&error), expected_class, "{id}: {error}");
            if matches!(expected_class, "allowlist" | "rule" | "required-rule")
                || id == "focused/extend-default-path-conflict"
            {
                assert_eq!(
                    error.to_string(),
                    expected["error"]["message"].as_str().unwrap(),
                    "{id}"
                );
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 112);
}

#[test]
fn compiled_configuration_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CompiledConfig>();
    assert_send_sync::<ConfigLoader>();
}

#[test]
fn selected_rules_preserve_requested_order_and_rebuild_effective_indexes() {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![
                RuleSpec {
                    id: "alpha".into(),
                    regex: "alpha".into(),
                    keywords: vec!["alpha-keyword".into()],
                    ..RuleSpec::default()
                },
                RuleSpec {
                    id: "beta".into(),
                    regex: "beta".into(),
                    keywords: vec!["beta-keyword".into()],
                    ..RuleSpec::default()
                },
            ],
            allowlists: vec![RawGlobalAllowlist {
                target_rules: vec!["beta".into()],
                allowlist: AllowlistSpec {
                    regexes: vec!["allowed".into()],
                    ..AllowlistSpec::default()
                },
            }],
            ..RawConfig::default()
        })
        .unwrap();

    let selected = config.select_rules(["beta", "beta"]).unwrap();
    assert_eq!(selected.rules().len(), 1);
    assert!(selected.rule("alpha").is_none());
    assert_eq!(selected.ordered_rule_ids(), ["beta", "beta"]);
    assert_eq!(
        selected
            .ordered_rules()
            .map(rustleaks_core::config::CompiledRule::id)
            .collect::<Vec<_>>(),
        ["beta", "beta"]
    );
    assert_eq!(
        selected.keywords().iter().collect::<Vec<_>>(),
        ["beta-keyword"]
    );
    assert_eq!(selected.rule("beta").unwrap().allowlists().len(), 1);

    let error = config.select_rules(["missing", "alpha"]).unwrap_err();
    assert_eq!(error.rule_id(), "missing");
    assert_eq!(
        error.to_string(),
        "requested rule missing not found in rules"
    );

    let error = config
        .select_rules(std::iter::repeat_n(
            "beta",
            CompiledConfig::MAX_SELECTED_RULES + 1,
        ))
        .unwrap_err();
    assert_eq!(error.rule_id(), "");
    assert!(error.to_string().contains("4096-item safety limit"));
}

#[test]
fn min_version_is_structured_and_advisory() {
    let raw = RawConfig {
        min_version: "v99.0.0".into(),
        rules: vec![RuleSpec {
            id: "r".into(),
            regex: "r".into(),
            ..RuleSpec::default()
        }],
        ..RawConfig::default()
    };
    let loader = ConfigLoader::new().with_current_version("v8.25.0").unwrap();
    assert!(loader.compile(raw).unwrap().requires_newer_version());
    let invalid = RawConfig {
        min_version: "not semver".into(),
        ..RawConfig::default()
    };
    assert_eq!(
        ConfigLoader::new()
            .compile(invalid.clone())
            .unwrap()
            .min_version(),
        "not semver"
    );
    assert!(
        loader
            .compile(invalid)
            .unwrap_err()
            .to_string()
            .starts_with("invalid minVersion 'not semver':")
    );
}

#[test]
fn rule_selection_rejects_a_caller_sized_projection_before_clone_growth() {
    let config = ConfigLoader::new()
        .compile(RawConfig {
            rules: vec![RuleSpec {
                id: "large".into(),
                description: "x".repeat(CompiledConfig::MAX_SELECTED_BYTES + 1),
                regex: "large".into(),
                ..RuleSpec::default()
            }],
            ..RawConfig::default()
        })
        .unwrap();
    let error = config.select_rules(["large"]).unwrap_err();
    assert!(error.to_string().contains("byte safety limit"));
}

#[test]
fn condition_aliases_normalize() {
    let loader = ConfigLoader::new();
    for (source, expected) in [
        ("and", Condition::And),
        ("&&", Condition::And),
        ("or", Condition::Or),
        ("||", Condition::Or),
    ] {
        let raw = loader
            .parse_toml(
                &format!("[[allowlists]]\ncondition='{source}'\ncommits=['a']\n"),
                None,
            )
            .unwrap();
        assert_eq!(raw.allowlists[0].allowlist.condition, expected);
    }
    let invalid = loader
        .load_toml("[[allowlists]]\ncondition='xor'\ncommits=['a']\n")
        .unwrap_err();
    assert!(
        invalid
            .to_string()
            .contains("unknown allowlist |condition| 'xor'")
    );
}
