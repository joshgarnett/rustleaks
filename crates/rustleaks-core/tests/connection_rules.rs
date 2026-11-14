//! Independently specified synthetic controls for the optional connection pack.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::fmt::Write as _;
use std::sync::OnceLock;

use rustleaks_core::config::{ConfigLoader, RawConfig};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::native::{
    CONNECTION_RULES_V1, CONNECTION_RULES_V1_SHA256, EXTRA_RULES_V1, NativePolicy,
    PROVIDER_RULES_V1,
};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

const PREFIX: &str = "rustleaks.connection-string.password.";
const FORMS: [(&str, &str, &str); 4] = [
    ("unquoted", "", ""),
    ("double-quoted", "\"", "\""),
    ("single-quoted", "'", "'"),
    ("odbc-braced", "{", "}"),
];

fn isolated() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(ConfigLoader::new().load_toml(CONNECTION_RULES_V1).unwrap())
            .build()
            .unwrap()
    })
}

fn scan(engine: &Engine, input: &[u8]) -> Vec<Finding> {
    let outcome = engine.scan_fragment(&Fragment::new(input), &ScanOptions::default());
    assert!(outcome.is_complete());
    outcome.findings().to_vec()
}

fn range(start: usize, end: usize) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

fn assert_one(input: &str, secret: &str, suffix: &str) {
    let findings = scan(isolated(), input.as_bytes());
    assert_eq!(findings.len(), 1, "{input:?}");
    assert_eq!(
        findings[0].rule_id().as_bytes(),
        format!("{PREFIX}{suffix}").as_bytes()
    );
    assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
}

#[test]
fn all_five_forms_preserve_exact_secret_match_ranges_and_byte_locations() {
    for (suffix, left, secret, right, match_start) in [
        ("unquoted", "Host=db.invalid;Pwd=", "R7!q", ";", 3),
        (
            "double-quoted",
            "Server=db.invalid;Password=\"",
            "R7;!q",
            "\";",
            3,
        ),
        (
            "single-quoted",
            "Data Source=db.invalid;Pwd='",
            "R7;!q",
            "';",
            3,
        ),
        ("odbc-braced", "DSN=synthetic;Pwd={", "R7}};!q", "};", 3),
        (
            "jdbc-query",
            "jdbc:postgresql://db.invalid/app?password=",
            "%52%37!q",
            "&",
            4,
        ),
    ] {
        let input = format!("p\nx={left}{secret}{right}");
        let secret_start = 4 + left.len();
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{suffix}");
        let finding = &findings[0];
        assert_eq!(
            finding.rule_id().as_bytes(),
            format!("{PREFIX}{suffix}").as_bytes()
        );
        assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
        assert_eq!(
            finding.match_text().as_bytes(),
            &input.as_bytes()[match_start..]
        );
        assert_eq!(
            finding.secret_range(),
            range(secret_start, secret_start + secret.len())
        );
        assert_eq!(finding.match_range(), range(match_start, input.len()));
        // Native locations retain the existing preceding-LF byte-column origin.
        assert_eq!(
            finding.location(),
            Location::new(1, 1, match_start, input.len() - 1).unwrap()
        );
    }
}

#[test]
fn weak_passwords_percent_bytes_case_variants_and_jdbc_dialects_are_literal() {
    for (suffix, open, close) in FORMS {
        for context in ["SERVER", "Host", "dAtA\t sOuRcE", "dsn"] {
            for password in ["weak", "%52q7!", "%ZZq7!", "%24%7BPASSWORD%7D"] {
                assert_one(
                    &format!(
                        "{context} \t= db.invalid ; Uid=synthetic; pWd\t = {open}{password}{close};"
                    ),
                    password,
                    suffix,
                );
            }
        }
    }
    for dialect in [
        "postgresql",
        "mysql",
        "mariadb",
        "mysql:loadbalance",
        "mysql:replication",
    ] {
        assert_one(
            &format!(
                "JDBC:{}://DB.INVALID/app?flag&USER=synthetic&AMP;password=weak&",
                dialect.to_ascii_uppercase()
            ),
            "weak",
            "jdbc-query",
        );
    }
    for (suffix, open, close) in [FORMS[0], FORMS[3]] {
        assert_one(
            &format!("JDBC:SQLSERVER://db.invalid;password={open}weak{close};"),
            "weak",
            suffix,
        );
    }
    // Percent sequences are never decoded by the raw connection detector.
    assert_one(
        "jdbc:mysql://db.invalid/app?password=%24%7BPASSWORD%7D",
        "%24%7BPASSWORD%7D",
        "jdbc-query",
    );
}

#[test]
fn syntax_near_misses_and_unsupported_languages_stay_outside_this_pack() {
    for input in [
        "Password=R7!q;",
        "ProxyServer=db.invalid;Pwd=R7!q;",
        "HostName=db.invalid;Pwd=R7!q;",
        "Pwd=R7!q;Host=db.invalid;",
        "Host=;Pwd=R7!q;",
        "Host=\"db.invalid\";Pwd=R7!q;",
        "Host=db.invalid;\nPwd=R7!q;",
        "Host=db.invalid;\r\nPwd=R7!q;",
        "Host=db.invalid;Driver={Synthetic;Pwd=R7!q;};",
        "Host=db.invalid;Pwd:R7!q;",
        "Host=db.invalid;Pwd=\"R7!q;",
        "Host=db.invalid;Pwd='R7!q;",
        "Host=db.invalid;Pwd={R7!q;",
        "Host=db.invalid;Pwd=\"R7\"\"!q\";",
        "Host=db.invalid;Pwd='R7''!q';",
        "jdbc:sqlserver://db.invalid;password=\"R7!q\";",
        "jdbc:sqlserver://db.invalid;password='R7!q';",
        "jdbc:mysql://db.invalid/app?PASSWORD=R7!q",
        "jdbc:mysql://db.invalid/app?notpassword=R7!q",
        "jdbc:mysql://db.invalid/app?passwordHint=R7!q",
        "jdbc:mysql://db.invalid/app?password=",
        "jdbc:mysql:///?password=R7!q",
        "jdbc:mysql://db invalid/app?password=R7!q",
        "jdbc:oracle:thin:@db.invalid:1521/app?password=R7!q",
        "jdbc:sqlite:db?password=R7!q",
        "host=db.invalid user=synthetic password='R7!q'",
        "_jdbc:mysql://db.invalid/app?password=R7!q",
        "xjdbc:mysql://db.invalid/app?password=R7!q",
    ] {
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{input:?}");
    }
    // This is a content detector: an allowed punctuation boundary can expose
    // an embedded JDBC substring. It does not certify the entire prefix.
    assert_one(
        "wrong+jdbc:mysql://db.invalid/app?password=R7!q",
        "R7!q",
        "jdbc-query",
    );
}

#[test]
fn per_form_bounds_are_bytes_and_odbc_doubled_braces_are_units() {
    for (suffix, open, close) in FORMS {
        for length in [4, 128] {
            let password = "Q".repeat(length);
            assert_one(
                &format!("Host=db.invalid;Pwd={open}{password}{close};"),
                &password,
                suffix,
            );
        }
        for length in [0, 3, 129] {
            let input = format!("Host=db.invalid;Pwd={open}{}{close};", "Q".repeat(length));
            assert!(
                scan(isolated(), input.as_bytes()).is_empty(),
                "{suffix}, {length}"
            );
        }
    }
    for length in [4, 128] {
        let password = "}}".repeat(length);
        assert_one(
            &format!("Host=db.invalid;Pwd={{{password}}};"),
            &password,
            "odbc-braced",
        );
    }
    for length in [3, 129] {
        let input = format!("Host=db.invalid;Pwd={{{}}};", "}}".repeat(length));
        assert!(scan(isolated(), input.as_bytes()).is_empty());
    }
    for (host_len, context_len, accepted) in
        [(128, 200, true), (129, 200, false), (128, 201, false)]
    {
        let input = format!(
            "Host={};A={};Pwd=R7!q;",
            "d".repeat(host_len),
            "x".repeat(context_len - 2)
        );
        assert_eq!(
            scan(isolated(), input.as_bytes()).len(),
            usize::from(accepted)
        );
    }
    // Trailing horizontal whitespace is outside the host repetition bound.
    assert_one(
        &format!("Host={}{};Pwd=R7!q;", "d".repeat(128), " ".repeat(129)),
        "R7!q",
        "unquoted",
    );
}

#[test]
fn jdbc_authority_path_query_count_key_and_value_limits_remain_distinct() {
    for (authority, path, options, password, accepted) in [
        (256, 200, 16, 128, true),
        (257, 200, 16, 128, false),
        (256, 201, 16, 128, false),
        (256, 200, 17, 128, false),
        (256, 200, 16, 129, false),
        (1, 0, 0, 4, true),
        (1, 0, 0, 3, false),
        (1, 0, 1, 4, true),
        (1, 0, 15, 4, true),
    ] {
        let input = format!(
            "jdbc:mysql://{}/{}?{}password={}&",
            "d".repeat(authority),
            "p".repeat(path),
            "a=b&".repeat(options),
            "Q".repeat(password)
        );
        assert_eq!(
            scan(isolated(), input.as_bytes()).len(),
            usize::from(accepted)
        );
    }
    for (key_len, value_len, accepted) in [(64, 200, true), (65, 200, false), (64, 201, false)] {
        let input = format!(
            "jdbc:postgresql://d/?{}={}&password=R7!q",
            "k".repeat(key_len),
            "v".repeat(value_len)
        );
        assert_eq!(
            scan(isolated(), input.as_bytes()).len(),
            usize::from(accepted)
        );
    }
    // Greedy preceding-option selection retains the last eligible password.
    assert_one(
        "jdbc:mysql://d/?password=R7!q&password=T8!w",
        "T8!w",
        "jdbc-query",
    );
}

#[test]
fn multiple_occurrences_preserve_nearest_selection_and_consumed_delimiters() {
    for (suffix, open, close) in FORMS {
        for between in ["", "Uid=synthetic;Database=app;"] {
            let first = format!("FIRST=Host=one;{between}Pwd={open}R7!q{close};");
            let second = format!(" SECOND=Host=two;{between}Pwd={open}T8!w{close};");
            let input = format!("{first}{second}");
            let findings = scan(isolated(), input.as_bytes());
            assert_eq!(findings.len(), 2, "{suffix}");
            for (finding, lead, secret, offset) in [
                (
                    &findings[0],
                    format!("FIRST=Host=one;{between}Pwd={open}"),
                    "R7!q",
                    0,
                ),
                (
                    &findings[1],
                    format!(" SECOND=Host=two;{between}Pwd={open}"),
                    "T8!w",
                    first.len(),
                ),
            ] {
                assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
                assert_eq!(
                    finding.secret_range(),
                    range(offset + lead.len(), offset + lead.len() + 4)
                );
            }
        }
    }
    let adjacent = "Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;";
    // The first full match consumes the semicolon required to start the next
    // match. This explicitly records the native occurrence gap. Cross-tool
    // enumeration is a separate question, not proved by this regression.
    assert_one(adjacent, "R7!q", "unquoted");
    let repeated = "FIRST=Host=one;Pwd=R7!q; SECOND=Host=two;Pwd=R7!q;";
    assert_eq!(scan(isolated(), repeated.as_bytes()).len(), 2);
    let input = "jdbc:mysql://one/?password=R7!q jdbc:mysql://two/?password=T8!w";
    let findings = scan(isolated(), input.as_bytes());
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].secret().as_bytes(), b"R7!q");
    assert_eq!(findings[1].secret().as_bytes(), b"T8!w");
}

#[test]
fn unicode_and_invalid_bytes_inside_matches_are_outside_the_ascii_pack() {
    for input in [
        "Hoſt=db.invalid;Pwd=R7!q;",
        "Host=☃;Pwd=R7!q;",
        "Host=db.invalid;Pwd=éééé;",
        "Host=db.invalid;Pwd=\"éééé\";",
        "Host=db.invalid;Pwd='éééé';",
        "Host=db.invalid;Pwd={éééé};",
        "Host=db.invalid;A=é;Pwd=R7!q;",
        "jdbc:mysql://db.invalid/é?password=R7!q",
        "jdbc:mysql://db.invalid/?password=R7éq",
        "jdbc:mysql://db.invalid/?password=R7!q\u{a0}",
    ] {
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{input:?}");
    }
    for input in [
        b"Host=d\xff;Pwd=R7!q;".as_slice(),
        b"Host=d;Pwd=R7\xffq;".as_slice(),
    ] {
        assert!(scan(isolated(), input).is_empty());
    }
    // An ASCII match is allowed inside a larger byte fragment. No Unicode or
    // invalid-byte normalization occurs, and source byte spans stay physical.
    for prefix in ["☃ ".as_bytes(), b"\xff ".as_slice()] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(b"Host=d;Pwd=R7!q;");
        let findings = scan(isolated(), &input);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].secret_range(),
            range(prefix.len() + 11, prefix.len() + 15)
        );
    }
    let input = b"Host=d;Pwd=R7\0q;";
    let findings = scan(isolated(), input);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret().as_bytes(), b"R7\0q");
}

fn assert_jdbc_space_terminated_prefix(input: &str, expected: &str) {
    let findings = scan(isolated(), input.as_bytes());
    let prefix = "jdbc:mysql://d/?password=";
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(
        finding.rule_id().as_bytes(),
        b"rustleaks.connection-string.password.jdbc-query"
    );
    assert_eq!(finding.secret().as_bytes(), expected.as_bytes());
    assert_eq!(
        finding.match_text().as_bytes(),
        format!("{prefix}{expected} ").as_bytes()
    );
    assert_eq!(
        finding.secret_range(),
        range(prefix.len(), prefix.len() + expected.len())
    );
    assert_eq!(
        finding.match_range(),
        range(0, prefix.len() + expected.len() + 1)
    );
}

#[test]
fn source_stopwords_are_case_insensitive_substrings_of_the_secret() {
    // Independently retained source policy inventory, not loaded from the TOML.
    let literal = [
        "${",
        "$(",
        "#{",
        "{{",
        "$env:",
        "redacted",
        "masked",
        "filtered",
        "****",
        "xxxx",
        "placeholder",
        "your_password",
        "yourpassword",
        "your-password",
        "your password",
        "insert_password",
        "replace_password",
        "changeme",
        "change_me",
        "change-me",
        "change.me",
        "change me",
        "replaceme",
        "replace_me",
        "replace-me",
        "replace.me",
        "replace me",
    ];
    let code = [
        "db_password",
        "database_password",
        "process.env",
        "os.environ",
        "config.",
        "config[",
        "settings.",
        "settings[",
        "secret.",
        "secrets.",
        "secrets[",
        "credential.",
        "credentials.",
        "credentials[",
        "getpassword(",
        "getenv(",
    ];
    for marker in literal {
        let secret = format!("Q7{}z9", marker.to_ascii_uppercase());
        for (_, open, close) in FORMS {
            let input = format!("Host=d;Pwd={open}{secret}{close};");
            assert!(scan(isolated(), input.as_bytes()).is_empty(), "{marker}");
        }
        let input = format!("jdbc:mysql://d/?password={secret}");
        // JDBC accepts whitespace as its terminal delimiter. These three
        // authored inputs therefore capture only the prefix before the space;
        // the complete two-word stopword is absent from the selected secret.
        // Semicolon forms above do not accept space alone as a terminator.
        match marker {
            "your password" => assert_jdbc_space_terminated_prefix(&input, "Q7YOUR"),
            "change me" => assert_jdbc_space_terminated_prefix(&input, "Q7CHANGE"),
            "replace me" => assert_jdbc_space_terminated_prefix(&input, "Q7REPLACE"),
            _ => assert!(scan(isolated(), input.as_bytes()).is_empty(), "{marker}"),
        }
    }
    for marker in code {
        let secret = format!("Q7{}z9", marker.to_ascii_uppercase());
        for (suffix, open, close) in FORMS {
            let input = format!("Host=d;Pwd={open}{secret}{close};");
            if suffix == "unquoted" {
                assert!(scan(isolated(), input.as_bytes()).is_empty(), "{marker}");
            } else {
                assert_one(&input, &secret, suffix);
            }
        }
        let input = format!("jdbc:mysql://d/?password={secret}");
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{marker}");
    }
    assert_one("Host=masked.invalid;Pwd=weak;", "weak", "unquoted");
    assert_one(
        "Host=d;Pwd=\"process.env.DB_PASSWORD\";",
        "process.env.DB_PASSWORD",
        "double-quoted",
    );
}

#[test]
fn custom_global_rule_and_targeted_allowlists_keep_existing_behavior() {
    let id = format!("{PREFIX}unquoted");
    for global in [false, true] {
        for condition in [
            "stopwords = ['7!']",
            "regexes = ['^R7!q$']",
            "paths = ['^allowed[.]conf$']",
            "commits = ['synthetic-commit']",
        ] {
            let mut raw: RawConfig = toml::from_str(CONNECTION_RULES_V1).unwrap();
            let source = if global {
                format!("[[allowlists]]\nregexTarget = 'secret'\n{condition}\n")
            } else {
                format!(
                    "[[rules]]\nid = 'source'\n[[rules.allowlists]]\nregexTarget = 'secret'\n{condition}\n"
                )
            };
            let extra: RawConfig = toml::from_str(&source).unwrap();
            if global {
                raw.allowlists.extend(extra.allowlists);
            } else {
                raw.rules
                    .iter_mut()
                    .find(|rule| rule.id == id)
                    .unwrap()
                    .allowlists
                    .extend(extra.rules[0].allowlists.clone());
            }
            let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                .build()
                .unwrap();
            let fragment = Fragment::builder(b"Host=d;Pwd=R7!q;".as_slice())
                .file_path("allowed.conf")
                .commit("synthetic-commit")
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert!(result.findings().is_empty());
        }
    }
    let mut raw: RawConfig = toml::from_str(CONNECTION_RULES_V1).unwrap();
    let extra: RawConfig = toml::from_str(&format!(
        "[[allowlists]]\ntargetRules = ['{id}']\nstopwords = ['R7!q']\n"
    ))
    .unwrap();
    raw.allowlists = extra.allowlists;
    let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        scan(&engine, b"Host=d;Pwd=R7!q; Host=d;Pwd=\"R7!q\";").len(),
        1
    );
    assert!(scan(isolated(), b"Host=d;Pwd=R7!q; gitleaks:allow").is_empty());
}

#[test]
fn composition_is_opt_in_and_overlapping_generic_attribution_remains_explicit() {
    let base = NativePolicy::builder().build().unwrap();
    let connections = NativePolicy::builder()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    assert!(
        base.engine()
            .config()
            .rule(&format!("{PREFIX}unquoted"))
            .is_none()
    );
    assert!(scan(base.engine(), b"Host=d;Pwd=weak;").is_empty());
    assert_eq!(scan(connections.engine(), b"Host=d;Pwd=weak;").len(), 1);
    // An already detected generic occurrence receives specific attribution.
    let input = b"Host=d;Password=Q7m2Z9v4L1c8R5s0N6b3X;";
    let old = scan(base.engine(), input);
    assert!(
        old.iter()
            .any(|finding| finding.rule_id().as_bytes() == b"generic-api-key")
    );
    let new = scan(connections.engine(), input);
    assert!(
        new.iter()
            .any(|finding| finding.rule_id().as_bytes() == format!("{PREFIX}unquoted").as_bytes())
    );
    assert!(
        !new.iter()
            .any(|finding| finding.rule_id().as_bytes() == b"generic-api-key")
    );
    for extra in [false, true] {
        let old_policy = if extra {
            NativePolicy::builder()
                .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
                .unwrap()
        } else {
            NativePolicy::builder()
        };
        let old_policy = old_policy
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap();
        let old = old_policy.clone().build().unwrap();
        let new = old_policy
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .build()
            .unwrap();
        for input in [
            b"mongodb://synthetic:weak@db.example.invalid/".as_slice(),
            b"r8_Q7m2Z9v4L1c8R5s0N6b3XQ7m2Z9v4L1c8R5s0N;".as_slice(),
        ] {
            assert_eq!(scan(new.engine(), input), scan(old.engine(), input));
        }
    }
    let token = format!(
        "r8_{}",
        "Q7m2Z9v4L1c8R5s0N6b3X"
            .chars()
            .cycle()
            .take(37)
            .collect::<String>()
    );
    let both = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    let input = format!("Host=d;Pwd={token};");
    let findings = scan(both.engine(), input.as_bytes());
    assert_eq!(findings.len(), 2);
    for id in [
        "rustleaks.replicate-api-token",
        "rustleaks.connection-string.password.unquoted",
    ] {
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id().as_bytes() == id.as_bytes())
            .unwrap();
        assert_eq!(finding.secret().as_bytes(), token.as_bytes());
        assert_eq!(finding.secret_range(), range(11, 11 + token.len()));
    }
}

#[test]
fn existing_decoding_keeps_raw_spelling_and_marks_ranges_unavailable() {
    let raw = "Host=d;Pwd=%52q7!;";
    let encoded = raw.bytes().fold(String::new(), |mut output, byte| {
        write!(output, "%{byte:02X}").unwrap();
        output
    });
    assert!(scan(isolated(), encoded.as_bytes()).is_empty());
    let result = isolated().scan_fragment(
        &Fragment::new(encoded.as_bytes()),
        &ScanOptions::builder().max_decode_depth(1).build(),
    );
    assert!(result.is_complete());
    assert_eq!(result.findings().len(), 1);
    assert_eq!(result.findings()[0].secret().as_bytes(), b"%52q7!");
    assert_eq!(
        result.findings()[0].secret_range(),
        FindingRange::Unavailable
    );
    assert_eq!(
        result.findings()[0].match_range(),
        FindingRange::Unavailable
    );
}

#[test]
fn builtin_identity_retains_old_compositions_and_binds_connection_order() {
    let pack = NativePolicy::builder()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    assert!(
        pack.identity()
            .builtin_review_reference()
            .unwrap()
            .contains(CONNECTION_RULES_V1_SHA256)
    );
    let mut identities = Vec::new();
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let packs = [
            ("rustleaks-extra-v1", EXTRA_RULES_V1),
            ("rustleaks-providers-v1", PROVIDER_RULES_V1),
            ("rustleaks-connections-v1", CONNECTION_RULES_V1),
        ];
        let mut policy = NativePolicy::builder();
        for index in order {
            policy = policy.with_pack(packs[index].0, packs[index].1).unwrap();
        }
        let engine = policy.build().unwrap();
        assert!(engine.identity().builtin_review_reference().is_some());
        assert!(!identities.contains(engine.identity()));
        identities.push(engine.identity().clone());
    }
    for (name, contents) in [
        ("custom-connections", CONNECTION_RULES_V1.to_owned()),
        (
            "rustleaks-connections-v1",
            format!("{CONNECTION_RULES_V1}\n"),
        ),
    ] {
        let engine = NativePolicy::builder()
            .with_pack(name, &contents)
            .unwrap()
            .build()
            .unwrap();
        assert!(engine.identity().builtin_review_reference().is_none());
    }
}

#[test]
fn dense_matches_keep_finite_finding_and_work_budgets() {
    let input = "item=Host=d;Pwd=R7!q; ".repeat(32);
    let fragment = Fragment::new(input.as_bytes());
    let options = ScanOptions::default();
    let full = isolated().scan_fragment(&fragment, &options);
    assert!(full.is_complete());
    assert_eq!(full.findings().len(), 32);
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
    let short = isolated().scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited()
            .with_budget(ScanBudget::unlimited().max_work_units(full.usage().work_units() - 1)),
    );
    assert!(!short.is_complete());
}

#[test]
fn database_uri_preserves_raw_password_ranges_delimiters_and_locations() {
    for scheme in ["postgres", "postgresql", "mysql", "mariadb", "POSTGRESQL"] {
        for secret in [
            "7",
            "weak",
            "R7!q:more",
            "%52q7!",
            "%ZZq7!",
            "%24%7BPASSWORD%7D",
        ] {
            for terminal in [
                "", " ", "\t", "\r", "\n", "\u{b}", "'", "\"", "`", "#", "\\n", "\\R",
            ] {
                let left = format!("{scheme}://app:");
                let tail = format!("@db.invalid:5432/app?mode=rw{terminal}");
                let input = format!("p\nx={left}{secret}{tail}");
                let findings = scan(isolated(), input.as_bytes());
                assert_eq!(findings.len(), 1, "{input:?}");
                let finding = &findings[0];
                let end = input.len() - usize::from(terminal == "\n");
                assert_eq!(
                    finding.rule_id().as_bytes(),
                    format!("{PREFIX}database-uri").as_bytes()
                );
                assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
                assert_eq!(
                    finding.secret_range(),
                    range(4 + left.len(), 4 + left.len() + secret.len())
                );
                assert_eq!(finding.match_range(), range(4, end));
                assert_eq!(finding.match_text().as_bytes(), &input.as_bytes()[4..end]);
                assert_eq!(finding.location(), Location::new(1, 1, 4, end - 1).unwrap());
            }
        }
    }
}

#[test]
fn database_uri_userinfo_host_bounds_and_content_boundaries_are_explicit() {
    for username_len in [0, 1, 128, 129] {
        for password_len in [0, 1, 256, 257] {
            let password = "7".repeat(password_len);
            let input = format!(
                "postgresql://{}:{password}@db.invalid/",
                "u".repeat(username_len)
            );
            assert_eq!(
                scan(isolated(), input.as_bytes()).len(),
                usize::from(username_len <= 128 && (1..=256).contains(&password_len))
            );
        }
    }
    for (host, accepted) in [
        ("d".repeat(253), true),
        ("d".repeat(254), false),
        (String::new(), false),
    ] {
        let input = format!("mysql://app:R7!q@{host}/");
        assert_eq!(
            scan(isolated(), input.as_bytes()).len(),
            usize::from(accepted)
        );
    }
    for port_len in [0, 1, 5, 6] {
        let input = format!("mariadb://app:R7!q@db.invalid:{}/", "9".repeat(port_len));
        assert_eq!(
            scan(isolated(), input.as_bytes()).len(),
            usize::from((1..=5).contains(&port_len))
        );
    }
    for input in [
        "postgresql://app:R7!q@[2001:DB8::1%25],db.invalid:1/",
        "postgres://:R7!q@db.invalid/",
        "postgresql://app;user:R7!q@db.invalid/",
        "wrong+postgresql://app:R7!q@db.invalid/",
        "jdbc:postgresql://app:R7!q@db.invalid/",
    ] {
        // Punctuation can expose an embedded URI. This does not validate its prefix.
        assert_one(input, "R7!q", "database-uri");
    }
    for input in [
        "postgresql://app:@db.invalid/",
        "postgresql://app@db.invalid/",
        "postgresql://app;R7!q@db.invalid/",
        "postgresql:/app:R7!q@db.invalid/",
        "postgresql://app:R7/q@db.invalid/",
        "postgresql://app:R7@q@db.invalid/",
        "postgresql://app:R7!q@-db.invalid/",
        "postgresql://app:R7!q@[GG::1]/",
        "postgresql://app:R7!q@db.invalid!",
        "xpostgresql://app:R7!q@db.invalid/",
        "_postgresql://app:R7!q@db.invalid/",
        "https://app:R7!q@db.invalid/",
        "mongodb://app:R7!q@db.invalid/",
        "redis://app:R7!q@db.invalid/",
        "host=db.invalid user=app password=R7!q",
    ] {
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{input:?}");
    }
}

#[test]
fn database_uri_retains_all_source_rejection_families_without_confidence_suppression() {
    // Independently authored representatives of the retained global and local predicates.
    for secret in [
        "TrUeSuffix",
        "prefixFALSEsuffix",
        "prefixNULL",
        "AAAA",
        "****",
        "....",
        "xxxx",
        "$1",
        "${12}",
        "$PASSWORD",
        "${PASSWORD}",
        "{{PASSWORD}}",
        "%PASSWORD%",
        "%s",
        "{12}",
        "your_password",
        "db-your-pwd",
        "password-goes-here",
        "replace-me",
        "insert_a_here",
        "placeholder",
        "[redacted]",
        "MASKED",
        "filtered",
        "$(PASSWORD)",
        "#{PASSWORD}",
        "%{PASSWORD}",
        "$Password1",
        "$env:Password1",
        "<Password1>",
        "[Password1]",
        "{Password1}",
        "R7${PASSWORD}q",
        "R7#{PASSWORD}q",
        "R7{{PASSWORD}}q",
        "R7%{PASSWORD}q",
        "R7ABCDEFGHIJKLMNOPQRSTUVWXYZq",
        "R7014DF517-39D1-4453-B7B3-9930C563627Cq",
    ] {
        let input = format!("postgres://app:{secret}@db.invalid/");
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{secret:?}");
    }
    for host in [
        "example",
        "EXAMPLE.",
        "example.com",
        "db.example.org:12345",
        "example.net,sub.example.com",
    ] {
        let input = format!("mysql://app:R7!q@{host}/");
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{host}");
    }
    for input in [
        "mysql://foo:bar@example.invalid/",
        "mysql://user:pass@test.com/",
    ] {
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{input}");
    }
    for (secret, host) in [
        ("password", "db.invalid"),
        ("example-password", "localhost"),
        ("test123!", "test"),
        ("R7!q", "example.invalid"),
        ("R7!q", "example.com.evil.invalid"),
        ("R7!q", "example.com,db.invalid"),
        ("R7maskedq", "db.invalid"),
        ("R7your_passwordq", "db.invalid"),
        ("%24%7BPASSWORD%7D", "db.invalid"),
    ] {
        let input = format!("postgres://user:{secret}@{host}/");
        assert_one(&input, secret, "database-uri");
        for path in [
            "README.md",
            "tests/fixture.conf",
            "docs/example.md",
            ".git/config",
            ".git-credentials",
            "shell_history",
        ] {
            let result = isolated().scan_fragment(
                &Fragment::builder(input.as_bytes()).file_path(path).build(),
                &ScanOptions::default(),
            );
            assert!(result.is_complete());
            assert_eq!(result.findings().len(), 1, "{path}: {input}");
        }
    }
}

#[test]
fn database_uri_ascii_domain_preserves_surrounding_bytes_and_raw_controls() {
    for input in [
        "poſtgres://app:R7!q@db.invalid/",
        "postgres://é:R7!q@db.invalid/",
        "postgres://app:R7éq@db.invalid/",
        "postgres://app:R7!q@é.invalid/",
        "postgres://app:R7!q@db.invalid/é",
        "postgres://app:R7!q@db.invalid\u{a0}",
    ] {
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{input:?}");
    }
    for input in [
        b"postgres://a\xff:R7!q@db.invalid/".as_slice(),
        b"postgres://app:R7\xffq@db.invalid/".as_slice(),
        b"postgres://app:R7!q@db\xff.invalid/".as_slice(),
        b"postgres://app:R7!q@db.invalid/\xff".as_slice(),
    ] {
        assert!(scan(isolated(), input).is_empty());
    }
    for prefix in ["☃ ".as_bytes(), b"\xff ".as_slice()] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(b"mysql://app:R7\0q@db.invalid/");
        let findings = scan(isolated(), &input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret().as_bytes(), b"R7\0q");
        assert_eq!(
            findings[0].secret_range(),
            range(prefix.len() + 12, prefix.len() + 16)
        );
        assert_eq!(findings[0].match_range(), range(prefix.len(), input.len()));
    }
}

#[test]
fn database_uri_multiple_occurrences_and_provider_overlap_keep_distinct_findings() {
    for between in [" ", "\n", "'", ")"] {
        let first = "postgres://app:R7!q@db.invalid/";
        let second = "mysql://app:R7!q@db.invalid/";
        let input = format!("{first}{between}{second}");
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 2, "{between:?}");
        assert_eq!(findings[0].secret_range(), range(15, 19));
        assert_eq!(
            findings[1].secret_range(),
            range(
                first.len() + between.len() + 12,
                first.len() + between.len() + 16
            )
        );
    }
    // Semicolons and all bytes in the second URI are also legal path bytes.
    // Greedy path matching therefore retains one first-password occurrence.
    let adjacent = "postgres://app:R7!q@db.invalid/;mysql://app:T8!w@db.invalid/";
    let findings = scan(isolated(), adjacent.as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret().as_bytes(), b"R7!q");
    assert_eq!(findings[0].match_range(), range(0, adjacent.len()));
    // A finite GitHub PAT detector can independently match this exact password.
    let token = format!(
        "ghp_{}",
        "Q7m2Z9v4L1c8R5s0N6b3X"
            .chars()
            .cycle()
            .take(36)
            .collect::<String>()
    );
    let input = format!("postgres://app:{token}@db.invalid/");
    for extra in [false, true] {
        let mut policy = NativePolicy::builder()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap();
        if extra {
            policy = policy
                .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
                .unwrap();
        }
        let before = policy.clone().build().unwrap();
        let after = policy
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .build()
            .unwrap();
        assert!(
            scan(before.engine(), input.as_bytes())
                .iter()
                .any(|f| f.rule_id().as_bytes() == b"github-pat")
        );
        let findings = scan(after.engine(), input.as_bytes());
        for id in [
            "github-pat",
            "rustleaks.connection-string.password.database-uri",
        ] {
            let finding = findings
                .iter()
                .find(|f| f.rule_id().as_bytes() == id.as_bytes())
                .unwrap();
            assert_eq!(finding.secret().as_bytes(), token.as_bytes());
            assert_eq!(finding.secret_range(), range(15, 15 + token.len()));
        }
    }
}

#[test]
fn database_uri_allowlists_and_decoding_retain_native_contracts() {
    for target in ["secret", "match", "line"] {
        let mut raw: RawConfig = toml::from_str(CONNECTION_RULES_V1).unwrap();
        let extra: RawConfig = toml::from_str(&format!("[[allowlists]]\ntargetRules = ['{PREFIX}database-uri']\nregexTarget = '{target}'\nregexes = ['R7!q']\n")).unwrap();
        raw.allowlists = extra.allowlists;
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        assert!(scan(&engine, b"postgres://app:R7!q@db.invalid/").is_empty());
        assert_eq!(scan(&engine, b"Host=d;Pwd=R7!q;").len(), 1);
    }
    for global in [false, true] {
        for condition in [
            "stopwords = ['7!']",
            "paths = ['^allowed[.]conf$']",
            "commits = ['synthetic-commit']",
        ] {
            let mut raw: RawConfig = toml::from_str(CONNECTION_RULES_V1).unwrap();
            let extra: RawConfig = toml::from_str(&format!(
                "[[allowlists]]\nregexTarget = 'secret'\n{condition}\n"
            ))
            .unwrap();
            if global {
                raw.allowlists = extra.allowlists;
            } else {
                raw.rules
                    .iter_mut()
                    .find(|r| r.id == format!("{PREFIX}database-uri"))
                    .unwrap()
                    .allowlists
                    .extend(extra.allowlists.into_iter().map(|entry| entry.allowlist));
            }
            let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
                .build()
                .unwrap();
            let fragment = Fragment::builder(b"postgres://app:R7!q@db.invalid/".as_slice())
                .file_path("allowed.conf")
                .commit("synthetic-commit")
                .build();
            let result = engine.scan_fragment(&fragment, &ScanOptions::default());
            assert!(result.is_complete());
            assert!(result.findings().is_empty());
        }
    }
    assert!(
        scan(
            isolated(),
            b"postgres://app:R7!q@db.invalid/ gitleaks:allow"
        )
        .is_empty()
    );
    let raw = "postgres://app:%52q7!@db.invalid/";
    let encoded = raw.bytes().fold(String::new(), |mut output, byte| {
        write!(output, "%{byte:02X}").unwrap();
        output
    });
    assert!(scan(isolated(), encoded.as_bytes()).is_empty());
    let result = isolated().scan_fragment(
        &Fragment::new(encoded.as_bytes()),
        &ScanOptions::builder().max_decode_depth(1).build(),
    );
    assert!(result.is_complete());
    assert_eq!(result.findings().len(), 1);
    assert_eq!(result.findings()[0].secret().as_bytes(), b"%52q7!");
    assert_eq!(
        result.findings()[0].secret_range(),
        FindingRange::Unavailable
    );
    assert_eq!(
        result.findings()[0].match_range(),
        FindingRange::Unavailable
    );
}

#[test]
fn database_uri_unbounded_host_lists_and_paths_obey_scan_controls() {
    let input = format!(
        "postgres://app:R7!q@[{}],db.invalid{}/{}",
        "a".repeat(8192),
        ",db.invalid:5432".repeat(1024),
        "p".repeat(32768)
    );
    let fragment = Fragment::new(input.as_bytes());
    let options = ScanOptions::default();
    let full = isolated().scan_fragment(&fragment, &options);
    assert!(full.is_complete());
    assert_eq!(full.findings().len(), 1);
    assert_eq!(full.findings()[0].match_range(), range(0, input.len()));
    for budget in [
        ScanBudget::unlimited().max_collected_spans(0),
        ScanBudget::unlimited().max_finding_payload_bytes(64),
        ScanBudget::unlimited().max_finding_records(0),
        ScanBudget::unlimited().max_work_units(0),
    ] {
        let result = isolated().scan_fragment_controlled(
            &fragment,
            &options,
            &ScanControl::unlimited().with_budget(budget),
        );
        assert!(!result.is_complete());
        assert!(result.findings().is_empty());
    }
    let cancellation = || true;
    let result = isolated().scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::cancellable(&cancellation),
    );
    assert!(!result.is_complete());
    assert!(result.findings().is_empty());
    let dense = "postgres://app:R7!q@db.invalid/ ".repeat(64);
    let result = isolated().scan_fragment_controlled(
        &Fragment::new(dense.as_bytes()),
        &options,
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_collected_spans(3)),
    );
    assert!(!result.is_complete());
    assert!(result.findings().is_empty());
    for negative in [
        format!("postgres://app:{}@db.invalid/", "7".repeat(32768)),
        format!("postgres://app:R7!q@{}/", "d".repeat(32768)),
        format!("postgres://app:R7!q@db.invalid/{}|", "p".repeat(32768)),
    ] {
        assert!(scan(isolated(), negative.as_bytes()).is_empty());
    }
}

#[test]
fn database_uri_independent_predicates_preserve_printf_case_and_exact_spans() {
    // Source global printf rejection lists b, d and s, but not B, D or S.
    // Earlier predicates' inline flags must not leak across regex-array entries.
    for secret in ["%B", "%D", "%S"] {
        let input = format!("mysql://app:{secret}@db.invalid");
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{secret}");
        let finding = &findings[0];
        assert_eq!(
            finding.rule_id().as_bytes(),
            b"rustleaks.connection-string.password.database-uri"
        );
        assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
        assert_eq!(finding.secret_range(), range(12, 14));
        assert_eq!(finding.match_range(), range(0, input.len()));
        assert_eq!(finding.match_text().as_bytes(), input.as_bytes());
        assert_eq!(
            finding.location(),
            Location::new(0, 0, 1, input.len()).unwrap()
        );
    }
    for secret in ["%b", "%d", "%s"] {
        let input = format!("mysql://app:{secret}@db.invalid");
        assert!(scan(isolated(), input.as_bytes()).is_empty(), "{secret}");
    }
}

#[test]
fn composed_database_uri_rule_retains_the_default_global_suppression_policy() {
    let native = NativePolicy::builder()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    // The pack's independent predicates preserve source case. Composition
    // additionally applies the pinned global array, whose legacy flag scope
    // makes its formatting-placeholder expression case-insensitive.
    for secret in ["%B", "%C", "%D", "%P", "%Q", "%S", "%u", "%V"] {
        let input = format!("mysql://app:{secret}@db.invalid");
        assert_eq!(scan(isolated(), input.as_bytes()).len(), 1, "{secret}");
        assert!(
            scan(native.engine(), input.as_bytes()).is_empty(),
            "{secret}"
        );
    }
    for secret in ["%Z", "%B0"] {
        let input = format!("mysql://app:{secret}@db.invalid");
        let findings = scan(native.engine(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{secret}");
        assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
        assert_eq!(findings[0].secret_range(), range(12, 12 + secret.len()));
        assert_eq!(findings[0].match_range(), range(0, input.len()));
    }
}

#[test]
fn database_uri_detector_and_rejection_predicates_keep_distinct_whitespace() {
    // Generated detector whitespace accepts VT. The source rejection runtime
    // uses Go whitespace without VT, including in full-match host predicates.
    for (username, secret, host) in [("user", "pass", "test.com"), ("app", "R7!q", "example.com")] {
        let left = format!("mysql://{username}:");
        let uri = format!("{left}{secret}@{host}");
        let input = format!("{uri}\u{b}");
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 1, "{input:?}");
        let finding = &findings[0];
        assert_eq!(
            finding.rule_id().as_bytes(),
            b"rustleaks.connection-string.password.database-uri"
        );
        assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
        assert_eq!(
            finding.secret_range(),
            range(left.len(), left.len() + secret.len())
        );
        assert_eq!(finding.match_range(), range(0, input.len()));
        assert_eq!(finding.match_text().as_bytes(), input.as_bytes());
        assert_eq!(
            finding.location(),
            Location::new(0, 0, 1, input.len()).unwrap()
        );
        assert!(scan(isolated(), format!("{uri} ").as_bytes()).is_empty());
    }
}
