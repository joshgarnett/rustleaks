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

#[allow(dead_code)] // `positives` serves the all-rules precedence test.
#[path = "support/connection_cases.rs"]
mod connection_cases;
use connection_cases::{
    DATABASE_URI_SCHEMES, DATABASE_URI_SECRETS, FIVE_FORMS, LIBPQ_FORMS, LIBPQ_SECRETS, PREFIX,
};

const FORMS: [(&str, &str, &str); 4] = [
    ("unquoted", "", ""),
    ("double-quoted", "\"", "\""),
    ("single-quoted", "'", "'"),
    ("odbc-braced", "{", "}"),
];

const HISTORICAL_CONNECTION_IDS: [&str; 9] = [
    "rustleaks.connection-string.password.double-quoted",
    "rustleaks.connection-string.password.single-quoted",
    "rustleaks.connection-string.password.odbc-braced",
    "rustleaks.connection-string.password.unquoted",
    "rustleaks.connection-string.password.jdbc-query",
    "rustleaks.connection-string.password.database-uri",
    "rustleaks.bitbucket-git-credentials",
    "rustleaks.codecatalyst-git-credentials",
    "rustleaks.codecommit-git-credentials",
];

fn historical_connection_toml() -> &'static str {
    static SOURCE: OnceLock<String> = OnceLock::new();
    SOURCE.get_or_init(|| {
        let mut value: toml::Value = toml::from_str(CONNECTION_RULES_V1).unwrap();
        value["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|rule| HISTORICAL_CONNECTION_IDS.contains(&rule["id"].as_str().unwrap()));
        assert_eq!(
            value["rules"].as_array().unwrap().len(),
            HISTORICAL_CONNECTION_IDS.len()
        );
        toml::to_string(&value).unwrap()
    })
}

fn isolated() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        Engine::builder(
            ConfigLoader::new()
                .load_toml(historical_connection_toml())
                .unwrap(),
        )
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
    for (suffix, left, secret, right, match_start) in FIVE_FORMS {
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
    // The first match consumes the shared semicolon. The next host key then
    // starts at an ASCII word boundary, so each connection gives a finding.
    for (suffix, open, close) in FORMS {
        let input = format!("Host=one;Pwd={open}R7!q{close};Host=two;Pwd={open}T8!w{close};");
        let open_len = open.len();
        let length = 18 + open_len + close.len();
        assert_eq!(input.len(), 2 * length);
        let findings = scan(isolated(), input.as_bytes());
        assert_eq!(findings.len(), 2, "{suffix}");
        for (finding, secret, offset) in [(&findings[0], "R7!q", 0), (&findings[1], "T8!w", length)]
        {
            assert_eq!(
                finding.rule_id().as_bytes(),
                format!("{PREFIX}{suffix}").as_bytes()
            );
            assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
            assert_eq!(
                finding.secret_range(),
                range(offset + 13 + open_len, offset + 17 + open_len)
            );
            assert_eq!(finding.match_range(), range(offset, offset + length));
        }
    }
    let repeated = "FIRST=Host=one;Pwd=R7!q; SECOND=Host=two;Pwd=R7!q;";
    assert_eq!(scan(isolated(), repeated.as_bytes()).len(), 2);
    let input = "jdbc:mysql://one/?password=R7!q jdbc:mysql://two/?password=T8!w";
    let findings = scan(isolated(), input.as_bytes());
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].secret().as_bytes(), b"R7!q");
    assert_eq!(findings[1].secret().as_bytes(), b"T8!w");
}

/// A half-open byte range as `(start, end)`.
type Span = (usize, usize);

/// Checks findings of one form as `(match, secret)` range pairs in order.
fn assert_form_ranges(suffix: &str, input: &str, expected: &[(Span, Span)]) {
    let findings = scan(isolated(), input.as_bytes());
    assert_eq!(
        findings.len(),
        expected.len(),
        "{suffix}, {}-byte input",
        input.len()
    );
    for (finding, ((match_start, match_end), (secret_start, secret_end))) in
        findings.iter().zip(expected)
    {
        assert_eq!(
            finding.rule_id().as_bytes(),
            format!("{PREFIX}{suffix}").as_bytes()
        );
        assert_eq!(finding.match_range(), range(*match_start, *match_end));
        assert_eq!(finding.secret_range(), range(*secret_start, *secret_end));
    }
}

fn assert_unquoted_ranges(input: &str, expected: &[(Span, Span)]) {
    assert_form_ranges("unquoted", input, expected);
}

#[test]
fn semicolon_host_keys_start_at_a_listed_byte_or_an_ascii_word_boundary() {
    // Three adjacent connections give three findings. Each later match starts
    // at the host key because the previous match consumed the semicolon.
    assert_unquoted_ranges(
        "Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;Host=six;Pwd=U9!e;",
        &[
            ((0, 18), (13, 17)),
            ((18, 36), (31, 35)),
            ((36, 54), (49, 53)),
        ],
    );
    // An intermediate segment does not change the boundary.
    assert_unquoted_ranges(
        "Host=one;Uid=a;Pwd=R7!q;Host=two;Uid=b;Pwd=T8!w;",
        &[((0, 24), (19, 23)), ((24, 48), (43, 47))],
    );
    // Unlisted ASCII punctuation and non-ASCII bytes before the key are not
    // consumed. The match starts at the key.
    assert_unquoted_ranges(".Host=d;Pwd=R7!q;", &[((1, 17), (12, 16))]);
    assert_unquoted_ranges("-Server=d;Pwd=R7!q;", &[((1, 19), (14, 18))]);
    assert_unquoted_ranges("éHost=d;Pwd=R7!q;", &[((2, 18), (13, 17))]);
    assert_unquoted_ranges("Proxy-Server=d;Pwd=R7!q;", &[((6, 24), (19, 23))]);
    assert_unquoted_ranges(".Data Source=d;Pwd=R7!q;", &[((1, 24), (19, 23))]);
    assert_form_ranges(
        "double-quoted",
        ".Host=d;Pwd=\"R7!q\";",
        &[((1, 19), (13, 17))],
    );
    // Control bytes outside tab through carriage return are not consumed.
    assert_unquoted_ranges("\x01Host=d;Pwd=R7!q;", &[((1, 17), (12, 16))]);
    // A letter, digit or underscore before the key still blocks the match.
    for input in [
        "xHost=d;Pwd=R7!q;",
        "_Host=d;Pwd=R7!q;",
        "9Host=d;Pwd=R7!q;",
    ] {
        assert_unquoted_ranges(input, &[]);
    }
    // The earliest key after unlisted punctuation starts the match.
    assert_unquoted_ranges(".Host=a;Server=b;Pwd=R7!q;", &[((1, 26), (21, 25))]);
    // A listed byte before the key is still consumed by the match.
    assert_unquoted_ranges("x=Host=d;Pwd=R7!q;", &[((1, 18), (13, 17))]);
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
            let mut raw: RawConfig = toml::from_str(historical_connection_toml()).unwrap();
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
    let mut raw: RawConfig = toml::from_str(historical_connection_toml()).unwrap();
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
    let input = ["Host=d;Password=", "Q7m2Z9v4L1c8R5s0N6b3X;"].concat();
    let input = input.as_bytes();
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
    for scheme in DATABASE_URI_SCHEMES {
        for secret in DATABASE_URI_SECRETS {
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
        let mut raw: RawConfig = toml::from_str(historical_connection_toml()).unwrap();
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
            let mut raw: RawConfig = toml::from_str(historical_connection_toml()).unwrap();
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

fn libpq_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let (config, _) = NativePolicy::builder()
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .compile()
            .unwrap();
        Engine::builder(
            config
                .select_rules([
                    "rustleaks.connection-string.password.libpq-quoted",
                    "rustleaks.connection-string.password.libpq-unquoted",
                ])
                .unwrap(),
        )
        .build()
        .unwrap()
    })
}

#[test]
fn libpq_passwords_preserve_literal_spelling_and_exact_ranges() {
    // Expected offsets follow the literal prefixes, not detector output.
    for (suffix, prefix, ending, offset) in LIBPQ_FORMS {
        for secret in LIBPQ_SECRETS {
            let matched = format!("{prefix}{secret}{ending}");
            let input = format!("{matched}dbname=application");
            let findings = scan(libpq_engine(), input.as_bytes());
            assert_eq!(findings.len(), 1);
            let finding = &findings[0];
            assert_eq!(
                finding.rule_id().as_bytes(),
                format!("{PREFIX}libpq-{suffix}").as_bytes()
            );
            assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
            assert_eq!(finding.match_text().as_bytes(), matched.as_bytes());
            assert_eq!(finding.secret_range(), range(offset, offset + secret.len()));
            assert_eq!(finding.match_range(), range(0, matched.len()));
            assert_eq!(
                finding.location(),
                Location::new(0, 0, 1, matched.len()).unwrap()
            );
        }
    }
    let input = "hostaddr = 192.0.2.1 password = 'Q7 v9 R2'";
    let findings = scan(libpq_engine(), input.as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret().as_bytes(), b"Q7 v9 R2");
    assert_eq!(findings[0].secret_range(), range(33, 41));
    assert_eq!(findings[0].match_range(), range(0, 42));
}

#[test]
fn libpq_rejects_incomplete_values_and_out_of_scope_context() {
    for input in [
        "host=db.invalid password=",
        "host=db.invalid password=''",
        "host=db.invalid user=bench",
        "password='Q7v9R2'",
        "host=db.invalid password:'Q7v9R2'",
        "host=db.invalid password='Q7v9R2",
        "host=db.invalid password='Q7v9R2'junk",
        "host=db.invalid password=Q7v9'R2",
        "host=db.invalid password=\"Q7v9R2\"",
        "host=db.invalid password=Q7v9R2\\",
        "host=db.invalid password='Q7v9R2\\'",
        "host=db.invalid\npassword='Q7v9R2'",
        "host=db.invalid password='Q7\nv9R2'",
        "host=db.invalid password='Q7雪v9R2'",
        "host=db.invalid Password='Q7v9R2'",
        "ghost=db.invalid password='Q7v9R2'",
        "xhost=db.invalid password='Q7v9R2'",
        "_host=db.invalid password='Q7v9R2'",
        "host=db.invalid unknown=word password='Q7v9R2'",
        "https://db.invalid/password/Q7v9R2",
        "The password for the host is Q7v9R2.",
    ] {
        assert!(scan(libpq_engine(), input.as_bytes()).is_empty());
    }
    for secret in ["${DB_PASSWORD}", "{{DB_PASSWORD}}", "changeme", "REDACTED"] {
        for (left, right) in [("'", "'"), ("", "")] {
            let input = format!("host=db.invalid password={left}{secret}{right}");
            assert!(scan(libpq_engine(), input.as_bytes()).is_empty());
        }
    }
}

#[test]
fn libpq_value_and_context_bounds_do_not_admit_prefixes() {
    for (left, right) in [("'", "'"), ("", "")] {
        for unit in ["Q", r"\Q"] {
            for count in [1, 128, 129] {
                // A final distinct byte avoids the inherited repeated-letter allowlist.
                let secret = format!("{}7", unit.repeat(count - 1));
                let input = format!("host=db.invalid password={left}{secret}{right}");
                let findings = scan(libpq_engine(), input.as_bytes());
                assert_eq!(findings.len(), usize::from(count <= 128));
                if let Some(finding) = findings.first() {
                    assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
                }
            }
        }
        for count in [7, 8] {
            let input = format!(
                "host=db.invalid{} password={left}Q7v9R2{right}",
                " user=bench".repeat(count)
            );
            assert_eq!(
                scan(libpq_engine(), input.as_bytes()).len(),
                usize::from(count == 7)
            );
        }
        for count in [128, 129] {
            let input = format!("host={} password={left}Q7v9R2{right}", "h".repeat(count));
            assert_eq!(
                scan(libpq_engine(), input.as_bytes()).len(),
                usize::from(count == 128)
            );
        }
    }
}

#[test]
fn libpq_occurrences_and_global_path_suppression_remain_distinct() {
    let input = b"\xff\nhost=db.invalid password='Q7v9R2'\nhost=db.invalid password=T8w0S3\n\xfe";
    let findings = scan(libpq_engine(), input);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].secret().as_bytes(), b"Q7v9R2");
    assert_eq!(findings[0].secret_range(), range(28, 34));
    assert_eq!(findings[1].secret().as_bytes(), b"T8w0S3");
    assert_eq!(findings[1].secret_range(), range(61, 67));
    let fragment = Fragment::builder(b"host=db.invalid password='Q7v9R2'".to_vec())
        .file_path("vendor/github.com/example/settings.conf")
        .build();
    assert!(
        libpq_engine()
            .scan_fragment(&fragment, &ScanOptions::default())
            .findings()
            .is_empty()
    );
}

#[test]
fn libpq_full_composition_has_explicit_attribution_and_negative_multisets() {
    let base = NativePolicy::builder().build().unwrap();
    let composed = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    let secret = ["Q7v9R2m8K4p6", "T1w3Z5s0N2h4"].concat();
    for (suffix, left, right, start) in [("quoted", "'", "'", 26), ("unquoted", "", "", 25)] {
        let input = format!("host=db.invalid password={left}{secret}{right}");
        let old = scan(base.engine(), input.as_bytes());
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].rule_id().as_bytes(), b"generic-api-key");
        assert_eq!(old[0].secret().as_bytes(), secret.as_bytes());
        let new = scan(composed.engine(), input.as_bytes());
        // Existing generic suppression prefers specific attribution for the
        // same secret; do not count that old alert as another occurrence.
        assert_eq!(new.len(), 1);
        assert_eq!(
            new[0].rule_id().as_bytes(),
            format!("{PREFIX}libpq-{suffix}").as_bytes()
        );
        assert_eq!(new[0].secret().as_bytes(), secret.as_bytes());
        assert_eq!(new[0].secret_range(), range(start, start + 24));
    }
    // Invalid libpq syntax remains eligible for a generic assignment rule.
    let malformed = format!("host=db.invalid password:'{secret}'");
    let findings = scan(composed.engine(), malformed.as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id().as_bytes(), b"generic-api-key");
    assert_eq!(findings[0].secret().as_bytes(), secret.as_bytes());
    for input in [
        "host=db.invalid password='${DB_PASSWORD}'",
        "host=db.invalid password=changeme",
        "host=db.invalid password=''",
        "https://db.invalid/password/Q7v9R2",
    ] {
        assert!(scan(composed.engine(), input.as_bytes()).is_empty());
    }
}

#[test]
fn libpq_adjacent_occurrences_keep_zero_width_ascii_boundaries() {
    for (left, right) in [("'", "'"), ("", "")] {
        let first = format!("host=db.invalid password={left}Q7v9R2{right}");
        let second = format!("host=db.invalid password={left}T8w0S3{right}");
        for between in [" ", "  ", "\t"] {
            let input = format!("{first}{between}{second}");
            let findings = scan(libpq_engine(), input.as_bytes());
            assert_eq!(findings.len(), 2);
            assert_eq!(findings[0].secret().as_bytes(), b"Q7v9R2");
            assert_eq!(findings[1].secret().as_bytes(), b"T8w0S3");
            assert_eq!(
                findings[1].match_range(),
                range(first.len() + between.len(), input.len())
            );
        }
    }
    // Go regex word boundaries are ASCII. Surrounding punctuation and UTF-8
    // are outside the match and do not become part of source coordinates.
    for prefix in ["(", ":", "é", " "] {
        let input = format!("{prefix}host=db.invalid password='Q7v9R2'");
        let findings = scan(libpq_engine(), input.as_bytes());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_range(), range(prefix.len(), input.len()));
        assert_eq!(
            findings[0].secret_range(),
            range(prefix.len() + 26, prefix.len() + 32)
        );
    }
}

#[test]
fn libpq_explicit_allowlists_keep_targets_and_fragment_context() {
    for condition in [
        "regexTarget = 'secret'\nregexes = ['Q7v9R2']",
        "stopwords = ['7v9']",
        "paths = ['^allowed[.]conf$']",
        "commits = ['synthetic-commit']",
    ] {
        let mut source: toml::Value = toml::from_str(CONNECTION_RULES_V1).unwrap();
        source["rules"].as_array_mut().unwrap().retain(|rule| {
            rule["id"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{PREFIX}libpq-"))
        });
        let mut raw: RawConfig = toml::from_str(&toml::to_string(&source).unwrap()).unwrap();
        let targeted: RawConfig = toml::from_str(&format!(
            "[[allowlists]]\ntargetRules = ['{PREFIX}libpq-quoted']\n{condition}\n"
        ))
        .unwrap();
        raw.allowlists = targeted.allowlists;
        let engine = Engine::builder(ConfigLoader::new().compile(raw).unwrap())
            .build()
            .unwrap();
        let fragment = Fragment::builder(
            b"host=db.invalid password='Q7v9R2'\nhost=db.invalid password=T8w0S3".to_vec(),
        )
        .file_path("allowed.conf")
        .commit("synthetic-commit")
        .build();
        let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
        assert!(outcome.is_complete());
        assert_eq!(outcome.findings().len(), 1);
        assert_eq!(outcome.findings()[0].secret().as_bytes(), b"T8w0S3");
    }
    assert!(scan(libpq_engine(), b"host=db.invalid password='Q7\xffv9R2'").is_empty());
}

fn default_rules() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| NativePolicy::builder().build().unwrap().engine().clone())
}

fn all_rules() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        NativePolicy::builder()
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .build()
            .unwrap()
            .engine()
            .clone()
    })
}

/// One expected finding: rule ID, secret and exact secret range, or `None`
/// for a decoded finding, which has no exact range in the original fragment.
type Outcome = (String, String, Option<(usize, usize)>);

fn outcomes(engine: &Engine, input: &str, options: &ScanOptions) -> Vec<Outcome> {
    let outcome = engine.scan_fragment(&Fragment::new(input.as_bytes()), options);
    assert!(outcome.is_complete(), "scan did not complete");
    let mut found = outcome
        .findings()
        .iter()
        .map(|finding| {
            let exact = finding.secret_range().exact();
            if exact.is_none() {
                // Decoded findings carry neither exact range and name the
                // single percent layer that produced them.
                assert_eq!(finding.match_range(), FindingRange::Unavailable);
                let tags = finding
                    .tags()
                    .iter()
                    .map(|tag| tag.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                assert!(
                    tags.iter().any(|tag| tag == "decoded:percent"),
                    "decoded finding lacks the decoded:percent tag"
                );
                assert!(
                    tags.iter().any(|tag| tag == "decode-depth:1"),
                    "decoded finding lacks the decode-depth:1 tag"
                );
            }
            (
                finding.rule_id().to_string_lossy().into_owned(),
                finding.secret().to_string_lossy().into_owned(),
                exact.map(|range| (range.start(), range.end())),
            )
        })
        .collect::<Vec<_>>();
    found.sort();
    found
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Form {
    Uri,
    Jdbc,
    Odbc,
    Libpq,
}

impl Form {
    const ALL: [Self; 4] = [Self::Uri, Self::Jdbc, Self::Odbc, Self::Libpq];

    const fn parts(self) -> (&'static str, &'static str) {
        match self {
            Self::Uri => ("postgresql://bench:", "@db.invalid:5432/application"),
            Self::Jdbc => (
                "jdbc:postgresql://db.invalid/application?user=bench&password=",
                "&sslmode=require",
            ),
            Self::Odbc => (
                "Driver={Synthetic};Server=db.invalid;UID=bench;PWD=",
                ";Database=application;",
            ),
            Self::Libpq => (
                "host=db.invalid user=bench password='",
                "' dbname=application",
            ),
        }
    }

    const fn omitted(self) -> &'static str {
        match self {
            Self::Uri => "postgresql://bench@db.invalid/application",
            Self::Jdbc => "jdbc:postgresql://db.invalid/application?user=bench",
            Self::Odbc => "Driver={Synthetic};Server=db.invalid;UID=bench;",
            Self::Libpq => "host=db.invalid user=bench dbname=application",
        }
    }

    const fn malformed(self) -> (&'static str, &'static str) {
        match self {
            Self::Uri => ("postgresql://bench;", "@db.invalid/application"),
            Self::Jdbc => (
                "jdbc:postgresql://db.invalid/application?user=bench&password:",
                "",
            ),
            Self::Odbc => ("Server=db.invalid;UID=bench;PWD:", ";"),
            Self::Libpq => ("host=db.invalid user=bench password:'", "'"),
        }
    }

    // The specific rule that owns a well-formed password slot.
    const fn rule(self) -> &'static str {
        match self {
            Self::Uri => "database-uri",
            Self::Jdbc => "jdbc-query",
            Self::Odbc => "unquoted",
            Self::Libpq => "libpq-quoted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Literal,
    Percent,
    Empty,
    Env,
    Template,
    Omitted,
    PublicUrl,
    Prose,
    Malformed,
}

impl Shape {
    const ALL: [Self; 9] = [
        Self::Literal,
        Self::Percent,
        Self::Empty,
        Self::Env,
        Self::Template,
        Self::Omitted,
        Self::PublicUrl,
        Self::Prose,
        Self::Malformed,
    ];

    /// Writes this shape of password into a connection form. Returns the
    /// input line and the byte where a secret in it starts.
    fn input(self, form: Form, password: &str, escaped: &str) -> (String, usize) {
        let (prefix, suffix) = form.parts();
        // A secret starts after the prefix written before it.
        let mut start = prefix.len();
        let input = match self {
            Self::Literal => format!("{prefix}{password}{suffix}\n"),
            Self::Percent => format!("{prefix}{escaped}{suffix}\n"),
            Self::Empty => format!("{prefix}{suffix}\n"),
            Self::Env => format!("{prefix}${{PASSWORD}}{suffix}\n"),
            Self::Template => format!("{prefix}{{{{PASSWORD}}}}{suffix}\n"),
            Self::Omitted => format!("{}\n", form.omitted()),
            Self::PublicUrl => "https://public.invalid/documentation?language=en\n".to_owned(),
            Self::Prose => {
                "The database password is supplied by the application at startup.\n".to_owned()
            }
            Self::Malformed => {
                let (left, right) = form.malformed();
                start = left.len();
                format!("{left}{password}{right}\n")
            }
        };
        (input, start)
    }
}

struct Expected {
    all_depth_0: Vec<Outcome>,
    all_depth_5_adds: Vec<Outcome>,
    default_depth_0: Vec<Outcome>,
    default_depth_5_adds: Vec<Outcome>,
}

fn exact(rule: &str, secret: &str, start: usize) -> Outcome {
    (
        rule.to_owned(),
        secret.to_owned(),
        Some((start, start + secret.len())),
    )
}

/// The outcomes expected for one form and shape of the connection matrix.
fn expected_outcomes(
    form: Form,
    shape: Shape,
    password: &str,
    escaped: &str,
    start: usize,
) -> Expected {
    let connection = |form: Form| format!("{PREFIX}{}", form.rule());
    let decoded = |rule: &str| -> Outcome { (rule.to_owned(), password.to_owned(), None) };
    let none = Vec::new;
    match (form, shape) {
        // Percent escapes are literal text to every connection rule;
        // a decode pass then finds the same rule in the decoded line.
        (_, Shape::Literal) if form != Form::Libpq => Expected {
            all_depth_0: vec![exact(&connection(form), password, start)],
            all_depth_5_adds: none(),
            default_depth_0: none(),
            default_depth_5_adds: none(),
        },
        (_, Shape::Percent) if form != Form::Libpq => Expected {
            all_depth_0: vec![exact(&connection(form), escaped, start)],
            all_depth_5_adds: vec![decoded(&connection(form))],
            default_depth_0: none(),
            default_depth_5_adds: none(),
        },
        // The quoted libpq value is also a generic assignment. With the
        // connection pack the specific rule owns that secret.
        (Form::Libpq, Shape::Literal) => Expected {
            all_depth_0: vec![exact(&connection(form), password, start)],
            all_depth_5_adds: none(),
            default_depth_0: vec![exact("generic-api-key", password, start)],
            default_depth_5_adds: none(),
        },
        // Generic entropy rejects the escaped spelling; the decoded
        // line restores the literal password for generic-api-key.
        (Form::Libpq, Shape::Percent) => Expected {
            all_depth_0: vec![exact(&connection(form), escaped, start)],
            all_depth_5_adds: vec![decoded(&connection(form))],
            default_depth_0: none(),
            default_depth_5_adds: vec![decoded("generic-api-key")],
        },
        // No connection rule accepts ':' for '='; generic-api-key
        // does, and only JDBC and libpq have a generic keyword.
        (Form::Jdbc | Form::Libpq, Shape::Malformed) => Expected {
            all_depth_0: vec![exact("generic-api-key", password, start)],
            all_depth_5_adds: none(),
            default_depth_0: vec![exact("generic-api-key", password, start)],
            default_depth_5_adds: none(),
        },
        _ => Expected {
            all_depth_0: none(),
            all_depth_5_adds: none(),
            default_depth_0: none(),
            default_depth_5_adds: none(),
        },
    }
}

#[test]
fn connection_matrix_has_independent_outcomes_under_all_and_default_rules() {
    // A 24-byte synthetic password with mixed classes and no stopword.
    let password = ["Q7v9R2m8", "K4p6T1w3", "Z5s0N2h4"].concat();
    // Its first byte 'Q' (0x51) spelled as one percent escape: 26 bytes.
    let escaped = format!("%51{}", &password[1..]);
    let depth_5 = ScanOptions::builder().max_decode_depth(5).build();
    let depth_0 = ScanOptions::default();
    let mut cases = 0;
    let (mut all_total_0, mut all_total_5) = (0, 0);
    let (mut default_total_0, mut default_total_5) = (0, 0);
    for form in Form::ALL {
        for shape in Shape::ALL {
            let (input, start) = shape.input(form, &password, &escaped);
            let expected = expected_outcomes(form, shape, &password, &escaped, start);
            let with = |base: &[Outcome], adds: &[Outcome]| {
                let mut all = base.to_vec();
                all.extend_from_slice(adds);
                all.sort();
                all
            };
            let label = format!("{form:?} {shape:?}");
            let mut sorted = expected.all_depth_0.clone();
            sorted.sort();
            assert_eq!(
                outcomes(all_rules(), &input, &depth_0),
                sorted,
                "all rules, depth 0: {label}"
            );
            assert_eq!(
                outcomes(all_rules(), &input, &depth_5),
                with(&expected.all_depth_0, &expected.all_depth_5_adds),
                "all rules, depth 5: {label}"
            );
            let mut sorted = expected.default_depth_0.clone();
            sorted.sort();
            assert_eq!(
                outcomes(default_rules(), &input, &depth_0),
                sorted,
                "default rules, depth 0: {label}"
            );
            let default_5 = outcomes(default_rules(), &input, &depth_5);
            assert_eq!(
                default_5,
                with(&expected.default_depth_0, &expected.default_depth_5_adds),
                "default rules, depth 5: {label}"
            );
            cases += 1;
            all_total_0 += expected.all_depth_0.len();
            all_total_5 += expected.all_depth_0.len() + expected.all_depth_5_adds.len();
            default_total_0 += expected.default_depth_0.len();
            default_total_5 += expected.default_depth_0.len() + expected.default_depth_5_adds.len();
            // The connection pack is opt-in: default rules never report it.
            assert!(
                default_5
                    .iter()
                    .all(|(rule, _, _)| !rule.starts_with(PREFIX))
            );
        }
    }
    assert_eq!(cases, 36);
    assert_eq!((all_total_0, all_total_5), (10, 14));
    assert_eq!((default_total_0, default_total_5), (3, 4));
}

#[test]
fn global_allowlist_suppresses_slack_token_containing_false() {
    // The packaged global allowlist regex `(?i)^true|false|null$` anchors
    // only `true` at the start and only `null` at the end, so any secret that
    // contains `false` is suppressed. That is the pinned upstream behavior and
    // is intended here; this test records it and must not weaken it.
    let token = [
        "xoxb-",
        "284719365012",
        "-",
        "7391846205738",
        "-Q7m2",
        "false",
        "R5s0N6b3X",
    ]
    .concat();
    let control = token.replace("false", "fa1se");
    assert_eq!(token.len(), 50);
    let isolated = Engine::builder(
        ConfigLoader::new()
            .load_toml(
                "[[rules]]\nid = 'slack-bot-token'\n\
                 regex = '''xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'''\n\
                 entropy = 3\nkeywords = ['xoxb']\n",
            )
            .unwrap(),
    )
    .build()
    .unwrap();
    let options = ScanOptions::default();
    for (engine, suppressed) in [
        (default_rules(), true),
        (all_rules(), true),
        (&isolated, false),
    ] {
        for (secret, expected) in [(&token, !suppressed), (&control, true)] {
            let found = outcomes(engine, &format!("{secret}\n"), &options);
            let want = if expected {
                vec![(
                    "slack-bot-token".to_owned(),
                    secret.clone(),
                    Some((0, secret.len())),
                )]
            } else {
                Vec::new()
            };
            assert_eq!(
                found,
                want,
                "{} suppressed={suppressed}",
                if *secret == token { "token" } else { "control" }
            );
        }
    }
}

// Rules for password-first semicolon forms, Oracle and SQLite JDBC URLs and
// more URI schemes. Expected ranges follow the literal parts of each input.

const NEW_CONNECTION_IDS: [&str; 5] = [
    PASSWORD_FIRST,
    JDBC_ORACLE,
    JDBC_QUERY_ORACLE_SQLITE,
    OTHER_DATABASE_URI,
    OTHER_SERVICE_URI,
];
const PASSWORD_FIRST: &str = "rustleaks.connection-string.password.password-first";
const JDBC_ORACLE: &str = "rustleaks.connection-string.password.jdbc-oracle";
const JDBC_QUERY_ORACLE_SQLITE: &str =
    "rustleaks.connection-string.password.jdbc-query-oracle-sqlite";
const OTHER_DATABASE_URI: &str = "rustleaks.connection-string.password.other-database-uri";
const OTHER_SERVICE_URI: &str = "rustleaks.other-service-uri-password";

/// Only the added rules, with the default global allowlists.
fn new_rules_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let (config, _) = NativePolicy::builder()
            .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
            .unwrap()
            .compile()
            .unwrap();
        Engine::builder(config.select_rules(NEW_CONNECTION_IDS).unwrap())
            .build()
            .unwrap()
    })
}

/// All three packs, with a connection pack that lacks the added rules.
fn all_rules_without_new_rules() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut value: toml::Value = toml::from_str(CONNECTION_RULES_V1).unwrap();
        let rules = value["rules"].as_array_mut().unwrap();
        let count = rules.len();
        rules.retain(|rule| !NEW_CONNECTION_IDS.contains(&rule["id"].as_str().unwrap()));
        assert_eq!(rules.len() + NEW_CONNECTION_IDS.len(), count);
        let connections = toml::to_string(&value).unwrap();
        NativePolicy::builder()
            .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
            .unwrap()
            .with_pack("rustleaks-connections-v1", &connections)
            .unwrap()
            .build()
            .unwrap()
            .engine()
            .clone()
    })
}

/// One input written as `{lead}{before}{secret}{after}`. The match starts
/// after `lead` and ends after the first `matched_after` bytes of `after`.
struct Case<'a> {
    lead: &'a str,
    before: &'a str,
    secret: &'a str,
    after: &'a str,
    matched_after: &'a str,
}

impl<'a> Case<'a> {
    /// A case whose match is the whole input.
    const fn whole(before: &'a str, secret: &'a str, after: &'a str) -> Self {
        Self {
            lead: "",
            before,
            secret,
            after,
            matched_after: after,
        }
    }

    fn input(&self) -> String {
        format!("{}{}{}{}", self.lead, self.before, self.secret, self.after)
    }

    /// Checks that the engine gives exactly this one finding from `rule`.
    fn assert_one(&self, engine: &Engine, rule: &str) {
        assert!(self.after.starts_with(self.matched_after));
        let input = self.input();
        let findings = scan(engine, input.as_bytes());
        assert_eq!(findings.len(), 1, "{input:?}");
        let finding = &findings[0];
        let secret_start = self.lead.len() + self.before.len();
        let match_end = secret_start + self.secret.len() + self.matched_after.len();
        assert_eq!(finding.rule_id().as_bytes(), rule.as_bytes(), "{input:?}");
        assert_eq!(
            finding.secret().as_bytes(),
            self.secret.as_bytes(),
            "{input:?}"
        );
        assert_eq!(
            finding.secret_range(),
            range(secret_start, secret_start + self.secret.len()),
            "{input:?}"
        );
        assert_eq!(
            finding.match_range(),
            range(self.lead.len(), match_end),
            "{input:?}"
        );
    }
}

fn assert_no_new_finding(input: &str) {
    assert!(
        scan(new_rules_engine(), input.as_bytes()).is_empty(),
        "{input:?}"
    );
}

fn scan_path(engine: &Engine, input: &str, path: &str) -> Vec<Finding> {
    let fragment = Fragment::builder(input.as_bytes().to_vec())
        .file_path(path)
        .build();
    let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
    assert!(outcome.is_complete());
    outcome.findings().to_vec()
}

#[test]
fn issue_lines_each_give_one_connection_finding_under_all_rules() {
    for (rule, case) in [
        (
            PASSWORD_FIRST,
            Case::whole("Pwd=", "Winter2026", ";Server=db.corp.internal;"),
        ),
        (
            PASSWORD_FIRST,
            Case::whole("Password=", "Winter2026", ";Data Source=db.corp.internal;"),
        ),
        (
            JDBC_ORACLE,
            Case::whole(
                "jdbc:oracle:thin:app/",
                "Q7vx9Lm2Rk4p",
                "@db.corp.internal:1521/sales",
            ),
        ),
        (
            JDBC_QUERY_ORACLE_SQLITE,
            Case::whole(
                "jdbc:oracle:thin:@db.corp.internal:1521/sales?user=app&password=",
                "Winter2026",
                "",
            ),
        ),
        (
            JDBC_QUERY_ORACLE_SQLITE,
            Case::whole("jdbc:sqlite:file.db?password=", "Winter2026", ""),
        ),
        (
            OTHER_DATABASE_URI,
            Case::whole(
                "mssql://app:",
                "Q7vx9Lm2Rk4p",
                "@db.corp.internal:1433/sales",
            ),
        ),
        (
            OTHER_DATABASE_URI,
            Case::whole(
                "sqlserver://app:",
                "Q7vx9Lm2Rk4p",
                "@db.corp.internal:1433/sales",
            ),
        ),
        (
            OTHER_DATABASE_URI,
            Case::whole(
                "oracle://app:",
                "Q7vx9Lm2Rk4p",
                "@db.corp.internal:1521/sales",
            ),
        ),
        (
            OTHER_DATABASE_URI,
            Case::whole(
                "clickhouse://app:",
                "Q7vx9Lm2Rk4p",
                "@db.corp.internal:9000/sales",
            ),
        ),
        (
            OTHER_SERVICE_URI,
            Case::whole("nats://app:", "Q7vx9Lm2Rk4p", "@bus.corp.internal:4222"),
        ),
    ] {
        case.assert_one(all_rules(), rule);
        // No connection rule found these lines before the added rules.
        let input = case.input();
        assert!(
            scan(all_rules_without_new_rules(), input.as_bytes())
                .iter()
                .all(|finding| !finding.rule_id().as_bytes().starts_with(b"rustleaks.conn")),
            "{input:?}"
        );
    }
    // HTTPS credential URLs stay outside the pack.
    assert!(
        scan(
            all_rules(),
            b"https://app:Q7vx9Lm2Rk4p@files.corp.internal/data"
        )
        .is_empty()
    );
}

#[test]
fn password_first_forms_keep_exact_secret_and_match_ranges() {
    for case in [
        Case::whole("Pwd=", "Winter2026", ";Server=db.corp.internal;"),
        Case::whole("PASSWORD = ", "Winter2026", " ; HOST = db.corp.internal ;"),
        Case::whole(
            "pWd=\"",
            "Win;ter 2026",
            "\";Uid=app;Database=sales;Host=db.corp.internal;",
        ),
        Case::whole(
            "Password='",
            "Win\"ter2026",
            "';Data \t Source=db.corp.internal;",
        ),
        Case::whole("Pwd={", "Win;ter}}2026", "};DSN=sales;"),
        Case::whole("Pwd=", "%57inter2026", ";Server=db.corp.internal"),
        // A quote after the host is consumed.
        Case::whole("Password=", "Winter2026", ";Server=db.corp.internal\""),
        // A line feed after the host is consumed and then trimmed.
        Case {
            lead: "",
            before: "Pwd=",
            secret: "Winter2026",
            after: ";Server=db.corp.internal\nnext",
            matched_after: ";Server=db.corp.internal",
        },
        // A listed byte before the key is consumed.
        Case {
            lead: "connectionString=",
            before: "\"Password=",
            secret: "Winter2026",
            after: ";Server=db.corp.internal\"",
            matched_after: ";Server=db.corp.internal\"",
        },
        Case {
            lead: "Driver={ODBC}",
            before: ";Pwd=",
            secret: "Winter2026",
            after: ";Server=db.corp.internal;Database=sales;",
            matched_after: ";Server=db.corp.internal;",
        },
    ] {
        case.assert_one(new_rules_engine(), PASSWORD_FIRST);
    }
    // Native locations keep the preceding-LF byte-column origin.
    let input = "p\nx=Pwd=Winter2026;Server=db.corp.internal;";
    let findings = scan(new_rules_engine(), input.as_bytes());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret_range(), range(8, 18));
    assert_eq!(findings[0].match_range(), range(3, input.len()));
    assert_eq!(
        findings[0].location(),
        Location::new(1, 1, 3, input.len() - 1).unwrap()
    );
}

#[test]
fn password_first_rejects_placeholders_missing_hosts_and_out_of_bound_values() {
    for password in [
        "${DB_PASSWORD}",
        "$DB_PASSWORD",
        "%DB_PASSWORD%",
        "<password>",
        "[DB_PASSWORD]",
        "your_password",
        "changeme",
        "REDACTED",
        "****",
        "xxxxxxxx",
        "process.env.DB",
        "config.db",
    ] {
        assert_no_new_finding(&format!("Pwd={password};Server=db.corp.internal;"));
        assert_no_new_finding(&format!("Pwd=\"{password}\";Server=db.corp.internal;"));
    }
    for input in [
        "Pwd=Winter2026;",
        "Pwd=Winter2026",
        "Pwd=Winter2026;Database=sales;",
        "Pwd=Winter2026;Server=;",
        "Pwd=Winter2026;Server=\"db.corp.internal\";",
        "Pwd=Winter2026;\nServer=db.corp.internal;",
        "Pwd=Winter2026;ProxyServer=db.corp.internal;",
        "Pwd=;Server=db.corp.internal;",
        "Pwd=\"\";Server=db.corp.internal;",
        "Pwd=Win;Server=db.corp.internal;",
        "Pwd:Winter2026;Server=db.corp.internal;",
        "DbPwd=Winter2026;Server=db.corp.internal;",
        "Pwd=Winter2026 Server=db.corp.internal;",
        "Pwd=\"Winter2026;Server=db.corp.internal;",
    ] {
        assert_no_new_finding(input);
    }
    for (length, accepted) in [(4, true), (128, true), (3, false), (129, false)] {
        // A final distinct byte avoids the inherited repeated-letter allowlist.
        let password = format!("{}7", "Q".repeat(length - 1));
        let input = format!("Pwd={password};Server=db.corp.internal;");
        assert_eq!(
            scan(new_rules_engine(), input.as_bytes()).len(),
            usize::from(accepted),
            "{length}"
        );
    }
    for (host, accepted) in [(128, true), (129, false)] {
        let input = format!("Pwd=Winter2026;Server={};", "d".repeat(host));
        assert_eq!(
            scan(new_rules_engine(), input.as_bytes()).len(),
            usize::from(accepted),
            "{host}"
        );
    }
    for (middle, accepted) in [(200, true), (201, false)] {
        let input = format!(
            "Pwd=Winter2026;A={};Server=db.corp.internal;",
            "x".repeat(middle - 2)
        );
        assert_eq!(
            scan(new_rules_engine(), input.as_bytes()).len(),
            usize::from(accepted),
            "{middle}"
        );
    }
}

#[test]
fn password_first_leaves_host_first_passwords_to_the_host_first_rules() {
    for (input, expected) in [
        // A password between two host properties gives only the host-first
        // finding.
        (
            "Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;",
            vec![("unquoted", "R7!q", 13), ("unquoted", "T8!w", 31)],
        ),
        (
            "Server=a;Pwd=Winter2026;Host=b;",
            vec![("unquoted", "Winter2026", 13)],
        ),
        (
            "Server=a;Pwd=\"Winter2026\";Host=b;",
            vec![("double-quoted", "Winter2026", 14)],
        ),
        (
            "Server=a;Pwd={Winter2026};Host=b;",
            vec![("odbc-braced", "Winter2026", 14)],
        ),
        (
            "jdbc:sqlserver://h;password=Winter2026;Server=y;",
            vec![("unquoted", "Winter2026", 28)],
        ),
        // A host-first connection with no later host property does not hide
        // a password-first connection before it.
        (
            "Pwd=Winter2026;Server=db.corp.internal;Pwd=Summer2027;",
            vec![
                ("password-first", "Winter2026", 4),
                ("unquoted", "Summer2027", 43),
            ],
        ),
        // Quotes end a connection, so two JSON values are separate.
        (
            "{\"A\":\"Server=a;Pwd=Autumn2025;\",\"B\":\"Pwd=Winter2026;Server=b;\"}",
            vec![
                ("unquoted", "Autumn2025", 19),
                ("password-first", "Winter2026", 41),
            ],
        ),
        // The exclusion reads only the line of the match.
        (
            "Host=one;Pwd=R7!q;Host=two;\nPwd=T8!w;Server=three;",
            vec![("unquoted", "R7!q", 13), ("password-first", "T8!w", 32)],
        ),
        (
            "Pwd=T8!w;Server=three\nHost=one;Pwd=R7!q;Host=two;",
            vec![("password-first", "T8!w", 4), ("unquoted", "R7!q", 35)],
        ),
    ] {
        let mut expected = expected
            .into_iter()
            .map(|(suffix, secret, start)| exact(&format!("{PREFIX}{suffix}"), secret, start))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            outcomes(all_rules(), input, &ScanOptions::default()),
            expected,
            "{input:?}"
        );
    }
}

#[test]
fn new_rules_take_over_generic_findings_for_the_same_password() {
    let secret = "Q7m2Z9v4L1c8R5s0N6b3X";
    for (rule, before, after) in [
        (PASSWORD_FIRST, "Password=", ";Server=db.corp.internal;"),
        (
            JDBC_QUERY_ORACLE_SQLITE,
            "jdbc:oracle:thin:@db.corp.internal:1521/sales?user=app&password=",
            "",
        ),
        (
            JDBC_QUERY_ORACLE_SQLITE,
            "jdbc:sqlite:file.db?password=",
            "",
        ),
    ] {
        let input = format!("{before}{secret}{after}");
        assert!(
            outcomes(default_rules(), &input, &ScanOptions::default()).contains(&exact(
                "generic-api-key",
                secret,
                before.len()
            )),
            "{input:?}"
        );
        assert_eq!(
            outcomes(all_rules(), &input, &ScanOptions::default()),
            vec![exact(rule, secret, before.len())],
            "{input:?}"
        );
    }
}

#[test]
fn jdbc_oracle_user_password_forms_keep_exact_ranges() {
    for case in [
        Case::whole(
            "jdbc:oracle:thin:app/",
            "Winter2026",
            "@db.corp.internal:1521/sales",
        ),
        Case::whole("JDBC:ORACLE:OCI:app/", "Winter2026", "@sales_tns"),
        Case::whole(
            "jdbc:oracle:thin:c##app/",
            "W!n%74er:2026",
            "@//db.corp.internal:1521/sales.corp",
        ),
        Case::whole(
            "jdbc:oracle:thin:app/",
            "Winter2026",
            "@db.corp.internal:1521:orcl",
        ),
        Case::whole(
            "jdbc:oracle:thin:app/",
            "Winter2026",
            "@[2001:db8::1]:1521/sales",
        ),
        Case::whole("jdbc:oracle:thin:app/", "7", "@db.corp.internal"),
        // A descriptor ends the match after its first key.
        Case {
            lead: "",
            before: "jdbc:oracle:thin:app/",
            secret: "Winter2026",
            after: "@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.corp.internal)))",
            matched_after: "@(DESCRIPTION=",
        },
        // A closing quote is consumed; the text after it is not.
        Case {
            lead: "url=\"",
            before: "jdbc:oracle:thin:app/",
            secret: "Winter2026",
            after: "@db.corp.internal\" next",
            matched_after: "@db.corp.internal\"",
        },
    ] {
        case.assert_one(new_rules_engine(), JDBC_ORACLE);
    }
}

#[test]
fn jdbc_oracle_rejects_examples_placeholders_and_missing_parts() {
    for input in [
        "jdbc:oracle:thin:scott/tiger@db.corp.internal:1521:orcl",
        "jdbc:oracle:thin:user/password@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:test1/test1@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/Winter2026@db.example.com:1521/sales",
        "jdbc:oracle:thin:app/Winter2026@example:1521/sales",
        "jdbc:oracle:thin:app/Winter2026@//example.org/sales",
        "jdbc:oracle:thin:app/${DB_PASSWORD}@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/{{db_password}}@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/<password>@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/$DB_PASSWORD@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/%DB_PASSWORD%@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/****@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/changeme@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/your_password@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/aaaa@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:/Winter2026@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app/Winter2026@",
        "jdbc:oracle:thin:app/Winter2026@ db.corp.internal",
        "jdbc:oracle:thin:app/Winter2026@-db.corp.internal",
        "jdbc:oracle:thin:@db.corp.internal:1521/sales",
        "jdbc:oracle:thin:app@db.corp.internal:1521/sales",
        "xjdbc:oracle:thin:app/Winter2026@db.corp.internal:1521/sales",
        "jdbc:oracle:kprb:app/Winter2026@db.corp.internal:1521/sales",
    ] {
        assert_no_new_finding(input);
    }
}

#[test]
fn jdbc_oracle_and_sqlite_query_passwords_keep_exact_ranges() {
    for case in [
        Case {
            lead: "",
            before: "jdbc:oracle:thin:@db.corp.internal:1521/sales?user=app&password=",
            secret: "Winter2026",
            after: "&ssl=true",
            matched_after: "&",
        },
        Case::whole(
            "jdbc:oracle:thin:@//db.corp.internal:1521/sales?password=",
            "Winter2026",
            "",
        ),
        Case::whole(
            "JDBC:ORACLE:OCI:@sales_tns?user=app&amp;password=",
            "Winter2026",
            "",
        ),
        Case::whole("jdbc:sqlite:file.db?password=", "W!n%74er:2026", ""),
        Case {
            lead: "",
            before: "jdbc:sqlite:/var/data/app.db?cipher=sqlcipher&password=",
            secret: "Winter2026",
            after: "&legacy=4",
            matched_after: "&",
        },
        Case::whole("jdbc:sqlite:C:\\data\\app.db?password=", "Winter2026", ""),
        Case {
            lead: "",
            before: "jdbc:sqlite::memory:?password=",
            secret: "Winter2026",
            after: " next",
            matched_after: " ",
        },
    ] {
        case.assert_one(new_rules_engine(), JDBC_QUERY_ORACLE_SQLITE);
    }
    // A user/password@ authority and a password option are two passwords.
    let before = "jdbc:oracle:thin:app/";
    let middle = "@db.corp.internal:1521/sales?password=";
    let input = format!("{before}Summer2027{middle}Winter2026");
    let mut expected = vec![
        exact(JDBC_ORACLE, "Summer2027", before.len()),
        exact(
            JDBC_QUERY_ORACLE_SQLITE,
            "Winter2026",
            before.len() + 10 + middle.len(),
        ),
    ];
    expected.sort();
    assert_eq!(
        outcomes(new_rules_engine(), &input, &ScanOptions::default()),
        expected
    );
}

#[test]
fn jdbc_oracle_and_sqlite_query_rejects_placeholders_and_missing_parts() {
    for value in [
        "",
        "Win",
        "$DB_PASSWORD",
        "%DB_PASSWORD%",
        "${DB_PASSWORD}",
        "<password>",
        "****",
        "changeme",
        "your_password",
        "REDACTED",
        "config.db",
    ] {
        for prefix in [
            "jdbc:sqlite:file.db?password=",
            "jdbc:oracle:thin:@db.corp.internal:1521/sales?user=app&password=",
        ] {
            assert_no_new_finding(&format!("{prefix}{value}"));
        }
    }
    for input in [
        "jdbc:sqlite:file.db?PASSWORD=Winter2026",
        "jdbc:sqlite:file.db?notpassword=Winter2026",
        "jdbc:sqlite:file.db?passwordHint=Winter2026",
        "jdbc:sqlite:file.db?a=b&xpassword=Winter2026",
        "jdbc:sqlite:file.db password=Winter2026",
        "jdbc:sqlite:?password=Winter2026",
        "jdbc:oracle:thin:@?password=Winter2026",
        "jdbc:oracle:thin:@/sales?password=Winter2026",
        "jdbc:oracle:thin:db.corp.internal:1521/sales?password=Winter2026",
        "jdbc:h2:file.db?password=Winter2026",
        "xjdbc:sqlite:file.db?password=Winter2026",
        "jdbc:mysql://db.corp.internal/sales?password=Winter2026",
    ] {
        assert_no_new_finding(input);
    }
}

#[test]
fn other_database_uri_schemes_keep_exact_ranges() {
    for scheme in [
        "mssql",
        "sqlserver",
        "oracle",
        "clickhouse",
        "cockroachdb",
        "couchdb",
        "influxdb",
        "cassandra",
        "neo4j",
        "bolt",
        "MSSQL",
        "mssql+pyodbc",
        "oracle+cx_oracle",
        "clickhouse+native",
        "cockroachdb+psycopg2",
        "neo4j+s",
        "neo4j+ssc",
        "bolt+s",
        "postgres+asyncpg",
        "postgresql+psycopg2",
        "mysql+pymysql",
        "mariadb+mariadbconnector",
    ] {
        let before = format!("{scheme}://app:");
        Case::whole(
            &before,
            "Q7vx9Lm2Rk4p",
            "@db.corp.internal:1433/sales?encrypt=true",
        )
        .assert_one(new_rules_engine(), OTHER_DATABASE_URI);
    }
    for case in [
        Case::whole(
            "cassandra://app:",
            "Q7vx9Lm2Rk4p",
            "@db1.corp.internal:9042,db2.corp.internal:9042/sales",
        ),
        Case::whole(
            "clickhouse://app:",
            "Q7vx9Lm2Rk4p",
            "@[2001:db8::1]:9000/sales",
        ),
        Case::whole(
            "influxdb://:",
            "Q7vx9Lm2Rk4p",
            "@metrics.corp.internal:8086/db",
        ),
        Case::whole("mssql://app:", "W!n:%74er", "@db.corp.internal/sales"),
        Case {
            lead: "\"",
            before: "mssql://app:",
            secret: "Q7vx9Lm2Rk4p",
            after: "@db.corp.internal/sales\" next",
            matched_after: "@db.corp.internal/sales\"",
        },
    ] {
        case.assert_one(new_rules_engine(), OTHER_DATABASE_URI);
    }
}

#[test]
fn other_database_uri_rejects_examples_placeholders_and_missing_parts() {
    for password in [
        "${DB_PASSWORD}",
        "{{db_password}}",
        "$DB_PASSWORD",
        "%DB_PASSWORD%",
        "<password>",
        "****",
        "true",
        "abcdefghijklmnopqrstuvwxyz",
        "your_password",
    ] {
        assert_no_new_finding(&format!("mssql://app:{password}@db.corp.internal/sales"));
    }
    for input in [
        "mssql://user:pass@example.com/sales",
        "oracle://foo:bar@test.com/sales",
        "mssql://app:Q7vx9Lm2Rk4p@db.example.com/sales",
        "mssql://app:Q7vx9Lm2Rk4p@example/sales",
        "clickhouse://app:Q7vx9Lm2Rk4p@example.org:9000",
        "mssql://app@db.corp.internal/sales",
        "mssql://app:@db.corp.internal/sales",
        "mssql://app:Q7vx9Lm2Rk4p@",
        "mssql://app:Q7vx9Lm2Rk4p@-db.corp.internal",
        "mssql+://app:Q7vx9Lm2Rk4p@db.corp.internal/sales",
        "xmssql://app:Q7vx9Lm2Rk4p@db.corp.internal/sales",
        "foo://app:Q7vx9Lm2Rk4p@db.corp.internal/sales",
        "postgresql://app:Q7vx9Lm2Rk4p@db.corp.internal/sales",
        // A semicolon cannot be part of the user name or password, so a JDBC
        // SQL Server property list is not read as user information.
        "jdbc:sqlserver://db.corp.internal:1433;user=app;password=Q7vx9@Lm2Rk4p;",
        "sqlserver://db.corp.internal:1433;user=app;password=Q7vx9Lm2Rk4p;",
    ] {
        assert_no_new_finding(input);
    }
}

#[test]
fn other_service_uri_schemes_keep_exact_ranges_and_exclusions() {
    for scheme in ["nats", "NATS", "mqtt", "mqtts", "memcached", "memcache"] {
        let before = format!("{scheme}://app:");
        Case::whole(&before, "Q7vx9Lm2Rk4p", "@bus.corp.internal:4222/x")
            .assert_one(new_rules_engine(), OTHER_SERVICE_URI);
    }
    Case::whole("nats://:", "Q7vx9Lm2Rk4p", "@bus.corp.internal:4222")
        .assert_one(new_rules_engine(), OTHER_SERVICE_URI);
    for input in [
        "nats://app:Q7vx9Lm2Rk4p@localhost:4222",
        "nats://app:Q7vx9Lm2Rk4p@bus.invalid:4222",
        "mqtt://app:Q7vx9Lm2Rk4p@broker.test:1883",
        "mqtt://app:Q7vx9Lm2Rk4p@broker.example.com:1883",
        "memcached://app:Q7vx9Lm2Rk4p@example:11211",
        "nats://user:pass@bus.corp.internal:4222",
        "nats://test:test@bus.corp.internal:4222",
        "nats://app:example_password@bus.corp.internal:4222",
        "nats://app:placeholder@bus.corp.internal:4222",
        "nats://app:xxxx@bus.corp.internal:4222",
        "nats://app:${NATS_PASSWORD}@bus.corp.internal:4222",
        "nats://app@bus.corp.internal:4222",
        "nats://app:@bus.corp.internal:4222",
        "nats://app:Q7vx9Lm2Rk4p@",
        "xnats://app:Q7vx9Lm2Rk4p@bus.corp.internal:4222",
        "rabbitmq://app:Q7vx9Lm2Rk4p@mq.corp.internal:5672",
    ] {
        assert_no_new_finding(input);
    }
    // Test and documentation paths are excluded, as in service-uri-password.
    let input = "nats://app:Q7vx9Lm2Rk4p@bus.corp.internal:4222";
    for path in ["tests/settings.conf", "README.md", "config.example.yaml"] {
        assert!(
            scan_path(new_rules_engine(), input, path).is_empty(),
            "{path}"
        );
    }
    assert_eq!(
        scan_path(new_rules_engine(), input, "config/settings.conf").len(),
        1
    );
}

#[test]
fn new_rules_add_no_finding_for_passwords_that_existing_rules_own() {
    for (input, path) in [
        (
            "postgresql://app:Q7vx9Lm2Rk4p@db.corp.internal:5432/sales",
            "",
        ),
        ("mysql://app:Q7vx9Lm2Rk4p@db.corp.internal/sales", ""),
        ("redis://:Q7vx9Lm2Rk4p@cache.corp.internal:6379", ""),
        ("amqp://app:Q7vx9Lm2Rk4p@mq.corp.internal:5672/vhost", ""),
        (
            "mongodb://app:Q7vx9Lm2Rk4pT8w0@db.corp.internal:27017, next",
            "",
        ),
        (
            "mongodb+srv://app:Q7vx9Lm2Rk4p@cluster0.corp.internal/sales",
            "",
        ),
        (
            "https://app:Q7vx9Lm2Rk4p@bitbucket.org/team/repo.git",
            "repo/.git/config",
        ),
        ("Server=db.corp.internal;Pwd=Winter2026;", ""),
        ("Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;", ""),
        (
            "jdbc:sqlserver://db.corp.internal:1433;user=app;password=Winter2026;Server=b;",
            "",
        ),
        (
            "jdbc:mysql://db.corp.internal/sales?password=Winter2026",
            "",
        ),
        (
            "jdbc:postgresql://db.corp.internal/sales?user=app&password=Winter2026",
            "",
        ),
        ("host=db.corp.internal password=Winter2026 dbname=sales", ""),
    ] {
        let old = scan_path(all_rules_without_new_rules(), input, path);
        assert!(!old.is_empty(), "{input:?}");
        assert_eq!(scan_path(all_rules(), input, path), old, "{input:?}");
    }
    // A provider token in the password slot keeps both findings, as for
    // database-uri. The engine removes only overlapping generic findings.
    let token = format!(
        "ghp_{}",
        "Q7m2Z9v4L1c8R5s0N6b3X"
            .chars()
            .cycle()
            .take(36)
            .collect::<String>()
    );
    let input = format!("nats://app:{token}@bus.corp.internal:4222");
    let mut expected = vec![
        exact("github-pat", &token, 11),
        exact(OTHER_SERVICE_URI, &token, 11),
    ];
    expected.sort();
    assert_eq!(
        outcomes(all_rules(), &input, &ScanOptions::default()),
        expected
    );
}
