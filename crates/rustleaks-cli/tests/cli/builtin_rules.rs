use super::*;

fn secret() -> String {
    format!(
        "gsk_{}",
        "Q7m2Z9v4L1c8R5s0N6b3X"
            .chars()
            .cycle()
            .take(52)
            .collect::<String>()
    )
}

fn args<'a>(prefix: &[&'a str]) -> Vec<&'a str> {
    let mut arguments = prefix.to_vec();
    arguments.extend([
        "--enable-rule",
        "rustleaks.groq-api-key",
        "--no-banner",
        "--log-level",
        "fatal",
        "--report-path",
        "-",
        "--report-format",
        "json",
    ]);
    arguments
}

fn stdin(fixture: &Fixture, bytes: &[u8], extra: &[&str]) -> Output {
    let mut arguments = args(&["stdin"]);
    arguments.extend_from_slice(extra);
    output_with_stdin(command(&fixture.0).args(arguments), bytes)
}

#[test]
fn a_default_scan_reports_builtin_rules() {
    let fixture = Fixture::new();
    let value = secret();
    let found = output_with_stdin(
        command(&fixture.0).args([
            "--no-banner",
            "stdin",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ]),
        value.as_bytes(),
    );
    assert_eq!(
        found.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&found.stderr)
    );
    let report = rustleaks_core::session::Baseline::from_go_json(&found.stdout).unwrap();
    let rows = report.entries();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rule_id().as_bytes(), b"rustleaks.groq-api-key");
    assert_eq!(rows[0].secret().as_bytes(), value.as_bytes());
    let rejected = stdin(&fixture, format!("gsk_{}", "0".repeat(52)).as_bytes(), &[]);
    assert_eq!(rejected.status.code(), Some(0));
    assert_eq!(rejected.stdout, b"[]\n");
}

#[test]
fn the_native_pack_flag_is_gone() {
    let fixture = Fixture::new();
    for flag in ["--native-pack=rustleaks-providers-v1", "--native-pack"] {
        let result = output_with_stdin(
            command(&fixture.0).args(["stdin", "--no-banner", flag]),
            secret().as_bytes(),
        );
        assert_eq!(result.status.code(), Some(126), "{flag}");
        assert!(result.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("native-pack"),
            "{flag}"
        );
    }
}

#[test]
fn builtin_uri_rule_keeps_global_suppression() {
    let fixture = Fixture::new();
    for (case, (secret, found)) in [
        ("%B", false),
        ("%D", false),
        ("%S", false),
        ("%Z", true),
        ("%B0", true),
    ]
    .into_iter()
    .enumerate()
    {
        let input = format!("mysql://app:{secret}@db.invalid");
        let result = output_with_stdin(
            command(&fixture.0).args([
                "stdin",
                "--enable-rule",
                "rustleaks.connection-string.password.database-uri",
                "--no-banner",
                "--log-level",
                "fatal",
                "--report-path",
                "-",
                "--report-format",
                "json",
            ]),
            input.as_bytes(),
        );
        assert_eq!(
            result.status.code(),
            Some(i32::from(found)),
            "case {case}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
        assert!(!report.was_null());
        let rows = report.entries();
        assert_eq!(rows.len(), usize::from(found), "case {case}");
        if found {
            assert_eq!(rows[0].secret().as_bytes(), secret.as_bytes());
            assert_eq!(
                rows[0].rule_id().as_bytes(),
                b"rustleaks.connection-string.password.database-uri"
            );
        }
    }
}

#[test]
fn six_builtin_byte_predicates_survive_cli_rule_selection() {
    let fixture = Fixture::new();
    for (id, prefix, length) in [
        ("rustleaks.dockerhub-personal-access-token", "dckr_pat_", 27),
        (
            "rustleaks.dockerhub-organization-access-token",
            "dckr_oat_",
            32,
        ),
        ("rustleaks.neon-api-key", "napi_", 64),
        ("rustleaks.render-api-key", "rnd_", 28),
        ("rustleaks.deno-account-token", "ddp_", 36),
        ("rustleaks.apify-api-token", "apify_api_", 34),
    ] {
        let high = format!(
            "{prefix}{}",
            "Q7m2Z9v4L1c8R5s0N6b3X"
                .chars()
                .cycle()
                .take(length)
                .collect::<String>()
        );
        // The fixed prefix plus repeated body passes the regex and does
        // not match the default single-letter placeholder allowlist.
        let low = format!("{prefix}{}", "A".repeat(length));
        for (value, count) in [(high, 1), (low, 0)] {
            let result = output_with_stdin(
                command(&fixture.0).args([
                    "stdin",
                    "--enable-rule",
                    id,
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ]),
                value.as_bytes(),
            );
            assert_eq!(
                result.status.code(),
                Some(count),
                "{id}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
            assert!(!report.was_null());
            let rows = report.entries();
            assert_eq!(rows.len(), usize::try_from(count).unwrap(), "{id}");
            if count != 0 {
                assert_eq!(rows[0].rule_id().as_bytes(), id.as_bytes());
                assert_eq!(rows[0].secret().as_bytes(), value.as_bytes());
            }
        }
    }
}

#[test]
fn configs_get_builtin_rules_only_by_extending_the_default() {
    // No `--enable-rule`: a config without the built-in rules must scan
    // cleanly instead of failing on a missing rule ID.
    let args = |prefix: &[&'static str]| {
        let mut arguments = prefix.to_vec();
        arguments.extend(["--no-banner", "--log-level", "fatal"]);
        arguments
    };
    let fixture = Fixture::new();
    let own = no_match_config();
    let extending = "[extend]\nuseDefault = true\n";
    fixture.write("own.toml", own);
    fixture.write("extending.toml", extending);
    fixture.write("chained.toml", "[extend]\npath = 'extending.toml'\n");
    for (path, count) in [("own.toml", 0), ("extending.toml", 1), ("chained.toml", 1)] {
        let result = output_with_stdin(
            command(&fixture.0).args(args(&["stdin", "--config", path])),
            secret().as_bytes(),
        );
        assert_eq!(
            result.status.code(),
            Some(count),
            "{path}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    for (key, value, count) in [
        ("RUSTLEAKS_CONFIG", "own.toml", 0),
        ("RUSTLEAKS_CONFIG", "extending.toml", 1),
        ("RUSTLEAKS_CONFIG_TOML", own, 0),
        ("RUSTLEAKS_CONFIG_TOML", extending, 1),
        ("GITLEAKS_CONFIG", "own.toml", 0),
        ("GITLEAKS_CONFIG_TOML", extending, 1),
    ] {
        let result = output_with_stdin(
            command(&fixture.0).env(key, value).args(args(&["stdin"])),
            secret().as_bytes(),
        );
        assert_eq!(result.status.code(), Some(count), "{key}={value}");
    }
    for filename in [".rustleaks.toml", ".gitleaks.toml"] {
        for (contents, count) in [(own, 0), (extending, 1)] {
            fixture.write(filename, contents);
            let result = output_with_stdin(
                command(&fixture.0).args(args(&["stdin"])),
                secret().as_bytes(),
            );
            assert_eq!(result.status.code(), Some(count), "{filename}");
        }
        fs::remove_file(fixture.0.join(filename)).unwrap();
    }
}

#[test]
fn builtin_rules_keep_redaction_ignores_baselines_and_source_exclusions() {
    let fixture = Fixture::new();
    let value = secret();
    let redacted = stdin(
        &fixture,
        value.as_bytes(),
        &["--redact", "--exit-code", "0"],
    );
    assert_eq!(redacted.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&redacted.stdout).contains(&value));
    assert!(String::from_utf8_lossy(&redacted.stdout).contains("REDACTED"));
    fixture.write(".rustleaksignore", ":rustleaks.groq-api-key:1\n");
    let ignored = stdin(&fixture, value.as_bytes(), &[]);
    assert_eq!(ignored.status.code(), Some(0));
    assert_eq!(ignored.stdout, b"[]\n");
    fs::remove_file(fixture.0.join(".rustleaksignore")).unwrap();
    let marked = stdin(
        &fixture,
        format!("{value} # rustleaks:allow").as_bytes(),
        &[],
    );
    assert_eq!(marked.status.code(), Some(0));
    fixture.write("secret.txt", &value);
    fixture.write("node_modules/ignored.txt", &value);
    let first = output(&fixture.0, &args(&["dir", "."]));
    assert_eq!(first.status.code(), Some(1));
    let report = rustleaks_core::session::Baseline::from_go_json(&first.stdout).unwrap();
    assert!(!report.was_null());
    let rows = report.entries();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].file().as_bytes(), b"secret.txt");
    fixture.write("baseline.json", &first.stdout);
    let second = output(
        &fixture.0,
        &args(&["dir", ".", "--baseline-path", "baseline.json"]),
    );
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(second.stdout, b"[]\n");
}

#[test]
fn ordinary_cli_config_rejects_native_tables_instead_of_discarding_them() {
    let fixture = Fixture::new();
    let source = "[[rules]]\nid='rustleaks.entropy'\nregex='ent=([^ ]+)'\nentropy={algorithm='byte-shannon-f64-v1',reject='lt',threshold=3.5}\n";
    fixture.write("native.toml", source);
    fixture.write(
        "combined.toml",
        format!("[extend]\nuseDefault=true\n{source}"),
    );
    fixture.write("extended.toml", "[extend]\npath='native.toml'\n");
    for path in ["native.toml", "combined.toml", "extended.toml"] {
        let result = output(
            &fixture.0,
            &[
                "stdin",
                "--config",
                path,
                "--no-banner",
                "--report-path",
                "-",
            ],
        );
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("could not compile config"));
    }
    let inline = command(&fixture.0)
        .env("RUSTLEAKS_CONFIG_TOML", source)
        .args(["stdin", "--no-banner", "--report-path", "-"])
        .output()
        .unwrap();
    assert_eq!(inline.status.code(), Some(1));
    assert!(inline.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&inline.stderr);
    assert!(stderr.contains("decode error"));
    assert!(!stderr.contains("byte-shannon-f64-v1"));
}
