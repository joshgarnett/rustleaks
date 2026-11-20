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
        "--native-pack",
        "rustleaks-providers-v1",
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
    let mut child = command(&fixture.0)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn builtin_selection_reaches_normal_pipeline_and_preserves_opt_in() {
    let fixture = Fixture::new();
    let value = secret();
    let accepted = stdin(
        &fixture,
        value.as_bytes(),
        &[
            "--native-pack",
            "rustleaks-extra-v1",
            "--native-pack",
            "rustleaks-connections-v1",
        ],
    );
    assert_eq!(
        accepted.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report = rustleaks_core::session::Baseline::from_go_json(&accepted.stdout).unwrap();
    assert!(!report.was_null());
    let rows = report.entries();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rule_id().as_bytes(), b"rustleaks.groq-api-key");
    assert_eq!(rows[0].secret().as_bytes(), value.as_bytes());
    let rejected = stdin(&fixture, format!("gsk_{}", "0".repeat(52)).as_bytes(), &[]);
    assert_eq!(rejected.status.code(), Some(0));
    assert_eq!(rejected.stdout, b"[]\n");
    let legacy = output(
        &fixture.0,
        &[
            "stdin",
            "--enable-rule",
            "rustleaks.groq-api-key",
            "--no-banner",
        ],
    );
    assert_eq!(legacy.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&legacy.stderr).contains("rustleaks.groq-api-key"));
    let diagnostic = stdin(&fixture, b"unrelated", &["--log-level", "debug"]);
    let stderr = String::from_utf8_lossy(&diagnostic.stderr);
    assert!(stderr.contains("built-in rule packs rustleaks-native-v1|"));
    assert!(stderr.contains("providers-sha256:"));
    assert!(!stderr.contains("[[rules]]"));
}

#[test]
fn native_uri_selection_preserves_global_suppression() {
    let fixture = Fixture::new();
    for (secret, found) in [
        ("%B", false),
        ("%D", false),
        ("%S", false),
        ("%Z", true),
        ("%B0", true),
    ] {
        let input = format!("mysql://app:{secret}@db.invalid");
        let mut child = command(&fixture.0)
            .args([
                "stdin",
                "--native-pack",
                "rustleaks-connections-v1",
                "--enable-rule",
                "rustleaks.connection-string.password.database-uri",
                "--no-banner",
                "--log-level",
                "fatal",
                "--report-path",
                "-",
                "--report-format",
                "json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(i32::from(found)),
            "{secret}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
        assert!(!report.was_null());
        let rows = report.entries();
        assert_eq!(rows.len(), usize::from(found), "{secret}");
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
            let mut child = command(&fixture.0)
                .args([
                    "stdin",
                    "--native-pack",
                    "rustleaks-providers-v1",
                    "--enable-rule",
                    id,
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(value.as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
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
fn conflicting_config_sources_are_not_silently_ignored() {
    let fixture = Fixture::new();
    let marker = "NATIVE_CONFIG_PRIVATE_SENTINEL";
    let custom = format!(
        "# {marker}\n[allowlist]\nregexes=['.*']\n{}",
        no_match_config()
    );
    fixture.write("custom.toml", &custom);
    let explicit = output(&fixture.0, &args(&["stdin", "--config", "custom.toml"]));
    assert_eq!(explicit.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&explicit.stderr).contains("set by --config"));
    assert!(explicit.stdout.is_empty());
    for (key, value) in [
        ("RUSTLEAKS_CONFIG", "custom.toml"),
        ("RUSTLEAKS_CONFIG_TOML", custom.as_str()),
        ("GITLEAKS_CONFIG", "custom.toml"),
        ("GITLEAKS_CONFIG_TOML", custom.as_str()),
    ] {
        let result = command(&fixture.0)
            .env(key, value)
            .args(args(&["stdin"]))
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(&format!("set by {key}")));
        assert!(!stderr.contains(marker));
        assert!(result.stdout.is_empty());
    }
    for filename in [".rustleaks.toml", ".gitleaks.toml"] {
        fixture.write(filename, &custom);
        for mode in [vec!["stdin"], vec!["dir", "."]] {
            let result = output(&fixture.0, &args(&mode));
            assert_eq!(result.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&result.stderr).contains("set by source-local config"));
            assert!(result.stdout.is_empty());
        }
        fs::remove_file(fixture.0.join(filename)).unwrap();
    }
    let empty = command(&fixture.0)
        .env("RUSTLEAKS_CONFIG", "")
        .env("RUSTLEAKS_CONFIG_TOML", "")
        .env("GITLEAKS_CONFIG", "")
        .env("GITLEAKS_CONFIG_TOML", "")
        .args(args(&["stdin"]))
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(0));
    let missing = output(&fixture.0, &args(&["dir", "absent-source"]));
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("during config selection"));
}

#[test]
fn unknown_and_duplicate_native_packs_fail_before_scanning() {
    let fixture = Fixture::new();
    for (id, message) in [
        ("unknown-private-sentinel", "unknown built-in rule pack"),
        ("rustleaks-providers-v1", "duplicate native pack identifier"),
    ] {
        let result = stdin(&fixture, secret().as_bytes(), &["--native-pack", id]);
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains(message));
        assert!(!stderr.contains("unknown-private-sentinel"));
    }
}

#[test]
fn native_composition_retains_redaction_ignores_baselines_and_source_exclusions() {
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
