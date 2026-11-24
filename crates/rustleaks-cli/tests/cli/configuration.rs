//! Configuration selection, version, ignore and baseline tests.

use super::*;

#[test]
fn config_equals_shorthand_and_raw_template_case_quirk_are_preserved() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let shorthand = output(&fixture.0, &["stdin", "--no-banner", "-c=config.toml"]);
    assert_eq!(shorthand.status.code(), Some(0));

    fixture.write("template.tmpl", "{{ range . }}{{ .RuleID }}{{ end }}");
    let uppercase = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c=config.toml",
            "-r",
            "-",
            "-f",
            "TEMPLATE",
            "--report-template",
            "template.tmpl",
        ],
    );
    assert_eq!(uppercase.status.code(), Some(1));
    assert!(uppercase.stdout.is_empty());
    assert!(String::from_utf8_lossy(&uppercase.stderr).contains("report format must be template"));
}

#[test]
fn explicit_config_wins_and_inline_errors_do_not_disclose_contents() {
    let fixture = Fixture::new();
    fixture.write("explicit.toml", no_match_config());
    fixture.write("environment.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let result = command(&fixture.0)
        .args(["dir", "secret.txt", "--no-banner", "-c", "explicit.toml"])
        .env("GITLEAKS_CONFIG", "environment.toml")
        .env("GITLEAKS_CONFIG_TOML", matching_config())
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let marker = "SECRET_MARKER_DO_NOT_PRINT";
    let invalid = command(&fixture.0)
        .args(["stdin", "--no-banner"])
        .env("GITLEAKS_CONFIG_TOML", format!("invalid=[{marker}"))
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains(marker));
}

#[test]
fn config_file_errors_show_position_but_not_file_text() {
    let marker = "SECRET_MARKER_DO_NOT_PRINT";
    let fixture = Fixture::new();
    fixture.write("broken.toml", format!("title = 'x'\ninvalid=[{marker}\n"));
    fixture.write("other.txt", format!("first line\n{marker}=value here\n"));
    fixture.write("extends.toml", "[extend]\npath = 'other.txt'\n");
    fixture.write("nested.toml", "[extend]\npath = 'extends.toml'\n");
    fixture.write("decode.toml", format!("title = ['{marker}']\n"));

    let cases = [
        ("broken.toml", "parse error at ", "at line 2, column"),
        (
            "extends.toml",
            "extended config error: parse error at ",
            "at line 1, column",
        ),
        (
            "nested.toml",
            "extended config error: extended config error: parse error at ",
            "at line 1, column",
        ),
        ("decode.toml", "decode error", ""),
    ];
    for (config, kind, position) in cases {
        let result = output(
            &fixture.0,
            &["stdin", "--no-banner", "--redact", "--config", config],
        );
        assert_eq!(result.status.code(), Some(1), "{config}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!stderr.contains(marker), "{config}: {stderr}");
        assert!(!stderr.contains("value here"), "{config}: {stderr}");
        assert!(
            stderr.contains("could not compile config"),
            "{config}: {stderr}"
        );
        assert!(stderr.contains(kind), "{config}: {stderr}");
        assert!(stderr.contains(position), "{config}: {stderr}");
    }
}

#[cfg(unix)]
#[test]
fn a_linked_source_local_config_does_not_print_the_linked_file() {
    let marker = "SECRET_MARKER_DO_NOT_PRINT";
    let fixture = Fixture::new();
    fixture.write("outside/private.txt", format!("{marker}=value here\n"));
    fixture.write("scan/readme.txt", "nothing here\n");
    std::os::unix::fs::symlink(
        fixture.0.join("outside/private.txt"),
        fixture.0.join("scan/.rustleaks.toml"),
    )
    .unwrap();
    let result = output(&fixture.0, &["dir", "scan", "--no-banner", "--redact"]);
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!stderr.contains(marker), "{stderr}");
    assert!(stderr.contains("parse error at "), "{stderr}");
}

#[test]
fn native_config_names_precede_backward_compatible_aliases() {
    let fixture = Fixture::new();
    fixture.write("native.toml", no_match_config());
    fixture.write("legacy.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");

    let environment = command(&fixture.0)
        .args(["dir", "secret.txt", "--no-banner"])
        .env("RUSTLEAKS_CONFIG", "native.toml")
        .env("GITLEAKS_CONFIG", "legacy.toml")
        .output()
        .unwrap();
    assert_eq!(environment.status.code(), Some(0));

    fixture.write(
        ".rustleaks.toml",
        "title='native'\n[[rules]]\nid='never'\nregex='''Z{1000}'''\n",
    );
    fixture.write(".gitleaks.toml", matching_config());
    let local = output(&fixture.0, &["dir", ".", "--no-banner"]);
    assert_eq!(local.status.code(), Some(0));

    let legacy_only = command(&fixture.0)
        .args(["dir", "secret.txt", "--no-banner"])
        .env("GITLEAKS_CONFIG", "legacy.toml")
        .output()
        .unwrap();
    assert_eq!(legacy_only.status.code(), Some(1));
}

#[test]
fn a_newer_min_version_warns_against_the_supported_gitleaks_version() {
    // Rustleaks reads configurations written for Gitleaks 8.30.0 and earlier,
    // so `minVersion` is compared with 8.30.0.
    let fixture = Fixture::new();
    let result = command(&fixture.0)
        .args(["stdin", "--no-banner"])
        .env("RUSTLEAKS_CONFIG_TOML", "minVersion = 'v99.0.0'\n")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains(" is newer than Gitleaks 8.30.0, the newest configuration version"),
        "{stderr}"
    );
}

#[test]
fn minimum_version_warning_is_one_warn_line_on_standard_error() {
    let fixture = Fixture::new();
    let default = output(&fixture.0, &["dir", ".", "--no-banner"]);
    let stderr = String::from_utf8_lossy(&default.stderr);
    assert_eq!(default.status.code(), Some(0), "{stderr}");
    assert!(default.stdout.is_empty());
    assert!(!stderr.contains("config minVersion"), "{stderr}");

    // The unit test in src/config.rs covers each version case.
    for (min_version, expected) in [
        ("v8.30.0", None),
        (
            "v99.0.0",
            Some(
                "config minVersion v99.0.0 is newer than Gitleaks 8.30.0, the newest configuration version that Rustleaks supports, so some settings may not be supported; config path=RUSTLEAKS_CONFIG_TOML",
            ),
        ),
    ] {
        let result = command(&fixture.0)
            .args(["dir", ".", "--no-banner"])
            .env(
                "RUSTLEAKS_CONFIG_TOML",
                format!("minVersion = '{min_version}'\n"),
            )
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(0), "{min_version}: {stderr}");
        assert!(result.stdout.is_empty());
        match expected {
            None => assert!(!stderr.contains("config minVersion"), "{stderr}"),
            Some(message) => {
                let warnings = stderr
                    .lines()
                    .filter(|line| line.contains("config minVersion"))
                    .collect::<Vec<_>>();
                assert_eq!(warnings.len(), 1, "{stderr}");
                assert!(warnings[0].contains("warn"), "{stderr}");
                assert!(warnings[0].ends_with(message), "{stderr}");
            }
        }
    }
}

#[test]
fn source_local_config_and_enabled_rule_projection_are_applied_before_scan() {
    let fixture = Fixture::new();
    fixture.write(".rustleaks.toml", two_rule_config());
    fixture.write("secrets.txt", b"alpha=AB12\nbeta=CD34\n");
    let selected = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "--enable-rule",
            "alpha",
            "-r",
            "-",
            "-f",
            "json",
        ],
    );
    assert_eq!(selected.status.code(), Some(1));
    assert!(
        selected
            .stdout
            .windows(b"alpha".len())
            .any(|v| v == b"alpha")
    );
    assert!(
        !selected
            .stdout
            .windows(b"beta=CD34".len())
            .any(|v| v == b"beta=CD34")
    );
    assert!(
        String::from_utf8_lossy(&selected.stderr).contains("info overriding enabled rules: alpha")
    );

    let suppressed = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "--log-level",
            "warn",
            "--enable-rule",
            "beta,alpha",
        ],
    );
    assert!(!String::from_utf8_lossy(&suppressed.stderr).contains("overriding enabled rules"));

    let invalid = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "--enable-rule",
            "absent",
            "-r",
            "must-not-exist.json",
        ],
    );
    assert_eq!(invalid.status.code(), Some(1));
    assert!(!fixture.0.join("must-not-exist.json").exists());
}

#[test]
fn selected_composite_keeps_its_required_rule_and_reports() {
    let fixture = Fixture::new();
    fixture.write(
        "composite.toml",
        "[[rules]]\nid='primary-rule'\ndescription='primary'\nregex='''password\\s*=\\s*\"([^\"]+)\"'''\n[[rules.required]]\nid='username-rule'\n[[rules]]\nid='username-rule'\ndescription='username'\nregex='''username\\s*=\\s*\"([^\"]+)\"'''\nskipReport=true\n",
    );
    fixture.write("secret.txt", b"username=\"alice\" password=\"AB12\"\n");
    let result = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "composite.toml",
            "--enable-rule",
            "primary-rule",
            "-r",
            "report.json",
        ],
    );
    // `username-rule` stays for `primary-rule` and reports nothing itself.
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = fs::read_to_string(fixture.0.join("report.json")).unwrap();
    assert_eq!(report.matches("\"RuleID\"").count(), 1, "{report}");
    assert!(report.contains("\"RuleID\": \"primary-rule\""), "{report}");
    assert!(!String::from_utf8_lossy(&result.stderr).contains("requires rule"));
}

#[test]
fn setup_diagnostic_cases_are_fatal_without_report_side_effects() {
    let fixture = Fixture::new();
    fixture.write("never.toml", no_match_config());
    fixture.write("two.toml", two_rule_config());
    fixture.write("secret.txt", b"alpha=AB12\n");
    fixture.write("template.tmpl", "{{ range . }}{{ .RuleID }}{{ end }}");

    let cases: [(&str, &[&str], Option<&str>); 7] = [
        (
            "missing source during config selection",
            &["dir", "missing", "--no-banner", "-r", "missing-source.json"],
            Some("missing-source.json"),
        ),
        (
            "missing enabled rule",
            &[
                "dir",
                "secret.txt",
                "--no-banner",
                "-c",
                "two.toml",
                "--enable-rule",
                "absent",
                "-r",
                "missing-rule.json",
            ],
            Some("missing-rule.json"),
        ),
        (
            "stdout report without format",
            &["stdin", "--no-banner", "-c", "never.toml", "-r", "-"],
            None,
        ),
        (
            "unknown inferred extension",
            &[
                "stdin",
                "--no-banner",
                "-c",
                "never.toml",
                "-r",
                "report.xml",
            ],
            Some("report.xml"),
        ),
        (
            "missing inferred extension",
            &["stdin", "--no-banner", "-c", "never.toml", "-r", "report"],
            Some("report"),
        ),
        (
            "missing template",
            &[
                "stdin",
                "--no-banner",
                "-c",
                "never.toml",
                "-r",
                "report.tmpl",
                "-f",
                "template",
                "--report-template",
                "missing.tmpl",
            ],
            Some("report.tmpl"),
        ),
        (
            "raw uppercase template mismatch",
            &[
                "stdin",
                "--no-banner",
                "-c",
                "never.toml",
                "-r",
                "uppercase.tmpl",
                "-f",
                "TEMPLATE",
                "--report-template",
                "template.tmpl",
            ],
            Some("uppercase.tmpl"),
        ),
    ];

    for (name, arguments, report) in cases {
        let result = output(&fixture.0, arguments);
        assert_eq!(result.status.code(), Some(1), "{name}");
        assert!(result.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            stderr.lines().any(|line| line.starts_with("fatal ")),
            "{name}: {stderr}"
        );
        assert!(
            stderr.lines().all(|line| !line.starts_with("error ")),
            "{name}: {stderr}"
        );
        if let Some(report) = report {
            assert!(!fixture.0.join(report).exists(), "{name}");
        }
    }
}

#[test]
fn oversized_source_local_config_is_fatal_before_the_scan() {
    let fixture = Fixture::new();
    let mut config = matching_config().as_bytes().to_vec();
    config.push(b'\n');
    config.resize(16 * 1024 * 1024 + 1, b'#');
    fixture.write("repo/.gitleaks.toml", config);
    fixture.write("repo/secret.txt", b"token=AB12\n");
    let result = output(
        &fixture.0,
        &["dir", "repo", "--no-banner", "-r", "report.json"],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.lines().any(|line| line.starts_with("fatal ")
            && line.contains("configuration file is larger than the 16 MiB limit")),
        "{stderr}"
    );
    assert!(!fixture.0.join("report.json").exists());
}

#[test]
fn baseline_is_nonfatal_and_excludes_its_own_report_file() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let first = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "baseline.json",
        ],
    );
    assert_eq!(first.status.code(), Some(1));
    let second = output(
        &fixture.0,
        &[
            "dir",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--baseline-path",
            "baseline.json",
        ],
    );
    assert_eq!(
        second.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stderr).contains("no leaks found"));

    let missing = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "config.toml",
            "--baseline-path",
            "missing.json",
        ],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("could not load baseline"));
}

#[test]
fn regular_ignore_file_does_not_make_its_child_probe_fatal() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("ignore.txt", b"# no entries\n");
    fixture.write("secret.txt", b"token=AB12\n");
    let result = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "config.toml",
            "-i",
            "ignore.txt",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("leaks found: 1"));
}

#[test]
fn stdin_source_local_ignore_is_unioned_with_a_custom_ignore_path() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("custom.ignore", b"# intentionally empty\n");
    fixture.write(".rustleaksignore", b":fixture-token:1\n");
    let result = output_with_stdin(
        command(&fixture.0).args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--rustleaks-ignore-path",
            "custom.ignore",
        ]),
        b"token=AB12\n",
    );
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stderr).contains("no leaks found"));
}

#[test]
fn invalid_ignore_entries_are_warned_once_in_plain_text() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("kept.txt", b"token=AB12\n");
    fixture.write("ignored.txt", b"token=CD34\n");
    // Line 2 has two fields. Line 3 is a valid global entry and must still
    // apply after the invalid line.
    fixture.write(
        ".rustleaksignore",
        b"# synthetic ignore file\na:b\nignored.txt:fixture-token:1\n",
    );
    fixture.write("extra.ignore", b"x\n");
    let warning = |fields: &str, file: &Path, line: u32| {
        format!(
            "warn ignore file entry has {fields}, expected 3 or 4 file={} line={line}",
            file.display()
        )
    };
    let source_warning = warning("2 fields", Path::new(".rustleaksignore"), 2);
    // A path that differs in text but names the same file.
    let fixture_name = fixture.0.file_name().unwrap().to_str().unwrap();
    let parent_path = Path::new("..").join(fixture_name).join(".rustleaksignore");
    let parent_path_text = parent_path.to_str().unwrap();
    let cases = vec![
        // The default ignore path "." and the scanned folder "." name the
        // same file, so it is read and reported once.
        (Vec::new(), vec![source_warning.clone()]),
        (
            vec!["-i", "extra.ignore"],
            vec![
                warning("1 field", Path::new("extra.ignore"), 1),
                source_warning.clone(),
            ],
        ),
        (
            vec!["-i", parent_path_text],
            vec![warning("2 fields", &parent_path, 2)],
        ),
    ];
    // A symlink is a second name for the same file.
    #[cfg(unix)]
    let cases = {
        let mut cases = cases;
        std::os::unix::fs::symlink(".rustleaksignore", fixture.0.join("link.ignore")).unwrap();
        cases.push((
            vec!["-i", "link.ignore"],
            vec![warning("2 fields", Path::new("link.ignore"), 2)],
        ));
        cases
    };

    for (arguments, expected) in cases {
        let mut all = vec!["dir", ".", "--no-banner", "-c", "config.toml"];
        all.extend_from_slice(&arguments);
        let result = output(&fixture.0, &all);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(1), "{arguments:?}: {stderr}");
        let warnings = stderr
            .lines()
            .filter(|line| line.contains("ignore file"))
            .collect::<Vec<_>>();
        assert_eq!(warnings, expected, "{arguments:?}: {stderr}");
        assert!(
            !stderr.contains("InvalidFieldCount") && !stderr.contains("ByteText"),
            "{stderr}"
        );
        assert!(stderr.contains("leaks found: 1"), "{arguments:?}: {stderr}");
    }
}
