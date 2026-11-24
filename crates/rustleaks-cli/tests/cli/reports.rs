//! Report, redaction, verbose and log level tests.

use super::*;

#[test]
fn redaction_and_custom_zero_exit_are_applied_to_reports() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let result = output_with_stdin(
        command(&fixture.0).args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--redact",
            "--exit-code",
            "0",
            "-r",
            "-",
            "-f",
            "json",
        ]),
        b"token=AB12\n",
    );
    assert_eq!(result.status.code(), Some(0));
    assert!(
        result
            .stdout
            .windows(b"REDACTED".len())
            .any(|v| v == b"REDACTED")
    );
    assert!(!result.stdout.windows(b"AB12".len()).any(|v| v == b"AB12"));
}

#[test]
fn redaction_hides_helper_values_of_composite_rules_in_verbose_output() {
    let fixture = Fixture::new();
    fixture.write(
        "composite.toml",
        "[[rules]]\nid='primary-rule'\ndescription='primary'\nregex='''password=\"([A-Za-z0-9]+)\"'''\nsecretGroup=1\n[[rules.required]]\nid='helper-rule'\n[[rules]]\nid='helper-rule'\ndescription='helper'\nregex='''client=\"([a-z0-9]+)\"'''\nsecretGroup=1\nskipReport=true\n",
    );
    fixture.write(
        "secret.txt",
        b"client=\"helperclient42\" password=\"Primary9Z\"\n",
    );
    let verbose = |extra: &[&str]| {
        let mut arguments = vec![
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "composite.toml",
            "--verbose",
        ];
        arguments.extend_from_slice(extra);
        let result = output(&fixture.0, &arguments);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8(result.stdout).unwrap();
        let required = stdout
            .lines()
            .filter(|line| line.starts_with("Required:"))
            .map(|line| line.split_whitespace().nth(1).unwrap().to_owned())
            .collect::<Vec<_>>();
        (stdout, required)
    };

    let (stdout, required) = verbose(&[]);
    assert_eq!(required, ["helper-rule:1:helperclient42"], "{stdout}");
    assert!(stdout.contains("Primary9Z"));

    // 14 bytes with 50 percent hidden keep the first 7.
    for (flag, shown) in [
        ("--redact", "helper-rule:1:REDACTED"),
        ("--redact=100", "helper-rule:1:REDACTED"),
        ("--redact=50", "helper-rule:1:helperc..."),
    ] {
        let (stdout, required) = verbose(&[flag]);
        assert_eq!(required, [shown], "{flag}: {stdout}");
        assert!(!stdout.contains("helperclient42"), "{flag}: {stdout}");
        assert!(!stdout.contains("Primary9Z"), "{flag}: {stdout}");
    }
}

#[test]
fn log_level_filters_normalized_summary_severities() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let quiet = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "error",
        ],
    );
    assert_eq!(quiet.status.code(), Some(0));
    assert!(quiet.stderr.is_empty());

    fixture.write("matching.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let warning = output(
        &fixture.0,
        &[
            "dir",
            "secret.txt",
            "--no-banner",
            "-c",
            "matching.toml",
            "--log-level",
            "warn",
        ],
    );
    let stderr = String::from_utf8(warning.stderr).unwrap();
    assert!(stderr.contains("leaks found: 1"));
    assert!(!stderr.contains("scanned ~"));
}

#[test]
fn report_inference_and_safe_error_routing_are_stable() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "empty.json",
        ],
    );
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(fs::read(fixture.0.join("empty.json")).unwrap(), b"[]\n");
    assert!(result.stdout.is_empty());

    let missing = output(
        &fixture.0,
        &["stdin", "--no-banner", "-c", "config.toml", "-r", "-"],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty());

    let unknown = output(&fixture.0, &["stdin", "--unknown"]);
    assert_eq!(unknown.status.code(), Some(126));
    assert!(unknown.stdout.is_empty());
    let unknown_stderr = String::from_utf8_lossy(&unknown.stderr);
    assert_eq!(
        unknown_stderr,
        "Error: unknown flag: --unknown\nUsage:\n  rustleaks stdin [flags]\n\nRun 'rustleaks help stdin' for details.\n\n"
    );

    for name in [
        "implicit.xml",
        "implicit.junit",
        "implicit.tmpl",
        "implicit.template",
    ] {
        let rejected = output(
            &fixture.0,
            &["stdin", "--no-banner", "-c", "config.toml", "-r", name],
        );
        assert_eq!(rejected.status.code(), Some(1));
        assert!(!fixture.0.join(name).exists());
    }
}

#[test]
fn format_and_template_flags_are_dormant_without_report_path() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--report-format",
            "not-a-format",
            "--report-template",
            "missing.tmpl",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
}

#[test]
fn failed_setup_never_truncates_existing_report() {
    let fixture = Fixture::new();
    fixture.write("broken.toml", "not = [ valid");
    fixture.write("report.json", b"preserve-this-report");
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "broken.toml",
            "-r",
            "report.json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.0.join("report.json")).unwrap(),
        b"preserve-this-report"
    );
}

#[test]
fn report_open_failure_is_observed_by_the_fresh_process() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            ".",
            "-f",
            "json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("could not write json report"), "{stderr}");
    assert!(stderr.contains("could not open report"), "{stderr}");
}

#[test]
fn template_is_constructed_before_scanning() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    fixture.write("template.tmpl", "{{ range . }}{{ .RuleID }}{{ end }}");
    let result = output(
        &fixture.0,
        &[
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "report.tmpl",
            "-f",
            "template",
            "--report-template",
            "template.tmpl",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(fs::read(fixture.0.join("report.tmpl")).unwrap().is_empty());
}

/// Runs a `stdin` scan that finds one secret and writes a JSON report to
/// `path`. Findings exit with 0, so a failure to write exits with 1.
fn json_report_command(cwd: &Path, path: &str) -> Command {
    let mut command = command(cwd);
    command.args([
        "stdin",
        "--no-banner",
        "-c",
        "config.toml",
        "--exit-code",
        "0",
        "-r",
        path,
        "-f",
        "json",
    ]);
    command
}

/// The rule ID of each finding in a JSON report.
fn report_rules(report: &[u8]) -> Vec<String> {
    json_report_rows(report)
        .into_iter()
        .map(|(rule, ..)| rule)
        .collect()
}

#[test]
fn new_report_file_is_created_with_owner_only_mode() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let result = output_with_stdin(
        &mut json_report_command(&fixture.0, "report.json"),
        b"token=AB12\n",
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let path = fixture.0.join("report.json");
    assert_eq!(report_rules(&fs::read(&path).unwrap()), ["fixture-token"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
    }
}

#[test]
fn existing_report_file_is_replaced() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let old = "old report contents\n".repeat(64);
    fixture.write("report.json", &old);
    let result = output_with_stdin(
        &mut json_report_command(&fixture.0, "report.json"),
        b"token=AB12\n",
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = fs::read(fixture.0.join("report.json")).unwrap();
    assert!(report.len() < old.len());
    assert_eq!(report_rules(&report), ["fixture-token"]);
}

#[cfg(unix)]
#[test]
fn symbolic_link_at_report_path_is_refused_before_the_scan() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("target.txt", b"keep this file");
    let link = |target: &str, name: &str| {
        std::os::unix::fs::symlink(fixture.0.join(target), fixture.0.join(name)).unwrap();
    };
    link("target.txt", "report.json");
    link("missing.txt", "dangling.json");
    for name in ["report.json", "dangling.json"] {
        let result = output_with_stdin(&mut json_report_command(&fixture.0, name), b"token=AB12\n");
        // The exit code of a report path that cannot be written.
        assert_eq!(result.status.code(), Some(1), "{name}");
        assert!(result.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("symbolic link"), "{name}: {stderr}");
        assert!(!stderr.contains("leaks found"), "{name}: {stderr}");
        let metadata = fs::symlink_metadata(fixture.0.join(name)).unwrap();
        assert!(metadata.file_type().is_symlink(), "{name}");
    }
    assert_eq!(
        fs::read(fixture.0.join("target.txt")).unwrap(),
        b"keep this file"
    );
    assert!(!fixture.0.join("missing.txt").exists());
}

#[cfg(unix)]
#[test]
fn dev_stdout_report_path_writes_to_standard_output() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());

    // Standard output is a pipe.
    let piped = output_with_stdin(
        &mut json_report_command(&fixture.0, "/dev/stdout"),
        b"token=AB12\n",
    );
    assert_eq!(
        piped.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&piped.stderr)
    );
    assert_eq!(report_rules(&piped.stdout), ["fixture-token"]);

    // Standard output is a regular file. /dev/stdout then leads to that file.
    let redirected = fixture.0.join("redirected.json");
    let mut child = json_report_command(&fixture.0, "/dev/stdout")
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&redirected).unwrap())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"token=AB12\n").unwrap();
    drop(stdin);
    let result = child.wait_with_output().unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        report_rules(&fs::read(&redirected).unwrap()),
        ["fixture-token"]
    );
}
