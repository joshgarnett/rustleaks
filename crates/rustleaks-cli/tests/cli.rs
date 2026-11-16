#![forbid(unsafe_code)]
//! Fresh-process compatibility checks for the thin CLI.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rustleaks-cli-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command(cwd: &Path) -> Command {
    let mut command = Command::new(rustleaks_executable());
    command
        .current_dir(cwd)
        .env_remove("RUSTLEAKS_CONFIG")
        .env_remove("RUSTLEAKS_CONFIG_TOML")
        .env_remove("GITLEAKS_CONFIG")
        .env_remove("GITLEAKS_CONFIG_TOML");
    let git = git_executable();
    if git.is_absolute() {
        command.env("PATH", git.parent().expect("declared Git has a parent"));
    }
    command
}

fn rustleaks_executable() -> PathBuf {
    resolve_runfile(PathBuf::from(env!("CARGO_BIN_EXE_rustleaks")), "Rustleaks")
}

fn git_executable() -> PathBuf {
    let runfile = std::env::var_os("RUSTLEAKS_TEST_GIT_RUNFILE")
        .map_or_else(|| PathBuf::from("git"), PathBuf::from);
    resolve_runfile(runfile, "Git")
}

fn resolve_runfile(runfile: PathBuf, label: &str) -> PathBuf {
    if runfile.is_absolute() {
        return runfile;
    }
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            let root = PathBuf::from(root);
            for candidate in [root.join(&runfile), root.join("_main").join(&runfile)] {
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        let key = runfile.to_string_lossy();
        let contents = fs::read_to_string(manifest).expect("read Bazel runfiles manifest");
        let workspace_key = format!("_main/{key}");
        let external_key = key.strip_prefix("../");
        if let Some((_, resolved)) = contents.lines().find_map(|line| {
            let (entry, resolved) = line.split_once(' ')?;
            (entry == key || entry == workspace_key || external_key == Some(entry))
                .then_some((entry, resolved))
        }) {
            return PathBuf::from(resolved);
        }
    }
    if runfile == Path::new("git") {
        return runfile;
    }
    panic!("cannot resolve {label} runfile {}", runfile.display());
}

fn output(cwd: &Path, arguments: &[&str]) -> Output {
    command(cwd).args(arguments).output().unwrap()
}

fn git(cwd: &Path, arguments: &[&str]) {
    let result = Command::new(git_executable())
        .current_dir(cwd)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "git {:?}: {}",
        arguments,
        String::from_utf8_lossy(&result.stderr)
    );
}

fn matching_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='fixture-token'\ndescription='fixture token'\nregex='''token=([A-Z0-9]{4})'''\nsecretGroup=1\nkeywords=['token']\n"
}

fn two_rule_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='alpha'\ndescription='alpha'\nregex='''alpha=([A-Z0-9]{4})'''\nsecretGroup=1\n[[rules]]\nid='beta'\ndescription='beta'\nregex='''beta=([A-Z0-9]{4})'''\nsecretGroup=1\n"
}

fn no_match_config() -> &'static str {
    "title='fixture'\n[[rules]]\nid='never'\ndescription='never'\nregex='''NEVER_MATCH_THIS_VALUE'''\n"
}

#[test]
fn help_and_version_forms_are_successful_and_side_effect_free() {
    let fixture = Fixture::new();
    for arguments in [vec![], vec!["--help"], vec!["version"], vec!["--version"]] {
        let output = output(&fixture.0, &arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    let help = String::from_utf8(output(&fixture.0, &["--help"]).stdout).unwrap();
    assert!(help.starts_with(
        "Rustleaks scans code, past or present, for secrets\n\nUsage:\n  rustleaks [command]\n"
    ));
    assert!(!help.contains("completion"));
    assert!(!help.contains("diagnostics"));
    let mut cursor = 0;
    for flag in [
        "--baseline-path",
        "--config",
        "--enable-rule",
        "--exit-code",
        "--rustleaks-ignore-path",
        "--gitleaks-ignore-path",
        "--ignore-rustleaks-allow",
        "--ignore-gitleaks-allow",
        "--log-level",
        "--max-archive-depth",
        "--max-decode-depth",
        "--max-target-megabytes",
        "--no-banner",
        "--no-color",
        "--redact",
        "--report-format",
        "--report-path",
        "--report-template",
        "--timeout",
        "--verbose",
        "--version",
    ] {
        let offset = help[cursor..]
            .find(flag)
            .unwrap_or_else(|| panic!("missing {flag}"));
        cursor += offset + flag.len();
    }
    for (command_name, usage, local_flag) in [
        ("dir", "rustleaks dir [flags] [path]", "--follow-symlinks"),
        ("git", "rustleaks git [flags] [repo]", "--log-opts"),
        ("stdin", "rustleaks stdin [flags]", "help for stdin"),
    ] {
        let help = String::from_utf8(output(&fixture.0, &[command_name, "--help"]).stdout).unwrap();
        assert!(help.contains(usage));
        assert!(help.contains(local_flag));
        assert!(help.contains("Global Flags:\n"));
        assert!(help.contains("--report-template"));
    }
    let version = output(&fixture.0, &["version", "--no-banner"]);
    assert!(version.status.success());
    assert!(!version.stdout.is_empty());
    assert!(version.stderr.is_empty());
}

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
fn directory_aliases_emit_the_same_json_and_custom_exit() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    let mut reports = Vec::new();
    for alias in ["dir", "file", "directory"] {
        let result = output(
            &fixture.0,
            &[
                alias,
                ".",
                "--no-banner",
                "-c",
                "config.toml",
                "-r",
                "-",
                "-f",
                "json",
                "--exit-code",
                "7",
            ],
        );
        assert_eq!(
            result.status.code(),
            Some(7),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("leaks found: 1"));
        reports.push(result.stdout);
    }
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
    assert!(String::from_utf8_lossy(&reports[0]).contains("\"secret.txt\""));
}

#[test]
fn stdin_scans_and_rejects_positional_arguments_before_side_effects() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let mut child = command(&fixture.0)
        .args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "-",
            "-f",
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
        .write_all(b"token=AB12\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.starts_with(b"["));

    fixture.write("report.json", b"preserve");
    let rejected = output(&fixture.0, &["stdin", "ignored", "-r", "report.json"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.0.join("report.json")).unwrap(),
        b"preserve"
    );
}

#[test]
fn extended_base64_mode_is_opt_in_and_respects_decode_depth() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    // Standard and URL-safe encodings of b"\xfftoken=AB12xx\xfe", with and
    // without padding. These literals are independent of the decoder under test.
    for encoded in [
        "/3Rva2VuPUFCMTJ4eP4=",
        "/3Rva2VuPUFCMTJ4eP4",
        "_3Rva2VuPUFCMTJ4eP4=",
        "_3Rva2VuPUFCMTJ4eP4",
    ] {
        fixture.write("encoded.txt", encoded);
        for (extra, expected_exit) in [
            (vec![], 0),
            (vec!["--base64-mode=compatible"], 0),
            (vec!["--base64-mode=extended"], 1),
            (vec!["--base64-mode=extended", "--max-decode-depth=0"], 0),
        ] {
            let result = command(&fixture.0)
                .args([
                    "dir",
                    "encoded.txt",
                    "--config=config.toml",
                    "--no-banner",
                    "--log-level=fatal",
                    "--report-path=-",
                    "--report-format=json",
                ])
                .args(extra)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(expected_exit),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report = String::from_utf8(result.stdout).unwrap();
            if expected_exit == 1 {
                assert!(report.contains("\"Secret\": \"AB12\""));
                assert_eq!(report.matches("\"RuleID\"").count(), 1);
            } else {
                assert_eq!(report.trim(), "[]");
            }
        }
    }
    let rejected = output(&fixture.0, &["stdin", "--base64-mode=unknown"]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("invalid value"));
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
fn embedded_default_emits_the_pinned_minimum_version_warning() {
    let fixture = Fixture::new();
    let result = output(&fixture.0, &["dir", ".", "--no-banner"]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains(
            "warn config requires a newer Gitleaks version... required=v8.25.0 current=0.1.0-alpha.9 config path=<embedded-default>"
        )
    );
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
fn selected_composite_logs_missing_required_rule_and_completes() {
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
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(fixture.0.join("report.json")).unwrap(), b"[]\n");
    assert!(String::from_utf8_lossy(&result.stderr).contains(
        "error required rule not found in config path=primary-rule rule-id=username-rule"
    ));
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
    let mut child = command(&fixture.0)
        .args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "--rustleaks-ignore-path",
            "custom.ignore",
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
        .write_all(b"token=AB12\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stderr).contains("no leaks found"));
}

#[test]
fn redaction_and_custom_zero_exit_are_applied_to_reports() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let mut child = command(&fixture.0)
        .args([
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
        .write_all(b"token=AB12\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
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
fn recoverable_source_issue_severity_distinguishes_corruption_from_limits() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    fixture.write("corrupt.gz", b"\x1f\x8bbad");
    let corrupt = output(
        &fixture.0,
        &[
            "dir",
            "corrupt.gz",
            "--no-banner",
            "-c",
            "config.toml",
            "--max-archive-depth",
            "1",
            "--log-level",
            "error",
        ],
    );
    assert_eq!(corrupt.status.code(), Some(0));
    let corrupt_stderr = String::from_utf8_lossy(&corrupt.stderr);
    assert!(
        corrupt_stderr
            .lines()
            .any(|line| line.starts_with("error source ") && line.contains("Decode")),
        "{corrupt_stderr}"
    );

    let oversized = fs::File::create(fixture.0.join("oversized.txt")).unwrap();
    oversized.set_len(1_000_001).unwrap();
    drop(oversized);
    let limited = output(
        &fixture.0,
        &[
            "dir",
            "oversized.txt",
            "--no-banner",
            "-c",
            "config.toml",
            "--max-target-megabytes",
            "1",
        ],
    );
    assert_eq!(limited.status.code(), Some(0));
    let limited_stderr = String::from_utf8_lossy(&limited.stderr);
    assert!(
        limited_stderr
            .lines()
            .any(|line| line.starts_with("warn source ") && line.contains("Limit/Limit")),
        "{limited_stderr}"
    );
}

#[test]
fn terminal_git_failure_writes_partial_report_then_exits_one() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    let result = output(
        &fixture.0,
        &[
            "git",
            "missing-repository",
            "--no-banner",
            "-c",
            "config.toml",
            "--platform",
            "none",
            "-r",
            "partial.json",
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(fixture.0.join("partial.json")).unwrap(), b"[]\n");
    assert!(String::from_utf8_lossy(&result.stderr).contains("partial scan"));
}

#[test]
fn git_history_worktree_and_staged_modes_use_native_process_arguments() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    git(&fixture.0, &["add", "secret.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "initial secret"]);

    let history = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--platform",
            "none",
            "-r",
            "history.json",
        ],
    );
    assert_eq!(history.status.code(), Some(1));
    assert!(
        fs::read(fixture.0.join("history.json"))
            .unwrap()
            .windows(b"AB12".len())
            .any(|value| value == b"AB12")
    );

    fixture.write("secret.txt", b"token=CD34\n");
    let worktree = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--pre-commit",
            "--platform",
            "not-consulted-in-diff-mode",
            "-r",
            "worktree.json",
        ],
    );
    assert_eq!(worktree.status.code(), Some(1));
    assert!(
        fs::read(fixture.0.join("worktree.json"))
            .unwrap()
            .windows(b"CD34".len())
            .any(|value| value == b"CD34")
    );

    git(&fixture.0, &["add", "secret.txt"]);
    let staged = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--staged",
            "-r",
            "staged.json",
        ],
    );
    assert_eq!(staged.status.code(), Some(1));
    assert!(
        fs::read(fixture.0.join("staged.json"))
            .unwrap()
            .windows(b"CD34".len())
            .any(|value| value == b"CD34")
    );
}

#[test]
fn scm_diagnostic_classes_obey_platform_resolution_and_log_levels() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", no_match_config());
    fixture.write("clean.txt", b"clean\n");
    git(&fixture.0, &["add", "clean.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "initial"]);
    git(
        &fixture.0,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/org/repo.git",
        ],
    );

    let unknown = output(
        &fixture.0,
        &["git", ".", "--no-banner", "-c", "config.toml"],
    );
    assert_eq!(unknown.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&unknown.stderr)
            .contains("info unknown SCM platform for host example.invalid; use --platform")
    );
    let suppressed = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "warn",
        ],
    );
    assert!(!String::from_utf8_lossy(&suppressed.stderr).contains("unknown SCM platform"));

    git(
        &fixture.0,
        &[
            "remote",
            "set-url",
            "origin",
            "https://github.com/org/repo.git",
        ],
    );
    let known = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "debug",
        ],
    );
    assert!(
        String::from_utf8_lossy(&known.stderr)
            .contains("info SCM platform github parsed from host github.com")
    );

    git(&fixture.0, &["remote", "remove", "origin"]);
    let absent = output(
        &fixture.0,
        &[
            "git",
            ".",
            "--no-banner",
            "-c",
            "config.toml",
            "--log-level",
            "debug",
        ],
    );
    assert!(
        String::from_utf8_lossy(&absent.stderr).contains("repository has no configured remote")
    );

    git(&fixture.0, &["remote", "add", "origin", "https://[bad"]);
    let malformed = output(
        &fixture.0,
        &["git", ".", "--no-banner", "-c", "config.toml"],
    );
    assert!(
        String::from_utf8_lossy(&malformed.stderr)
            .contains("error skipping finding links: unable to parse remote URL")
    );
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
    assert!(unknown_stderr.starts_with("Error: unknown flag: --unknown\nUsage:\n"));
    assert!(unknown_stderr.contains("rustleaks stdin [flags]"));
    assert!(!unknown_stderr.contains("fatal "));

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
fn paths_with_spaces_are_passed_without_a_shell() {
    let fixture = Fixture::new();
    fixture.write("config file.toml", matching_config());
    fixture.write("source dir/secret file.txt", b"token=AB12\n");
    let result = output(
        &fixture.0,
        &[
            "dir",
            "source dir",
            "--no-banner",
            "-c",
            "config file.toml",
            "-r",
            "report file.json",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = fs::read(fixture.0.join("report file.json")).unwrap();
    assert!(
        report
            .windows(b"secret file.txt".len())
            .any(|window| window == b"secret file.txt")
    );
}

#[cfg(unix)]
#[test]
fn native_non_utf8_config_and_source_paths_cross_the_process_boundary() {
    use std::os::unix::ffi::OsStringExt;

    let fixture = Fixture::new();
    let config = std::ffi::OsString::from_vec(b"config-\xfe.toml".to_vec());
    let source = std::ffi::OsString::from_vec(b"source-\xff.txt".to_vec());
    fixture.write("valid.toml", no_match_config());

    let missing_source = command(&fixture.0)
        .arg("dir")
        .arg(&source)
        .arg("--no-banner")
        .arg("-c")
        .arg("valid.toml")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&missing_source.stderr);
    assert!(!stderr.contains("must be valid UTF-8"), "{stderr}");
    assert!(stderr.contains("source Metadata/NotFound"), "{stderr}");

    let missing_config = command(&fixture.0)
        .arg("stdin")
        .arg("--no-banner")
        .arg("-c")
        .arg(&config)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&missing_config.stderr);
    assert!(!stderr.contains("requires a UTF-8 value"), "{stderr}");
    assert!(stderr.contains("could not read config"), "{stderr}");
}

#[test]
fn dash_separator_allows_a_source_beginning_with_dash() {
    let fixture = Fixture::new();
    fixture.write("config.toml", no_match_config());
    fixture.write("-source/file.txt", b"clean\n");
    let result = output(
        &fixture.0,
        &["dir", "--no-banner", "-c", "config.toml", "--", "-source"],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
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

#[test]
fn shorthand_unknown_is_not_the_unknown_long_exit_class() {
    let fixture = Fixture::new();
    let result = output(&fixture.0, &["stdin", "-x"]);
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.starts_with("Error: unknown shorthand flag: 'x' in -x\nUsage:\n"));
    assert!(stderr.ends_with("fatal unknown shorthand flag: 'x' in -x\n"));
    assert!(!result.status.success());
    assert_ne!(OsStr::new("-x"), OsStr::new("--x"));
}

mod complete_profile {
    use super::*;
    use std::io::{self, Cursor, Read};

    const PROFILE: &str = "version=1\ntarget_bytes=65536\noperation_original_bytes=1048576\noperation_fragments=100\noperation_issues=10\nworkers=1\nqueue_capacity=1\nfragment_decoded_bytes=1048576\noperation_decoded_bytes=1048576\nfragment_work_units=1000000\noperation_work_units=1000000\nfragment_finding_records=100\noperation_finding_records=100\nfragment_finding_payload_bytes=1048576\noperation_finding_payload_bytes=1048576\nfragment_collected_spans=1000\noperation_collected_spans=1000\nfragment_normalization_bytes=1048576\noperation_normalization_bytes=1048576\narchive_entries=100\narchive_member_bytes=65536\narchive_total_bytes=1048576\narchive_spool_bytes=65536\ngit_patch_bytes=1048576\ngit_patch_lines=10000\ngit_stderr_bytes=65536\ngit_blob_bytes=65536\ngit_metadata_bytes=65536\ngit_path_bytes=4096\ngit_files=100\ngit_hunks=100\nscm_link_bytes=4096\noperation_scm_link_bytes=8192\n";

    #[test]
    fn explicit_native_packs_are_independent_of_complete_target_selection() {
        let fixture = Fixture::new();
        profile(&fixture, &[]);
        let value = format!(
            "dckr_pat_{}",
            "Q7m2Z9v4L1c8R5s0N6b3X"
                .chars()
                .cycle()
                .take(27)
                .collect::<String>()
        );
        fixture.write("secret.txt", &value);
        let common = [
            "--native-pack",
            "rustleaks-providers-v1",
            "--enable-rule",
            "rustleaks.dockerhub-personal-access-token",
            "--complete-profile",
            "scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ];
        let mut child = command(&fixture.0)
            .args(["stdin"])
            .args(common)
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
        let input = child.wait_with_output().unwrap();
        assert_eq!(
            input.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&input.stderr)
        );
        assert!(status(&input.stderr).contains("status=complete"));
        let directory = command(&fixture.0)
            .args(["dir", "secret.txt"])
            .args(common)
            .output()
            .unwrap();
        assert_eq!(
            directory.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&directory.stderr)
        );
        assert!(status(&directory.stderr).contains("status=complete"));
        for result in [&input, &directory] {
            let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
            assert!(!report.was_null());
            let rows = report.entries();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].rule_id().as_bytes(),
                b"rustleaks.dockerhub-personal-access-token"
            );
        }
        let conflict = command(&fixture.0)
            .env("RUSTLEAKS_CONFIG_TOML", no_match_config())
            .args(["stdin"])
            .args(common)
            .output()
            .unwrap();
        assert_eq!(conflict.status.code(), Some(2));
        assert!(conflict.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&conflict.stderr)
                .contains("requires embedded-default configuration")
        );
    }

    fn profile(fixture: &Fixture, replacements: &[(&str, usize)]) {
        let text = PROFILE
            .lines()
            .map(|line| {
                let (key, _) = line.split_once('=').unwrap();
                replacements
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map_or_else(
                        || format!("{line}\n"),
                        |(_, value)| format!("{key}={value}\n"),
                    )
            })
            .collect::<String>();
        fixture.write("scan.limits", text);
    }

    fn arguments<'a>(command: &'a [&'a str]) -> Vec<&'a str> {
        let mut args = command.to_vec();
        args.extend([
            "--complete-profile",
            "scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--config",
            "config.toml",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ]);
        args
    }

    fn stdin(fixture: &Fixture, bytes: &[u8], extra: &[&str]) -> Output {
        let mut args = arguments(&["stdin"]);
        args.extend_from_slice(extra);
        let mut child = command(&fixture.0)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        child.wait_with_output().unwrap()
    }

    fn status(stderr: &[u8]) -> &str {
        let text = std::str::from_utf8(stderr).unwrap();
        let records = text
            .lines()
            .filter(|line| line.starts_with("rustleaks_scan_status "))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "{text}");
        records[0]
    }

    fn injected<R: Read + Send + 'static>(
        fixture: &Fixture,
        reader: R,
        extra: &[&str],
    ) -> (i32, Vec<u8>, Vec<u8>) {
        let mut args = arguments(&["stdin"]);
        args.extend_from_slice(extra);
        let environment = rustleaks_cli::RunEnvironment {
            cwd: fixture.0.clone(),
            config_path: None,
            config_toml: None,
            legacy_config_path: None,
            legacy_config_toml: None,
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = rustleaks_cli::run_from(
            args.into_iter().map(std::ffi::OsString::from),
            environment,
            reader,
            &mut stdout,
            &mut stderr,
        );
        (code, stdout, stderr)
    }

    #[test]
    fn clean_positive_exact_cap_and_overflow_have_distinct_status_and_exit() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[("target_bytes", 10)]);
        for (bytes, code, state) in [
            (&b"clean\n"[..], 0, "status=complete reason=complete"),
            (&b"token=AB12"[..], 1, "status=complete reason=complete"),
            (
                &b"token=AB12\n"[..],
                2,
                "status=incomplete reason=resource_exhaustion",
            ),
        ] {
            let result = stdin(&fixture, bytes, &[]);
            assert_eq!(
                result.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(status(&result.stderr).contains(state));
            if code == 2 {
                assert_eq!(result.stdout, b"[]\n");
            }
        }
        let redacted = stdin(&fixture, b"token=AB12", &["--redact", "--exit-code", "0"]);
        assert_eq!(redacted.status.code(), Some(0));
        assert!(status(&redacted.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&redacted.stdout).contains("REDACTED"));
        assert!(!String::from_utf8_lossy(&redacted.stdout).contains("AB12"));
        let incomplete = stdin(&fixture, b"token=AB12\n", &["--exit-code", "0"]);
        assert_eq!(incomplete.status.code(), Some(2));
    }

    #[test]
    fn invalid_profiles_and_conflicting_options_fail_before_input() {
        struct MustNotRead;
        impl Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("invalid profile read stdin")
            }
        }
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        for field in ["workers", "queue_capacity"] {
            profile(&fixture, &[(field, usize::MAX)]);
            let (code, stdout, stderr) = injected(&fixture, MustNotRead, &[]);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(status(&stderr).contains("reason=profile_error"));
        }
        for extra in [
            vec!["--exit-code", "2"],
            vec!["--max-target-megabytes", "1"],
        ] {
            profile(&fixture, &[]);
            let (code, stdout, stderr) = injected(&fixture, MustNotRead, &extra);
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(status(&stderr).contains("reason=profile_error"));
        }
        fixture.write(
            "scan.limits",
            format!("{PROFILE}private_value=synthetic-private-value\n"),
        );
        let (code, stdout, stderr) = injected(&fixture, MustNotRead, &[]);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert!(!String::from_utf8_lossy(&stderr).contains("synthetic-private-value"));
        assert!(status(&stderr).contains("reason=profile_error"));
    }

    #[test]
    fn engine_limits_discard_failed_fragment_and_report_exact_resource_scope() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[("fragment_finding_records", 1)]);
        let exact = stdin(&fixture, b"token=AB12\n", &[]);
        assert_eq!(exact.status.code(), Some(1));
        assert!(status(&exact.stderr).contains("finding_records=1"));
        let exceeded = stdin(&fixture, b"token=AB12\ntoken=CD34\n", &[]);
        assert_eq!(exceeded.status.code(), Some(2));
        assert_eq!(exceeded.stdout, b"[]\n");
        assert!(status(&exceeded.stderr).contains(
            "resource=finding_records budget_scope=fragment limit=1 consumed=1 requested=1"
        ));
        profile(&fixture, &[("operation_finding_records", 0)]);
        let exceeded = stdin(&fixture, b"token=AB12\n", &[]);
        assert_eq!(exceeded.status.code(), Some(2));
        assert!(status(&exceeded.stderr).contains(
            "resource=finding_records budget_scope=operation limit=0 consumed=0 requested=1"
        ));
        for (field, resource) in [
            ("fragment_work_units", "work_units"),
            ("fragment_collected_spans", "collected_spans"),
            ("fragment_finding_payload_bytes", "finding_payload_bytes"),
        ] {
            profile(&fixture, &[(field, 0)]);
            let exceeded = stdin(&fixture, b"token=AB12\n", &[]);
            assert_eq!(exceeded.status.code(), Some(2));
            assert_eq!(exceeded.stdout, b"[]\n");
            assert!(status(&exceeded.stderr).contains(&format!(
                "resource={resource} budget_scope=fragment limit=0"
            )));
        }
    }

    #[test]
    fn complete_directory_retains_prior_targets_and_marks_report_partial() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        fixture.write("inputs/a.txt", b"token=AB12");
        fixture.write("inputs/b.txt", b"token=CD34\n");
        profile(&fixture, &[("target_bytes", 10)]);
        let result = output(&fixture.0, &arguments(&["dir", "inputs"]));
        assert_eq!(result.status.code(), Some(2));
        let report = String::from_utf8_lossy(&result.stdout);
        assert!(report.contains("AB12"));
        assert!(!report.contains("CD34"));
        assert_eq!(report.matches("\"RuleID\"").count(), 1);
        assert!(status(&result.stderr).contains("status=incomplete"));
        assert!(status(&result.stderr).contains("reports=partial"));
        assert!(status(&result.stderr).contains("completed_fragments=1"));
    }

    #[test]
    fn read_error_discards_the_whole_target_and_report_write_failure_is_incomplete() {
        struct Failed {
            first: bool,
        }
        impl Read for Failed {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.first {
                    self.first = false;
                    output[..10].copy_from_slice(b"token=AB12");
                    Ok(10)
                } else {
                    Err(io::Error::other("synthetic read failure"))
                }
            }
        }
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[]);
        let (code, stdout, stderr) =
            injected(&fixture, Failed { first: true }, &["--exit-code", "0"]);
        assert_eq!(code, 2);
        assert_eq!(stdout, b"[]\n");
        assert!(status(&stderr).contains("reason=coverage_failure"));
        let (code, _, stderr) = injected(
            &fixture,
            Cursor::new(Vec::<u8>::new()),
            &["--report-path", "."],
        );
        assert_eq!(code, 2);
        assert!(status(&stderr).contains("reason=report_failure"));
    }

    #[test]
    fn normal_config_precedence_rule_selection_allowlists_and_ignore_remain_active() {
        let fixture = Fixture::new();
        profile(&fixture, &[]);
        fixture.write("config.toml", two_rule_config());
        let selected = stdin(
            &fixture,
            b"alpha=AB12\nbeta=CD34\n",
            &["--enable-rule", "alpha"],
        );
        assert_eq!(selected.status.code(), Some(1));
        let report = String::from_utf8_lossy(&selected.stdout);
        assert!(report.contains("AB12"));
        assert!(!report.contains("CD34"));
        fixture.write(".rustleaksignore", b":alpha:1\n");
        let ignored = stdin(&fixture, b"alpha=AB12\n", &[]);
        assert_eq!(ignored.status.code(), Some(0));
        assert_eq!(ignored.stdout, b"[]\n");
        fs::remove_file(fixture.0.join(".rustleaksignore")).unwrap();
        fixture.write(
            "config.toml",
            format!(
                "{}\n[allowlist]\npaths=['''excluded[.]txt$''']\n",
                matching_config()
            ),
        );
        fixture.write("inputs/excluded.txt", b"token=AB12\n");
        let excluded = output(&fixture.0, &arguments(&["dir", "inputs"]));
        assert_eq!(excluded.status.code(), Some(0));
        assert_eq!(excluded.stdout, b"[]\n");
        fixture.write(".rustleaks.toml", two_rule_config());
        let auto = output(
            &fixture.0,
            &[
                "dir",
                "inputs",
                "--complete-profile",
                "scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
            ],
        );
        assert_eq!(auto.status.code(), Some(0));
        fixture.write("inputs/active.txt", b"beta=CD34\n");
        let auto = output(
            &fixture.0,
            &[
                "dir",
                ".",
                "--complete-profile",
                "scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
                "--enable-rule",
                "beta",
            ],
        );
        assert_eq!(auto.status.code(), Some(1));
        let env_selected = command(&fixture.0)
            .env("RUSTLEAKS_CONFIG_TOML", no_match_config())
            .args([
                "dir",
                "inputs",
                "--complete-profile",
                "scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
            ])
            .output()
            .unwrap();
        assert_eq!(env_selected.status.code(), Some(0));
        assert!(status(&env_selected.stderr).contains("status=complete"));
    }

    #[test]
    fn scm_long_url_preflight_and_aggregate_limits_are_inclusive() {
        let fixture = Fixture::new();
        git(&fixture.0, &["init", "--quiet"]);
        git(&fixture.0, &["config", "user.name", "Complete CLI Test"]);
        git(
            &fixture.0,
            &["config", "user.email", "complete@example.invalid"],
        );
        fixture.write("config.toml", matching_config());
        fixture.write("secret%.txt", b"token=AB12\ntoken=CD34\n");
        git(&fixture.0, &["add", "secret%.txt"]);
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", "synthetic fixture"],
        );
        let remote = format!("https://example.invalid/{}", "x".repeat(6000));
        git(&fixture.0, &["remote", "add", "origin", &remote]);
        let length = remote.len() + b"/blob/".len() + 40 + b"/secret%25.txt#L1".len();
        let args = arguments(&["git", ".", "--platform", "github"]);
        profile(
            &fixture,
            &[
                ("scm_link_bytes", length),
                ("operation_scm_link_bytes", 2 * length),
            ],
        );
        let exact = output(&fixture.0, &args);
        assert_eq!(
            exact.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&exact.stderr)
        );
        assert!(status(&exact.stderr).contains("status=complete"));
        assert!(status(&exact.stderr).contains(&format!("scm_link_bytes={}", 2 * length)));
        assert_eq!(
            String::from_utf8_lossy(&exact.stdout)
                .matches("https://example.invalid/")
                .count(),
            2
        );
        profile(
            &fixture,
            &[
                ("scm_link_bytes", length - 1),
                ("operation_scm_link_bytes", 2 * length),
            ],
        );
        let per_link = output(&fixture.0, &args);
        assert_eq!(per_link.status.code(), Some(2));
        assert!(status(&per_link.stderr).contains("reason=metadata_failure"));
        assert!(status(&per_link.stderr).contains("resource=scm_link_bytes budget_scope=link"));
        assert!(!String::from_utf8_lossy(&per_link.stdout).contains("https://example.invalid/"));
        profile(
            &fixture,
            &[
                ("scm_link_bytes", length),
                ("operation_scm_link_bytes", 2 * length - 1),
            ],
        );
        let total = output(&fixture.0, &args);
        assert_eq!(total.status.code(), Some(2));
        assert!(status(&total.stderr).contains("resource=scm_link_bytes budget_scope=operation"));
        assert_eq!(
            String::from_utf8_lossy(&total.stdout)
                .matches("\"RuleID\"")
                .count(),
            2
        );
        assert_eq!(
            String::from_utf8_lossy(&total.stdout)
                .matches("https://example.invalid/")
                .count(),
            1
        );
        let disabled = output(&fixture.0, &arguments(&["git", ".", "--platform", "none"]));
        assert_eq!(disabled.status.code(), Some(1));
        assert!(status(&disabled.stderr).contains("status=complete"));
        git(
            &fixture.0,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/%invalid",
            ],
        );
        let invalid = output(&fixture.0, &args);
        assert_eq!(invalid.status.code(), Some(2));
        assert!(status(&invalid.stderr).contains("reason=metadata_failure"));
    }

    fn tar_leaf(bytes: &[u8]) -> Vec<u8> {
        tar_named_leaf(b"leaf.txt", bytes)
    }

    fn tar_named_leaf(name: &[u8], bytes: &[u8]) -> Vec<u8> {
        assert!(name.len() <= 100);
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name);
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| usize::from(*byte)).sum::<usize>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut archive = header.to_vec();
        archive.extend_from_slice(bytes);
        archive.resize(512 + bytes.len().div_ceil(512) * 512 + 1024, 0);
        archive
    }

    #[test]
    fn complete_profile_reaches_stdin_directory_and_git_archive_leaves() {
        let fixture = Fixture::new();
        fixture.write("config.toml", matching_config());
        profile(&fixture, &[("target_bytes", 10)]);
        let archive = tar_leaf(b"token=AB12");
        // Archive recognition uses the source name. Unnamed stdin remains a
        // plaintext target even when archive traversal is enabled.
        let input = stdin(&fixture, b"token=AB12", &["--max-archive-depth", "1"]);
        assert_eq!(
            input.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&input.stderr)
        );
        assert!(status(&input.stderr).contains("status=complete"));
        fixture.write("input.tar", &archive);
        let args = arguments(&["dir", "input.tar", "--max-archive-depth", "1"]);
        let dir = output(&fixture.0, &args);
        assert_eq!(
            dir.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&dir.stderr)
        );
        assert!(status(&dir.stderr).contains("status=complete"));
        git(&fixture.0, &["init", "--quiet"]);
        git(
            &fixture.0,
            &["config", "user.name", "Complete Archive Test"],
        );
        git(
            &fixture.0,
            &["config", "user.email", "archive@example.invalid"],
        );
        git(&fixture.0, &["add", "input.tar"]);
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", "synthetic archive"],
        );
        let history = output(
            &fixture.0,
            &arguments(&["git", ".", "--platform", "none", "--max-archive-depth", "1"]),
        );
        assert_eq!(
            history.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&history.stderr)
        );
        assert!(status(&history.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&history.stdout).contains("AB12"));
        fixture.write("input.tar", tar_leaf(b"token=AB12\n"));
        let exceeded = output(&fixture.0, &args);
        assert_eq!(exceeded.status.code(), Some(2));
        assert_eq!(exceeded.stdout, b"[]\n");
        assert!(status(&exceeded.stderr).contains("status=incomplete"));
        fixture.write("input.tar", b"\x1f\x8bbad");
        let corrupt = output(&fixture.0, &args);
        assert_eq!(corrupt.status.code(), Some(2));
        assert_eq!(corrupt.stdout, b"[]\n");
        assert!(status(&corrupt.stderr).contains("reason=coverage_failure"));
    }

    #[test]
    fn complete_control_files_are_excluded_before_the_source_cap() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("inputs/config.toml", matching_config());
        fixture.write("inputs/baseline.json", format!("[]{}", " ".repeat(100)));
        fixture.write("inputs/z.txt", b"token=AB12");
        let cwd = fixture.0.join("inputs");
        let common = [
            "--complete-profile",
            "../scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--config",
            "config.toml",
            "--baseline-path",
            "baseline.json",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ];
        for (source, count) in [("config.toml", 0), (".", 1)] {
            let result = command(&cwd)
                .args(["dir", source])
                .args(common)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(count),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(status(&result.stderr).contains("status=complete"));
            assert_eq!(
                String::from_utf8_lossy(&result.stdout)
                    .matches("\"RuleID\"")
                    .count(),
                usize::try_from(count).unwrap()
            );
        }
        fixture.write("inputs/config.toml.bak", b"token=CD34\n");
        let eligible = command(&cwd)
            .args(["dir", "."])
            .args(common)
            .output()
            .unwrap();
        assert_eq!(eligible.status.code(), Some(2));
        assert!(status(&eligible.stderr).contains("reason=resource_exhaustion"));
        fs::remove_file(cwd.join("config.toml.bak")).unwrap();
        fs::rename(cwd.join("config.toml"), cwd.join(".rustleaks.toml")).unwrap();
        let automatic = command(&cwd)
            .args([
                "dir",
                ".",
                "--complete-profile",
                "../scan.limits",
                "--no-banner",
                "--log-level",
                "fatal",
                "--baseline-path",
                "baseline.json",
                "--report-path",
                "-",
                "--report-format",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            automatic.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&automatic.stderr)
        );
        assert!(status(&automatic.stderr).contains("status=complete"));
        assert_eq!(
            String::from_utf8_lossy(&automatic.stdout)
                .matches("\"RuleID\"")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn complete_self_exclusions_compare_resolved_file_paths_not_symlink_aliases() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("inputs/config.toml", matching_config());
        fixture.write("inputs/z.txt", b"token=AB12");
        symlink("config.toml", fixture.0.join("inputs/alias")).unwrap();
        let common = [
            "dir",
            ".",
            "--complete-profile",
            "../scan.limits",
            "--no-banner",
            "--log-level",
            "fatal",
            "--config",
            "config.toml",
            "--follow-symlinks",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ];
        let cwd = fixture.0.join("inputs");
        let excluded = command(&cwd).args(common).output().unwrap();
        assert_eq!(
            excluded.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&excluded.stderr)
        );
        assert!(status(&excluded.stderr).contains("status=complete"));
        // Selecting the alias as --config excludes the alias spelling only;
        // emitted FilePath still names config.toml, as in the legacy route.
        let eligible = command(&cwd)
            .args(common)
            .args(["--config", "alias"])
            .output()
            .unwrap();
        assert_eq!(eligible.status.code(), Some(2));
        assert!(status(&eligible.stderr).contains("reason=resource_exhaustion"));
    }

    #[test]
    fn exact_control_path_exclusions_reach_directory_and_git_archive_leaves() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("outer.tar!leaf.txt", matching_config());
        fixture.write("outer.tar!leaf.txt.other", matching_config());
        let mut archive = tar_leaf(b"token=CD34\n");
        archive.truncate(archive.len() - 1024);
        archive.extend(tar_named_leaf(b"z.txt", b"token=AB12"));
        fixture.write("outer.tar", archive);
        let mut args = arguments(&["dir", "outer.tar", "--max-archive-depth", "1"]);
        args.extend(["--config", "outer.tar!leaf.txt"]);
        let selected = output(&fixture.0, &args);
        assert_eq!(
            selected.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&selected.stderr)
        );
        assert!(status(&selected.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&selected.stdout).contains("AB12"));
        assert!(!String::from_utf8_lossy(&selected.stdout).contains("CD34"));
        let environment = rustleaks_cli::RunEnvironment {
            cwd: fixture.0.clone(),
            config_path: None,
            config_toml: None,
            legacy_config_path: None,
            legacy_config_toml: None,
        };
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = rustleaks_cli::run_from(
            args.iter().copied().map(std::ffi::OsString::from),
            environment,
            Cursor::new(Vec::<u8>::new()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1, "{}", String::from_utf8_lossy(&stderr));
        assert!(status(&stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&stdout).contains("AB12"));
        let different = command(&fixture.0)
            .args(&args)
            .args(["--config", "outer.tar!leaf.txt.other"])
            .output()
            .unwrap();
        assert_eq!(different.status.code(), Some(2));
        git(&fixture.0, &["init", "--quiet"]);
        git(
            &fixture.0,
            &["config", "user.name", "Complete Exclusion Test"],
        );
        git(
            &fixture.0,
            &["config", "user.email", "exclusion@example.invalid"],
        );
        git(&fixture.0, &["add", "outer.tar"]);
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", "synthetic exclusion archive"],
        );
        let mut args = arguments(&["git", ".", "--platform", "none", "--max-archive-depth", "1"]);
        args.extend(["--config", "outer.tar!leaf.txt"]);
        let selected = output(&fixture.0, &args);
        assert_eq!(
            selected.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&selected.stderr)
        );
        assert!(status(&selected.stderr).contains("status=complete"));
        assert!(String::from_utf8_lossy(&selected.stdout).contains("AB12"));
        assert!(!String::from_utf8_lossy(&selected.stdout).contains("CD34"));
    }

    #[test]
    fn exact_exclusions_preserve_dot_slash_file_and_archive_spelling() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("inputs/config.toml", matching_config());
        fixture.write("inputs/z.txt", b"token=AB12");
        let cwd = fixture.0.join("inputs");
        for (source, config, expected) in [
            (".", "config.toml", 1),
            ("./", "config.toml", 2),
            ("./", "./config.toml", 1),
        ] {
            let result = command(&cwd)
                .args([
                    "dir",
                    source,
                    "--config",
                    config,
                    "--complete-profile",
                    "../scan.limits",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                status(&result.stderr).contains("status=complete"),
                expected == 1
            );
            if source == "./" && expected == 1 {
                assert!(String::from_utf8_lossy(&result.stdout).contains("./z.txt"));
            }
        }
        fixture.write("outer.tar!leaf.txt", matching_config());
        let mut archive = tar_leaf(b"token=CD34\n");
        archive.truncate(archive.len() - 1024);
        archive.extend(tar_named_leaf(b"z.txt", b"token=AB12"));
        fixture.write("outer.tar", archive);
        for (source, config, expected) in [
            ("outer.tar", "outer.tar!leaf.txt", 1),
            ("./outer.tar", "outer.tar!leaf.txt", 2),
            ("./outer.tar", "./outer.tar!leaf.txt", 1),
        ] {
            let result = command(&fixture.0)
                .args([
                    "dir",
                    source,
                    "--config",
                    config,
                    "--complete-profile",
                    "scan.limits",
                    "--max-archive-depth",
                    "1",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ])
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(expected),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                status(&result.stderr).contains("status=complete"),
                expected == 1
            );
        }
    }

    #[test]
    fn exact_self_exclusion_of_nested_container_does_not_hide_its_leaf() {
        let fixture = Fixture::new();
        profile(&fixture, &[("target_bytes", 10)]);
        fixture.write("outer.tar!inner.tar", matching_config());
        fixture.write("outer.tar!inner.tar!leaf.txt", matching_config());
        let inner = tar_leaf(b"token=AB12");
        fixture.write("outer.tar", tar_named_leaf(b"inner.tar", &inner));
        for (config, expected) in [
            ("outer.tar!inner.tar", 1),
            ("outer.tar!inner.tar!leaf.txt", 0),
        ] {
            for complete in [false, true] {
                let mut args = vec![
                    "dir",
                    "outer.tar",
                    "--config",
                    config,
                    "--max-archive-depth",
                    "2",
                    "--no-banner",
                    "--log-level",
                    "fatal",
                    "--report-path",
                    "-",
                    "--report-format",
                    "json",
                ];
                if complete {
                    args.extend(["--complete-profile", "scan.limits"]);
                }
                let result = output(&fixture.0, &args);
                assert_eq!(
                    result.status.code(),
                    Some(expected),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
                if complete {
                    assert!(status(&result.stderr).contains("status=complete"));
                }
                assert_eq!(
                    String::from_utf8_lossy(&result.stdout)
                        .matches("\"RuleID\"")
                        .count(),
                    usize::try_from(expected).unwrap()
                );
            }
        }
    }
}

mod native_packs {
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
        assert!(stderr.contains("native policy rustleaks-native-v1|"));
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
                let report =
                    rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
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
        assert!(String::from_utf8_lossy(&explicit.stderr).contains("selected from --config"));
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
            assert!(stderr.contains(&format!("selected from {key}")));
            assert!(!stderr.contains(marker));
            assert!(result.stdout.is_empty());
        }
        for filename in [".rustleaks.toml", ".gitleaks.toml"] {
            fixture.write(filename, &custom);
            for mode in [vec!["stdin"], vec!["dir", "."]] {
                let result = output(&fixture.0, &args(&mode));
                assert_eq!(result.status.code(), Some(1));
                assert!(
                    String::from_utf8_lossy(&result.stderr)
                        .contains("selected from source-local config")
                );
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
            (
                "unknown-private-sentinel",
                "unknown builtin native pack identifier",
            ),
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
}
