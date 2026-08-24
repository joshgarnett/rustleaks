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
            "warn config requires a newer Gitleaks version... required=v8.25.0 current=0.1.0-alpha.1 config path=<embedded-default>"
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
