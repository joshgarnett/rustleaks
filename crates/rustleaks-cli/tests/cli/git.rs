//! Git history, staged and pre-commit scan tests.

use super::*;

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
fn staged_and_pre_commit_scan_different_sides_of_the_index() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    // The config is never added, so it is in no diff or commit.
    fixture.write("config.toml", matching_config());
    fixture.write("secret.txt", b"token=AB12\n");
    git(&fixture.0, &["add", "secret.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "c1"]);
    let c1 = git_stdout(&fixture.0, &["rev-parse", "HEAD"]);
    // HEAD has AB12, the index has CD34 and the worktree has EF56.
    fixture.write("secret.txt", b"token=CD34\n");
    git(&fixture.0, &["add", "secret.txt"]);
    fixture.write("secret.txt", b"token=EF56\n");

    for (mode, secret, commit, absent) in [
        ("--staged", "CD34", "", &["AB12", "EF56"]),
        ("--pre-commit", "EF56", "", &["AB12", "CD34"]),
        ("--platform=none", "AB12", c1.as_str(), &["CD34", "EF56"]),
    ] {
        let result = output(
            &fixture.0,
            &[
                "git",
                ".",
                mode,
                "--no-banner",
                "-c",
                "config.toml",
                "--report-path",
                "-",
                "--report-format",
                "json",
                "--log-level",
                "fatal",
            ],
        );
        let stdout = String::from_utf8_lossy(&result.stdout);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{mode}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            report_rows(&result),
            [(
                "fixture-token".to_owned(),
                "secret.txt".to_owned(),
                1,
                secret.to_owned(),
                commit.to_owned(),
            )],
            "{mode}"
        );
        for value in absent {
            assert!(!stdout.contains(value), "{mode}");
        }
    }
}

/// `.gitattributes` that marks a text file as binary does not hide it from
/// history and staged scans. A worktree diff (`--pre-commit`) keeps the
/// attributes, so there the file stays binary and is not scanned.
#[test]
fn attributes_that_mark_text_as_binary_do_not_hide_history_findings() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", matching_config());
    fixture.write(".gitattributes", b"*.txt -diff\n");
    fixture.write("secret.txt", b"token=AB12\n");
    git(&fixture.0, &["add", ".gitattributes", "secret.txt"]);
    git(&fixture.0, &["commit", "--quiet", "-m", "c1"]);
    let c1 = git_stdout(&fixture.0, &["rev-parse", "HEAD"]);
    fixture.write("secret.txt", b"token=CD34\n");
    git(&fixture.0, &["add", "secret.txt"]);
    fixture.write("secret.txt", b"token=EF56\n");

    let row = |secret: &str, commit: &str| {
        (
            "fixture-token".to_owned(),
            "secret.txt".to_owned(),
            1,
            secret.to_owned(),
            commit.to_owned(),
        )
    };
    for (mode, code, rows) in [
        ("--platform=none", 1, vec![row("AB12", &c1)]),
        ("--log-opts=--all", 1, vec![row("AB12", &c1)]),
        ("--staged", 1, vec![row("CD34", "")]),
        ("--pre-commit", 0, Vec::new()),
    ] {
        let result = output(
            &fixture.0,
            &[
                "git",
                ".",
                mode,
                "--no-banner",
                "-c",
                "config.toml",
                "--report-path",
                "-",
                "--report-format",
                "json",
                "--log-level",
                "fatal",
            ],
        );
        assert_eq!(
            result.status.code(),
            Some(code),
            "{mode}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(report_rows(&result), rows, "{mode}");
    }
}

#[test]
fn log_opts_range_attributes_a_finding_to_its_commit() {
    let fixture = Fixture::new();
    git(&fixture.0, &["init", "--quiet"]);
    git(&fixture.0, &["config", "user.name", "CLI Test"]);
    git(&fixture.0, &["config", "user.email", "cli@example.invalid"]);
    fixture.write("config.toml", matching_config());
    let mut commits = vec![String::new()];
    let mut notes = String::new();
    for k in 1..=8 {
        let _ = writeln!(notes, "entry {k}");
        fixture.write("notes.txt", &notes);
        git(&fixture.0, &["add", "notes.txt"]);
        // Only commit 5 adds the token line.
        if k == 5 {
            fixture.write("secret.txt", b"token=AB12\n");
            git(&fixture.0, &["add", "secret.txt"]);
        }
        git(
            &fixture.0,
            &["commit", "--quiet", "-m", &format!("commit {k}")],
        );
        commits.push(git_stdout(&fixture.0, &["rev-parse", "HEAD"]));
    }
    let row = (
        "fixture-token".to_owned(),
        "secret.txt".to_owned(),
        1,
        "AB12".to_owned(),
        commits[5].clone(),
    );

    for (range, code, rows) in [
        (Some((4, 6)), 1, vec![row.clone()]),
        (Some((5, 8)), 0, Vec::new()),
        (None, 1, vec![row.clone()]),
    ] {
        let log_opts =
            range.map(|(from, to)| format!("--log-opts={}..{}", commits[from], commits[to]));
        let mut arguments = vec![
            "git",
            ".",
            "--platform",
            "none",
            "--no-banner",
            "-c",
            "config.toml",
            "--report-path",
            "-",
            "--report-format",
            "json",
            "--log-level",
            "fatal",
        ];
        arguments.extend(log_opts.as_deref());
        let result = output(&fixture.0, &arguments);
        assert_eq!(
            result.status.code(),
            Some(code),
            "{range:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(report_rows(&result), rows, "{range:?}");
        if rows.is_empty() {
            assert_eq!(result.stdout, b"[]\n");
        }
    }
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
