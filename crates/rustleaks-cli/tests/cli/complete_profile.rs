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
    let input = output_with_stdin(
        command(&fixture.0).args(["stdin"]).args(common),
        value.as_bytes(),
    );
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
            .contains("works only with the default configuration")
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
    output_with_stdin(command(&fixture.0).args(args), bytes)
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
        ..rustleaks_cli::RunEnvironment::default()
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
    assert!(
        status(&exceeded.stderr).contains(
            "resource=finding_records budget_scope=fragment limit=1 consumed=1 requested=1"
        )
    );
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
    let (code, stdout, stderr) = injected(&fixture, Failed { first: true }, &["--exit-code", "0"]);
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

struct ArchiveCase {
    name: &'static str,
    depth: &'static str,
    code: i32,
    state: &'static str,
    reason: &'static str,
    reports: &'static str,
    fragments: usize,
    issues: usize,
    files: &'static [&'static str],
    diagnostic: &'static str,
}

const ARCHIVE_CASES: &[ArchiveCase] = &[
    ArchiveCase {
        name: "partial.tar",
        depth: "1",
        code: 2,
        state: "incomplete",
        reason: "coverage_failure",
        reports: "partial",
        fragments: 1,
        issues: 0,
        files: &["partial.tar!first.txt"],
        diagnostic: "truncated TAR member",
    },
    // Archives stream: the whole leaf is scanned before the gzip
    // trailer after the TAR end fails its CRC check.
    ArchiveCase {
        name: "corrupt.tgz",
        depth: "1",
        code: 2,
        state: "incomplete",
        reason: "coverage_failure",
        reports: "partial",
        fragments: 1,
        issues: 0,
        files: &["corrupt.tgz!leaf.txt"],
        diagnostic: "gzip size or CRC mismatch",
    },
    ArchiveCase {
        name: "outer.tgz",
        depth: "2",
        code: 0,
        state: "complete",
        reason: "complete",
        reports: "complete",
        fragments: 0,
        issues: 2,
        files: &[],
        diagnostic: "skipping archive: exceeds maximum archive depth",
    },
    ArchiveCase {
        name: "outer.tgz",
        depth: "3",
        code: 1,
        state: "complete",
        reason: "complete",
        reports: "complete",
        fragments: 2,
        issues: 0,
        files: &[
            "outer.tgz!wrapper.tgz!left.tgz!leaf.txt",
            "outer.tgz!wrapper.tgz!right.tgz!leaf.txt",
        ],
        diagnostic: "",
    },
    ArchiveCase {
        name: "outer.tar",
        depth: "2",
        code: 0,
        state: "complete",
        reason: "complete",
        reports: "complete",
        fragments: 0,
        issues: 2,
        files: &[],
        diagnostic: "skipping archive: exceeds maximum archive depth",
    },
    ArchiveCase {
        name: "outer.tar",
        depth: "3",
        code: 1,
        state: "complete",
        reason: "complete",
        reports: "complete",
        fragments: 2,
        issues: 0,
        files: &[
            "outer.tar!wrapper.tar!left.tar!leaf.txt",
            "outer.tar!wrapper.tar!right.tar!leaf.txt",
        ],
        diagnostic: "",
    },
    ArchiveCase {
        name: "outer.zip",
        depth: "2",
        code: 0,
        state: "complete",
        reason: "complete",
        reports: "complete",
        fragments: 0,
        issues: 2,
        files: &[],
        diagnostic: "skipping archive: exceeds maximum archive depth",
    },
    ArchiveCase {
        name: "outer.zip",
        depth: "3",
        code: 1,
        state: "complete",
        reason: "complete",
        reports: "complete",
        fragments: 2,
        issues: 0,
        files: &[
            "outer.zip!wrapper.zip!left.zip!leaf.txt",
            "outer.zip!wrapper.zip!right.zip!leaf.txt",
        ],
        diagnostic: "",
    },
    ArchiveCase {
        name: "checksum.tar",
        depth: "1",
        code: 2,
        state: "incomplete",
        reason: "coverage_failure",
        reports: "partial",
        fragments: 0,
        issues: 0,
        files: &[],
        diagnostic: "invalid TAR header checksum",
    },
    ArchiveCase {
        name: "crc.zip",
        depth: "1",
        code: 2,
        state: "incomplete",
        reason: "coverage_failure",
        reports: "partial",
        fragments: 0,
        issues: 0,
        files: &[],
        diagnostic: "ZIP member size or CRC mismatch",
    },
    ArchiveCase {
        name: "noend.zip",
        depth: "1",
        code: 2,
        state: "incomplete",
        reason: "coverage_failure",
        reports: "partial",
        fragments: 0,
        issues: 0,
        files: &[],
        diagnostic: "",
    },
    // The cut is after the whole leaf, in the TAR end blocks.
    ArchiveCase {
        name: "half.tgz",
        depth: "1",
        code: 2,
        state: "incomplete",
        reason: "coverage_failure",
        reports: "partial",
        fragments: 1,
        issues: 0,
        files: &["half.tgz!leaf.txt"],
        diagnostic: "",
    },
];

fn assert_archive_case(case: &ArchiveCase, result: &Output) {
    let ArchiveCase {
        name,
        depth,
        code,
        state,
        reason,
        reports,
        fragments,
        issues,
        files,
        diagnostic,
    } = *case;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(code), "{name}/{depth}: {stderr}");
    let fields = status(&result.stderr)
        .split_whitespace()
        .collect::<Vec<_>>();
    for expected in [
        format!("status={state}"),
        format!("reason={reason}"),
        format!("reports={reports}"),
        "source_scope=directory_targets".to_owned(),
        "resource=none".to_owned(),
        "budget_scope=none".to_owned(),
        "usage=available".to_owned(),
        "usage_exact=1".to_owned(),
        format!("archive_depth={depth}"),
        format!("findings={fragments}"),
        format!("original_bytes={}", fragments * 10),
        format!("fragments={fragments}"),
        format!("completed_fragments={fragments}"),
        format!("issues={issues}"),
    ] {
        assert!(fields.contains(&expected.as_str()), "{expected}: {stderr}");
    }
    let report = rustleaks_core::session::Baseline::from_go_json(&result.stdout).unwrap();
    assert!(!report.was_null());
    let rows = report.entries();
    assert_eq!(rows.len(), files.len());
    let mut actual_files = rows
        .iter()
        .map(|row| row.file().as_bytes())
        .collect::<Vec<_>>();
    actual_files.sort_unstable();
    let mut expected_files = files.iter().map(|file| file.as_bytes()).collect::<Vec<_>>();
    expected_files.sort_unstable();
    assert_eq!(actual_files, expected_files);
    for row in rows {
        assert_eq!(row.rule_id().as_bytes(), b"fixture-token");
        assert_eq!(row.start_line(), 1);
        assert_eq!(row.end_line(), 1);
        assert_eq!(row.start_column(), 1);
        assert_eq!(row.end_column(), 10);
        assert_eq!(row.match_text().as_bytes(), b"token=AB12");
        assert_eq!(row.secret().as_bytes(), b"AB12");
    }
    if !diagnostic.is_empty() {
        assert!(stderr.contains(diagnostic), "{stderr}");
    }
}

#[test]
fn complete_archive_status_distinguishes_partial_members_and_depth_exclusions() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    profile(&fixture, &[]);
    let mut partial = tar_named_leaf(b"first.txt", b"token=AB12");
    partial.truncate(partial.len() - 1024);
    partial.extend(tar_named_leaf(b"second.txt", b"token=CD34"));
    partial.truncate(1024 + 512 + 7);
    fixture.write("partial.tar", partial);
    let inner = stored_gzip(&tar_leaf(b"token=AB12"));
    let mut corrupt = inner.clone();
    let crc = corrupt.len() - 8;
    corrupt[crc] ^= 1;
    fixture.write("corrupt.tgz", corrupt);
    let mut siblings = tar_named_leaf(b"left.tgz", &inner);
    siblings.truncate(siblings.len() - 1024);
    siblings.extend(tar_named_leaf(b"right.tgz", &inner));
    let middle = stored_gzip(&siblings);
    let outer = stored_gzip(&tar_named_leaf(b"wrapper.tgz", &middle));
    fixture.write("outer.tgz", outer);
    let leaf_tar = tar_leaf(b"token=AB12");
    let mut tar_siblings = tar_named_leaf(b"left.tar", &leaf_tar);
    tar_siblings.truncate(tar_siblings.len() - 1024);
    tar_siblings.extend(tar_named_leaf(b"right.tar", &leaf_tar));
    fixture.write("outer.tar", tar_named_leaf(b"wrapper.tar", &tar_siblings));
    let leaf_zip = stored_zip(&[(b"leaf.txt", b"token=AB12")]);
    let middle_zip = stored_zip(&[(b"left.zip", &leaf_zip), (b"right.zip", &leaf_zip)]);
    fixture.write("outer.zip", stored_zip(&[(b"wrapper.zip", &middle_zip)]));
    let mut checksum = leaf_tar.clone();
    checksum[148] ^= 1;
    fixture.write("checksum.tar", checksum);
    // Data starts after the 30-byte local header and the 8-byte name, so
    // byte 47 is the final '2' of the leaf. Both stored CRCs stay intact.
    let mut crc = leaf_zip.clone();
    assert_eq!(crc[47], b'2');
    crc[47] ^= 1;
    fixture.write("crc.zip", crc);
    // Drop exactly the 22-byte end of central directory record.
    fixture.write("noend.zip", &leaf_zip[..leaf_zip.len() - 22]);
    let half = stored_gzip(&leaf_tar);
    fixture.write("half.tgz", &half[..half.len() / 2]);
    for case in ARCHIVE_CASES {
        let command_args = ["dir", case.name, "--max-archive-depth", case.depth];
        let mut args = arguments(&command_args);
        args.extend(["--log-level", "info"]);
        assert_archive_case(case, &output(&fixture.0, &args));
    }
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
        ..rustleaks_cli::RunEnvironment::default()
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
