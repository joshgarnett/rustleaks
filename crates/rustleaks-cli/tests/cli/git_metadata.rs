use super::*;

/// A synthetic Bitbucket credential URL. No real account uses it.
const CREDENTIAL_URL: &str =
    "https://synthetic7:Q4w8E2r6T1y9U3i5O7p0AsDf@bitbucket.org/workspace/repository.git";

/// A checkout whose `.git` folder holds the credential URL in `config`
/// and the same text in an object file, the index and a lock file.
fn checkout() -> Fixture {
    let fixture = Fixture::new();
    fixture.write("repo/README.md", "no secrets here\n");
    let config = format!("[remote \"origin\"]\n\turl = {CREDENTIAL_URL}\n");
    fixture.write("repo/.git/config", &config);
    fixture.write("repo/.git/config.lock", &config);
    fixture.write("repo/.git/index", &config);
    fixture.write("repo/.git/objects/ab/cdef0123456789", &config);
    fixture.write("repo/.git/HEAD", "ref: refs/heads/main\n");
    fixture
}

fn scan(fixture: &Fixture, extra: &[&str]) -> Output {
    command(&fixture.0)
        .args([
            "dir",
            "repo",
            "--native-pack",
            "rustleaks-connections-v1",
            "--no-banner",
            "--log-level",
            "fatal",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ])
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn git_folders_are_skipped_without_the_flag() {
    let fixture = checkout();
    for extra in [&[][..], &["--scan-git-metadata=false"][..]] {
        let result = scan(&fixture, extra);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{extra:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(report_rows(&result).is_empty(), "{extra:?}");
    }
}

#[test]
fn the_flag_reports_a_credential_url_in_git_config_only() {
    let fixture = checkout();
    let result = scan(&fixture, &["--scan-git-metadata"]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        report_rows(&result),
        [(
            "rustleaks.bitbucket-git-credentials".to_owned(),
            "repo/.git/config".to_owned(),
            2,
            CREDENTIAL_URL.to_owned(),
            String::new(),
        )]
    );
}

#[test]
fn the_flag_works_with_a_complete_profile() {
    let fixture = checkout();
    fixture.write(
            "scan.limits",
            "version=1\ntarget_bytes=65536\noperation_original_bytes=1048576\noperation_fragments=100\noperation_issues=10\nworkers=1\nqueue_capacity=1\nfragment_decoded_bytes=1048576\noperation_decoded_bytes=1048576\nfragment_work_units=1000000\noperation_work_units=1000000\nfragment_finding_records=100\noperation_finding_records=100\nfragment_finding_payload_bytes=1048576\noperation_finding_payload_bytes=1048576\nfragment_collected_spans=1000\noperation_collected_spans=1000\nfragment_normalization_bytes=1048576\noperation_normalization_bytes=1048576\narchive_entries=100\narchive_member_bytes=65536\narchive_total_bytes=1048576\narchive_spool_bytes=65536\ngit_patch_bytes=1048576\ngit_patch_lines=10000\ngit_stderr_bytes=65536\ngit_blob_bytes=65536\ngit_metadata_bytes=65536\ngit_path_bytes=4096\ngit_files=100\ngit_hunks=100\nscm_link_bytes=4096\noperation_scm_link_bytes=8192\n",
        );
    let result = scan(
        &fixture,
        &["--scan-git-metadata", "--complete-profile", "scan.limits"],
    );
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.lines().any(|line| {
            line.starts_with("rustleaks_scan_status ") && line.contains("status=complete")
        }),
        "{stderr}"
    );
    let rows = report_rows(&result);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "repo/.git/config");
}

#[test]
fn the_flag_respects_the_size_limit() {
    let fixture = checkout();
    let mut large = format!("[remote \"origin\"]\n\turl = {CREDENTIAL_URL}\n");
    large.push_str(&"#\n".repeat(600_000));
    fixture.write("repo/.git/config", &large);
    let result = scan(
        &fixture,
        &[
            "--scan-git-metadata",
            "--max-target-megabytes",
            "1",
            "--log-level",
            "warn",
        ],
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(0), "{stderr}");
    assert!(report_rows(&result).is_empty());
    // The file was reached and then skipped by the size limit.
    let skipped = stderr
        .lines()
        .filter(|line| line.contains("exceeds maximum file size"))
        .collect::<Vec<_>>();
    assert_eq!(skipped.len(), 1, "{stderr}");
    // Windows reports the path with backslashes.
    assert!(
        skipped[0].replace('\\', "/").contains("repo/.git/config"),
        "{stderr}"
    );
}

#[test]
fn a_git_folder_given_as_the_scan_path_is_scanned_in_full() {
    let fixture = checkout();
    let scan_root = |extra: &[&str]| {
        command(&fixture.0)
            .args([
                "dir",
                "repo/.git",
                "--native-pack",
                "rustleaks-connections-v1",
                "--no-banner",
                "--log-level",
                "fatal",
                "--report-path",
                "-",
                "--report-format",
                "json",
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    // The scan path itself is not matched by the default `.git` folder
    // entry, so the folder is scanned in full either way. The pack rule's
    // path condition keeps the finding to `config`.
    let expected = [(
        "rustleaks.bitbucket-git-credentials".to_owned(),
        "repo/.git/config".to_owned(),
        2,
        CREDENTIAL_URL.to_owned(),
        String::new(),
    )];
    for result in [scan_root(&[]), scan_root(&["--scan-git-metadata"])] {
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(report_rows(&result), expected);
    }
}

#[test]
fn the_flag_belongs_to_the_dir_command_only() {
    let fixture = Fixture::new();
    for command_name in ["git", "stdin"] {
        let result = output(&fixture.0, &[command_name, "--scan-git-metadata"]);
        assert_eq!(result.status.code(), Some(126), "{command_name}");
    }
}
