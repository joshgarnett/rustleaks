//! Directory, file and standard input scan tests.

use super::*;

/// A file that does not end with a newline: an allow comment on an earlier
/// line does not hide a secret on the last line, and the template `Line` of
/// that finding is only the last line, starting with the newline before it.
#[test]
fn allow_comments_on_earlier_lines_do_not_hide_a_last_line_without_newline() {
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    fixture.write(
        "report.tmpl",
        "{{ range . }}<{{ .File }}|{{ .Line }}>{{ end }}",
    );
    fixture.write("input/earlier.txt", "token=AB12 gitleaks:allow\ntoken=CD34");
    fixture.write("input/crlf.txt", "rustleaks:allow\r\nx\r\ntoken=EF56");
    fixture.write("input/last.txt", "x\ntoken=GH78 gitleaks:allow");
    fixture.write("input/single.txt", "token=IJ90 rustleaks:allow");
    let scan = |format: &[&str]| {
        let mut arguments = vec![
            "dir",
            "input",
            "--no-banner",
            "--log-level=fatal",
            "-c",
            "config.toml",
            "-r",
            "-",
        ];
        arguments.extend(format);
        let result = output(&fixture.0, &arguments);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        result
    };

    let mut rows = report_rows(&scan(&["-f", "json"]));
    rows.sort();
    let row = |file: &str, line: i128, secret: &str| {
        (
            "fixture-token".to_owned(),
            file.to_owned(),
            line,
            secret.to_owned(),
            String::new(),
        )
    };
    assert_eq!(
        rows,
        vec![
            row("input/crlf.txt", 3, "EF56"),
            row("input/earlier.txt", 2, "CD34"),
        ]
    );

    let template = scan(&["-f", "template", "--report-template", "report.tmpl"]);
    let text = String::from_utf8(template.stdout).unwrap();
    let mut lines = text
        .split_terminator('>')
        .map(|entry| entry.strip_prefix('<').unwrap())
        .collect::<Vec<_>>();
    lines.sort_unstable();
    assert_eq!(
        lines,
        vec![
            "input/crlf.txt|\ntoken=EF56",
            "input/earlier.txt|\ntoken=CD34"
        ]
    );
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
    let result = output_with_stdin(
        command(&fixture.0).args([
            "stdin",
            "--no-banner",
            "-c",
            "config.toml",
            "-r",
            "-",
            "-f",
            "json",
        ]),
        b"token=AB12\n",
    );
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
fn archive_depth_zero_reads_archive_named_files_as_text() {
    // Gitleaks skips these files unread at archive depth 0, because each name
    // contains an archive or compression extension. Rustleaks reads them as
    // plain text, so their secrets are reported.
    let fixture = Fixture::new();
    fixture.write("config.toml", matching_config());
    let names = [
        "docker-compose.branch.yml",
        "app.browser.js",
        "notes.zipper.txt",
        "data.gz.md",
        "plain.zip",
    ];
    for (index, name) in names.iter().enumerate() {
        fixture.write(name, format!("token=AB{index:02}\n"));
    }
    let result = output(
        &fixture.0,
        &[
            "dir",
            ".",
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
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut rows = report_rows(&result);
    rows.sort();
    let mut expected = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                "fixture-token".to_owned(),
                (*name).to_owned(),
                1,
                format!("AB{index:02}"),
                String::new(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(rows, expected);
}

#[test]
fn default_rules_hide_hash_like_values_and_keep_real_formats() {
    // The default rules hide a 32-character hex digest under a name with md5
    // and still report a GitHub token in its documented layout. A
    // configuration that does not extend the default rules gets none of
    // their allowlists, so its generic rule reports the digest. Values are
    // built from fixed steps through their alphabets, so this file holds no
    // credential-shaped text.
    let cycle = |alphabet: &[u8], step: usize, start: usize, length: usize| {
        (0..length)
            .map(|index| char::from(alphabet[(index * step + start) % alphabet.len()]))
            .collect::<String>()
    };
    let digest = cycle(b"0123456789abcdef", 7, 3, 32);
    let token = format!(
        "gh{}_{}",
        "p",
        cycle(
            b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            7,
            5,
            36
        )
    );
    let fixture = Fixture::new();
    fixture.write("hash.env", format!("token_md5 = {digest}\n"));
    fixture.write("token.env", format!("GITHUB_TOKEN={token}\n"));
    let scan = |config: Option<&str>| {
        let mut arguments = vec![
            "dir",
            ".",
            "--no-banner",
            "--report-path",
            "-",
            "--report-format",
            "json",
            "--log-level",
            "fatal",
        ];
        if let Some(config) = config {
            arguments.extend(["-c", config]);
        }
        let result = output(&fixture.0, &arguments);
        assert_eq!(
            result.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut rows = report_rows(&result);
        rows.sort();
        rows
    };
    let github = (
        "github-pat".to_owned(),
        "token.env".to_owned(),
        1,
        token.clone(),
        String::new(),
    );
    assert_eq!(scan(None), vec![github.clone()]);
    fixture.write(
        "standalone.toml",
        "[[rules]]\nid = \"generic-api-key\"\nregex = '''token_md5 = ([0-9a-f]{32})'''\nsecretGroup = 1\n",
    );
    let generic = (
        "generic-api-key".to_owned(),
        "hash.env".to_owned(),
        1,
        digest,
        String::new(),
    );
    assert_eq!(scan(Some("standalone.toml")), vec![generic]);
}
