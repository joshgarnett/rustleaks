//! The number of detection threads must not change findings, reports, exit
//! codes or log lines. Each scan below runs with every thread count and report
//! format, and the outputs are compared byte for byte. The expected findings
//! come from the planted inputs, not from scanner output.

use super::*;

/// One thread, a few, more than the 64 that a profile allows, and no flag,
/// which uses one thread for each CPU.
const JOBS: &[Option<&str>] = &[Some("1"), Some("2"), Some("4"), Some("128"), None];
const FORMATS: &[&str] = &["json", "csv", "sarif", "junit", "template"];
const CONFIG: &str = "title='jobs'\n[[rules]]\nid='jobs-token'\ndescription='jobs token'\nregex='''token=([A-Z0-9]{8})'''\nsecretGroup=1\nkeywords=['token']\n[[rules]]\nid='jobs-key'\ndescription='jobs key'\nregex='''key-[a-f0-9]{12}'''\nkeywords=['key-']\n";
const TEMPLATE: &str = "{{ range . }}{{ .RuleID }} {{ .File }} {{ .StartLine }} {{ .Secret }} {{ .Fingerprint }}\n{{ end }}";
const FILLER: &str = "filler text with no secret value in it, only padding for size";
const PROFILE: &str = "version=1\ntarget_bytes=1048576\noperation_original_bytes=67108864\noperation_fragments=100000\noperation_issues=100\nworkers=1\nqueue_capacity=4\nfragment_decoded_bytes=16777216\noperation_decoded_bytes=268435456\nfragment_work_units=100000000\noperation_work_units=1000000000\nfragment_finding_records=10000\noperation_finding_records=100000\nfragment_finding_payload_bytes=16777216\noperation_finding_payload_bytes=268435456\nfragment_collected_spans=100000\noperation_collected_spans=1000000\nfragment_normalization_bytes=67108864\noperation_normalization_bytes=1073741824\narchive_entries=1000\narchive_member_bytes=1048576\narchive_total_bytes=16777216\narchive_spool_bytes=16777216\ngit_patch_bytes=16777216\ngit_patch_lines=1000000\ngit_stderr_bytes=65536\ngit_blob_bytes=1048576\ngit_metadata_bytes=65536\ngit_path_bytes=4096\ngit_files=1000\ngit_hunks=10000\nscm_link_bytes=4096\noperation_scm_link_bytes=65536\n";

type Row = (String, String, i128, String, String);

fn token(file: &str, line: usize, secret: &str, commit: &str) -> Row {
    (
        "jobs-token".to_owned(),
        file.to_owned(),
        i128::try_from(line).unwrap(),
        secret.to_owned(),
        commit.to_owned(),
    )
}

fn fixture() -> Fixture {
    let fixture = Fixture::new();
    fixture.write("config.toml", CONFIG);
    fixture.write("report.tmpl", TEMPLATE);
    fixture
}

/// A TAR archive with these members, in order.
fn tar(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    for (name, body) in members {
        let member = tar_named_leaf(name, body);
        archive.extend_from_slice(&member[..member.len() - 1024]);
    }
    archive.resize(archive.len() + 1024, 0);
    archive
}

/// Text of `lines` filler lines with a token line at each planted
/// one-based line number.
fn planted(lines: usize, plants: &[(usize, String)]) -> String {
    let mut text = String::new();
    for line in 1..=lines {
        match plants.iter().find(|(planted, _)| *planted == line) {
            Some((_, secret)) => {
                let _ = writeln!(text, "value token={secret} end");
            }
            None => {
                let _ = writeln!(text, "{FILLER} {line}");
            }
        }
    }
    text
}

/// Log lines without the elapsed time, the only part that changes between
/// two identical scans.
fn stable_log(stderr: &[u8]) -> String {
    String::from_utf8(stderr.to_vec())
        .unwrap()
        .lines()
        .map(|line| {
            if line.starts_with("info scanned ~")
                || line.starts_with("warn partial scan completed in ")
            {
                line.rsplit_once(" in ").map_or(line, |(head, _)| head)
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn scan(fixture: &Fixture, arguments: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = command(&fixture.0)
        .args(arguments)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(bytes) = stdin {
        let mut input = child.stdin.take().unwrap();
        // A failed write shows up in the exit status check.
        let _ = input.write_all(bytes);
    }
    child.wait_with_output().unwrap()
}

/// Runs the scan with every thread count and report format, checks that
/// each format gives the same report, exit status and log lines for every
/// count, and returns the JSON report rows and the log lines.
fn same_for_every_count(
    fixture: &Fixture,
    scan_arguments: &[&str],
    stdin: Option<&[u8]>,
    exit: i32,
) -> (Vec<Row>, String) {
    let mut rows = Vec::new();
    let mut log = String::new();
    for &format in FORMATS {
        let mut first: Option<(Vec<u8>, String)> = None;
        for &jobs in JOBS {
            let mut arguments = scan_arguments.to_vec();
            arguments.extend([
                "--no-banner",
                "--config",
                "config.toml",
                "--exit-code",
                "7",
                "--report-path",
                "-",
                "--report-format",
                format,
            ]);
            if format == "template" {
                arguments.extend(["--report-template", "report.tmpl"]);
            }
            if let Some(jobs) = jobs {
                arguments.extend(["--jobs", jobs]);
            }
            let result = scan(fixture, &arguments, stdin);
            let stderr = stable_log(&result.stderr);
            assert_eq!(result.status.code(), Some(exit), "{arguments:?}: {stderr}");
            assert!(!result.stdout.is_empty(), "{arguments:?}");
            match &first {
                None => first = Some((result.stdout, stderr)),
                Some((report, first_log)) => {
                    assert!(
                        *report == result.stdout,
                        "{format} report differs with --jobs {jobs:?}"
                    );
                    assert_eq!(*first_log, stderr, "{format} log with --jobs {jobs:?}");
                }
            }
        }
        let (report, first_log) = first.unwrap();
        if format == "json" {
            rows = json_report_rows(&report);
            log = first_log;
        } else {
            assert_eq!(log, first_log, "{format} log differs from the JSON run");
        }
    }
    (rows, log)
}

fn sorted(mut rows: Vec<Row>) -> Vec<Row> {
    rows.sort();
    rows
}

/// Plants 300 files in six folders. Every tenth file is about 280 KB, so it
/// is scanned in three pieces. Returns the expected findings.
fn plant_folders(fixture: &Fixture) -> Vec<Row> {
    let mut expected = Vec::new();
    for folder in 0..6 {
        for file in 0..50 {
            let number = folder * 50 + file;
            let path = format!("input/d{folder}/f{file:03}.txt");
            let (lines, positions) = if number % 10 == 3 {
                (4_200, vec![5, 1_700, 3_300, 4_200])
            } else {
                (number % 7 * 40 + 1, vec![number % 7 * 40 + 1])
            };
            let plants = positions
                .iter()
                .enumerate()
                .map(|(index, line)| (*line, format!("{:08}", number * 10 + index)))
                .collect::<Vec<_>>();
            let mut text = planted(lines, &plants);
            for (line, secret) in &plants {
                expected.push(token(&path, *line, secret, ""));
            }
            if number % 7 == 2 {
                let key = format!("key-{:012x}", 0xa0_0000 + number);
                let _ = writeln!(text, "second rule {key}");
                expected.push((
                    "jobs-key".to_owned(),
                    path.clone(),
                    i128::try_from(lines + 1).unwrap(),
                    key,
                    String::new(),
                ));
            }
            fixture.write(&path, text);
        }
    }
    expected
}

#[test]
fn directory_findings_reports_and_warnings_do_not_depend_on_jobs() {
    let fixture = fixture();
    let mut expected = plant_folders(&fixture);

    // An ignore entry and an allow comment each remove one finding.
    let ignored = token("input/d2/f010.txt", 201, "00001100", "");
    assert!(expected.contains(&ignored));
    expected.retain(|row| *row != ignored);
    fixture.write(".gitleaksignore", "input/d2/f010.txt:jobs-token:201\n");
    fixture.write("input/allow.txt", "token=ALLOW123 gitleaks:allow\n");

    // "dG9rZW49QjY0U0VDUlQ=" is the Base64 form of "token=B64SECRT".
    fixture.write("input/encoded.txt", "first line\ndG9rZW49QjY0U0VDUlQ=\n");
    expected.push(token("input/encoded.txt", 2, "B64SECRT", ""));

    fixture.write(
        "input/bundle.tar",
        tar(&[
            (b"a.txt", b"token=TAR00001\n"),
            (b"sub/b.txt", b"x\nx\ntoken=TAR00002\n"),
        ]),
    );
    expected.push(token("input/bundle.tar!a.txt", 1, "TAR00001", ""));
    expected.push(token("input/bundle.tar!sub/b.txt", 3, "TAR00002", ""));
    fixture.write(
        "input/bundle.zip",
        stored_zip(&[(b"c.txt", b"token=ZIP00001\n")]),
    );
    expected.push(token("input/bundle.zip!c.txt", 1, "ZIP00001", ""));
    fixture.write(
        "input/bundle.tar.gz",
        stored_gzip(&tar(&[(b"e.txt", b"token=TGZ00001\n")])),
    );
    expected.push(token("input/bundle.tar.gz!e.txt", 1, "TGZ00001", ""));
    // A final `.tgz` suffix is a gzip TAR archive without a profile too.
    fixture.write(
        "input/bundle.tgz",
        stored_gzip(&tar(&[(b"f.txt", b"token=TGZ00002\n")])),
    );
    expected.push(token("input/bundle.tgz!f.txt", 1, "TGZ00002", ""));
    fixture.write(
        "input/nested.tar",
        tar(&[(
            b"inner.zip",
            &stored_zip(&[(b"d.txt", b"x\ntoken=NEST0001\n")]),
        )]),
    );
    expected.push(token("input/nested.tar!inner.zip!d.txt", 2, "NEST0001", ""));

    // Each gives a warning: an archive deeper than the depth limit and a
    // damaged gzip header.
    let deepest = tar(&[(b"f.txt", b"token=DEEP0001\n")]);
    let deeper = tar(&[(b"deepest.tar", &deepest)]);
    fixture.write("input/deep.tar", tar(&[(b"deeper.tar", &deeper)]));
    fixture.write("input/broken.tar.gz", b"\x1f\x8bbad");

    #[cfg(unix)]
    {
        fixture.write("outside/target.txt", "token=LINK0001\n");
        std::os::unix::fs::symlink("../outside/target.txt", fixture.0.join("input/link.txt"))
            .unwrap();
    }

    let (rows, log) = same_for_every_count(
        &fixture,
        &[
            "dir",
            "input",
            "--max-archive-depth",
            "2",
            "--follow-symlinks",
        ],
        None,
        7,
    );
    let mut rows = sorted(rows);
    #[cfg(unix)]
    {
        let link = rows
            .iter()
            .position(|row| row.3 == "LINK0001")
            .expect("the linked file is scanned");
        let link = rows.remove(link);
        assert_eq!((link.0.as_str(), link.2), ("jobs-token", 1));
        assert!(link.1.ends_with("outside/target.txt"), "{}", link.1);
    }
    assert_eq!(rows, sorted(expected));
    assert!(log.contains("exceeds maximum archive depth"), "{log}");
    // Source warnings name the path with the platform separator.
    let broken = std::path::Path::new("input").join("broken.tar.gz");
    assert!(log.contains(&format!(" {}", broken.display())), "{log}");
    assert!(
        log.lines()
            .filter(|line| line.starts_with("warn source ") || line.starts_with("error source "))
            .count()
            >= 2,
        "{log}"
    );
}

/// Skipped, unreadable and linked inputs among many tiny files. Their
/// warnings must keep their order between the files that are read.
#[test]
fn directory_skips_and_their_warnings_do_not_depend_on_jobs() {
    let fixture = fixture();
    let mut expected = Vec::new();
    for file in 0..400_usize {
        let path = format!("input/t{}/f{file:03}.txt", file % 8);
        if file % 9 == 4 {
            fixture.write(&path, "");
        } else if file % 4 == 1 {
            let secret = format!("TINY{file:04}");
            fixture.write(&path, format!("value token={secret} end\n"));
            expected.push(token(&path, 1, &secret, ""));
        } else {
            fixture.write(&path, format!("plain {file}\n"));
        }
    }
    // Above --max-target-megabytes 1, so skipped with a warning, between
    // read files of the same folder.
    fixture.write(
        "input/t3/f100-large.txt",
        planted(17_000, &[(1, "SKIPPED1".to_owned())]),
    );
    // A WebAssembly header makes a binary file, which is skipped.
    fixture.write("input/t5/binary.wasm", b"\0asm\x01\0\0\0token=BINARY01\n");
    #[cfg(unix)]
    let locked = {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let input = fixture.0.join("input");
        symlink("missing.txt", input.join("t1/f050-dangling.txt")).unwrap();
        symlink("f061-loop.txt", input.join("t2/f060-loop.txt")).unwrap();
        symlink("f060-loop.txt", input.join("t2/f061-loop.txt")).unwrap();
        symlink("../t0", input.join("t4/f070-folder")).unwrap();
        fixture.write("input/t6/f080-locked.txt", "token=LOCKED01\n");
        fixture.write("input/t7/f090-locked/inside.txt", "token=LOCKED02\n");
        fs::set_permissions(
            input.join("t6/f080-locked.txt"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        fs::set_permissions(
            input.join("t7/f090-locked"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        fs::File::open(input.join("t6/f080-locked.txt")).is_err()
    };
    let result = std::panic::catch_unwind(|| {
        same_for_every_count(
            &fixture,
            &[
                "dir",
                "input",
                "--follow-symlinks",
                "--max-target-megabytes",
                "1",
            ],
            None,
            7,
        )
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in ["input/t6/f080-locked.txt", "input/t7/f090-locked"] {
            fs::set_permissions(fixture.0.join(path), fs::Permissions::from_mode(0o755)).unwrap();
        }
        if !locked {
            expected.push(token("input/t6/f080-locked.txt", 1, "LOCKED01", ""));
            expected.push(token("input/t7/f090-locked/inside.txt", 1, "LOCKED02", ""));
        }
    }
    let (rows, log) = result.unwrap();
    assert_eq!(sorted(rows), sorted(expected));
    assert!(log.contains("f100-large.txt"), "{log}");
    #[cfg(unix)]
    {
        for name in ["f050-dangling.txt", "f060-loop.txt", "f061-loop.txt"] {
            assert!(log.contains(name), "{name}: {log}");
        }
        if locked {
            for name in ["f080-locked.txt", "f090-locked"] {
                assert!(log.contains(name), "{name}: {log}");
            }
        }
    }
}

#[test]
fn complete_profile_scans_do_not_depend_on_jobs() {
    let fixture = fixture();
    let expected = plant_folders(&fixture)
        .into_iter()
        .filter(|row| row.1.starts_with("input/d1/"))
        .collect::<Vec<_>>();
    fixture.write("scan.limits", PROFILE);
    let (rows, log) = same_for_every_count(
        &fixture,
        &["dir", "input/d1", "--complete-profile", "scan.limits"],
        None,
        7,
    );
    assert_eq!(sorted(rows), sorted(expected.clone()));
    let status = log
        .lines()
        .find(|line| line.starts_with("rustleaks_scan_status "))
        .unwrap();
    assert!(
        status.contains(&format!(
            " status=complete reason=complete source_scope=directory_targets findings={} ",
            expected.len()
        )),
        "{status}"
    );
}

#[test]
fn stdin_findings_and_reports_do_not_depend_on_jobs() {
    let fixture = fixture();
    // About 640 KB, so standard input is scanned in several pieces.
    let plants = (0..40)
        .map(|index| (index * 250 + 7, format!("STD{index:05}")))
        .collect::<Vec<_>>();
    let input = planted(10_000, &plants);
    let (rows, _) = same_for_every_count(&fixture, &["stdin"], Some(input.as_bytes()), 7);
    let found = sorted(rows)
        .into_iter()
        .map(|(rule, _, line, secret, commit)| (rule, line, secret, commit))
        .collect::<Vec<_>>();
    let mut expected = plants
        .iter()
        .map(|(line, secret)| {
            (
                "jobs-token".to_owned(),
                i128::try_from(*line).unwrap(),
                secret.clone(),
                String::new(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn git_history_findings_and_reports_do_not_depend_on_jobs() {
    let fixture = fixture();
    let repository = fixture.0.join("repo");
    fs::create_dir_all(repository.join("src")).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Jobs Test"]);
    // This history has enough loose objects for automatic maintenance to
    // repack them in the background while a scan reads them.
    git(&repository, &["config", "gc.auto", "0"]);
    git(&repository, &["config", "maintenance.auto", "false"]);
    git(
        &repository,
        &["config", "user.email", "jobs@example.invalid"],
    );
    let mut contents = vec![String::new(); 5];
    let mut expected = Vec::new();
    for commit in 0..24_usize {
        // Every fourth commit also edits the first line of m0.txt, so
        // that commit has a hunk without a token in another place.
        if commit % 4 == 3 {
            let rest = contents[0]
                .split_once('\n')
                .map_or("", |(_, rest)| rest)
                .to_owned();
            contents[0] = format!("edited line {commit}\n{rest}");
        }
        let mut added = Vec::new();
        for change in 0..3_usize {
            let index = (commit + change) % 5;
            for filler in 0..=(commit * (change + 1)) % 9 {
                let _ = writeln!(contents[index], "plain {commit} {change} {filler}");
            }
            let secret = format!("G{commit:03}{change:04}");
            let _ = writeln!(contents[index], "value token={secret} end");
            let line = contents[index].lines().count();
            added.push((format!("src/m{index}.txt"), line, secret));
        }
        for (index, text) in contents.iter().enumerate() {
            fs::write(repository.join(format!("src/m{index}.txt")), text).unwrap();
        }
        git(&repository, &["add", "src"]);
        git(
            &repository,
            &["commit", "--quiet", "-m", &format!("change {commit}")],
        );
        let sha = git_stdout(&repository, &["rev-parse", "HEAD"]);
        for (file, line, secret) in added {
            expected.push(token(&file, line, &secret, &sha));
        }
    }
    fs::create_dir(repository.join("pkg")).unwrap();
    fs::write(
        repository.join("pkg/bundle.tar"),
        tar(&[(b"a.txt", b"token=GITTAR01\n")]),
    )
    .unwrap();
    git(&repository, &["add", "pkg"]);
    git(&repository, &["commit", "--quiet", "-m", "archive"]);
    let sha = git_stdout(&repository, &["rev-parse", "HEAD"]);
    expected.push(token("pkg/bundle.tar!a.txt", 1, "GITTAR01", &sha));

    let (rows, log) = same_for_every_count(
        &fixture,
        &[
            "git",
            "repo",
            "--platform",
            "none",
            "--max-archive-depth",
            "1",
        ],
        None,
        7,
    );
    assert_eq!(sorted(rows), sorted(expected));
    assert!(log.contains("25 commits scanned."), "{log}");
}

/// Imports a `git fast-import` stream and returns the object name of
/// each mark.
fn fast_import(repository: &Path, stream: &[u8]) -> Vec<(usize, String)> {
    let marks = repository.join(".git/marks.txt");
    let mut child = Command::new(git_executable())
        .current_dir(repository)
        .args(["fast-import", "--quiet"])
        .arg(format!("--export-marks={}", marks.display()))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stream).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read_to_string(&marks)
        .unwrap()
        .lines()
        .map(|line| {
            let (mark, sha) = line.split_once(' ').unwrap();
            (mark[1..].parse().unwrap(), sha.to_owned())
        })
        .collect()
}

#[test]
fn git_history_read_by_several_git_processes_matches_one_process() {
    // More than two batches of 250 commits, so every count above one
    // reads the history with several `git log` processes. A side branch
    // is merged back, and some commits show no diff.
    let fixture = fixture();
    let repository = fixture.0.join("repo");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "gc.auto", "0"]);
    git(&repository, &["config", "maintenance.auto", "false"]);
    let mut stream = String::new();
    let mut contents = vec![String::new(); 7];
    let mut plants = Vec::new();
    for mark in 1..=640_usize {
        let branch = if (300..340).contains(&mark) {
            "side"
        } else {
            "main"
        };
        let _ = write!(
            stream,
            "commit refs/heads/{branch}\nmark :{mark}\n\
                 author Jobs Test <jobs@example.invalid> {time} +0000\n\
                 committer Jobs Test <jobs@example.invalid> {time} +0000\n\
                 data 10\nchange {mark:03}\n",
            time = 1_700_000_000 + mark * 60,
        );
        match mark {
            1 => {}
            300 => stream.push_str("from :299\n"),
            // The merge keeps the files of the side branch. Git shows no
            // diff for a merge with the default options.
            340 => {
                stream.push_str("from :299\nmerge :339\n");
                for (index, text) in contents.iter().enumerate() {
                    let _ = write!(
                        stream,
                        "M 100644 inline src/f{index}.txt\ndata {}\n{text}\n",
                        text.len()
                    );
                }
            }
            _ => {
                let _ = writeln!(stream, "from :{}", mark - 1);
            }
        }
        // Every 50th commit changes nothing.
        if mark % 50 != 0 && mark != 340 {
            let index = mark % 7;
            let secret = format!("H{mark:07}");
            for filler in 0..mark % 4 {
                let _ = writeln!(contents[index], "plain {mark} {filler}");
            }
            let _ = writeln!(contents[index], "value token={secret} end");
            let line = contents[index].lines().count();
            let path = format!("src/f{index}.txt");
            let _ = write!(
                stream,
                "M 100644 inline {path}\ndata {}\n{}\n",
                contents[index].len(),
                contents[index]
            );
            plants.push((mark, path, line, secret));
        }
        stream.push('\n');
    }
    let marks = fast_import(&repository, stream.as_bytes());
    let expected = plants
        .iter()
        .map(|(mark, path, line, secret)| {
            let (_, sha) = marks.iter().find(|(found, _)| found == mark).unwrap();
            token(path, *line, secret, sha)
        })
        .collect::<Vec<_>>();

    let (rows, log) =
        same_for_every_count(&fixture, &["git", "repo", "--platform", "none"], None, 7);
    assert_eq!(sorted(rows.clone()), sorted(expected));
    assert!(
        log.contains(&format!("{} commits scanned.", plants.len())),
        "{log}"
    );

    // Git records the commands that ran: with four threads, one commit
    // list and three batches of at most 250 commits.
    let trace = fixture.0.join("git-trace");
    let result = command(&fixture.0)
        .args([
            "git",
            "repo",
            "--platform",
            "none",
            "--no-banner",
            "--config",
            "config.toml",
            "--jobs",
            "4",
            "--report-path",
            "-",
            "--report-format",
            "json",
        ])
        .env("GIT_TRACE", &trace)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(sorted(json_report_rows(&result.stdout)), sorted(rows));
    let trace = fs::read_to_string(&trace).unwrap();
    let count = |needle: &str| trace.lines().filter(|line| line.contains(needle)).count();
    assert_eq!(count("built-in: git rev-list --full-history --all"), 1);
    assert_eq!(count("--no-walk=unsorted --stdin"), 3);
}

#[test]
fn jobs_overrides_the_profile_which_overrides_the_cpu_count() {
    let fixture = fixture();
    fixture.write("input/a.txt", "token=PREC0001\n");
    fixture.write("scan.limits", PROFILE.replace("workers=1\n", "workers=2\n"));
    let cpus = std::thread::available_parallelism().map_or(1, |cpus| cpus.get().min(12));
    for (extra, threads) in [
        (&[][..], cpus),
        (&["--jobs", "3"][..], 3),
        (&["-j", "200"][..], 200),
        (&["--complete-profile", "scan.limits"][..], 2),
        (&["--complete-profile", "scan.limits", "--jobs", "5"][..], 5),
        (&["--jobs", "6", "--complete-profile", "scan.limits"][..], 6),
    ] {
        let mut arguments = vec![
            "dir",
            "input",
            "--no-banner",
            "--config",
            "config.toml",
            "--log-level",
            "debug",
        ];
        arguments.extend(extra);
        let result = output(&fixture.0, &arguments);
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(result.status.code(), Some(1), "{extra:?}: {stderr}");
        let lines = stderr
            .lines()
            .filter(|line| line.starts_with("info detection threads: "))
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [format!("info detection threads: {threads}")],
            "{extra:?}"
        );
    }
    for value in ["0", "-2", "two"] {
        let result = output(&fixture.0, &["dir", "input", "--jobs", value]);
        assert_eq!(result.status.code(), Some(1), "{value}");
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(
            stderr.starts_with(&format!(
                "Error: the --jobs argument {value:?} is not a whole number from 1 to "
            )),
            "{stderr}"
        );
    }
}
