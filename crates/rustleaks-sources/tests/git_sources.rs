//! Isolated native Git subprocess coverage.
#![forbid(unsafe_code)]

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "archives")]
use rustleaks_sources::ArchiveOptions;
use rustleaks_sources::{
    CallbackError, CancellationToken, GitLimits, GitMode, Source, SourceControl, SourceError,
    SourceEvent, SourceIssueKind, SourceStage,
};

use support::collect;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRepo(PathBuf);

impl TempRepo {
    fn copy_fixture(name: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let destination = std::env::temp_dir().join(format!(
            "rustleaks-git-source-{name}-{}-{unique}",
            std::process::id()
        ));
        let source = fixture_root().join("testdata/repos").join(name);
        copy_tree(&source, &destination);
        fs::rename(destination.join("dotGit"), destination.join(".git"))
            .expect("activate copied Git metadata");
        Self(destination)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/fixtures/upstream")
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let file_type = entry.file_type().expect("fixture type");
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy fixture file");
        }
    }
}

#[cfg(unix)]
const SYNTHETIC_HUNK_PATCH: &[u8] = b"commit 0123456789abcdef0123456789abcdef01234567\n\
Author: Synthetic Test <synthetic@example.com>\n\
Date:   Tue Nov 2 18:37:53 2021 -0500\n\n\
\x20\x20\x20\x20synthetic 'hunks'\n\n\
diff --git a/single.txt b/single.txt\n\
--- a/single.txt\n\
+++ b/single.txt\n\
@@ -2,0 +3 @@\n\
+single\n\
diff --git a/mode.txt b/mode.txt\n\
old mode 100644\n\
new mode 100755\n\
diff --git a/binary.bin b/binary.bin\n\
Binary files a/binary.bin and b/binary.bin differ\n\
diff --git a/deleted.txt b/deleted.txt\n\
deleted file mode 100644\n\
--- a/deleted.txt\n\
+++ /dev/null\n\
@@ -1 +0,0 @@\n\
-deleted\n\
diff --git a/multi.txt b/multi.txt\n\
--- a/multi.txt\n\
+++ b/multi.txt\n\
@@ -3,0 +4 @@\n\
+first\n\
@@ -7 +7,0 @@\n\
-removed\n\
@@ -11,0 +13 @@\n\
+last's line\n\
\\ No newline at end of file\n";

#[cfg(unix)]
fn scripted_git_executable() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/git-fixture.sh")
        .canonicalize()
        .expect("resolve committed synthetic Git command")
}

#[cfg(unix)]
fn scripted_patch_source(
    patch: &[u8],
    stderr: bool,
    exit_code: u8,
) -> (TempRepo, rustleaks_sources::GitSource) {
    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let repository = TempRepo(std::env::temp_dir().join(format!(
        "rustleaks-git-patch-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir(repository.path()).expect("create synthetic patch directory");
    fs::write(repository.path().join("git-fixture.patch"), patch)
        .expect("write synthetic Git patch");
    fs::write(
        repository.path().join("git-fixture.stderr"),
        if stderr { "synthetic warning\n" } else { "" },
    )
    .expect("write synthetic Git stderr");
    fs::write(
        repository.path().join("git-fixture.exit"),
        format!("{exit_code}\n"),
    )
    .expect("write synthetic Git exit status");
    let source =
        rustleaks_sources::GitSource::new(repository.path()).executable(scripted_git_executable());
    (repository, source)
}

#[cfg(unix)]
#[test]
fn scripted_git_launcher_preserves_stdout_stderr_and_exit_status() {
    for patch in [
        SYNTHETIC_HUNK_PATCH,
        b"synthetic 'patch'\r\nno final newline\0\xff".as_slice(),
    ] {
        for stderr in [false, true] {
            for exit_code in [0, 7] {
                let (repository, _source) = scripted_patch_source(patch, stderr, exit_code);
                let output = std::process::Command::new(scripted_git_executable())
                    .arg("-C")
                    .arg(repository.path())
                    .arg("log")
                    .output()
                    .expect("run committed synthetic Git command");
                assert_eq!(output.stdout, patch);
                assert_eq!(
                    output.stderr,
                    if stderr {
                        b"synthetic warning\n".as_slice()
                    } else {
                        b"".as_slice()
                    }
                );
                assert_eq!(output.status.code(), Some(i32::from(exit_code)));
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn single_and_multiple_hunks_preserve_owned_fragment_fields_and_order() {
    let (_repository, mut source) = scripted_patch_source(SYNTHETIC_HUNK_PATCH, false, 0);
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());
    let expected = [
        (b"single.txt".as_slice(), 3, b"single\n".as_slice()),
        (b"multi.txt".as_slice(), 4, b"first\n".as_slice()),
        (b"multi.txt".as_slice(), 7, b"".as_slice()),
        (b"multi.txt".as_slice(), 13, b"last's line".as_slice()),
    ];
    assert_eq!(fragments.len(), expected.len());
    for (fragment, (path, line, bytes)) in fragments.iter().zip(expected) {
        assert_eq!(fragment.file_path().as_bytes(), path);
        assert_eq!(fragment.start_line(), line);
        assert_eq!(fragment.content().as_bytes(), bytes);
        assert_eq!(
            fragment.commit().as_bytes(),
            b"0123456789abcdef0123456789abcdef01234567"
        );
        let metadata = fragment.commit_metadata().expect("metadata on every hunk");
        assert_eq!(metadata.sha().as_bytes(), fragment.commit().as_bytes());
        assert_eq!(metadata.author_name().as_bytes(), b"Synthetic Test");
        assert_eq!(metadata.author_email().as_bytes(), b"synthetic@example.com");
        assert_eq!(metadata.date().as_bytes(), b"2021-11-02T23:37:53Z");
        assert_eq!(metadata.message().as_bytes(), b"synthetic 'hunks'");
        assert!(fragment.symlink_file().is_empty());
        assert!(fragment.windows_file_path().is_empty());
        assert!(!fragment.inherited_from_finding());
    }
}

#[cfg(unix)]
#[test]
fn hunk_emission_stops_on_callback_control_and_failure() {
    for stop_at in [1, 2, 4] {
        for fail in [false, true] {
            let (repository, mut source) = scripted_patch_source(SYNTHETIC_HUNK_PATCH, false, 0);
            let mut seen = 0;
            let result = source.visit(&CancellationToken::new(), &mut |event| {
                assert!(
                    matches!(event, SourceEvent::Fragment { issue: None, .. }),
                    "stop_at={stop_at}, fail={fail}, repository={:?}, event={event:?}",
                    repository.path()
                );
                seen += 1;
                if seen == stop_at {
                    if fail {
                        Err(CallbackError::new("synthetic callback failure"))
                    } else {
                        Ok(SourceControl::Stop)
                    }
                } else {
                    Ok(SourceControl::Continue)
                }
            });
            assert_eq!(
                seen,
                stop_at,
                "stop_at={stop_at}, fail={fail}, repository={:?}, result={result:?}",
                repository.path()
            );
            if fail {
                assert!(
                    matches!(result, Err(SourceError::Callback(_))),
                    "stop_at={stop_at}, repository={:?}, result={result:?}",
                    repository.path()
                );
            } else {
                assert!(
                    matches!(result, Ok(SourceControl::Stop)),
                    "stop_at={stop_at}, repository={:?}, result={result:?}",
                    repository.path()
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn late_patch_and_command_errors_follow_the_records_before_them() {
    // Git output is parsed while Git runs. A file record is published once
    // the next record starts, so records before a failure are published.
    // The final record waits until Git exits successfully.
    let mut truncated = SYNTHETIC_HUNK_PATCH.to_vec();
    truncated.extend_from_slice(
        b"diff --git a/broken b/broken\n--- a/broken\n+++ b/broken\n@@ -0,0 +1,2 @@\n+truncated\n",
    );
    // single.txt has one hunk and multi.txt three. The truncated record
    // follows multi.txt; with exit code 7, multi.txt is the final record.
    for (patch, exit_code, stage, published) in [
        (truncated.as_slice(), 0, SourceStage::GitParse, 4),
        (SYNTHETIC_HUNK_PATCH, 7, SourceStage::GitExit, 1),
    ] {
        for stderr in [false, true] {
            let (repository, mut source) = scripted_patch_source(patch, stderr, exit_code);
            let mut fragments = 0;
            let mut issues = Vec::new();
            let error = source
                .visit(&CancellationToken::new(), &mut |event| {
                    match event {
                        SourceEvent::Fragment { .. } => fragments += 1,
                        SourceEvent::Issue(issue) => issues.push((issue.stage(), issue.kind())),
                        _ => panic!("unexpected future Git source event"),
                    }
                    Ok(SourceControl::Continue)
                })
                .expect_err("late error must remain terminal");
            assert!(
                matches!(error, SourceError::Terminal { stage: actual, .. } if actual == stage),
                "stage={stage:?}, stderr={stderr}, exit_code={exit_code}, repository={:?}, error={error:?}",
                repository.path()
            );
            assert_eq!(fragments, published);
            if stderr && stage == SourceStage::GitParse {
                assert_eq!(
                    issues,
                    [(SourceStage::GitCommand, SourceIssueKind::GitStderr)]
                );
            } else {
                assert!(issues.is_empty());
            }
        }
    }
}

/// Returns the commit count, and the most bytes and lines of one commit, in
/// `git log` output, counting from each `commit ` line to the next.
#[cfg(unix)]
fn largest_commit(output: &[u8]) -> (usize, usize, usize) {
    let mut sizes = Vec::new();
    for line in output.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"commit ") {
            sizes.push((0, 0));
        }
        let (bytes, lines) = sizes.last_mut().expect("output starts with a commit");
        *bytes += line.len();
        *lines += 1;
    }
    let largest = sizes.iter().map(|(bytes, _)| *bytes).max().unwrap();
    let most_lines = sizes.iter().map(|(_, lines)| *lines).max().unwrap();
    (sizes.len(), largest, most_lines)
}

#[cfg(unix)]
#[test]
fn history_larger_than_the_per_commit_limits_scans_completely() {
    // Each commit adds one file. Every commit fits the patch limits below,
    // but the whole history is several times larger. A total limit would
    // stop this scan; a per-commit limit must not.
    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let repository = TempRepo(std::env::temp_dir().join(format!(
        "rustleaks-git-per-commit-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir(repository.path()).expect("create synthetic repository");
    let git = |arguments: &[&str]| {
        let output = support::command()
            .arg("-C")
            .arg(repository.path())
            .args([
                "-c",
                "user.name=Synthetic Test",
                "-c",
                "user.email=synthetic@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(arguments)
            .env("GIT_AUTHOR_DATE", "2021-11-02T23:37:53Z")
            .env("GIT_COMMITTER_DATE", "2021-11-02T23:37:53Z")
            .output()
            .expect("run isolated Git");
        assert!(output.status.success(), "isolated Git {arguments:?} failed");
        output.stdout
    };
    git(&["init", "--quiet"]);
    let commits = 6;
    let mut contents = Vec::new();
    for index in 0..commits {
        let name = format!("file-{index}.txt");
        let content = format!("synthetic value {index}\n").repeat(20);
        fs::write(repository.path().join(&name), &content).expect("write synthetic file");
        git(&["add", "--", &name]);
        git(&["commit", "--quiet", "-m", &format!("add {name}")]);
        contents.push((name, content));
    }

    // Measure each commit in the same output that the source reads.
    let output = git(&[
        "log",
        "-p",
        "-U0",
        "--full-history",
        "--all",
        "--diff-filter=tuxdb",
    ]);
    let (count, largest, most_lines) = largest_commit(&output);
    assert_eq!(count, commits);
    assert!(
        output.len() > 3 * largest,
        "the history must exceed one commit"
    );

    let limits = |bytes, lines| {
        GitLimits::new(bytes, lines, 1 << 20, 1 << 20)
            .and_then(|limits| limits.with_parser_limits(4096, 4096, 1, 1))
            .expect("per-commit limits")
    };
    let mut source = support::git_source(repository.path()).limits(limits(largest, most_lines));
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), commits);
    for (name, content) in &contents {
        let fragment = fragments
            .iter()
            .find(|fragment| fragment.file_path().as_bytes() == name.as_bytes())
            .expect("every commit is scanned");
        assert_eq!(fragment.content().as_bytes(), content.as_bytes());
        assert_eq!(fragment.start_line(), 1);
        let metadata = fragment.commit_metadata().expect("commit metadata");
        assert_eq!(
            metadata.message().as_bytes(),
            format!("add {name}").as_bytes()
        );
    }
    let mut shas = fragments
        .iter()
        .map(|fragment| fragment.commit().as_bytes().to_vec())
        .collect::<Vec<_>>();
    shas.sort();
    shas.dedup();
    assert_eq!(shas.len(), commits);

    // One byte or one line less than the largest commit still stops the scan.
    for limits in [
        limits(largest - 1, most_lines),
        limits(largest, most_lines - 1),
    ] {
        let error = support::git_source(repository.path())
            .limits(limits)
            .visit(&CancellationToken::new(), &mut |_| {
                Ok(SourceControl::Continue)
            })
            .expect_err("a commit above the limit must fail closed");
        assert!(matches!(
            error,
            SourceError::Terminal {
                stage: SourceStage::Limit,
                ..
            }
        ));
    }
}

#[test]
fn default_log_matches_recorded_added_fragment_stream() {
    let repository = TempRepo::copy_fixture("small");
    let mut source = support::git_source(repository.path());
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());

    let mut actual = Vec::new();
    for fragment in &fragments {
        actual.extend_from_slice(fragment.content().as_bytes());
    }
    let ignore =
        fs::read(repository.path().join("api/ignoreCommit.go")).expect("read ignore fixture");
    let recorded = fs::read(fixture_root().join("testdata/expected/git/small.txt"))
        .expect("read recorded fragment stream");
    let mut expected = Vec::new();
    expected.extend_from_slice(&ignore);
    expected.extend_from_slice(&ignore);
    expected.extend_from_slice(&recorded);
    assert_eq!(actual, expected);

    let secret = fragments
        .iter()
        .find(|fragment| {
            fragment.commit().as_bytes() == b"1b6da43b82b22e4eaa10bcf8ee591e91abbfc587"
        })
        .expect("secret commit fragment");
    assert_eq!(secret.file_path().as_bytes(), b"main.go");
    assert_eq!(secret.start_line(), 18);
    let metadata = secret.commit_metadata().expect("commit metadata");
    assert_eq!(metadata.author_name().as_bytes(), b"Zachary Rice");
    assert_eq!(metadata.date().as_bytes(), b"2021-11-02T23:37:53Z");
    assert_eq!(metadata.message().as_bytes(), b"Accidentally add a secret");
}

#[test]
fn diff_and_index_fragments_have_zero_metadata() {
    let repository = TempRepo::copy_fixture("staged");
    let mut source = support::git_source(repository.path()).mode(GitMode::Diff { staged: true });
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].file_path().as_bytes(), b"api/api.go");
    assert_eq!(fragments[0].start_line(), 6);
    assert_eq!(
        fragments[0].content().as_bytes(),
        b"\taws_token := \"AKIALALEMEL33243OLIA\"  // fingerprint of that secret is added to .gitleaksignore\n\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not\n\tfmt.Println(aws_token)\n\tfmt.Println(aws_token2)\n" // gitleaks:allow
    );
    assert!(fragments[0].commit().is_empty());
    let metadata = fragments[0].commit_metadata().expect("zero diff metadata");
    assert!(metadata.sha().is_empty());
    assert_eq!(metadata.date().as_bytes(), b"0001-01-01T00:00:00Z");
}

#[test]
fn patch_byte_and_line_ceilings_are_structured_limit_failures() {
    let repository = TempRepo::copy_fixture("small");
    let cases = [
        GitLimits::new(64, 2_000_000, 1 << 20, 1 << 20).expect("byte ceiling"),
        GitLimits::new(1 << 20, 1, 1 << 20, 1 << 20).expect("line ceiling"),
    ];
    for limits in cases {
        let error = support::git_source(repository.path())
            .limits(limits)
            .visit(&CancellationToken::new(), &mut |_| {
                Ok(SourceControl::Continue)
            })
            .expect_err("configured Git limit must fail closed");
        assert!(matches!(
            error,
            SourceError::Terminal {
                stage: SourceStage::Limit,
                ..
            }
        ));
    }
}

#[test]
fn callback_failure_remains_distinct_after_git_is_reaped() {
    let repository = TempRepo::copy_fixture("small");
    let mut callbacks = 0;
    assert_eq!(
        support::git_source(repository.path())
            .visit(&CancellationToken::new(), &mut |_| {
                callbacks += 1;
                Ok(SourceControl::Stop)
            })
            .expect("callback stop"),
        SourceControl::Stop
    );
    assert_eq!(callbacks, 1);
    let error = support::git_source(repository.path())
        .visit(&CancellationToken::new(), &mut |_| {
            Err(CallbackError::new("injected callback failure"))
        })
        .expect_err("callback failure");
    assert!(matches!(error, SourceError::Callback(_)));
}

#[cfg(feature = "archives")]
#[test]
fn binary_and_history_archives_reuse_safe_archive_expansion() {
    let repository = TempRepo::copy_fixture("archives");
    let mut source = support::git_source(repository.path()).archives(ArchiveOptions::default());
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty(), "unexpected archive issues: {issues:?}");

    let stream = fragments
        .iter()
        .find(|fragment| {
            fragment.commit().as_bytes() == b"db8789716fc664dbce0ed2d492570e92abf717a5"
                && fragment.file_path().as_bytes() == b"main.go.zst"
        })
        .expect("expanded Zstandard history blob");
    assert!(
        stream
            .content()
            .as_bytes()
            .windows(20)
            .any(|window| window == b"AKIALALEMEL33243OLIA") // gitleaks:allow
    );
    assert_eq!(
        stream
            .commit_metadata()
            .expect("archive commit metadata")
            .author_name()
            .as_bytes(),
        b"Test User"
    );

    assert!(fragments.iter().any(|fragment| {
        fragment.commit().as_bytes() == b"07d2bd71800f1abf0421abe9bc4a83a6fdca1f68"
            && fragment.file_path().as_bytes() == b"nested.tar.gz!archives/files.zip!files/api.go"
    }));
}

#[cfg(feature = "archives")]
#[test]
fn archive_blob_exact_over_and_early_stop_are_structured() {
    let repository = TempRepo::copy_fixture("archives");
    let commit = "db8789716fc664dbce0ed2d492570e92abf717a5";
    let blob_size = usize::try_from(
        fs::metadata(repository.path().join("main.go.zst"))
            .expect("archive blob metadata")
            .len(),
    )
    .expect("blob size fits usize");
    let mode = || GitMode::LogArguments(vec!["-1".into(), commit.into()]);
    let limits =
        |blob| GitLimits::new(64 << 20, 1_000_000, 1 << 20, blob).expect("Git blob limits");

    let mut exact = support::git_source(repository.path())
        .mode(mode())
        .limits(limits(blob_size))
        .archives(ArchiveOptions::default());
    let (fragments, issues) = collect(&mut exact);
    assert!(!fragments.is_empty());
    assert!(issues.is_empty());

    // A blob over its limit is skipped with a limit issue, like other
    // archive limits, and the history scan goes on.
    let mut over_issues = Vec::new();
    let control = support::git_source(repository.path())
        .mode(mode())
        .limits(limits(blob_size - 1))
        .archives(ArchiveOptions::default())
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Issue(issue) => over_issues.push((issue.stage(), issue.kind())),
                SourceEvent::Fragment { fragment, .. } => {
                    assert_ne!(fragment.file_path().as_bytes(), b"main.go.zst");
                }
                _ => unreachable!("future source event"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("over-limit archive blob is skipped");
    assert_eq!(control, SourceControl::Continue);
    assert_eq!(over_issues, [(SourceStage::Limit, SourceIssueKind::Limit)]);

    let mut callbacks = 0;
    let control = support::git_source(repository.path())
        .mode(mode())
        .limits(limits(blob_size))
        .archives(ArchiveOptions::default())
        .visit(&CancellationToken::new(), &mut |_| {
            callbacks += 1;
            Ok(SourceControl::Stop)
        })
        .expect("early blob consumer stop");
    assert_eq!(control, SourceControl::Stop);
    assert_eq!(callbacks, 1);
}

#[cfg(all(feature = "archives", unix))]
#[test]
fn binary_archive_paths_reach_blob_expansion_without_loss() {
    use std::os::unix::ffi::OsStrExt;

    let repository = TempRepo::copy_fixture("small");
    let paths: &[&[u8]] = &[b"tab\tarchive.tar", b"folder b/archive.tar"];
    let content = b"synthetic archive content\n";
    let mut header = [0_u8; 512];
    header[..10].copy_from_slice(b"inside.txt");
    header[100..108].copy_from_slice(b"0000644\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(content);
    archive.resize(2048, 0);
    for path in paths {
        let path = repository.path().join(std::ffi::OsStr::from_bytes(path));
        fs::create_dir_all(path.parent().expect("archive parent")).expect("create archive parent");
        fs::write(path, &archive).expect("write synthetic archive");
    }
    let output = support::command()
        .arg("-C")
        .arg(repository.path())
        .args(["add", "--"])
        .args(paths.iter().map(|path| std::ffi::OsStr::from_bytes(path)))
        .output()
        .expect("stage synthetic archives");
    assert!(output.status.success(), "isolated Git add failed");
    let output = support::command()
        .arg("-C")
        .arg(repository.path())
        .args([
            "-c",
            "user.name=Synthetic Test",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "add synthetic archives",
        ])
        .output()
        .expect("commit synthetic archives");
    assert!(output.status.success(), "isolated Git commit failed");
    let mut source = support::git_source(repository.path())
        .mode(GitMode::LogArguments(vec!["-1".into()]))
        .archives(ArchiveOptions::default());
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), paths.len());
    for path in paths {
        let mut expected = path.to_vec();
        expected.extend_from_slice(b"!inside.txt");
        let fragment = fragments
            .iter()
            .find(|fragment| fragment.file_path().as_bytes() == expected)
            .expect("every binary archive is expanded at its exact path");
        assert_eq!(fragment.content().as_bytes(), content);
        let metadata = fragment.commit_metadata().expect("archive commit metadata");
        assert_eq!(metadata.sha().as_bytes(), fragment.commit().as_bytes());
        assert_eq!(metadata.author_name().as_bytes(), b"Synthetic Test");
        assert_eq!(metadata.message().as_bytes(), b"add synthetic archives");
    }
}

#[cfg(all(feature = "archives", unix))]
fn commit_complete_archive_fixture(repository: &Path, paths: &[&str]) {
    let output = support::command()
        .arg("-C")
        .arg(repository)
        .args(["add", "--"])
        .args(paths)
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = support::command()
        .arg("-C")
        .arg(repository)
        .args([
            "-c",
            "user.name=Synthetic Test",
            "-c",
            "user.email=synthetic@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "synthetic complete archive test",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[cfg(all(feature = "archives", unix))]
#[test]
fn complete_archive_options_reach_git_blobs_without_changing_text_hunks() {
    let repository = TempRepo::copy_fixture("small");
    fs::write(
        repository.path().join("text-scope.txt"),
        b"first\nKEEP-CONTEXT\nlast\n",
    )
    .unwrap();
    commit_complete_archive_fixture(repository.path(), &["text-scope.txt"]);
    fs::write(
        repository.path().join("text-scope.txt"),
        b"first changed\nKEEP-CONTEXT\nlast changed\n",
    )
    .unwrap();
    let mut content = vec![b'.'; 124_995];
    content.extend_from_slice(b"token=A001\n");
    let mut header = [0_u8; 512];
    header[..10].copy_from_slice(b"inside.txt");
    header[100..108].copy_from_slice(b"0000644\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(&content);
    archive.resize(archive.len().div_ceil(512) * 512 + 1024, 0);
    fs::write(repository.path().join("boundary.tar"), archive).unwrap();
    commit_complete_archive_fixture(repository.path(), &["text-scope.txt", "boundary.tar"]);
    for complete in [false, true] {
        let options = if complete {
            rustleaks_sources::FileOptions::complete(content.len()).unwrap()
        } else {
            rustleaks_sources::FileOptions::default()
        };
        let mut source = support::git_source(repository.path())
            .mode(GitMode::LogArguments(vec!["-1".into()]))
            .archives(ArchiveOptions::default())
            .archive_file_options(options);
        let (fragments, issues) = collect(&mut source);
        assert!(issues.is_empty());
        let text = fragments
            .iter()
            .filter(|fragment| fragment.file_path().as_bytes() == b"text-scope.txt")
            .map(|fragment| (fragment.start_line(), fragment.content().as_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(
            text,
            [
                (1, b"first changed\n".as_slice()),
                (3, b"last changed\n".as_slice())
            ]
        );
        let members = fragments
            .iter()
            .filter(|fragment| fragment.file_path().as_bytes() == b"boundary.tar!inside.txt")
            .collect::<Vec<_>>();
        if complete {
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].content().as_bytes(), content);
            assert_eq!(members[0].start_line(), 1);
        } else {
            assert!(members.len() > 1);
        }
        assert!(
            members
                .iter()
                .all(|fragment| fragment.commit_metadata().is_some())
        );
    }
    let mut too_small = support::git_source(repository.path())
        .mode(GitMode::LogArguments(vec!["-1".into()]))
        .archives(ArchiveOptions::default())
        .archive_file_options(rustleaks_sources::FileOptions::complete(content.len() - 1).unwrap());
    let error = too_small
        .visit(&CancellationToken::new(), &mut |_| {
            Ok(SourceControl::Continue)
        })
        .unwrap_err();
    assert!(matches!(
        error,
        SourceError::Terminal {
            stage: SourceStage::Limit,
            ..
        }
    ));
}

#[cfg(all(feature = "archives", unix))]
#[test]
fn git_expands_tgz_blobs_in_normal_and_complete_mode() {
    let repository = TempRepo::copy_fixture("small");
    let archive = fs::read(fixture_root().join("testdata/archives/nested.tar.gz")).unwrap();
    fs::write(repository.path().join("bundle.TGZ"), archive).unwrap();
    commit_complete_archive_fixture(repository.path(), &["bundle.TGZ"]);
    let expected = fs::read(fixture_root().join("testdata/archives/files/api.go")).unwrap();
    for complete in [false, true] {
        let file_options = if complete {
            rustleaks_sources::FileOptions::complete(1 << 20).unwrap()
        } else {
            rustleaks_sources::FileOptions::default()
        };
        let mut source = support::git_source(repository.path())
            .mode(GitMode::LogArguments(vec!["-1".into()]))
            .archives(ArchiveOptions::default())
            .archive_file_options(file_options);
        let (fragments, issues) = collect(&mut source);
        assert!(issues.is_empty());
        let leaf = fragments
            .iter()
            .find(|fragment| {
                fragment.file_path().as_bytes() == b"bundle.TGZ!archives/files.zip!files/api.go"
            })
            .unwrap_or_else(|| panic!("complete={complete}: the .TGZ blob is read as gzip TAR"));
        assert_eq!(leaf.content().as_bytes(), expected);
        assert_eq!(leaf.start_line(), 1);
        assert!(leaf.commit_metadata().is_some());
    }
}

/// Writes an executable script that records each run next to itself and
/// prints a replacement for the content Git would show.
#[cfg(unix)]
fn recording_script(directory: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\n: > \"$(dirname \"$0\")/{name}.ran\"\necho hidden\n"),
    )
    .expect("write recording script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("make script executable");
    path
}

/// Writes a stand-in for Git that prints the rename-limit warning on
/// standard error, in English only when Git messages are untranslated
/// (`LC_ALL=C` and no `LANGUAGE`), as a translated Git would.
#[cfg(unix)]
fn locale_warning_git(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join("git");
    fs::write(
        &path,
        "#!/bin/sh\n\
         if [ \"${LC_ALL-}\" = C ] && [ -z \"${LANGUAGE+set}\" ]; then\n\
         echo 'warning: exhaustive rename detection was skipped due to too many files.' >&2\n\
         echo 'warning: you may want to set your diff.renameLimit variable to at least 9 and retry the command.' >&2\n\
         else\n\
         echo 'Warnung: Die Erkennung von Umbenennungen wurde uebersprungen.' >&2\n\
         fi\n",
    )
    .expect("write Git stand-in");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("make script executable");
    path
}

#[cfg(unix)]
#[test]
fn translated_locale_does_not_turn_the_rename_limit_warning_into_an_issue() {
    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let root = TempRepo(std::env::temp_dir().join(format!(
        "rustleaks-git-locale-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir_all(root.path()).expect("create script directory");
    let git = locale_warning_git(root.path());
    let translated = [("LANG", "de_DE.UTF-8"), ("LC_MESSAGES", "de_DE.UTF-8")]
        .map(|(key, value)| (key.into(), value.into()));
    for mode in [
        GitMode::Log { options: None },
        GitMode::LogArguments(vec!["--all".into()]),
        GitMode::Diff { staged: true },
    ] {
        let mut source = rustleaks_sources::GitSource::new(root.path())
            .executable(&git)
            .mode(mode.clone())
            .command_environment(translated.clone());
        let (fragments, issues) = collect(&mut source);
        assert!(fragments.is_empty(), "{mode:?}");
        assert!(issues.is_empty(), "{mode:?}: {issues:?}");
    }

    // A locale that the caller sets for Git is kept, so its translated
    // warning is reported.
    let mut source = rustleaks_sources::GitSource::new(root.path())
        .executable(&git)
        .mode(GitMode::LogArguments(vec!["--all".into()]))
        .command_environment([("LC_ALL".into(), "de_DE.UTF-8".into())]);
    let (_, issues) = collect(&mut source);
    assert_eq!(issues, [SourceIssueKind::GitStderr]);
}

#[cfg(unix)]
#[test]
fn repository_config_cannot_run_commands_or_replace_patch_content() {
    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let root = TempRepo(std::env::temp_dir().join(format!(
        "rustleaks-git-config-commands-{}-{unique}",
        std::process::id()
    )));
    let repository = root.path().join("repository");
    let tools = root.path().join("tools");
    fs::create_dir_all(&repository).expect("create synthetic repository");
    fs::create_dir_all(&tools).expect("create script directory");
    let git = |arguments: &[&str]| {
        let output = support::command()
            .arg("-C")
            .arg(&repository)
            .args([
                "-c",
                "user.name=Synthetic Test",
                "-c",
                "user.email=synthetic@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.fsmonitor=",
            ])
            .args(arguments)
            .output()
            .expect("run isolated Git");
        assert!(output.status.success(), "isolated Git {arguments:?} failed");
    };
    git(&["init", "--quiet"]);
    fs::write(repository.join(".gitattributes"), "*.txt diff=hide\n").expect("write attributes");
    fs::write(repository.join("value.txt"), "raw committed content\n").expect("write file");
    git(&["add", "--", ".gitattributes", "value.txt"]);
    git(&["commit", "--quiet", "-m", "synthetic commit"]);

    let textconv = recording_script(&tools, "textconv");
    let monitor = recording_script(&tools, "fsmonitor");
    let signature = recording_script(&tools, "gpg");
    for (key, value) in [
        ("diff.hide.textconv", textconv.to_str().unwrap()),
        ("core.fsmonitor", monitor.to_str().unwrap()),
        ("gpg.program", signature.to_str().unwrap()),
        ("log.showSignature", "true"),
        ("color.ui", "always"),
    ] {
        git(&["config", "--local", key, value]);
    }
    fs::write(repository.join("value.txt"), "raw staged content\n").expect("stage change");
    git(&["add", "--", "value.txt"]);
    fs::write(repository.join("value.txt"), "raw worktree content\n").expect("worktree change");

    let processes = std::num::NonZeroUsize::new(2).unwrap();
    let cases = [
        (GitMode::Log { options: None }, "raw committed content\n"),
        (
            GitMode::LogArguments(vec!["--all".into()]),
            "raw committed content\n",
        ),
        (GitMode::Diff { staged: true }, "raw staged content\n"),
        (GitMode::Diff { staged: false }, "raw worktree content\n"),
    ];
    for (mode, expected) in cases {
        for many in [false, true] {
            let mut source = support::git_source(&repository).mode(mode.clone());
            if many {
                source = source.history_processes(processes);
            }
            let (fragments, issues) = collect(&mut source);
            assert!(issues.is_empty(), "{mode:?}: {issues:?}");
            let contents = fragments
                .iter()
                .filter(|fragment| fragment.file_path().as_bytes() == b"value.txt")
                .map(|fragment| fragment.content().as_bytes().to_vec())
                .collect::<Vec<_>>();
            assert_eq!(contents, [expected.as_bytes()], "{mode:?}");
        }
    }
    for name in ["textconv", "fsmonitor", "gpg"] {
        assert!(
            !tools.join(format!("{name}.ran")).exists(),
            "Git ran the repository's {name} command"
        );
    }
}

/// A file that `.gitattributes` marks as binary is read by its content in
/// history and staged scans, in SHA-1 and SHA-256 repositories, also when
/// `GIT_ATTR_SOURCE` names the commit's attributes. A file with a NUL byte
/// is binary by its content even when the attributes mark it as text
/// (`diff`). A worktree diff keeps the attributes, so the file marked
/// binary stays binary there.
#[test]
fn attributes_that_mark_text_as_binary_do_not_hide_history_content() {
    for format in ["sha1", "sha256"] {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = TempRepo(std::env::temp_dir().join(format!(
            "rustleaks-git-binary-attributes-{format}-{}-{unique}",
            std::process::id()
        )));
        let repository = root.path().to_path_buf();
        fs::create_dir_all(&repository).expect("create synthetic repository");
        let git = |arguments: &[&str]| {
            let output = support::command()
                .arg("-C")
                .arg(&repository)
                .args([
                    "-c",
                    "user.name=Synthetic Test",
                    "-c",
                    "user.email=synthetic@example.invalid",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.fsmonitor=",
                ])
                .args(arguments)
                .output()
                .expect("run isolated Git");
            assert!(output.status.success(), "isolated Git {arguments:?} failed");
        };
        git(&["init", "--quiet", &format!("--object-format={format}")]);
        // Git for Windows sets `core.autocrlf` in its system configuration,
        // and the worktree diff would then warn about line endings.
        git(&["config", "--local", "core.autocrlf", "false"]);
        fs::write(
            repository.join(".gitattributes"),
            "*.env -diff\n*.lock binary\n*.dat diff\n",
        )
        .expect("write attributes");
        fs::write(repository.join("first.env"), "first marked text\n").expect("write file");
        fs::write(repository.join("real.bin"), b"binary\0content\n").expect("write file");
        fs::write(
            repository.join("forced.dat"),
            b"binary\0content\nforced text\n",
        )
        .expect("write file");
        git(&["add", "--", "."]);
        git(&["commit", "--quiet", "-m", "first synthetic commit"]);
        fs::write(repository.join("second.lock"), "second marked text\n").expect("write file");
        git(&["add", "--", "second.lock"]);
        git(&["commit", "--quiet", "-m", "second synthetic commit"]);
        fs::write(repository.join("third.env"), "staged marked text\n").expect("write file");
        git(&["add", "--", "third.env"]);
        fs::write(repository.join("third.env"), "worktree marked text\n").expect("write file");

        let contents = |label: &str, source: &mut rustleaks_sources::GitSource| {
            let (fragments, issues) = collect(source);
            assert!(issues.is_empty(), "{format} {label}: {issues:?}");
            let mut contents = fragments
                .iter()
                .map(|fragment| {
                    (
                        String::from_utf8_lossy(fragment.file_path().as_bytes()).into_owned(),
                        String::from_utf8_lossy(fragment.content().as_bytes()).into_owned(),
                    )
                })
                .filter(|(path, _)| path != ".gitattributes")
                .collect::<Vec<_>>();
            contents.sort();
            contents
        };
        let history = [
            ("first.env".to_owned(), "first marked text\n".to_owned()),
            ("second.lock".to_owned(), "second marked text\n".to_owned()),
        ];
        let one = std::num::NonZeroUsize::MIN;
        let two = std::num::NonZeroUsize::new(2).unwrap();
        for (label, mut source) in [
            ("history", support::git_source(&repository)),
            (
                "two processes",
                support::git_source(&repository)
                    .history_processes(two)
                    .history_batch_commits(one),
            ),
            (
                "log arguments",
                support::git_source(&repository).mode(GitMode::LogArguments(vec!["--all".into()])),
            ),
            (
                "history with GIT_ATTR_SOURCE",
                support::git_source(&repository)
                    .command_environment([("GIT_ATTR_SOURCE".into(), "HEAD".into())]),
            ),
            (
                "two processes with GIT_ATTR_SOURCE",
                support::git_source(&repository)
                    .command_environment([("GIT_ATTR_SOURCE".into(), "HEAD".into())])
                    .history_processes(two)
                    .history_batch_commits(one),
            ),
        ] {
            assert_eq!(contents(label, &mut source), history, "{format} {label}");
        }
        for (label, mut staged) in [
            (
                "staged",
                support::git_source(&repository).mode(GitMode::Diff { staged: true }),
            ),
            (
                "staged with GIT_ATTR_SOURCE",
                support::git_source(&repository)
                    .mode(GitMode::Diff { staged: true })
                    .command_environment([("GIT_ATTR_SOURCE".into(), "HEAD".into())]),
            ),
        ] {
            assert_eq!(
                contents(label, &mut staged),
                [("third.env".to_owned(), "staged marked text\n".to_owned())],
                "{format} {label}"
            );
        }
        let mut worktree = support::git_source(&repository).mode(GitMode::Diff { staged: false });
        assert_eq!(contents("worktree", &mut worktree), [], "{format}");
    }
}
