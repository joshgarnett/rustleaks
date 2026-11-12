//! Isolated native Git subprocess coverage.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustleaks_core::model::Fragment;
#[cfg(feature = "archives")]
use rustleaks_sources::ArchiveOptions;
use rustleaks_sources::{
    CallbackError, CancellationToken, GitLimits, GitMode, Source, SourceControl, SourceError,
    SourceEvent, SourceIssueKind, SourceStage,
};

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
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/fixtures/upstream")
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

fn collect(source: &mut dyn Source) -> (Vec<Fragment>, Vec<SourceIssueKind>) {
    let mut fragments = Vec::new();
    let mut issues = Vec::new();
    source
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Fragment { fragment, issue } => {
                    fragments.push(*fragment);
                    if let Some(issue) = issue {
                        issues.push(issue.kind());
                    }
                }
                SourceEvent::Issue(issue) => issues.push(issue.kind()),
                _ => panic!("unexpected future Git source event"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("Git source succeeds");
    (fragments, issues)
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
fn scripted_patch_source(
    patch: &[u8],
    stderr: bool,
    exit_code: u8,
) -> (TempRepo, rustleaks_sources::GitSource) {
    use std::os::unix::fs::PermissionsExt as _;

    let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let repository = TempRepo(std::env::temp_dir().join(format!(
        "rustleaks-git-patch-{}-{unique}",
        std::process::id()
    )));
    fs::create_dir(repository.path()).expect("create synthetic patch directory");
    let executable = repository.path().join("git-fixture");
    let mut script = b"#!/bin/sh\nprintf '%s' '".to_vec();
    for byte in patch {
        if *byte == b'\'' {
            script.extend_from_slice(b"'\\''");
        } else {
            script.push(*byte);
        }
    }
    script.extend_from_slice(b"'\n");
    if stderr {
        script.extend_from_slice(b"printf 'synthetic warning\\n' >&2\n");
    }
    script.extend_from_slice(format!("exit {exit_code}\n").as_bytes());
    fs::write(&executable, script).expect("write synthetic Git command");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("make synthetic Git command executable");
    let source = rustleaks_sources::GitSource::new(repository.path()).executable(executable);
    (repository, source)
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
            let (_repository, mut source) = scripted_patch_source(SYNTHETIC_HUNK_PATCH, false, 0);
            let mut seen = 0;
            let result = source.visit(&CancellationToken::new(), &mut |event| {
                assert!(matches!(event, SourceEvent::Fragment { issue: None, .. }));
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
            assert_eq!(seen, stop_at);
            if fail {
                assert!(matches!(result, Err(SourceError::Callback(_))));
            } else {
                assert_eq!(result.expect("normal callback stop"), SourceControl::Stop);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn late_patch_and_command_errors_publish_no_fragments() {
    let mut truncated = SYNTHETIC_HUNK_PATCH.to_vec();
    truncated.extend_from_slice(
        b"diff --git a/broken b/broken\n--- a/broken\n+++ b/broken\n@@ -0,0 +1,2 @@\n+truncated\n",
    );
    for (patch, exit_code, stage) in [
        (truncated.as_slice(), 0, SourceStage::GitParse),
        (SYNTHETIC_HUNK_PATCH, 7, SourceStage::GitExit),
    ] {
        for stderr in [false, true] {
            let (_repository, mut source) = scripted_patch_source(patch, stderr, exit_code);
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
                matches!(error, SourceError::Terminal { stage: actual, .. } if actual == stage)
            );
            assert_eq!(fragments, 0);
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

#[test]
fn default_log_matches_current_pinned_added_fragment_stream() {
    let repository = TempRepo::copy_fixture("small");
    let mut source = support::git_source(repository.path());
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());

    let mut actual = Vec::new();
    for fragment in &fragments {
        actual.extend_from_slice(fragment.content().as_bytes());
    }
    let ignore = fs::read(repository.path().join("api/ignoreCommit.go"))
        .expect("read pinned ignore fixture");
    let legacy = fs::read(fixture_root().join("testdata/expected/git/small.txt"))
        .expect("read pinned legacy golden");
    let mut expected = Vec::new();
    expected.extend_from_slice(&ignore);
    expected.extend_from_slice(&ignore);
    expected.extend_from_slice(&legacy);
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
fn matrix_f_diff_and_index_fragments_have_zero_metadata() {
    let repository = TempRepo::copy_fixture("staged");
    let mut source = support::git_source(repository.path()).mode(GitMode::Diff { staged: true });
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].file_path().as_bytes(), b"api/api.go");
    assert_eq!(fragments[0].start_line(), 6);
    assert_eq!(
        fragments[0].content().as_bytes(),
        b"\taws_token := \"AKIALALEMEL33243OLIA\"  // fingerprint of that secret is added to .gitleaksignore\n\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not\n\tfmt.Println(aws_token)\n\tfmt.Println(aws_token2)\n"
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
fn matrix_i_callback_failure_remains_distinct_after_git_is_reaped() {
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
fn matrix_e_binary_and_history_archives_reuse_safe_archive_expansion() {
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
            .any(|window| window == b"AKIALALEMEL33243OLIA")
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
fn matrix_k_archive_blob_exact_over_and_early_stop_are_structured() {
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

    let error = support::git_source(repository.path())
        .mode(mode())
        .limits(limits(blob_size - 1))
        .archives(ArchiveOptions::default())
        .visit(&CancellationToken::new(), &mut |_| {
            Ok(SourceControl::Continue)
        })
        .expect_err("over-limit archive blob");
    assert!(matches!(
        error,
        SourceError::Terminal {
            stage: SourceStage::Limit,
            ..
        }
    ));

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
