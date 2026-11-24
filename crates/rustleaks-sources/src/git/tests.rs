use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use super::patch::*;
use super::process::*;
use super::text::*;
use super::*;

struct CancelAfterPolls(std::sync::atomic::AtomicUsize);

impl Cancellation for CancelAfterPolls {
    fn is_cancelled(&self) -> bool {
        let mut previous = self.0.load(Ordering::Acquire);
        loop {
            match self.0.compare_exchange_weak(
                previous,
                previous.saturating_sub(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        previous == 0
    }
}

#[cfg(unix)]
struct CancelWhenFileContainsPid(PathBuf);

#[cfg(unix)]
impl Cancellation for CancelWhenFileContainsPid {
    fn is_cancelled(&self) -> bool {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|pid| pid != 0)
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected pipe read failure"))
    }
}

#[derive(Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent injected lifecycle outcomes"
)]
struct LifecycleProbe {
    terminated: bool,
    reaped: bool,
    fail_terminate: bool,
    fail_reap: bool,
}

impl GitChildLifecycle for LifecycleProbe {
    fn terminate(&mut self) -> io::Result<()> {
        self.terminated = true;
        if self.fail_terminate {
            Err(io::Error::other("injected terminate failure"))
        } else {
            Ok(())
        }
    }

    fn reap(&mut self) -> io::Result<()> {
        self.reaped = true;
        if self.fail_reap {
            Err(io::Error::other("injected reap failure"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn cleanup_attempts_reap_after_kill_failure_and_fails_closed() {
    for (fail_terminate, fail_reap) in [(true, false), (false, true), (true, true)] {
        let mut child = LifecycleProbe {
            fail_terminate,
            fail_reap,
            ..LifecycleProbe::default()
        };
        let error = stop_and_reap(&mut child, SourceStage::GitCommand, "injected")
            .expect_err("cleanup failure must be terminal");
        assert!(matches!(
            error,
            SourceError::Terminal {
                stage: SourceStage::GitCommand,
                ..
            }
        ));
        assert!(child.terminated);
        assert!(child.reaped);
    }
}

#[test]
fn subprocess_fixture_waits() {
    if let Some(code) = std::env::var_os("RUSTLEAKS_GIT_CHILD_EXIT") {
        use std::io::Write as _;
        if let Some(length) = std::env::var_os("RUSTLEAKS_GIT_CHILD_STDOUT_BYTES") {
            let length = length.to_string_lossy().parse().expect("stdout byte count");
            std::io::stdout()
                .write_all(&vec![b'x'; length])
                .expect("write fixture stdout");
        }
        if let Some(stderr) = std::env::var_os("RUSTLEAKS_GIT_CHILD_STDERR") {
            std::io::stderr()
                .write_all(stderr.to_string_lossy().as_bytes())
                .expect("write fixture stderr");
        }
        let code = code.to_string_lossy().parse().expect("numeric exit code");
        std::process::exit(code);
    }
    if std::env::var_os("RUSTLEAKS_GIT_CANCEL_CHILD").is_none() {
        return;
    }
    if let Some(path) = std::env::var_os("RUSTLEAKS_GIT_CANCEL_PID_FILE") {
        std::fs::write(path, std::process::id().to_string()).expect("write child PID");
    }
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn cancellation_after_spawn_kills_reaps_and_joins_git_helpers() {
    let executable = std::env::current_exe().expect("current test executable");
    let environment = [(
        OsString::from("RUSTLEAKS_GIT_CANCEL_CHILD"),
        OsString::from("1"),
    )];
    for stage in [SourceStage::GitCommand, SourceStage::GitBlob] {
        let cancellation = CancelAfterPolls(std::sync::atomic::AtomicUsize::new(4));
        let started = std::time::Instant::now();
        let result = stream_command(
            executable.as_os_str(),
            &fixture_arguments(),
            64 * 1024,
            &environment,
            &cancellation,
            stage,
            &mut |_| Ok(SourceControl::Continue),
        );
        assert!(matches!(result, Err(SourceError::Cancelled)));
        // The child sleeps for 30 seconds unless it is killed.
        assert!(started.elapsed() < Duration::from_secs(20));
    }
}

#[cfg(unix)]
#[test]
fn cancelled_git_child_is_not_left_waitable_or_zombie() {
    let pid_path =
        std::env::temp_dir().join(format!("rustleaks-git-child-pid-{}", std::process::id()));
    let _ = std::fs::remove_file(&pid_path);
    let executable = std::env::current_exe().expect("current test executable");
    let environment = [
        (
            OsString::from("RUSTLEAKS_GIT_CANCEL_CHILD"),
            OsString::from("1"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CANCEL_PID_FILE"),
            pid_path.as_os_str().to_owned(),
        ),
    ];
    let cancellation = CancelWhenFileContainsPid(pid_path.clone());
    let result = stream_command(
        executable.as_os_str(),
        &fixture_arguments(),
        64 * 1024,
        &environment,
        &cancellation,
        SourceStage::GitCommand,
        &mut |_| Ok(SourceControl::Continue),
    );
    assert!(matches!(result, Err(SourceError::Cancelled)));
    let raw_pid = std::fs::read_to_string(&pid_path)
        .expect("read selected child PID")
        .parse()
        .expect("selected child PID is numeric");
    let pid = rustix::process::Pid::from_raw(raw_pid).expect("selected child PID is nonzero");
    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
        Err(error) if error == rustix::io::Errno::CHILD => {}
        Ok(Some((unreaped, status))) => {
            panic!("cancelled Git child PID {unreaped} remained waitable: {status:?}")
        }
        Ok(None) => panic!("cancelled Git child PID {pid} was still running"),
        Err(error) => panic!("could not verify cancelled Git child PID {pid}: {error}"),
    }
    std::fs::remove_file(pid_path).expect("remove child PID record");
}

#[test]
fn matrix_b_text_patch_hunks_preserve_added_bytes_and_no_newline() {
    let patch = b"commit 0123456789abcdef\nAuthor: Test User <user@example.com>\nDate:   Tue Nov 2 18:37:53 2021 -0500\n\n    title\n\ndiff --git a/a.txt b/a.txt\nindex 1111111..2222222 100644\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1,2 @@\n-old\n+new\n+tail\n\\ No newline at end of file\n";
    let files = parse_patch(
        patch,
        GitLimits::default(),
        &crate::CancellationToken::new(),
    )
    .expect("patch");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, b"a.txt");
    assert_eq!(files[0].hunks[0].added, b"new\ntail");
    assert_eq!(files[0].hunks[0].new_position, 1);
    let metadata = files[0].metadata.as_ref().expect("metadata");
    assert_eq!(metadata.author_name().as_bytes(), b"Test User");
    assert_eq!(metadata.author_email().as_bytes(), b"user@example.com");
    assert_eq!(metadata.date().as_bytes(), b"2021-11-02T23:37:53Z");
    assert_eq!(metadata.message().as_bytes(), b"title");
}

#[test]
fn matrix_c_strict_byte_paths_decode_git_quoting() {
    assert_eq!(
        decode_patch_path(
            br#""b/tab\tand\303\251.txt""#,
            true,
            1024,
            &crate::CancellationToken::new(),
        )
        .expect("path"),
        b"tab\tand\xc3\xa9.txt"
    );
    assert_eq!(
        decode_patch_path(
            br#""b/invalid-\377""#,
            true,
            1024,
            &crate::CancellationToken::new(),
        )
        .expect("invalid UTF-8 path"),
        b"invalid-\xff"
    );
    assert_eq!(
        decode_patch_path(
            b"b/repeated///slash",
            true,
            1024,
            &crate::CancellationToken::new(),
        )
        .expect("repeated slash path"),
        b"repeated/slash"
    );
}

#[test]
fn nontext_records_preserve_quoted_and_ambiguous_paths() {
    // GIT-007/008: the filename is independent of whether a text hunk exists.
    let paths: &[(&str, &[u8])] = &[
        ("plain.tar", b"plain.tar"),
        ("with space.tar", b"with space.tar"),
        ("folder b/nested.tar", b"folder b/nested.tar"),
        (r"tab\tname.tar", b"tab\tname.tar"),
        (r"invalid-\377.tar", b"invalid-\xff.tar"),
        (r#"quote\"name.tar"#, b"quote\"name.tar"),
        (r"back\\slash.tar", b"back\\slash.tar"),
    ];
    for &(spelling, expected) in paths {
        let quoted = spelling.contains('\\');
        let header = if quoted {
            format!("diff --git \"a/{spelling}\" \"b/{spelling}\"\n")
        } else {
            format!("diff --git a/{spelling} b/{spelling}\n")
        };
        for suffix in [
            "new file mode 100644\nBinary files /dev/null and placeholder differ\n",
            "old mode 100644\nnew mode 100755\n",
            "new file mode 100644\n",
        ] {
            let patch = format!("{header}{suffix}");
            let limits = GitLimits::default()
                .with_parser_limits(20, expected.len(), 1, 1)
                .expect("exact path and file limits");
            let files = parse_patch(patch.as_bytes(), limits, &crate::CancellationToken::new())
                .expect("valid nontext patch");
            assert_eq!(files.len(), 1, "spelling={spelling}, suffix={suffix}");
            assert_eq!(
                files[0].path, expected,
                "spelling={spelling}, suffix={suffix}"
            );
            assert!(files[0].hunks.is_empty());
            assert!(matches!(
                parse_patch(
                    patch.repeat(2).as_bytes(),
                    limits,
                    &crate::CancellationToken::new()
                ),
                Err(PatchError::Limit(_))
            ));
            let over = limits
                .with_parser_limits(20, expected.len() - 1, 1, 1)
                .expect("short path limit");
            assert!(matches!(
                parse_patch(patch.as_bytes(), over, &crate::CancellationToken::new()),
                Err(PatchError::Limit(_))
            ));
        }
    }
    for operation in ["rename", "copy"] {
        let patch = format!(
            "diff --git a/old.tar \"b/new\\tname.tar\"\n{operation} from old.tar\n{operation} to \"new\\tname.tar\"\nBinary files a/old.tar and \"b/new\\tname.tar\" differ\n"
        );
        let files = parse_patch(
            patch.as_bytes(),
            GitLimits::default(),
            &crate::CancellationToken::new(),
        )
        .expect("nontext rename/copy patch");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, b"new\tname.tar");
    }
}

#[test]
fn mixed_quoted_rename_and_copy_paths_use_exact_decoded_limits() {
    type PathCase<'a> = (&'a str, &'a str, &'a str, &'a str, &'a [u8], usize);
    let cases: &[PathCase<'_>] = &[
        (
            "a/old",
            r#""b/new\tlong""#,
            "old",
            r#""new\tlong""#,
            b"new\tlong",
            8,
        ),
        (
            r#""a/old\tlong""#,
            "b/new",
            r#""old\tlong""#,
            "new",
            b"new",
            8,
        ),
        (
            "a/old-long-name",
            r#""b/n\t""#,
            "old-long-name",
            r#""n\t""#,
            b"n\t",
            13,
        ),
        (
            r#""a/o\t""#,
            "b/new-long-name",
            r#""o\t""#,
            "new-long-name",
            b"new-long-name",
            13,
        ),
    ];
    for &(old, new, from, to, expected, width) in cases {
        for operation in ["rename", "copy"] {
            for suffix in [
                "Binary files source and destination differ\n",
                "old mode 100644\nnew mode 100755\n",
                "@@ -0,0 +1 @@\n+new content\n",
            ] {
                let patch = format!(
                    "diff --git {old} {new}\n{operation} from {from}\n{operation} to {to}\n{suffix}"
                );
                let exact = GitLimits::default()
                    .with_parser_limits(20, width, 1, 1)
                    .unwrap();
                let files = parse_patch(patch.as_bytes(), exact, &crate::CancellationToken::new())
                    .expect("mixed quoting");
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].path, expected);
                if suffix.starts_with("@@") {
                    assert_eq!(files[0].hunks[0].added, b"new content\n");
                }
                let below = exact.with_parser_limits(20, width - 1, 1, 1).unwrap();
                assert!(matches!(
                    parse_patch(patch.as_bytes(), below, &crate::CancellationToken::new()),
                    Err(PatchError::Limit(_))
                ));
                assert!(matches!(
                    parse_patch(
                        patch.repeat(2).as_bytes(),
                        exact,
                        &crate::CancellationToken::new()
                    ),
                    Err(PatchError::Limit(_))
                ));
            }
        }
    }
}

#[test]
fn malformed_hunks_cannot_consume_a_later_record_boundary() {
    let prefix = "diff --git a/first b/first\n--- a/first\n+++ b/first\n";
    let boundaries = [
        "",
        "@@ -0,0 +8 @@\n+next hunk\n",
        "diff --git a/second b/second\n--- a/second\n+++ b/second\n@@ -0,0 +1 @@\n+next file\n",
        "commit abc\nAuthor: Synthetic <synthetic@example.invalid>\nDate:   Tue Nov 2 23:37:53 2021 +0000\n\n    synthetic\n\ndiff --git a/second b/second\nnew file mode 100644\n",
    ];
    for body in [
        "@@ -1,2 +1,2 @@\n context\n",
        "@@ -1 +1 @@\n-old\n",
        "@@ -0,0 +1,2 @@\n+only one\n",
        "@@ -1,2 +0,0 @@\n-only one\n",
        "@@ -0,0 +1 @@\n+complete\n+surplus\n",
        "@@ -1 +1 @@\n context\n-unexpected\n",
    ] {
        for boundary in boundaries {
            let patch = format!("{prefix}{body}{boundary}");
            assert!(
                matches!(
                    parse_patch(
                        patch.as_bytes(),
                        GitLimits::default(),
                        &crate::CancellationToken::new()
                    ),
                    Err(PatchError::Invalid(_))
                ),
                "body={body:?}, boundary={boundary:?}"
            );
        }
    }
    for body in [
        "@@ -1 +1 @@\n-old\n+new\n",
        "@@ -0,0 +1 @@\n+new\n\\ No newline at end of file\n",
    ] {
        for boundary in boundaries {
            let patch = format!("{prefix}{body}{boundary}");
            let files = parse_patch(
                patch.as_bytes(),
                GitLimits::default(),
                &crate::CancellationToken::new(),
            )
            .expect("complete control hunk");
            assert_eq!(files[0].path, b"first");
            assert_eq!(
                files[0].hunks[0].added,
                if body.contains("No newline") {
                    b"new".as_slice()
                } else {
                    b"new\n".as_slice()
                }
            );
        }
    }
}

#[test]
fn hunk_projection_preserves_compacted_bytes_and_record_boundaries() {
    // GIT-004/005/006: context and deleted bytes never enter Raw; StartLine
    // remains the new-range origin even when context precedes additions.
    for contexts in 0..=2 {
        for deletions in 0..=2 {
            for additions in 0..=2 {
                if deletions + additions == 0 {
                    continue;
                }
                for no_newline in [false, true] {
                    let mut patch = format!(
                            "diff --git a/first b/first\n--- a/first\n+++ b/first\n@@ -7,{} +13,{} @@\n",
                            contexts + deletions, contexts + additions
                        ).into_bytes();
                    for _ in 0..contexts {
                        patch.extend_from_slice(b" context\xff\n");
                    }
                    for _ in 0..deletions {
                        patch.extend_from_slice(b"-deleted\xfe\n");
                    }
                    if no_newline && deletions > 0 {
                        patch.extend_from_slice(b"\\ No newline at end of file\n");
                    }
                    let mut expected = b"added\xfd\r\n".repeat(additions);
                    for _ in 0..additions {
                        patch.extend_from_slice(b"+added\xfd\r\n");
                    }
                    if no_newline && additions > 0 {
                        patch.extend_from_slice(b"\\ No newline at end of file\n");
                        expected.pop();
                    }
                    let first_end = patch.len();
                    patch.extend_from_slice(b"@@ -20,0 +88 @@\n+next hunk\n");
                    patch.extend_from_slice(b"diff --git a/second b/second\n--- a/second\n+++ b/second\n@@ -0,0 +1 @@\n+next file\n");
                    let limits = GitLimits::default()
                        .with_parser_limits(20, 6, 2, 3)
                        .expect("exact aggregate record limits");
                    let files = parse_patch(&patch, limits, &crate::CancellationToken::new())
                        .expect("constructed patch");
                    assert_eq!(files.len(), 2);
                    assert_eq!(files[0].hunks.len(), 2);
                    assert_eq!(files[0].hunks[0].added, expected);
                    assert_eq!(files[0].hunks[0].new_position, 13);
                    assert_eq!(files[0].hunks[1].added, b"next hunk\n");
                    assert_eq!(files[0].hunks[1].new_position, 88);
                    assert_eq!(files[1].path, b"second");
                    assert_eq!(files[1].hunks[0].added, b"next file\n");
                    // Removing the final operation or its preceding newline
                    // leaves a count short; no later record may fill it in.
                    let mut truncated = patch[..first_end].to_vec();
                    if no_newline {
                        let marker = b"\\ No newline at end of file\n";
                        if truncated.ends_with(marker) {
                            truncated.truncate(truncated.len() - marker.len());
                        }
                    }
                    truncated.pop();
                    let last_line = truncated
                        .iter()
                        .rposition(|byte| *byte == b'\n')
                        .expect("header remains")
                        + 1;
                    truncated.truncate(last_line);
                    truncated.extend_from_slice(&patch[first_end..]);
                    assert!(matches!(
                        parse_patch(&truncated, limits, &crate::CancellationToken::new()),
                        Err(PatchError::Invalid(_))
                    ));
                }
            }
        }
    }
}

#[test]
fn malformed_old_hunk_positions_are_structured_errors() {
    for position in [
        "garbage",
        "",
        "9223372036854775808",
        "184467440737095516160",
    ] {
        let patch =
            format!("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -{position},1 +1 @@\n-old\n+new\n");
        assert!(
            matches!(
                parse_patch(
                    patch.as_bytes(),
                    GitLimits::default(),
                    &crate::CancellationToken::new()
                ),
                Err(PatchError::Invalid(_))
            ),
            "invalid old position must reject the complete patch: {position}"
        );
    }
    // The pinned parser uses signed int64 for this unused old position.
    for position in ["-1", "+1", "-9223372036854775808", "9223372036854775807"] {
        let patch =
            format!("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -{position},1 +1 @@\n-old\n+new\n");
        let files = parse_patch(
            patch.as_bytes(),
            GitLimits::default(),
            &crate::CancellationToken::new(),
        )
        .expect("pinned signed old position");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].hunks[0].added, b"new\n");
    }
}

#[test]
fn matrix_a_exact_argv_preserves_literal_space_splitting() {
    let source = GitSource::new("repo").mode(GitMode::Log {
        options: Some("--all  foo...".to_owned()),
    });
    assert_eq!(
        source
            .arguments(EMPTY_TREE_SHA1)
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>(),
        [
            "-C",
            "repo",
            "-c",
            "core.fsmonitor=",
            "-c",
            "attr.tree=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "log",
            "-p",
            "-U0",
            "--no-textconv",
            "--no-ext-diff",
            "--no-color",
            "--no-show-signature",
            "--all",
            "",
            "foo..."
        ]
    );

    assert_eq!(
        GitSource::new("").arguments(EMPTY_TREE_SHA1)[1].to_string_lossy(),
        "."
    );
    let arguments = GitSource::new("repo space/é")
        .mode(GitMode::LogArguments(vec![
            OsString::from("-U3"),
            OsString::from("--pretty=short"),
            OsString::from("--no-patch"),
        ]))
        .arguments(EMPTY_TREE_SHA1);
    assert_eq!(arguments[0], "-C");
    assert_eq!(
        PathBuf::from(arguments[1].as_os_str()),
        PathBuf::from("repo space/é")
    );
    assert_eq!(
        arguments[6..]
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>(),
        [
            "log",
            "-p",
            "-U0",
            "--no-textconv",
            "--no-ext-diff",
            "--no-color",
            "--no-show-signature",
            "-U3",
            "--pretty=short",
            "--no-patch"
        ]
    );

    let explicit = GitSource::new("repo").mode(GitMode::LogArguments(vec![
        OsString::from("--all"),
        OsString::from("path with spaces"),
    ]));
    assert_eq!(
        explicit
            .arguments(EMPTY_TREE_SHA1)
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>(),
        [
            "-C",
            "repo",
            "-c",
            "core.fsmonitor=",
            "-c",
            "attr.tree=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "log",
            "-p",
            "-U0",
            "--no-textconv",
            "--no-ext-diff",
            "--no-color",
            "--no-show-signature",
            "--all",
            "path with spaces"
        ]
    );
}

#[test]
fn history_and_staged_diffs_read_attributes_from_the_empty_tree() {
    let words = |source: GitSource, tree: &str| {
        source
            .arguments(tree)
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };
    let sha256 = format!("attr.tree={EMPTY_TREE_SHA256}");
    for mode in [
        GitMode::Log { options: None },
        GitMode::LogArguments(vec![OsString::from("--all")]),
        GitMode::Diff { staged: true },
    ] {
        let arguments = words(GitSource::new("repo").mode(mode.clone()), EMPTY_TREE_SHA256);
        assert_eq!(
            arguments[2..6],
            ["-c", "core.fsmonitor=", "-c", sha256.as_str()],
            "{mode:?}"
        );
    }
    let worktree = words(
        GitSource::new("repo").mode(GitMode::Diff { staged: false }),
        EMPTY_TREE_SHA256,
    );
    assert_eq!(
        worktree,
        [
            "-C",
            "repo",
            "-c",
            "core.fsmonitor=",
            "diff",
            "-U0",
            "--no-textconv",
            "--no-ext-diff",
            "--no-color",
            "."
        ]
    );
}

#[test]
fn classifies_only_pinned_stderr_warnings_as_ignorable() {
    assert!(first_non_ignored_stderr(b"Auto packing the repository in background for optimum performance.\nSee \"git help gc\" for manual housekeeping.\n").is_none());
    assert_eq!(
        first_non_ignored_stderr(b"warning\nfatal: broken\n"),
        Some(b"warning".as_slice())
    );
    assert_eq!(first_non_ignored_stderr(b"\n"), Some(b"".as_slice()));
    assert_eq!(
        first_non_ignored_stderr(b"warning\r\n"),
        Some(b"warning".as_slice())
    );
}

#[test]
fn matrix_j_resource_boundaries_fail_closed() {
    assert!(GitLimits::new(0, 1, 1, 1).is_err());
    assert!(GitLimits::new(1, 0, 1, 1).is_err());
    assert!(GitLimits::new(1, 1, 0, 1).is_err());
    assert!(GitLimits::new(1, 1, 1, 0).is_err());
    assert!(GitLimits::default().with_parser_limits(0, 1, 1, 1).is_err());
    assert!(GitLimits::default().with_parser_limits(1, 0, 1, 1).is_err());
    assert!(GitLimits::default().with_parser_limits(1, 1, 0, 1).is_err());
    assert!(GitLimits::default().with_parser_limits(1, 1, 1, 0).is_err());

    let exceeded = OutputBudget::new(5);
    let (retained, limited) =
        read_bounded_and_drain(io::Cursor::new(b"abcdef"), &exceeded).expect("bounded read");
    assert_eq!(retained, b"abcde");
    assert!(limited);
    assert!(exceeded.is_exceeded());

    let exact = OutputBudget::new(5);
    let (retained, limited) =
        read_bounded_and_drain(io::Cursor::new(b"abcde"), &exact).expect("exact read");
    assert_eq!(retained, b"abcde");
    assert!(!limited);
    assert!(!exact.is_exceeded());

    // Readers that share a budget keep at most its bytes together.
    let shared = OutputBudget::new(6);
    let (first, first_limited) =
        read_bounded_and_drain(io::Cursor::new(b"abcd"), &shared).expect("first read");
    assert_eq!(
        (first.as_slice(), first_limited),
        (b"abcd".as_slice(), false)
    );
    assert!(!shared.is_exceeded());
    let (second, second_limited) =
        read_bounded_and_drain(io::Cursor::new(b"efgh"), &shared).expect("second read");
    assert_eq!(
        (second.as_slice(), second_limited),
        (b"ef".as_slice(), true)
    );
    assert!(shared.is_exceeded());

    let limits = GitLimits::new(64, 2, 64, 64).expect("limits");
    assert!(parse_patch(b"\n\n", limits, &crate::CancellationToken::new()).is_ok());
    assert!(
        parse_patch(
            b"one\ntwo\nthree\n",
            limits,
            &crate::CancellationToken::new()
        )
        .is_err()
    );
}

/// Runs a command through [`stream_command`] and keeps its standard
/// output.
fn run_streamed(
    program: &OsStr,
    arguments: &[OsString],
    stderr_limit: usize,
    environment: &[(OsString, OsString)],
    stage: SourceStage,
) -> Result<(Vec<u8>, StreamedOutput), SourceError> {
    let mut stdout = Vec::new();
    let output = stream_command(
        program,
        arguments,
        stderr_limit,
        environment,
        &crate::CancellationToken::new(),
        stage,
        &mut |chunk| {
            stdout.extend_from_slice(chunk);
            Ok(SourceControl::Continue)
        },
    )?;
    Ok((stdout, output))
}

#[test]
fn matrix_h_exit_status_and_bounded_stderr_are_diagnostic() {
    let executable = std::env::current_exe().expect("current test executable");
    let environment = [
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
            OsString::from("7"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
            OsString::from("fixture stderr"),
        ),
    ];
    let (_, output) = run_streamed(
        executable.as_os_str(),
        &fixture_arguments(),
        64 * 1024,
        &environment,
        SourceStage::GitCommand,
    )
    .expect("collect child failure");
    let message = git_exit_message(output.status, &output.stderr);
    assert!(message.contains('7'), "{message}");
    assert!(message.contains("fixture stderr"), "{message}");
    #[cfg(feature = "archives")]
    assert!(matches!(
        validate_archive_blob_output(
            output.stderr_limited,
            output.status,
            &output.stderr,
            std::path::Path::new("repository")
        ),
        Err(SourceError::Terminal {
            stage: SourceStage::GitBlob,
            ..
        })
    ));

    for stderr in ["", "exhaustive rename detection was skipped\n"] {
        let environment = [
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
                OsString::from("9"),
            ),
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
                OsString::from(stderr),
            ),
        ];
        let (_, output) = run_streamed(
            executable.as_os_str(),
            &fixture_arguments(),
            64,
            &environment,
            SourceStage::GitCommand,
        )
        .expect("collect nonzero fixture");
        assert!(!output.status.expect("status").success());
        assert!(git_exit_message(output.status, &output.stderr).contains('9'));
    }

    let overflow_environment = [
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
            OsString::from("0"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
            OsString::from("12345"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_STDOUT_BYTES"),
            OsString::from("5"),
        ),
    ];
    let (stdout, exact) = run_streamed(
        executable.as_os_str(),
        &fixture_arguments(),
        5,
        &overflow_environment,
        SourceStage::GitBlob,
    )
    .expect("exact command boundaries");
    assert!(!exact.stderr_limited);
    assert_eq!(exact.stderr, b"12345");
    assert!(stdout.contains(&b'x'));
    #[cfg(feature = "archives")]
    assert!(
        validate_archive_blob_output(
            exact.stderr_limited,
            exact.status,
            &exact.stderr,
            std::path::Path::new("repository")
        )
        .expect("successful blob classification")
        .is_some()
    );
    let (_, overflow) = run_streamed(
        executable.as_os_str(),
        &fixture_arguments(),
        4,
        &overflow_environment,
        SourceStage::GitBlob,
    )
    .expect("overflow command boundaries");
    assert!(overflow.stderr_limited);
    #[cfg(feature = "archives")]
    assert!(matches!(
        validate_archive_blob_output(
            overflow.stderr_limited,
            overflow.status,
            &overflow.stderr,
            std::path::Path::new("repository")
        ),
        Err(SourceError::Terminal {
            stage: SourceStage::Limit,
            ..
        })
    ));

    let missing = run_streamed(
        OsStr::new("rustleaks-deliberately-missing-git-executable"),
        &[],
        1,
        &[],
        SourceStage::GitCommand,
    );
    assert!(matches!(
        missing,
        Err(SourceError::Terminal {
            stage: SourceStage::GitCommand,
            ..
        })
    ));
}

#[test]
fn matrix_d_metadata_uses_go_unicode_whitespace() {
    let patch = "commit abc\nAuthor: \u{3000}A User\u{00a0} <a@example.com>\nDate:   Tue Nov 2 18:37:53 2021 -0500\n\n    \u{3000}title\u{00a0}\n\ndiff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
    let files = parse_patch(
        patch.as_bytes(),
        GitLimits::default(),
        &crate::CancellationToken::new(),
    )
    .expect("Unicode metadata patch");
    let metadata = files[0].metadata.as_ref().expect("metadata");
    assert_eq!(metadata.author_name().as_bytes(), b"A User");
    assert_eq!(metadata.message().as_bytes(), b"title");

    let fuller = b"commit abc\nAuthor: A User <a@example.com>\nAuthorDate: Tue Nov 2 18:37:53 2021 -0500\nCommit: C User <c@example.com>\nCommitDate: Wed Nov 3 18:37:53 2021 -0500\n\n    fuller title\n\ndiff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
    let files = parse_patch(
        fuller,
        GitLimits::default(),
        &crate::CancellationToken::new(),
    )
    .expect("fuller metadata patch");
    let metadata = files[0].metadata.as_ref().expect("fuller metadata");
    assert_eq!(metadata.author_name().as_bytes(), b"A User");
    assert_eq!(metadata.date().as_bytes(), b"2021-11-02T23:37:53Z");
    assert_eq!(metadata.message().as_bytes(), b"fuller title");
}

#[test]
fn malformed_multibyte_git_timezone_fails_closed() {
    assert_eq!(
        git_date_to_rfc3339("Thu Jan 1 00:00:00 1970 +0풉".as_bytes(), 64)
            .expect("malformed date is non-fatal"),
        None
    );
}

#[test]
fn overflowing_git_dates_are_ignored_without_panicking() {
    for date in [
        "Thu Jan 1 9223372036854775807:00:00 1970 +0000",
        "Thu Jan 1 -9223372036854775808:00:00 1970 +0000",
        "Thu Jan 1 00:9223372036854775807:00 1970 +0000",
        "Thu Jan 1 00:-9223372036854775808:00 1970 +0000",
        "Thu Jan 1 01:00:9223372036854775807 1970 +0000",
        "Thu Jan 1 -1:00:-9223372036854775808 1970 +0000",
        "Thu Jan 1 00:00:00 9223372036854775807 +0000",
        "Thu Jan 1 00:00:00 -9223372036854775808 +0000",
        "Thu Mar 1 00:00:00 -9223372036854775808 +0000",
    ] {
        assert_eq!(
            git_date_to_rfc3339(date.as_bytes(), 64).expect("invalid date is non-fatal"),
            None,
            "{date}"
        );
        let patch = format!(
            "commit abc\nDate:   {date}\n\ndiff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n"
        );
        let files = parse_patch(
            patch.as_bytes(),
            GitLimits::default(),
            &crate::CancellationToken::new(),
        )
        .expect("invalid date preserves the patch");
        assert_eq!(
            files[0]
                .metadata
                .as_ref()
                .expect("metadata")
                .date()
                .as_bytes(),
            b"0001-01-01T00:00:00Z"
        );
    }
}

#[test]
fn malformed_diff_and_hunk_fail_closed() {
    for patch in [
        b"arbitrary non-patch output\n".as_slice(),
        b"diff --git a/x b/x\nnonsense\n".as_slice(),
        b"diff --git a/x b/x\n--- a/x\n".as_slice(),
        b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n".as_slice(),
        b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+x\n+surplus\n".as_slice(),
    ] {
        assert!(matches!(
            parse_patch(
                patch,
                GitLimits::default(),
                &crate::CancellationToken::new()
            ),
            Err(PatchError::Invalid(_))
        ));
    }
}

#[test]
fn matrix_j_cancellation_is_polled_during_large_parser_streams() {
    let input = vec![b'x'; 64 * 1024];
    assert!(matches!(
        parse_patch(
            &input,
            GitLimits::default(),
            &CancelAfterPolls(std::sync::atomic::AtomicUsize::new(2)),
        ),
        Err(PatchError::Cancelled)
    ));
}

#[test]
fn matrix_k_parser_resource_boundaries_are_exact() {
    let cancellation = crate::CancellationToken::new();
    assert_eq!(
        decode_patch_path(b"b/abcd", true, 4, &cancellation).expect("exact path"),
        b"abcd"
    );
    assert!(matches!(
        decode_patch_path(b"b/abcde", true, 4, &cancellation),
        Err(PatchError::Limit(_))
    ));

    let one_file = b"diff --git a/abcd b/abcd\n--- a/abcd\n+++ b/abcd\n@@ -0,0 +1 @@\n+x\n";
    let two_files = b"diff --git a/abcd b/abcd\n--- a/abcd\n+++ b/abcd\ndiff --git a/efgh b/efgh\n--- a/efgh\n+++ b/efgh\n";
    let two_hunks =
        b"diff --git a/abcd b/abcd\n--- a/abcd\n+++ b/abcd\n@@ -0,0 +1 @@\n+x\n@@ -0,0 +1 @@\n+y\n";
    let exact = GitLimits::default()
        .with_parser_limits(20, 4, 1, 1)
        .expect("exact parser limits");
    assert!(parse_patch(one_file, exact, &cancellation).is_ok());
    assert!(matches!(
        parse_patch(two_files, exact, &cancellation),
        Err(PatchError::Limit(_))
    ));
    assert!(matches!(
        parse_patch(two_hunks, exact, &cancellation),
        Err(PatchError::Limit(_))
    ));
    let metadata_over = GitLimits::default()
        .with_parser_limits(19, 4, 1, 1)
        .expect("metadata over limit");
    assert!(matches!(
        parse_patch(one_file, metadata_over, &cancellation),
        Err(PatchError::Limit(_))
    ));

    assert!(read_bounded_and_drain(FailingReader, &OutputBudget::new(8)).is_err());
    assert!(matches!(
        reserve_input(&mut Vec::new(), usize::MAX, "injected allocation"),
        Err(PatchError::Limit(_))
    ));
}

/// History output that crosses commit, file and hunk starts, with a
/// merge header, CRLF lines, a rename, a copy, binary markers, a binary
/// payload, quoted paths, a deletion, a mode change, and added lines that
/// look like record starts.
const STREAM_PATCH: &[u8] = b"\n\
commit 1111111111111111111111111111111111111111\r\n\
Merge: aaaaaaa bbbbbbb\n\
Author: Synthetic One <one@example.invalid>\n\
Date:   Tue Nov 2 18:37:53 2021 -0500\n\
\n\
\x20\x20\x20\x20merge title\n\
\n\
\x20\x20\x20\x20merge body\n\
\n\
commit 2222222222222222222222222222222222222222\n\
Author: Synthetic Two <two@example.invalid>\n\
Date:   Wed Nov 3 01:02:03 2021 +0100\n\
\n\
\x20\x20\x20\x20second\n\
\n\
diff --git a/plain.txt b/plain.txt\n\
index 1111111..2222222 100644\n\
--- a/plain.txt\n\
+++ b/plain.txt\n\
@@ -1,2 +1,4 @@\n\
-old line\n\
\x20context\n\
+new line one\n\
+commit lookalike\n\
+diff --git lookalike\n\
@@ -9 +10 @@\r\n\
-crlf old\r\n\
+crlf new\r\n\
diff --git a/old name.txt b/new name.txt\n\
similarity index 90%\n\
rename from old name.txt\n\
rename to new name.txt\n\
--- a/old name.txt\n\
+++ b/new name.txt\n\
@@ -0,0 +1 @@\n\
+renamed added\n\
\\ No newline at end of file\n\
diff --git a/image.bin b/image.bin\n\
new file mode 100644\n\
index 0000000..3333333\n\
Binary files /dev/null and b/image.bin differ\n\
diff --git a/blob.dat b/blob.dat\n\
index 3333333..4444444 100644\n\
GIT binary patch\n\
literal 12\n\
zcmZ?wbhEHbG-qJ}0RR6000000\n\
\n\
literal 0\n\
HcmV?d00001\n\
\n\
diff --git \"a/tab\\there.txt\" \"b/tab\\there.txt\"\n\
new file mode 100644\n\
--- /dev/null\n\
+++ \"b/tab\\there.txt\"\n\
@@ -0,0 +1,2 @@\n\
+quoted one\n\
+quoted two\n\
commit 3333333333333333333333333333333333333333\n\
Author: Synthetic Three <three@example.invalid>\n\
Date:   Thu Nov 4 12:00:00 2021 +0000\n\
\n\
\x20\x20\x20\x20third\n\
\n\
diff --git a/copy.txt b/copied.txt\n\
similarity index 100%\n\
copy from copy.txt\n\
copy to copied.txt\n\
diff --git a/gone.txt b/gone.txt\n\
deleted file mode 100644\n\
--- a/gone.txt\n\
+++ /dev/null\n\
@@ -1 +0,0 @@\n\
-gone\n\
diff --git a/mode.sh b/mode.sh\n\
old mode 100644\n\
new mode 100755\n\
commit 4444444444444444444444444444444444444444";

type FileSummary = (Vec<u8>, Vec<u8>, bool, bool, Vec<(usize, Vec<u8>)>);

fn summarize(files: &[ParsedFile]) -> Vec<FileSummary> {
    files
        .iter()
        .map(|file| {
            (
                file.path.clone(),
                file.commit.clone(),
                file.deleted,
                file.binary,
                file.hunks
                    .iter()
                    .map(|hunk| (hunk.new_position, hunk.added.clone()))
                    .collect(),
            )
        })
        .collect()
}

/// Parses `input` whole, in one-byte and other fixed-size chunks, and in
/// pseudo-random sizes, and requires the same files and the same error
/// from each.
fn assert_chunking_is_invisible(
    input: &[u8],
    limits: GitLimits,
) -> (Vec<ParsedFile>, Option<PatchError>) {
    let cancellation = crate::CancellationToken::new();
    let whole = parse_patch_chunks(input, || usize::MAX, limits, &cancellation);
    let mut schedules: Vec<Box<dyn FnMut() -> usize>> = Vec::new();
    for size in [1, 2, 3, 5, 7, 11, 13, 64] {
        schedules.push(Box::new(move || size));
    }
    for seed in [1_u32, 0x9e37_79b9, 0xdead_beef] {
        let mut state = seed;
        schedules.push(Box::new(move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            usize::try_from(state % 211).unwrap_or(0) + 1
        }));
    }
    for (index, schedule) in schedules.into_iter().enumerate() {
        let chunked = parse_patch_chunks(input, schedule, limits, &cancellation);
        assert!(
            chunked == whole,
            "schedule {index} changed the parse: whole={:?}/{:?}, chunked={:?}/{:?}",
            summarize(&whole.0),
            whole.1,
            summarize(&chunked.0),
            chunked.1
        );
    }
    whole
}

#[test]
fn streamed_history_matches_independent_expectations_in_any_chunking() {
    let (files, error) = assert_chunking_is_invisible(STREAM_PATCH, GitLimits::default());
    assert_eq!(error, None);
    let second = b"2222222222222222222222222222222222222222".to_vec();
    let third = b"3333333333333333333333333333333333333333".to_vec();
    let expected: Vec<FileSummary> = vec![
        (
            b"plain.txt".to_vec(),
            second.clone(),
            false,
            false,
            vec![
                (
                    1,
                    b"new line one\ncommit lookalike\ndiff --git lookalike\n".to_vec(),
                ),
                (10, b"crlf new\r\n".to_vec()),
            ],
        ),
        (
            b"new name.txt".to_vec(),
            second.clone(),
            false,
            false,
            vec![(1, b"renamed added".to_vec())],
        ),
        (b"image.bin".to_vec(), second.clone(), false, true, vec![]),
        (b"blob.dat".to_vec(), second.clone(), false, true, vec![]),
        (
            b"tab\there.txt".to_vec(),
            second,
            false,
            false,
            vec![(1, b"quoted one\nquoted two\n".to_vec())],
        ),
        (b"copied.txt".to_vec(), third.clone(), false, false, vec![]),
        (
            b"gone.txt".to_vec(),
            third.clone(),
            true,
            false,
            vec![(0, Vec::new())],
        ),
        (b"mode.sh".to_vec(), third, false, false, vec![]),
    ];
    assert_eq!(summarize(&files), expected);
    let metadata = files[0].metadata.as_ref().expect("second commit metadata");
    assert_eq!(metadata.author_name().as_bytes(), b"Synthetic Two");
    assert_eq!(metadata.date().as_bytes(), b"2021-11-03T00:02:03Z");
    assert_eq!(metadata.message().as_bytes(), b"second");
    let metadata = files[5].metadata.as_ref().expect("third commit metadata");
    assert_eq!(
        metadata.sha().as_bytes(),
        b"3333333333333333333333333333333333333333"
    );
    assert_eq!(metadata.message().as_bytes(), b"third");
    assert_eq!(
        files
            .iter()
            .map(|file| file.commit_index)
            .collect::<Vec<_>>(),
        [2, 2, 2, 2, 2, 3, 3, 3]
    );
}

#[test]
fn truncated_and_damaged_history_parses_alike_in_any_chunking() {
    // Every prefix ends inside a commit, file record, hunk or line.
    for end in 0..=STREAM_PATCH.len() {
        assert_chunking_is_invisible(&STREAM_PATCH[..end], GitLimits::default());
    }
    // A newline or a letter in place of any byte moves or breaks a record
    // start, a hunk count or a path.
    for position in (0..STREAM_PATCH.len()).step_by(3) {
        for replacement in [b'\n', b'x'] {
            let mut damaged = STREAM_PATCH.to_vec();
            damaged[position] = replacement;
            assert_chunking_is_invisible(&damaged, GitLimits::default());
        }
    }
}

#[test]
fn per_commit_limits_stop_alike_in_any_chunking() {
    for bytes in [1, 40, 120, 300, 480, 700, 1024] {
        for lines in [1, 6, 20, 40] {
            for (files, hunks) in [(1, 1), (2, 2), (5, 3)] {
                let limits = GitLimits::new(bytes, lines, 64, 64)
                    .and_then(|limits| limits.with_parser_limits(4096, 64, files, hunks))
                    .expect("positive limits");
                let (_, error) = assert_chunking_is_invisible(STREAM_PATCH, limits);
                assert!(
                    matches!(error, None | Some(PatchError::Limit(_))),
                    "bytes={bytes}, lines={lines}, files={files}, hunks={hunks}: {error:?}"
                );
            }
        }
    }
}

#[test]
fn patch_limits_apply_to_each_commit_not_to_the_whole_history() {
    let commit = |name: &str, body: &str| {
        format!(
            "commit {name}\nAuthor: Synthetic <synthetic@example.invalid>\nDate:   Tue Nov 2 23:37:53 2021 +0000\n\n    {name}\n{body}\ndiff --git a/{name}.txt b/{name}.txt\nnew file mode 100644\n--- /dev/null\n+++ b/{name}.txt\n@@ -0,0 +1 @@\n+{name}\n"
        )
    };
    // The second commit has more bytes and more lines than the first.
    let first = commit("first", "");
    let second = commit("second-commit", "\n    body one\n    body two\n");
    let patch = format!("{first}{second}");
    let largest = first.len().max(second.len());
    let most_lines = first.lines().count().max(second.lines().count());
    assert!(patch.len() > largest);
    let cancellation = crate::CancellationToken::new();
    let exact = GitLimits::new(largest, most_lines, 64, 64)
        .and_then(|limits| limits.with_parser_limits(4096, 64, 1, 1))
        .expect("exact per-commit limits");
    let files = parse_patch(patch.as_bytes(), exact, &cancellation).expect("each commit fits");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].path, b"first.txt");
    assert_eq!(files[1].path, b"second-commit.txt");
    assert_eq!(files[1].hunks[0].added, b"second-commit\n");

    for below in [
        GitLimits::new(largest - 1, most_lines, 64, 64),
        GitLimits::new(largest, most_lines - 1, 64, 64),
    ] {
        let below = below
            .and_then(|limits| limits.with_parser_limits(4096, 64, 1, 1))
            .expect("short per-commit limits");
        let (files, error) = parse_patch_chunks(patch.as_bytes(), || 7, below, &cancellation);
        // The first commit is smaller, so it is published before the
        // second commit reaches the limit.
        assert_eq!(summarize(&files).len(), 1);
        assert!(matches!(error, Some(PatchError::Limit(_))), "{error:?}");
    }

    // Two files or two hunks in one commit still exceed a limit of one.
    let two_files = format!(
        "{first}diff --git a/more.txt b/more.txt\nnew file mode 100644\n--- /dev/null\n+++ b/more.txt\n@@ -0,0 +1 @@\n+more\n"
    );
    let two_hunks = format!("{first}@@ -3,0 +4 @@\n+more\n");
    for patch in [two_files, two_hunks] {
        assert!(matches!(
            parse_patch(patch.as_bytes(), exact, &cancellation),
            Err(PatchError::Limit(_))
        ));
    }
}

#[test]
fn records_before_a_later_error_are_published_first() {
    let mut patch = STREAM_PATCH.to_vec();
    patch.extend_from_slice(
            b"\ncommit 5555555555555555555555555555555555555555\n\ndiff --git a/bad b/bad\n--- a/bad\n+++ b/bad\n@@ -0,0 +1,2 @@\n+only one\n",
        );
    let (files, error) = assert_chunking_is_invisible(&patch, GitLimits::default());
    assert_eq!(files.len(), 8);
    assert_eq!(
        error,
        Some(PatchError::Invalid("truncated Git hunk".to_owned()))
    );
    // A record start inside an incomplete hunk is an invalid hunk line.
    patch.extend_from_slice(b"diff --git a/next b/next\nnew file mode 100644\n");
    let (files, error) = assert_chunking_is_invisible(&patch, GitLimits::default());
    assert_eq!(files.len(), 8);
    assert_eq!(
        error,
        Some(PatchError::Invalid(
            "invalid Git hunk line operation".to_owned()
        ))
    );
}

#[test]
fn stream_buffer_keeps_only_the_open_record() {
    let record = b"diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+a\n";
    let mut stream = PatchStream::new(GitLimits::default());
    let cancellation = crate::CancellationToken::new();
    let mut parsed = 0;
    for _ in 0..10_000 {
        stream.push(record).expect("push record");
        while stream
            .next_file(&cancellation)
            .expect("parse record")
            .is_some()
        {
            parsed += 1;
        }
        assert!(stream.buffer.len() <= 2 * record.len());
    }
    stream.finish();
    while stream
        .next_file(&cancellation)
        .expect("parse final record")
        .is_some()
    {
        parsed += 1;
    }
    assert_eq!(parsed, 10_000);
}

fn fixture_arguments() -> [OsString; 3] {
    [
        OsString::from("--exact"),
        OsString::from("git::tests::subprocess_fixture_waits"),
        OsString::from("--nocapture"),
    ]
}

#[test]
fn streamed_command_delivers_output_status_and_bounded_stderr() {
    let executable = std::env::current_exe().expect("current test executable");
    let environment = [
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
            OsString::from("5"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
            OsString::from("12345"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_STDOUT_BYTES"),
            OsString::from("1000000"),
        ),
    ];
    let mut received = 0;
    let output = stream_command(
        executable.as_os_str(),
        &fixture_arguments(),
        5,
        &environment,
        &crate::CancellationToken::new(),
        SourceStage::GitCommand,
        &mut |chunk| {
            received += chunk.len();
            Ok(SourceControl::Continue)
        },
    )
    .expect("streamed command");
    // The test harness can add its own lines around the fixture bytes.
    assert!(received >= 1_000_000, "{received}");
    assert!(received < 1_000_000 + 4096, "{received}");
    assert!(!output.stopped);
    assert!(!output.stderr_limited);
    assert_eq!(output.status.and_then(|status| status.code()), Some(5));
    assert_eq!(output.stderr, b"12345");

    let limited = stream_command(
        executable.as_os_str(),
        &fixture_arguments(),
        4,
        &environment,
        &crate::CancellationToken::new(),
        SourceStage::GitCommand,
        &mut |_| Ok(SourceControl::Continue),
    )
    .expect("stderr limit is reported, not raised");
    assert!(limited.stderr_limited);
}

#[test]
fn streamed_command_stops_and_fails_when_the_consumer_does() {
    let executable = std::env::current_exe().expect("current test executable");
    let environment = [
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
            OsString::from("0"),
        ),
        (
            OsString::from("RUSTLEAKS_GIT_CHILD_STDOUT_BYTES"),
            OsString::from("8000000"),
        ),
    ];
    let mut chunks = 0;
    let output = stream_command(
        executable.as_os_str(),
        &fixture_arguments(),
        64,
        &environment,
        &crate::CancellationToken::new(),
        SourceStage::GitCommand,
        &mut |_| {
            chunks += 1;
            Ok(SourceControl::Stop)
        },
    )
    .expect("consumer stop");
    assert!(output.stopped);
    assert_eq!(chunks, 1);
    assert!(output.status.is_none());

    let error = stream_command(
        executable.as_os_str(),
        &fixture_arguments(),
        64,
        &environment,
        &crate::CancellationToken::new(),
        SourceStage::GitCommand,
        &mut |_| {
            Err(SourceError::terminal(
                SourceStage::GitParse,
                None,
                "injected parse failure",
            ))
        },
    );
    assert!(matches!(
        error,
        Err(SourceError::Terminal {
            stage: SourceStage::GitParse,
            ..
        })
    ));

    let missing = stream_command(
        OsStr::new("rustleaks-deliberately-missing-git-executable"),
        &[],
        1,
        &[],
        &crate::CancellationToken::new(),
        SourceStage::GitCommand,
        &mut |_| Ok(SourceControl::Continue),
    );
    assert!(matches!(
        missing,
        Err(SourceError::Terminal {
            stage: SourceStage::GitCommand,
            ..
        })
    ));
}
