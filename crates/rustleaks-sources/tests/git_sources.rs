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
