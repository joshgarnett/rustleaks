//! Native reader, directory, symlink, cancellation, and runner coverage.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{ByteText, Fragment, ScanOptions};
use rustleaks_core::session::{IgnoreSet, SessionPolicy};
use rustleaks_sources::{
    CallbackError, Cancellation, CancellationToken, DirectoryOptions, DirectorySource, FileOptions,
    FileSource, ReadOutcome, ReadStatus, Source, SourceControl, SourceError, SourceEvent,
    SourceIssue, SourceIssueKind, SourceReader, SourceRunner, SourceStage, SourceTermination,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustleaks-sources-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temporary tree");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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
                _ => panic!("unexpected future source event in compatibility test"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("source visit succeeds");
    (fragments, issues)
}

#[derive(Clone)]
struct ScheduledStep {
    bytes: Vec<u8>,
    status: ReadStatus,
}

struct ScheduledReader {
    steps: VecDeque<ScheduledStep>,
}

impl ScheduledReader {
    fn new(steps: impl IntoIterator<Item = ScheduledStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
        }
    }
}

impl SourceReader for ScheduledReader {
    fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
        let Some(step) = self.steps.pop_front() else {
            return ReadOutcome::new(0, ReadStatus::Eof);
        };
        assert!(step.bytes.len() <= buffer.len());
        buffer[..step.bytes.len()].copy_from_slice(&step.bytes);
        ReadOutcome::new(step.bytes.len(), step.status)
    }
}

fn read_error() -> ReadStatus {
    ReadStatus::Error {
        kind: io::ErrorKind::Other,
        message: "scheduled read error".to_owned(),
    }
}

#[test]
fn read_protocol_preserves_data_error_and_empty_error_shapes() {
    let options = FileOptions::new(4_096).expect("positive");
    let mut data_error = FileSource::from_source_reader(
        Box::new(ScheduledReader::new([ScheduledStep {
            bytes: b"value\n\n".to_vec(),
            status: read_error(),
        }])),
        "data-error",
        options,
    );
    let (fragments, issues) = collect(&mut data_error);
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].content().as_bytes(), b"value\n\n");
    assert_eq!(issues, [SourceIssueKind::Read]);

    let mut immediate = FileSource::from_source_reader(
        Box::new(ScheduledReader::new([ScheduledStep {
            bytes: Vec::new(),
            status: read_error(),
        }])),
        "immediate-error",
        options,
    );
    let (fragments, issues) = collect(&mut immediate);
    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].content().is_empty());
    assert_eq!(fragments[0].start_line(), 0);
    assert_eq!(issues, [SourceIssueKind::Read]);

    let mut with_eof = FileSource::from_source_reader(
        Box::new(ScheduledReader::new([ScheduledStep {
            bytes: b"final\n\n".to_vec(),
            status: ReadStatus::Eof,
        }])),
        "data-eof",
        options,
    );
    let (fragments, issues) = collect(&mut with_eof);
    assert_eq!(fragments.len(), 1);
    assert!(issues.is_empty());
}

#[test]
fn boundary_read_error_drops_buffered_bytes_and_emits_empty_fragment_issue() {
    let options = FileOptions::new(3).expect("positive");
    let mut source = FileSource::from_source_reader(
        Box::new(ScheduledReader::new([ScheduledStep {
            bytes: b"abc".to_vec(),
            status: read_error(),
        }])),
        "boundary-error",
        options,
    );
    let (fragments, issues) = collect(&mut source);
    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].content().is_empty());
    assert_eq!(issues, [SourceIssueKind::BoundaryRead]);
}

#[test]
fn callback_failure_is_distinct_from_normal_stop() {
    let mut source = FileSource::new(&b"value\n\n"[..], "callback");
    let error = source
        .visit(&CancellationToken::new(), &mut |_| {
            Err(CallbackError::new("consumer rejected fragment"))
        })
        .expect_err("callback error propagates");
    assert!(matches!(error, SourceError::Callback(_)));

    let mut source = FileSource::new(&b"value\n\n"[..], "callback");
    assert_eq!(
        source
            .visit(&CancellationToken::new(), &mut |_| Ok(SourceControl::Stop))
            .expect("normal stop"),
        SourceControl::Stop
    );
}

#[test]
fn application_mime_after_first_line_is_scanned() {
    let options = FileOptions::new(3).expect("positive");
    let mut source = FileSource::with_options(&b"a\n\n%PDF"[..], "mime", options);
    let (fragments, issues) = collect(&mut source);
    assert_eq!(
        fragments
            .iter()
            .map(|fragment| fragment.content().as_bytes())
            .collect::<Vec<_>>(),
        [b"a\n\n".as_slice(), b"%PDF".as_slice()]
    );
    assert!(issues.is_empty());
}

#[test]
fn directory_walk_is_lexical_and_size_equality_is_scanned() {
    let tree = TempTree::new("lexical-size");
    fs::write(tree.path().join("b"), b"bbbb").expect("write b");
    fs::write(tree.path().join("a"), b"aaaaa").expect("write a");
    fs::write(tree.path().join("c"), b"cccccc").expect("write c");
    fs::write(tree.path().join("empty"), b"").expect("write empty");

    let options = DirectoryOptions::default()
        .max_file_size(Some(5))
        .emit_limit_issues(true);
    let mut source = DirectorySource::with_options(tree.path(), options);
    let (fragments, issues) = collect(&mut source);
    let names = fragments
        .iter()
        .map(|fragment| {
            PathBuf::from(fragment.file_path().as_str().expect("UTF-8 path"))
                .file_name()
                .expect("filename")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(fragments[0].content().len(), 5);
    assert_eq!(issues, [SourceIssueKind::Limit]);
}

#[cfg(target_os = "linux")]
#[test]
fn directory_source_preserves_invalid_unix_filename_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let tree = TempTree::new("invalid-path");
    let name = OsString::from_vec(b"invalid-\xff-name".to_vec());
    fs::write(tree.path().join(&name), b"bytes").expect("write invalid-byte filename");
    let mut source = DirectorySource::new(tree.path());
    let (fragments, issues) = collect(&mut source);
    assert_eq!(fragments.len(), 1);
    assert!(
        fragments[0]
            .file_path()
            .as_bytes()
            .ends_with(b"invalid-\xff-name")
    );
    assert!(issues.is_empty());
}

#[test]
fn global_path_allowlist_prunes_subtrees_before_open() {
    let tree = TempTree::new("allowlist");
    fs::create_dir(tree.path().join("skip")).expect("create skip");
    fs::write(tree.path().join("skip/value"), b"hidden").expect("write hidden");
    fs::write(tree.path().join("keep"), b"visible").expect("write visible");

    let config = ConfigLoader::new()
        .load_toml(
            r#"
            [[rules]]
            id = "unused"
            regex = '''never-match'''

            [[allowlists]]
            paths = ['''(?:^|/)skip(?:/|$)''']
            "#,
        )
        .expect("compile config");
    let options = DirectoryOptions::default().path_config(Arc::new(config));
    let mut source = DirectorySource::with_options(tree.path(), options);
    let (fragments, _) = collect(&mut source);
    assert_eq!(fragments.len(), 1);
    assert!(fragments[0].file_path().as_bytes().ends_with(b"keep"));
}

#[test]
fn logical_root_drives_early_pruning_and_emitted_paths_without_changing_traversal() {
    let tree = TempTree::new("logical-root");
    fs::create_dir(tree.path().join("skip")).expect("create skip");
    fs::write(tree.path().join("skip/value"), b"hidden").expect("write hidden");
    fs::write(tree.path().join("keep"), b"visible").expect("write visible");

    let config = ConfigLoader::new()
        .load_toml(
            r#"
            [[rules]]
            id = "unused"
            regex = '''never-match'''

            [[allowlists]]
            paths = ['''^repo/skip(?:/|$)''']
            "#,
        )
        .expect("compile config");
    let options = DirectoryOptions::default()
        .path_config(Arc::new(config))
        .logical_root("repo");
    let mut source = DirectorySource::with_options(tree.path(), options);
    let (fragments, issues) = collect(&mut source);
    assert!(issues.is_empty());
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].file_path().as_bytes(), b"repo/keep");
}

#[cfg(any(unix, windows))]
#[test]
fn file_symlinks_preserve_alias_and_target_and_handle_failures() {
    let tree = TempTree::new("symlinks");
    let outside = TempTree::new("symlink-target");
    let target = outside.path().join("target");
    fs::write(&target, b"target bytes").expect("write target");
    let alias = tree.path().join("alias");
    let chain = outside.path().join("chain");
    create_file_symlink(&target, &chain);
    create_file_symlink(&chain, &alias);

    let mut disabled = DirectorySource::new(tree.path());
    assert!(collect(&mut disabled).0.is_empty());

    let options = DirectoryOptions::default().follow_symlinks(true);
    let mut enabled = DirectorySource::with_options(tree.path(), options.clone());
    let (fragments, issues) = collect(&mut enabled);
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].content().as_bytes(), b"target bytes");
    assert_eq!(
        fragments[0].symlink_file().as_str().expect("UTF-8 alias"),
        alias.to_string_lossy()
    );
    assert_eq!(
        fragments[0].file_path().as_str().expect("UTF-8 target"),
        resolved_expected(&target).to_string_lossy()
    );
    assert!(issues.is_empty());

    let dangling = tree.path().join("dangling");
    create_file_symlink(&tree.path().join("missing"), &dangling);
    let mut dangling_source = DirectorySource::with_options(&dangling, options.clone());
    let mut dangling_issues = Vec::new();
    dangling_source
        .visit(&CancellationToken::new(), &mut |event| {
            if let SourceEvent::Issue(issue) = event {
                dangling_issues.push((issue.stage(), issue.kind()));
            }
            Ok(SourceControl::Continue)
        })
        .expect("dangling symlink issue is recoverable");
    assert_eq!(
        dangling_issues,
        [(SourceStage::Symlink, SourceIssueKind::DanglingSymlink)]
    );

    let loop_a = tree.path().join("loop-a");
    let loop_b = tree.path().join("loop-b");
    create_file_symlink(&loop_b, &loop_a);
    create_file_symlink(&loop_a, &loop_b);
    let mut loop_source = DirectorySource::with_options(&loop_a, options);
    assert_eq!(collect(&mut loop_source).1, [SourceIssueKind::SymlinkLoop]);
}

#[cfg(any(unix, windows))]
#[test]
fn directory_symlink_is_never_traversed() {
    let tree = TempTree::new("directory-symlink");
    let outside = TempTree::new("directory-target");
    fs::write(outside.path().join("value"), b"value").expect("write target file");
    let alias = tree.path().join("alias");
    create_directory_symlink(outside.path(), &alias);

    let options = DirectoryOptions::default().follow_symlinks(true);
    let mut source = DirectorySource::with_options(tree.path(), options);
    let (fragments, issues) = collect(&mut source);
    assert!(fragments.is_empty());
    assert_eq!(issues, [SourceIssueKind::DirectorySymlink]);
}

struct FragmentSource {
    fragments: VecDeque<Fragment>,
    cancel_after_first: Option<CancellationToken>,
}

impl Source for FragmentSource {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut emitted = 0_usize;
        while let Some(fragment) = self.fragments.pop_front() {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            let control = emit(SourceEvent::fragment(fragment)).map_err(SourceError::Callback)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
            emitted += 1;
            if emitted == 1 {
                if let Some(token) = &self.cancel_after_first {
                    token.cancel();
                }
            }
        }
        Ok(SourceControl::Continue)
    }
}

fn engine() -> Engine {
    let config = ConfigLoader::new()
        .load_toml(
            r#"
            [[rules]]
            id = "example-token"
            description = "Example token"
            regex = '''token=([A-Z0-9]{4})'''
            keywords = ["token"]
            "#,
        )
        .expect("compile runner config");
    Engine::builder(config).build().expect("build engine")
}

fn runner_files(worker_count: usize) -> Vec<Vec<u8>> {
    let mut fragments = (0..32)
        .map(|index| {
            Fragment::builder(format!("token=A{index:03}"))
                .file_path(format!("file-{index:02}"))
                .start_line(1)
                .build()
        })
        .collect::<VecDeque<_>>();
    fragments.push_back(
        Fragment::builder("token=A000")
            .file_path("file-00")
            .start_line(1)
            .build(),
    );
    let mut source = FragmentSource {
        fragments,
        cancel_after_first: None,
    };
    let runner = SourceRunner::new(worker_count, 3).expect("positive runner bounds");
    let outcome = runner.run(
        &mut source,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &CancellationToken::new(),
    );
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert!(outcome.issues().is_empty());
    let mut files = outcome
        .findings()
        .iter()
        .map(|finding| finding.file().as_bytes().to_vec())
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn runner_worker_counts_preserve_complete_duplicate_aware_multiset() {
    assert_eq!(runner_files(1), runner_files(4));
    assert_eq!(runner_files(4).len(), 33);
    assert_eq!(
        runner_files(4)
            .iter()
            .filter(|path| path.as_slice() == b"file-00")
            .count(),
        2
    );
    assert_eq!(
        SourceRunner::new(0, 1).expect_err("zero workers").field(),
        "workers"
    );
    assert_eq!(
        SourceRunner::new(1, 0).expect_err("zero queue").field(),
        "queue_capacity"
    );
}

#[test]
fn runner_applies_one_session_policy_to_worker_batches() {
    let parsed = IgnoreSet::parse_go_compatible(b"file:example-token:1\n");
    assert!(parsed.issues.is_empty());
    let policy = SessionPolicy::builder().ignores(parsed.ignores).build();
    let mut source = FragmentSource {
        fragments: VecDeque::from([Fragment::builder("token=A000")
            .file_path("file")
            .start_line(1)
            .build()]),
        cancel_after_first: None,
    };
    let outcome = SourceRunner::new(2, 1).expect("runner").run(
        &mut source,
        &engine(),
        ScanOptions::default(),
        &policy,
        &CancellationToken::new(),
    );
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert!(outcome.findings().is_empty());
}

struct CoupledIssueSource;

impl Source for CoupledIssueSource {
    fn visit(
        &mut self,
        _cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        emit(SourceEvent::Fragment {
            fragment: Box::new(Fragment::builder("token=A000").start_line(1).build()),
            issue: Some(SourceIssue::new(
                SourceStage::Read,
                SourceIssueKind::Read,
                None,
                "data plus read error",
            )),
        })
        .map_err(SourceError::Callback)
    }
}

#[test]
fn runner_records_but_does_not_scan_fragments_with_coupled_issues() {
    let outcome = SourceRunner::default().run(
        &mut CoupledIssueSource,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &CancellationToken::new(),
    );
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert!(outcome.findings().is_empty());
    assert_eq!(outcome.issues().len(), 1);
}

#[test]
fn runner_counts_scanned_bytes_and_distinct_nonempty_commits() {
    let mut source = FragmentSource {
        fragments: VecDeque::from([
            Fragment::builder("abc").commit("commit-a").build(),
            Fragment::builder("de").commit("commit-a").build(),
            Fragment::builder("f").commit("commit-b").build(),
            Fragment::builder("ghij").build(),
        ]),
        cancel_after_first: None,
    };
    let outcome = SourceRunner::new(2, 2).expect("runner").run(
        &mut source,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &CancellationToken::new(),
    );

    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert_eq!(outcome.scanned_bytes(), 10);
    assert_eq!(outcome.unique_commit_count(), 2);
    assert_eq!(
        outcome.unique_commits(),
        [ByteText::from("commit-a"), ByteText::from("commit-b")]
    );
}

#[test]
fn cancellation_returns_only_after_bounded_workers_join() {
    let token = CancellationToken::new();
    let mut source = FragmentSource {
        fragments: VecDeque::from([Fragment::new(b"token=A000"), Fragment::new(b"token=A001")]),
        cancel_after_first: Some(token.clone()),
    };
    let outcome = SourceRunner::new(3, 1).expect("runner").run(
        &mut source,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &token,
    );
    assert_eq!(outcome.termination(), &SourceTermination::Cancelled);
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, alias: &Path) {
    std::os::unix::fs::symlink(target, alias).expect("create file symlink");
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, alias: &Path) {
    std::os::windows::fs::symlink_file(target, alias).expect("create file symlink");
}

#[cfg(unix)]
fn create_directory_symlink(target: &Path, alias: &Path) {
    std::os::unix::fs::symlink(target, alias).expect("create directory symlink");
}

#[cfg(windows)]
fn create_directory_symlink(target: &Path, alias: &Path) {
    std::os::windows::fs::symlink_dir(target, alias).expect("create directory symlink");
}

#[cfg(unix)]
fn resolved_expected(path: &Path) -> PathBuf {
    fs::canonicalize(path).expect("canonical target")
}

#[cfg(windows)]
fn resolved_expected(path: &Path) -> PathBuf {
    path.to_path_buf()
}
