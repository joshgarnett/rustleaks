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
    FileSource, LogicalPath, ReadOutcome, ReadStatus, Source, SourceControl, SourceError,
    SourceEvent, SourceIssue, SourceIssueKind, SourceReader, SourceRunner, SourceStage,
    SourceTermination,
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

fn expected_directory_fragment(path: &Path) -> SourceEvent {
    let logical = LogicalPath::from_native(path);
    let mut builder = Fragment::builder(b"value\n\n".as_slice())
        .file_path(logical.normalized().clone())
        .start_line(1);
    if let Some(original) = logical.windows_original() {
        builder = builder.windows_file_path(original.clone());
    }
    SourceEvent::fragment(builder.build())
}

#[test]
fn directory_walk_preserves_nested_order_path_spelling_and_limit_events() {
    let tree = TempTree::new("nested-lexical-paths");
    fs::create_dir(tree.path().join("prefix")).expect("create nested directory");
    for name in [
        "z",
        "prefix-long",
        "prefix/z",
        "prefix/a",
        "a1z",
        "a1",
        "a01",
        "a",
    ] {
        fs::write(tree.path().join(name), b"value\n\n").expect("write ordered input");
    }
    fs::write(tree.path().join("a0"), b"oversized\n\n").expect("write oversized input");
    fs::write(tree.path().join("a00"), b"").expect("write empty input");

    for logical_root in [
        None,
        Some(tree.path().to_path_buf()),
        Some(tree.path().join(".")),
        Some(PathBuf::from(
            tree.path().to_string_lossy().replace('\\', "/"),
        )),
        Some(PathBuf::from("repo")),
        Some(PathBuf::from(".")),
    ] {
        let mut options = DirectoryOptions::default()
            .max_file_size(Some(7))
            .emit_limit_issues(true);
        if let Some(root) = &logical_root {
            options = options.logical_root(root);
        }
        let display_root = match logical_root.as_deref() {
            Some(root) if root == Path::new(".") => Path::new(""),
            Some(root) => root,
            None => tree.path(),
        };
        let mut expected = Vec::new();
        for name in [
            "a",
            "a0",
            "a01",
            "a1",
            "a1z",
            "prefix/a",
            "prefix/z",
            "prefix-long",
            "z",
        ] {
            if name == "a0" {
                expected.push(SourceEvent::Issue(SourceIssue::new(
                    SourceStage::Limit,
                    SourceIssueKind::Limit,
                    Some(tree.path().join(name)),
                    "skipping file: exceeds maximum file size",
                )));
            } else {
                let path = name
                    .split('/')
                    .fold(display_root.to_path_buf(), |path, part| path.join(part));
                expected.push(expected_directory_fragment(&path));
            }
        }
        let mut source = DirectorySource::with_options(tree.path(), options);
        let mut events = Vec::new();
        let control = source
            .visit(&CancellationToken::new(), &mut |event| {
                events.push(event);
                Ok(SourceControl::Continue)
            })
            .expect("directory visit succeeds");
        assert_eq!(control, SourceControl::Continue);
        assert_eq!(events, expected, "logical root {logical_root:?}");
    }
}

#[test]
fn directory_callback_stop_error_and_cancellation_precede_later_entries() {
    let tree = TempTree::new("directory-callback-boundaries");
    fs::write(tree.path().join("z"), b"value\n\n").expect("write later sibling");
    fs::create_dir(tree.path().join("a")).expect("create first directory");
    fs::write(tree.path().join("a/z"), b"oversized\n\n").expect("write later limit");
    fs::write(tree.path().join("a/a"), b"value\n\n").expect("write first fragment");

    for logical_root in [tree.path().to_path_buf(), PathBuf::from("repo")] {
        for response in [
            Ok(SourceControl::Stop),
            Ok(SourceControl::Continue),
            Err(CallbackError::new("consumer rejected fragment")),
        ] {
            let options = DirectoryOptions::default()
                .logical_root(&logical_root)
                .max_file_size(Some(7))
                .emit_limit_issues(true);
            let mut source = DirectorySource::with_options(tree.path(), options);
            let token = CancellationToken::new();
            let mut events = Vec::new();
            let result = source.visit(&token, &mut |event| {
                events.push(event);
                if response == Ok(SourceControl::Continue) {
                    token.cancel();
                }
                response.clone()
            });
            let expected_result = match response {
                Ok(SourceControl::Stop) => Ok(SourceControl::Stop),
                Ok(SourceControl::Continue) => Err(SourceError::Cancelled),
                Err(error) => Err(SourceError::Callback(error)),
            };
            assert_eq!(result, expected_result);
            assert_eq!(
                events,
                [expected_directory_fragment(
                    &logical_root.join("a").join("a")
                )]
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn directory_source_preserves_invalid_unix_filename_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let tree = TempTree::new("invalid-path");
    let root = tree.path().join(OsString::from_vec(b"root-\xff".to_vec()));
    fs::create_dir(&root).expect("create invalid-byte root");
    for name in [
        b"invalid-\xff-name",
        b"invalid-\xfe-name",
        b"invalid-a-name",
    ] {
        fs::write(root.join(OsString::from_vec(name.to_vec())), b"value\n\n")
            .expect("write invalid-byte filename");
    }
    let options = DirectoryOptions::default().logical_root(&root);
    let mut source = DirectorySource::with_options(&root, options);
    let (fragments, issues) = collect(&mut source);
    let expected = [
        b"invalid-a-name",
        b"invalid-\xfe-name",
        b"invalid-\xff-name",
    ]
    .map(|name| expected_directory_fragment(&root.join(OsString::from_vec(name.to_vec()))));
    let events = fragments
        .into_iter()
        .map(SourceEvent::fragment)
        .collect::<Vec<_>>();
    assert_eq!(events, expected);
    assert!(issues.is_empty());
}

#[cfg(windows)]
#[test]
fn windows_native_paths_retain_raw_spelling_and_match_both_forms() {
    let logical = LogicalPath::from_native(Path::new(r"C:\work\mixed/path"));
    assert_eq!(logical.normalized().as_bytes(), b"C:/work/mixed/path");
    let original = logical
        .windows_original()
        .expect("Windows path retains its native spelling");
    assert_eq!(original.as_bytes(), br"C:\work\mixed/path");

    for (pattern, matches_normalized) in [
        (r"^C:/work/mixed/path$", true),
        (r"^C:\\work\\mixed/path$", false),
    ] {
        let config = ConfigLoader::new()
            .load_toml(&format!(
                r#"
                [[rules]]
                id = "unused"
                regex = '''never-match'''

                [[allowlists]]
                paths = ['''{pattern}''']
                "#,
            ))
            .expect("compile Windows path allowlist");
        assert_eq!(
            config.source_path_allowed(logical.normalized().as_bytes(), None),
            matches_normalized,
        );
        assert!(
            config.source_path_allowed(logical.normalized().as_bytes(), Some(original.as_bytes()),)
        );
    }
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

#[cfg(unix)]
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
    for (logical_root, expected_alias) in [
        (None, alias.clone()),
        (Some(tree.path().to_path_buf()), alias.clone()),
        (Some(PathBuf::from("repo")), PathBuf::from("repo/alias")),
        (Some(PathBuf::from(".")), PathBuf::from("alias")),
    ] {
        let mut mapped_options = options.clone();
        if let Some(root) = logical_root {
            mapped_options = mapped_options.logical_root(root);
        }
        let mut enabled = DirectorySource::with_options(tree.path(), mapped_options);
        let (fragments, issues) = collect(&mut enabled);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].content().as_bytes(), b"target bytes");
        assert_eq!(
            fragments[0].symlink_file().as_str().expect("UTF-8 alias"),
            expected_alias.to_string_lossy()
        );
        assert_eq!(
            fragments[0].file_path().as_str().expect("UTF-8 target"),
            resolved_expected(&target).to_string_lossy()
        );
        assert!(issues.is_empty());
    }

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

#[cfg(unix)]
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

#[cfg(windows)]
#[test]
fn zero_length_symlink_metadata_is_filtered_before_resolution() {
    let tree = TempTree::new("zero-length-symlinks");
    let outside = TempTree::new("zero-length-symlink-targets");
    let file_target = outside.path().join("file");
    let directory_target = outside.path().join("directory");
    fs::write(&file_target, b"target bytes").expect("write file target");
    fs::create_dir(&directory_target).expect("create directory target");

    let file_alias = tree.path().join("file-alias");
    let directory_alias = tree.path().join("directory-alias");
    create_file_symlink(&file_target, &file_alias);
    create_directory_symlink(&directory_target, &directory_alias);
    assert_eq!(
        fs::symlink_metadata(&file_alias)
            .expect("file symlink metadata")
            .len(),
        0
    );
    assert_eq!(
        fs::symlink_metadata(&directory_alias)
            .expect("directory symlink metadata")
            .len(),
        0
    );

    let options = DirectoryOptions::default().follow_symlinks(true);
    let mut source = DirectorySource::with_options(tree.path(), options);
    let (fragments, issues) = collect(&mut source);
    assert!(fragments.is_empty());
    assert!(issues.is_empty());
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
            if emitted == 1
                && let Some(token) = &self.cancel_after_first
            {
                token.cancel();
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

fn budget_engine() -> Engine {
    Engine::builder(
        ConfigLoader::new()
            .load_toml("[[rules]]\nid = 'synthetic'\nregex = 'A'\n")
            .unwrap(),
    )
    .build()
    .unwrap()
}

fn budget_fragments(count: usize, content: &str) -> FragmentSource {
    FragmentSource {
        fragments: (0..count)
            .map(|index| {
                Fragment::builder(content)
                    .file_path(format!("synthetic-{index}"))
                    .start_line(1)
                    .build()
            })
            .collect(),
        cancel_after_first: None,
    }
}

#[test]
fn source_budget_validation_requires_reservable_aggregate_dimensions() {
    use rustleaks_core::{ScanBudget, ScanBudgetKind};
    use rustleaks_sources::SourceBudget;
    for (aggregate, expected) in [
        (
            ScanBudget::unlimited().max_work_units(0),
            ScanBudgetKind::WorkUnits,
        ),
        (
            ScanBudget::unlimited().max_decoded_bytes(0),
            ScanBudgetKind::DecodedBytes,
        ),
        (
            ScanBudget::unlimited().max_finding_records(0),
            ScanBudgetKind::FindingRecords,
        ),
    ] {
        let error = SourceRunner::default()
            .with_budget(SourceBudget::unlimited().aggregate(aggregate))
            .unwrap_err();
        assert_eq!(error.kind(), expected);
    }
    assert!(SourceRunner::default().budget().is_none());
    let budget = SourceBudget::unlimited();
    assert_eq!(
        SourceRunner::default()
            .with_budget(budget)
            .unwrap()
            .budget(),
        Some(budget)
    );
}

#[test]
fn source_budget_inclusive_totals_preserve_complete_duplicate_aware_findings() {
    use rustleaks_core::ScanBudget;
    use rustleaks_sources::SourceBudget;
    let detector = budget_engine();
    for workers in [1, 4] {
        let per_fragment = ScanBudget::unlimited()
            .max_work_units(3)
            .max_finding_records(1)
            .max_decoded_bytes(0);
        let aggregate = ScanBudget::unlimited()
            .max_work_units(24)
            .max_finding_records(8)
            .max_decoded_bytes(0);
        let budget = SourceBudget::unlimited()
            .per_fragment(per_fragment)
            .aggregate(aggregate)
            .max_fragment_bytes(1)
            .max_original_bytes(8)
            .max_fragments(8)
            .max_issues(0);
        let mut source = budget_fragments(8, "A");
        let outcome = SourceRunner::new(workers, 2)
            .unwrap()
            .with_budget(budget)
            .unwrap()
            .run(
                &mut source,
                &detector,
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            );
        assert_eq!(outcome.termination(), &SourceTermination::Completed);
        let usage = outcome.usage().unwrap();
        assert!(usage.is_exact());
        assert_eq!(usage.original_bytes(), 8);
        assert_eq!(usage.fragments(), 8);
        assert_eq!(usage.completed_fragments(), 8);
        assert_eq!(usage.incomplete_fragments(), 0);
        assert_eq!(
            usage.work_units(),
            24,
            "one scan pass, one rule and one candidate per fragment"
        );
        assert_eq!(usage.finding_records(), 8);
        assert_eq!(usage.decoded_bytes(), 0);
        let mut files = outcome
            .findings()
            .iter()
            .map(|finding| {
                assert_eq!(finding.secret().as_bytes(), b"A");
                assert_eq!(finding.match_range().exact().unwrap().as_range(), 0..1);
                finding.file().as_bytes().to_vec()
            })
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(
            files,
            (0..8)
                .map(|index| format!("synthetic-{index}").into_bytes())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn aggregate_work_and_finding_limits_do_not_multiply_by_workers() {
    use rustleaks_core::ScanBudget;
    use rustleaks_sources::{SourceBudget, SourceBudgetKind, SourceBudgetScope};
    let detector = budget_engine();
    for workers in [1, 4] {
        for (aggregate, kind, expected_work, expected_records) in [
            (
                ScanBudget::unlimited().max_work_units(0),
                SourceBudgetKind::WorkUnits,
                0,
                0,
            ),
            (
                ScanBudget::unlimited().max_work_units(11),
                SourceBudgetKind::WorkUnits,
                11,
                3,
            ),
            (
                ScanBudget::unlimited().max_finding_records(0),
                SourceBudgetKind::FindingRecords,
                3,
                0,
            ),
            (
                ScanBudget::unlimited().max_finding_records(3),
                SourceBudgetKind::FindingRecords,
                12,
                3,
            ),
        ] {
            let budget = SourceBudget::unlimited()
                .per_fragment(
                    ScanBudget::unlimited()
                        .max_work_units(3)
                        .max_finding_records(1),
                )
                .aggregate(aggregate);
            let outcome = SourceRunner::new(workers, 2)
                .unwrap()
                .with_budget(budget)
                .unwrap()
                .run(
                    &mut budget_fragments(32, "A"),
                    &detector,
                    ScanOptions::default(),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                );
            let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
                panic!("expected a budget stop: {:?}", outcome.termination())
            };
            assert_eq!(exceeded.scope(), SourceBudgetScope::Operation);
            assert_eq!(exceeded.kind(), kind);
            assert_eq!(exceeded.requested(), 1);
            let usage = outcome.usage().unwrap();
            assert_eq!(usage.work_units(), expected_work);
            assert_eq!(usage.finding_records(), expected_records);
            assert_eq!(usage.completed_fragments(), expected_records);
            assert_eq!(outcome.findings().len(), expected_records);
            assert!(usage.incomplete_fragments() >= 1);
            assert!(usage.is_exact());
        }
    }
}

#[test]
fn aggregate_decoded_bytes_charge_whole_passes_across_workers() {
    use rustleaks_core::ScanBudget;
    use rustleaks_sources::{SourceBudget, SourceBudgetKind, SourceBudgetScope};
    let detector = Engine::builder(
        ConfigLoader::new()
            .load_toml("[[rules]]\nid = 'decoded'\nregex = 'marker=VALUE'\n")
            .unwrap(),
    )
    .build()
    .unwrap();
    for workers in [1, 4] {
        for total in [0, 11, 12, 35, 36] {
            let budget = SourceBudget::unlimited()
                .per_fragment(ScanBudget::unlimited().max_decoded_bytes(12))
                .aggregate(ScanBudget::unlimited().max_decoded_bytes(total));
            let outcome = SourceRunner::new(workers, 2)
                .unwrap()
                .with_budget(budget)
                .unwrap()
                .run(
                    &mut budget_fragments(3, "bWFya2VyPVZBTFVF"),
                    &detector,
                    ScanOptions::builder().max_decode_depth(1).build(),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                );
            let complete = total / 12;
            assert_eq!(outcome.findings().len(), complete);
            let usage = outcome.usage().unwrap();
            assert_eq!(usage.decoded_bytes(), complete * 12);
            assert_eq!(usage.completed_fragments(), complete);
            if total == 36 {
                assert_eq!(outcome.termination(), &SourceTermination::Completed);
            } else {
                let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
                    panic!("expected decoded-byte stop")
                };
                assert_eq!(exceeded.scope(), SourceBudgetScope::Operation);
                assert_eq!(exceeded.kind(), SourceBudgetKind::DecodedBytes);
                assert_eq!(exceeded.limit(), total);
                assert_eq!(exceeded.requested(), 12);
            }
        }
    }
}

#[test]
fn per_fragment_exhaustion_discards_its_completed_rule_prefix() {
    use rustleaks_core::ScanBudget;
    use rustleaks_sources::{SourceBudget, SourceBudgetKind, SourceBudgetScope};
    let detector = Engine::builder(
        ConfigLoader::new()
            .load_toml(
                "[[rules]]\nid = 'a-first'\nregex = 'A'\n[[rules]]\nid = 'b-last'\nregex = 'B'\n",
            )
            .unwrap(),
    )
    .build()
    .unwrap();
    for workers in [1, 4] {
        let budget = SourceBudget::unlimited()
            .per_fragment(ScanBudget::unlimited().max_finding_records(1))
            .aggregate(ScanBudget::unlimited().max_finding_records(10));
        let outcome = SourceRunner::new(workers, 1)
            .unwrap()
            .with_budget(budget)
            .unwrap()
            .run(
                &mut budget_fragments(1, "A B"),
                &detector,
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            );
        let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
            panic!("expected per-fragment stop")
        };
        assert_eq!(exceeded.scope(), SourceBudgetScope::Fragment);
        assert_eq!(exceeded.kind(), SourceBudgetKind::FindingRecords);
        assert_eq!(exceeded.limit(), 1);
        assert_eq!(exceeded.consumed(), 1);
        assert_eq!(outcome.usage().unwrap().finding_records(), 1);
        assert_eq!(outcome.usage().unwrap().completed_fragments(), 0);
        assert!(
            outcome.findings().is_empty(),
            "the complete first rule cannot publish a partial fragment"
        );
    }
}

#[test]
fn original_byte_fragment_and_issue_admissions_have_zero_and_inclusive_limits() {
    use rustleaks_sources::{SourceBudget, SourceBudgetKind, SourceBudgetScope};
    let detector = budget_engine();
    for workers in [1, 4] {
        for (budget, expected_kind, scope) in [
            (
                SourceBudget::unlimited().max_original_bytes(0),
                SourceBudgetKind::OriginalBytes,
                SourceBudgetScope::Operation,
            ),
            (
                SourceBudget::unlimited().max_fragment_bytes(0),
                SourceBudgetKind::OriginalBytes,
                SourceBudgetScope::Fragment,
            ),
            (
                SourceBudget::unlimited().max_fragments(0),
                SourceBudgetKind::Fragments,
                SourceBudgetScope::Operation,
            ),
        ] {
            let outcome = SourceRunner::new(workers, 1)
                .unwrap()
                .with_budget(budget)
                .unwrap()
                .run(
                    &mut budget_fragments(1, "A"),
                    &detector,
                    ScanOptions::default(),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                );
            let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
                panic!("expected admission stop")
            };
            assert_eq!(exceeded.kind(), expected_kind);
            assert_eq!(exceeded.scope(), scope);
            assert_eq!(exceeded.limit(), 0);
            assert_eq!(outcome.usage().unwrap().fragments(), 0);
            assert_eq!(outcome.scanned_bytes(), 0);
            assert!(outcome.findings().is_empty());
        }
        let outcome = SourceRunner::new(workers, 1)
            .unwrap()
            .with_budget(
                SourceBudget::unlimited()
                    .max_original_bytes(0)
                    .max_fragment_bytes(0)
                    .max_fragments(2),
            )
            .unwrap()
            .run(
                &mut budget_fragments(3, ""),
                &detector,
                ScanOptions::default(),
                &SessionPolicy::default(),
                &CancellationToken::new(),
            );
        let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
            panic!("expected empty-fragment admission stop")
        };
        assert_eq!(exceeded.kind(), SourceBudgetKind::Fragments);
        assert_eq!(exceeded.limit(), 2);
        assert_eq!(outcome.usage().unwrap().fragments(), 2);
        assert_eq!(outcome.usage().unwrap().original_bytes(), 0);

        for maximum in [0, 1] {
            let outcome = SourceRunner::new(workers, 1)
                .unwrap()
                .with_budget(SourceBudget::unlimited().max_issues(maximum))
                .unwrap()
                .run(
                    &mut CoupledIssueSource,
                    &detector,
                    ScanOptions::default(),
                    &SessionPolicy::default(),
                    &CancellationToken::new(),
                );
            assert_eq!(outcome.issues().len(), maximum);
            assert_eq!(outcome.usage().unwrap().fragments(), 0);
            if maximum == 0 {
                let SourceTermination::BudgetExceeded(exceeded) = outcome.termination() else {
                    panic!("expected issue stop")
                };
                assert_eq!(exceeded.kind(), SourceBudgetKind::Issues);
            } else {
                assert_eq!(outcome.termination(), &SourceTermination::Completed);
            }
        }
    }
}

#[test]
fn source_budgets_count_findings_before_session_suppression() {
    use rustleaks_core::ScanBudget;
    use rustleaks_sources::SourceBudget;
    let ignores = IgnoreSet::parse_go_compatible(b"synthetic-0:synthetic:1\n").ignores;
    let policy = SessionPolicy::builder().ignores(ignores).build();
    let budget = SourceBudget::unlimited()
        .per_fragment(ScanBudget::unlimited().max_finding_records(1))
        .aggregate(ScanBudget::unlimited().max_finding_records(1));
    let outcome = SourceRunner::default().with_budget(budget).unwrap().run(
        &mut budget_fragments(2, "A"),
        &budget_engine(),
        ScanOptions::default(),
        &policy,
        &CancellationToken::new(),
    );
    assert!(matches!(
        outcome.termination(),
        SourceTermination::BudgetExceeded(_)
    ));
    assert_eq!(outcome.usage().unwrap().finding_records(), 1);
    assert_eq!(outcome.usage().unwrap().completed_fragments(), 1);
    assert!(outcome.findings().is_empty());
}
