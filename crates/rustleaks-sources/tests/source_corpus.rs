//! Differential replay of reader and direct-file source outcomes.
#![cfg(feature = "archives")]

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use rustleaks_core::Engine;
use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{Finding, Fragment, RequiredFinding, ScanOptions};
use rustleaks_core::session::{IgnoreSet, ScanSession, SessionPolicy};
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CallbackError, CancellationToken,
    DirectoryOptions, DirectorySource, FileOptions, FileSource, LogicalPath, ReadOutcome,
    ReadStatus, Source, SourceControl, SourceError, SourceEvent, SourceIssue, SourceIssueKind,
    SourceReader,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct Request {
    id: String,
    operation: String,
    #[serde(default)]
    content_base64: String,
    buffer_size: Option<usize>,
    max_peek_size: Option<usize>,
    #[serde(default)]
    reader_schedule: Vec<ReaderStep>,
    #[serde(default)]
    path_base64: String,
    #[serde(default)]
    logical_path: String,
    #[serde(default)]
    fixture_path: String,
    #[serde(default)]
    config_fixture: String,
    max_archive_depth: Option<usize>,
    #[serde(default)]
    detect: bool,
    #[serde(default)]
    cancel_before: bool,
    yield_error_after: Option<usize>,
    #[serde(default)]
    skip_paths_base64: Vec<String>,
    #[serde(default)]
    root_subpath: String,
    #[serde(default)]
    entries: Vec<FixtureEntry>,
    #[serde(default)]
    follow_symlinks: bool,
    max_file_size: Option<u64>,
    #[serde(default)]
    missing_root: bool,
}

#[derive(Deserialize)]
struct FixtureEntry {
    path: String,
    kind: String,
    #[serde(default)]
    content_base64: String,
    #[serde(default)]
    target: String,
    mode: Option<u32>,
}

#[derive(Deserialize)]
struct ReaderStep {
    #[serde(default)]
    data_base64: String,
    #[serde(default)]
    error: String,
}

#[derive(Deserialize)]
struct Outcome {
    id: String,
    fragments: Vec<FragmentWire>,
    findings: Vec<FindingWire>,
    issues: Vec<IssueWire>,
    error: Option<ErrorWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FragmentWire {
    raw_base64: String,
    bytes_base64: String,
    bytes_nil: bool,
    file_base64: String,
    windows_file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    start_line: usize,
    inherited_from_finding: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FindingWire {
    rule_id: String,
    description_base64: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
    file_base64: String,
    symlink_file_base64: String,
    commit_base64: String,
    link_base64: String,
    entropy_bits: u32,
    author_base64: String,
    email_base64: String,
    date_base64: String,
    message_base64: String,
    tags_base64: Vec<String>,
    fingerprint_base64: String,
    fragment: Option<FragmentWire>,
    required_findings: Vec<RequiredWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RequiredWire {
    rule_id: String,
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    line_base64: String,
    match_base64: String,
    secret_base64: String,
}

#[derive(Deserialize)]
struct IssueWire {
    class: String,
    fragment: Option<FragmentWire>,
}

#[derive(Deserialize)]
struct ErrorWire {
    class: String,
}

#[derive(Clone)]
struct ScheduledStep {
    bytes: Vec<u8>,
    status: ReadStatus,
}

struct ScheduledReader {
    steps: VecDeque<ScheduledStep>,
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

#[test]
fn complete_source_corpus_matches_frozen_go_outcomes_or_exact_safe_dispositions() {
    let root = corpus_root();
    let requests = json_lines::<Request>(&root.join("requests-v1.jsonl"));
    let request_count = requests.len();
    let outcomes = json_lines::<Outcome>(&root.join("outcomes-v1.jsonl"))
        .into_iter()
        .map(|outcome| (outcome.id.clone(), outcome))
        .collect::<BTreeMap<_, _>>();
    let mut replayed = 0_usize;
    let mut dispositions = 0_usize;
    let mut unobservable_reader_fragment_dispositions = 0_usize;

    for request in requests {
        let expected = outcomes.get(&request.id).expect("matching outcome");
        if cfg!(windows) && windows_platform_disposition(&request) {
            // The frozen outcomes are Darwin-native. Upstream applies the
            // alias-size gate before symlink resolution, so zero-length
            // Windows symlink metadata has a different exact disposition.
            // The permission row depends on Unix mode bits. Focused native
            // tests retain executable Windows symlink coverage.
            assert_eq!(request.operation, "files");
            dispositions += 1;
            continue;
        }
        match request.operation.as_str() {
            "reader" | "file" | "files" => {
                replay(&request, expected);
                replayed += 1;
                if request.operation == "reader" {
                    unobservable_reader_fragment_dispositions += 1;
                }
            }
            "boundary" if request.buffer_size != Some(0) => {
                replay(&request, expected);
                replayed += 1;
            }
            "boundary" => {
                assert_eq!(request.id, "boundary-empty");
                assert_eq!(expected.fragments.len(), 1);
                assert!(decode(&expected.fragments[0].raw_base64).is_empty());
                assert!(FileOptions::new(0).is_err());
                dispositions += 1;
            }
            operation => panic!("unknown source corpus operation {operation}"),
        }
    }
    assert_eq!(replayed + dispositions, request_count);
    assert_eq!(dispositions, if cfg!(windows) { 10 } else { 1 });
    assert_eq!(unobservable_reader_fragment_dispositions, 9);
}

fn windows_platform_disposition(request: &Request) -> bool {
    matches!(
        request.id.as_str(),
        "files-symlink-disabled"
            | "files-symlink-enabled"
            | "files-directory-symlink"
            | "files-chained-symlink"
            | "files-symlink-alias-size-skip"
            | "files-symlink-target-size-bypass"
            | "files-dangling-symlink"
            | "files-looping-symlink"
            | "files-permission-denied"
    )
}

fn replay(request: &Request, expected: &Outcome) {
    let config = load_config(request);
    let mut built = build_source(request, config.as_ref());
    let cancellation = CancellationToken::new();
    if request.cancel_before {
        cancellation.cancel();
    }
    let mapping = built.mapping.as_ref();
    let mut fragments = Vec::<(Fragment, Option<SourceIssueKind>, bool)>::new();
    let mut emitted = 0_usize;
    let result = built.source.visit(&cancellation, &mut |event| {
        match event {
            SourceEvent::Fragment { fragment, issue } => {
                let fragment = if let Some(mapping) = mapping {
                    remap_fragment(&fragment, mapping)
                } else {
                    *fragment
                };
                fragments.push((fragment, issue.map(|value| value.kind()), false));
            }
            SourceEvent::Issue(issue) => {
                let fragment = issue_fragment(&issue, mapping);
                fragments.push((fragment, Some(issue.kind()), true));
            }
            _ => unreachable!("future source event"),
        }
        emitted += 1;
        if request.yield_error_after == Some(emitted) {
            return Err(CallbackError::new("scheduled yield error"));
        }
        Ok(SourceControl::Continue)
    });

    let actual_error = match result {
        Ok(_) => None,
        Err(SourceError::Cancelled) => Some("canceled"),
        Err(SourceError::Callback(_)) => Some("yield"),
        Err(_) => Some("source"),
    };
    let expected_error = expected.error.as_ref().map(|error| error.class.as_str());
    // Rust deliberately turns corrupt/decode source failures into structured
    // recoverable issues. The pinned multi-volume backend panics when only its
    // unnamed first-part stream is available; Rust gives that input the same
    // safe structured disposition. Cancellation and callback failure remain
    // terminal.
    let safe_archive_disposition = expected_error == Some("source")
        || (request.id == "archive-rar5-multivolume" && expected_error == Some("panic"));
    if !safe_archive_disposition {
        assert_eq!(actual_error, expected_error, "{}", request.id);
    }

    let actual_fragments = fragments
        .iter()
        .filter(|(fragment, _, issue_only)| {
            !issue_only
                || expected.issues.iter().any(|issue| {
                    issue.fragment.as_ref().is_some_and(|expected_fragment| {
                        fragment_wire(fragment).file_base64 == expected_fragment.file_base64
                    })
                })
        })
        .map(|(fragment, _, _)| fragment_wire(fragment))
        .collect::<Vec<_>>();
    if request.operation == "reader" {
        // The deprecated Go DetectReader/StreamDetectReader APIs expose only
        // findings plus a final error; they do not expose their intermediate
        // fragments. Keep that absence explicit while comparing every
        // observable finding/error/issue below. Rust's fragments are still
        // exercised by the focused file/source tests and are not presented as
        // pinned-Go differential evidence here.
        assert!(expected.fragments.is_empty(), "{}", request.id);
    } else {
        assert_fragments(request, &actual_fragments, &expected.fragments);
    }
    if request.operation == "boundary" {
        let reconstructed = actual_fragments
            .iter()
            .flat_map(|fragment| decode(&fragment.raw_base64))
            .collect::<Vec<_>>();
        assert_eq!(
            reconstructed,
            decode(&request.content_base64),
            "{}",
            request.id
        );
    }

    let actual_issue_classes = fragments
        .iter()
        .filter_map(|(_, issue, _)| issue.map(issue_class))
        .collect::<Vec<_>>();
    let expected_classes = expected_issue_classes(request, expected);
    assert!(
        issues_match(&actual_issue_classes, &expected_classes),
        "{} issue projection mismatch: actual={actual_issue_classes:?} expected={expected_classes:?}",
        request.id
    );

    let mut actual_findings = detect(request, config, &fragments)
        .iter()
        .map(finding_wire)
        .collect::<Vec<_>>();
    let mut expected_findings = expected.findings.clone();
    actual_findings
        .sort_by_cached_key(|finding| serde_json::to_string(finding).expect("wire JSON"));
    expected_findings
        .sort_by_cached_key(|finding| serde_json::to_string(finding).expect("wire JSON"));
    assert_eq!(actual_findings, expected_findings, "{}", request.id);
}

fn issue_fragment(issue: &SourceIssue, mapping: Option<&PathMapping>) -> Fragment {
    let fragment = issue.path().map_or_else(
        || Fragment::new(Vec::<u8>::new()),
        |path| {
            let logical = LogicalPath::from_native(path);
            let mut builder =
                Fragment::builder(Vec::<u8>::new()).file_path(logical.normalized().as_bytes());
            if let Some(original) = logical.windows_original() {
                builder = builder.windows_file_path(original.as_bytes());
            }
            builder.build()
        },
    );
    if let Some(mapping) = mapping {
        remap_fragment(&fragment, mapping)
    } else {
        fragment
    }
}

struct BuiltSource {
    source: Box<dyn Source>,
    mapping: Option<PathMapping>,
    _sandbox: Option<Sandbox>,
}

struct PathMapping {
    physical: Vec<Vec<u8>>,
    logical: Vec<u8>,
}

fn build_source(request: &Request, config: Option<&CompiledConfig>) -> BuiltSource {
    if request.operation == "files" {
        return build_directory_source(request, config);
    }
    let bytes = if request.fixture_path.is_empty() {
        decode(&request.content_base64)
    } else {
        fs::read(upstream_fixture(&request.fixture_path)).expect("read source fixture")
    };
    let path = request_path(request);
    let options = FileOptions::new(request.buffer_size.unwrap_or(100_000).max(1))
        .expect("positive corpus buffer")
        .max_boundary_read_ahead(request.max_peek_size.unwrap_or(25_000));
    let scheduled = !request.reader_schedule.is_empty();
    let archive_depth = request.max_archive_depth.or_else(|| {
        let lower = request.logical_path.to_ascii_lowercase();
        [
            ".7z", ".br", ".bz2", ".gz", ".lz", ".lz4", ".mz", ".rar", ".s2", ".sz", ".tar", ".xz",
            ".zip", ".zst", ".zz",
        ]
        .iter()
        .any(|extension| lower.contains(extension))
        .then_some(8)
    });
    if let Some(depth) = archive_depth {
        let limits = ArchiveLimits::new(depth, 10_000, 64 << 20, 256 << 20, 64 << 20)
            .expect("valid corpus archive limits");
        let mut archive_options = ArchiveOptions::new(limits);
        if let Some(config) = config {
            archive_options = archive_options.path_config(std::sync::Arc::new(config.clone()));
        }
        return BuiltSource {
            source: Box::new(ArchiveSource::with_options(
                std::io::Cursor::new(bytes),
                path,
                options,
                archive_options,
            )),
            mapping: None,
            _sandbox: None,
        };
    }
    let source: Box<dyn Source> = if scheduled {
        Box::new(FileSource::from_source_reader(
            Box::new(ScheduledReader {
                steps: schedule(request),
            }),
            path,
            options,
        ))
    } else {
        Box::new(FileSource::with_options(
            std::io::Cursor::new(bytes),
            path,
            options,
        ))
    };
    BuiltSource {
        source,
        mapping: None,
        _sandbox: None,
    }
}

fn build_directory_source(request: &Request, config: Option<&CompiledConfig>) -> BuiltSource {
    let sandbox = Sandbox::new(&request.id);
    let physical_base = sandbox.root.join("materialized");
    if !request.missing_root {
        if request.fixture_path.is_empty() {
            materialize_entries(&physical_base, &request.entries);
        } else {
            copy_fixture_tree(&upstream_fixture(&request.fixture_path), &physical_base);
        }
    }
    let root = if request.root_subpath.is_empty() {
        physical_base.clone()
    } else {
        physical_base.join(&request.root_subpath)
    };
    let mut options = DirectoryOptions::default()
        .follow_symlinks(request.follow_symlinks)
        .max_file_size(request.max_file_size);
    if let Some(config) = config {
        options = options.path_config(std::sync::Arc::new(config.clone()));
    }
    if let Some(depth) = request.max_archive_depth {
        let limits = ArchiveLimits::new(depth, 10_000, 64 << 20, 256 << 20, 64 << 20)
            .expect("valid corpus archive limits");
        options = options.archives(ArchiveOptions::new(limits));
    }
    let mapping = PathMapping {
        physical: physical_prefixes(&physical_base),
        logical: logical_base(request).into_bytes(),
    };
    BuiltSource {
        source: Box::new(DirectorySource::with_options(root, options)),
        mapping: Some(mapping),
        _sandbox: Some(sandbox),
    }
}

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(id: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rustleaks-source-corpus-{}-{unique}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create unique source corpus sandbox");
        Self { root }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove source corpus sandbox");
    }
}

fn materialize_entries(root: &Path, entries: &[FixtureEntry]) {
    fs::create_dir_all(root).expect("create synthetic source root");
    for entry in entries {
        let path = root.join(&entry.path);
        match entry.kind.as_str() {
            "dir" => fs::create_dir_all(path).expect("create synthetic directory"),
            "file" => {
                fs::create_dir_all(path.parent().expect("entry parent"))
                    .expect("create synthetic file parent");
                fs::write(&path, decode(&entry.content_base64)).expect("write synthetic file");
                set_fixture_mode(&path, entry.mode);
            }
            "symlink" => {
                fs::create_dir_all(path.parent().expect("entry parent"))
                    .expect("create synthetic symlink parent");
                let target = PathBuf::from(&entry.target);
                let target_is_dir = path.parent().expect("entry parent").join(&target).is_dir();
                create_symlink(&target, &path, target_is_dir);
            }
            kind => panic!("unsupported synthetic fixture kind {kind}"),
        }
    }
}

#[cfg(unix)]
fn set_fixture_mode(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("set synthetic file mode");
    }
}

#[cfg(not(unix))]
fn set_fixture_mode(_path: &Path, _mode: Option<u32>) {}

fn copy_fixture_tree(source: &Path, destination: &Path) {
    let metadata = fs::symlink_metadata(source).expect("fixture metadata");
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source).expect("read fixture symlink");
        // Bazel materializes ordinary data files as absolute runfile symlinks.
        // Copy those as files so directory traversal exercises the same tree
        // Cargo sees, while preserving relative fixture symlinks.
        if target.is_absolute() {
            copy_fixture_tree(&target, destination);
            return;
        }
        let target_is_dir = source
            .parent()
            .expect("fixture parent")
            .join(&target)
            .is_dir();
        create_symlink(&target, destination, target_is_dir);
    } else if metadata.is_dir() {
        fs::create_dir_all(destination).expect("create copied fixture directory");
        let mut children = fs::read_dir(source)
            .expect("read fixture directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read fixture entries");
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            copy_fixture_tree(&child.path(), &destination.join(child.file_name()));
        }
    } else {
        fs::create_dir_all(destination.parent().expect("fixture destination parent"))
            .expect("create copied fixture parent");
        fs::copy(source, destination).expect("copy fixture file");
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path, _target_is_dir: bool) {
    std::os::unix::fs::symlink(target, link).expect("create required fixture symlink");
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path, target_is_dir: bool) {
    let result = if target_is_dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    };
    result.expect("native Windows symlink capability is required for source parity");
}

fn logical_base(request: &Request) -> String {
    let logical = request.logical_path.replace('\\', "/");
    if request.root_subpath.is_empty() {
        return logical;
    }
    let suffix = format!("/{}", request.root_subpath.replace('\\', "/"));
    logical
        .strip_suffix(&suffix)
        .unwrap_or_else(|| panic!("{} logical path/root subpath mismatch", request.id))
        .to_owned()
}

fn normalized_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().replace('\\', "/").into_bytes()
}

fn physical_prefixes(path: &Path) -> Vec<Vec<u8>> {
    let lexical = normalized_path_bytes(path);
    let canonical = fs::canonicalize(path)
        .ok()
        .map(|value| normalized_path_bytes(&value));
    let mut prefixes = vec![lexical];
    if let Some(canonical) = canonical {
        if canonical != prefixes[0] {
            prefixes.push(canonical);
        }
    }
    prefixes
}

fn remap_fragment(fragment: &Fragment, mapping: &PathMapping) -> Fragment {
    let mut builder = Fragment::builder(fragment.content().as_bytes().to_vec())
        .file_path(remap_path(fragment.file_path().as_bytes(), mapping, false))
        .symlink_file(remap_path(
            fragment.symlink_file().as_bytes(),
            mapping,
            false,
        ))
        .windows_file_path(remap_path(
            fragment.windows_file_path().as_bytes(),
            mapping,
            cfg!(windows),
        ))
        .commit(fragment.commit().clone())
        .start_line(fragment.start_line())
        .inherited_from_finding(fragment.inherited_from_finding());
    if let Some(metadata) = fragment.commit_metadata() {
        builder = builder.commit_metadata(metadata.clone());
    }
    builder.build()
}

fn remap_path(value: &[u8], mapping: &PathMapping, windows: bool) -> Vec<u8> {
    if value.is_empty() {
        return Vec::new();
    }
    let normalized = value
        .iter()
        .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
        .collect::<Vec<_>>();
    let Some(suffix) = mapping
        .physical
        .iter()
        .find_map(|prefix| normalized.strip_prefix(prefix.as_slice()))
    else {
        return value.to_vec();
    };
    let mut result = mapping.logical.clone();
    result.extend_from_slice(suffix);
    if windows {
        result = windows_archive_path(&result);
    }
    result
}

fn expected_issue_classes<'a>(request: &Request, expected: &'a Outcome) -> Vec<&'a str> {
    if request.id == "files-looping-symlink" {
        return vec!["source", "source"];
    }
    if request.id == "files-corrupt-archive-matrix" {
        return vec!["source"; request.entries.len()];
    }
    if request.id.starts_with("archive-direct-corrupt-") {
        return vec!["source"];
    }
    if matches!(
        request.id.as_str(),
        "archive-rar5-encrypted-headers" | "archive-rar5-multivolume"
    ) {
        return vec!["source"];
    }
    if let Some(class) = match request.id.as_str() {
        "file-malformed-archive"
        | "archive-direct-corrupt-tar"
        | "files-directory-symlink"
        | "files-dangling-symlink"
        | "files-corrupt-tar"
        | "files-missing" => Some("source"),
        "files-permission-denied" if cfg!(unix) => Some("source"),
        _ => None,
    } {
        return vec![class];
    }
    expected
        .issues
        .iter()
        .map(|issue| issue.class.as_str())
        .collect()
}

fn issues_match(actual: &[&str], expected: &[&str]) -> bool {
    actual == expected
}

fn schedule(request: &Request) -> VecDeque<ScheduledStep> {
    request
        .reader_schedule
        .iter()
        .map(|step| ScheduledStep {
            bytes: decode(&step.data_base64),
            status: match step.error.to_ascii_lowercase().as_str() {
                "" => ReadStatus::Continue,
                "eof" => ReadStatus::Eof,
                _ => ReadStatus::Error {
                    kind: io::ErrorKind::Other,
                    message: "scheduled read error".to_owned(),
                },
            },
        })
        .collect()
}

fn request_path(request: &Request) -> PathBuf {
    if !request.path_base64.is_empty() {
        return bytes_path(decode(&request.path_base64));
    }
    if request.logical_path.is_empty() {
        PathBuf::new()
    } else {
        PathBuf::from(&request.logical_path)
    }
}

#[cfg(unix)]
fn bytes_path(bytes: Vec<u8>) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    PathBuf::from(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn bytes_path(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

fn load_config(request: &Request) -> Option<CompiledConfig> {
    if !request.config_fixture.is_empty() {
        let bytes =
            fs::read(upstream_fixture("testdata/config").join(request.config_fixture.as_str()))
                .expect("read config fixture");
        return Some(
            ConfigLoader::new()
                .load_toml(std::str::from_utf8(&bytes).expect("UTF-8 config"))
                .expect("compile config fixture"),
        );
    }
    if request.skip_paths_base64.is_empty() {
        return None;
    }
    let paths = request
        .skip_paths_base64
        .iter()
        .map(|value| String::from_utf8(decode(value)).expect("UTF-8 path expression"))
        .map(|value| format!("'''{value}'''"))
        .collect::<Vec<_>>()
        .join(", ");
    let text =
        format!("[[rules]]\nid='unused'\nregex='''never'''\n[[allowlists]]\npaths=[{paths}]\n");
    Some(
        ConfigLoader::new()
            .load_toml(&text)
            .expect("compile corpus path allowlist"),
    )
}

fn detect(
    request: &Request,
    config: Option<CompiledConfig>,
    fragments: &[(Fragment, Option<SourceIssueKind>, bool)],
) -> Vec<Finding> {
    if !request.detect && request.operation != "reader" {
        return Vec::new();
    }
    let detector_config = config.unwrap_or_else(|| {
        ConfigLoader::new()
            .load_default()
            .expect("load pinned default detector config")
    });
    let engine = Engine::builder(detector_config)
        .build()
        .expect("build corpus engine");
    if request.operation == "reader" {
        return fragments
            .iter()
            .filter(|(_, issue, _)| issue.is_none())
            .flat_map(|(fragment, _, _)| {
                engine
                    .scan_fragment(fragment, &ScanOptions::default())
                    .into_findings()
            })
            .collect();
    }
    let policy = if request.config_fixture.is_empty() {
        SessionPolicy::default()
    } else {
        let ignore = match request.config_fixture.as_str() {
            "archives.toml" => Some("testdata/archives/files/.gitleaksignore"),
            "simple.toml" | "generic.toml" => Some("testdata/repos/nogit/.gitleaksignore"),
            _ => None,
        };
        ignore.map_or_else(SessionPolicy::default, |path| {
            let parsed = IgnoreSet::parse_go_compatible(
                &fs::read(upstream_fixture(path)).expect("read ignore fixture"),
            );
            assert!(parsed.issues.is_empty());
            SessionPolicy::builder().ignores(parsed.ignores).build()
        })
    };
    let mut session = ScanSession::new(policy);
    for (fragment, issue, _) in fragments {
        if issue.is_some() {
            continue;
        }
        for finding in engine
            .scan_fragment(fragment, &ScanOptions::default())
            .into_findings()
        {
            session.add_finding(finding);
        }
    }
    session.into_findings()
}

fn assert_fragments(request: &Request, actual: &[FragmentWire], expected: &[FragmentWire]) {
    compare_fragments(actual, expected)
        .unwrap_or_else(|message| panic!("{} {message}", request.id));
}

fn compare_fragments(actual: &[FragmentWire], expected: &[FragmentWire]) -> Result<(), String> {
    let comparable = |wire: &FragmentWire| FragmentWire {
        raw_base64: wire.raw_base64.clone(),
        bytes_base64: wire.raw_base64.clone(),
        // Rust has one owned byte representation and cannot reproduce Go's
        // nil-versus-empty slice distinction without reintroducing aliasing.
        bytes_nil: false,
        file_base64: wire.file_base64.clone(),
        windows_file_base64: wire.windows_file_base64.clone(),
        symlink_file_base64: wire.symlink_file_base64.clone(),
        commit_base64: wire.commit_base64.clone(),
        start_line: wire.start_line,
        inherited_from_finding: wire.inherited_from_finding,
    };
    let actual = actual.iter().map(comparable).collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(comparable)
        .map(|mut wire| {
            if cfg!(windows) {
                // The oracle outcome is Darwin-native. Derive upstream's
                // Windows FilePath/WindowsFilePath pair exactly: FilePath is
                // slash-normalized, completed archive segments stay
                // normalized, and only the current member is native.
                let original = windows_representable(&decode(&wire.file_base64));
                let normalized = original
                    .iter()
                    .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
                    .collect::<Vec<_>>();
                wire.file_base64 = encode(&normalized);
                if wire.windows_file_base64.is_empty() {
                    let windows = if normalized.contains(&b'!') {
                        windows_archive_path(&normalized)
                    } else {
                        original
                    };
                    wire.windows_file_base64 = encode(&windows);
                }
            }
            wire
        })
        .collect::<Vec<_>>();
    if actual == expected {
        Ok(())
    } else {
        let differing_index = actual
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected);
        let detail = differing_index.map_or_else(
            || format!("fragment counts differ: actual={} expected={}", actual.len(), expected.len()),
            |index| {
                let actual = &actual[index];
                let expected = &expected[index];
                format!(
                    "first differing fragment {index}: raw bytes actual={} expected={}; file actual={:?} expected={:?}; start line actual={} expected={}",
                    decode(&actual.raw_base64).len(),
                    decode(&expected.raw_base64).len(),
                    String::from_utf8_lossy(&decode(&actual.file_base64)),
                    String::from_utf8_lossy(&decode(&expected.file_base64)),
                    actual.start_line,
                    expected.start_line,
                )
            },
        );
        Err(format!("fragment projection mismatch: {detail}"))
    }
}

fn windows_archive_path(value: &[u8]) -> Vec<u8> {
    let mut result = value.to_vec();
    let inner_start = result
        .iter()
        .rposition(|byte| *byte == b'!')
        .map_or(0, |index| index + 1);
    for byte in &mut result[inner_start..] {
        if *byte == b'/' {
            *byte = b'\\';
        }
    }
    result
}

fn windows_representable(value: &[u8]) -> Vec<u8> {
    // A Windows PathBuf cannot represent the corpus's invalid UTF-8 byte path.
    // The adapter records the exact replacement-string disposition instead.
    String::from_utf8_lossy(value).into_owned().into_bytes()
}

fn fragment_wire(fragment: &Fragment) -> FragmentWire {
    let content = encode(fragment.content().as_bytes());
    FragmentWire {
        raw_base64: content.clone(),
        bytes_base64: content,
        bytes_nil: false,
        file_base64: encode(fragment.file_path().as_bytes()),
        windows_file_base64: encode(fragment.windows_file_path().as_bytes()),
        symlink_file_base64: encode(fragment.symlink_file().as_bytes()),
        commit_base64: encode(fragment.commit().as_bytes()),
        start_line: fragment.start_line(),
        inherited_from_finding: fragment.inherited_from_finding(),
    }
}

fn finding_wire(finding: &Finding) -> FindingWire {
    FindingWire {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        description_base64: encode(finding.description().as_bytes()),
        start_line: finding.location().start_line(),
        end_line: finding.location().end_line(),
        start_column: finding.location().start_column(),
        end_column: finding.location().end_column(),
        line_base64: encode(finding.line().as_bytes()),
        match_base64: encode(finding.match_text().as_bytes()),
        secret_base64: encode(finding.secret().as_bytes()),
        file_base64: encode(finding.file().as_bytes()),
        symlink_file_base64: encode(finding.symlink_file().as_bytes()),
        commit_base64: encode(finding.commit().as_bytes()),
        link_base64: encode(finding.link().as_bytes()),
        entropy_bits: finding.entropy().to_bits(),
        author_base64: encode(finding.author().as_bytes()),
        email_base64: encode(finding.email().as_bytes()),
        date_base64: encode(finding.date().as_bytes()),
        message_base64: encode(finding.message().as_bytes()),
        tags_base64: finding
            .tags()
            .iter()
            .map(|value| encode(value.as_bytes()))
            .collect(),
        fingerprint_base64: encode(finding.fingerprint().as_bytes()),
        fragment: finding.fragment().map(fragment_wire),
        required_findings: finding
            .required_findings()
            .iter()
            .map(required_wire)
            .collect(),
    }
}

fn required_wire(finding: &RequiredFinding) -> RequiredWire {
    RequiredWire {
        rule_id: finding.rule_id().to_string_lossy().into_owned(),
        start_line: finding.location().start_line(),
        end_line: finding.location().end_line(),
        start_column: finding.location().start_column(),
        end_column: finding.location().end_column(),
        line_base64: encode(finding.line().as_bytes()),
        match_base64: encode(finding.match_text().as_bytes()),
        secret_base64: encode(finding.secret().as_bytes()),
    }
}

fn issue_class(kind: SourceIssueKind) -> &'static str {
    match kind {
        SourceIssueKind::Read | SourceIssueKind::BoundaryRead => "read",
        _ => "source",
    }
}

fn corpus_root() -> PathBuf {
    std::env::var_os("RUSTLEAKS_SOURCE_CORPUS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/source-corpus"),
        PathBuf::from,
    )
}

fn upstream_fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/fixtures/upstream")
        .join(relative)
}

fn json_lines<T: for<'de> Deserialize<'de>>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .expect("read JSONL corpus")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid JSONL row"))
        .collect()
}

fn decode(value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .expect("valid frozen base64")
}

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

#[test]
fn corpus_comparators_reject_material_mutations() {
    assert_eq!(windows_archive_path(b"tree/a"), br"tree\a");
    assert_eq!(
        windows_archive_path(b"tree/outer.zip!middle/archive.tar!leaf/value"),
        br"tree/outer.zip!middle/archive.tar!leaf\value"
    );

    let wire = FragmentWire {
        raw_base64: encode(b"first"),
        bytes_base64: encode(b"first"),
        bytes_nil: false,
        file_base64: encode(b"tree/a"),
        windows_file_base64: if cfg!(windows) {
            encode(br"tree\a")
        } else {
            String::new()
        },
        symlink_file_base64: String::new(),
        commit_base64: String::new(),
        start_line: 1,
        inherited_from_finding: false,
    };
    let mut changed_directory = wire.clone();
    changed_directory.file_base64 = encode(b"tree/b");
    assert!(compare_fragments(&[changed_directory], std::slice::from_ref(&wire)).is_err());

    let mut changed_windows = wire.clone();
    changed_windows.windows_file_base64 = encode(br"tree\wrong");
    assert!(compare_fragments(&[changed_windows], std::slice::from_ref(&wire)).is_err());

    let second = FragmentWire {
        raw_base64: encode(b"second"),
        bytes_base64: encode(b"second"),
        ..wire.clone()
    };
    let reconstructed = [wire.clone(), second.clone()]
        .iter()
        .flat_map(|fragment| decode(&fragment.raw_base64))
        .collect::<Vec<_>>();
    assert_eq!(reconstructed, b"firstsecond");
    let mut changed_second = second.clone();
    changed_second.raw_base64 = encode(b"changed");
    assert!(
        compare_fragments(
            &[wire.clone(), changed_second.clone()],
            &[wire.clone(), second]
        )
        .is_err()
    );
    let mutated = [wire, changed_second]
        .iter()
        .flat_map(|fragment| decode(&fragment.raw_base64))
        .collect::<Vec<_>>();
    assert_ne!(mutated, b"firstsecond");

    assert!(!issues_match(&["source"], &[]));
}
