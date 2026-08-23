//! Differential replay of the pinned fresh-process Git source corpus.
#![cfg(feature = "archives")]

mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use rustleaks_core::Engine;
use rustleaks_core::config::{CompiledConfig, ConfigLoader, FileSystemResolver};
use rustleaks_core::model::{
    ByteText, CommitMetadata, Finding, Fragment, RequiredFinding, ScanOptions,
};
use rustleaks_core::session::{IgnoreSet, ScanSession, SessionPolicy};
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, CancellationToken, GitMode, ScmPlatform, Source, SourceControl,
    SourceError, SourceEvent, SourceIssueKind, SourceStage,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct Request {
    id: String,
    operation: String,
    repository: String,
    #[serde(default)]
    log_options: String,
    #[serde(default)]
    staged: bool,
    #[serde(default)]
    mutation: String,
    #[serde(default)]
    config_fixture: String,
    max_archive_depth: Option<usize>,
    #[serde(default)]
    cancel_after_start: bool,
    #[serde(default)]
    detect: bool,
    #[serde(default)]
    load_ignore: bool,
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
    commit_info: Option<CommitInfoWire>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_field_names)]
struct CommitInfoWire {
    author_name_base64: String,
    author_email_base64: String,
    date_base64: String,
    message_base64: String,
    sha_base64: String,
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
}

#[derive(Deserialize)]
struct ErrorWire {
    class: String,
}

#[test]
fn matrix_n_isolated_platform_fixtures_use_distinct_private_copies() {
    let first = Sandbox::new("matrix-n");
    let second = Sandbox::new("matrix-n");
    assert_ne!(first.root, second.root);
    assert!(first.root.starts_with(std::env::temp_dir()));
    assert!(second.root.starts_with(std::env::temp_dir()));
}

#[test]
fn matrix_g_allowlist_corpus_retains_source_work_and_downstream_suppression() {
    let requests = json_lines::<Request>(&corpus_root().join("requests-v1.jsonl"));
    let request = requests
        .iter()
        .find(|request| request.id == "ineffective-commit-allowlist")
        .expect("source-level allowlist corpus row");
    assert!(!replay(request).fragments.is_empty());
}

#[test]
fn valid_git_corpus_fragments_match_and_failures_have_safe_dispositions() {
    let root = corpus_root();
    let requests = json_lines::<Request>(&root.join("requests-v1.jsonl"));
    let outcomes = json_lines::<Outcome>(&root.join("outcomes-v1.jsonl"))
        .into_iter()
        .map(|outcome| (outcome.id.clone(), outcome))
        .collect::<BTreeMap<_, _>>();
    let mut equal = 0;
    let mut safe = 0;
    let mut remote = 0;

    for request in requests {
        let expected = &outcomes[&request.id];
        if request.operation == "remote" {
            remote += 1;
            continue;
        }
        let actual = replay(&request);
        match request.id.as_str() {
            "log-options-double-space"
            | "log-options-leading-trailing-space"
            | "log-options-literal-quotes"
            | "log-options-literal-double-quotes"
            | "log-options-tab-not-split"
            | "log-options-shell-metacharacters-literal"
            | "malformed-not-a-repository" => {
                assert_eq!(expected.issues.len(), 1, "{}", request.id);
                assert_eq!(expected.issues[0].class, "stderr", "{}", request.id);
                assert!(
                    matches!(
                        actual.error,
                        Some(SourceError::Terminal {
                            stage: SourceStage::GitExit,
                            ..
                        })
                    ),
                    "{}",
                    request.id
                );
                assert!(actual.fragments.is_empty(), "{}", request.id);
                safe += 1;
            }
            "cancel-after-start" => {
                assert_eq!(
                    expected.error.as_ref().map(|error| error.class.as_str()),
                    Some("canceled")
                );
                assert!(matches!(actual.error, Some(SourceError::Cancelled)));
                safe += 1;
            }
            "staged-malformed-archive-worker-error" => {
                assert!(expected.fragments.is_empty());
                assert!(expected.issues.is_empty());
                assert!(expected.error.is_none());
                assert!(
                    actual.error.is_some()
                        || actual.issues.iter().any(|kind| matches!(
                            kind,
                            SourceIssueKind::CorruptArchive
                                | SourceIssueKind::ArchiveMember
                                | SourceIssueKind::Decode
                        )),
                    "Rust must surface the Go worker-error loss"
                );
                safe += 1;
            }
            _ => {
                assert!(actual.error.is_none(), "{}: {:?}", request.id, actual.error);
                assert!(
                    actual.issues.is_empty(),
                    "{}: {:?}",
                    request.id,
                    actual.issues
                );
                assert_fragments(&request.id, &actual.fragments, &expected.fragments);
                assert_findings(&request.id, &actual.findings, &expected.findings);
                equal += 1;
            }
        }
        assert!(
            !actual.repository.join("proof").exists(),
            "shell metacharacters executed"
        );
    }

    assert_eq!(equal, 12);
    assert_eq!(safe, 9);
    assert_eq!(remote, 13);
}

struct Replay {
    fragments: Vec<FragmentWire>,
    findings: Vec<FindingWire>,
    issues: Vec<SourceIssueKind>,
    error: Option<SourceError>,
    repository: PathBuf,
    _sandbox: Sandbox,
}

fn replay(request: &Request) -> Replay {
    let sandbox = Sandbox::new(&request.id);
    let repository = sandbox.root.join("repository");
    if request.repository == "empty" {
        fs::create_dir(&repository).expect("create private repository");
    } else {
        copy_tree(
            &fixture_root()
                .join("testdata/repos")
                .join(&request.repository),
            &repository,
        );
        fs::rename(repository.join("dotGit"), repository.join(".git"))
            .expect("activate copied Git metadata");
    }
    let empty_config = sandbox.root.join("empty-gitconfig");
    fs::write(&empty_config, []).expect("write empty Git config");
    let environment = git_environment(&empty_config);
    apply_mutation(&repository, &request.mutation, &environment);

    let mode = match request.operation.as_str() {
        "log" => GitMode::Log {
            options: (!request.log_options.is_empty()).then(|| request.log_options.clone()),
        },
        "diff" => GitMode::Diff {
            staged: request.staged,
        },
        operation => panic!("unsupported Git corpus operation {operation}"),
    };
    let detector_config = load_config(request);
    let mut source = support::git_source(&repository)
        .mode(mode)
        .command_environment(environment.clone());
    if let Some(depth) = request.max_archive_depth {
        let limits = ArchiveLimits::new(depth, 10_000, 64 << 20, 256 << 20, 64 << 20)
            .expect("valid Git corpus archive limits");
        let mut options = ArchiveOptions::new(limits);
        if !request.config_fixture.is_empty() {
            let config = detector_config.clone().expect("Git corpus archive config");
            options = options.path_config(Arc::new(config));
        }
        source = source.archives(options);
    }

    let cancellation = CancellationToken::new();
    if request.cancel_after_start {
        // Rust guarantees the stronger before-spawn form here; the process
        // lifecycle unit tests cover kill/reap after a real spawn.
        cancellation.cancel();
    }
    let mut fragments = Vec::new();
    let mut source_fragments = Vec::new();
    let mut issues = Vec::new();
    let result = source.visit(&cancellation, &mut |event| {
        match event {
            SourceEvent::Fragment { fragment, issue } => {
                fragments.push(fragment_wire(&fragment));
                source_fragments.push((*fragment).clone());
                if let Some(issue) = issue {
                    issues.push(issue.kind());
                }
            }
            SourceEvent::Issue(issue) => issues.push(issue.kind()),
            _ => panic!("unexpected future Git source event"),
        }
        Ok(SourceControl::Continue)
    });
    let findings = detect_findings(request, detector_config, &repository, &source_fragments);
    Replay {
        fragments,
        findings,
        issues,
        error: result.err(),
        repository,
        _sandbox: sandbox,
    }
}

fn load_config(request: &Request) -> Option<CompiledConfig> {
    if request.config_fixture.is_empty() {
        return None;
    }
    let path = fixture_root()
        .join("testdata/config")
        .join(&request.config_fixture);
    Some(
        ConfigLoader::new()
            .with_resolver(FileSystemResolver::new())
            .load_resolved(path.to_str().expect("UTF-8 fixture path"))
            .expect("load Git corpus config"),
    )
}

fn detect_findings(
    request: &Request,
    config: Option<CompiledConfig>,
    repository: &Path,
    fragments: &[Fragment],
) -> Vec<FindingWire> {
    if !request.detect {
        return Vec::new();
    }
    let engine = Engine::builder(config.expect("detector config"))
        .build()
        .expect("build Git corpus engine");
    let policy = if request.load_ignore {
        let parsed = IgnoreSet::parse_go_compatible(
            &fs::read(repository.join(".gitleaksignore")).expect("read repository ignore file"),
        );
        assert!(parsed.issues.is_empty());
        SessionPolicy::builder().ignores(parsed.ignores).build()
    } else {
        SessionPolicy::default()
    };
    let mut session = ScanSession::new(policy);
    for fragment in fragments {
        for finding in engine
            .scan_fragment(fragment, &ScanOptions::default())
            .into_findings()
        {
            session.add_finding(finding);
        }
    }
    let remote =
        support::discover_remote(ScmPlatform::Unknown, repository, &CancellationToken::new())
            .expect("discover fixture remote");
    session
        .into_findings()
        .iter()
        .map(|finding| {
            let link = remote.link_for(finding).expect("construct fixture link");
            finding_wire(finding, link.as_ref().map(ByteText::as_bytes))
        })
        .collect()
}

fn fragment_wire(fragment: &Fragment) -> FragmentWire {
    FragmentWire {
        raw_base64: encode(fragment.content().as_bytes()),
        bytes_base64: String::new(),
        bytes_nil: true,
        file_base64: encode(fragment.file_path().as_bytes()),
        windows_file_base64: encode(fragment.windows_file_path().as_bytes()),
        symlink_file_base64: encode(fragment.symlink_file().as_bytes()),
        commit_base64: encode(fragment.commit().as_bytes()),
        start_line: fragment.start_line(),
        inherited_from_finding: fragment.inherited_from_finding(),
        commit_info: fragment.commit_metadata().map(commit_wire),
    }
}

fn assert_fragments(id: &str, actual: &[FragmentWire], expected: &[FragmentWire]) {
    let comparable = |wire: &FragmentWire| FragmentWire {
        raw_base64: wire.raw_base64.clone(),
        bytes_base64: wire.raw_base64.clone(),
        // Rust deliberately models fragment content once rather than preserving
        // Go's nil-versus-populated alias of the same bytes.
        bytes_nil: false,
        file_base64: wire.file_base64.clone(),
        windows_file_base64: wire.windows_file_base64.clone(),
        symlink_file_base64: wire.symlink_file_base64.clone(),
        commit_base64: wire.commit_base64.clone(),
        start_line: wire.start_line,
        inherited_from_finding: wire.inherited_from_finding,
        commit_info: wire.commit_info.clone(),
    };
    let actual = actual.iter().map(comparable).collect::<Vec<_>>();
    let expected = expected.iter().map(comparable).collect::<Vec<_>>();
    if actual != expected {
        let first = actual
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected);
        panic!(
            "{id}: Git fragment projection differs at {first:?} (actual {}, expected {})",
            actual.len(),
            expected.len()
        );
    }
}

fn assert_findings(id: &str, actual: &[FindingWire], expected: &[FindingWire]) {
    let mut actual = actual
        .iter()
        .map(|finding| serde_json::to_string(finding).expect("serialize actual finding"))
        .collect::<Vec<_>>();
    let mut expected = expected
        .iter()
        .map(|finding| serde_json::to_string(finding).expect("serialize expected finding"))
        .collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual != expected {
        let first = actual
            .iter()
            .zip(&expected)
            .position(|(actual, expected)| actual != expected);
        panic!(
            "{id}: Git finding multiset differs at {first:?} (actual {}, expected {})",
            actual.len(),
            expected.len()
        );
    }
}

fn finding_wire(finding: &Finding, link: Option<&[u8]>) -> FindingWire {
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
        link_base64: encode(link.unwrap_or(finding.link().as_bytes())),
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

fn commit_wire(metadata: &CommitMetadata) -> CommitInfoWire {
    CommitInfoWire {
        author_name_base64: encode(metadata.author_name().as_bytes()),
        author_email_base64: encode(metadata.author_email().as_bytes()),
        date_base64: encode(metadata.date().as_bytes()),
        message_base64: encode(metadata.message().as_bytes()),
        sha_base64: encode(metadata.sha().as_bytes()),
    }
}

fn apply_mutation(repository: &Path, mutation: &str, environment: &[(OsString, OsString)]) {
    match mutation {
        "" => {}
        "working-additions" => fs::write(
            repository.join("main.go"),
            b"this line is added\nand another one",
        )
        .expect("write working additions"),
        "delete-main" => fs::remove_file(repository.join("main.go")).expect("delete main"),
        "binary-main" => fs::write(repository.join("main.go"), b"bin\0ary").expect("write binary"),
        "staged-rename" => run_git(repository, ["mv", "main.go", "renamed.go"], environment),
        "staged-bad-archive" => {
            fs::rename(repository.join("main.go"), repository.join("broken.zip"))
                .expect("rename malformed archive");
            fs::write(repository.join("broken.zip"), b"PK\x03\x04\0x")
                .expect("write malformed archive");
            run_git(
                repository,
                ["add", "-A", "--", "main.go", "broken.zip"],
                environment,
            );
        }
        "binary-archive-worktree" => fs::write(repository.join("main.go.zst"), b"bad\0zst")
            .expect("write divergent worktree archive"),
        value => panic!("unknown Git corpus mutation {value}"),
    }
}

fn run_git<const N: usize>(
    repository: &Path,
    arguments: [&str; N],
    environment: &[(OsString, OsString)],
) {
    let status = support::command()
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .envs(environment.iter().cloned())
        .status()
        .expect("run fixture Git mutation");
    assert!(status.success());
}

fn git_environment(config: &Path) -> Vec<(OsString, OsString)> {
    vec![
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            config.as_os_str().to_owned(),
        ),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("TZ"), OsString::from("UTC")),
    ]
}

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rustleaks-git-corpus-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create Git corpus sandbox");
        Self { root }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove Git corpus sandbox");
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create copied Git directory");
    for entry in fs::read_dir(source).expect("read Git fixture") {
        let entry = entry.expect("Git fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("Git fixture type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy Git fixture file");
        }
    }
}

fn json_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Vec<T> {
    fs::read_to_string(path)
        .expect("read Git corpus JSONL")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("decode Git corpus row"))
        .collect()
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/git-corpus")
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/fixtures/upstream")
}

fn encode(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}
