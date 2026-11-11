//! Synthetic source, Git, and CLI scale workloads for the opt-in runner.
//!
//! Every fixture is generated before its timers start and is removed afterward.
//! Expected counts, paths, lines, and finding multisets come from the generator
//! manifest and from `expected_chunks`, an independent model of the `FileSource`
//! fragment rule. No expectation is derived from output of the measured code.

use std::error::Error;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustleaks_core::Engine;
use rustleaks_core::config::{CompiledConfig, ConfigLoader, DEFAULT_CONFIG_BYTES};
use rustleaks_core::model::{CommitMetadata, Finding, Fragment, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_sources::{
    CallbackError, Cancellation, CancellationToken, DirectoryOptions, DirectorySource, GitMode,
    GitSource, Source, SourceControl, SourceError, SourceEvent, SourceOutcome, SourceRunner,
    SourceTermination,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::{Phase, SCOPE, fingerprint};
use crate::representative_io;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub const WORKLOADS: &[&str] = &[
    "source-default-config-1-workers",
    "source-default-config-4-workers",
    "source-default-config-8-workers",
    "source-blank-lines-12-mib",
    "source-no-blank-lines-12-mib",
    "source-single-line-64-mib",
    "source-many-tiny-50000",
    "source-deep-tree",
    "source-mostly-ignored",
    "source-binary-mix",
    "source-skewed-sizes",
    "git-many-tiny-commits",
    "git-wide-commit",
    "git-merge-and-rename",
    "git-archive-blobs",
    "archive-high-ratio-gzip",
    "archive-high-ratio-zstd",
    "archive-high-ratio-bzip2",
    "archive-nested-depth-8",
    "archive-nested-depth-9",
    "archive-tar-10000-members",
    "archive-tar-10001-members",
    "archive-zstd-many-small",
    "cli-many-issues",
    "cli-stdin-chunked",
    "cli-enable-rule-startup",
];

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
/// Unit tests run the same generators over a smaller fixture.
const SCALE: usize = if cfg!(test) { 64 } else { 1 };

/// Applies a minimum through a runtime value so both scale settings compile alike.
fn at_least(value: usize, minimum: usize) -> usize {
    value.max(minimum)
}
const QUEUE_CAPACITY: usize = 8;
const FILLER: &[u8] = b"pad the fixture body with ordinary words and spaces here\n";
const SIMPLE_CONFIG: &str = "[[rules]]\nid = 'perf-token'\ndescription = 'synthetic token'\nregex = 'A{16}'\nkeywords = ['AAAA']\n";
const TOKEN: &[u8; 16] = b"AAAAAAAAAAAAAAAA";
const TOKEN_RULE: &str = "perf-token";
const GITHUB_RULE: &str = "github-pat";
const GIT_AUTHOR: &str = "Performance Fixture";
const GIT_EMAIL: &str = "perf@example.invalid";
const GIT_BASE_TIME: u64 = 946_684_800; // 2000-01-01T00:00:00Z
const GIT_LOG_NO_RENAMES: [&str; 5] = [
    "--all",
    "--full-history",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
];
const GIT_LOG_WITH_COPIES: [&str; 7] = [
    "--all",
    "--full-history",
    "--no-ext-diff",
    "--no-textconv",
    "-M",
    "-C",
    "--find-copies-harder",
];

pub fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    if !(1..=1_000).contains(&iterations) {
        return Err("source scale iterations outside 1..=1000".into());
    }
    match id {
        "source-default-config-1-workers" => default_config_workload(iterations, 1),
        "source-default-config-4-workers" => default_config_workload(iterations, 4),
        "source-default-config-8-workers" => default_config_workload(iterations, 8),
        "source-blank-lines-12-mib" => {
            let fixture = line_chunking_fixture(true)?;
            directory_workload(&fixture, 1, iterations)
        }
        "source-no-blank-lines-12-mib" => {
            let fixture = line_chunking_fixture(false)?;
            directory_workload(&fixture, 1, iterations)
        }
        "source-single-line-64-mib" => directory_workload(&single_line_fixture()?, 1, iterations),
        "source-many-tiny-50000" => directory_workload(&many_tiny_fixture()?, 1, iterations),
        "source-deep-tree" => directory_workload(&deep_tree_fixture()?, 1, iterations),
        "source-mostly-ignored" => directory_workload(&mostly_ignored_fixture()?, 1, iterations),
        "source-binary-mix" => directory_workload(&binary_mix_fixture()?, 1, iterations),
        "source-skewed-sizes" => directory_workload(&skewed_sizes_fixture()?, 1, iterations),
        "git-many-tiny-commits" => git_workload(&many_tiny_commits_plan(), iterations),
        "git-wide-commit" => git_workload(&wide_commit_plan(), iterations),
        "git-merge-and-rename" => git_workload(&merge_and_rename_plan(), iterations),
        "cli-many-issues" => cli_many_issues(iterations),
        "cli-stdin-chunked" => cli_stdin_chunked(iterations),
        "cli-enable-rule-startup" => cli_enable_rule_startup(iterations),
        "git-archive-blobs"
        | "archive-high-ratio-gzip"
        | "archive-high-ratio-zstd"
        | "archive-high-ratio-bzip2"
        | "archive-nested-depth-8"
        | "archive-nested-depth-9"
        | "archive-tar-10000-members"
        | "archive-tar-10001-members"
        | "archive-zstd-many-small" => archive_driver(id, iterations),
        _ => Err(format!("unknown source scale workload {id}").into()),
    }
}

// Shared scratch, engine, and comparison helpers.

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rustleaks-perf-scale-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("empty"))?;
        fs::write(root.join("empty-config"), b"")?;
        Ok(Self(root))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn simple_engine() -> Result<Engine> {
    Ok(Engine::builder(ConfigLoader::new().load_toml(SIMPLE_CONFIG)?).build()?)
}

fn default_config() -> Result<CompiledConfig> {
    Ok(ConfigLoader::new().load_toml(std::str::from_utf8(DEFAULT_CONFIG_BYTES)?)?)
}

/// One expected finding, keyed by fields the generator computes independently.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct FindingKey {
    rule: Vec<u8>,
    file: Vec<u8>,
    commit: Vec<u8>,
    line: usize,
    column: usize,
    secret: Vec<u8>,
}

fn key(
    rule: &str,
    file: &str,
    commit: &str,
    line: usize,
    column: usize,
    secret: &[u8],
) -> FindingKey {
    FindingKey {
        rule: rule.as_bytes().to_vec(),
        file: file.as_bytes().to_vec(),
        commit: commit.as_bytes().to_vec(),
        line,
        column,
        secret: secret.to_vec(),
    }
}

fn finding_keys(findings: &[Finding]) -> Vec<FindingKey> {
    let mut keys = findings
        .iter()
        .map(|finding| FindingKey {
            rule: finding.rule_id().as_bytes().to_vec(),
            file: finding.file().as_bytes().to_vec(),
            commit: finding.commit().as_bytes().to_vec(),
            line: finding.location().start_line(),
            column: finding.location().start_column(),
            secret: finding.secret().as_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn verify_findings(actual: &[Finding], expected: &[FindingKey]) -> Result<Vec<u8>> {
    let keys = finding_keys(actual);
    if keys != expected {
        let mismatch = keys
            .iter()
            .zip(expected)
            .position(|(left, right)| left != right)
            .unwrap_or(keys.len().min(expected.len()));
        return Err(format!(
            "source scale findings differ from the generator manifest: expected {}, observed {}; first mismatch {mismatch}: expected {:?}, observed {:?}",
            expected.len(),
            keys.len(),
            expected.get(mismatch).map(describe_key),
            keys.get(mismatch).map(describe_key)
        )
        .into());
    }
    Ok(serde_json::to_vec(&keys)?)
}

fn describe_key(key: &FindingKey) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        String::from_utf8_lossy(&key.rule),
        String::from_utf8_lossy(&key.file),
        String::from_utf8_lossy(&key.commit),
        key.line,
        key.column
    )
}

fn verify_outcome(
    outcome: &SourceOutcome,
    bytes: u64,
    commits: usize,
    expected: &[FindingKey],
) -> Result<Vec<u8>> {
    if outcome.termination() != &SourceTermination::Completed || !outcome.issues().is_empty() {
        return Err("source scale run stopped or produced an unexpected issue".into());
    }
    if outcome.scanned_bytes() != bytes {
        return Err(format!(
            "source scale scanned {} bytes, generator manifest has {bytes}",
            outcome.scanned_bytes()
        )
        .into());
    }
    if outcome.unique_commit_count() != commits {
        return Err("source scale unique commit count differs from the generator".into());
    }
    verify_findings(outcome.findings(), expected)
}

fn collect_fragments(source: &mut dyn Source) -> Result<Vec<Fragment>> {
    let mut fragments = Vec::new();
    let control = source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment {
                fragment,
                issue: None,
            } => fragments.push(*fragment),
            _ => return Err(CallbackError::new("source scale traversal issue")),
        }
        Ok(SourceControl::Continue)
    })?;
    if control != SourceControl::Continue {
        return Err("source scale traversal stopped".into());
    }
    Ok(fragments)
}

fn fragment_sort_key(fragment: &Fragment) -> (Vec<u8>, Vec<u8>, usize) {
    (
        fragment.commit().as_bytes().to_vec(),
        fragment.file_path().as_bytes().to_vec(),
        fragment.start_line(),
    )
}

fn verify_fragments(mut actual: Vec<Fragment>, expected: &[Fragment], sorted: bool) -> Result<()> {
    if sorted {
        actual.sort_by_key(fragment_sort_key);
    }
    if actual.len() != expected.len() {
        return Err(format!(
            "source scale produced {} fragments, generator manifest has {}",
            actual.len(),
            expected.len()
        )
        .into());
    }
    if let Some(index) = actual
        .iter()
        .zip(expected)
        .position(|(left, right)| left != right)
    {
        return Err(format!(
            "source scale fragment {index} differs from the generator manifest: path {}, start line {}, bytes {} versus expected path {}, start line {}, bytes {}",
            actual[index].file_path().to_string_lossy(),
            actual[index].start_line(),
            actual[index].content().len(),
            expected[index].file_path().to_string_lossy(),
            expected[index].start_line(),
            expected[index].content().len()
        )
        .into());
    }
    Ok(())
}

struct Replay<'a>(&'a [Fragment]);

impl Source for Replay<'_> {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> std::result::Result<SourceControl, CallbackError>,
    ) -> std::result::Result<SourceControl, SourceError> {
        for fragment in self.0 {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            if emit(SourceEvent::fragment(fragment.clone())).map_err(SourceError::Callback)?
                == SourceControl::Stop
            {
                return Ok(SourceControl::Stop);
            }
        }
        Ok(SourceControl::Continue)
    }
}

struct Row<'a> {
    phase: &'a str,
    iterations: usize,
    elapsed: Duration,
    unit: &'a str,
    units: u64,
    input_fingerprint: &'a str,
    config: &'a [u8],
    outcome: &'a [u8],
    findings: usize,
    counts: Value,
}

fn row(row: Row<'_>) -> Result<Phase> {
    Ok(Phase {
        phase: row.phase.into(),
        iterations: row.iterations,
        elapsed_ns: u64::try_from(row.elapsed.as_nanos())?,
        logical_unit: row.unit.into(),
        logical_units_per_iteration: row.units,
        input_fnv1a64: row.input_fingerprint.to_owned(),
        config_fnv1a64: fingerprint(row.config),
        outcome_fnv1a64: fingerprint(row.outcome),
        findings: row.findings as u64,
        errors: 0,
        complete: true,
        counts: row.counts,
        scope: SCOPE.into(),
    })
}

// Independent FileSource fragment model.

const NOMINAL_BYTES: usize = 100_000;
const READ_AHEAD_BYTES: usize = 25_000;
const READER_FILL_BYTES: usize = 4_096;

/// One fragment expected from the file chunking rule.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Chunk {
    start: usize,
    end: usize,
    start_line: usize,
}

const fn boundary_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn suffix_is_safe(bytes: &[u8]) -> bool {
    if !bytes.last().copied().is_some_and(boundary_whitespace) {
        return false;
    }
    let mut newlines = 0_u8;
    for byte in bytes.iter().rev().copied() {
        if byte == b'\n' {
            newlines += 1;
            if newlines >= 2 {
                return true;
            }
        } else if !boundary_whitespace(byte) {
            return false;
        }
    }
    false
}

/// Models `FileSource`: one 100,000-byte read, then read-ahead through a
/// 4,096-byte buffered reader until a blank line or 25,000 appended bytes.
/// Leftover buffered bytes are drained by the next nominal read, which is
/// therefore short. The chunker sees whole-file bytes at once; every read is
/// assumed to return the requested count unless end of input is reached.
#[allow(
    clippy::naive_bytecount,
    reason = "bounded fixture oracle outside timers"
)]
fn expected_chunks(content: &[u8]) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut position = 0_usize;
    let mut buffered = 0_usize;
    let mut total_lines = 0_usize;
    loop {
        let start = position;
        if buffered > 0 {
            position += buffered.min(NOMINAL_BYTES);
            buffered -= buffered.min(NOMINAL_BYTES);
        } else {
            let count = (content.len() - position).min(NOMINAL_BYTES);
            if count == 0 {
                break;
            }
            position += count;
        }
        let nominal_end = position;
        if !suffix_is_safe(&content[start..position]) {
            let mut newlines = 0_u8;
            loop {
                let last = content[position - 1];
                if last == b'\n' {
                    newlines += 1;
                    if newlines >= 2 {
                        break;
                    }
                } else if !boundary_whitespace(last) {
                    newlines = 0;
                }
                if position - nominal_end >= READ_AHEAD_BYTES {
                    break;
                }
                if buffered == 0 {
                    let available = (content.len() - position).min(READER_FILL_BYTES);
                    if available == 0 {
                        break;
                    }
                    buffered = available;
                }
                buffered -= 1;
                position += 1;
            }
        }
        chunks.push(Chunk {
            start,
            end: position,
            start_line: total_lines + 1,
        });
        total_lines += content[start..position]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
    }
    chunks
}

/// Returns the absolute one-based line and upstream column of a planted match.
///
/// The engine reports `start - previous_newline + 1` within a fragment, and
/// `start + 1` on the fragment's first line, so the column depends on where
/// the expected fragment boundaries fall.
#[allow(
    clippy::naive_bytecount,
    reason = "bounded fixture oracle outside timers"
)]
fn locate(content: &[u8], chunks: &[Chunk], offset: usize) -> (usize, usize) {
    let index = chunks.partition_point(|chunk| chunk.end <= offset);
    let chunk = &chunks[index];
    let within = &content[chunk.start..offset];
    let line = chunk.start_line + within.iter().filter(|byte| **byte == b'\n').count();
    (line, fragment_column(within, offset - chunk.start))
}

fn fragment_column(before_match: &[u8], offset: usize) -> usize {
    match before_match.iter().rposition(|byte| *byte == b'\n') {
        Some(previous) => offset - previous + 1,
        None => offset + 1,
    }
}

fn file_fragments(path: &str, content: &[u8], fragments: &mut Vec<Fragment>) {
    for chunk in expected_chunks(content) {
        let mut builder = Fragment::builder(content[chunk.start..chunk.end].to_vec())
            .file_path(path.to_owned())
            .start_line(chunk.start_line);
        if cfg!(windows) {
            builder = builder.windows_file_path(path.replace('/', "\\"));
        }
        fragments.push(builder.build());
    }
}

// Directory fixtures.

struct DirectoryFixture {
    scratch: Scratch,
    config: CompiledConfigKind,
    path_config: Option<Arc<CompiledConfig>>,
    fragments: Vec<Fragment>,
    findings: Vec<FindingKey>,
    bytes: u64,
    files: usize,
    input_fingerprint: String,
}

enum CompiledConfigKind {
    Simple,
    Default { prune_paths: bool },
}

fn write_tree(root: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    let mut last_parent: Option<PathBuf> = None;
    for (relative, content) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent()
            && last_parent.as_deref() != Some(parent)
        {
            fs::create_dir_all(parent)?;
            last_parent = Some(parent.to_path_buf());
        }
        fs::write(path, content)?;
    }
    Ok(())
}

fn manifest_fingerprint(files: &[(String, Vec<u8>)]) -> String {
    let mut bytes = Vec::with_capacity(files.len() * 32);
    for (path, content) in files {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(fingerprint(content).as_bytes());
        bytes.push(b'\n');
    }
    fingerprint(&bytes)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the fixture takes ownership of its generated file table"
)]
fn finish_directory_fixture(
    files: Vec<(String, Vec<u8>)>,
    fragments: Vec<Fragment>,
    mut findings: Vec<FindingKey>,
    config: CompiledConfigKind,
) -> Result<DirectoryFixture> {
    let scratch = Scratch::new()?;
    let input = scratch.0.join("input");
    fs::create_dir(&input)?;
    write_tree(&input, &files)?;
    let bytes = fragments
        .iter()
        .map(|fragment| fragment.content().len() as u64)
        .sum();
    findings.sort();
    let path_config = if matches!(config, CompiledConfigKind::Default { prune_paths: true }) {
        Some(Arc::new(default_config()?))
    } else {
        None
    };
    Ok(DirectoryFixture {
        input_fingerprint: manifest_fingerprint(&files),
        scratch,
        config,
        path_config,
        fragments,
        findings,
        bytes,
        files: files.len(),
    })
}

fn github_token(index: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut state = 0x9e37_79b9_u32.wrapping_mul(u32::try_from(index).unwrap_or(0).wrapping_add(1));
    let mut token = b"ghp_".to_vec();
    for _ in 0..36 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        token.push(ALPHABET[(state >> 24) as usize % ALPHABET.len()]);
    }
    token
}

/// Pads a token line to one filler-sized row so plants never move boundaries.
fn token_row(token: &[u8]) -> Vec<u8> {
    let mut row = token.to_vec();
    row.resize(FILLER.len() - 1, b' ');
    row.push(b'\n');
    row
}

fn default_config_workload(iterations: usize, workers: usize) -> Result<Vec<Phase>> {
    directory_workload(&default_config_fixture()?, workers, iterations)
}

fn default_config_fixture() -> Result<DirectoryFixture> {
    let file_bytes = 131_072 / SCALE;
    let rows = file_bytes / FILLER.len();
    let mut files = Vec::new();
    let mut fragments = Vec::new();
    let mut findings = Vec::new();
    for index in 0..96 {
        let path = format!("input/file-{index:03}.txt");
        let token_at = (rows / 2 + index) % rows;
        let token = github_token(index);
        let mut content = Vec::with_capacity(file_bytes);
        for row in 0..rows {
            content.extend_from_slice(&if row == token_at {
                token_row(&token)
            } else {
                FILLER.to_vec()
            });
        }
        let chunks = expected_chunks(&content);
        let (line, column) = locate(&content, &chunks, token_at * FILLER.len());
        findings.push(key(GITHUB_RULE, &path, "", line, column, &token));
        file_fragments(&path, &content, &mut fragments);
        files.push((format!("file-{index:03}.txt"), content));
    }
    finish_directory_fixture(
        files,
        fragments,
        findings,
        CompiledConfigKind::Default { prune_paths: false },
    )
}

fn line_chunking_fixture(blank_lines: bool) -> Result<DirectoryFixture> {
    let total = 12 * MIB / SCALE;
    let lines = total / FILLER.len();
    let token_row_every = (lines / 16).max(2);
    let mut content = Vec::with_capacity(total + lines);
    let mut token_offsets = Vec::new();
    let path = "input/data.txt";
    for index in 0..lines {
        if index != 0 && index % token_row_every == 0 {
            token_offsets.push(content.len());
            content.extend_from_slice(&token_row(TOKEN));
        } else {
            content.extend_from_slice(FILLER);
        }
        if blank_lines && index % 32 == 31 {
            content.push(b'\n');
        }
    }
    let chunks = expected_chunks(&content);
    let findings = token_offsets
        .into_iter()
        .map(|offset| {
            let (line, column) = locate(&content, &chunks, offset);
            key(TOKEN_RULE, path, "", line, column, TOKEN)
        })
        .collect();
    let mut fragments = Vec::new();
    file_fragments(path, &content, &mut fragments);
    finish_directory_fixture(
        vec![("data.txt".to_owned(), content)],
        fragments,
        findings,
        CompiledConfigKind::Simple,
    )
}

/// One line of filler bytes, so read-ahead always reaches its 25,000-byte cap
/// and every fragment keeps start line 1. The first fragment is 125,000 bytes,
/// and every later one is 3,672 bytes of drained read-ahead plus 25,000 more.
fn single_line_fixture() -> Result<DirectoryFixture> {
    let size = 64 * MIB / SCALE;
    let mut content = vec![b'x'; size];
    let chunks = expected_chunks(&content);
    assert_eq!(
        chunks.len(),
        1 + (size - 125_000).div_ceil(28_672),
        "single-line fragment count must match 125,000 plus 28,672-byte fragments"
    );
    let path = "input/single.txt";
    let mut findings = Vec::new();
    let step = (chunks.len() / 16).max(1);
    for (index, chunk) in chunks.iter().enumerate() {
        if index % step == 0 && index != 0 {
            // Straddle the cut before this fragment: neither side holds 16 bytes.
            content[chunk.start - 8..chunk.start + 8].copy_from_slice(TOKEN);
        } else if index % step == step / 2 {
            let offset = chunk.start + (chunk.end - chunk.start) / 2 - 8;
            content[offset..offset + TOKEN.len()].copy_from_slice(TOKEN);
            findings.push(key(
                TOKEN_RULE,
                path,
                "",
                1,
                offset - chunk.start + 1,
                TOKEN,
            ));
        }
    }
    let mut fragments = Vec::new();
    file_fragments(path, &content, &mut fragments);
    if fragments.len() != chunks.len() {
        return Err("planted tokens changed single-line chunk boundaries".into());
    }
    finish_directory_fixture(
        vec![("single.txt".to_owned(), content)],
        fragments,
        findings,
        CompiledConfigKind::Simple,
    )
}

fn many_tiny_fixture() -> Result<DirectoryFixture> {
    let count = 50_000 / SCALE;
    let directories = 250;
    let per_directory = count.div_ceil(directories);
    let mut files = Vec::with_capacity(count);
    let mut fragments = Vec::with_capacity(count);
    let mut findings = Vec::new();
    let mut written = 0;
    for directory in 0..directories {
        for file in 0..per_directory {
            if written == count {
                break;
            }
            let relative = format!("d{directory:03}/f{file:03}.txt");
            let path = format!("input/{relative}");
            let mut content = vec![b'.'; 200];
            content[199] = b'\n';
            if written % 1000 == 0 {
                content[..TOKEN.len()].copy_from_slice(TOKEN);
                findings.push(key(TOKEN_RULE, &path, "", 1, 1, TOKEN));
            }
            file_fragments(&path, &content, &mut fragments);
            files.push((relative, content));
            written += 1;
        }
    }
    finish_directory_fixture(files, fragments, findings, CompiledConfigKind::Simple)
}

const DEEP_LEVELS: usize = 64;

fn deep_tree_fixture() -> Result<DirectoryFixture> {
    let chains = at_least(32 / SCALE, 2);
    let mut files = Vec::new();
    let mut fragments = Vec::new();
    let mut findings = Vec::new();
    for chain in 0..chains {
        for level in (0..=DEEP_LEVELS).rev() {
            let directories = "d/".repeat(level);
            let relative = format!("c{chain:02}/{directories}f.txt");
            let path = format!("input/{relative}");
            let mut content = FILLER.repeat(16);
            if level == DEEP_LEVELS / 2 {
                content[..TOKEN.len()].copy_from_slice(TOKEN);
                findings.push(key(TOKEN_RULE, &path, "", 1, 1, TOKEN));
            }
            file_fragments(&path, &content, &mut fragments);
            files.push((relative, content));
        }
    }
    finish_directory_fixture(files, fragments, findings, CompiledConfigKind::Simple)
}

fn mostly_ignored_fixture() -> Result<DirectoryFixture> {
    let total = 2_000 / SCALE;
    let file_bytes = 8 * KIB;
    let kept = (total / 20).max(4);
    let mut files = Vec::with_capacity(total);
    let mut fragments = Vec::new();
    let mut findings = Vec::new();
    let rows = file_bytes / FILLER.len();
    for index in 0..total {
        let relative = if index < kept {
            format!("app/src/file-{index:04}.txt")
        } else if index % 2 == 0 {
            format!("node_modules/pkg{:02}/file-{index:04}.js", index % 20)
        } else {
            format!(
                "vendor/github.com/org{:02}/repo/file-{index:04}.go",
                index % 20
            )
        };
        let path = format!("input/{relative}");
        let token = github_token(index);
        let token_at = rows / 2;
        let mut content = Vec::with_capacity(file_bytes);
        for row in 0..rows {
            content.extend_from_slice(&if row == token_at {
                token_row(&token)
            } else {
                FILLER.to_vec()
            });
        }
        if index < kept {
            let chunks = expected_chunks(&content);
            let (line, column) = locate(&content, &chunks, token_at * FILLER.len());
            findings.push(key(GITHUB_RULE, &path, "", line, column, &token));
            file_fragments(&path, &content, &mut fragments);
        }
        files.push((relative, content));
    }
    // Lexical traversal visits app/ before node_modules/ and vendor/.
    fragments.sort_by_key(|fragment| fragment.file_path().as_bytes().to_vec());
    finish_directory_fixture(
        files,
        fragments,
        findings,
        CompiledConfigKind::Default { prune_paths: true },
    )
}

/// ELF, zip, and wasm magic are application MIME types and skip the file; PNG
/// and JPEG magic are image types and scan. Each file ends with a token line.
fn binary_mix_fixture() -> Result<DirectoryFixture> {
    let per_kind = at_least(200 / SCALE, 4);
    let mut files = Vec::new();
    let mut fragments = Vec::new();
    let mut findings = Vec::new();
    let mut kinds: Vec<(&str, Vec<u8>, bool)> = vec![
        ("elf", header(b"\x7fELF", 64), false),
        ("zip", header(b"PK\x03\x04", 64), false),
        ("wasm", header(b"\0asm\x01\0\0\0", 64), false),
        ("png", header(b"\x89PNG\r\n\x1a\n", 64), true),
        ("jpeg", header(b"\xff\xd8\xff\xe0", 64), true),
    ];
    kinds.sort_by(|left, right| left.0.cmp(right.0));
    for (kind, magic, scanned) in &kinds {
        for index in 0..per_kind {
            let relative = format!("{kind}-{index:03}.dat");
            let path = format!("input/{relative}");
            let mut content = magic.clone();
            content.push(b'\n');
            let token_offset = content.len();
            content.extend_from_slice(TOKEN);
            content.push(b'\n');
            if *scanned {
                let chunks = expected_chunks(&content);
                let (line, column) = locate(&content, &chunks, token_offset);
                findings.push(key(TOKEN_RULE, &path, "", line, column, TOKEN));
                file_fragments(&path, &content, &mut fragments);
            }
            files.push((relative, content));
        }
    }
    finish_directory_fixture(files, fragments, findings, CompiledConfigKind::Simple)
}

fn header(magic: &[u8], size: usize) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.resize(size, b'.');
    bytes
}

fn skewed_sizes_fixture() -> Result<DirectoryFixture> {
    let big_size = 64 * MIB / SCALE;
    let lines = big_size / FILLER.len();
    let mut big = Vec::with_capacity(big_size);
    let mut token_offsets = Vec::new();
    for index in 0..lines {
        if index % (lines / 16).max(1) == lines / 32 {
            token_offsets.push(big.len());
            big.extend_from_slice(&token_row(TOKEN));
        } else {
            big.extend_from_slice(FILLER);
        }
    }
    let big_chunks = expected_chunks(&big);
    let mut findings: Vec<FindingKey> = token_offsets
        .into_iter()
        .map(|offset| {
            let (line, column) = locate(&big, &big_chunks, offset);
            key(TOKEN_RULE, "input/big.txt", "", line, column, TOKEN)
        })
        .collect();
    let mut fragments = Vec::new();
    file_fragments("input/big.txt", &big, &mut fragments);
    let mut files = vec![("big.txt".to_owned(), big)];
    let small_count = 10_000 / SCALE;
    for directory in 0..small_count.div_ceil(100) {
        for file in 0..100.min(small_count - directory * 100) {
            let relative = format!("small/d{directory:02}/f{file:02}.txt");
            let path = format!("input/{relative}");
            let mut content = vec![b'.'; KIB];
            content[KIB - 1] = b'\n';
            if (directory * 100 + file) % 100 == 0 {
                content[..TOKEN.len()].copy_from_slice(TOKEN);
                findings.push(key(TOKEN_RULE, &path, "", 1, 1, TOKEN));
            }
            file_fragments(&path, &content, &mut fragments);
            files.push((relative, content));
        }
    }
    finish_directory_fixture(files, fragments, findings, CompiledConfigKind::Simple)
}

fn directory_source(fixture: &DirectoryFixture) -> DirectorySource {
    let mut options = DirectoryOptions::default()
        .logical_root("input")
        .emit_limit_issues(true);
    if let Some(config) = &fixture.path_config {
        options = options.path_config(Arc::clone(config));
    }
    DirectorySource::with_options(fixture.scratch.0.join("input"), options)
}

#[allow(
    clippy::too_many_lines,
    reason = "keep phase setup, timers, and verification together"
)]
fn directory_workload(
    fixture: &DirectoryFixture,
    workers: usize,
    iterations: usize,
) -> Result<Vec<Phase>> {
    let config_text;
    let (engine, config_bytes): (Engine, &[u8]) = match fixture.config {
        CompiledConfigKind::Simple => (simple_engine()?, SIMPLE_CONFIG.as_bytes()),
        CompiledConfigKind::Default { .. } => {
            config_text = DEFAULT_CONFIG_BYTES;
            (Engine::builder(default_config()?).build()?, config_text)
        }
    };
    if !engine
        .scan_fragment(
            &Fragment::new(b"warm initialization"),
            &ScanOptions::default(),
        )
        .is_complete()
    {
        return Err("source scale engine warmup did not complete".into());
    }
    let runner = SourceRunner::new(workers, QUEUE_CAPACITY)?;
    let policy = SessionPolicy::default();
    let cancellation = CancellationToken::new();
    let counts = json!({"files": fixture.files, "fragments": fixture.fragments.len(), "input_bytes": fixture.bytes, "workers": workers, "queue_capacity": QUEUE_CAPACITY, "planted_findings": fixture.findings.len(), "filesystem_state": "setup-written-cache-uncontrolled", "returned_result_destruction": "outside-timer", "internal_temporary_destruction": "inside-timer"});

    let mut phases = Vec::new();
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = directory_source(fixture);
        let start = Instant::now();
        let fragments = black_box(collect_fragments(&mut source));
        elapsed += start.elapsed();
        verify_fragments(fragments?, &fixture.fragments, false)?;
    }
    phases.push(row(Row {
        phase: "traversal-and-read",
        iterations,
        elapsed,
        unit: "input-bytes",
        units: fixture.bytes,
        input_fingerprint: &fixture.input_fingerprint,
        config: b"no-scan",
        outcome: fixture.input_fingerprint.as_bytes(),
        findings: 0,
        counts: counts.clone(),
    })?);

    for (name, replay) in [
        ("runner-detection-and-session", true),
        ("traversal-and-detection", false),
    ] {
        let mut elapsed = Duration::ZERO;
        let mut outcome_bytes = Vec::new();
        for _ in 0..iterations {
            let mut replay_source;
            let mut directory;
            let source: &mut dyn Source = if replay {
                replay_source = Replay(&fixture.fragments);
                &mut replay_source
            } else {
                directory = directory_source(fixture);
                &mut directory
            };
            let start = Instant::now();
            let outcome = black_box(runner.run(
                source,
                &engine,
                ScanOptions::default(),
                &policy,
                &cancellation,
            ));
            elapsed += start.elapsed();
            outcome_bytes = verify_outcome(&outcome, fixture.bytes, 0, &fixture.findings)?;
        }
        let mut phase_counts = counts.clone();
        phase_counts["fragment_clone"] = json!(if replay {
            "inside-timer"
        } else {
            "not-applicable"
        });
        phases.push(row(Row {
            phase: name,
            iterations,
            elapsed,
            unit: "input-bytes",
            units: fixture.bytes,
            input_fingerprint: &fixture.input_fingerprint,
            config: config_bytes,
            outcome: &outcome_bytes,
            findings: fixture.findings.len(),
            counts: phase_counts,
        })?);
    }
    Ok(phases)
}

// Git fixtures.

struct GitFile {
    path: String,
    start_line: usize,
    added: Vec<u8>,
}

struct GitCommit {
    time_offset: u64,
    parents: Vec<usize>,
    reference: &'static str,
    message: Vec<u8>,
    commands: Vec<u8>,
    files: Vec<GitFile>,
}

struct GitPlan {
    commits: Vec<GitCommit>,
    log_arguments: &'static [&'static str],
    scope_notes: &'static str,
}

fn push_inline_modify(commands: &mut Vec<u8>, path: &str, content: &[u8]) {
    commands
        .extend_from_slice(format!("M 100644 inline {path}\ndata {}\n", content.len()).as_bytes());
    commands.extend_from_slice(content);
    commands.push(b'\n');
}

fn push_delete(commands: &mut Vec<u8>, path: &str) {
    commands.extend_from_slice(format!("D {path}\n").as_bytes());
}

fn many_tiny_commits_plan() -> GitPlan {
    let count = 20_000 / SCALE;
    let mut commits = Vec::with_capacity(count);
    for index in 0..count {
        let path = format!("tiny/f{:03}.txt", index % 200);
        let added = if index % 100 == 0 {
            format!("{} {index:06}\n", String::from_utf8_lossy(TOKEN))
        } else {
            format!("entry number {index:06}\n")
        };
        let mut commands = Vec::with_capacity(path.len() + added.len() + 32);
        push_inline_modify(&mut commands, &path, added.as_bytes());
        commits.push(GitCommit {
            time_offset: index as u64,
            parents: if index == 0 { vec![] } else { vec![index - 1] },
            reference: "refs/heads/main",
            message: b"tiny".to_vec(),
            commands,
            files: vec![GitFile {
                path,
                start_line: 1,
                added: added.into_bytes(),
            }],
        });
    }
    GitPlan {
        commits,
        log_arguments: &GIT_LOG_NO_RENAMES,
        scope_notes: "one line changed per commit; no renames",
    }
}

fn wide_commit_plan() -> GitPlan {
    let count = 5_000 / SCALE;
    let mut commands = Vec::with_capacity(count * 80);
    let mut files = Vec::with_capacity(count);
    for index in 0..count {
        let path = format!("wide/d{:02}/f{index:04}.txt", index % 64);
        let token = if index % 50 == 0 {
            String::from_utf8_lossy(TOKEN).into_owned()
        } else {
            "ordinary second row".to_owned()
        };
        let content = format!("wide file {index:04}\n{token}\nend of file {index:04}\n");
        push_inline_modify(&mut commands, &path, content.as_bytes());
        files.push(GitFile {
            path,
            start_line: 1,
            added: content.into_bytes(),
        });
    }
    GitPlan {
        commits: vec![GitCommit {
            time_offset: 0,
            parents: vec![],
            reference: "refs/heads/main",
            message: vec![b'm'; 16 * KIB],
            commands,
            files,
        }],
        log_arguments: &GIT_LOG_NO_RENAMES,
        scope_notes: "one commit with a 16 KiB message and one new file per path",
    }
}

const BASE_FILE_LINES: usize = 20;

fn base_file_body(file: usize, edited: Option<(usize, &[u8])>) -> Vec<u8> {
    let mut body = Vec::new();
    for line in 0..BASE_FILE_LINES {
        match edited {
            Some((at, replacement)) if at == line => {
                body.extend_from_slice(replacement);
                body.push(b'\n');
            }
            _ => {
                body.extend_from_slice(format!("unique base row {file:04} {line:04}\n").as_bytes());
            }
        }
    }
    body
}

/// Rename, copy, and side-branch edits that `git log -M -C --find-copies-harder`
/// reports as similarity-index diffs, plus a two-parent merge whose own diff is
/// empty because `git log` omits merge diffs by default.
#[allow(
    clippy::too_many_lines,
    reason = "keep the merge, rename, and copy edit list and expected hunks together"
)]
fn merge_and_rename_plan() -> GitPlan {
    let renames = 50 / SCALE + 2;
    let copies = 30 / SCALE + 2;
    let base_files = at_least(renames + copies, 100 / SCALE + 4);
    let side_files = 1000 / SCALE + 2;
    let mut commits = Vec::new();

    // Commit 0: base tree with unique lines in every file.
    let mut base_commands = Vec::new();
    let mut base_expected = Vec::new();
    for file in 0..base_files {
        let path = format!("a/f{file:04}.txt");
        let body = base_file_body(file, None);
        push_inline_modify(&mut base_commands, &path, &body);
        base_expected.push(GitFile {
            path,
            start_line: 1,
            added: body,
        });
    }
    commits.push(GitCommit {
        time_offset: 0,
        parents: vec![],
        reference: "refs/heads/main",
        message: b"add base tree".to_vec(),
        commands: base_commands,
        files: base_expected,
    });

    // Commit 1: rename the first files and replace one line in each.
    let edit_line = 9_usize;
    let mut rename_commands = Vec::new();
    let mut rename_expected = Vec::new();
    for file in 0..renames {
        let old = format!("a/f{file:04}.txt");
        let new = format!("b/f{file:04}.txt");
        let replacement = format!("renamed row {file:04} {}", String::from_utf8_lossy(TOKEN));
        let body = base_file_body(file, Some((edit_line, replacement.as_bytes())));
        push_delete(&mut rename_commands, &old);
        push_inline_modify(&mut rename_commands, &new, &body);
        rename_expected.push(GitFile {
            path: new,
            start_line: edit_line + 1,
            added: format!("{replacement}\n").into_bytes(),
        });
    }
    commits.push(GitCommit {
        time_offset: 1,
        parents: vec![0],
        reference: "refs/heads/main",
        message: b"rename with edits".to_vec(),
        commands: rename_commands,
        files: rename_expected,
    });

    // Commit 2: copy untouched files to a new directory and edit each copy.
    let mut copy_commands = Vec::new();
    let mut copy_expected = Vec::new();
    for offset in 0..copies {
        let source_file = renames + offset;
        let new = format!("c/f{offset:04}.txt");
        let replacement = format!("copied row {offset:04} {}", String::from_utf8_lossy(TOKEN));
        let body = base_file_body(source_file, Some((4, replacement.as_bytes())));
        push_inline_modify(&mut copy_commands, &new, &body);
        copy_expected.push(GitFile {
            path: new,
            start_line: 5,
            added: format!("{replacement}\n").into_bytes(),
        });
    }
    commits.push(GitCommit {
        time_offset: 2,
        parents: vec![1],
        reference: "refs/heads/main",
        message: b"copy with edits".to_vec(),
        commands: copy_commands,
        files: copy_expected,
    });

    // Commit 3: a large side branch from commit 1 that adds many new files.
    let mut side_commands = Vec::new();
    let mut side_expected = Vec::new();
    for file in 0..side_files {
        let path = format!("feature/f{file:04}.txt");
        let content = format!(
            "feature row {file:05}\n{}\nfeature tail {file:05}\n",
            String::from_utf8_lossy(TOKEN)
        );
        push_inline_modify(&mut side_commands, &path, content.as_bytes());
        side_expected.push(GitFile {
            path,
            start_line: 1,
            added: content.into_bytes(),
        });
    }
    commits.push(GitCommit {
        time_offset: 3,
        parents: vec![1],
        reference: "refs/heads/feature",
        message: b"feature work".to_vec(),
        commands: side_commands,
        files: side_expected,
    });

    // Commit 4: merge the side branch; `git log` shows no diff for the merge.
    let mut merge_commands = Vec::new();
    for file in 0..side_files {
        let path = format!("feature/f{file:04}.txt");
        let content = format!(
            "feature row {file:05}\n{}\nfeature tail {file:05}\n",
            String::from_utf8_lossy(TOKEN)
        );
        push_inline_modify(&mut merge_commands, &path, content.as_bytes());
    }
    commits.push(GitCommit {
        time_offset: 4,
        parents: vec![2, 3],
        reference: "refs/heads/main",
        message: b"merge feature".to_vec(),
        commands: merge_commands,
        files: Vec::new(),
    });
    GitPlan {
        commits,
        log_arguments: &GIT_LOG_WITH_COPIES,
        scope_notes: "renames and copies detected with -M -C --find-copies-harder; merge diffs are omitted by default",
    }
}

fn rfc3339_offset(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let remainder = seconds % 60;
    format!("2000-01-01T{hours:02}:{minutes:02}:{remainder:02}Z")
}

fn fast_import_stream(plan: &GitPlan) -> Vec<u8> {
    let mut stream = Vec::new();
    for (index, commit) in plan.commits.iter().enumerate() {
        let time = GIT_BASE_TIME + commit.time_offset;
        stream.extend_from_slice(
            format!(
                "commit {}\nmark :{}\nauthor {GIT_AUTHOR} <{GIT_EMAIL}> {time} +0000\ncommitter {GIT_AUTHOR} <{GIT_EMAIL}> {time} +0000\ndata {}\n",
                commit.reference,
                index + 1,
                commit.message.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&commit.message);
        stream.push(b'\n');
        if let Some((first, rest)) = commit.parents.split_first() {
            stream.extend_from_slice(format!("from :{}\n", first + 1).as_bytes());
            for parent in rest {
                stream.extend_from_slice(format!("merge :{}\n", parent + 1).as_bytes());
            }
        }
        stream.extend_from_slice(&commit.commands);
        stream.push(b'\n');
    }
    stream.extend_from_slice(b"done\n");
    stream
}

struct GitFixture {
    scratch: Scratch,
    fragments: Vec<Fragment>,
    findings: Vec<FindingKey>,
    bytes: u64,
    unique_commits: usize,
    commits: usize,
    files: usize,
    hunks: usize,
    log_arguments: Vec<std::ffi::OsString>,
    input_fingerprint: String,
    scope_notes: &'static str,
}

#[allow(
    clippy::too_many_lines,
    reason = "one fast-import stream and its generated oracle stay together"
)]
fn import_plan(plan: &GitPlan) -> Result<GitFixture> {
    let executable = representative_io::executable("RUSTLEAKS_PERF_GIT")?;
    let scratch = Scratch::new()?;
    let repository = scratch.0.join("repo");
    let mut init = representative_io::command(&executable, &scratch.0);
    init.arg("init")
        .arg("--quiet")
        .arg("--initial-branch=main")
        .arg("--object-format=sha1")
        .arg("--template")
        .arg(scratch.0.join("empty"))
        .arg(&repository);
    if !representative_io::output(init, None)?.status.success() {
        return Err("synthetic Git init failed".into());
    }
    let stream = fast_import_stream(plan);
    let marks_path = scratch.0.join("marks");
    let mut import = representative_io::command(&executable, &scratch.0);
    import
        .arg("-C")
        .arg(&repository)
        .arg("fast-import")
        .arg("--quiet")
        .arg("--done")
        .arg(format!("--export-marks={}", marks_path.display()));
    let imported = representative_io::output(import, Some(&stream))?;
    if !imported.status.success() {
        return Err(format!(
            "synthetic Git import failed: {}",
            String::from_utf8_lossy(&imported.stderr)
        )
        .into());
    }
    let marks = fs::read_to_string(marks_path)?;
    let mut shas = vec![String::new(); plan.commits.len()];
    for line in marks.lines() {
        let (mark, sha) = line
            .strip_prefix(':')
            .and_then(|rest| rest.split_once(' '))
            .ok_or("malformed Git marks line")?;
        let mark: usize = mark.parse()?;
        sha.clone_into(&mut shas[mark - 1]);
    }
    let mut fragments = Vec::new();
    let mut findings = Vec::new();
    let mut files = 0_usize;
    let mut unique_commits = 0_usize;
    for (commit, sha) in plan.commits.iter().zip(&shas) {
        if !commit.files.is_empty() {
            unique_commits += 1;
        }
        let metadata = CommitMetadata::builder()
            .sha(sha.clone())
            .author_name(GIT_AUTHOR)
            .author_email(GIT_EMAIL)
            .date(rfc3339_offset(commit.time_offset))
            .message(commit.message.clone())
            .build();
        for file in &commit.files {
            files += 1;
            fragments.push(
                Fragment::builder(file.added.clone())
                    .file_path(file.path.clone())
                    .commit(sha.clone())
                    .start_line(file.start_line)
                    .commit_metadata(metadata.clone())
                    .build(),
            );
            let mut line_start = 0_usize;
            for (line, text) in file
                .added
                .split_inclusive(|byte| *byte == b'\n')
                .enumerate()
            {
                if let Some(at) = text.windows(TOKEN.len()).position(|window| window == TOKEN) {
                    let offset = line_start + at;
                    findings.push(key(
                        TOKEN_RULE,
                        &file.path,
                        sha,
                        file.start_line + line,
                        fragment_column(&file.added[..offset], offset),
                        TOKEN,
                    ));
                }
                line_start += text.len();
            }
        }
    }
    fragments.sort_by_key(fragment_sort_key);
    findings.sort();
    let bytes = fragments
        .iter()
        .map(|fragment| fragment.content().len() as u64)
        .sum();
    Ok(GitFixture {
        input_fingerprint: fingerprint(&stream),
        scratch,
        fragments,
        findings,
        bytes,
        unique_commits,
        commits: plan.commits.len(),
        files,
        hunks: files,
        log_arguments: plan
            .log_arguments
            .iter()
            .map(std::ffi::OsString::from)
            .collect(),
        scope_notes: plan.scope_notes,
    })
}

fn git_source(fixture: &GitFixture) -> Result<GitSource> {
    representative_io::reject_ambient_git_state()?;
    Ok(GitSource::new(fixture.scratch.0.join("repo"))
        .executable(representative_io::executable("RUSTLEAKS_PERF_GIT")?.into_os_string())
        .mode(GitMode::LogArguments(fixture.log_arguments.clone()))
        .command_environment(representative_io::git_environment(&fixture.scratch.0)))
}

fn git_workload(plan: &GitPlan, iterations: usize) -> Result<Vec<Phase>> {
    let fixture = import_plan(plan)?;
    let engine = simple_engine()?;
    let counts = json!({"commits": fixture.commits, "commits_with_fragments": fixture.unique_commits, "files": fixture.files, "hunks": fixture.hunks, "workers": 1, "queue_capacity": QUEUE_CAPACITY, "input_bytes": fixture.bytes, "scope": fixture.scope_notes, "filesystem_state": "setup-written-cache-uncontrolled", "git_limits": "source-default-v1"});
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = git_source(&fixture)?;
        let start = Instant::now();
        let fragments = black_box(collect_fragments(&mut source));
        elapsed += start.elapsed();
        verify_fragments(fragments?, &fixture.fragments, true)?;
    }
    let mut phases = vec![row(Row {
        phase: "git-history-and-parse",
        iterations,
        elapsed,
        unit: "input-bytes",
        units: fixture.bytes,
        input_fingerprint: &fixture.input_fingerprint,
        config: b"no-scan",
        outcome: fixture.input_fingerprint.as_bytes(),
        findings: 0,
        counts: counts.clone(),
    })?];
    let runner = SourceRunner::new(1, QUEUE_CAPACITY)?;
    let policy = SessionPolicy::default();
    let cancellation = CancellationToken::new();
    let mut elapsed = Duration::ZERO;
    let mut outcome_bytes = Vec::new();
    for _ in 0..iterations {
        let mut source = git_source(&fixture)?;
        let start = Instant::now();
        let outcome = black_box(runner.run(
            &mut source,
            &engine,
            ScanOptions::default(),
            &policy,
            &cancellation,
        ));
        elapsed += start.elapsed();
        outcome_bytes = verify_outcome(
            &outcome,
            fixture.bytes,
            fixture.unique_commits,
            &fixture.findings,
        )?;
    }
    phases.push(row(Row {
        phase: "git-history-and-detection",
        iterations,
        elapsed,
        unit: "input-bytes",
        units: fixture.bytes,
        input_fingerprint: &fixture.input_fingerprint,
        config: SIMPLE_CONFIG.as_bytes(),
        outcome: &outcome_bytes,
        findings: fixture.findings.len(),
        counts,
    })?);
    Ok(phases)
}

// CLI workloads.

fn parse_report(stdout: &[u8]) -> Result<Vec<Value>> {
    let value: Value = serde_json::from_slice(stdout)?;
    Ok(value
        .as_array()
        .ok_or("CLI JSON report is not an array")?
        .clone())
}

fn report_keys(report: &[Value]) -> Result<Vec<FindingKey>> {
    let mut keys = Vec::with_capacity(report.len());
    for finding in report {
        let field = |name: &str| -> Result<&str> {
            finding[name]
                .as_str()
                .ok_or_else(|| format!("CLI JSON finding omits {name}").into())
        };
        keys.push(key(
            field("RuleID")?,
            field("File")?,
            field("Commit")?,
            usize::try_from(finding["StartLine"].as_u64().ok_or("missing StartLine")?)?,
            usize::try_from(
                finding["StartColumn"]
                    .as_u64()
                    .ok_or("missing StartColumn")?,
            )?,
            field("Secret")?.as_bytes(),
        ));
    }
    keys.sort();
    Ok(keys)
}

/// Exact diagnostics produced for files over `--max-target-megabytes`.
fn cli_many_issues(iterations: usize) -> Result<Vec<Phase>> {
    let cli = representative_io::executable("RUSTLEAKS_PERF_CLI")?;
    let scratch = Scratch::new()?;
    let input = scratch.0.join("input");
    fs::create_dir(&input)?;
    fs::write(scratch.0.join("config.toml"), SIMPLE_CONFIG)?;
    let files = 10_000 / SCALE;
    let oversized = 1_000_001_u64;
    let mut expected_lines = Vec::with_capacity(files);
    for index in 0..files {
        let name = format!("big-{index:05}.bin");
        File::create(input.join(&name))?.set_len(oversized)?;
        expected_lines.push(format!(
            "warn source Limit/Limit {}: skipping file: exceeds maximum file size",
            Path::new("input").join(&name).display()
        ));
    }
    let expected_stderr = expected_lines.join("\n");
    let mut elapsed = Duration::ZERO;
    let mut report = Vec::new();
    for _ in 0..iterations {
        let mut invocation = representative_io::command(&cli, &scratch.0);
        invocation.args([
            "dir",
            "input",
            "--config",
            "config.toml",
            "--no-banner",
            "--no-color",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--exit-code",
            "7",
            "--max-target-megabytes",
            "1",
        ]);
        let start = Instant::now();
        let result = black_box(representative_io::output(invocation, None));
        elapsed += start.elapsed();
        let result = result?;
        if result.status.code() != Some(0) || !parse_report(&result.stdout)?.is_empty() {
            return Err("CLI size-limit scan reported findings or failed".into());
        }
        let stderr = String::from_utf8(result.stderr)?;
        let mut lines = stderr.lines().collect::<Vec<_>>();
        let Some(("info no leaks found", scanned_line)) = lines.pop().zip(lines.pop()) else {
            return Err("CLI size-limit diagnostics omit the summary".into());
        };
        if !scanned_line.starts_with("info scanned ~0 bytes (0) in ")
            || lines.join("\n") != expected_stderr
        {
            return Err("CLI size-limit diagnostics differ from the generator manifest".into());
        }
        report = expected_stderr.clone().into_bytes();
    }
    let input_fingerprint = fingerprint(format!("cli-many-issues-v1;files={files}").as_bytes());
    Ok(vec![row(Row {
        phase: "cold-cli-startup-config-scan-report",
        iterations,
        elapsed,
        unit: "files",
        units: files as u64,
        input_fingerprint: &input_fingerprint,
        config: SIMPLE_CONFIG.as_bytes(),
        outcome: &report,
        findings: 0,
        counts: json!({"files": files, "file_bytes_sparse": oversized, "stderr_lines": files + 2, "limit": "--max-target-megabytes=1", "process_state": "fresh-child-per-iteration", "filesystem_state": "setup-written-cache-uncontrolled"}),
    })?])
}

/// Paragraphs of filler separated by blank lines, with a token alone on its own
/// line in every paragraph, so no fragment boundary can split a token.
fn stdin_chunked_input() -> (Vec<u8>, Vec<FindingKey>) {
    let target = 2 * MIB / SCALE;
    let mut input = Vec::with_capacity(target);
    let mut findings = Vec::new();
    let mut line = 1_usize;
    while input.len() < target {
        // The token is never the first line of a paragraph, and every fragment
        // starts at a paragraph, so its column cannot depend on fragmentation.
        input.extend_from_slice(FILLER);
        findings.push(key(TOKEN_RULE, "", "", line + 1, 2, TOKEN));
        input.extend_from_slice(TOKEN);
        input.push(b'\n');
        for _ in 0..16 {
            input.extend_from_slice(FILLER);
        }
        input.push(b'\n');
        line += 19;
    }
    findings.sort();
    (input, findings)
}

fn output_chunked(mut command: Command, input: &[u8], write_size: usize) -> Result<Output> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or("child stdin missing")?;
    for chunk in input.chunks(write_size) {
        stdin.write_all(chunk)?;
    }
    drop(stdin);
    Ok(child.wait_with_output()?)
}

fn cli_stdin_chunked(iterations: usize) -> Result<Vec<Phase>> {
    let cli = representative_io::executable("RUSTLEAKS_PERF_CLI")?;
    let scratch = Scratch::new()?;
    fs::write(scratch.0.join("config.toml"), SIMPLE_CONFIG)?;
    let (input, expected) = stdin_chunked_input();
    let input_fingerprint = fingerprint(&input);
    let mut phases = Vec::new();
    for (phase, write_size) in [
        ("cold-stdin-one-write", input.len()),
        ("cold-stdin-4-kib-writes", 4 * KIB),
    ] {
        let mut elapsed = Duration::ZERO;
        let mut outcome = Vec::new();
        for _ in 0..iterations {
            let mut invocation = representative_io::command(&cli, &scratch.0);
            invocation.args([
                "stdin",
                "--config",
                "config.toml",
                "--no-banner",
                "--no-color",
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--exit-code",
                "7",
            ]);
            let start = Instant::now();
            let result = black_box(output_chunked(invocation, &input, write_size));
            elapsed += start.elapsed();
            let result = result?;
            if result.status.code() != Some(7) {
                return Err("CLI stdin scan did not report the planted findings".into());
            }
            let keys = report_keys(&parse_report(&result.stdout)?)?;
            if keys != expected {
                return Err(format!(
                    "CLI stdin findings differ with write size {write_size}: expected {}, observed {}",
                    expected.len(),
                    keys.len()
                )
                .into());
            }
            let stderr = String::from_utf8(result.stderr)?;
            if !stderr.contains(&format!("scanned ~{} bytes (", input.len()))
                || !stderr.contains(&format!("warn leaks found: {}", expected.len()))
            {
                return Err("CLI stdin diagnostics differ from the generator manifest".into());
            }
            outcome = serde_json::to_vec(&keys)?;
        }
        phases.push(row(Row {
            phase,
            iterations,
            elapsed,
            unit: "input-bytes",
            units: input.len() as u64,
            input_fingerprint: &input_fingerprint,
            config: SIMPLE_CONFIG.as_bytes(),
            outcome: &outcome,
            findings: expected.len(),
            counts: json!({"write_size": write_size, "input_bytes": input.len(), "process_state": "fresh-child-per-iteration"}),
        })?);
    }
    Ok(phases)
}

fn cli_enable_rule_startup(iterations: usize) -> Result<Vec<Phase>> {
    let cli = representative_io::executable("RUSTLEAKS_PERF_CLI")?;
    let scratch = Scratch::new()?;
    let input_fingerprint = fingerprint(b"empty-stdin");
    let mut phases = Vec::new();
    for (phase, rule_arguments, expected_info) in [
        ("cold-default-config-empty-stdin", &[][..], None),
        (
            "cold-enable-rule-empty-stdin",
            &["--enable-rule", "github-pat"][..],
            Some("info overriding enabled rules: github-pat"),
        ),
    ] {
        let mut elapsed = Duration::ZERO;
        for _ in 0..iterations {
            let mut invocation = representative_io::command(&cli, &scratch.0);
            invocation.args([
                "stdin",
                "--no-banner",
                "--no-color",
                "--report-format",
                "json",
                "--report-path",
                "-",
            ]);
            invocation.args(rule_arguments);
            let start = Instant::now();
            let result = black_box(representative_io::output(invocation, Some(b"")));
            elapsed += start.elapsed();
            let result = result?;
            if result.status.code() != Some(0) || !parse_report(&result.stdout)?.is_empty() {
                return Err("CLI startup scan was not empty and successful".into());
            }
            let stderr = String::from_utf8(result.stderr)?;
            let expected_prefix =
                expected_info.is_none_or(|line| stderr.lines().next() == Some(line));
            if !expected_prefix || !stderr.contains("scanned ~0 bytes (0)") {
                return Err("CLI startup diagnostics differ from the expected shape".into());
            }
        }
        phases.push(row(Row {
            phase,
            iterations,
            elapsed,
            unit: "processes",
            units: 1,
            input_fingerprint: &input_fingerprint,
            config: DEFAULT_CONFIG_BYTES,
            outcome: rule_arguments.join(" ").as_bytes(),
            findings: 0,
            counts: json!({"enable_rule": !rule_arguments.is_empty(), "process_state": "fresh-child-per-iteration"}),
        })?);
    }
    Ok(phases)
}

// Archive-driver bridge for workloads that require the archive feature.

fn archive_driver(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    let mut invocation = Command::new(representative_io::executable(
        "RUSTLEAKS_PERF_ARCHIVE_DRIVER",
    )?);
    invocation
        .args([
            "--exact",
            "representative_archive_scale_driver",
            "--ignored",
            "--nocapture",
        ])
        .env("RUSTLEAKS_PERF_ITERATIONS", iterations.to_string())
        .env("RUSTLEAKS_PERF_ARCHIVE_SCALE_WORKLOAD", id);
    let result = representative_io::output(invocation, None)?;
    if !result.status.success() {
        return Err(format!(
            "archive scale driver failed for {id}: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    let mut phases: Vec<Phase> = Vec::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        if let Some(json) = line.strip_prefix("RUSTLEAKS_PERF_ARCHIVE_PHASE=") {
            phases.push(serde_json::from_str(json)?);
        }
    }
    if phases.is_empty() {
        return Err(format!("archive scale driver produced no phases for {id}").into());
    }
    for phase in &phases {
        if !phase.complete || phase.errors != 0 || phase.iterations != iterations {
            return Err(
                format!("archive scale driver returned an incomplete phase for {id}").into(),
            );
        }
    }
    Ok(phases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustleaks_sources::{FileOptions, FileSource};

    fn real_chunks(content: &[u8]) -> Vec<(usize, usize, usize)> {
        let mut source = FileSource::with_options(
            std::io::Cursor::new(content.to_vec()),
            "input",
            FileOptions::new(NOMINAL_BYTES).expect("positive"),
        );
        let fragments = collect_fragments(&mut source).expect("file fragments");
        let mut offset = 0;
        fragments
            .iter()
            .map(|fragment| {
                let start = offset;
                offset += fragment.content().len();
                (start, offset, fragment.start_line())
            })
            .collect()
    }

    fn modeled_chunks(content: &[u8]) -> Vec<(usize, usize, usize)> {
        expected_chunks(content)
            .into_iter()
            .map(|chunk| (chunk.start, chunk.end, chunk.start_line))
            .collect()
    }

    #[test]
    fn chunk_model_matches_file_source_on_representative_shapes() {
        let mut no_blank_lines = Vec::new();
        for index in 0..4000 {
            no_blank_lines.extend_from_slice(format!("row {index:06} filler words\n").as_bytes());
        }
        let mut with_blank_lines = Vec::new();
        for index in 0..4000 {
            with_blank_lines.extend_from_slice(FILLER);
            if index % 11 == 10 {
                with_blank_lines.push(b'\n');
            }
        }
        for content in [
            vec![b'x'; 300_000],
            vec![b'x'; 125_001],
            vec![b'x'; 124_999],
            vec![b'x'; 100_000],
            vec![b'x'; 28_672],
            no_blank_lines,
            with_blank_lines,
            b"short\n".to_vec(),
        ] {
            assert_eq!(
                modeled_chunks(&content),
                real_chunks(&content),
                "chunk model disagrees for a {}-byte shape",
                content.len()
            );
        }
    }

    #[test]
    fn single_line_chunks_follow_the_documented_read_ahead_sizes() {
        let chunks = expected_chunks(&vec![b'x'; 400_000]);
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.end - chunk.start)
                .collect::<Vec<_>>(),
            // 400,000 - 125,000 - 9 * 28,672 = 16,952 bytes remain for the last read.
            vec![
                125_000, 28_672, 28_672, 28_672, 28_672, 28_672, 28_672, 28_672, 28_672, 28_672,
                16_952
            ]
        );
        assert!(chunks.iter().all(|chunk| chunk.start_line == 1));
    }

    #[test]
    fn workload_list_contains_each_required_shape_exactly_once() {
        assert_eq!(WORKLOADS.len(), 26);
        let mut unique = WORKLOADS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), WORKLOADS.len());
    }

    #[test]
    fn fixtures_have_exact_generator_outcomes_at_test_scale() {
        for id in [
            "source-default-config-4-workers",
            "source-blank-lines-12-mib",
            "source-no-blank-lines-12-mib",
            "source-single-line-64-mib",
            "source-many-tiny-50000",
            "source-deep-tree",
            "source-mostly-ignored",
            "source-binary-mix",
            "source-skewed-sizes",
            "git-many-tiny-commits",
            "git-wide-commit",
            "git-merge-and-rename",
            "cli-many-issues",
            "cli-stdin-chunked",
            "cli-enable-rule-startup",
        ] {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            assert!(!phases.is_empty(), "{id} returned no phases");
            assert!(
                phases
                    .iter()
                    .all(|phase| phase.complete && phase.errors == 0)
            );
        }
    }
}
