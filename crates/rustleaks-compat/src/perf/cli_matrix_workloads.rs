//! CLI end-to-end workloads over one generated repository, scanned as a folder
//! and as Git history.
//!
//! The repository holds plain source files with planted GitHub tokens, one
//! database URI for the connections pack, Base64 values encoded once and six
//! times, and a TAR file nested two levels deep. Each phase starts a fresh CLI
//! process with fixed flags. The expected findings for each flag set come from
//! the plant list: a plant is found when its decode depth, archive depth and
//! pack fit the flags. Nothing is read back from an earlier scan.

use std::fmt::Write as _;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::source_scale_workloads::{
    GITHUB_RULE, GitCommit, GitPlan, Row, Scratch, import_commits, push_inline_modify, row,
    token_row,
};
use super::suite_support::{
    DATABASE_URI_RULE, Lcg, PACKS, Result, checked_github_token, database_uri, go_entropy,
    keyword_census, pack_config, prose_line, prose_line_of, tar,
};
use super::{Phase, fingerprint};
use crate::representative_io;

pub(super) const WORKLOADS: &[&str] = &[
    "cli-matrix-startup-packs",
    "cli-matrix-dir-decode-depth",
    "cli-matrix-git-decode-depth",
    "cli-matrix-dir-archive-depth",
    "cli-matrix-git-archive-depth",
    "cli-matrix-dir-report",
    "cli-matrix-git-report",
    "cli-matrix-dir-packs-profile",
    "cli-matrix-git-packs-profile",
    "cli-matrix-dir-workers",
    "cli-matrix-git-workers",
    "cli-matrix-dir-size-series",
    "cli-matrix-dir-ignore-baseline",
];

const KIB: usize = 1024;
/// Unit tests run the same generators over a smaller repository.
const SCALE: usize = if cfg!(test) { 64 } else { 1 };
const SOURCE_FILES: usize = if 256 / SCALE < 4 { 4 } else { 256 / SCALE };
const SOURCE_FILE_BYTES: usize = 16 * KIB;
const ONCE_ENCODED: usize = 8;
const SIX_ENCODED: usize = 4;
const SERIES_MIB: &[usize] = &[0, 1, 16, 128];
const SERIES_FILE_BYTES: usize = 64 * KIB / SCALE;
const UNRELATED_ENTRIES: usize = 10_000;
const LOG_ARGUMENTS: &str = "--all --full-history --no-ext-diff --no-textconv --no-renames";
/// The example profile from the complete scanning guide with a placeholder for
/// the worker count.
const PROFILE: &str = "version=1\ntarget_bytes=8388608\noperation_original_bytes=268435456\noperation_fragments=200000\noperation_issues=1024\nworkers=WORKERS\nqueue_capacity=8\nfragment_decoded_bytes=33554432\noperation_decoded_bytes=134217728\nfragment_work_units=10000000\noperation_work_units=100000000\nfragment_finding_records=100000\noperation_finding_records=200000\nfragment_finding_payload_bytes=33554432\noperation_finding_payload_bytes=67108864\nfragment_collected_spans=500000\noperation_collected_spans=2000000\nfragment_normalization_bytes=268435456\noperation_normalization_bytes=536870912\narchive_entries=10000\narchive_member_bytes=8388608\narchive_total_bytes=33554432\narchive_spool_bytes=8388608\ngit_patch_bytes=33554432\ngit_patch_lines=500000\ngit_stderr_bytes=1048576\ngit_blob_bytes=8388608\ngit_metadata_bytes=1048576\ngit_path_bytes=65536\ngit_files=100000\ngit_hunks=200000\nscm_link_bytes=4194304\noperation_scm_link_bytes=33554432\n";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Dir,
    Git,
    Stdin,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Dir => "dir",
            Self::Git => "git",
            Self::Stdin => "stdin",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Report {
    Stdout,
    File,
    None,
}

/// One CLI flag set.
#[derive(Clone, Copy)]
struct Flags {
    mode: Mode,
    decode: usize,
    archive: usize,
    packs: bool,
    workers: Option<usize>,
    report: Report,
}

impl Flags {
    const fn new(mode: Mode) -> Self {
        Self {
            mode,
            decode: 0,
            archive: 0,
            packs: false,
            workers: None,
            report: Report::Stdout,
        }
    }
}

/// A planted value and the conditions under which a scan reports it.
#[derive(Clone)]
struct Plant {
    rule: &'static str,
    path: String,
    line: usize,
    column: usize,
    secret: Vec<u8>,
    decode_depth: usize,
    archive_depth: usize,
    pack: bool,
    commit: usize,
}

/// The fields compared for every finding, including the decode depth tag.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Expected {
    rule: String,
    file: String,
    commit: String,
    line: usize,
    column: usize,
    secret: Vec<u8>,
    decode_depth: usize,
}

struct Repository {
    scratch: Scratch,
    plants: Vec<Plant>,
    shas: Vec<String>,
    text_bytes: u64,
    leaf_bytes: u64,
    files: usize,
    input_fingerprint: String,
}

impl Repository {
    fn expected(&self, flags: Flags) -> Vec<Expected> {
        let mut expected = self
            .plants
            .iter()
            .filter(|plant| {
                plant.decode_depth <= flags.decode
                    && plant.archive_depth <= flags.archive
                    && (flags.packs || !plant.pack)
            })
            .map(|plant| Expected {
                rule: plant.rule.into(),
                file: if flags.mode == Mode::Dir {
                    format!("repo/{}", plant.path)
                } else {
                    plant.path.clone()
                },
                commit: if flags.mode == Mode::Git {
                    self.shas[plant.commit].clone()
                } else {
                    String::new()
                },
                line: plant.line,
                column: plant.column,
                secret: plant.secret.clone(),
                decode_depth: plant.decode_depth,
            })
            .collect::<Vec<_>>();
        expected.sort();
        expected
    }

    /// Text bytes, plus the archive leaf once the nested archive is opened.
    const fn scanned_bytes(&self, flags: Flags) -> u64 {
        if flags.archive >= 2 {
            self.text_bytes + self.leaf_bytes
        } else {
            self.text_bytes
        }
    }

    /// Commits whose hunks or archive leaves produce at least one fragment.
    const fn commits(flags: Flags) -> usize {
        if flags.archive >= 2 { 3 } else { 2 }
    }
}

/// Lines of filler of exactly `size` bytes, ending in a newline.
fn prose_block(rng: &mut Lcg, size: usize) -> Vec<u8> {
    let mut block = Vec::with_capacity(size);
    while block.len() + 64 < size {
        block.extend_from_slice(&prose_line(rng));
    }
    match size - block.len() {
        0 => {}
        1 => block.push(b'\n'),
        rest => block.extend_from_slice(&prose_line_of(rng, rest)),
    }
    block
}

#[allow(
    clippy::naive_bytecount,
    reason = "bounded fixture oracle outside timers"
)]
fn line_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

/// Line and column of a plant at the start of a line after `before`.
fn line_start(before: &[u8]) -> (usize, usize) {
    let line = line_count(before) + 1;
    (line, if line == 1 { 1 } else { 2 })
}

#[allow(
    clippy::too_many_lines,
    reason = "the repository layout and its plant list stay together"
)]
fn repository() -> Result<Repository> {
    let (census_config, _, _) = pack_config(&PACKS.iter().map(|(id, _)| *id).collect::<Vec<_>>())?;
    let mut rng = Lcg::new(0x636c_6900);
    let mut plants = Vec::new();
    let mut filler = Vec::new();
    let mut source_commands = Vec::new();
    let mut files = Vec::new();
    for index in 0..SOURCE_FILES {
        let path = format!("src/mod-{index:03}.txt");
        let token = checked_github_token(20_000 + index)?;
        let before = prose_block(&mut rng, 512 + (index * 977) % (8 * KIB));
        let mut content = before.clone();
        let (line, column) = line_start(&content);
        plants.push(plant(GITHUB_RULE, &path, line, column, &token, 0));
        content.extend_from_slice(&token_row(&token));
        if index == 0 {
            let (uri, password) = database_uri(0);
            let (line, column) = line_start(&content);
            let mut uri_plant = plant(DATABASE_URI_RULE, &path, line, column, &password, 0);
            uri_plant.pack = true;
            plants.push(uri_plant);
            content.extend_from_slice(&uri);
            content.push(b'\n');
        }
        let after = prose_block(&mut rng, SOURCE_FILE_BYTES - content.len());
        content.extend_from_slice(&after);
        filler.extend_from_slice(&before);
        filler.extend_from_slice(&after);
        push_inline_modify(&mut source_commands, &path, &content);
        files.push((path, content));
    }
    let mut encoded_commands = Vec::new();
    for (path, levels, count) in [
        ("encoded/once.txt", 1, ONCE_ENCODED),
        ("encoded/six.txt", 6, SIX_ENCODED),
    ] {
        let mut content = Vec::new();
        for index in 0..count {
            let text = prose_line(&mut rng);
            filler.extend_from_slice(&text);
            content.extend_from_slice(&text);
            let token = checked_github_token(30_000 + levels * 100 + index)?;
            let mut value = token.clone();
            for _ in 0..levels {
                value = super::super::base64(&value);
            }
            let (line, column) = line_start(&content);
            plants.push(plant(GITHUB_RULE, path, line, column, &token, levels));
            let last = plants.len() - 1;
            plants[last].commit = 1;
            content.extend_from_slice(&value);
            content.push(b'\n');
        }
        push_inline_modify(&mut encoded_commands, path, &content);
        files.push((path.to_owned(), content));
    }
    // The leaf is two archive levels deep. A folder scan skips ustar data as
    // binary at depth 0, and Git prints it as a binary change.
    let leaf_prose = prose_line(&mut rng);
    filler.extend_from_slice(&leaf_prose);
    let leaf_token = checked_github_token(40_000)?;
    let mut leaf = leaf_prose;
    leaf.extend_from_slice(&leaf_token);
    leaf.push(b'\n');
    let mut leaf_plant = plant(
        GITHUB_RULE,
        "vendor/bundle.tar!inner.tar!config.txt",
        2,
        2,
        &leaf_token,
        0,
    );
    leaf_plant.archive_depth = 2;
    leaf_plant.commit = 2;
    plants.push(leaf_plant);
    let inner = tar(&[("config.txt", &leaf)])?;
    let outer = tar(&[("inner.tar", &inner)])?;
    let mut archive_commands = Vec::new();
    push_inline_modify(&mut archive_commands, "vendor/bundle.tar", &outer);
    keyword_census(&census_config, &filler)?;

    let commit = |time: usize, parents: Vec<usize>, message: &str, commands: Vec<u8>| GitCommit {
        time_offset: time as u64,
        parents,
        reference: "refs/heads/main".into(),
        message: message.as_bytes().to_vec(),
        commands,
        files: Vec::new(),
    };
    let plan = GitPlan {
        commits: vec![
            commit(0, vec![], "add sources", source_commands),
            commit(1, vec![0], "add encoded values", encoded_commands),
            commit(2, vec![1], "add vendor bundle", archive_commands),
        ],
        log_arguments: &[],
        scope_notes: "",
    };
    let (scratch, shas, stream) = import_commits(&plan)?;
    let text_bytes = files.iter().map(|(_, content)| content.len() as u64).sum();
    let root = scratch.0.join("repo");
    for (path, content) in &files {
        let target = root.join(path);
        fs::create_dir_all(target.parent().ok_or("plant path has no parent")?)?;
        fs::write(target, content)?;
    }
    fs::create_dir_all(root.join("vendor"))?;
    fs::write(root.join("vendor/bundle.tar"), &outer)?;
    Ok(Repository {
        scratch,
        plants,
        shas,
        text_bytes,
        leaf_bytes: leaf.len() as u64,
        files: files.len() + 1,
        input_fingerprint: fingerprint(&stream),
    })
}

fn plant(
    rule: &'static str,
    path: &str,
    line: usize,
    column: usize,
    secret: &[u8],
    decode_depth: usize,
) -> Plant {
    Plant {
        rule,
        path: path.to_owned(),
        line,
        column,
        secret: secret.to_vec(),
        decode_depth,
        archive_depth: 0,
        pack: false,
        commit: 0,
    }
}

fn report_rows(report: &[u8]) -> Result<Vec<Expected>> {
    let value: Value = serde_json::from_slice(report)?;
    let mut rows = Vec::new();
    for finding in value.as_array().ok_or("CLI JSON report is not an array")? {
        let text = |name: &str| -> Result<String> {
            Ok(finding[name]
                .as_str()
                .ok_or_else(|| format!("CLI JSON finding omits {name}"))?
                .to_owned())
        };
        let number = |name: &str| -> Result<usize> {
            Ok(usize::try_from(finding[name].as_u64().ok_or_else(
                || format!("CLI JSON finding omits {name}"),
            )?)?)
        };
        let mut decode_depth = 0;
        for tag in finding["Tags"]
            .as_array()
            .ok_or("CLI JSON finding omits Tags")?
        {
            if let Some(depth) = tag
                .as_str()
                .and_then(|tag| tag.strip_prefix("decode-depth:"))
            {
                decode_depth = depth.parse()?;
            }
        }
        rows.push(Expected {
            rule: text("RuleID")?,
            file: text("File")?,
            commit: text("Commit")?,
            line: number("StartLine")?,
            column: number("StartColumn")?,
            secret: text("Secret")?.into_bytes(),
            decode_depth,
        });
    }
    rows.sort();
    Ok(rows)
}

fn compare(actual: &[Expected], expected: &[Expected]) -> Result<()> {
    if actual != expected {
        let index = actual
            .iter()
            .zip(expected)
            .position(|(left, right)| left != right)
            .unwrap_or(actual.len().min(expected.len()));
        let describe = |row: Option<&Expected>| {
            row.map(|row| {
                format!(
                    "{}:{}:{}:{}:{}:depth {}",
                    row.rule,
                    row.file,
                    &row.commit[..row.commit.len().min(8)],
                    row.line,
                    row.column,
                    row.decode_depth
                )
            })
        };
        return Err(format!(
            "CLI findings differ from the plants: expected {}, observed {}; first mismatch {index}: expected {:?}, observed {:?}",
            expected.len(),
            actual.len(),
            describe(expected.get(index)),
            describe(actual.get(index))
        )
        .into());
    }
    Ok(())
}

/// The fixed context of one CLI phase.
struct Run<'a> {
    cli: &'a Path,
    git: &'a Path,
    root: &'a Path,
    target: &'a str,
}

fn invocation(run: &Run<'_>, flags: Flags, extra: &[&str]) -> Command {
    let mut command = representative_io::command(run.cli, run.root);
    command.arg(flags.mode.name());
    if flags.mode != Mode::Stdin {
        command.arg(run.target);
    }
    command.args(["--no-banner", "--no-color"]);
    command.args([
        format!("--max-decode-depth={}", flags.decode),
        format!("--max-archive-depth={}", flags.archive),
    ]);
    if flags.mode == Mode::Git {
        command.args(["--log-opts", LOG_ARGUMENTS]);
        if let Some(parent) = run.git.parent() {
            command.env("PATH", parent);
        }
    }
    if flags.packs {
        for (id, _) in PACKS {
            command.args(["--native-pack", id]);
        }
    }
    if let Some(workers) = flags.workers {
        command.args(["--complete-profile", &format!("profile-w{workers}.limits")]);
    } else {
        // One thread, as before --jobs, so phases do not depend on the
        // number of CPUs of the host.
        command.args(["--jobs", "1"]);
    }
    match flags.report {
        Report::Stdout => {
            command.args(["--report-format", "json", "--report-path", "-"]);
        }
        Report::File => {
            command.args([
                "--report-format",
                "json",
                "--report-path",
                &report_file(flags),
            ]);
        }
        Report::None => {}
    }
    command.args(["--exit-code", "7"]);
    command.args(extra);
    command
}

/// Checks exit status, report and diagnostics against the expected findings.
fn verify(
    run: &Run<'_>,
    flags: Flags,
    output: &std::process::Output,
    expected: &[Expected],
    bytes: u64,
    commits: usize,
) -> Result<Vec<u8>> {
    let exit = if expected.is_empty() { 0 } else { 7 };
    let stderr = String::from_utf8(output.stderr.clone())?;
    if output.status.code() != Some(exit) {
        return Err(format!(
            "CLI exit status {:?}, expected {exit}: {stderr}",
            output.status.code()
        )
        .into());
    }
    let report = match flags.report {
        Report::Stdout => output.stdout.clone(),
        Report::File => fs::read(run.root.join(report_file(flags)))?,
        Report::None => {
            if !output.stdout.is_empty() {
                return Err("CLI wrote a report without a report path".into());
            }
            Vec::new()
        }
    };
    // The outcome identity uses sorted report rows, so it does not depend on
    // the order in which workers finish.
    let mut outcome = Vec::new();
    if flags.report != Report::None {
        let rows = report_rows(&report)?;
        compare(&rows, expected)?;
        outcome = format!("{rows:?}").into_bytes();
    }
    let summary = if expected.is_empty() {
        "info no leaks found".to_owned()
    } else {
        format!("warn leaks found: {}", expected.len())
    };
    let mut lines = stderr.lines().collect::<Vec<_>>();
    if let Some(workers) = flags.workers {
        let status = lines
            .pop()
            .ok_or("CLI omitted the complete-profile status line")?;
        let scope = if flags.mode == Mode::Git {
            "git_additions_and_archive_leaves"
        } else {
            "directory_targets"
        };
        let prefix = format!(
            "rustleaks_scan_status version=1 status=complete reason=complete source_scope={scope} findings={} reports=complete decode_depth={} archive_depth={} resource=none",
            expected.len(),
            flags.decode,
            flags.archive
        );
        if !status.starts_with(&prefix) {
            return Err(
                format!("CLI profile status with {workers} workers differs: {status}").into(),
            );
        }
    }
    if !lines.contains(&summary.as_str())
        || !stderr.contains(&format!("scanned ~{bytes} bytes ("))
        || stderr.contains("partial")
        || lines
            .iter()
            .any(|line| !(line.starts_with("info ") || *line == summary))
    {
        return Err(format!("CLI diagnostics differ from the plants: {stderr}").into());
    }
    if flags.mode == Mode::Git && !stderr.contains(&format!("info {commits} commits scanned.")) {
        return Err("CLI Git commit count differs from the plan".into());
    }
    outcome.extend_from_slice(summary.as_bytes());
    Ok(outcome)
}

/// One report file per mode, so workloads that share a repository never share
/// a report path.
fn report_file(flags: Flags) -> String {
    format!("report-{}.json", flags.mode.name())
}

fn phase_name(flags: Flags, label: &str) -> String {
    format!("cold-{}-{label}", flags.mode.name())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one phase row needs its flags, plants and fixture identity"
)]
fn measure(
    run: &Run<'_>,
    iterations: usize,
    name: &str,
    flags: Flags,
    extra: &[&str],
    expected: &[Expected],
    bytes: u64,
    commits: usize,
    input_fingerprint: &str,
) -> Result<Phase> {
    let mut elapsed = Duration::ZERO;
    let mut outcome = Vec::new();
    for _ in 0..iterations {
        if flags.report == Report::File {
            let _ = fs::remove_file(run.root.join(report_file(flags)));
        }
        let command = invocation(run, flags, extra);
        let start = Instant::now();
        let result = black_box(representative_io::output(
            command,
            (flags.mode == Mode::Stdin).then_some(&b""[..]),
        ));
        elapsed += start.elapsed();
        outcome = verify(run, flags, &result?, expected, bytes, commits)?;
    }
    let report = match flags.report {
        Report::Stdout => "json-stdout",
        Report::File => "json-file",
        Report::None => "none",
    };
    row(Row {
        phase: name,
        iterations,
        elapsed,
        unit: "input-bytes",
        units: bytes,
        input_fingerprint,
        config: if flags.packs {
            b"default-and-all-packs"
        } else {
            b"default"
        },
        outcome: &outcome,
        findings: expected.len(),
        counts: json!({
            "mode": flags.mode.name(), "decode_depth": flags.decode,
            "archive_depth": flags.archive, "packs": flags.packs,
            "complete_profile_workers": flags.workers, "report": report,
            "commits": if flags.mode == Mode::Git { commits } else { 0 },
            "process_state": "fresh-child-per-iteration",
            "filesystem_state": "setup-written-cache-uncontrolled",
        }),
    })
}

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    match id {
        "cli-matrix-startup-packs" | "cli-matrix-dir-size-series" => run_on(id, iterations, None),
        _ if WORKLOADS.contains(&id) => run_on(id, iterations, Some(&prepared_repository()?)),
        _ => Err(format!("unknown CLI matrix workload {id}").into()),
    }
}

/// The generated repository with the complete-profile files beside it.
fn prepared_repository() -> Result<Repository> {
    representative_io::reject_ambient_git_state()?;
    let repository = repository()?;
    for workers in [1, 4, 8] {
        fs::write(
            repository
                .scratch
                .0
                .join(format!("profile-w{workers}.limits")),
            PROFILE.replace("WORKERS", &workers.to_string()),
        )?;
    }
    Ok(repository)
}

/// Runs one workload. Every workload except startup and the size series needs
/// the prepared repository.
fn run_on(id: &str, iterations: usize, repository: Option<&Repository>) -> Result<Vec<Phase>> {
    if !(1..=1_000).contains(&iterations) {
        return Err("CLI matrix iterations outside 1..=1000".into());
    }
    let cli = representative_io::executable("RUSTLEAKS_PERF_CLI")?;
    match id {
        "cli-matrix-startup-packs" => startup(&cli, iterations),
        "cli-matrix-dir-size-series" => size_series(&cli, iterations),
        _ if WORKLOADS.contains(&id) => {
            let repository = repository.ok_or("CLI matrix workload needs the repository")?;
            let git = representative_io::executable("RUSTLEAKS_PERF_GIT")?;
            let run = Run {
                cli: &cli,
                git: &git,
                root: &repository.scratch.0,
                target: "repo",
            };
            matrix(id, iterations, &run, repository)
        }
        _ => Err(format!("unknown CLI matrix workload {id}").into()),
    }
}

fn matrix(
    id: &str,
    iterations: usize,
    run: &Run<'_>,
    repository: &Repository,
) -> Result<Vec<Phase>> {
    let mode = if id.starts_with("cli-matrix-git-") {
        Mode::Git
    } else {
        Mode::Dir
    };
    let base = Flags::new(mode);
    let mut cases: Vec<(String, Flags)> = Vec::new();
    if id.ends_with("-decode-depth") {
        for depth in [0, 5, 8] {
            let flags = Flags {
                decode: depth,
                ..base
            };
            cases.push((phase_name(flags, &format!("decode-depth-{depth}")), flags));
        }
    } else if id.ends_with("-archive-depth") {
        for depth in [0, 8] {
            let flags = Flags {
                archive: depth,
                ..base
            };
            cases.push((phase_name(flags, &format!("archive-depth-{depth}")), flags));
        }
    } else if id.ends_with("-report") {
        // The shipped decode depth is 5; archives stay closed by default.
        for (label, report) in [
            ("no-report", Report::None),
            ("json-report-file", Report::File),
        ] {
            let flags = Flags {
                decode: 5,
                report,
                ..base
            };
            cases.push((phase_name(flags, label), flags));
        }
    } else if id.ends_with("-packs-profile") {
        for packs in [false, true] {
            for workers in [None, Some(1)] {
                let flags = Flags {
                    decode: 5,
                    packs,
                    workers,
                    ..base
                };
                let label = format!(
                    "packs-{}-profile-{}",
                    if packs { "on" } else { "off" },
                    if workers.is_some() { "on" } else { "off" }
                );
                cases.push((phase_name(flags, &label), flags));
            }
        }
    } else if id.ends_with("-workers") {
        for workers in [1, 4, 8] {
            let flags = Flags {
                decode: 5,
                packs: true,
                workers: Some(workers),
                ..base
            };
            cases.push((
                phase_name(flags, &format!("profile-workers-{workers}")),
                flags,
            ));
        }
    } else if id == "cli-matrix-dir-ignore-baseline" {
        return ignore_baseline(iterations, run, repository);
    } else {
        return Err(format!("unknown CLI matrix workload {id}").into());
    }
    cases
        .into_iter()
        .map(|(name, flags)| {
            let mut phase = measure(
                run,
                iterations,
                &name,
                flags,
                &[],
                &repository.expected(flags),
                repository.scanned_bytes(flags),
                Repository::commits(flags),
                &repository.input_fingerprint,
            )?;
            phase.counts["files"] = json!(repository.files);
            Ok(phase)
        })
        .collect()
}

/// Empty standard input with the default rules alone, each pack, and all packs.
fn startup(cli: &Path, iterations: usize) -> Result<Vec<Phase>> {
    let scratch = Scratch::new("scale")?;
    let run = Run {
        cli,
        git: cli,
        root: &scratch.0,
        target: "",
    };
    let mut selections: Vec<(&str, Vec<&str>)> = vec![("none", Vec::new())];
    for (id, _) in PACKS {
        selections.push((
            id.trim_start_matches("rustleaks-").trim_end_matches("-v1"),
            vec![id],
        ));
    }
    selections.push(("all", PACKS.iter().map(|(id, _)| *id).collect()));
    let mut phases = Vec::new();
    for (label, packs) in selections {
        let extra = packs
            .iter()
            .flat_map(|id| ["--native-pack", id])
            .collect::<Vec<_>>();
        phases.push(measure(
            &run,
            iterations,
            &format!("cold-empty-stdin-packs-{label}"),
            Flags::new(Mode::Stdin),
            &extra,
            &[],
            0,
            0,
            &fingerprint(b"empty-stdin"),
        )?);
    }
    Ok(phases)
}

/// Folders of 64 KiB files with one token each, from empty to 128 MiB, so the
/// empty folder gives the fixed cost and the others the cost per byte.
fn size_series(cli: &Path, iterations: usize) -> Result<Vec<Phase>> {
    let (config, _, _) = pack_config(&[])?;
    let scratch = Scratch::new("scale")?;
    let mut rng = Lcg::new(0x7365_7269);
    let mut phases = Vec::new();
    for mib in SERIES_MIB {
        let folder = format!("series-{mib}-mib");
        let root = scratch.0.join(&folder);
        fs::create_dir(&root)?;
        // 16 files per MiB at full size; unit tests write fewer, smaller files.
        let files = if *mib == 0 {
            0
        } else {
            (mib * 16 / SCALE).max(1)
        };
        let mut expected = Vec::with_capacity(files);
        let mut filler = Vec::new();
        for index in 0..files {
            let path = format!("f{index:04}.txt");
            let token = checked_github_token(50_000 + index)?;
            let before = prose_block(&mut rng, 256 + (index * 131) % (SERIES_FILE_BYTES / 2));
            let mut content = before.clone();
            let (line, column) = line_start(&content);
            content.extend_from_slice(&token_row(&token));
            let after = prose_block(&mut rng, SERIES_FILE_BYTES - content.len());
            content.extend_from_slice(&after);
            if index == 0 {
                filler.extend_from_slice(&before);
                filler.extend_from_slice(&after);
            }
            fs::write(root.join(&path), &content)?;
            expected.push(Expected {
                rule: GITHUB_RULE.into(),
                file: format!("{folder}/{path}"),
                commit: String::new(),
                line,
                column,
                secret: token,
                decode_depth: 0,
            });
        }
        keyword_census(&config, &filler)?;
        expected.sort();
        let run = Run {
            cli,
            git: cli,
            root: &scratch.0,
            target: &folder,
        };
        let flags = Flags {
            decode: 5,
            ..Flags::new(Mode::Dir)
        };
        let bytes = (files * SERIES_FILE_BYTES) as u64;
        phases.push(measure(
            &run,
            iterations,
            &format!("cold-dir-{mib}-mib"),
            flags,
            &[],
            &expected,
            bytes,
            0,
            &fingerprint(format!("size-series-v1;files={files};bytes={bytes}").as_bytes()),
        )?);
        fs::remove_dir_all(&root)?;
    }
    Ok(phases)
}

/// No suppression, then an ignore file and a baseline that each hold 10,000
/// unrelated entries and one entry for a planted finding.
fn ignore_baseline(
    iterations: usize,
    run: &Run<'_>,
    repository: &Repository,
) -> Result<Vec<Phase>> {
    let flags = Flags::new(Mode::Dir);
    let all = repository.expected(flags);
    let ignored = all
        .iter()
        .position(|row| row.file == "repo/src/mod-000.txt" && row.rule == GITHUB_RULE)
        .ok_or("ignore plant missing")?;
    let baselined = all
        .iter()
        .position(|row| row.file == "repo/src/mod-001.txt")
        .ok_or("baseline plant missing")?;
    let mut ignore = String::from("# synthetic ignore file\n");
    for index in 0..UNRELATED_ENTRIES {
        writeln!(
            ignore,
            "unrelated/f{index:05}.txt:{GITHUB_RULE}:{}",
            index % 97 + 1
        )?;
    }
    writeln!(
        ignore,
        "{}:{GITHUB_RULE}:{}",
        all[ignored].file, all[ignored].line
    )?;
    fs::write(run.root.join("ignore-10000"), ignore)?;

    let (config, _, _) = pack_config(&[])?;
    let description = config
        .rule(GITHUB_RULE)
        .ok_or("default configuration lacks github-pat")?
        .description()
        .to_owned();
    let entry = |file: &str, row: &Expected| {
        let secret = String::from_utf8_lossy(&row.secret).into_owned();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "reports store entropy as a 32-bit float"
        )]
        let entropy = go_entropy(&row.secret)? as f32;
        Ok::<_, Box<dyn std::error::Error>>(json!({
            "RuleID": row.rule, "Description": description,
            "StartLine": row.line, "EndLine": row.line,
            "StartColumn": row.column, "EndColumn": row.column + row.secret.len() - 1,
            "Match": secret, "Secret": secret, "File": file, "SymlinkFile": "",
            "Commit": "", "Entropy": entropy, "Author": "", "Email": "", "Date": "",
            "Message": "", "Tags": [], "Fingerprint": format!("{file}:{}:{}", row.rule, row.line),
        }))
    };
    let mut baseline = Vec::with_capacity(UNRELATED_ENTRIES + 1);
    for index in 0..UNRELATED_ENTRIES {
        baseline.push(entry(
            &format!("unrelated/f{index:05}.txt"),
            &all[baselined],
        )?);
    }
    baseline.push(entry(&all[baselined].file, &all[baselined])?);
    fs::write(
        run.root.join("baseline-10000.json"),
        serde_json::to_vec(&baseline)?,
    )?;

    let without = |skip: usize| {
        let mut rows = all.clone();
        rows.remove(skip);
        rows
    };
    let bytes = repository.scanned_bytes(flags);
    Ok(vec![
        measure(
            run,
            iterations,
            "cold-dir-no-suppression",
            flags,
            &[],
            &all,
            bytes,
            0,
            &repository.input_fingerprint,
        )?,
        measure(
            run,
            iterations,
            "cold-dir-ignore-10000",
            flags,
            &["--gitleaks-ignore-path", "ignore-10000"],
            &without(ignored),
            bytes,
            0,
            &repository.input_fingerprint,
        )?,
        measure(
            run,
            iterations,
            "cold-dir-baseline-10000",
            flags,
            &["--baseline-path", "baseline-10000.json"],
            &without(baselined),
            bytes,
            0,
            &repository.input_fingerprint,
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// One repository for every test in this module. It is never dropped, so
    /// its folder stays in the test temporary folder after the run.
    fn shared() -> &'static Repository {
        static REPOSITORY: OnceLock<Repository> = OnceLock::new();
        REPOSITORY.get_or_init(|| prepared_repository().expect("CLI matrix repository"))
    }

    fn check(id: &str) {
        let repository = match id {
            "cli-matrix-startup-packs" | "cli-matrix-dir-size-series" => None,
            _ => Some(shared()),
        };
        let phases = run_on(id, 1, repository).unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(!phases.is_empty(), "{id}");
    }

    #[test]
    fn startup_packs_has_exact_outcomes() {
        check("cli-matrix-startup-packs");
    }

    #[test]
    fn dir_decode_depth_has_exact_outcomes() {
        check("cli-matrix-dir-decode-depth");
    }

    #[test]
    fn git_decode_depth_has_exact_outcomes() {
        check("cli-matrix-git-decode-depth");
    }

    #[test]
    fn dir_archive_depth_has_exact_outcomes() {
        check("cli-matrix-dir-archive-depth");
    }

    #[test]
    fn git_archive_depth_has_exact_outcomes() {
        check("cli-matrix-git-archive-depth");
    }

    #[test]
    fn dir_report_has_exact_outcomes() {
        check("cli-matrix-dir-report");
    }

    #[test]
    fn git_report_has_exact_outcomes() {
        check("cli-matrix-git-report");
    }

    #[test]
    fn dir_packs_profile_has_exact_outcomes() {
        check("cli-matrix-dir-packs-profile");
    }

    #[test]
    fn git_packs_profile_has_exact_outcomes() {
        check("cli-matrix-git-packs-profile");
    }

    #[test]
    fn dir_workers_has_exact_outcomes() {
        check("cli-matrix-dir-workers");
    }

    #[test]
    fn git_workers_has_exact_outcomes() {
        check("cli-matrix-git-workers");
    }

    #[test]
    fn dir_size_series_has_exact_outcomes() {
        check("cli-matrix-dir-size-series");
    }

    #[test]
    fn dir_ignore_baseline_has_exact_outcomes() {
        check("cli-matrix-dir-ignore-baseline");
    }

    #[test]
    fn every_workload_has_a_test() {
        assert_eq!(WORKLOADS.len(), 13);
    }

    #[test]
    fn plants_follow_depth_archive_and_pack_flags() {
        let repository = shared();
        let count = |flags| repository.expected(flags).len();
        let base = Flags::new(Mode::Dir);
        let raw = SOURCE_FILES;
        assert_eq!(count(base), raw);
        assert_eq!(count(Flags { decode: 5, ..base }), raw + ONCE_ENCODED);
        assert_eq!(
            count(Flags { decode: 8, ..base }),
            raw + ONCE_ENCODED + SIX_ENCODED
        );
        assert_eq!(count(Flags { archive: 8, ..base }), raw + 1);
        assert_eq!(
            count(Flags {
                packs: true,
                ..base
            }),
            raw + 1
        );
        assert_eq!(repository.files, SOURCE_FILES + 3);
    }
}
