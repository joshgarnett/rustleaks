//! Explicit I/O phases for the opt-in representative performance runner.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{
    ByteRange, CommitMetadata, Finding, FindingRange, Fragment, Location, ScanOptions,
};
use rustleaks_core::session::{SessionPolicy, sort_findings_canonical};
use rustleaks_report::{JsonReporter, Reporter};
use rustleaks_sources::{
    CallbackError, Cancellation, CancellationToken, DirectoryOptions, DirectorySource, GitMode,
    GitSource, Source, SourceControl, SourceError, SourceEvent, SourceOutcome, SourceRunner,
    SourceTermination,
};
use serde_json::{Value, json};

use super::representative::{Phase, fingerprint};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub const WORKLOADS: &[&str] = &[
    "source-many-small-w1",
    "source-many-small-w4",
    "source-few-large-w1",
    "source-few-large-w4",
    "source-skipped-input-control",
    "git-repeated-blobs",
    "cli-startup",
    "cli-dir",
    "cli-stdin",
    "cli-git",
    "archives-all-formats",
];

pub const ARCHIVE_PHASES: &[&str] = &[
    "archive-expand/tar-two-members",
    "archive-expand/zip",
    "archive-expand/7z-stored",
    "archive-expand/rar5-stored",
    "archive-expand/tar-gzip-two-members",
    "archive-expand/gzip",
    "archive-expand/tar-xz-two-members",
    "archive-expand/xz",
    "archive-expand/bzip2",
    "archive-expand/brotli",
    "archive-expand/lz4",
    "archive-expand/snappy",
    "archive-expand/minlz",
    "archive-expand/zstd",
    "archive-expand/zlib",
    "archive-expand/lzip",
    "archive-expand/s2",
    "archive-expand/rar5-compressed",
    "archive-expand/rar2-compressed",
    "archive-expand/rar3-compressed",
    "archive-expand/7z-compressed",
    "archive-expand/gzip-compressed",
    "archive-expand/zlib-compressed",
];

const CONFIG: &str = "[[rules]]\nid = 'perf-token'\ndescription = 'synthetic token'\nregex = 'A{16}'\nkeywords = ['AAAA']\n";
const TOKEN: &[u8] = b"AAAAAAAAAAAAAAAA";
const GIT_COMMITS: usize = 32;
const SCOPE: &str = "representative-v1-operation-only";

pub fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    if !(1..=1_000).contains(&iterations) {
        return Err("representative I/O iterations outside 1..=1000".into());
    }
    match id {
        "source-many-small-w1"
        | "source-many-small-w4"
        | "source-few-large-w1"
        | "source-few-large-w4"
        | "source-skipped-input-control" => directory(id, iterations),
        "git-repeated-blobs" => git(iterations),
        "cli-startup" | "cli-dir" | "cli-stdin" | "cli-git" => cli(id, iterations),
        "archives-all-formats" => archives(iterations),
        _ => Err(format!("unknown representative I/O workload {id}").into()),
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rustleaks-perf-io-{}-{}",
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

struct Fixture {
    scratch: Scratch,
    fragments: Vec<Fragment>,
    input: Vec<u8>,
    commits: usize,
}
impl Fixture {
    fn directory(files: usize, bytes: usize) -> Result<Self> {
        let scratch = Scratch::new()?;
        fs::create_dir(scratch.0.join("input"))?;
        let mut fragments = Vec::new();
        for index in 0..files {
            let mut content = vec![b'x'; bytes];
            if index % 2 == 0 {
                content[..TOKEN.len()].copy_from_slice(TOKEN);
                content[TOKEN.len()] = b'\n';
            }
            content[bytes - 1] = b'\n';
            let name = format!("file-{index:03}.txt");
            fs::write(scratch.0.join("input").join(&name), &content)?;
            let mut builder = Fragment::builder(content)
                .file_path(format!("input/{name}"))
                .start_line(1);
            if cfg!(windows) {
                builder = builder.windows_file_path(format!("input\\{name}"));
            }
            fragments.push(builder.build());
        }
        let input = fragment_bytes(&fragments)?;
        Ok(Self {
            scratch,
            fragments,
            input,
            commits: 0,
        })
    }
    fn bytes(&self) -> u64 {
        self.fragments
            .iter()
            .map(|f| f.content().len() as u64)
            .sum()
    }
    fn source(&self) -> Result<DirectorySource> {
        Ok(DirectorySource::with_options(
            self.scratch.0.join("input"),
            DirectoryOptions::new(2 * 1024 * 1024)?
                .logical_root("input")
                .emit_limit_issues(true),
        ))
    }
    fn expected(&self) -> Result<Vec<Finding>> {
        expected_findings(&self.fragments)
    }
}

fn fragment_bytes(fragments: &[Fragment]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(fragments)?)
}

fn expected_findings(fragments: &[Fragment]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for fragment in fragments {
        if !fragment.content().as_bytes().starts_with(TOKEN) {
            continue;
        }
        let file = fragment.file_path().as_str()?;
        let commit = fragment.commit().as_str()?;
        let fingerprint = if commit.is_empty() {
            format!("{file}:perf-token:1")
        } else {
            format!("{commit}:{file}:perf-token:1")
        };
        let mut builder = Finding::builder()
            .rule_id("perf-token")
            .description("synthetic token")
            .location(Location::new(1, 1, 1, TOKEN.len())?)
            .match_range(FindingRange::Exact(ByteRange::new(0, TOKEN.len())?))
            .secret_range(FindingRange::Exact(ByteRange::new(0, TOKEN.len())?))
            .line(TOKEN)
            .match_text(TOKEN)
            .secret(TOKEN)
            .file(file)
            .commit(commit)
            .entropy(0.0)
            .fingerprint(fingerprint);
        if let Some(metadata) = fragment.commit_metadata() {
            builder = builder
                .author(metadata.author_name().as_bytes())
                .email(metadata.author_email().as_bytes())
                .date(metadata.date().as_bytes())
                .message(metadata.message().as_bytes());
        }
        findings.push(builder.build()?);
    }
    sort_findings_canonical(&mut findings);
    Ok(findings)
}

fn engine() -> Result<Engine> {
    let engine = Engine::builder(ConfigLoader::new().load_toml(CONFIG)?).build()?;
    let first = engine.scan_fragment(
        &Fragment::new(b"warm initialization"),
        &ScanOptions::default(),
    );
    if !first.is_complete() {
        return Err("I/O engine warmup did not complete".into());
    }
    Ok(engine)
}

fn collect(source: &mut dyn Source) -> Result<Vec<Fragment>> {
    let mut fragments = Vec::new();
    let control = source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment {
                fragment,
                issue: None,
            } => fragments.push(*fragment),
            _ => return Err(CallbackError::new("representative traversal issue")),
        }
        Ok(SourceControl::Continue)
    })?;
    if control != SourceControl::Continue {
        return Err("representative traversal stopped".into());
    }
    Ok(fragments)
}

fn verify_fragments(actual: &[Fragment], expected: &[Fragment]) -> Result<()> {
    if actual != expected {
        return Err(
            "representative source fragments differ in bytes, paths, order, or metadata".into(),
        );
    }
    Ok(())
}

fn verify_outcome(
    actual: &SourceOutcome,
    fixture: &Fixture,
    expected: &[Finding],
) -> Result<Vec<u8>> {
    if actual.termination() != &SourceTermination::Completed
        || !actual.issues().is_empty()
        || actual.scanned_bytes() != fixture.bytes()
        || actual.unique_commit_count() != fixture.commits
    {
        return Err("representative source skipped input, stopped, or produced issues".into());
    }
    let mut findings = actual.findings().to_vec();
    sort_findings_canonical(&mut findings);
    if findings != expected {
        return Err("representative source exact findings differ".into());
    }
    let mut report = Vec::new();
    JsonReporter.write(&mut report, &findings)?;
    Ok(report)
}

struct Counted<'a> {
    source: &'a mut dyn Source,
    fragments: usize,
}
impl Source for Counted<'_> {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> std::result::Result<SourceControl, CallbackError>,
    ) -> std::result::Result<SourceControl, SourceError> {
        self.source.visit(cancellation, &mut |event| {
            if matches!(&event, SourceEvent::Fragment { .. }) {
                self.fragments += 1;
            }
            emit(event)
        })
    }
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

fn row(
    phase: &str,
    iterations: usize,
    elapsed: Duration,
    fixture: &Fixture,
    outcome: &[u8],
    findings: usize,
    counts: Value,
) -> Result<Phase> {
    Ok(Phase {
        phase: phase.into(),
        iterations,
        elapsed_ns: u64::try_from(elapsed.as_nanos())?,
        logical_unit: "input-bytes".into(),
        logical_units_per_iteration: fixture.bytes(),
        input_fnv1a64: fingerprint(&fixture.input),
        config_fnv1a64: fingerprint(CONFIG.as_bytes()),
        outcome_fnv1a64: fingerprint(outcome),
        findings: findings as u64,
        errors: 0,
        complete: true,
        counts,
        scope: SCOPE.into(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "keep phase setup, timers, and exact verification together"
)]
fn directory(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    let (files, size) = if id.contains("few-large") {
        (4, 256 * 1024)
    } else {
        (64, 1024)
    };
    let workers = if id.ends_with("w4") { 4 } else { 1 };
    let fixture = Fixture::directory(files, size)?;
    let engine = engine()?;
    let runner = SourceRunner::new(workers, 8)?;
    let policy = SessionPolicy::default();
    let cancellation = CancellationToken::new();
    let expected = fixture.expected()?;
    let counts = json!({"files": files, "fragments": files, "workers": workers, "queue_capacity": 8, "consumed_fragment_accounting": "inside-timer", "input_bytes": fixture.bytes(), "chunk_bytes": 2 * 1024 * 1024, "filesystem_state": "setup-written-cache-uncontrolled", "returned_result_destruction": "outside-timer", "internal_temporary_destruction": "inside-timer"});
    let mut phases = Vec::new();
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = fixture.source()?;
        let start = Instant::now();
        let fragments = black_box(collect(&mut source));
        elapsed += start.elapsed();
        verify_fragments(&fragments?, &fixture.fragments)?;
    }
    phases.push(row(
        "traversal-and-read",
        iterations,
        elapsed,
        &fixture,
        &fixture.input,
        0,
        counts.clone(),
    )?);
    for replay in [true, false] {
        let mut elapsed = Duration::ZERO;
        let mut hash_input = Vec::new();
        for _ in 0..iterations {
            let mut source: Box<dyn Source + '_> = if replay {
                Box::new(Replay(&fixture.fragments))
            } else {
                Box::new(fixture.source()?)
            };
            let mut counted = Counted {
                source: source.as_mut(),
                fragments: 0,
            };
            let start = Instant::now();
            let outcome = black_box(runner.run(
                &mut counted,
                &engine,
                ScanOptions::default(),
                &policy,
                &cancellation,
            ));
            elapsed += start.elapsed();
            if counted.fragments != fixture.fragments.len() {
                return Err("source consumed fragment count differs".into());
            }
            hash_input = verify_outcome(&outcome, &fixture, &expected)?;
        }
        let phase = if replay {
            "runner-detection-and-session"
        } else {
            "traversal-and-detection"
        };
        let mut counts = counts.clone();
        counts["fragment_clone"] = json!(if replay {
            "inside-timer"
        } else {
            "not-applicable"
        });
        phases.push(row(
            phase,
            iterations,
            elapsed,
            &fixture,
            &hash_input,
            expected.len(),
            counts,
        )?);
    }
    if id == "source-skipped-input-control" {
        // The omitted last file is clean: finding equality alone cannot detect it.
        fs::remove_file(
            fixture
                .scratch
                .0
                .join("input")
                .join(format!("file-{:03}.txt", files - 1)),
        )?;
        let outcome = runner.run(
            &mut fixture.source()?,
            &engine,
            ScanOptions::default(),
            &policy,
            &cancellation,
        );
        if outcome.findings().len() != expected.len()
            || verify_outcome(&outcome, &fixture, &expected).is_ok()
        {
            return Err("skipped clean input negative control was not rejected".into());
        }
        for phase in &mut phases {
            phase.counts["skipped_clean_input_rejected"] = json!(true);
        }
    }
    Ok(phases)
}

fn executable(name: &str) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(name) {
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_file() {
            return Err(format!("{name} must name an existing absolute executable").into());
        }
        return Ok(path);
    }
    let runfile = std::env::var_os(format!("{name}_RUNFILE"))
        .ok_or_else(|| format!("missing bound executable {name}"))?;
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            for path in [
                PathBuf::from(&root).join(&runfile),
                PathBuf::from(root).join("_main").join(&runfile),
            ] {
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        for line in fs::read_to_string(manifest)?.lines() {
            if let Some((key, path)) = line.split_once(' ')
                && key == runfile.to_string_lossy()
            {
                return Ok(PathBuf::from(path));
            }
        }
    }
    if cfg!(windows) && runfile == "git" {
        for parent in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let path = parent.join("git.exe");
            if path.is_file() {
                return Ok(fs::canonicalize(path)?);
            }
        }
    }
    Err(format!("cannot resolve {name} runfile").into())
}

fn git_environment(root: &Path) -> Vec<(OsString, OsString)> {
    let text = |s: &str| OsString::from(s);
    vec![
        (text("GIT_CONFIG_NOSYSTEM"), text("1")),
        (
            text("GIT_CONFIG_SYSTEM"),
            root.join("empty-config").into_os_string(),
        ),
        (
            text("GIT_CONFIG_GLOBAL"),
            root.join("empty-config").into_os_string(),
        ),
        (text("GIT_CONFIG_COUNT"), text("3")),
        (text("GIT_CONFIG_KEY_0"), text("core.hooksPath")),
        (
            text("GIT_CONFIG_VALUE_0"),
            root.join("empty").into_os_string(),
        ),
        (text("GIT_CONFIG_KEY_1"), text("core.attributesFile")),
        (
            text("GIT_CONFIG_VALUE_1"),
            root.join("empty-config").into_os_string(),
        ),
        (text("GIT_CONFIG_KEY_2"), text("core.autocrlf")),
        (text("GIT_CONFIG_VALUE_2"), text("false")),
        (text("GIT_TERMINAL_PROMPT"), text("0")),
        (text("GIT_OPTIONAL_LOCKS"), text("0")),
        (text("LC_ALL"), text("C")),
        (text("TZ"), text("UTC")),
    ]
}

fn command(executable: &Path, root: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .current_dir(root)
        .envs(git_environment(root));
    for name in ["SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

fn output(mut command: Command, input: Option<&[u8]>) -> Result<Output> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or("child stdin missing")?
            .write_all(input)?;
    }
    Ok(child.wait_with_output()?)
}

fn setup_git() -> Result<Fixture> {
    let executable = executable("RUSTLEAKS_PERF_GIT")?;
    let scratch = Scratch::new()?;
    let repository = scratch.0.join("repo");
    let mut init = command(&executable, &scratch.0);
    init.arg("init")
        .arg("--quiet")
        .arg("--initial-branch=main")
        .arg("--object-format=sha1")
        .arg("--template")
        .arg(scratch.0.join("empty"))
        .arg(&repository);
    if !output(init, None)?.status.success() {
        return Err("synthetic Git init failed".into());
    }
    let body = [TOKEN, b"\n"].concat();
    let mut stream = format!("blob\nmark :1\ndata {}\n", body.len()).into_bytes();
    stream.extend_from_slice(&body);
    stream.push(b'\n');
    for index in 0..GIT_COMMITS {
        stream.extend_from_slice(format!("commit refs/heads/main\nmark :{}\nauthor Performance Fixture <perf@example.invalid> 946684800 +0000\ncommitter Performance Fixture <perf@example.invalid> 946684800 +0000\ndata 7\nfixture\n", index + 100).as_bytes());
        if index > 0 {
            stream.extend_from_slice(format!("from :{}\n", index + 99).as_bytes());
        }
        stream.extend_from_slice(format!("M 100644 :1 file-{index:03}.txt\n\n").as_bytes());
    }
    stream.extend_from_slice(b"done\n");
    let marks_path = scratch.0.join("marks");
    let mut import = command(&executable, &scratch.0);
    import
        .arg("-C")
        .arg(&repository)
        .arg("fast-import")
        .arg("--quiet")
        .arg("--done")
        .arg(format!("--export-marks={}", marks_path.display()));
    if !output(import, Some(&stream))?.status.success() {
        return Err("synthetic Git import failed".into());
    }
    let marks = fs::read_to_string(marks_path)?;
    let mut fragments = Vec::new();
    for index in (0..GIT_COMMITS).rev() {
        let prefix = format!(":{} ", index + 100);
        let sha = marks
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .ok_or("missing synthetic commit mark")?;
        let metadata = CommitMetadata::builder()
            .sha(sha)
            .author_name("Performance Fixture")
            .author_email("perf@example.invalid")
            .date("2000-01-01T00:00:00Z")
            .message("fixture")
            .build();
        fragments.push(
            Fragment::builder(body.clone())
                .file_path(format!("file-{index:03}.txt"))
                .commit(sha)
                .start_line(1)
                .commit_metadata(metadata)
                .build(),
        );
    }
    Ok(Fixture {
        scratch,
        fragments,
        input: stream,
        commits: GIT_COMMITS,
    })
}

fn git_source(fixture: &Fixture) -> Result<GitSource> {
    // The parent representative runner launches this child with env_clear. Reject
    // accidental direct invocation with Git routing or command injection state.
    for (name, _) in std::env::vars_os() {
        if let Some(name) = name.to_str()
            && name.starts_with("GIT_")
            && !matches!(
                name,
                "GIT_CONFIG_NOSYSTEM"
                    | "GIT_CONFIG_GLOBAL"
                    | "GIT_CONFIG_SYSTEM"
                    | "GIT_TERMINAL_PROMPT"
                    | "GIT_OPTIONAL_LOCKS"
            )
        {
            return Err(
                format!("ambient {name} is not permitted in a representative Git process").into(),
            );
        }
    }
    Ok(GitSource::new(fixture.scratch.0.join("repo"))
        .executable(executable("RUSTLEAKS_PERF_GIT")?.into_os_string())
        .mode(GitMode::LogArguments(
            [
                "--all",
                "--full-history",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
            ]
            .map(OsString::from)
            .to_vec(),
        ))
        .command_environment(git_environment(&fixture.scratch.0)))
}

fn git(iterations: usize) -> Result<Vec<Phase>> {
    let fixture = setup_git()?;
    let engine = engine()?;
    let expected = fixture.expected()?;
    let counts = json!({"commits": GIT_COMMITS, "files": GIT_COMMITS, "hunks": GIT_COMMITS, "unique_blobs": 1, "workers": 1, "queue_capacity": 8, "consumed_fragment_accounting": "inside-timer", "input_bytes": fixture.bytes(), "filesystem_state": "setup-written-cache-uncontrolled", "returned_result_destruction": "outside-timer", "git_limits": "source-default-v1"});
    let mut elapsed = Duration::ZERO;
    for _ in 0..iterations {
        let mut source = git_source(&fixture)?;
        let start = Instant::now();
        let fragments = black_box(collect(&mut source));
        elapsed += start.elapsed();
        verify_fragments(&fragments?, &fixture.fragments)?;
    }
    let mut phases = vec![row(
        "git-history-and-parse",
        iterations,
        elapsed,
        &fixture,
        &fragment_bytes(&fixture.fragments)?,
        0,
        counts.clone(),
    )?];
    let runner = SourceRunner::new(1, 8)?;
    let policy = SessionPolicy::default();
    let cancellation = CancellationToken::new();
    let mut elapsed = Duration::ZERO;
    let mut report = Vec::new();
    for _ in 0..iterations {
        let mut source = git_source(&fixture)?;
        let mut counted = Counted {
            source: &mut source,
            fragments: 0,
        };
        let start = Instant::now();
        let outcome = black_box(runner.run(
            &mut counted,
            &engine,
            ScanOptions::default(),
            &policy,
            &cancellation,
        ));
        elapsed += start.elapsed();
        if counted.fragments != GIT_COMMITS {
            return Err("Git consumed hunk count differs".into());
        }
        report = verify_outcome(&outcome, &fixture, &expected)?;
    }
    phases.push(row(
        "git-history-and-detection",
        iterations,
        elapsed,
        &fixture,
        &report,
        expected.len(),
        counts,
    )?);
    Ok(phases)
}

#[allow(
    clippy::too_many_lines,
    reason = "keep subprocess arguments and exact verification together"
)]
fn cli(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    let executable = executable("RUSTLEAKS_PERF_CLI")?;
    let fixture = if id == "cli-git" {
        setup_git()?
    } else {
        Fixture::directory(8, 1024)?
    };
    fs::write(fixture.scratch.0.join("config.toml"), CONFIG)?;
    let git = if id == "cli-git" {
        Some(self::executable("RUSTLEAKS_PERF_GIT")?)
    } else {
        None
    };
    let stdin_bytes = [TOKEN, b"\n"].concat();
    let stdin_fragment = [Fragment::builder(stdin_bytes.clone()).start_line(1).build()];
    let expected = if id == "cli-stdin" {
        expected_findings(&stdin_fragment)?
    } else {
        fixture.expected()?
    };
    let mut expected_json = Vec::new();
    JsonReporter.write(&mut expected_json, &expected)?;
    let expected_json: Value = serde_json::from_slice(&expected_json)?;
    let bytes = if id == "cli-stdin" {
        stdin_bytes.len() as u64
    } else {
        fixture.bytes()
    };
    let mut elapsed = Duration::ZERO;
    let mut report = Vec::new();
    for _ in 0..iterations {
        let mut invocation = command(&executable, &fixture.scratch.0);
        if id == "cli-startup" {
            invocation.arg("version");
        } else {
            invocation.arg(match id {
                "cli-dir" => "dir",
                "cli-git" => "git",
                _ => "stdin",
            });
            if id == "cli-dir" {
                invocation.arg("input");
            }
            if id == "cli-git" {
                invocation.arg("repo").args([
                    "--log-opts",
                    "--all --full-history --no-ext-diff --no-textconv --no-renames",
                ]);
                let git = git.as_ref().ok_or("missing CLI Git executable")?;
                invocation.env("PATH", git.parent().ok_or("Git has no parent")?);
            }
            invocation.args([
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
        }
        let start = Instant::now();
        let result = black_box(output(
            invocation,
            (id == "cli-stdin").then_some(stdin_bytes.as_slice()),
        ));
        elapsed += start.elapsed();
        let result = result?;
        if id == "cli-startup" {
            if !result.status.success()
                || result.stdout != format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
                || !result.stderr.is_empty()
            {
                return Err("CLI startup/version output mismatch".into());
            }
        } else {
            if result.status.code() != Some(7) {
                return Err("CLI did not return the explicit finding exit status".into());
            }
            let actual: Value = serde_json::from_slice(&result.stdout)?;
            let mut actual = actual.as_array().ok_or("CLI JSON is not an array")?.clone();
            let mut expected = expected_json
                .as_array()
                .ok_or("expected JSON is not an array")?
                .clone();
            actual.sort_by_key(ToString::to_string);
            expected.sort_by_key(ToString::to_string);
            if actual != expected {
                return Err("CLI exact report fields differ".into());
            }
            report = serde_json::to_vec(&actual)?;
            let diagnostics = std::str::from_utf8(&result.stderr)?;
            if !diagnostics.contains(&format!("scanned ~{bytes} bytes ("))
                || diagnostics.contains("partial")
                || diagnostics.lines().any(|line| {
                    !(line.starts_with("info ")
                        || line == format!("warn leaks found: {}", expected.len()))
                })
            {
                return Err("CLI consumed-byte count or completion diagnostics differ".into());
            }
            if id == "cli-git" && !diagnostics.contains(&format!("{GIT_COMMITS} commits scanned."))
            {
                return Err("CLI Git commit count differs".into());
            }
        }
        if id == "cli-startup" {
            report = result.stdout;
        }
    }
    let mut phase = row(
        if id == "cli-startup" {
            "cold-process-version"
        } else {
            "cold-cli-startup-config-scan-report"
        },
        iterations,
        elapsed,
        &fixture,
        &report,
        if id == "cli-startup" {
            0
        } else {
            expected.len()
        },
        json!({"input_bytes": if id == "cli-startup" { 0 } else { bytes }, "commits": fixture.commits, "fixture_files": if id == "cli-stdin" || id == "cli-startup" { 0 } else { fixture.fragments.len() }, "workers": 1, "queue_capacity": 1, "source_limits": "cli-default-v1", "process_state": "fresh-child-per-iteration", "filesystem_state": "setup-written-cache-uncontrolled", "child_result_destruction": "outside-timer", "child_internal_destruction": "inside-timer"}),
    )?;
    if id == "cli-startup" {
        phase.logical_unit = "processes".into();
        phase.logical_units_per_iteration = 1;
        phase.input_fnv1a64 = fingerprint(b"version");
        phase.config_fnv1a64 = fingerprint(b"no-config");
    } else if id == "cli-stdin" {
        phase.logical_units_per_iteration = bytes;
        phase.input_fnv1a64 = fingerprint(&stdin_bytes);
    }
    Ok(vec![phase])
}

fn archives(iterations: usize) -> Result<Vec<Phase>> {
    let mut invocation = Command::new(executable("RUSTLEAKS_PERF_ARCHIVE_DRIVER")?);
    invocation
        .args([
            "--exact",
            "representative_archive_driver",
            "--ignored",
            "--nocapture",
        ])
        .env("RUSTLEAKS_PERF_ITERATIONS", iterations.to_string());
    let result = output(invocation, None)?;
    if !result.status.success() {
        return Err("representative archive driver failed".into());
    }
    let mut phases: Vec<Phase> = Vec::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        if let Some(json) = line.strip_prefix("RUSTLEAKS_PERF_ARCHIVE_PHASE=") {
            phases.push(serde_json::from_str(json)?);
        }
    }
    if phases
        .iter()
        .map(|phase| phase.phase.as_str())
        .collect::<Vec<_>>()
        != ARCHIVE_PHASES
    {
        return Err("archive driver omitted or reordered a required format".into());
    }
    if phases.iter().any(|phase| {
        !phase.complete
            || phase.errors != 0
            || phase.iterations != iterations
            || phase.logical_units_per_iteration == 0
    }) {
        return Err("archive driver returned an incomplete phase".into());
    }
    Ok(phases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_clean_input_fails_even_with_equal_findings() {
        let rows = directory("source-skipped-input-control", 1)
            .expect("exact source phases and skipped-input rejection");
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .all(|row| row.counts["skipped_clean_input_rejected"] == true)
        );
    }

    #[test]
    fn declared_cli_and_git_tools_produce_exact_representative_results() {
        assert_eq!(git(1).expect("Git phases").len(), 2);
        for id in ["cli-startup", "cli-dir", "cli-stdin", "cli-git"] {
            assert_eq!(cli(id, 1).expect("CLI phase").len(), 1);
        }
    }

    #[test]
    fn representative_source_sizes_and_worker_counts_have_exact_results() {
        for id in [
            "source-many-small-w4",
            "source-few-large-w1",
            "source-few-large-w4",
        ] {
            assert_eq!(directory(id, 1).expect("source phases").len(), 3);
        }
    }
}
