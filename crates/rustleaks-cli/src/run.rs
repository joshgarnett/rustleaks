use std::collections::HashSet;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rustleaks_core::Engine;
use rustleaks_core::model::{ByteText, Finding, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_sources::{
    CancellationToken, RemoteMetadata, ScmErrorKind, ScmPlatform, SourceBudgetScope, SourceIssue,
    SourceIssueKind, SourceRunner, SourceTermination,
};

use crate::args::{self, Action, CommandKind, Invocation, ParseErrorKind};
use crate::complete_profile::{CompleteProfile, CompletionReason, CompletionStatus};
use crate::config::{self, ConfigEnvironment};
use crate::limits::{self, ScanLimits};
use crate::output::{self, ReportPlan};
use crate::source::{self, BuiltSource};
use crate::{completion, help};

/// Process context injected into one command execution.
#[derive(Clone, Debug, Default)]
pub struct RunEnvironment {
    /// Current directory used for relative config extension resolution.
    pub cwd: PathBuf,
    /// Optional path-valued configuration environment variable.
    pub config_path: Option<OsString>,
    /// Optional inline TOML configuration environment variable.
    pub config_toml: Option<OsString>,
    /// Optional backward-compatible Gitleaks configuration path.
    pub legacy_config_path: Option<OsString>,
    /// Optional backward-compatible inline Gitleaks configuration.
    pub legacy_config_toml: Option<OsString>,
}

impl RunEnvironment {
    /// Captures the supported process context without mutating it.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            config_path: std::env::var_os("RUSTLEAKS_CONFIG"),
            config_toml: std::env::var_os("RUSTLEAKS_CONFIG_TOML"),
            legacy_config_path: std::env::var_os("GITLEAKS_CONFIG"),
            legacy_config_toml: std::env::var_os("GITLEAKS_CONFIG_TOML"),
        }
    }
}

/// Runs one parsed command against injected streams and process context.
///
/// This function never calls `process::exit`, changes the process current
/// directory, changes environment variables, or closes caller-owned output.
#[must_use]
#[allow(
    clippy::needless_pass_by_value,
    reason = "one run owns a stable snapshot of its injected process context"
)]
pub fn run_from<R: Read + Send + 'static>(
    arguments: impl IntoIterator<Item = OsString>,
    environment: RunEnvironment,
    stdin: R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let action = match args::parse(arguments) {
        Ok(action) => action,
        Err(error) => {
            let _ = output::parse_error(stderr, &error.message);
            if error.kind == ParseErrorKind::UnknownCommand {
                let _ = help::root_hint(stderr);
            } else if let Some(command) = error.command {
                let _ = help::usage_block(command, stderr);
            }
            if error.kind != ParseErrorKind::UnknownLong {
                let _ = output::fatal(stderr, &error.message);
            }
            return if error.kind == ParseErrorKind::UnknownLong {
                126
            } else {
                1
            };
        }
    };
    match action {
        Action::RootHelp => help::root(stdout).map_or(1, |()| 0),
        Action::CommandHelp(topic) => help::command_page(topic, stdout).map_or(1, |()| 0),
        Action::Completion(shell) => completion::write(shell, stdout).map_or(1, |()| 0),
        Action::Version { qualified } => {
            let result = if qualified {
                writeln!(stdout, "rustleaks version {}", env!("CARGO_PKG_VERSION"))
            } else {
                writeln!(stdout, "{}", env!("CARGO_PKG_VERSION"))
            };
            result.map_or(1, |()| 0)
        }
        Action::Scan(invocation) => run_scan(&invocation, &environment, stdin, stdout, stderr),
    }
}

fn run_scan<R: Read + Send + 'static>(
    invocation: &Invocation,
    environment: &RunEnvironment,
    stdin: R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let mut status = CompletionStatus::default();
    let profile = match invocation.options.complete_profile.as_ref() {
        None => None,
        Some(path) => match CompleteProfile::load(&config::resolve(&environment.cwd, path))
            .and_then(|profile| {
                CompleteProfile::validate_invocation(invocation)?;
                Ok(profile)
            }) {
            Ok(profile) => Some(profile),
            Err(error) => {
                status.reason = CompletionReason::ProfileError;
                let _ = output::error(stderr, error);
                let _ = status.write(invocation, stderr);
                return 2;
            }
        },
    };
    let code = run_scan_inner(
        invocation,
        environment,
        stdin,
        stdout,
        stderr,
        profile.as_ref(),
        &mut status,
    );
    if profile.is_some() && (status.write(invocation, stderr).is_err() || !status.is_complete()) {
        return 2;
    }
    code
}

/// What a scan has built before it reads any input.
struct ScanSetup {
    /// When the scan clock started, for the summary line.
    started: Instant,
    cancellation: CancellationToken,
    timer: Option<Timer>,
    log_level: LogLevel,
    policy: SessionPolicy,
    report: Option<ReportPlan>,
    engine: Engine,
    scan_options: ScanOptions,
    runner: SourceRunner,
    source: BuiltSource,
    remote: Option<RemoteMetadata>,
}

/// What a finished scan produced.
struct ScanResult {
    findings: Vec<Finding>,
    /// Bytes read, including the bytes of self-excluded files.
    bytes: u64,
    /// The scan ended before it read the whole source.
    partial: bool,
}

/// Runs one scan in four steps: set up, scan, attach links and write
/// outputs. Each step returns the exit code when it stops the command.
fn run_scan_inner<R: Read + Send + 'static>(
    invocation: &Invocation,
    environment: &RunEnvironment,
    stdin: R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    profile: Option<&CompleteProfile>,
    status: &mut CompletionStatus,
) -> i32 {
    let mut setup = match set_up(invocation, environment, stdin, stderr, profile, status) {
        Ok(setup) => setup,
        Err(code) => return code,
    };
    let mut result = match scan(invocation, &mut setup, stderr, profile, status) {
        Ok(result) => result,
        Err(code) => return code,
    };
    let findings = std::mem::take(&mut result.findings);
    result.findings = attach_links(findings, &setup, stderr, profile, status);
    result.partial = result.partial || profile.is_some() && !status.is_complete();
    write_outputs(invocation, &setup, &result, stdout, stderr, status)
}

#[allow(
    clippy::too_many_lines,
    reason = "setup runs its steps in one order that decides which error is printed first"
)]
fn set_up<R: Read + Send + 'static>(
    invocation: &Invocation,
    environment: &RunEnvironment,
    stdin: R,
    stderr: &mut dyn Write,
    profile: Option<&CompleteProfile>,
    status: &mut CompletionStatus,
) -> Result<ScanSetup, i32> {
    let mut started = Instant::now();
    let cancellation = CancellationToken::new();
    // A directory scan starts its clock and its timeout after the
    // configuration is loaded. Other scans start them first.
    let mut timer = if invocation.command == CommandKind::Directory {
        None
    } else {
        Timer::start(limits::timeout(&invocation.options), cancellation.clone()).map_err(
            |error| {
                let _ = output::error(stderr, error);
                1
            },
        )?
    };
    let log_level = select_log_level(invocation, stderr);
    if !invocation.options.no_banner && output::banner(stderr).is_err() {
        finish_timer(timer.take());
        return Err(1);
    }
    let limits = match ScanLimits::from_options(&invocation.options) {
        Ok(limits) => limits,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::fatal(stderr, error);
            return Err(1);
        }
    };
    let config = match config::assemble(
        invocation,
        ConfigEnvironment {
            path: environment.config_path.as_ref(),
            inline: environment.config_toml.as_ref(),
            legacy_path: environment.legacy_config_path.as_ref(),
            legacy_inline: environment.legacy_config_toml.as_ref(),
        },
        &environment.cwd,
        &mut |rules| {
            if log_level.shows_info() {
                let _ = output::info(
                    stderr,
                    format_args!("overriding enabled rules: {}", JoinedRules(rules)),
                );
            }
        },
    ) {
        Ok(config) => config,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::fatal(stderr, error);
            return Err(1);
        }
    };
    if invocation.command == CommandKind::Directory {
        started = Instant::now();
        timer = Timer::start(limits::timeout(&invocation.options), cancellation.clone()).map_err(
            |error| {
                let _ = output::error(stderr, error);
                1
            },
        )?;
    }
    if log_level.shows_warn() {
        for warning in &config.warnings {
            let _ = output::warn(stderr, warning);
        }
    }
    if log_level.shows_error() {
        for error in &config.errors {
            let _ = output::error(stderr, error);
        }
    }
    if log_level.shows_debug() {
        let _ = output::info(stderr, format_args!("using config {}", config.origin));
        if let Some(reference) = &config.native_policy_reference {
            let _ = output::info(stderr, format_args!("built-in rule packs {reference}"));
        }
    }

    let report = match ReportPlan::new(&invocation.options, config.full.as_ref(), &environment.cwd)
    {
        Ok(report) => report,
        Err(error) => {
            finish_timer(timer.take());
            status.reason = CompletionReason::ReportFailure;
            let _ = output::fatal(stderr, error);
            return Err(1);
        }
    };
    let engine = match Engine::builder(config.selected).build() {
        Ok(engine) => engine,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::error(stderr, error);
            return Err(1);
        }
    };
    let scan_options = build_scan_options(invocation, &limits);
    let jobs = invocation.options.jobs;
    let runner = match profile.map_or_else(
        || default_runner(jobs, thread::available_parallelism),
        |profile| profile.runner(jobs),
    ) {
        Ok(runner) => runner,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::error(stderr, error);
            return Err(1);
        }
    };
    let source = match source::build(
        invocation,
        stdin,
        &config.full,
        config.excluded_paths,
        &environment.cwd,
        &limits,
        profile,
        git_history_processes(runner.workers()),
    ) {
        Ok(source) => source,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::error(stderr, error);
            return Err(1);
        }
    };

    let remote = match discover_remote(
        invocation,
        &environment.cwd,
        &cancellation,
        stderr,
        log_level,
    ) {
        Ok(remote) => remote,
        Err(error) => {
            finish_timer(timer.take());
            status.reason = if cancellation.is_cancelled() {
                CompletionReason::Cancelled
            } else {
                CompletionReason::MetadataFailure
            };
            let _ = output::error(stderr, error);
            return Err(1);
        }
    };
    Ok(ScanSetup {
        started,
        cancellation,
        timer,
        log_level,
        policy: config.policy,
        report,
        engine,
        scan_options,
        runner,
        source,
        remote,
    })
}

/// Reads the source, logs its issues and counts what it read.
fn scan(
    invocation: &Invocation,
    setup: &mut ScanSetup,
    stderr: &mut dyn Write,
    profile: Option<&CompleteProfile>,
    status: &mut CompletionStatus,
) -> Result<ScanResult, i32> {
    let log_level = setup.log_level;
    warn_quoted_log_options(invocation, stderr, log_level);
    let workers = setup.runner.workers();
    setup.source.set_read_threads(read_threads(workers));
    if log_level.shows_debug() {
        let _ = output::info(stderr, format_args!("detection threads: {workers}"));
    }
    let outcome = setup.runner.run(
        &mut setup.source,
        &setup.engine,
        setup.scan_options,
        &setup.policy,
        &setup.cancellation,
    );
    finish_timer(setup.timer.take());
    status.observe(&outcome);

    log_source_issues(
        stderr,
        outcome.issues(),
        outcome.omitted_issues(),
        log_level,
    );
    let partial = if profile.is_some() {
        !status.is_complete()
    } else {
        !matches!(
            outcome.termination(),
            SourceTermination::Completed | SourceTermination::Stopped
        )
    };
    if partial && let Some(line) = outcome_termination(outcome.termination()) {
        let _ = output::error(stderr, line);
    }
    let Some(bytes) = outcome
        .scanned_bytes()
        .checked_add(setup.source.excluded_bytes())
    else {
        status.reason = CompletionReason::ResourceExhaustion;
        let _ = output::error(stderr, "source byte accounting overflowed");
        return Err(1);
    };
    if invocation.command == CommandKind::Git {
        let Some(commits) =
            commit_union_count(outcome.unique_commits(), setup.source.excluded_commits())
        else {
            status.reason = CompletionReason::ResourceExhaustion;
            let _ = output::error(stderr, "source commit accounting overflowed");
            return Err(1);
        };
        if log_level.shows_info() {
            let _ = output::info(stderr, format_args!("{commits} commits scanned."));
        }
    }
    Ok(ScanResult {
        findings: outcome.into_findings(),
        bytes,
        partial,
    })
}

/// Adds a source-control link to each finding when the remote is known.
/// With a complete profile, links count against the profile link limits.
fn attach_links(
    findings: Vec<Finding>,
    setup: &ScanSetup,
    stderr: &mut dyn Write,
    profile: Option<&CompleteProfile>,
    status: &mut CompletionStatus,
) -> Vec<Finding> {
    let Some(metadata) = &setup.remote else {
        return findings;
    };
    findings
        .into_iter()
        .map(|finding| {
            if let Some(profile) = profile {
                match metadata.link_length(&finding) {
                    Ok(Some(length)) if status.admit_link(profile, length) => {}
                    Ok(_) => return finding,
                    Err(_) => {
                        status.reason = CompletionReason::MetadataFailure;
                        return finding;
                    }
                }
            }
            match metadata.link_for(&finding) {
                Ok(Some(link)) => finding.with_link(link),
                Ok(None) => finding,
                Err(error) => {
                    if profile.is_some() {
                        status.reason = CompletionReason::MetadataFailure;
                    }
                    if setup.log_level.shows_warn() {
                        let _ = output::warn(
                            stderr,
                            format_args!("could not construct source link: {error}"),
                        );
                    }
                    finding
                }
            }
        })
        .collect()
}

/// Writes verbose findings, the summary and the report, and returns the
/// exit code.
fn write_outputs(
    invocation: &Invocation,
    setup: &ScanSetup,
    result: &ScanResult,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    status: &mut CompletionStatus,
) -> i32 {
    let findings = &result.findings;
    if invocation.options.verbose
        && output::verbose(stdout, findings, invocation.options.redact).is_err()
    {
        status.reason = CompletionReason::ReportFailure;
        return 1;
    }
    if output::summary(
        stderr,
        result.bytes,
        setup.started.elapsed(),
        findings.len(),
        result.partial,
        setup.log_level.shows_info(),
        setup.log_level.shows_warn(),
    )
    .is_err()
    {
        status.reason = CompletionReason::ReportFailure;
        return 1;
    }
    if let Some(report) = &setup.report
        && let Err(error) = report.write(stdout, findings)
    {
        status.reason = CompletionReason::ReportFailure;
        let _ = output::error(
            stderr,
            format_args!("could not write {} report: {error}", report.format),
        );
        return 1;
    }
    if result.partial {
        1
    } else if findings.is_empty() {
        0
    } else {
        invocation.options.exit_code
    }
}

/// Logs each retained source issue and, when the runner kept only the first
/// issues, one line with the number it did not keep.
fn log_source_issues(
    stderr: &mut dyn Write,
    issues: &[SourceIssue],
    omitted: u64,
    log_level: LogLevel,
) {
    for issue in issues {
        let path = issue
            .path()
            .map_or_else(String::new, |path| format!(" {}", path.display()));
        if source_issue_is_error(issue.kind()) {
            if log_level.shows_error() {
                let _ = output::error(
                    stderr,
                    format_args!(
                        "source {:?}/{:?}{path}: {}",
                        issue.stage(),
                        issue.kind(),
                        issue.message()
                    ),
                );
            }
        } else if log_level.shows_warn() {
            let _ = output::warn(
                stderr,
                format_args!(
                    "source {:?}/{:?}{path}: {}",
                    issue.stage(),
                    issue.kind(),
                    issue.message()
                ),
            );
        }
    }
    if omitted > 0 {
        // The omitted issues can be warnings or errors, so show the line at
        // the lowest level that the log level shows.
        let message = format!("{omitted} more source warnings and errors were not shown");
        if log_level.shows_warn() {
            let _ = output::warn(stderr, &message);
        } else if log_level.shows_error() {
            let _ = output::error(stderr, &message);
        }
    }
}

fn source_issue_is_error(kind: SourceIssueKind) -> bool {
    matches!(
        kind,
        SourceIssueKind::Decode
            | SourceIssueKind::CorruptArchive
            | SourceIssueKind::DanglingSymlink
    )
}

/// Counts the commits in either list. `None` means the count overflowed.
fn commit_union_count(included: &[ByteText], excluded: &[ByteText]) -> Option<usize> {
    let mut total = included.len().checked_add(excluded.len())?;
    if excluded.is_empty() {
        return Some(total);
    }
    let mut index = HashSet::new();
    if index.try_reserve(included.len()).is_ok() {
        index.extend(included.iter().map(ByteText::as_bytes));
        for commit in excluded {
            if index.contains(commit.as_bytes()) {
                total = total.checked_sub(1)?;
            }
        }
    } else {
        for commit in excluded {
            if included.iter().any(|known| known == commit) {
                total = total.checked_sub(1)?;
            }
        }
    }
    Some(total)
}

fn build_scan_options(invocation: &Invocation, limits: &ScanLimits) -> ScanOptions {
    ScanOptions::builder()
        .max_decode_depth(limits.decode_depth)
        .base64_mode(invocation.options.base64_mode)
        .max_target_bytes(limits.engine_max)
        .redaction_percent(invocation.options.redact)
        .honor_allow_markers(!invocation.options.ignore_allow_markers)
        .build()
}

fn discover_remote(
    invocation: &Invocation,
    cwd: &std::path::Path,
    cancellation: &CancellationToken,
    stderr: &mut dyn Write,
    log_level: LogLevel,
) -> Result<Option<RemoteMetadata>, String> {
    if invocation.command != CommandKind::Git
        || invocation.options.pre_commit
        || invocation.options.staged
    {
        return Ok(None);
    }
    let platform =
        ScmPlatform::from_str(&invocation.options.platform).map_err(|error| error.to_string())?;
    match RemoteMetadata::discover(
        platform,
        config::resolve(cwd, &invocation.source),
        cancellation,
    ) {
        Ok(metadata) => {
            if platform == ScmPlatform::Unknown {
                match metadata.platform() {
                    ScmPlatform::Unknown => {
                        if log_level.shows_info() {
                            let _ = output::info(
                                stderr,
                                format_args!(
                                    "unknown SCM platform for host {}; use --platform to include links in findings",
                                    remote_host(metadata.url())
                                ),
                            );
                        }
                    }
                    ScmPlatform::NoPlatform => {
                        if log_level.shows_debug() {
                            let _ = output::info(
                                stderr,
                                "skipping finding links: repository has no configured remote",
                            );
                        }
                    }
                    resolved => {
                        if log_level.shows_debug() {
                            let _ = output::info(
                                stderr,
                                format_args!(
                                    "SCM platform {resolved} parsed from host {}",
                                    remote_host(metadata.url())
                                ),
                            );
                        }
                    }
                }
            }
            Ok(Some(metadata))
        }
        Err(error) => {
            if invocation.options.complete_profile.is_some() {
                return Err(format!(
                    "could not read the Git remote for finding links: {}",
                    scm_error_words(error.kind())
                ));
            }
            if log_level.shows_error() {
                let _ = output::error(
                    stderr,
                    format_args!("skipping finding links: unable to parse remote URL: {error}"),
                );
            }
            Ok(None)
        }
    }
}

/// Plain words for a Git remote discovery error.
const fn scm_error_words(kind: ScmErrorKind) -> &'static str {
    match kind {
        ScmErrorKind::InvalidPlatform => "unknown platform",
        ScmErrorKind::Cancelled => "cancelled",
        ScmErrorKind::Spawn => "could not start Git",
        ScmErrorKind::ChildOutput => "could not read the output of Git",
        ScmErrorKind::OutputLimit => "Git printed too much output",
        ScmErrorKind::GitExit => "Git failed",
        ScmErrorKind::InvalidRemote => "the remote URL is not valid",
        ScmErrorKind::Cleanup => "could not stop Git",
        ScmErrorKind::Allocation => "not enough memory",
    }
}

/// The error line for a scan that ended before it read the whole source.
/// A completed scan has no such line.
fn outcome_termination(termination: &SourceTermination) -> Option<String> {
    Some(match termination {
        SourceTermination::Completed => return None,
        SourceTermination::Stopped => "source stopped".to_owned(),
        SourceTermination::Cancelled => "source cancelled".to_owned(),
        SourceTermination::SourceError(error) => error.to_string(),
        SourceTermination::WorkerPanic => "source detection worker panicked".to_owned(),
        SourceTermination::BudgetExceeded(exceeded) => format!(
            "the scan reached its {} limit for {}: limit={} consumed={} requested={}",
            crate::complete_profile::resource_name(exceeded.kind()),
            match exceeded.scope() {
                SourceBudgetScope::Fragment => "one fragment",
                SourceBudgetScope::Operation => "the whole scan",
            },
            exceeded.limit(),
            exceeded.consumed(),
            exceeded.requested()
        ),
        _ => "source ended with an unknown terminal state".to_owned(),
    })
}

/// The most fragments that wait for a detection thread without a profile.
/// Waiting fragments hold their bytes, so this bounds that memory for any
/// `--jobs` value. The profile key `queue_capacity` has the same maximum.
const MAX_DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// The most detection threads that a scan starts when neither `--jobs` nor a
/// profile sets the count. More threads made large scans only a little
/// faster and used much more memory. `--jobs` can set more.
const MAX_DEFAULT_JOBS: usize = 12;

/// The most `git log` processes that read Git history at the same time.
/// Each process maps the pack files and holds its own caches, from hundreds
/// of megabytes to gigabytes for large histories. Fewer processes made large
/// history scans slower, and more were not faster.
const MAX_GIT_HISTORY_PROCESSES: usize = 6;

/// Reads Git history with one process for each detection thread, up to
/// `MAX_GIT_HISTORY_PROCESSES`. So `--jobs 1` keeps one Git process.
fn git_history_processes(workers: usize) -> NonZeroUsize {
    NonZeroUsize::new(workers.min(MAX_GIT_HISTORY_PROCESSES)).unwrap_or(NonZeroUsize::MIN)
}

/// Builds the runner of a scan without `--complete-profile`. `--jobs` sets the
/// detection threads; otherwise there is one for each CPU that the process
/// may use, up to `MAX_DEFAULT_JOBS`, or one when that number is unknown. The
/// queue holds one fragment for each thread, so memory for waiting fragments
/// grows with the thread count and stays bounded.
fn default_runner(
    jobs: Option<NonZeroUsize>,
    available: impl FnOnce() -> std::io::Result<NonZeroUsize>,
) -> Result<SourceRunner, String> {
    let workers = jobs.map_or_else(
        || available().map_or(1, |cpus| cpus.get().min(MAX_DEFAULT_JOBS)),
        NonZeroUsize::get,
    );
    SourceRunner::new(workers, workers.min(MAX_DEFAULT_QUEUE_CAPACITY))
        .map_err(|error| error.to_string())
}

/// The most threads that read the files of a directory scan. Two reader
/// threads were faster than one. More were not faster and used more CPU
/// time, because opening files in the operating system was then the limit.
const MAX_READ_THREADS: usize = 2;

/// Returns how many threads read the files of a directory scan: one for each
/// detection thread, up to `MAX_READ_THREADS`. With one detection thread,
/// detection is the limit, so a second reader would add CPU time for little
/// gain.
fn read_threads(workers: usize) -> NonZeroUsize {
    NonZeroUsize::new(workers.min(MAX_READ_THREADS)).unwrap_or(NonZeroUsize::MIN)
}

#[derive(Clone, Copy)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    const fn shows_debug(self) -> bool {
        matches!(self, Self::Trace | Self::Debug)
    }

    const fn shows_info(self) -> bool {
        matches!(self, Self::Trace | Self::Debug | Self::Info)
    }

    const fn shows_warn(self) -> bool {
        !matches!(self, Self::Error | Self::Fatal)
    }

    const fn shows_error(self) -> bool {
        !matches!(self, Self::Fatal)
    }
}

fn select_log_level(invocation: &Invocation, stderr: &mut dyn Write) -> LogLevel {
    let level = invocation.options.log_level.to_ascii_lowercase();
    match level.as_str() {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "err" | "error" => LogLevel::Error,
        "fatal" => LogLevel::Fatal,
        _ => {
            let _ = output::warn(
                stderr,
                format_args!("unknown log level: {}", invocation.options.log_level),
            );
            LogLevel::Info
        }
    }
}

fn warn_quoted_log_options(invocation: &Invocation, stderr: &mut dyn Write, log_level: LogLevel) {
    if invocation.command != CommandKind::Git
        || invocation.options.pre_commit
        || invocation.options.staged
    {
        return;
    }
    let Some(options) = &invocation.options.git_log_args else {
        return;
    };
    if log_level.shows_warn() && options.split(' ').any(is_quoted_log_token) {
        let _ = output::warn(
            stderr,
            format_args!(
                "the following `--log-opts` values may not work as expected: {}",
                QuotedLogTokens(options)
            ),
        );
    }
}

fn is_quoted_log_token(token: &str) -> bool {
    token.len() >= 2
        && ((token.starts_with('\'') && token.ends_with('\''))
            || (token.starts_with('"') && token.ends_with('"')))
}

struct QuotedLogTokens<'a>(&'a str);

impl std::fmt::Display for QuotedLogTokens<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[")?;
        let mut separator = "";
        for token in self.0.split(' ').filter(|token| is_quoted_log_token(token)) {
            formatter.write_str(separator)?;
            formatter.write_str(token)?;
            separator = " ";
        }
        formatter.write_str("]")
    }
}

struct JoinedRules<'a>(&'a [String]);

impl std::fmt::Display for JoinedRules<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut separator = "";
        for rule in self.0 {
            formatter.write_str(separator)?;
            formatter.write_str(rule)?;
            separator = ", ";
        }
        Ok(())
    }
}

fn remote_host(url: &rustleaks_core::model::ByteText) -> std::borrow::Cow<'_, str> {
    let bytes = url.as_bytes();
    let authority = bytes
        .split(|byte| *byte == b'/')
        .nth(if bytes.windows(3).any(|part| part == b"://") {
            2
        } else {
            0
        })
        .unwrap_or_default();
    let without_user = authority
        .rsplit(|byte| *byte == b'@')
        .next()
        .unwrap_or_default();
    let host = if without_user.first() == Some(&b'[') {
        without_user[1..]
            .split(|byte| *byte == b']')
            .next()
            .unwrap_or_default()
    } else {
        without_user
            .split(|byte| *byte == b':')
            .next()
            .unwrap_or_default()
    };
    String::from_utf8_lossy(host)
}

struct Timer {
    done: mpsc::Sender<()>,
    handle: thread::JoinHandle<()>,
}

impl Timer {
    fn start(
        timeout: Option<Duration>,
        cancellation: CancellationToken,
    ) -> Result<Option<Self>, String> {
        timeout
            .map(|timeout| Self::start_after(timeout, cancellation))
            .transpose()
    }

    fn start_after(timeout: Duration, cancellation: CancellationToken) -> Result<Self, String> {
        let (done, receiver) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("rustleaks-timeout".to_owned())
            .spawn(move || {
                if receiver.recv_timeout(timeout).is_err() {
                    cancellation.cancel();
                }
            })
            .map_err(|error| format!("could not start timeout helper: {error}"))?;
        Ok(Self { done, handle })
    }

    fn finish(self) {
        let _ = self.done.send(());
        let _ = self.handle.join();
    }
}

fn finish_timer(timer: Option<Timer>) {
    if let Some(timer) = timer {
        timer.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(cwd: PathBuf) -> RunEnvironment {
        RunEnvironment {
            cwd,
            ..RunEnvironment::default()
        }
    }

    #[test]
    fn directory_scans_read_files_on_one_thread_per_detection_thread_up_to_two() {
        for (workers, expected) in [(1, 1), (2, 2), (3, 2), (12, 2), (128, 2)] {
            assert_eq!(read_threads(workers).get(), expected, "{workers} workers");
        }
    }

    #[test]
    fn default_runner_prefers_jobs_then_available_cpus_up_to_twelve_then_one() {
        let never = || -> std::io::Result<NonZeroUsize> { panic!("--jobs skips the CPU query") };
        for (available, expected) in [
            (Some(1), (1, 1)),
            (Some(4), (4, 4)),
            (Some(12), (12, 12)),
            (Some(13), (12, 12)),
            (Some(36), (12, 12)),
            (Some(4096), (12, 12)),
            (None, (1, 1)),
        ] {
            let runner = default_runner(None, || {
                available
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| std::io::Error::other("synthetic unknown CPU count"))
            })
            .unwrap();
            assert_eq!((runner.workers(), runner.queue_capacity()), expected);
            assert_eq!(runner.budget(), None);
        }
        for (jobs, expected) in [
            (1, (1, 1)),
            (8, (8, 8)),
            (65, (65, 65)),
            (5000, (5000, 1024)),
        ] {
            let runner = default_runner(NonZeroUsize::new(jobs), never).unwrap();
            assert_eq!((runner.workers(), runner.queue_capacity()), expected);
        }
    }

    #[test]
    fn jobs_help_names_the_default_maximum() {
        let help = crate::cli_spec::scan_flag("jobs").unwrap().help.join(" ");
        assert!(
            help.contains(&format!("up to {MAX_DEFAULT_JOBS}.")),
            "{help}"
        );
    }

    #[test]
    fn git_history_uses_one_process_for_each_thread_up_to_six() {
        for (workers, expected) in [(1, 1), (2, 2), (6, 6), (7, 6), (12, 6), (5000, 6)] {
            assert_eq!(git_history_processes(workers).get(), expected, "{workers}");
        }
    }

    #[test]
    fn omitted_source_issues_are_summarized_in_one_line() {
        let issues = [
            SourceIssue::new(
                rustleaks_sources::SourceStage::Traverse,
                SourceIssueKind::Read,
                Some(PathBuf::from("a.txt")),
                "read failed",
            ),
            SourceIssue::new(
                rustleaks_sources::SourceStage::Traverse,
                SourceIssueKind::DanglingSymlink,
                None,
                "dangling",
            ),
        ];
        let log = |omitted, level| {
            let mut stderr = Vec::new();
            log_source_issues(&mut stderr, &issues, omitted, level);
            String::from_utf8(stderr)
                .unwrap()
                .lines()
                .map(|line| line.split_once(' ').unwrap().1.to_owned())
                .collect::<Vec<_>>()
        };
        let read = "source Traverse/Read a.txt: read failed";
        let dangling = "source Traverse/DanglingSymlink: dangling";
        assert_eq!(log(0, LogLevel::Info), [read, dangling]);
        assert_eq!(
            log(15_000, LogLevel::Warn),
            [
                read,
                dangling,
                "15000 more source warnings and errors were not shown"
            ]
        );
        assert_eq!(
            log(1, LogLevel::Error),
            [dangling, "1 more source warnings and errors were not shown"]
        );
        assert!(log(1, LogLevel::Fatal).is_empty());

        let mut stderr = Vec::new();
        log_source_issues(&mut stderr, &issues[..1], 2, LogLevel::Warn);
        let stderr = String::from_utf8(stderr).unwrap();
        let prefixes = stderr
            .lines()
            .map(|line| line.split_once(' ').unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(prefixes, ["warn", "warn"]);
        let mut stderr = Vec::new();
        log_source_issues(&mut stderr, &[], 2, LogLevel::Error);
        assert!(String::from_utf8(stderr).unwrap().starts_with("error "));
    }

    #[test]
    fn parser_errors_have_no_scan_output_and_unknown_long_is_126() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_from(
            [OsString::from("dir"), OsString::from("--unknown")],
            environment(PathBuf::from(".")),
            std::io::empty(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 126);
        assert!(stdout.is_empty());
        assert!(String::from_utf8(stderr).unwrap().contains("unknown flag"));
    }

    #[test]
    fn root_and_version_are_side_effect_free() {
        for arguments in [
            vec![],
            vec![OsString::from("--help")],
            vec![OsString::from("version")],
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            assert_eq!(
                run_from(
                    arguments,
                    environment(PathBuf::from("missing")),
                    std::io::empty(),
                    &mut stdout,
                    &mut stderr
                ),
                0
            );
            assert!(!stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn report_format_without_path_is_not_validated() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let inline = "[[rules]]\nid='x'\nregex='never-match-this'\n";
        let env = RunEnvironment {
            cwd: PathBuf::from("."),
            config_toml: Some(OsString::from(inline)),
            ..RunEnvironment::default()
        };
        let code = run_from(
            [
                OsString::from("stdin"),
                OsString::from("--no-banner"),
                OsString::from("--report-format=not-a-format"),
            ],
            env,
            std::io::empty(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(stdout.is_empty());
    }

    #[test]
    fn inline_config_error_never_discloses_contents() {
        let marker = "SECRET_MARKER_DO_NOT_PRINT";
        let env = RunEnvironment {
            cwd: PathBuf::from("."),
            config_toml: Some(OsString::from(format!("invalid = [ {marker}"))),
            ..RunEnvironment::default()
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_from(
                [OsString::from("stdin"), OsString::from("--no-banner")],
                env,
                std::io::empty(),
                &mut stdout,
                &mut stderr
            ),
            1
        );
        assert!(!String::from_utf8(stderr).unwrap().contains(marker));
    }

    #[test]
    fn injected_cwd_resolves_operational_paths_and_preserves_logical_paths() {
        let root = std::env::temp_dir().join(format!(
            "rustleaks-run-cwd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("config.toml"),
            "[[rules]]\nid='token'\ndescription='token'\nregex='''token=([A-Z0-9]{4})'''\nsecretGroup=1\n",
        )
        .unwrap();
        std::fs::write(root.join("secret.txt"), b"token=AB12\n").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_from(
            [
                OsString::from("dir"),
                OsString::from("secret.txt"),
                OsString::from("--no-banner"),
                OsString::from("-c"),
                OsString::from("config.toml"),
                OsString::from("-r"),
                OsString::from("report.json"),
            ],
            environment(root.clone()),
            std::io::empty(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1, "{}", String::from_utf8_lossy(&stderr));
        let report = std::fs::read(root.join("report.json")).unwrap();
        assert!(
            report
                .windows(b"\"File\": \"secret.txt\"".len())
                .any(|value| value == b"\"File\": \"secret.txt\"")
        );
        assert!(
            !report
                .windows(root.as_os_str().len())
                .any(|value| value == root.to_string_lossy().as_bytes())
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn timeout_helper_cancels_and_joins() {
        let token = CancellationToken::new();
        let timer = Timer::start_after(Duration::from_millis(10), token.clone()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !token.is_cancelled() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let cancelled = token.is_cancelled();
        timer.finish();
        assert!(cancelled);
    }

    #[test]
    fn quoted_log_tokens_retain_order_and_obey_level_and_mode() {
        let history = Invocation {
            command: CommandKind::Git,
            source: PathBuf::from("."),
            options: crate::args::Options {
                git_log_args: Some("'--first' plain \"--second=value\"".to_owned()),
                ..crate::args::Options::default()
            },
        };
        let mut stderr = Vec::new();
        warn_quoted_log_options(&history, &mut stderr, LogLevel::Info);
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "warn the following `--log-opts` values may not work as expected: ['--first' \"--second=value\"]\n"
        );

        let mut suppressed = Vec::new();
        warn_quoted_log_options(&history, &mut suppressed, LogLevel::Error);
        assert!(suppressed.is_empty());

        let mut diff = history.clone();
        diff.options.pre_commit = true;
        warn_quoted_log_options(&diff, &mut suppressed, LogLevel::Info);
        assert!(suppressed.is_empty());

        let mut empty = history;
        empty.options.git_log_args = Some(String::new());
        warn_quoted_log_options(&empty, &mut suppressed, LogLevel::Info);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn commit_count_is_an_exact_union() {
        let included = [ByteText::from("one"), ByteText::from("two")];
        let excluded = [ByteText::from("two"), ByteText::from("three")];
        assert_eq!(commit_union_count(&included, &excluded), Some(3));
        assert_eq!(commit_union_count(&included, &[]), Some(2));
    }

    #[test]
    fn commit_union_counts_each_excluded_commit_found_in_included() {
        // Excluded values are unique when they come from `CommitCounter`, but
        // the arithmetic is specified over the slices exactly as given.
        let included = [
            ByteText::from("one"),
            ByteText::from("two"),
            ByteText::from("three"),
        ];
        let excluded = [
            ByteText::from("two"),
            ByteText::from("four"),
            ByteText::from("two"),
        ];
        assert_eq!(commit_union_count(&included, &excluded), Some(4));
        assert_eq!(commit_union_count(&[], &excluded), Some(3));
    }

    #[test]
    fn source_issue_severity_matches_recoverable_cli_classes() {
        for kind in [
            SourceIssueKind::Decode,
            SourceIssueKind::CorruptArchive,
            SourceIssueKind::DanglingSymlink,
        ] {
            assert!(source_issue_is_error(kind));
        }
        assert!(!source_issue_is_error(SourceIssueKind::Limit));
        assert!(!source_issue_is_error(SourceIssueKind::Read));
    }
}
