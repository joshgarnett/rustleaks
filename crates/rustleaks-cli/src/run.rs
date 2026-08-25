use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rustleaks_core::Engine;
use rustleaks_core::model::{ByteText, ScanOptions};
use rustleaks_sources::{
    CancellationToken, RemoteMetadata, ScmPlatform, SourceIssueKind, SourceRunner,
    SourceTermination,
};

use crate::args::{self, Action, CommandKind, Invocation, ParseErrorKind};
use crate::config::{self, ConfigEnvironment};
use crate::output::{self, ReportPlan};
use crate::source;

/// Process context injected into one command execution.
#[derive(Clone, Debug)]
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
                let _ = output::root_usage_hint(stderr);
            } else if let Some(command) = error.command {
                let _ = output::command_usage(command, stderr);
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
        Action::RootHelp => output::root_help(stdout).map_or(1, |()| 0),
        Action::CommandHelp(command) => output::command_help(command, stdout).map_or(1, |()| 0),
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

#[allow(
    clippy::too_many_lines,
    reason = "the command lifecycle remains auditable as one ordered compatibility flow"
)]
fn run_scan<R: Read + Send + 'static>(
    invocation: &Invocation,
    environment: &RunEnvironment,
    stdin: R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let mut started = Instant::now();
    let cancellation = CancellationToken::new();
    let mut timer = if invocation.command == CommandKind::Directory {
        None
    } else {
        match Timer::start(invocation.options.timeout_seconds, cancellation.clone()) {
            Ok(timer) => timer,
            Err(error) => {
                let _ = output::error(stderr, error);
                return 1;
            }
        }
    };
    let log_level = select_log_level(invocation, stderr);
    if !invocation.options.no_banner && output::banner(stderr).is_err() {
        finish_timer(timer.take());
        return 1;
    }
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
            return 1;
        }
    };
    if invocation.command == CommandKind::Directory {
        started = Instant::now();
        timer = match Timer::start(invocation.options.timeout_seconds, cancellation.clone()) {
            Ok(timer) => timer,
            Err(error) => {
                let _ = output::error(stderr, error);
                return 1;
            }
        };
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
    if invocation.options.log_level.eq_ignore_ascii_case("debug")
        || invocation.options.log_level.eq_ignore_ascii_case("trace")
    {
        let _ = output::info(stderr, format_args!("using config {}", config.origin));
    }

    let report = match ReportPlan::new(&invocation.options, config.full.as_ref(), &environment.cwd)
    {
        Ok(report) => report,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::fatal(stderr, error);
            return 1;
        }
    };
    let engine = match Engine::builder(config.selected).build() {
        Ok(engine) => engine,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::error(stderr, error);
            return 1;
        }
    };
    let scan_options = match build_scan_options(invocation) {
        Ok(options) => options,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::error(stderr, error);
            return 1;
        }
    };
    let mut source = match source::build(
        invocation,
        stdin,
        &config.full,
        config.excluded_paths,
        &environment.cwd,
    ) {
        Ok(source) => source,
        Err(error) => {
            finish_timer(timer.take());
            let _ = output::error(stderr, error);
            return 1;
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
            let _ = output::error(stderr, error);
            return 1;
        }
    };
    warn_quoted_log_options(invocation, stderr, log_level);
    let outcome = SourceRunner::default().run(
        &mut source,
        &engine,
        scan_options,
        &config.policy,
        &cancellation,
    );
    finish_timer(timer.take());

    for issue in outcome.issues() {
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
    let partial = !matches!(
        outcome.termination(),
        SourceTermination::Completed | SourceTermination::Stopped
    );
    if partial {
        let _ = output::error(stderr, outcome_termination(outcome.termination()));
    }
    let Some(bytes) = outcome.scanned_bytes().checked_add(source.excluded_bytes()) else {
        let _ = output::error(stderr, "source byte accounting overflowed");
        return 1;
    };
    if invocation.command == CommandKind::Git {
        let Some(commits) = commit_union_count(
            outcome.unique_commits(),
            source.excluded_commits(),
            source.excluded_commit_count(),
        ) else {
            let _ = output::error(stderr, "source commit accounting overflowed");
            return 1;
        };
        if log_level.shows_info() {
            let _ = output::info(stderr, format_args!("{commits} commits scanned."));
        }
    }
    let mut findings = outcome.into_findings();
    if let Some(metadata) = remote {
        findings = findings
            .into_iter()
            .map(|finding| match metadata.link_for(&finding) {
                Ok(Some(link)) => finding.with_link(link),
                Ok(None) => finding,
                Err(error) => {
                    if log_level.shows_warn() {
                        let _ = output::warn(
                            stderr,
                            format_args!("could not construct source link: {error}"),
                        );
                    }
                    finding
                }
            })
            .collect();
    }
    if invocation.options.verbose && output::verbose(stdout, &findings).is_err() {
        return 1;
    }
    if output::summary(
        stderr,
        bytes,
        started.elapsed(),
        findings.len(),
        partial,
        log_level.shows_info(),
        log_level.shows_warn(),
    )
    .is_err()
    {
        return 1;
    }
    if let Some(report) = report {
        if let Err(error) = report.write(stdout, &findings) {
            let _ = output::error(
                stderr,
                format_args!("could not write {} report: {error}", report.format),
            );
            return 1;
        }
    }
    if partial {
        1
    } else if findings.is_empty() {
        0
    } else {
        invocation.options.exit_code
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

fn commit_union_count(
    included: &[ByteText],
    excluded: &[ByteText],
    excluded_count: usize,
) -> Option<usize> {
    if excluded.len() != excluded_count {
        return None;
    }
    let mut total = included.len().checked_add(excluded_count)?;
    for commit in excluded {
        if included.iter().any(|known| known == commit) {
            total = total.checked_sub(1)?;
        }
    }
    Some(total)
}

fn build_scan_options(invocation: &Invocation) -> Result<ScanOptions, String> {
    let decode_depth = if invocation.options.max_decode_depth <= 0 {
        0
    } else {
        usize::try_from(invocation.options.max_decode_depth)
            .map_err(|_| "--max-decode-depth is out of range".to_owned())?
    };
    Ok(ScanOptions::builder()
        .max_decode_depth(decode_depth)
        .max_target_bytes(source::engine_maximum(invocation)?)
        .redaction_percent(invocation.options.redact)
        .honor_allow_markers(!invocation.options.ignore_allow_markers)
        .build())
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

fn outcome_termination(termination: &SourceTermination) -> String {
    match termination {
        SourceTermination::Completed => "source completed".to_owned(),
        SourceTermination::Stopped => "source stopped".to_owned(),
        SourceTermination::Cancelled => "source cancelled".to_owned(),
        SourceTermination::SourceError(error) => error.to_string(),
        SourceTermination::WorkerPanic => "source detection worker panicked".to_owned(),
        _ => "source ended with an unknown terminal state".to_owned(),
    }
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
    fn start(seconds: i64, cancellation: CancellationToken) -> Result<Option<Self>, String> {
        if seconds <= 0 {
            return Ok(None);
        }
        let seconds = u64::try_from(seconds).map_err(|_| "--timeout is out of range".to_owned())?;
        Self::start_after(Duration::from_secs(seconds), cancellation).map(Some)
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
            config_path: None,
            config_toml: None,
            legacy_config_path: None,
            legacy_config_toml: None,
        }
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
            config_path: None,
            config_toml: Some(OsString::from(inline)),
            legacy_config_path: None,
            legacy_config_toml: None,
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
            config_path: None,
            config_toml: Some(OsString::from(format!("invalid = [ {marker}"))),
            legacy_config_path: None,
            legacy_config_toml: None,
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
    fn commit_count_is_an_allocation_free_exact_union() {
        let included = [ByteText::from("one"), ByteText::from("two")];
        let excluded = [ByteText::from("two"), ByteText::from("three")];
        assert_eq!(
            commit_union_count(&included, &excluded, excluded.len()),
            Some(3)
        );
        assert_eq!(commit_union_count(&included, &[], 0), Some(2));
        assert_eq!(commit_union_count(&included, &excluded, usize::MAX), None);
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
