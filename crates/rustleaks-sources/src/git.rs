use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use rustleaks_core::model::{CommitMetadata, Fragment};

#[cfg(feature = "archives")]
use crate::{ArchiveOptions, ArchiveSource};
use crate::{
    CallbackError, Cancellation, Source, SourceConfigError, SourceControl, SourceError,
    SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

const DEFAULT_MAX_PATCH_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_PATCH_LINES: usize = 2_000_000;
const DEFAULT_MAX_STDERR_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_BLOB_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_PATH_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_FILES: usize = 1_000_000;
const DEFAULT_MAX_HUNKS: usize = 2_000_000;

/// Git history or worktree/index selection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitMode {
    /// Scan `git log -p -U0`, using the pinned defaults when options are absent.
    Log {
        /// Literal space-delimited arguments appended after `-U0`.
        options: Option<String>,
    },
    /// Scan history with explicit shell-free arguments after the pinned prefix.
    LogArguments(Vec<OsString>),
    /// Scan a worktree or staged-index diff.
    Diff {
        /// Insert `--staged` before the pinned pathspec.
        staged: bool,
    },
}

impl Default for GitMode {
    fn default() -> Self {
        Self::Log { options: None }
    }
}

/// Checked memory ceilings for Git subprocess output and archive blobs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitLimits {
    patch: NonZeroUsize,
    lines: NonZeroUsize,
    stderr: NonZeroUsize,
    blob: NonZeroUsize,
    metadata: NonZeroUsize,
    path: NonZeroUsize,
    files: NonZeroUsize,
    hunks: NonZeroUsize,
}

impl GitLimits {
    /// Creates positive output ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`SourceConfigError`] when any ceiling is zero.
    pub fn new(
        patch_bytes: usize,
        patch_lines: usize,
        stderr_bytes: usize,
        blob_bytes: usize,
    ) -> Result<Self, SourceConfigError> {
        Ok(Self {
            patch: NonZeroUsize::new(patch_bytes)
                .ok_or_else(|| SourceConfigError::positive("git_patch_bytes"))?,
            lines: NonZeroUsize::new(patch_lines)
                .ok_or_else(|| SourceConfigError::positive("git_patch_lines"))?,
            stderr: NonZeroUsize::new(stderr_bytes)
                .ok_or_else(|| SourceConfigError::positive("git_stderr_bytes"))?,
            blob: NonZeroUsize::new(blob_bytes)
                .ok_or_else(|| SourceConfigError::positive("git_blob_bytes"))?,
            metadata: NonZeroUsize::new(DEFAULT_MAX_METADATA_BYTES).unwrap_or(NonZeroUsize::MIN),
            path: NonZeroUsize::new(DEFAULT_MAX_PATH_BYTES).unwrap_or(NonZeroUsize::MIN),
            files: NonZeroUsize::new(DEFAULT_MAX_FILES).unwrap_or(NonZeroUsize::MIN),
            hunks: NonZeroUsize::new(DEFAULT_MAX_HUNKS).unwrap_or(NonZeroUsize::MIN),
        })
    }

    /// Replaces parser-state ceilings for one commit's metadata, one path,
    /// total parsed files, and total parsed hunks.
    ///
    /// # Errors
    ///
    /// Returns [`SourceConfigError`] when any ceiling is zero.
    pub fn with_parser_limits(
        mut self,
        metadata_bytes: usize,
        path_bytes: usize,
        files: usize,
        hunks: usize,
    ) -> Result<Self, SourceConfigError> {
        self.metadata = NonZeroUsize::new(metadata_bytes)
            .ok_or_else(|| SourceConfigError::positive("git_metadata_bytes"))?;
        self.path = NonZeroUsize::new(path_bytes)
            .ok_or_else(|| SourceConfigError::positive("git_path_bytes"))?;
        self.files =
            NonZeroUsize::new(files).ok_or_else(|| SourceConfigError::positive("git_files"))?;
        self.hunks =
            NonZeroUsize::new(hunks).ok_or_else(|| SourceConfigError::positive("git_hunks"))?;
        Ok(self)
    }

    /// Returns the retained patch-output ceiling.
    #[must_use]
    pub const fn patch_bytes(self) -> usize {
        self.patch.get()
    }

    /// Returns the parsed patch line-count ceiling.
    #[must_use]
    pub const fn patch_lines(self) -> usize {
        self.lines.get()
    }

    /// Returns the retained standard-error ceiling.
    #[must_use]
    pub const fn stderr_bytes(self) -> usize {
        self.stderr.get()
    }

    /// Returns the retained archive-blob ceiling.
    #[must_use]
    pub const fn blob_bytes(self) -> usize {
        self.blob.get()
    }

    /// Returns the per-commit retained metadata ceiling.
    #[must_use]
    pub const fn metadata_bytes(self) -> usize {
        self.metadata.get()
    }

    /// Returns the per-path decoded byte ceiling.
    #[must_use]
    pub const fn path_bytes(self) -> usize {
        self.path.get()
    }

    /// Returns the parsed file-count ceiling.
    #[must_use]
    pub const fn files(self) -> usize {
        self.files.get()
    }

    /// Returns the total parsed hunk-count ceiling.
    #[must_use]
    pub const fn hunks(self) -> usize {
        self.hunks.get()
    }
}

impl Default for GitLimits {
    fn default() -> Self {
        Self {
            patch: NonZeroUsize::new(DEFAULT_MAX_PATCH_BYTES).unwrap_or(NonZeroUsize::MIN),
            lines: NonZeroUsize::new(DEFAULT_MAX_PATCH_LINES).unwrap_or(NonZeroUsize::MIN),
            stderr: NonZeroUsize::new(DEFAULT_MAX_STDERR_BYTES).unwrap_or(NonZeroUsize::MIN),
            blob: NonZeroUsize::new(DEFAULT_MAX_BLOB_BYTES).unwrap_or(NonZeroUsize::MIN),
            metadata: NonZeroUsize::new(DEFAULT_MAX_METADATA_BYTES).unwrap_or(NonZeroUsize::MIN),
            path: NonZeroUsize::new(DEFAULT_MAX_PATH_BYTES).unwrap_or(NonZeroUsize::MIN),
            files: NonZeroUsize::new(DEFAULT_MAX_FILES).unwrap_or(NonZeroUsize::MIN),
            hunks: NonZeroUsize::new(DEFAULT_MAX_HUNKS).unwrap_or(NonZeroUsize::MIN),
        }
    }
}

/// Safe, synchronous Git subprocess source.
///
/// Git remains an explicit external executable boundary. Patch parsing,
/// metadata projection, cancellation, output accounting, and optional archive
/// expansion are implemented in safe portable Rust.
pub struct GitSource {
    executable: OsString,
    repository: PathBuf,
    mode: GitMode,
    limits: GitLimits,
    environment: Vec<(OsString, OsString)>,
    #[cfg(feature = "archives")]
    archives: Option<ArchiveOptions>,
}

impl GitSource {
    /// Creates a Git source using the pinned default history command.
    #[must_use]
    pub fn new(repository: impl Into<PathBuf>) -> Self {
        Self {
            executable: OsString::from("git"),
            repository: crate::path::clean_native_path(&repository.into()),
            mode: GitMode::default(),
            limits: GitLimits::default(),
            environment: Vec::new(),
            #[cfg(feature = "archives")]
            archives: None,
        }
    }

    /// Selects the Git executable used by this source.
    ///
    /// The default is `git` resolved by the child process. Embedders and test
    /// harnesses can provide a declared absolute executable instead.
    #[must_use]
    pub fn executable(mut self, executable: impl Into<OsString>) -> Self {
        self.executable = executable.into();
        self
    }

    /// Selects history or diff mode.
    #[must_use]
    pub fn mode(mut self, mode: GitMode) -> Self {
        self.mode = mode;
        self
    }

    /// Replaces subprocess output ceilings.
    #[must_use]
    pub const fn limits(mut self, limits: GitLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Adds child-process environment overrides without mutating global state.
    ///
    /// Production callers normally inherit the environment unchanged. Test
    /// harnesses can use this to isolate Git's global/system configuration and
    /// locale while retaining the exact compatibility argv.
    #[must_use]
    pub fn command_environment(
        mut self,
        values: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Self {
        self.environment.extend(values);
        self
    }

    /// Enables binary archive expansion through the safe archive source.
    #[cfg(feature = "archives")]
    #[must_use]
    pub fn archives(mut self, options: ArchiveOptions) -> Self {
        self.archives = Some(options);
        self
    }

    fn arguments(&self) -> Vec<OsString> {
        let mut arguments = vec![OsString::from("-C"), self.repository.as_os_str().to_owned()];
        match &self.mode {
            GitMode::Log { options } => {
                arguments.extend([
                    OsString::from("log"),
                    OsString::from("-p"),
                    OsString::from("-U0"),
                ]);
                if let Some(options) = options.as_ref().filter(|value| !value.is_empty()) {
                    arguments.extend(options.split(' ').map(OsString::from));
                } else {
                    arguments.extend([
                        OsString::from("--full-history"),
                        OsString::from("--all"),
                        OsString::from("--diff-filter=tuxdb"),
                    ]);
                }
            }
            GitMode::LogArguments(options) => {
                arguments.extend([
                    OsString::from("log"),
                    OsString::from("-p"),
                    OsString::from("-U0"),
                ]);
                arguments.extend(options.iter().cloned());
            }
            GitMode::Diff { staged } => {
                arguments.extend([
                    OsString::from("diff"),
                    OsString::from("-U0"),
                    OsString::from("--no-ext-diff"),
                ]);
                if *staged {
                    arguments.push(OsString::from("--staged"));
                }
                arguments.push(OsString::from("."));
            }
        }
        arguments
    }
}

impl Source for GitSource {
    #[allow(
        clippy::too_many_lines,
        reason = "the source lifecycle remains auditable in one flow"
    )]
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let output = collect_command(
            &self.executable,
            &self.arguments(),
            self.limits.patch_bytes(),
            self.limits.stderr_bytes(),
            &self.environment,
            cancellation,
            SourceStage::GitCommand,
        )?;
        if output.stderr_limited {
            return Err(terminal(
                SourceStage::Limit,
                Some(self.repository.clone()),
                "Git standard error exceeded its configured byte ceiling",
            ));
        }
        if output.stdout_limited {
            return Err(terminal(
                SourceStage::Limit,
                Some(self.repository.clone()),
                "Git patch output exceeded its configured byte ceiling",
            ));
        }
        if !output.status.is_some_and(|status| status.success()) {
            return Err(terminal(
                SourceStage::GitExit,
                Some(self.repository.clone()),
                git_exit_message(output.status, &output.stderr),
            ));
        }
        if first_non_ignored_stderr(&output.stderr).is_some() {
            let control = emit(SourceEvent::Issue(SourceIssue::new(
                SourceStage::GitCommand,
                SourceIssueKind::GitStderr,
                Some(self.repository.clone()),
                "stderr is not empty",
            )))
            .map_err(SourceError::Callback)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        let files = match parse_patch(&output.stdout, self.limits, cancellation) {
            Ok(files) => files,
            Err(PatchError::Cancelled) => return Err(SourceError::Cancelled),
            Err(PatchError::Limit(message)) => {
                return Err(terminal(
                    SourceStage::Limit,
                    Some(self.repository.clone()),
                    message,
                ));
            }
            Err(PatchError::Invalid(message)) => {
                return Err(terminal(
                    SourceStage::GitParse,
                    Some(self.repository.clone()),
                    message,
                ));
            }
        };
        for file in files {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            if file.deleted {
                continue;
            }
            if file.binary {
                #[cfg(feature = "archives")]
                if let Some(options) = self.archives.clone() {
                    if crate::archive::name_is_archive(&file.path) {
                        let control =
                            self.visit_archive_blob(&file, options, cancellation, emit)?;
                        if control == SourceControl::Stop {
                            return Ok(control);
                        }
                    }
                }
                continue;
            }
            for hunk in file.hunks {
                let path = copy_limited(&file.path, self.limits.path_bytes(), "Git fragment path")
                    .map_err(|error| patch_error_to_source(error, &self.repository))?;
                let commit = copy_limited(
                    &file.commit,
                    self.limits.metadata_bytes(),
                    "Git fragment commit SHA",
                )
                .map_err(|error| patch_error_to_source(error, &self.repository))?;
                let mut builder = Fragment::builder(hunk.added)
                    .file_path(path)
                    .commit(commit)
                    .start_line(hunk.new_position);
                if let Some(metadata) = file
                    .metadata
                    .as_ref()
                    .map(|value| fallible_clone_metadata(value, self.limits.metadata_bytes()))
                    .transpose()
                    .map_err(|error| patch_error_to_source(error, &self.repository))?
                {
                    builder = builder.commit_metadata(metadata);
                }
                let control =
                    emit(SourceEvent::fragment(builder.build())).map_err(SourceError::Callback)?;
                if control == SourceControl::Stop {
                    return Ok(control);
                }
            }
        }
        Ok(SourceControl::Continue)
    }
}

#[cfg(feature = "archives")]
impl GitSource {
    fn visit_archive_blob(
        &self,
        file: &ParsedFile,
        options: ArchiveOptions,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let object = object_spec(&file.commit, &file.path)?;
        let output = collect_command(
            &self.executable,
            &[
                OsString::from("-C"),
                self.repository.as_os_str().to_owned(),
                OsString::from("cat-file"),
                OsString::from("blob"),
                object,
            ],
            self.limits.blob_bytes(),
            self.limits.stderr_bytes(),
            &self.environment,
            cancellation,
            SourceStage::GitBlob,
        )?;
        let stderr_issue = validate_archive_blob_output(&output, &self.repository)?;
        if let Some(issue) = stderr_issue {
            let control = emit(SourceEvent::Issue(issue)).map_err(SourceError::Callback)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        let logical = bytes_to_path_buf(
            copy_limited(&file.path, self.limits.path_bytes(), "Git archive path")
                .map_err(|error| patch_error_to_source(error, &self.repository))?,
        );
        let mut archive = ArchiveSource::with_options(
            io::Cursor::new(output.stdout),
            logical,
            crate::FileOptions::default(),
            options,
        );
        let mut overlay_error = None;
        let result = archive.visit(cancellation, &mut |event| match event {
            SourceEvent::Fragment { fragment, issue } => {
                match overlay_commit(&fragment, file, self.limits) {
                    Ok(fragment) => emit(SourceEvent::Fragment {
                        fragment: Box::new(fragment),
                        issue,
                    }),
                    Err(error) => {
                        let source_error = patch_error_to_source(error, &self.repository);
                        let callback_error = CallbackError::new(source_error.to_string());
                        overlay_error = Some(source_error);
                        Err(callback_error)
                    }
                }
            }
            SourceEvent::Issue(issue) => emit(SourceEvent::Issue(issue)),
        });
        if let Some(error) = overlay_error {
            Err(error)
        } else {
            result
        }
    }
}

#[cfg(feature = "archives")]
fn validate_archive_blob_output(
    output: &CollectedOutput,
    repository: &std::path::Path,
) -> Result<Option<SourceIssue>, SourceError> {
    if output.stdout_limited {
        return Err(terminal(
            SourceStage::Limit,
            Some(repository.into()),
            "Git archive blob exceeded its configured byte ceiling",
        ));
    }
    if output.stderr_limited {
        return Err(terminal(
            SourceStage::Limit,
            Some(repository.into()),
            "Git archive-blob stderr exceeded its configured byte ceiling",
        ));
    }
    if !output.status.is_some_and(|status| status.success()) {
        return Err(terminal(
            SourceStage::GitBlob,
            Some(repository.into()),
            git_exit_message(output.status, &output.stderr),
        ));
    }
    if first_non_ignored_stderr(&output.stderr).is_some() {
        return Ok(Some(SourceIssue::new(
            SourceStage::GitBlob,
            SourceIssueKind::GitStderr,
            Some(repository.into()),
            "stderr is not empty",
        )));
    }
    Ok(None)
}

#[cfg(feature = "archives")]
fn overlay_commit(
    fragment: &Fragment,
    file: &ParsedFile,
    limits: GitLimits,
) -> PatchResult<Fragment> {
    let mut builder = Fragment::builder(copy_limited(
        fragment.content().as_bytes(),
        usize::MAX,
        "Git archive fragment",
    )?)
    .file_path(copy_limited(
        fragment.file_path().as_bytes(),
        usize::MAX,
        "archive path",
    )?)
    .symlink_file(copy_limited(
        fragment.symlink_file().as_bytes(),
        usize::MAX,
        "archive symlink path",
    )?)
    .windows_file_path(copy_limited(
        fragment.windows_file_path().as_bytes(),
        usize::MAX,
        "archive Windows path",
    )?)
    .commit(copy_limited(
        &file.commit,
        limits.metadata_bytes(),
        "Git archive commit SHA",
    )?)
    .start_line(fragment.start_line())
    .inherited_from_finding(fragment.inherited_from_finding());
    if let Some(metadata) = file
        .metadata
        .as_ref()
        .map(|value| fallible_clone_metadata(value, limits.metadata_bytes()))
        .transpose()?
    {
        builder = builder.commit_metadata(metadata);
    }
    Ok(builder.build())
}

struct CollectedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_limited: bool,
    stderr_limited: bool,
    status: Option<ExitStatus>,
}

enum CollectionStop {
    Exited(ExitStatus),
    Cancelled,
    Limited,
}

fn collect_command(
    program: &OsStr,
    arguments: &[OsString],
    stdout_limit: usize,
    stderr_limit: usize,
    environment: &[(OsString, OsString)],
    cancellation: &dyn Cancellation,
    stage: SourceStage,
) -> Result<CollectedOutput, SourceError> {
    let mut child = Command::new(program)
        .args(arguments)
        .envs(environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| terminal(stage, None, format!("could not start Git: {error}")))?;
    let Some(stdout) = child.stdout.take() else {
        stop_and_reap(&mut child, stage, "after a missing stdout pipe")?;
        return Err(terminal(
            stage,
            None,
            "Git standard output pipe was unavailable",
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        stop_and_reap(&mut child, stage, "after a missing stderr pipe")?;
        return Err(terminal(
            stage,
            None,
            "Git standard error pipe was unavailable",
        ));
    };

    thread::scope(|scope| {
        let stdout_exceeded = Arc::new(AtomicBool::new(false));
        let stderr_exceeded = Arc::new(AtomicBool::new(false));
        let stdout_flag = Arc::clone(&stdout_exceeded);
        let stderr_flag = Arc::clone(&stderr_exceeded);
        let stdout_reader =
            scope.spawn(move || read_bounded_and_drain(stdout, stdout_limit, &stdout_flag));
        let stderr_reader =
            scope.spawn(move || read_bounded_and_drain(stderr, stderr_limit, &stderr_flag));
        let stop = loop {
            if cancellation.is_cancelled() {
                stop_and_reap(&mut child, stage, "after cancellation")?;
                break CollectionStop::Cancelled;
            }
            if stdout_exceeded.load(Ordering::Acquire) || stderr_exceeded.load(Ordering::Acquire) {
                stop_and_reap(&mut child, stage, "after an output limit")?;
                break CollectionStop::Limited;
            }
            match child.try_wait() {
                Ok(Some(status)) => break CollectionStop::Exited(status),
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(error) => {
                    stop_and_reap(&mut child, stage, "after a wait failure")?;
                    return Err(terminal(
                        stage,
                        None,
                        format!("could not wait for Git: {error}"),
                    ));
                }
            }
        };
        let (stdout, stdout_limited) = stdout_reader
            .join()
            .map_err(|_| terminal(stage, None, "Git stdout reader panicked"))?
            .map_err(|error| {
                terminal(stage, None, format!("could not read Git stdout: {error}"))
            })?;
        let (stderr, stderr_limited) = stderr_reader
            .join()
            .map_err(|_| terminal(stage, None, "Git stderr reader panicked"))?
            .map_err(|error| {
                terminal(stage, None, format!("could not read Git stderr: {error}"))
            })?;
        let status = match stop {
            CollectionStop::Exited(status) => Some(status),
            CollectionStop::Cancelled => return Err(SourceError::Cancelled),
            CollectionStop::Limited => None,
        };
        Ok(CollectedOutput {
            stdout,
            stderr,
            stdout_limited,
            stderr_limited,
            status,
        })
    })
}

fn stop_and_reap(
    child: &mut impl GitChildLifecycle,
    stage: SourceStage,
    context: &str,
) -> Result<(), SourceError> {
    let kill_error = child.terminate().err().filter(|error| {
        !matches!(
            error.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
        )
    });
    let wait_error = child.reap().err();
    match (kill_error, wait_error) {
        (None, None) => Ok(()),
        (kill, wait) => Err(terminal(
            stage,
            None,
            format!("could not clean up Git {context}: kill={kill:?}; wait={wait:?}"),
        )),
    }
}

trait GitChildLifecycle {
    fn terminate(&mut self) -> io::Result<()>;
    fn reap(&mut self) -> io::Result<()>;
}

impl GitChildLifecycle for std::process::Child {
    fn terminate(&mut self) -> io::Result<()> {
        self.kill()
    }

    fn reap(&mut self) -> io::Result<()> {
        self.wait().map(|_| ())
    }
}

fn git_exit_message(status: Option<ExitStatus>, stderr: &[u8]) -> String {
    let status = status.map_or_else(|| "terminated".to_owned(), |status| status.to_string());
    if stderr.is_empty() {
        format!("Git exited unsuccessfully ({status}) with empty stderr")
    } else {
        format!(
            "Git exited unsuccessfully ({status}); bounded stderr: {}",
            String::from_utf8_lossy(stderr)
        )
    }
}

fn read_bounded_and_drain(
    mut reader: impl Read,
    limit: usize,
    exceeded: &AtomicBool,
) -> io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(limit.min(64 * 1024))
        .map_err(|error| io::Error::other(format!("could not reserve command output: {error}")))?;
    let mut buffer = [0_u8; 8192];
    let mut limited = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = read.min(remaining);
        if keep > 0 {
            retained.try_reserve(keep).map_err(|error| {
                io::Error::other(format!("could not grow command output: {error}"))
            })?;
            retained.extend_from_slice(&buffer[..keep]);
        }
        limited |= keep < read;
        if limited {
            exceeded.store(true, Ordering::Release);
        }
    }
    Ok((retained, limited))
}

fn first_non_ignored_stderr(stderr: &[u8]) -> Option<&[u8]> {
    if stderr.is_empty() {
        return None;
    }
    let mut start = 0;
    loop {
        let end = stderr[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(stderr.len(), |relative| start + relative);
        let line = stderr[start..end]
            .strip_suffix(b"\r")
            .unwrap_or(&stderr[start..end]);
        let ignored = [
            b"exhaustive rename detection was skipped".as_slice(),
            b"inexact rename detection was skipped".as_slice(),
            b"you may want to set your diff.renameLimit".as_slice(),
            b"See \"git help gc\" for manual housekeeping".as_slice(),
            b"Auto packing the repository in background for optimum performance".as_slice(),
        ]
        .iter()
        .any(|needle| line.windows(needle.len()).any(|window| window == *needle));
        if !ignored {
            return Some(line);
        }
        if end == stderr.len() || end + 1 == stderr.len() {
            return None;
        }
        start = end + 1;
    }
}

#[derive(Clone)]
struct ParsedFile {
    path: Vec<u8>,
    commit: Vec<u8>,
    metadata: Option<CommitMetadata>,
    deleted: bool,
    binary: bool,
    hunks: Vec<ParsedHunk>,
}

#[derive(Clone)]
struct ParsedHunk {
    new_position: usize,
    added: Vec<u8>,
}

#[derive(Debug)]
enum PatchError {
    Cancelled,
    Limit(String),
    Invalid(String),
}

type PatchResult<T> = Result<T, PatchError>;

fn poll_patch_cancellation(cancellation: &dyn Cancellation) -> PatchResult<()> {
    if cancellation.is_cancelled() {
        Err(PatchError::Cancelled)
    } else {
        Ok(())
    }
}

fn patch_allocation(context: &str, error: impl fmt::Display) -> PatchError {
    PatchError::Limit(format!("could not allocate {context}: {error}"))
}

fn copy_limited(value: &[u8], limit: usize, context: &str) -> PatchResult<Vec<u8>> {
    if value.len() > limit {
        return Err(PatchError::Limit(format!(
            "{context} exceeds the configured {limit}-byte ceiling"
        )));
    }
    let mut output = Vec::new();
    reserve_input(&mut output, value.len(), context)?;
    output.extend_from_slice(value);
    Ok(output)
}

fn push_limited(
    output: &mut Vec<u8>,
    value: &[u8],
    limit: usize,
    context: &str,
) -> PatchResult<()> {
    let required = output
        .len()
        .checked_add(value.len())
        .ok_or_else(|| PatchError::Limit(format!("{context} size overflowed usize")))?;
    if required > limit {
        return Err(PatchError::Limit(format!(
            "{context} exceeds the configured {limit}-byte ceiling"
        )));
    }
    reserve_input(output, value.len(), context)?;
    output.extend_from_slice(value);
    Ok(())
}

fn reserve_input(output: &mut Vec<u8>, additional: usize, context: &str) -> PatchResult<()> {
    output
        .try_reserve_exact(additional)
        .map_err(|error| patch_allocation(context, error))
}

fn fallible_clone_metadata(metadata: &CommitMetadata, limit: usize) -> PatchResult<CommitMetadata> {
    let sha = copy_limited(metadata.sha().as_bytes(), limit, "Git metadata SHA")?;
    let author_name = copy_limited(metadata.author_name().as_bytes(), limit, "Git author name")?;
    let author_email = copy_limited(
        metadata.author_email().as_bytes(),
        limit,
        "Git author email",
    )?;
    let date = copy_limited(metadata.date().as_bytes(), limit, "Git commit date")?;
    let message = copy_limited(metadata.message().as_bytes(), limit, "Git commit message")?;
    let total = sha
        .len()
        .checked_add(author_name.len())
        .and_then(|size| size.checked_add(author_email.len()))
        .and_then(|size| size.checked_add(date.len()))
        .and_then(|size| size.checked_add(message.len()))
        .ok_or_else(|| PatchError::Limit("Git metadata size overflowed usize".to_owned()))?;
    if total > limit {
        return Err(PatchError::Limit(format!(
            "Git commit metadata exceeds the configured {limit}-byte ceiling"
        )));
    }
    Ok(CommitMetadata::builder()
        .sha(sha)
        .author_name(author_name)
        .author_email(author_email)
        .date(date)
        .message(message)
        .build())
}

fn zero_commit_metadata() -> CommitMetadata {
    CommitMetadata::builder()
        .date(b"0001-01-01T00:00:00Z".as_slice())
        .build()
}

#[allow(
    clippy::too_many_lines,
    reason = "the byte parser state machine is intentionally linear"
)]
fn parse_patch(
    input: &[u8],
    limits: GitLimits,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<ParsedFile>> {
    let lines = split_inclusive_lines(input, limits.patch_lines(), cancellation)?;
    let mut files = Vec::new();
    let mut index = 0;
    let mut current_commit = Vec::new();
    let mut current_metadata = Some(zero_commit_metadata());
    let mut total_hunks = 0_usize;
    while index < lines.len() {
        poll_patch_cancellation(cancellation)?;
        if let Some(value) = lines[index].strip_prefix(b"commit ") {
            current_commit =
                copy_limited(trim_line(value), limits.metadata_bytes(), "Git commit SHA")?;
            let (metadata, next) = parse_commit_header(
                &lines,
                index,
                &current_commit,
                limits.metadata_bytes(),
                cancellation,
            )?;
            current_metadata = Some(metadata);
            index = next;
            continue;
        }
        if !lines[index].starts_with(b"diff --git ") {
            if !trim_line(lines[index]).is_empty() {
                return Err(PatchError::Invalid(
                    "Git patch contains an unrecognized nonempty preamble".to_owned(),
                ));
            }
            index += 1;
            continue;
        }
        let mut file = ParsedFile {
            path: parse_diff_fallback(lines[index], limits.path_bytes())?.unwrap_or_default(),
            commit: copy_limited(
                &current_commit,
                limits.metadata_bytes(),
                "Git file commit SHA",
            )?,
            metadata: current_metadata
                .as_ref()
                .map(|metadata| fallible_clone_metadata(metadata, limits.metadata_bytes()))
                .transpose()?,
            deleted: false,
            binary: false,
            hunks: Vec::new(),
        };
        let mut saw_old_path = false;
        let mut saw_new_path = false;
        let mut saw_old_mode = false;
        let mut saw_new_mode = false;
        let mut saw_rename_from = false;
        let mut saw_rename_to = false;
        let mut saw_copy_from = false;
        let mut saw_copy_to = false;
        let mut saw_file_lifecycle_mode = false;
        let mut binary_payload = false;
        index += 1;
        while index < lines.len()
            && !lines[index].starts_with(b"diff --git ")
            && !lines[index].starts_with(b"commit ")
        {
            poll_patch_cancellation(cancellation)?;
            let line = lines[index];
            if binary_payload {
                index += 1;
                continue;
            }
            if line.starts_with(b"deleted file mode ") {
                file.deleted = true;
                saw_file_lifecycle_mode = true;
            } else if let Some(value) = line.strip_prefix(b"+++ ") {
                if !saw_old_path {
                    return Err(PatchError::Invalid(
                        "Git new-path header precedes its old-path header".to_owned(),
                    ));
                }
                saw_new_path = true;
                let value = trim_line(value);
                if value == b"/dev/null" {
                    file.deleted = true;
                } else {
                    file.path = decode_patch_path(value, true, limits.path_bytes(), cancellation)?;
                }
            } else if line.starts_with(b"Binary files ") {
                file.binary = true;
            } else if line.starts_with(b"GIT binary patch") {
                file.binary = true;
                binary_payload = true;
            } else if line.starts_with(b"@@ -") {
                total_hunks = total_hunks.checked_add(1).ok_or_else(|| {
                    PatchError::Limit("Git hunk count overflowed usize".to_owned())
                })?;
                if total_hunks > limits.hunks() {
                    return Err(PatchError::Limit(format!(
                        "Git patch exceeds the configured {}-hunk ceiling",
                        limits.hunks()
                    )));
                }
                let (hunk, next) = parse_hunk(&lines, index, cancellation)?;
                file.hunks
                    .try_reserve(1)
                    .map_err(|error| patch_allocation("Git hunks", error))?;
                file.hunks.push(hunk);
                index = next;
                continue;
            } else if line.starts_with(b"--- ") {
                saw_old_path = true;
            } else if line.starts_with(b"old mode ") {
                saw_old_mode = true;
            } else if line.starts_with(b"new file mode ") {
                saw_new_mode = true;
                saw_file_lifecycle_mode = true;
            } else if line.starts_with(b"new mode ") {
                saw_new_mode = true;
            } else if line.starts_with(b"rename from ") {
                saw_rename_from = true;
            } else if line.starts_with(b"rename to ") {
                if !saw_rename_from {
                    return Err(PatchError::Invalid(
                        "Git rename destination has no source".to_owned(),
                    ));
                }
                saw_rename_to = true;
            } else if line.starts_with(b"copy from ") {
                saw_copy_from = true;
            } else if line.starts_with(b"copy to ") {
                if !saw_copy_from {
                    return Err(PatchError::Invalid(
                        "Git copy destination has no source".to_owned(),
                    ));
                }
                saw_copy_to = true;
            } else if line.starts_with(b"index ")
                || line.starts_with(b"similarity index ")
                || line.starts_with(b"dissimilarity index ")
                || trim_line(line).is_empty()
            {
                // Auxiliary headers and separators do not make a record valid.
            } else {
                return Err(PatchError::Invalid(
                    "Git diff record contains an unexpected line".to_owned(),
                ));
            }
            index += 1;
        }
        let valid_structure = file.binary
            || !file.hunks.is_empty()
            || (saw_old_path && saw_new_path)
            || (saw_old_mode && saw_new_mode)
            || saw_file_lifecycle_mode
            || (saw_rename_from && saw_rename_to)
            || (saw_copy_from && saw_copy_to);
        if !valid_structure {
            return Err(PatchError::Invalid(
                "Git diff record contains incomplete or unrecognized structure".to_owned(),
            ));
        }
        if !file.path.is_empty() {
            if files.len() >= limits.files() {
                return Err(PatchError::Limit(format!(
                    "Git patch exceeds the configured {}-file ceiling",
                    limits.files()
                )));
            }
            files
                .try_reserve(1)
                .map_err(|error| patch_allocation("parsed Git files", error))?;
            files.push(file);
        }
    }
    Ok(files)
}

/// Exercises the in-process Git patch parser for the standalone fuzz target.
///
/// This entry point is available only with the `fuzzing` feature and exposes
/// no parser implementation types. Production users should use [`GitSource`].
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_patch(
    input: &[u8],
    limits: GitLimits,
    cancellation: &dyn Cancellation,
) -> Result<(usize, usize), ()> {
    let files = parse_patch(input, limits, cancellation).map_err(|_| ())?;
    let mut hunks = 0_usize;
    for file in &files {
        assert!(
            file.path.len() <= limits.path_bytes(),
            "successful Git patch path exceeded its parser limit"
        );
        hunks = hunks
            .checked_add(file.hunks.len())
            .expect("bounded Git patch hunk count must fit usize");
    }
    assert!(
        files.len() <= limits.files(),
        "successful Git patch file count exceeded its parser limit"
    );
    assert!(
        hunks <= limits.hunks(),
        "successful Git patch hunk count exceeded its parser limit"
    );
    Ok((files.len(), hunks))
}

fn parse_commit_header(
    lines: &[&[u8]],
    start: usize,
    sha: &[u8],
    metadata_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<(CommitMetadata, usize)> {
    let mut author_name = Vec::new();
    let mut author_email = Vec::new();
    let mut date = copy_limited(b"0001-01-01T00:00:00Z", metadata_limit, "Git commit date")?;
    let mut index = start + 1;
    while index < lines.len()
        && !lines[index].starts_with(b"diff --git ")
        && !lines[index].starts_with(b"commit ")
    {
        poll_patch_cancellation(cancellation)?;
        let line = lines[index];
        if trim_line(line).is_empty() {
            index += 1;
            break;
        }
        if let Some(author) = line.strip_prefix(b"Author: ") {
            let author = trim_line(author);
            if let Some(open) = author.iter().rposition(|byte| *byte == b'<') {
                if author.ends_with(b">") {
                    author_name = copy_limited(
                        trim_unicode_space(&author[..open]),
                        metadata_limit,
                        "Git author name",
                    )?;
                    author_email = copy_limited(
                        &author[open + 1..author.len() - 1],
                        metadata_limit,
                        "Git author email",
                    )?;
                }
            }
        } else if let Some(value) = line
            .strip_prefix(b"Date:   ")
            .or_else(|| line.strip_prefix(b"AuthorDate: "))
        {
            if let Some(parsed) = git_date_to_rfc3339(trim_line(value), metadata_limit)? {
                date = parsed;
            }
        }
        index += 1;
    }
    while index < lines.len() && trim_line(lines[index]).is_empty() {
        poll_patch_cancellation(cancellation)?;
        index += 1;
    }
    let mut message_lines = Vec::new();
    while index < lines.len()
        && !lines[index].starts_with(b"diff --git ")
        && !lines[index].starts_with(b"commit ")
    {
        poll_patch_cancellation(cancellation)?;
        let line = trim_line(lines[index]);
        message_lines
            .try_reserve(1)
            .map_err(|error| patch_allocation("Git commit message lines", error))?;
        message_lines.push(line);
        index += 1;
    }
    while message_lines.last().is_some_and(|line| line.is_empty()) {
        message_lines.pop();
    }
    let message = join_message(&message_lines, metadata_limit, cancellation)?;
    let metadata_size = sha
        .len()
        .checked_add(author_name.len())
        .and_then(|size| size.checked_add(author_email.len()))
        .and_then(|size| size.checked_add(date.len()))
        .and_then(|size| size.checked_add(message.len()))
        .ok_or_else(|| PatchError::Limit("Git metadata size overflowed usize".to_owned()))?;
    if metadata_size > metadata_limit {
        return Err(PatchError::Limit(format!(
            "Git commit metadata exceeds the configured {metadata_limit}-byte ceiling"
        )));
    }
    let sha = copy_limited(sha, metadata_limit, "Git metadata SHA")?;
    Ok((
        CommitMetadata::builder()
            .sha(sha)
            .author_name(author_name)
            .author_email(author_email)
            .date(date)
            .message(message)
            .build(),
        index,
    ))
}

fn join_message(
    lines: &[&[u8]],
    metadata_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<u8>> {
    let Some(first_nonempty) = lines
        .iter()
        .position(|line| !trim_unicode_space(line).is_empty())
    else {
        return Ok(Vec::new());
    };
    let indent_len = lines[first_nonempty]
        .len()
        .saturating_sub(trim_unicode_space_start(lines[first_nonempty]).len());
    let indent = &lines[first_nonempty][..indent_len];
    let mut title = Vec::new();
    let mut index = first_nonempty;
    while index < lines.len() {
        poll_patch_cancellation(cancellation)?;
        let line = trim_unicode_space(lines[index]);
        if line.is_empty() {
            break;
        }
        if !title.is_empty() {
            push_limited(&mut title, b" ", metadata_limit, "Git commit title")?;
        }
        push_limited(&mut title, line, metadata_limit, "Git commit title")?;
        index += 1;
    }
    while index < lines.len() && trim_unicode_space(lines[index]).is_empty() {
        poll_patch_cancellation(cancellation)?;
        index += 1;
    }
    let mut body = Vec::new();
    let mut pending_empty = false;
    while index < lines.len() {
        poll_patch_cancellation(cancellation)?;
        let mut line = trim_unicode_space_end(lines[index]);
        if !indent.is_empty() {
            line = line.strip_prefix(indent).unwrap_or(line);
        }
        if line.is_empty() {
            pending_empty = true;
        } else {
            if !body.is_empty() {
                push_limited(&mut body, b"\n", metadata_limit, "Git commit body")?;
                if pending_empty {
                    push_limited(&mut body, b"\n", metadata_limit, "Git commit body")?;
                }
            }
            push_limited(&mut body, line, metadata_limit, "Git commit body")?;
            pending_empty = false;
        }
        index += 1;
    }
    if !body.is_empty() {
        push_limited(&mut title, b"\n\n", metadata_limit, "Git commit message")?;
        push_limited(&mut title, &body, metadata_limit, "Git commit message")?;
    }
    Ok(title)
}

fn parse_hunk(
    lines: &[&[u8]],
    start: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<(ParsedHunk, usize)> {
    let header = trim_line(lines[start]);
    let plus = header
        .windows(2)
        .position(|window| window == b" +")
        .ok_or_else(|| {
            PatchError::Invalid("invalid Git hunk header: missing new range".to_owned())
        })?;
    let range = &header[plus + 2..];
    let end = range
        .windows(3)
        .position(|window| window == b" @@")
        .ok_or_else(|| {
            PatchError::Invalid("invalid Git hunk header: missing range terminator".to_owned())
        })?;
    let range = &range[..end];
    let comma = range.iter().position(|byte| *byte == b',');
    let new_position =
        parse_usize(comma.map_or(range, |at| &range[..at])).map_err(PatchError::Invalid)?;
    let mut new_remaining = match comma {
        Some(at) => parse_usize(&range[at + 1..]).map_err(PatchError::Invalid)?,
        None => 1,
    };
    let minus = header
        .strip_prefix(b"@@ -")
        .ok_or_else(|| PatchError::Invalid("invalid Git hunk header prefix".to_owned()))?;
    let old_end = minus
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| PatchError::Invalid("invalid Git old range".to_owned()))?;
    let old_range = &minus[..old_end];
    let old_comma = old_range.iter().position(|byte| *byte == b',');
    let mut old_remaining = match old_comma {
        Some(at) => parse_usize(&old_range[at + 1..]).map_err(PatchError::Invalid)?,
        None => 1,
    };
    let mut added = Vec::new();
    let mut previous_added = false;
    let mut index = start + 1;
    while old_remaining > 0 || new_remaining > 0 {
        poll_patch_cancellation(cancellation)?;
        let line = lines
            .get(index)
            .copied()
            .ok_or_else(|| PatchError::Invalid("truncated Git hunk".to_owned()))?;
        match line.first().copied() {
            Some(b'+') => {
                new_remaining = new_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too many additions".to_owned())
                })?;
                added
                    .try_reserve(line.len().saturating_sub(1))
                    .map_err(|error| patch_allocation("Git hunk bytes", error))?;
                added.extend_from_slice(&line[1..]);
                previous_added = true;
            }
            Some(b'-') => {
                old_remaining = old_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too many deletions".to_owned())
                })?;
                previous_added = false;
            }
            Some(b' ' | b'\n') => {
                old_remaining = old_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too much context".to_owned())
                })?;
                new_remaining = new_remaining.checked_sub(1).ok_or_else(|| {
                    PatchError::Invalid("Git hunk has too much context".to_owned())
                })?;
                previous_added = false;
            }
            Some(b'\\') if line.starts_with(b"\\ ") => {
                if previous_added && added.last() == Some(&b'\n') {
                    added.pop();
                }
            }
            _ => {
                return Err(PatchError::Invalid(
                    "invalid Git hunk line operation".to_owned(),
                ));
            }
        }
        index += 1;
    }
    if lines
        .get(index)
        .is_some_and(|line| line.starts_with(b"\\ "))
    {
        if previous_added && added.last() == Some(&b'\n') {
            added.pop();
        }
        index += 1;
    }
    Ok((
        ParsedHunk {
            new_position,
            added,
        },
        index,
    ))
}

fn parse_diff_fallback(line: &[u8], path_limit: usize) -> PatchResult<Option<Vec<u8>>> {
    let Some(value) = line.strip_prefix(b"diff --git ") else {
        return Ok(None);
    };
    let value = trim_line(value);
    if value.starts_with(b"\"") {
        return Ok(None);
    }
    let marker = b" b/";
    let Some(at) = value
        .windows(marker.len())
        .rposition(|window| window == marker)
    else {
        return Ok(None);
    };
    copy_limited(&value[at + marker.len()..], path_limit, "Git fallback path").map(Some)
}

fn decode_patch_path(
    value: &[u8],
    tree_prefix: bool,
    path_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<u8>> {
    poll_patch_cancellation(cancellation)?;
    let encoded_limit = if tree_prefix {
        path_limit
            .checked_add(2)
            .ok_or_else(|| PatchError::Limit("Git path ceiling overflowed usize".to_owned()))?
    } else {
        path_limit
    };
    let mut decoded = if value.starts_with(b"\"") {
        decode_c_quoted(value, encoded_limit, cancellation)?
    } else {
        copy_limited(value, encoded_limit, "Git path")?
    };
    if tree_prefix && (decoded.starts_with(b"a/") || decoded.starts_with(b"b/")) {
        decoded.drain(..2);
    }
    if tree_prefix {
        let mut previous_slash = false;
        decoded.retain(|byte| {
            let keep = *byte != b'/' || !previous_slash;
            previous_slash = *byte == b'/';
            keep
        });
    }
    if decoded.len() > path_limit {
        return Err(PatchError::Limit(format!(
            "Git path exceeds the configured {path_limit}-byte ceiling"
        )));
    }
    Ok(decoded)
}

fn decode_c_quoted(
    value: &[u8],
    path_limit: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<u8>> {
    if value.len() < 2 || value.last() != Some(&b'\"') {
        return Err(PatchError::Invalid(
            "unterminated quoted Git path".to_owned(),
        ));
    }
    let mut output = Vec::new();
    let mut index = 1;
    while index + 1 < value.len() {
        poll_patch_cancellation(cancellation)?;
        if output.len() >= path_limit {
            return Err(PatchError::Limit(format!(
                "Git path exceeds the configured {path_limit}-byte ceiling"
            )));
        }
        output
            .try_reserve(1)
            .map_err(|error| patch_allocation("decoded Git path", error))?;
        if value[index] != b'\\' {
            output.push(value[index]);
            index += 1;
            continue;
        }
        index += 1;
        let escaped = *value
            .get(index)
            .ok_or_else(|| PatchError::Invalid("truncated quoted Git path escape".to_owned()))?;
        match escaped {
            b'a' => output.push(0x07),
            b'b' => output.push(0x08),
            b't' => output.push(b'\t'),
            b'n' => output.push(b'\n'),
            b'v' => output.push(0x0b),
            b'f' => output.push(0x0c),
            b'r' => output.push(b'\r'),
            b'\\' | b'\"' => output.push(escaped),
            b'0'..=b'7' => {
                let mut octal = usize::from(escaped - b'0');
                let mut count = 1;
                while count < 3
                    && value
                        .get(index + 1)
                        .is_some_and(|byte| matches!(byte, b'0'..=b'7'))
                {
                    index += 1;
                    octal = octal * 8 + usize::from(value[index] - b'0');
                    count += 1;
                }
                output.push(u8::try_from(octal).map_err(|_| {
                    PatchError::Invalid("Git path octal escape overflow".to_owned())
                })?);
            }
            _ => {
                return Err(PatchError::Invalid(
                    "unsupported quoted Git path escape".to_owned(),
                ));
            }
        }
        index += 1;
    }
    Ok(output)
}

fn git_date_to_rfc3339(value: &[u8], limit: usize) -> PatchResult<Option<Vec<u8>>> {
    let Ok(text) = std::str::from_utf8(value) else {
        return Ok(None);
    };
    let mut parts = text.split_ascii_whitespace();
    let Some(_weekday) = parts.next() else {
        return Ok(None);
    };
    let Some(month_name) = parts.next() else {
        return Ok(None);
    };
    let Some(day_text) = parts.next() else {
        return Ok(None);
    };
    let Some(clock_text) = parts.next() else {
        return Ok(None);
    };
    let Some(year_text) = parts.next() else {
        return Ok(None);
    };
    let Some(zone_text) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() {
        return Ok(None);
    }
    let month = match month_name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return Ok(None),
    };
    let Ok(day) = day_text.parse::<i64>() else {
        return Ok(None);
    };
    let mut clock = clock_text.split(':');
    let Some(Ok(hour)) = clock.next().map(str::parse::<i64>) else {
        return Ok(None);
    };
    let Some(Ok(minute)) = clock.next().map(str::parse::<i64>) else {
        return Ok(None);
    };
    let Some(Ok(second)) = clock.next().map(str::parse::<i64>) else {
        return Ok(None);
    };
    if clock.next().is_some() {
        return Ok(None);
    }
    let Ok(year) = year_text.parse::<i64>() else {
        return Ok(None);
    };
    let zone = zone_text.as_bytes();
    if zone.len() != 5 || !matches!(zone[0], b'+' | b'-') {
        return Ok(None);
    }
    let Ok(zone_hours) = zone_text[1..3].parse::<i64>() else {
        return Ok(None);
    };
    let Ok(zone_minutes) = zone_text[3..5].parse::<i64>() else {
        return Ok(None);
    };
    let sign = if zone[0] == b'-' { -1 } else { 1 };
    let offset = sign * (zone_hours * 3600 + zone_minutes * 60);
    let Some(days) = days_from_civil(year, month, day) else {
        return Ok(None);
    };
    let Some(timestamp) = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3600 + minute * 60 + second))
        .and_then(|value| value.checked_sub(offset))
    else {
        return Ok(None);
    };
    let Some((utc_year, utc_month, utc_day, utc_hour, utc_minute, utc_second)) =
        civil_from_timestamp(timestamp)
    else {
        return Ok(None);
    };
    let rendered = format!(
        "{utc_year:04}-{utc_month:02}-{utc_day:02}T{utc_hour:02}:{utc_minute:02}:{utc_second:02}Z"
    );
    copy_limited(rendered.as_bytes(), limit, "Git commit date").map(Some)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn civil_from_timestamp(timestamp: i64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_piece = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_piece + 2) / 5 + 1;
    let month = month_piece + if month_piece < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some((
        year,
        month,
        day,
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60,
    ))
}

fn split_inclusive_lines<'a>(
    input: &'a [u8],
    max_lines: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<&'a [u8]>> {
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(max_lines.min(4096))
        .map_err(|error| patch_allocation("Git patch lines", error))?;
    let mut start = 0;
    for (index, byte) in input.iter().enumerate() {
        if index % 4096 == 0 {
            poll_patch_cancellation(cancellation)?;
        }
        if *byte == b'\n' {
            if lines.len() >= max_lines {
                return Err(PatchError::Limit(format!(
                    "Git patch exceeds the configured {max_lines}-line ceiling"
                )));
            }
            lines
                .try_reserve(1)
                .map_err(|error| patch_allocation("Git patch lines", error))?;
            lines.push(&input[start..=index]);
            start = index + 1;
        }
    }
    if start < input.len() {
        if lines.len() >= max_lines {
            return Err(PatchError::Limit(format!(
                "Git patch exceeds the configured {max_lines}-line ceiling"
            )));
        }
        lines
            .try_reserve(1)
            .map_err(|error| patch_allocation("Git patch lines", error))?;
        lines.push(&input[start..]);
    }
    Ok(lines)
}

fn trim_line(value: &[u8]) -> &[u8] {
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    value.strip_suffix(b"\r").unwrap_or(value)
}

fn trim_unicode_space(mut value: &[u8]) -> &[u8] {
    value = trim_unicode_space_start(value);
    trim_unicode_space_end(value)
}

fn trim_unicode_space_start(mut value: &[u8]) -> &[u8] {
    while let Some((character, width)) = utf8_prefix(value) {
        if !is_go_space(character) {
            break;
        }
        value = &value[width..];
    }
    value
}

fn trim_unicode_space_end(mut value: &[u8]) -> &[u8] {
    while let Some((character, start)) = utf8_suffix(value) {
        if !is_go_space(character) {
            break;
        }
        value = &value[..start];
    }
    value
}

fn utf8_prefix(value: &[u8]) -> Option<(char, usize)> {
    let first = *value.first()?;
    let width = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let text = std::str::from_utf8(value.get(..width)?).ok()?;
    Some((text.chars().next()?, width))
}

fn utf8_suffix(value: &[u8]) -> Option<(char, usize)> {
    let mut start = value.len().checked_sub(1)?;
    while start > 0 && value[start] & 0xc0 == 0x80 {
        start -= 1;
    }
    let text = std::str::from_utf8(&value[start..]).ok()?;
    Some((text.chars().next()?, start))
}

fn is_go_space(character: char) -> bool {
    matches!(
        character,
        '\t'..='\r'
            | ' '
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn parse_usize(value: &[u8]) -> Result<usize, String> {
    std::str::from_utf8(value)
        .map_err(|_| "non-UTF-8 Git hunk range".to_owned())?
        .parse::<usize>()
        .map_err(|_| "invalid Git hunk range".to_owned())
}

fn terminal(stage: SourceStage, path: Option<PathBuf>, message: impl Into<String>) -> SourceError {
    SourceError::Terminal {
        stage,
        path,
        message: message.into(),
    }
}

fn patch_error_to_source(error: PatchError, repository: &std::path::Path) -> SourceError {
    match error {
        PatchError::Cancelled => SourceError::Cancelled,
        PatchError::Limit(message) => {
            terminal(SourceStage::Limit, Some(repository.into()), message)
        }
        PatchError::Invalid(message) => {
            terminal(SourceStage::GitParse, Some(repository.into()), message)
        }
    }
}

#[cfg(all(feature = "archives", unix))]
fn bytes_to_os_string(bytes: Vec<u8>) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes)
}

#[cfg(all(feature = "archives", not(unix)))]
fn bytes_to_os_string(bytes: Vec<u8>) -> OsString {
    OsString::from(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(feature = "archives")]
fn bytes_to_path_buf(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(bytes_to_os_string(bytes))
}

#[cfg(feature = "archives")]
fn object_spec(commit: &[u8], path: &[u8]) -> Result<OsString, SourceError> {
    let required = commit
        .len()
        .checked_add(path.len())
        .and_then(|size| size.checked_add(1))
        .ok_or_else(|| {
            terminal(
                SourceStage::Limit,
                None,
                "Git object specification size overflowed usize",
            )
        })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(required).map_err(|error| {
        terminal(
            SourceStage::Limit,
            None,
            format!("could not allocate Git object specification: {error}"),
        )
    })?;
    bytes.extend_from_slice(commit);
    bytes.push(b':');
    bytes.extend_from_slice(path);
    Ok(bytes_to_os_string(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CancelAfterPolls(std::sync::atomic::AtomicUsize);

    impl Cancellation for CancelAfterPolls {
        fn is_cancelled(&self) -> bool {
            let mut previous = self.0.load(Ordering::Acquire);
            loop {
                match self.0.compare_exchange_weak(
                    previous,
                    previous.saturating_sub(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => previous = observed,
                }
            }
            previous == 0
        }
    }

    #[cfg(unix)]
    struct CancelWhenFileContainsPid(PathBuf);

    #[cfg(unix)]
    impl Cancellation for CancelWhenFileContainsPid {
        fn is_cancelled(&self) -> bool {
            std::fs::read_to_string(&self.0)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|pid| pid != 0)
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected pipe read failure"))
        }
    }

    #[derive(Default)]
    #[allow(
        clippy::struct_excessive_bools,
        reason = "independent injected lifecycle outcomes"
    )]
    struct LifecycleProbe {
        terminated: bool,
        reaped: bool,
        fail_terminate: bool,
        fail_reap: bool,
    }

    impl GitChildLifecycle for LifecycleProbe {
        fn terminate(&mut self) -> io::Result<()> {
            self.terminated = true;
            if self.fail_terminate {
                Err(io::Error::other("injected terminate failure"))
            } else {
                Ok(())
            }
        }

        fn reap(&mut self) -> io::Result<()> {
            self.reaped = true;
            if self.fail_reap {
                Err(io::Error::other("injected reap failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn cleanup_attempts_reap_after_kill_failure_and_fails_closed() {
        for (fail_terminate, fail_reap) in [(true, false), (false, true), (true, true)] {
            let mut child = LifecycleProbe {
                fail_terminate,
                fail_reap,
                ..LifecycleProbe::default()
            };
            let error = stop_and_reap(&mut child, SourceStage::GitCommand, "injected")
                .expect_err("cleanup failure must be terminal");
            assert!(matches!(
                error,
                SourceError::Terminal {
                    stage: SourceStage::GitCommand,
                    ..
                }
            ));
            assert!(child.terminated);
            assert!(child.reaped);
        }
    }

    #[test]
    fn subprocess_fixture_waits() {
        if let Some(code) = std::env::var_os("RUSTLEAKS_GIT_CHILD_EXIT") {
            use std::io::Write as _;
            if let Some(length) = std::env::var_os("RUSTLEAKS_GIT_CHILD_STDOUT_BYTES") {
                let length = length.to_string_lossy().parse().expect("stdout byte count");
                std::io::stdout()
                    .write_all(&vec![b'x'; length])
                    .expect("write fixture stdout");
            }
            if let Some(stderr) = std::env::var_os("RUSTLEAKS_GIT_CHILD_STDERR") {
                std::io::stderr()
                    .write_all(stderr.to_string_lossy().as_bytes())
                    .expect("write fixture stderr");
            }
            let code = code.to_string_lossy().parse().expect("numeric exit code");
            std::process::exit(code);
        }
        if std::env::var_os("RUSTLEAKS_GIT_CANCEL_CHILD").is_none() {
            return;
        }
        if let Some(path) = std::env::var_os("RUSTLEAKS_GIT_CANCEL_PID_FILE") {
            std::fs::write(path, std::process::id().to_string()).expect("write child PID");
        }
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn cancellation_after_spawn_kills_reaps_and_joins_git_helpers() {
        let executable = std::env::current_exe().expect("current test executable");
        let arguments = [
            OsString::from("--exact"),
            OsString::from("git::tests::subprocess_fixture_waits"),
            OsString::from("--nocapture"),
        ];
        let environment = [(
            OsString::from("RUSTLEAKS_GIT_CANCEL_CHILD"),
            OsString::from("1"),
        )];
        let started = std::time::Instant::now();
        for stage in [SourceStage::GitCommand, SourceStage::GitBlob] {
            let cancellation = CancelAfterPolls(std::sync::atomic::AtomicUsize::new(4));
            let result = collect_command(
                executable.as_os_str(),
                &arguments,
                64 * 1024,
                64 * 1024,
                &environment,
                &cancellation,
                stage,
            );
            assert!(matches!(result, Err(SourceError::Cancelled)));
        }
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    fn cancelled_git_child_is_not_left_waitable_or_zombie() {
        let pid_path =
            std::env::temp_dir().join(format!("rustleaks-git-child-pid-{}", std::process::id()));
        let _ = std::fs::remove_file(&pid_path);
        let executable = std::env::current_exe().expect("current test executable");
        let arguments = [
            OsString::from("--exact"),
            OsString::from("git::tests::subprocess_fixture_waits"),
            OsString::from("--nocapture"),
        ];
        let environment = [
            (
                OsString::from("RUSTLEAKS_GIT_CANCEL_CHILD"),
                OsString::from("1"),
            ),
            (
                OsString::from("RUSTLEAKS_GIT_CANCEL_PID_FILE"),
                pid_path.as_os_str().to_owned(),
            ),
        ];
        let result = collect_command(
            executable.as_os_str(),
            &arguments,
            64 * 1024,
            64 * 1024,
            &environment,
            &CancelWhenFileContainsPid(pid_path.clone()),
            SourceStage::GitCommand,
        );
        assert!(matches!(result, Err(SourceError::Cancelled)));
        let raw_pid = std::fs::read_to_string(&pid_path)
            .expect("read selected child PID")
            .parse()
            .expect("selected child PID is numeric");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("selected child PID is nonzero");
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
            Err(error) if error == rustix::io::Errno::CHILD => {}
            Ok(Some((unreaped, status))) => {
                panic!("cancelled Git child PID {unreaped} remained waitable: {status:?}")
            }
            Ok(None) => panic!("cancelled Git child PID {pid} was still running"),
            Err(error) => panic!("could not verify cancelled Git child PID {pid}: {error}"),
        }
        std::fs::remove_file(pid_path).expect("remove child PID record");
    }

    #[test]
    fn matrix_b_text_patch_hunks_preserve_added_bytes_and_no_newline() {
        let patch = b"commit 0123456789abcdef\nAuthor: Test User <user@example.com>\nDate:   Tue Nov 2 18:37:53 2021 -0500\n\n    title\n\ndiff --git a/a.txt b/a.txt\nindex 1111111..2222222 100644\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1,2 @@\n-old\n+new\n+tail\n\\ No newline at end of file\n";
        let files = parse_patch(
            patch,
            GitLimits::default(),
            &crate::CancellationToken::new(),
        )
        .expect("patch");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, b"a.txt");
        assert_eq!(files[0].hunks[0].added, b"new\ntail");
        assert_eq!(files[0].hunks[0].new_position, 1);
        let metadata = files[0].metadata.as_ref().expect("metadata");
        assert_eq!(metadata.author_name().as_bytes(), b"Test User");
        assert_eq!(metadata.author_email().as_bytes(), b"user@example.com");
        assert_eq!(metadata.date().as_bytes(), b"2021-11-02T23:37:53Z");
        assert_eq!(metadata.message().as_bytes(), b"title");
    }

    #[test]
    fn matrix_c_strict_byte_paths_decode_git_quoting() {
        assert_eq!(
            decode_patch_path(
                br#""b/tab\tand\303\251.txt""#,
                true,
                1024,
                &crate::CancellationToken::new(),
            )
            .expect("path"),
            b"tab\tand\xc3\xa9.txt"
        );
        assert_eq!(
            decode_patch_path(
                br#""b/invalid-\377""#,
                true,
                1024,
                &crate::CancellationToken::new(),
            )
            .expect("invalid UTF-8 path"),
            b"invalid-\xff"
        );
        assert_eq!(
            decode_patch_path(
                b"b/repeated///slash",
                true,
                1024,
                &crate::CancellationToken::new(),
            )
            .expect("repeated slash path"),
            b"repeated/slash"
        );
    }

    #[test]
    fn matrix_a_exact_argv_preserves_literal_space_splitting() {
        let source = GitSource::new("repo").mode(GitMode::Log {
            options: Some("--all  foo...".to_owned()),
        });
        assert_eq!(
            source
                .arguments()
                .iter()
                .map(|value| value.to_string_lossy())
                .collect::<Vec<_>>(),
            ["-C", "repo", "log", "-p", "-U0", "--all", "", "foo..."]
        );

        assert_eq!(GitSource::new("").arguments()[1].to_string_lossy(), ".");
        let arguments = GitSource::new("repo space/é")
            .mode(GitMode::LogArguments(vec![
                OsString::from("-U3"),
                OsString::from("--pretty=short"),
                OsString::from("--no-patch"),
            ]))
            .arguments();
        assert_eq!(arguments[0], "-C");
        assert_eq!(
            PathBuf::from(arguments[1].as_os_str()),
            PathBuf::from("repo space/é")
        );
        assert_eq!(
            arguments[2..]
                .iter()
                .map(|value| value.to_string_lossy())
                .collect::<Vec<_>>(),
            ["log", "-p", "-U0", "-U3", "--pretty=short", "--no-patch"]
        );

        let explicit = GitSource::new("repo").mode(GitMode::LogArguments(vec![
            OsString::from("--all"),
            OsString::from("path with spaces"),
        ]));
        assert_eq!(
            explicit
                .arguments()
                .iter()
                .map(|value| value.to_string_lossy())
                .collect::<Vec<_>>(),
            [
                "-C",
                "repo",
                "log",
                "-p",
                "-U0",
                "--all",
                "path with spaces"
            ]
        );
    }

    #[test]
    fn classifies_only_pinned_stderr_warnings_as_ignorable() {
        assert!(first_non_ignored_stderr(b"Auto packing the repository in background for optimum performance.\nSee \"git help gc\" for manual housekeeping.\n").is_none());
        assert_eq!(
            first_non_ignored_stderr(b"warning\nfatal: broken\n"),
            Some(b"warning".as_slice())
        );
        assert_eq!(first_non_ignored_stderr(b"\n"), Some(b"".as_slice()));
        assert_eq!(
            first_non_ignored_stderr(b"warning\r\n"),
            Some(b"warning".as_slice())
        );
    }

    #[test]
    fn matrix_j_resource_boundaries_fail_closed() {
        assert!(GitLimits::new(0, 1, 1, 1).is_err());
        assert!(GitLimits::new(1, 0, 1, 1).is_err());
        assert!(GitLimits::new(1, 1, 0, 1).is_err());
        assert!(GitLimits::new(1, 1, 1, 0).is_err());
        assert!(GitLimits::default().with_parser_limits(0, 1, 1, 1).is_err());
        assert!(GitLimits::default().with_parser_limits(1, 0, 1, 1).is_err());
        assert!(GitLimits::default().with_parser_limits(1, 1, 0, 1).is_err());
        assert!(GitLimits::default().with_parser_limits(1, 1, 1, 0).is_err());

        let exceeded = AtomicBool::new(false);
        let (retained, limited) =
            read_bounded_and_drain(io::Cursor::new(b"abcdef"), 5, &exceeded).expect("bounded read");
        assert_eq!(retained, b"abcde");
        assert!(limited);
        assert!(exceeded.load(Ordering::Acquire));

        let exact = AtomicBool::new(false);
        let (retained, limited) =
            read_bounded_and_drain(io::Cursor::new(b"abcde"), 5, &exact).expect("exact read");
        assert_eq!(retained, b"abcde");
        assert!(!limited);
        assert!(!exact.load(Ordering::Acquire));

        let limits = GitLimits::new(64, 2, 64, 64).expect("limits");
        assert!(parse_patch(b"\n\n", limits, &crate::CancellationToken::new()).is_ok());
        assert!(
            parse_patch(
                b"one\ntwo\nthree\n",
                limits,
                &crate::CancellationToken::new()
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table covers every command outcome class"
    )]
    fn matrix_h_exit_status_and_bounded_stderr_are_diagnostic() {
        let executable = std::env::current_exe().expect("current test executable");
        let arguments = [
            OsString::from("--exact"),
            OsString::from("git::tests::subprocess_fixture_waits"),
            OsString::from("--nocapture"),
        ];
        let environment = [
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
                OsString::from("7"),
            ),
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
                OsString::from("fixture stderr"),
            ),
        ];
        let output = collect_command(
            executable.as_os_str(),
            &arguments,
            64 * 1024,
            64 * 1024,
            &environment,
            &crate::CancellationToken::new(),
            SourceStage::GitCommand,
        )
        .expect("collect child failure");
        let message = git_exit_message(output.status, &output.stderr);
        assert!(message.contains('7'), "{message}");
        assert!(message.contains("fixture stderr"), "{message}");
        #[cfg(feature = "archives")]
        assert!(matches!(
            validate_archive_blob_output(&output, std::path::Path::new("repository")),
            Err(SourceError::Terminal {
                stage: SourceStage::GitBlob,
                ..
            })
        ));

        for stderr in ["", "exhaustive rename detection was skipped\n"] {
            let environment = [
                (
                    OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
                    OsString::from("9"),
                ),
                (
                    OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
                    OsString::from(stderr),
                ),
            ];
            let output = collect_command(
                executable.as_os_str(),
                &arguments,
                64,
                64,
                &environment,
                &crate::CancellationToken::new(),
                SourceStage::GitCommand,
            )
            .expect("collect nonzero fixture");
            assert!(!output.status.expect("status").success());
            assert!(git_exit_message(output.status, &output.stderr).contains('9'));
        }

        let overflow_environment = [
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_EXIT"),
                OsString::from("0"),
            ),
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_STDERR"),
                OsString::from("12345"),
            ),
            (
                OsString::from("RUSTLEAKS_GIT_CHILD_STDOUT_BYTES"),
                OsString::from("5"),
            ),
        ];
        let exact = collect_command(
            executable.as_os_str(),
            &arguments,
            64 * 1024,
            5,
            &overflow_environment,
            &crate::CancellationToken::new(),
            SourceStage::GitBlob,
        )
        .expect("exact command boundaries");
        assert!(!exact.stdout_limited);
        assert!(!exact.stderr_limited);
        assert!(exact.stdout.contains(&b'x'));
        #[cfg(feature = "archives")]
        assert!(
            validate_archive_blob_output(&exact, std::path::Path::new("repository"))
                .expect("successful blob classification")
                .is_some()
        );
        let overflow = collect_command(
            executable.as_os_str(),
            &arguments,
            64 * 1024,
            4,
            &overflow_environment,
            &crate::CancellationToken::new(),
            SourceStage::GitBlob,
        )
        .expect("overflow command boundaries");
        assert!(!overflow.stdout_limited);
        assert!(overflow.stderr_limited);
        #[cfg(feature = "archives")]
        assert!(matches!(
            validate_archive_blob_output(&overflow, std::path::Path::new("repository")),
            Err(SourceError::Terminal {
                stage: SourceStage::Limit,
                ..
            })
        ));

        let missing = collect_command(
            OsStr::new("rustleaks-deliberately-missing-git-executable"),
            &[],
            1,
            1,
            &[],
            &crate::CancellationToken::new(),
            SourceStage::GitCommand,
        );
        assert!(matches!(
            missing,
            Err(SourceError::Terminal {
                stage: SourceStage::GitCommand,
                ..
            })
        ));
    }

    #[test]
    fn matrix_d_metadata_uses_go_unicode_whitespace() {
        let patch = "commit abc\nAuthor: \u{3000}A User\u{00a0} <a@example.com>\nDate:   Tue Nov 2 18:37:53 2021 -0500\n\n    \u{3000}title\u{00a0}\n\ndiff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
        let files = parse_patch(
            patch.as_bytes(),
            GitLimits::default(),
            &crate::CancellationToken::new(),
        )
        .expect("Unicode metadata patch");
        let metadata = files[0].metadata.as_ref().expect("metadata");
        assert_eq!(metadata.author_name().as_bytes(), b"A User");
        assert_eq!(metadata.message().as_bytes(), b"title");

        let fuller = b"commit abc\nAuthor: A User <a@example.com>\nAuthorDate: Tue Nov 2 18:37:53 2021 -0500\nCommit: C User <c@example.com>\nCommitDate: Wed Nov 3 18:37:53 2021 -0500\n\n    fuller title\n\ndiff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
        let files = parse_patch(
            fuller,
            GitLimits::default(),
            &crate::CancellationToken::new(),
        )
        .expect("fuller metadata patch");
        let metadata = files[0].metadata.as_ref().expect("fuller metadata");
        assert_eq!(metadata.author_name().as_bytes(), b"A User");
        assert_eq!(metadata.date().as_bytes(), b"2021-11-02T23:37:53Z");
        assert_eq!(metadata.message().as_bytes(), b"fuller title");
    }

    #[test]
    fn malformed_diff_and_hunk_fail_closed() {
        for patch in [
            b"arbitrary non-patch output\n".as_slice(),
            b"diff --git a/x b/x\nnonsense\n".as_slice(),
            b"diff --git a/x b/x\n--- a/x\n".as_slice(),
            b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n".as_slice(),
            b"diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+x\n+surplus\n".as_slice(),
        ] {
            assert!(matches!(
                parse_patch(
                    patch,
                    GitLimits::default(),
                    &crate::CancellationToken::new()
                ),
                Err(PatchError::Invalid(_))
            ));
        }
    }

    #[test]
    fn matrix_j_cancellation_is_polled_during_large_parser_streams() {
        let input = vec![b'x'; 64 * 1024];
        assert!(matches!(
            parse_patch(
                &input,
                GitLimits::default(),
                &CancelAfterPolls(std::sync::atomic::AtomicUsize::new(2)),
            ),
            Err(PatchError::Cancelled)
        ));
    }

    #[test]
    fn matrix_k_parser_resource_boundaries_are_exact() {
        let cancellation = crate::CancellationToken::new();
        assert_eq!(
            decode_patch_path(b"b/abcd", true, 4, &cancellation).expect("exact path"),
            b"abcd"
        );
        assert!(matches!(
            decode_patch_path(b"b/abcde", true, 4, &cancellation),
            Err(PatchError::Limit(_))
        ));

        let one_file = b"diff --git a/abcd b/abcd\n--- a/abcd\n+++ b/abcd\n@@ -0,0 +1 @@\n+x\n";
        let two_files = b"diff --git a/abcd b/abcd\n--- a/abcd\n+++ b/abcd\ndiff --git a/efgh b/efgh\n--- a/efgh\n+++ b/efgh\n";
        let two_hunks = b"diff --git a/abcd b/abcd\n--- a/abcd\n+++ b/abcd\n@@ -0,0 +1 @@\n+x\n@@ -0,0 +1 @@\n+y\n";
        let exact = GitLimits::default()
            .with_parser_limits(20, 4, 1, 1)
            .expect("exact parser limits");
        assert!(parse_patch(one_file, exact, &cancellation).is_ok());
        assert!(matches!(
            parse_patch(two_files, exact, &cancellation),
            Err(PatchError::Limit(_))
        ));
        assert!(matches!(
            parse_patch(two_hunks, exact, &cancellation),
            Err(PatchError::Limit(_))
        ));
        let metadata_over = GitLimits::default()
            .with_parser_limits(19, 4, 1, 1)
            .expect("metadata over limit");
        assert!(matches!(
            parse_patch(one_file, metadata_over, &cancellation),
            Err(PatchError::Limit(_))
        ));

        assert!(read_bounded_and_drain(FailingReader, 8, &AtomicBool::new(false)).is_err());
        assert!(matches!(
            reserve_input(&mut Vec::new(), usize::MAX, "injected allocation"),
            Err(PatchError::Limit(_))
        ));
    }

    #[test]
    fn safe_portable_boundary_has_no_owned_unsafe() {
        let production = include_str!("git.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production prefix");
        assert!(!production.contains("unsafe {"));
        assert!(!production.contains("std::os::windows"));
    }
}
