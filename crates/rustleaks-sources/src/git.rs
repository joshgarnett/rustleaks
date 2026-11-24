use std::ffi::OsString;
#[cfg(feature = "archives")]
use std::io;
use std::num::NonZeroUsize;
use std::path::PathBuf;
#[cfg(feature = "archives")]
use std::process::ExitStatus;

use rustleaks_core::model::Fragment;

#[cfg(feature = "archives")]
use crate::archive::spool::{PushSpool, Spool};
#[cfg(feature = "archives")]
use crate::file::FragmentCommit;
use crate::source::emit_issue;
#[cfg(feature = "archives")]
use crate::{ArchiveOptions, ArchiveSource};
use crate::{
    CallbackError, Cancellation, Source, SourceConfigError, SourceControl, SourceError,
    SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

mod history;
mod patch;
mod process;
mod text;

#[cfg(feature = "fuzzing")]
pub use patch::fuzz_parse_patch;

use patch::{
    ParsedFile, PatchStream, copy_limited, fallible_clone_metadata, patch_error_to_source,
};
#[cfg(feature = "archives")]
use process::stream_command;
use process::{
    CommandIo, OutputBudget, StreamedOutput, first_non_ignored_stderr, git_exit_message,
    stream_command_with,
};

// Patch, line, file, hunk and metadata ceilings apply to one commit. History
// output is parsed one file record at a time, so these values do not bound
// the size of a whole history.
const DEFAULT_MAX_PATCH_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024 * 1024).unwrap();
const DEFAULT_MAX_PATCH_LINES: NonZeroUsize = NonZeroUsize::new(16_000_000).unwrap();
const DEFAULT_MAX_STDERR_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();
const DEFAULT_MAX_BLOB_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024 * 1024).unwrap();
const DEFAULT_MAX_METADATA_BYTES: NonZeroUsize = NonZeroUsize::new(16 * 1024 * 1024).unwrap();
const DEFAULT_MAX_PATH_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();
const DEFAULT_MAX_FILES: NonZeroUsize = NonZeroUsize::new(1_000_000).unwrap();
const DEFAULT_MAX_HUNKS: NonZeroUsize = NonZeroUsize::new(2_000_000).unwrap();

/// Git history or worktree/index selection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GitMode {
    /// Scan `git log -p -U0`, using the default options when none are given.
    Log {
        /// Literal space-delimited arguments appended after `-U0`.
        options: Option<String>,
    },
    /// Scan history with explicit shell-free arguments after the default prefix.
    LogArguments(Vec<OsString>),
    /// Scan a worktree or staged-index diff.
    Diff {
        /// Insert `--staged` before the default pathspec.
        staged: bool,
    },
}

impl Default for GitMode {
    fn default() -> Self {
        Self::Log { options: None }
    }
}

/// Checked ceilings for Git subprocess output and archive blobs.
///
/// Rustleaks reads `git log` and `git diff` output while Git runs. The patch
/// byte, patch line, file, hunk and metadata ceilings apply to the output of
/// one commit, from its `commit` line to the next one. A `git diff` has no
/// commit lines, so its whole output is one commit for these ceilings.
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
            ..Self::default()
        })
    }

    /// Replaces parser-state ceilings for one commit's metadata, one path,
    /// the files of one commit, and the hunks of one commit.
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

    /// Returns the patch-output ceiling for one commit.
    #[must_use]
    pub const fn patch_bytes(self) -> usize {
        self.patch.get()
    }

    /// Returns the patch line-count ceiling for one commit.
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

    /// Returns the file-count ceiling for one commit.
    #[must_use]
    pub const fn files(self) -> usize {
        self.files.get()
    }

    /// Returns the hunk-count ceiling for one commit.
    #[must_use]
    pub const fn hunks(self) -> usize {
        self.hunks.get()
    }
}

impl Default for GitLimits {
    fn default() -> Self {
        Self {
            patch: DEFAULT_MAX_PATCH_BYTES,
            lines: DEFAULT_MAX_PATCH_LINES,
            stderr: DEFAULT_MAX_STDERR_BYTES,
            blob: DEFAULT_MAX_BLOB_BYTES,
            metadata: DEFAULT_MAX_METADATA_BYTES,
            path: DEFAULT_MAX_PATH_BYTES,
            files: DEFAULT_MAX_FILES,
            hunks: DEFAULT_MAX_HUNKS,
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
    history_processes: NonZeroUsize,
    history_batch_commits: Option<NonZeroUsize>,
    #[cfg(feature = "archives")]
    archives: Option<ArchiveOptions>,
    #[cfg(feature = "archives")]
    archive_file_options: crate::FileOptions,
}

/// Configuration that every `git log` and `git diff` of the source sets. A
/// repository's `core.fsmonitor` can name a command that Git starts when it
/// reads the index. An empty value turns the monitor off in Git versions
/// that read the value as a flag and in those that read it as a hook path.
pub(super) const CONFIG_OVERRIDES: [&str; 2] = ["-c", "core.fsmonitor="];

/// Object names of the empty tree in SHA-1 and SHA-256 repositories.
const EMPTY_TREE_SHA1: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const EMPTY_TREE_SHA256: &str = "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321";

/// Returns the empty tree name for `git rev-parse --show-object-format`
/// output. A Git version without the option prints it back; such a version
/// reads only SHA-1 repositories.
fn empty_tree_for_format(output: &[u8]) -> &'static str {
    if output.trim_ascii_end() == b"sha256" {
        EMPTY_TREE_SHA256
    } else {
        EMPTY_TREE_SHA1
    }
}

/// The `-c attr.tree=<empty tree>` override for `git log` and
/// `git diff --staged`. A repository's `.gitattributes` can mark a text file
/// as binary (`-diff` or `binary`), and Git then shows no patch for it.
/// Reading attributes from the empty tree lets Git decide from the content
/// alone: a file with a NUL byte near its start is binary, including one
/// that the repository's attributes mark as text (`diff`). Git 2.43 and
/// later read `attr.tree`; earlier versions ignore it. `GIT_ATTR_SOURCE`
/// takes precedence, so these commands run without it. A value that does
/// not name a tree of the repository's object format has no effect, so the
/// name must match it. A worktree `git diff` keeps the attributes, since it
/// needs the clean filters that they name.
fn attribute_override(empty_tree: &str) -> [OsString; 2] {
    [
        OsString::from("-c"),
        OsString::from(format!("attr.tree={empty_tree}")),
    ]
}

/// Options for every `git diff` that the source runs. A repository's own
/// configuration and attributes can name commands for textconv filters and
/// external diff tools; these options keep Git from running them and keep
/// the raw content in the patch. `--no-color` keeps the output parseable
/// when a user configuration sets `color.ui=always`.
pub(super) const DIFF_OPTIONS: [&str; 3] = ["--no-textconv", "--no-ext-diff", "--no-color"];

/// Options for every `git log` that the source runs: [`DIFF_OPTIONS`] and
/// `--no-show-signature`, which keeps `log.showSignature` from starting the
/// configured signature program. Caller `--log-opts` come after these and
/// can turn them back on.
pub(super) const LOG_OPTIONS: [&str; 4] = [
    "--no-textconv",
    "--no-ext-diff",
    "--no-color",
    "--no-show-signature",
];

impl GitSource {
    /// Creates a Git source using the default history command.
    #[must_use]
    pub fn new(repository: impl Into<PathBuf>) -> Self {
        Self {
            executable: OsString::from("git"),
            repository: crate::path::clean_native_path(&repository.into()),
            mode: GitMode::default(),
            limits: GitLimits::default(),
            environment: Vec::new(),
            history_processes: NonZeroUsize::MIN,
            history_batch_commits: None,
            #[cfg(feature = "archives")]
            archives: None,
            #[cfg(feature = "archives")]
            archive_file_options: crate::FileOptions::default(),
        }
    }

    /// Selects file assembly for archive blobs without changing text hunk scope.
    #[cfg(feature = "archives")]
    #[must_use]
    pub const fn archive_file_options(mut self, options: crate::FileOptions) -> Self {
        self.archive_file_options = options;
        self
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

    /// Sets the most `git log` processes that read history at the same time.
    ///
    /// The default is one. With more, and with the default history options,
    /// the source lists the commits with `git rev-list`, shows consecutive
    /// batches of them with separate `git log` processes, and parses their
    /// output in list order. The parser reads the same bytes as from one
    /// `git log` process, so fragments, their order, issues and error stages
    /// do not change. Only the Git error text of a failed batch can differ.
    /// Other modes and history options, a configured `format.pretty`, and
    /// histories of one batch use one process.
    #[must_use]
    pub const fn history_processes(mut self, processes: NonZeroUsize) -> Self {
        self.history_processes = processes;
        self
    }

    /// Sets the commits that each `git log` process shows when several
    /// processes read history.
    ///
    /// The default is 250. Larger batches start fewer processes, but each
    /// process uses more memory as it reads more commits, and more output
    /// waits for the parser.
    #[must_use]
    pub const fn history_batch_commits(mut self, commits: NonZeroUsize) -> Self {
        self.history_batch_commits = Some(commits);
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

    /// Whether the Git command of this mode reads attributes from the empty
    /// tree. See [`attribute_override`].
    const fn reads_empty_attributes(&self) -> bool {
        !matches!(self.mode, GitMode::Diff { staged: false })
    }

    /// Returns the name of the empty tree in the repository's object format.
    /// When Git cannot report the format, such as outside a repository, this
    /// is the SHA-1 name; the scan command then reports any failure itself.
    fn empty_tree(&self, cancellation: &dyn Cancellation) -> Result<&'static str, SourceError> {
        let mut arguments = vec![OsString::from("-C"), self.repository.as_os_str().to_owned()];
        arguments.extend(CONFIG_OVERRIDES.map(OsString::from));
        arguments.extend([
            OsString::from("rev-parse"),
            OsString::from("--show-object-format"),
        ]);
        let mut output = Vec::new();
        let result = stream_command_with(
            &self.executable,
            &arguments,
            CommandIo {
                input: None,
                stderr: &OutputBudget::new(self.limits.stderr_bytes()),
                clear_attribute_source: true,
            },
            &self.environment,
            cancellation,
            SourceStage::GitCommand,
            &mut |chunk| {
                if output.len().saturating_add(chunk.len()) > 64 {
                    return Ok(SourceControl::Stop);
                }
                output.extend_from_slice(&chunk);
                Ok(SourceControl::Continue)
            },
        );
        match result {
            Ok(listed)
                if !listed.stopped && listed.status.is_some_and(|status| status.success()) =>
            {
                Ok(empty_tree_for_format(&output))
            }
            Err(SourceError::Cancelled) => Err(SourceError::Cancelled),
            Ok(_) | Err(_) => Ok(EMPTY_TREE_SHA1),
        }
    }

    fn arguments(&self, empty_tree: &str) -> Vec<OsString> {
        let mut arguments = vec![OsString::from("-C"), self.repository.as_os_str().to_owned()];
        arguments.extend(CONFIG_OVERRIDES.map(OsString::from));
        if self.reads_empty_attributes() {
            arguments.extend(attribute_override(empty_tree));
        }
        match &self.mode {
            GitMode::Log { options } => {
                arguments.extend([
                    OsString::from("log"),
                    OsString::from("-p"),
                    OsString::from("-U0"),
                ]);
                arguments.extend(LOG_OPTIONS.map(OsString::from));
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
                arguments.extend(LOG_OPTIONS.map(OsString::from));
                arguments.extend(options.iter().cloned());
            }
            GitMode::Diff { staged } => {
                arguments.extend([OsString::from("diff"), OsString::from("-U0")]);
                arguments.extend(DIFF_OPTIONS.map(OsString::from));
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
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let this = &*self;
        let empty_tree = if this.reads_empty_attributes() {
            this.empty_tree(cancellation)?
        } else {
            EMPTY_TREE_SHA1
        };
        if let Some(plan) = history::plan(this, cancellation)? {
            return history::visit(this, &plan, empty_tree, cancellation, emit);
        }
        let mut stream = PatchStream::new(this.limits);
        // Each file record is parsed and emitted once the next record starts,
        // so memory follows the largest record instead of the whole history.
        // The last record waits for Git to exit successfully.
        let output = stream_command_with(
            &this.executable,
            &this.arguments(empty_tree),
            CommandIo {
                input: None,
                stderr: &OutputBudget::new(this.limits.stderr_bytes()),
                clear_attribute_source: this.reads_empty_attributes(),
            },
            &this.environment,
            cancellation,
            SourceStage::GitCommand,
            &mut |chunk| {
                stream
                    .push(&chunk)
                    .map_err(|error| patch_error_to_source(error, &this.repository))?;
                this.emit_ready_files(&mut stream, cancellation, emit)
            },
        )?;
        if output.stopped {
            return Ok(SourceControl::Stop);
        }
        if output.stderr_limited {
            return Err(this.stderr_exceeded());
        }
        if !output.status.is_some_and(|status| status.success()) {
            return Err(this.exit_error(&output));
        }
        let warned = first_non_ignored_stderr(&output.stderr).is_some();
        this.finish_history(stream, warned, cancellation, emit)
    }
}

impl GitSource {
    fn stderr_exceeded(&self) -> SourceError {
        SourceError::terminal(
            SourceStage::Limit,
            Some(self.repository.clone()),
            "Git standard error exceeded its configured byte ceiling",
        )
    }

    fn exit_error(&self, output: &StreamedOutput) -> SourceError {
        SourceError::terminal(
            SourceStage::GitExit,
            Some(self.repository.clone()),
            git_exit_message(output.status, &output.stderr),
        )
    }

    /// Ends a history scan after every Git process succeeded: reports a Git
    /// warning on standard error, then publishes the last file record.
    fn finish_history(
        &self,
        mut stream: PatchStream,
        warned: bool,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if warned {
            let control = emit_issue(
                SourceIssue::new(
                    SourceStage::GitCommand,
                    SourceIssueKind::GitStderr,
                    Some(self.repository.clone()),
                    "stderr is not empty",
                ),
                emit,
            )?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        stream.finish();
        self.emit_ready_files(&mut stream, cancellation, emit)
    }

    fn emit_ready_files(
        &self,
        stream: &mut PatchStream,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        while let Some(file) = stream
            .next_file(cancellation)
            .map_err(|error| patch_error_to_source(error, &self.repository))?
        {
            if self.emit_file(file, cancellation, emit)? == SourceControl::Stop {
                return Ok(SourceControl::Stop);
            }
        }
        Ok(SourceControl::Continue)
    }

    fn emit_file(
        &self,
        mut file: ParsedFile,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        if file.deleted {
            return Ok(SourceControl::Continue);
        }
        if file.binary {
            #[cfg(feature = "archives")]
            if let Some(options) = self.archives.clone()
                && crate::archive::name_is_archive(
                    &file.path,
                    self.archive_file_options.complete_target_bytes().is_some(),
                )
            {
                return self.visit_archive_blob(&file, options, cancellation, emit);
            }
            return Ok(SourceControl::Continue);
        }
        let mut hunks = file.hunks.into_iter().peekable();
        while let Some(hunk) = hunks.next() {
            let (path, commit, metadata) = if hunks.peek().is_none() {
                // Parsing already checked these limits. The final hunk can
                // consume the fields that earlier hunks still need to copy.
                (
                    std::mem::take(&mut file.path),
                    std::mem::take(&mut file.commit),
                    file.metadata.take(),
                )
            } else {
                let path = copy_limited(&file.path, self.limits.path_bytes(), "Git fragment path")
                    .map_err(|error| patch_error_to_source(error, &self.repository))?;
                let commit = copy_limited(
                    &file.commit,
                    self.limits.metadata_bytes(),
                    "Git fragment commit SHA",
                )
                .map_err(|error| patch_error_to_source(error, &self.repository))?;
                let metadata = file
                    .metadata
                    .as_ref()
                    .map(|value| fallible_clone_metadata(value, self.limits.metadata_bytes()))
                    .transpose()
                    .map_err(|error| patch_error_to_source(error, &self.repository))?;
                (path, commit, metadata)
            };
            let mut builder = Fragment::builder(hunk.added)
                .file_path(path)
                .commit(commit)
                .start_line(hunk.new_position);
            if let Some(metadata) = metadata {
                builder = builder.commit_metadata(metadata);
            }
            let control =
                emit(SourceEvent::fragment(builder.build())).map_err(SourceError::Callback)?;
            if control == SourceControl::Stop {
                return Ok(control);
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
        let logical = bytes_to_path_buf(
            copy_limited(&file.path, self.limits.path_bytes(), "Git archive path")
                .map_err(|error| patch_error_to_source(error, &self.repository))?,
        );
        // The blob streams into a spool: memory for a small blob, otherwise
        // an anonymous temporary file. ZIP and 7z need random access, and the
        // spool keeps memory bounded for every format.
        let limit = self
            .limits
            .blob_bytes()
            .min(options.limits().maximum_spool_bytes());
        let mut blob = PushSpool::new(limit, crate::archive::spool::MEMORY_SPOOL_BYTES);
        let mut limited = false;
        let mut write_error = None;
        let output = stream_command(
            &self.executable,
            &[
                OsString::from("-C"),
                self.repository.as_os_str().to_owned(),
                OsString::from("cat-file"),
                OsString::from("blob"),
                object,
            ],
            self.limits.stderr_bytes(),
            &self.environment,
            cancellation,
            SourceStage::GitBlob,
            &mut |chunk| match blob.push(chunk) {
                Ok(true) => Ok(SourceControl::Continue),
                Ok(false) => {
                    limited = true;
                    Ok(SourceControl::Stop)
                }
                Err(error) => {
                    write_error = Some(error);
                    Ok(SourceControl::Stop)
                }
            },
        )?;
        if output.stopped {
            // Git was stopped and reaped. Skip this blob like an archive
            // that reaches a limit, and go on with the history.
            let issue = if limited {
                SourceIssue::new(
                    SourceStage::Limit,
                    SourceIssueKind::Limit,
                    Some(logical),
                    "Git archive blob exceeds its byte limit",
                )
            } else {
                let error = write_error.map_or_else(String::new, |error| error.to_string());
                SourceIssue::new(
                    SourceStage::GitBlob,
                    SourceIssueKind::Read,
                    Some(logical),
                    format!("could not store a Git archive blob: {error}"),
                )
            };
            return emit_issue(issue, emit);
        }
        if let Some(issue) = validate_archive_blob_output(
            output.stderr_limited,
            output.status,
            &output.stderr,
            &self.repository,
        )? {
            let control = emit_issue(issue, emit)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        let commit = FragmentCommit {
            sha: copy_limited(
                &file.commit,
                self.limits.metadata_bytes(),
                "Git archive commit SHA",
            )
            .map_err(|error| patch_error_to_source(error, &self.repository))?,
            metadata: file
                .metadata
                .as_ref()
                .map(|value| fallible_clone_metadata(value, self.limits.metadata_bytes()))
                .transpose()
                .map_err(|error| patch_error_to_source(error, &self.repository))?,
        };
        let archive = match blob.finish() {
            Spool::Memory(bytes) => ArchiveSource::with_options(
                io::Cursor::new(bytes),
                logical,
                self.archive_file_options,
                options,
            ),
            Spool::File(file) => ArchiveSource::from_file(
                file.into_file(),
                logical,
                self.archive_file_options,
                options,
            ),
        };
        // Fragments carry the commit from the start, so their bytes are
        // never copied again.
        archive.with_commit(commit).visit(cancellation, emit)
    }
}

/// Classifies how `git cat-file` ended: a failure stops the scan, and
/// unexpected standard error is an issue.
#[cfg(feature = "archives")]
fn validate_archive_blob_output(
    stderr_limited: bool,
    status: Option<ExitStatus>,
    stderr: &[u8],
    repository: &std::path::Path,
) -> Result<Option<SourceIssue>, SourceError> {
    if stderr_limited {
        return Err(SourceError::terminal(
            SourceStage::Limit,
            Some(repository.into()),
            "Git archive-blob stderr exceeded its configured byte ceiling",
        ));
    }
    if !status.is_some_and(|status| status.success()) {
        return Err(SourceError::terminal(
            SourceStage::GitBlob,
            Some(repository.into()),
            git_exit_message(status, stderr),
        ));
    }
    if first_non_ignored_stderr(stderr).is_some() {
        return Ok(Some(SourceIssue::new(
            SourceStage::GitBlob,
            SourceIssueKind::GitStderr,
            Some(repository.into()),
            "stderr is not empty",
        )));
    }
    Ok(None)
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
            SourceError::terminal(
                SourceStage::Limit,
                None,
                "Git object specification size overflowed usize",
            )
        })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(required).map_err(|error| {
        SourceError::terminal(
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
mod tests;
