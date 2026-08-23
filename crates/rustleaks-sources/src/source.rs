use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use rustleaks_core::model::Fragment;

use crate::Cancellation;

/// Invalid positive-size source or runner configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceConfigError {
    field: &'static str,
}

impl SourceConfigError {
    pub(crate) const fn positive(field: &'static str) -> Self {
        Self { field }
    }

    /// Returns the invalid configuration field.
    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for SourceConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} must be greater than zero", self.field)
    }
}

impl Error for SourceConfigError {}

/// The source operation at which a recoverable issue occurred.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SourceStage {
    /// Archive-name classification.
    ArchiveIdentify,
    /// Archive container parsing or enumeration.
    Archive,
    /// Opening or reading one archive member.
    ArchiveMember,
    /// Decompressing a stream or member.
    Decode,
    /// Building a bounded in-memory seekable spool.
    Spool,
    /// Directory discovery or enumeration.
    Traverse,
    /// Filesystem metadata lookup.
    Metadata,
    /// Symlink resolution or validation.
    Symlink,
    /// Opening a discovered file.
    Open,
    /// The nominal file read.
    Read,
    /// Safe-boundary read-ahead.
    BoundaryRead,
    /// Checked resource or arithmetic limit enforcement.
    Limit,
    /// Source callback delivery.
    Callback,
    /// A worker in the bounded runner.
    Worker,
    /// Starting, waiting for, or collecting a Git subprocess.
    GitCommand,
    /// Parsing Git patch output.
    GitParse,
    /// A Git child exited unsuccessfully after its pipes were drained.
    GitExit,
    /// Reading an archive blob through `git cat-file`.
    GitBlob,
}

/// Stable category for a recoverable source issue.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SourceIssueKind {
    /// A recognized archive container is corrupt.
    CorruptArchive,
    /// One archive member could not be opened or read.
    ArchiveMember,
    /// Compressed data could not be decoded or verified.
    Decode,
    /// A recognized format is outside the selected native decoder boundary.
    UnsupportedArchive,
    /// A path or object was not present.
    NotFound,
    /// Access was denied by the operating system.
    PermissionDenied,
    /// Metadata could not be obtained or interpreted.
    Metadata,
    /// A file could not be opened.
    Open,
    /// A read failed.
    Read,
    /// Read-ahead failed before a safe boundary.
    BoundaryRead,
    /// A symlink target does not exist.
    DanglingSymlink,
    /// A symlink cycle or hop ceiling was reached.
    SymlinkLoop,
    /// A followed symlink resolved to a directory and was not traversed.
    DirectorySymlink,
    /// A configured or representable limit was exceeded.
    Limit,
    /// A detection worker terminated unexpectedly.
    WorkerPanic,
    /// Git wrote a non-ignorable diagnostic to standard error.
    GitStderr,
    /// Git patch output could not be parsed.
    GitParse,
    /// A Git subprocess could not be started or collected.
    GitCommand,
}

/// Structured, recoverable source diagnostic.
///
/// Issues are data, not logging side effects. A [`SourceEvent::Fragment`] can
/// carry one together with successfully read bytes, preserving upstream's
/// `n > 0` plus non-EOF error outcome without making the fragment unobservable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIssue {
    stage: SourceStage,
    kind: SourceIssueKind,
    path: Option<PathBuf>,
    message: String,
}

impl SourceIssue {
    /// Creates a structured issue.
    #[must_use]
    pub fn new(
        stage: SourceStage,
        kind: SourceIssueKind,
        path: Option<PathBuf>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            kind,
            path,
            message: message.into(),
        }
    }

    /// Returns the operation stage.
    #[must_use]
    pub const fn stage(&self) -> SourceStage {
        self.stage
    }

    /// Returns the stable issue category.
    #[must_use]
    pub const fn kind(&self) -> SourceIssueKind {
        self.kind
    }

    /// Returns the affected physical path, when one exists.
    #[must_use]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Returns the operating-system or adapter diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// One owned value emitted by a source.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceEvent {
    /// Successfully read bytes, optionally accompanied by the read issue that
    /// occurred in the same underlying operation.
    Fragment {
        /// Owned fragment safe to retain after the callback returns.
        fragment: Box<Fragment>,
        /// Recoverable issue coupled to these bytes.
        issue: Option<SourceIssue>,
    },
    /// A recoverable issue for which no fragment was produced.
    Issue(SourceIssue),
}

impl SourceEvent {
    /// Creates a fragment event without a coupled issue.
    #[must_use]
    pub fn fragment(fragment: Fragment) -> Self {
        Self::Fragment {
            fragment: Box::new(fragment),
            issue: None,
        }
    }
}

/// Callback instruction returned after one source event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceControl {
    /// Continue visiting source events.
    Continue,
    /// Stop normally after the current event.
    Stop,
}

/// Error deliberately returned by a source callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackError {
    message: String,
}

impl CallbackError {
    /// Creates a callback error with caller-owned context.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the callback diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CallbackError {}

/// Terminal source failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceError {
    /// Cooperative cancellation was observed.
    Cancelled,
    /// The consumer rejected an event.
    Callback(CallbackError),
    /// A source invariant or terminal operation failed.
    Terminal {
        /// Stage at which the source stopped.
        stage: SourceStage,
        /// Affected physical path, when available.
        path: Option<PathBuf>,
        /// Diagnostic details.
        message: String,
    },
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("source cancelled"),
            Self::Callback(error) => write!(formatter, "source callback failed: {error}"),
            Self::Terminal {
                stage,
                path,
                message,
            } => {
                write!(formatter, "source {stage:?} failed")?;
                if let Some(path) = path {
                    write!(formatter, " for {}", path.display())?;
                }
                write!(formatter, ": {message}")
            }
        }
    }
}

impl Error for SourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Callback(error) => Some(error),
            Self::Cancelled | Self::Terminal { .. } => None,
        }
    }
}

/// Synchronous, cancellation-aware source of owned fragments and issues.
///
/// Implementations do not choose a detection scheduler. The callback may
/// request normal stop or return a distinct callback failure.
pub trait Source: Send {
    /// Visits events until completion, cancellation, callback stop, or error.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Cancelled`] when cancellation is observed,
    /// [`SourceError::Callback`] when the callback rejects an event, or a
    /// source-specific terminal error.
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError>;
}
