#![forbid(unsafe_code)]
//! Synchronous source adapters for the Rustleaks engine.
//!
//! Source production is intentionally separate from detection. [`Source`]
//! implementations emit owned fragments and structured recoverable issues,
//! while [`SourceRunner`] provides optional bounded, caller-selected
//! parallel detection without requiring an async runtime or global pool.

#[cfg(feature = "archives")]
mod archive;
mod cancellation;
mod commit;
mod directory;
mod file;
mod git;
mod mime;
mod path;
mod process;
mod runner;
mod scm;
mod source;

#[cfg(feature = "archives")]
pub use archive::{ArchiveLimits, ArchiveOptions, ArchiveSource};
pub use cancellation::{Cancellation, CancellationToken};
pub use directory::{DirectoryOptions, DirectorySource};
pub use file::{
    COMPLETE_MIME_WINDOW, DEFAULT_CHUNK_SIZE, FileOptions, FileSource, MAX_BOUNDARY_READ_AHEAD,
    ReadOutcome, ReadStatus, SourceReader,
};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use git::fuzz_parse_patch;
pub use git::{GitLimits, GitMode, GitSource};
pub use path::{INNER_PATH_SEPARATOR, LogicalPath};
pub use runner::{
    SourceBudget, SourceBudgetError, SourceBudgetExceeded, SourceBudgetKind, SourceBudgetScope,
    SourceOutcome, SourceRunner, SourceTermination, SourceUsage,
};
pub use scm::{RemoteMetadata, ScmError, ScmErrorKind, ScmPlatform};
pub use source::{
    CallbackError, Source, SourceConfigError, SourceControl, SourceError, SourceEvent, SourceIssue,
    SourceIssueDisposition, SourceIssueKind, SourceStage,
};
