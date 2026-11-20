use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
#[cfg(panic = "unwind")]
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustleaks_core::config::CompiledConfig;

use crate::file::{FileTarget, FragmentCommit, visit_borrowed};
use crate::source::emit_issue;
use crate::{
    CallbackError, Cancellation, FileOptions, LogicalPath, Source, SourceConfigError,
    SourceControl, SourceError, SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

pub(crate) mod spool;
mod stream;

use spool::{MEMORY_SPOOL_BYTES, Spool, SpoolError, SpoolGuard, file_reader};
use stream::{
    Body, Budget, DecodeErrors, Failure, FillInput, GzipReader, Inflater, LzipReader, MemberReader,
    Metered, ReadErrors, ReadSeek, Replay, Walker, ZipCheck, ZstdBuffers, ZstdReader,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const GIB: usize = 1024 * MIB;
const DEFAULT_MAX_DEPTH: usize = 8;
const DEFAULT_MAX_ENTRIES: NonZeroUsize = NonZeroUsize::new(1_000_000).unwrap();
const DEFAULT_MAX_MEMBER_BYTES: NonZeroUsize = NonZeroUsize::new(4 * GIB).unwrap();
const DEFAULT_MAX_TOTAL_BYTES: NonZeroUsize = NonZeroUsize::new(16 * GIB).unwrap();
const DEFAULT_MAX_SPOOL_BYTES: NonZeroUsize = NonZeroUsize::new(GIB).unwrap();
/// Largest archive part that must be held in memory at once: a RAR member,
/// a Snappy or `MinLZ` stream, a TAR long name, 7z headers, and the decoder
/// dictionaries of 7z, Zstandard and LZIP. The member limit lowers it.
pub(crate) const MEMORY_BYTES: usize = 64 * MIB;
const COPY_BUFFER: usize = 16 * KIB;
const BROTLI_LARGE_WINDOW_HEADER: u8 = 0x11;

/// Checked resource ceilings applied across one archive traversal.
///
/// Members are decompressed and scanned as they are read, so memory does not
/// grow with the member or archive size. The member and total limits bound
/// the work that one archive can cause, such as a decompression bomb. Entry
/// counts bound the number of members. Spool storage bounds the copies made
/// when a ZIP, 7z, Zstandard or LZ4 input is not a file on disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    depth: usize,
    entries: NonZeroUsize,
    member_bytes: NonZeroUsize,
    total_bytes: NonZeroUsize,
    spool_bytes: NonZeroUsize,
}

impl ArchiveLimits {
    /// Creates explicit archive ceilings. A depth of zero disables archive handling.
    ///
    /// # Errors
    ///
    /// Entry, member, cumulative, and spool ceilings must be positive.
    pub fn new(
        max_depth: usize,
        max_entries: usize,
        max_member_bytes: usize,
        max_total_bytes: usize,
        max_spool_bytes: usize,
    ) -> Result<Self, SourceConfigError> {
        Ok(Self {
            depth: max_depth,
            entries: positive(max_entries, "max_archive_entries")?,
            member_bytes: positive(max_member_bytes, "max_archive_member_bytes")?,
            total_bytes: positive(max_total_bytes, "max_archive_total_bytes")?,
            spool_bytes: positive(max_spool_bytes, "max_archive_spool_bytes")?,
        })
    }

    /// Maximum number of recognized archive layers.
    #[must_use]
    pub const fn maximum_depth(self) -> usize {
        self.depth
    }

    /// Maximum archive headers or entries enumerated across the traversal.
    #[must_use]
    pub const fn maximum_entries(self) -> usize {
        self.entries.get()
    }

    /// Maximum decoded bytes accepted for one member or stream.
    #[must_use]
    pub const fn maximum_member_bytes(self) -> usize {
        self.member_bytes.get()
    }

    /// Maximum cumulative decoded member bytes across the traversal.
    #[must_use]
    pub const fn maximum_total_bytes(self) -> usize {
        self.total_bytes.get()
    }

    /// Maximum bytes kept at once in spools, in memory or temporary files.
    #[must_use]
    pub const fn maximum_spool_bytes(self) -> usize {
        self.spool_bytes.get()
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            depth: DEFAULT_MAX_DEPTH,
            entries: DEFAULT_MAX_ENTRIES,
            member_bytes: DEFAULT_MAX_MEMBER_BYTES,
            total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            spool_bytes: DEFAULT_MAX_SPOOL_BYTES,
        }
    }
}

fn positive(value: usize, field: &'static str) -> Result<NonZeroUsize, SourceConfigError> {
    NonZeroUsize::new(value).ok_or_else(|| SourceConfigError::positive(field))
}

/// Options for the optional safe native archive decorator.
#[derive(Clone, Debug, Default)]
pub struct ArchiveOptions {
    limits: ArchiveLimits,
    path_config: Option<Arc<CompiledConfig>>,
    excluded_paths: Vec<rustleaks_core::model::ByteText>,
    emit_limit_issues: bool,
    strict_7z_member_lengths: bool,
}

impl ArchiveOptions {
    /// Creates options from checked traversal ceilings.
    #[must_use]
    pub const fn new(limits: ArchiveLimits) -> Self {
        Self {
            limits,
            path_config: None,
            excluded_paths: Vec::new(),
            emit_limit_issues: false,
            strict_7z_member_lengths: false,
        }
    }

    /// Installs configuration for the first extracted member-name allowlist check.
    #[must_use]
    pub fn path_config(mut self, config: Arc<CompiledConfig>) -> Self {
        self.path_config = Some(config);
        self
    }

    /// Adds exact decorated target paths excluded before complete-mode reads.
    ///
    /// This compares normalized logical paths. Chunked scans ignore it.
    /// Only emitted leaf paths, including compressed streams, are matched.
    /// Naming a container does not exclude its descendants. Container and
    /// shared-decoder checks needed to reach eligible members remain active.
    #[must_use]
    pub fn exclude_paths(mut self, paths: Vec<rustleaks_core::model::ByteText>) -> Self {
        self.excluded_paths.extend(paths);
        self
    }

    fn target_excluded(&self, logical: &LogicalPath, name: &[u8]) -> bool {
        // Containers never emit a fragment under their own path. An exact
        // leaf exclusion must not suppress descendants of such a container.
        is_leaf_name(name, true)
            && self
                .excluded_paths
                .iter()
                .any(|path| path == logical.normalized())
    }

    /// Emits recoverable issues when configured depth limits skip archives.
    ///
    /// The default remains silent so callers that only consume fragments do
    /// not receive command-oriented diagnostics unexpectedly.
    #[must_use]
    pub const fn emit_limit_issues(mut self, enabled: bool) -> Self {
        self.emit_limit_issues = enabled;
        self
    }

    /// Requires each 7z member stream to produce its declared uncompressed size.
    ///
    /// Disabled by default to preserve the pinned archive backend's acceptance
    /// of early EOF. When enabled, a size mismatch produces a recoverable decode
    /// issue at the end of that member and stops that 7z archive. Members are
    /// scanned while they are read, so earlier members and the bytes of the
    /// short member are already published. Existing member and aggregate
    /// ceilings still apply. Complete-target file options always require this
    /// check, and a complete target never publishes the short member. This
    /// does not prove archive authenticity or add CRC validation beyond the
    /// decoder's checks.
    #[must_use]
    pub const fn strict_7z_member_lengths(mut self, enabled: bool) -> Self {
        self.strict_7z_member_lengths = enabled;
        self
    }

    /// Returns the configured resource ceilings.
    #[must_use]
    pub const fn limits(&self) -> ArchiveLimits {
        self.limits
    }
}

/// Name-driven, synchronous archive decorator around a reader-backed file source.
///
/// Unrecognized names are scanned as ordinary bytes. Recognized names consume
/// one depth before any decoding, including externally compressed TAR files.
///
/// Archives are read as streams. Members are decompressed and scanned while
/// they are read, so memory does not grow with the archive size. ZIP and 7z
/// need random access: a file on disk is read in place, and other input is
/// copied to a bounded spool first, in memory when small and otherwise in an
/// anonymous owner-only temporary file in the system temporary folder.
pub struct ArchiveSource {
    input: Option<SourceInput>,
    physical_path: PathBuf,
    logical_path: LogicalPath,
    symlink_path: Option<PathBuf>,
    file_options: FileOptions,
    options: ArchiveOptions,
    commit: Option<Arc<FragmentCommit>>,
}

enum SourceInput {
    Reader(Box<dyn Read + Send>),
    File(File),
}

impl ArchiveSource {
    /// Creates an archive-decorated source with safe defaults.
    #[must_use]
    pub fn new<R>(reader: R, path: impl Into<PathBuf>) -> Self
    where
        R: Read + Send + 'static,
    {
        Self::with_options(
            reader,
            path,
            FileOptions::default(),
            ArchiveOptions::default(),
        )
    }

    /// Creates an archive-decorated source with explicit file and archive options.
    #[must_use]
    pub fn with_options<R>(
        reader: R,
        path: impl Into<PathBuf>,
        file_options: FileOptions,
        options: ArchiveOptions,
    ) -> Self
    where
        R: Read + Send + 'static,
    {
        Self::from_input(
            SourceInput::Reader(Box::new(reader)),
            path.into(),
            file_options,
            options,
        )
    }

    /// Creates a source for an archive file, read in place with random access.
    pub(crate) fn from_file(
        file: File,
        path: impl Into<PathBuf>,
        file_options: FileOptions,
        options: ArchiveOptions,
    ) -> Self {
        Self::from_input(SourceInput::File(file), path.into(), file_options, options)
    }

    fn from_input(
        input: SourceInput,
        physical_path: PathBuf,
        file_options: FileOptions,
        options: ArchiveOptions,
    ) -> Self {
        let options = if file_options.complete_target_bytes().is_some() {
            options.strict_7z_member_lengths(true)
        } else {
            options
        };
        let logical_path = LogicalPath::from_native(&physical_path);
        Self {
            input: Some(input),
            physical_path,
            logical_path,
            symlink_path: None,
            file_options,
            options,
            commit: None,
        }
    }

    /// Records a discovered symlink alias without changing archive inner paths.
    #[must_use]
    pub fn with_symlink_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.symlink_path = Some(path.into());
        self
    }

    /// Gives every fragment the commit of the Git blob being scanned.
    pub(crate) fn with_commit(mut self, commit: FragmentCommit) -> Self {
        self.commit = Some(Arc::new(commit));
        self
    }
}

impl Source for ArchiveSource {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        self.visit_with_buffer(&mut Vec::new(), cancellation, emit)
    }
}

impl ArchiveSource {
    /// Visits the input, sharing `nominal` across every scanned member.
    pub(crate) fn visit_with_buffer(
        &mut self,
        nominal: &mut Vec<u8>,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        crate::source::visit_with_coverage(
            self.file_options.complete_target_bytes().is_some(),
            emit,
            |emit| self.visit_inner(nominal, cancellation, emit),
        )
    }

    fn visit_inner(
        &mut self,
        nominal: &mut Vec<u8>,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let input = self.input.take().ok_or_else(|| {
            SourceError::terminal(
                SourceStage::Open,
                Some(self.physical_path.clone()),
                "archive source was already consumed",
            )
        })?;
        let name = native_file_name_bytes(&self.physical_path);
        let complete = self.file_options.complete_target_bytes().is_some();
        if complete && self.options.target_excluded(&self.logical_path, &name) {
            return Ok(SourceControl::Continue);
        }
        if identify_for_mode(&name, complete).is_none() {
            let target = FileTarget::member(
                &self.physical_path,
                &self.logical_path,
                self.symlink_path.as_ref(),
                self.file_options,
                self.commit.as_ref(),
            );
            return match input {
                SourceInput::Reader(mut reader) => {
                    visit_borrowed(&mut *reader, &target, nominal, cancellation, emit)
                }
                SourceInput::File(file) => {
                    visit_borrowed(&mut &file, &target, nominal, cancellation, emit)
                }
            };
        }
        if self.options.limits.depth == 0 {
            return Ok(SourceControl::Continue);
        }
        let budget = Budget::new(self.options.limits.total_bytes.get());
        let mut state = ArchiveState {
            physical_path: &self.physical_path,
            symlink_path: self.symlink_path.as_ref(),
            file_options: self.file_options,
            options: &self.options,
            commit: self.commit.as_ref(),
            nominal,
            budget: &budget,
        };
        match input {
            SourceInput::Reader(mut reader) => {
                let mut reader = ReadErrors(&mut *reader);
                state.process(
                    Input::Stream(&mut reader),
                    &name,
                    &self.logical_path,
                    0,
                    cancellation,
                    emit,
                )
            }
            SourceInput::File(file) => state.process(
                Input::File(&file),
                &name,
                &self.logical_path,
                0,
                cancellation,
                emit,
            ),
        }
    }
}

/// One archive layer's input.
enum Input<'a> {
    /// A sequential stream, such as a member or decompressed bytes.
    Stream(&'a mut dyn Read),
    /// A 7z member stream whose read sizes reach the file scanner unchanged.
    Chunked(&'a mut dyn Read),
    /// Bytes in memory.
    Memory(&'a [u8]),
    /// A file on disk or a temporary spool file, read from its start.
    File(&'a File),
}

/// A sequential reader opened from any [`Input`].
enum Sequential<'a> {
    Borrowed(&'a mut dyn Read),
    Memory(&'a [u8]),
    File(std::io::BufReader<ReadErrors<&'a File>>),
}

impl<'a> Sequential<'a> {
    fn open(input: Input<'a>) -> Result<Self, Failure> {
        Ok(match input {
            Input::Stream(reader) | Input::Chunked(reader) => Self::Borrowed(reader),
            Input::Memory(bytes) => Self::Memory(bytes),
            Input::File(file) => Self::File(file_reader(file)?),
        })
    }

    fn reader(&mut self) -> &mut dyn Read {
        match self {
            Self::Borrowed(reader) => &mut **reader,
            Self::Memory(bytes) => bytes,
            Self::File(reader) => reader,
        }
    }
}

/// A random-access reader opened from a memory or file [`Input`].
enum Random<'a> {
    Memory(Cursor<&'a [u8]>),
    File(std::io::BufReader<ReadErrors<&'a File>>),
}

impl<'a> Random<'a> {
    #[allow(clippy::needless_pass_by_value)] // Input holds borrows; it is moved like one.
    fn open(input: Input<'a>) -> Result<Self, Failure> {
        match input {
            Input::Memory(bytes) => Ok(Self::Memory(Cursor::new(bytes))),
            Input::File(file) => Ok(Self::File(file_reader(file)?)),
            Input::Stream(_) | Input::Chunked(_) => Err(Failure::Read(
                "archive input needs random access".to_owned(),
            )),
        }
    }

    fn reader(&mut self) -> &mut dyn ReadSeek {
        match self {
            Self::Memory(reader) => reader,
            Self::File(reader) => reader,
        }
    }
}

impl Spool {
    const fn input(&self) -> Input<'_> {
        match self {
            Self::Memory(bytes) => Input::Memory(bytes.as_slice()),
            Self::File(file) => Input::File(file.file()),
        }
    }
}

/// How a member's bytes count toward the archive limits.
#[derive(Clone, Copy)]
enum Account {
    /// The container states the size, which is charged before reading.
    Known(usize),
    /// The reader already counts bytes as they are read.
    Counted,
}

struct ArchiveState<'a> {
    physical_path: &'a Path,
    symlink_path: Option<&'a PathBuf>,
    file_options: FileOptions,
    options: &'a ArchiveOptions,
    commit: Option<&'a Arc<FragmentCommit>>,
    nominal: &'a mut Vec<u8>,
    budget: &'a Budget,
}

impl<'a> ArchiveState<'a> {
    const fn complete(&self) -> bool {
        self.file_options.complete_target_bytes().is_some()
    }

    /// The largest archive part held in memory at once.
    fn memory_limit(&self) -> usize {
        self.options.limits.member_bytes.get().min(MEMORY_BYTES)
    }

    fn process(
        &mut self,
        input: Input<'_>,
        name: &[u8],
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        if self.complete() && self.options.target_excluded(logical, name) {
            return Ok(SourceControl::Continue);
        }
        let Some(format) = identify_for_mode(name, self.complete()) else {
            return self.plain(input, logical, cancellation, emit);
        };
        if depth >= self.options.limits.depth {
            if !self.options.emit_limit_issues {
                return Ok(SourceControl::Continue);
            }
            return emit_issue(
                limit_issue(
                    self.physical_path,
                    "skipping archive: exceeds maximum archive depth",
                )
                .excluded(),
                emit,
            );
        }
        match format {
            Format::Tar => match Sequential::open(input) {
                Ok(mut sequential) => {
                    self.extract_tar(sequential.reader(), logical, depth, cancellation, emit)
                }
                Err(failure) => self.emit_failure(failure, emit),
            },
            Format::Rar => match Sequential::open(input) {
                Ok(mut sequential) => {
                    self.extract_rar(sequential.reader(), logical, depth, cancellation, emit)
                }
                Err(failure) => self.emit_failure(failure, emit),
            },
            Format::Zip | Format::SevenZip => {
                let zip = matches!(format, Format::Zip);
                match input {
                    Input::Stream(reader) | Input::Chunked(reader) => {
                        match self.spool(reader, cancellation) {
                            Ok(guard) => self.random_access(
                                zip,
                                guard.spool().input(),
                                logical,
                                depth,
                                cancellation,
                                emit,
                            ),
                            Err(failure) => self.emit_failure(failure, emit),
                        }
                    }
                    other => self.random_access(zip, other, logical, depth, cancellation, emit),
                }
            }
            Format::CompressedTar(codec) => {
                self.decode(codec, input, logical, depth, true, cancellation, emit)
            }
            Format::Stream(codec) => {
                self.decode(codec, input, logical, depth, false, cancellation, emit)
            }
        }
    }

    /// Reads a ZIP or 7z archive from memory or a file.
    fn random_access(
        &mut self,
        zip: bool,
        input: Input<'_>,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if zip {
            return self.open_zip(input, logical, depth, cancellation, emit);
        }
        match Random::open(input) {
            Ok(mut random) => self.extract_7z(random.reader(), logical, depth, cancellation, emit),
            Err(failure) => self.emit_failure(failure, emit),
        }
    }

    /// Copies a stream to a bounded spool for random access.
    fn spool(
        &self,
        reader: &mut dyn Read,
        cancellation: &dyn Cancellation,
    ) -> Result<SpoolGuard<'a>, Failure> {
        spool::spool(
            reader,
            self.budget,
            self.options.limits.spool_bytes.get(),
            MEMORY_SPOOL_BYTES,
            cancellation,
        )
        .map_err(|error| match error {
            SpoolError::Limit => Failure::Limit("archive spool limit exceeded".to_owned()),
            SpoolError::Failure(failure) => failure,
        })
    }

    /// Reports a failure as an issue, or returns cancellation.
    fn emit_failure(
        &self,
        failure: Failure,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let issue = match failure {
            Failure::Cancelled => return Err(SourceError::Cancelled),
            Failure::Limit(message) => limit_issue(self.physical_path, message),
            Failure::Decode(message) => issue(
                self.physical_path,
                SourceStage::Decode,
                SourceIssueKind::Decode,
                message,
            ),
            Failure::Corrupt(message) => corrupt(self.physical_path, message),
            Failure::Read(message) => issue(
                self.physical_path,
                SourceStage::Read,
                SourceIssueKind::Read,
                message,
            ),
        };
        emit_issue(issue, emit)
    }

    /// Scans one member that is not an archive.
    fn plain(
        &mut self,
        input: Input<'_>,
        logical: &LogicalPath,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let target = FileTarget::member(
            self.physical_path,
            logical,
            self.symlink_path,
            self.file_options,
            self.commit,
        );
        match input {
            Input::Memory(mut bytes) => {
                visit_borrowed(&mut bytes, &target, self.nominal, cancellation, emit)
            }
            Input::Stream(reader) => self.plain_stream(reader, true, &target, cancellation, emit),
            Input::Chunked(reader) => self.plain_stream(reader, false, &target, cancellation, emit),
            Input::File(file) => match file_reader(file) {
                Ok(mut reader) => self.plain_stream(&mut reader, true, &target, cancellation, emit),
                Err(failure) => self.emit_failure(failure, emit),
            },
        }
    }

    fn plain_stream(
        &mut self,
        reader: &mut dyn Read,
        fill: bool,
        target: &FileTarget,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut member = MemberReader::new(reader, fill, self.complete());
        let result = visit_borrowed(&mut member, target, self.nominal, cancellation, emit);
        let Some(failure) = member.into_failure() else {
            return result;
        };
        match result {
            Err(SourceError::Cancelled | SourceError::Callback(_)) | Ok(SourceControl::Stop) => {
                result
            }
            // A complete target saw the failure as a read error and published
            // nothing; report the failure itself instead.
            _ => self.emit_failure(failure, emit),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn member(
        &mut self,
        input: Input<'_>,
        account: Account,
        native_name: &[u8],
        outer: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let normalized_name = normalize_member(native_name);
        if depth == 0 && self.first_level_allowed(&normalized_name, native_name) {
            return Ok(SourceControl::Continue);
        }
        let logical = outer.joined_archive(&normalized_name, native_name);
        if self.complete() && self.options.target_excluded(&logical, native_name) {
            return Ok(SourceControl::Continue);
        }
        if let Account::Known(bytes) = account
            && let Err(issue) = self.account(bytes)
        {
            return emit_issue(issue, emit);
        }
        self.process(input, native_name, &logical, depth + 1, cancellation, emit)
    }

    fn account(&self, bytes: usize) -> Result<(), SourceIssue> {
        if bytes > self.options.limits.member_bytes.get() {
            return Err(limit_issue(
                self.physical_path,
                "archive member limit exceeded",
            ));
        }
        self.budget
            .charge(bytes)
            .map_err(|message| limit_issue(self.physical_path, message))
    }

    fn bump_entry(&self) -> Result<(), SourceIssue> {
        let entries = self
            .budget
            .entries
            .get()
            .checked_add(1)
            .ok_or_else(|| limit_issue(self.physical_path, "archive entry count overflow"))?;
        self.budget.entries.set(entries);
        if entries > self.options.limits.entries.get() {
            return Err(limit_issue(
                self.physical_path,
                "archive entry limit exceeded",
            ));
        }
        Ok(())
    }

    fn complete_member_excluded(
        &self,
        native_name: &[u8],
        logical: &LogicalPath,
        depth: usize,
    ) -> bool {
        if !self.complete() {
            return false;
        }
        let normalized = normalize_member(native_name);
        depth == 0 && self.first_level_allowed(&normalized, native_name)
            || !self.options.excluded_paths.is_empty()
                && self.options.target_excluded(
                    &logical.joined_archive(&normalized, native_name),
                    native_name,
                )
    }

    fn first_level_allowed(&self, normalized: &[u8], _native: &[u8]) -> bool {
        self.options.path_config.as_ref().is_some_and(|config| {
            #[cfg(windows)]
            let windows = Some(_native);
            #[cfg(not(windows))]
            let windows = None;
            config.source_path_allowed(normalized, windows)
        })
    }

    /// Decompresses a stream, then scans it as a TAR or as one member.
    #[allow(clippy::too_many_arguments)]
    fn decode(
        &mut self,
        codec: Codec,
        input: Input<'_>,
        logical: &LogicalPath,
        depth: usize,
        tar: bool,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        // Zstandard and LZ4 walk their frame structure before decoding.
        match input {
            Input::Stream(reader) | Input::Chunked(reader) if codec.walks_frames() => {
                match self.spool(reader, cancellation) {
                    Ok(guard) => self.decode_input(
                        codec,
                        guard.spool().input(),
                        logical,
                        depth,
                        tar,
                        cancellation,
                        emit,
                    ),
                    Err(failure) => self.emit_failure(failure, emit),
                }
            }
            other => self.decode_input(codec, other, logical, depth, tar, cancellation, emit),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_input(
        &mut self,
        codec: Codec,
        input: Input<'_>,
        logical: &LogicalPath,
        depth: usize,
        tar: bool,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let budget = self.budget;
        // A decompressed TAR is a container: each member meets the member
        // limit, and the stream itself counts only toward the total.
        let member_limit = if tar {
            usize::MAX
        } else {
            self.options.limits.member_bytes.get()
        };
        let memory_limit = self.memory_limit();
        let decoded = with_codec(codec, input, memory_limit, cancellation, |reader| {
            let mut metered = Metered::new(
                reader,
                budget,
                member_limit,
                "archive expansion limit exceeded",
                cancellation,
            );
            let control = if tar {
                self.extract_tar(&mut metered, logical, depth, cancellation, emit)?
            } else {
                self.plain(Input::Stream(&mut metered), logical, cancellation, emit)?
            };
            if control == SourceControl::Stop || metered.failed {
                return Ok(control);
            }
            // Decode what the scan did not read, such as the rest of a
            // binary file or the bytes after the TAR end, so that checksums
            // and trailers are still verified.
            match stream::drain(&mut metered, cancellation) {
                Ok(()) => Ok(control),
                Err(failure) => self.emit_failure(failure, emit),
            }
        });
        match decoded {
            Ok(result) => result,
            Err(failure) => self.emit_failure(failure, emit),
        }
    }

    #[allow(clippy::too_many_lines)] // One TAR header, body and padding loop.
    fn extract_tar(
        &mut self,
        reader: &mut dyn Read,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut pending_long_name = None;
        let mut saw_header = false;
        let mut header = [0_u8; 512];
        loop {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            let count = match stream::read_full(reader, &mut header) {
                Ok(count) => count,
                Err(failure) => return self.emit_failure(failure, emit),
            };
            if count == 0 {
                break;
            }
            if count < header.len() {
                return emit_issue(corrupt(self.physical_path, "truncated TAR header"), emit);
            }
            if header.iter().all(|byte| *byte == 0) {
                return Ok(SourceControl::Continue);
            }
            saw_header = true;
            if !tar_checksum_valid(&header) {
                return emit_issue(
                    corrupt(self.physical_path, "invalid TAR header checksum"),
                    emit,
                );
            }
            let Some(size) = parse_tar_octal(&header[124..136]) else {
                return emit_issue(corrupt(self.physical_path, "invalid TAR member size"), emit);
            };
            let typeflag = header[156];
            if let Err(issue) = self.bump_entry() {
                return emit_issue(issue, emit);
            }
            let name = pending_long_name
                .take()
                .unwrap_or_else(|| tar_name(&header));
            let mut body = Body::new(reader, size as u64);
            if typeflag == b'L' {
                if size > self.memory_limit() {
                    return emit_issue(
                        limit_issue(self.physical_path, "TAR long name exceeds limit"),
                        emit,
                    );
                }
                let mut long_name = Vec::new();
                if long_name.try_reserve_exact(size).is_err() {
                    return emit_issue(
                        limit_issue(self.physical_path, "TAR long name exceeds limit"),
                        emit,
                    );
                }
                long_name.resize(size, 0);
                if let Err(failure) = stream::read_full(&mut body, &mut long_name) {
                    return self.emit_failure(failure, emit);
                }
                while long_name.last() == Some(&0) {
                    long_name.pop();
                }
                pending_long_name = Some(long_name);
            } else if !matches!(typeflag, b'5' | b'x' | b'g') {
                let name = clean_member_name(&name);
                // Header, body and padding boundaries still belong to the
                // container contract. Skip an explicitly excluded payload
                // once its validated name and body range are known.
                if !self.complete_member_excluded(&name, logical, depth) {
                    let member_limit = self
                        .budget
                        .remaining()
                        .min(self.options.limits.member_bytes.get());
                    if size > member_limit {
                        return emit_issue(
                            limit_issue(self.physical_path, "TAR member exceeds limit"),
                            emit,
                        );
                    }
                    let control = self.member(
                        Input::Stream(&mut body),
                        Account::Known(size),
                        &name,
                        logical,
                        depth,
                        cancellation,
                        emit,
                    )?;
                    if body.failed || control == SourceControl::Stop {
                        // Whoever read the failed body reported the failure.
                        return Ok(control);
                    }
                }
            }
            // Read what the member scan did not use, then the padding.
            if let Err(failure) = stream::drain(&mut body, cancellation) {
                return self.emit_failure(failure, emit);
            }
            let padding = (512 - size % 512) % 512;
            match stream::skip(reader, padding as u64, cancellation) {
                Ok(skipped) if skipped == padding as u64 => {}
                Ok(_) => {
                    return emit_issue(
                        corrupt(self.physical_path, "truncated TAR member padding"),
                        emit,
                    );
                }
                Err(failure) => return self.emit_failure(failure, emit),
            }
        }
        if saw_header {
            Ok(SourceControl::Continue)
        } else {
            emit_issue(corrupt(self.physical_path, "empty TAR stream"), emit)
        }
    }

    fn extract_rar(
        &mut self,
        reader: &mut dyn Read,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let remaining_entries = self
            .options
            .limits
            .entries
            .get()
            .saturating_sub(self.budget.entries.get());
        let remaining_bytes = self.budget.remaining();
        let member_limit = self.memory_limit();
        let mut outcome = None;
        let result = crate::rar::extract(
            reader,
            remaining_entries,
            member_limit,
            remaining_bytes,
            cancellation,
            &mut |entry| {
                if let Err(issue) = self.bump_entry() {
                    outcome = Some(emit_issue(issue, emit));
                    return false;
                }
                if entry.is_directory {
                    return true;
                }
                let name = clean_member_name(&entry.name);
                match self.member(
                    Input::Memory(&entry.data),
                    Account::Known(entry.data.len()),
                    &name,
                    logical,
                    depth,
                    cancellation,
                    emit,
                ) {
                    Ok(SourceControl::Continue) => true,
                    other => {
                        outcome = Some(other);
                        false
                    }
                }
            },
        );
        if let Some(outcome) = outcome {
            return outcome;
        }
        match result {
            Ok(()) => Ok(SourceControl::Continue),
            Err(crate::rar::RarFailure::Cancelled) => Err(SourceError::Cancelled),
            Err(crate::rar::RarFailure::Limit(message)) => {
                emit_issue(limit_issue(self.physical_path, message), emit)
            }
            Err(crate::rar::RarFailure::Unsupported(message)) => emit_issue(
                issue(
                    self.physical_path,
                    SourceStage::ArchiveMember,
                    SourceIssueKind::UnsupportedArchive,
                    message,
                ),
                emit,
            ),
            Err(crate::rar::RarFailure::Corrupt(message)) => {
                emit_issue(corrupt(self.physical_path, message), emit)
            }
            Err(crate::rar::RarFailure::Read(error)) => {
                self.emit_failure(Failure::from_io(error), emit)
            }
        }
    }

    #[allow(clippy::needless_pass_by_value)] // Input holds borrows; it is moved like one.
    fn open_zip(
        &mut self,
        input: Input<'_>,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut buffer = vec![0_u8; rawzip::RECOMMENDED_BUFFER_SIZE];
        match input {
            Input::Memory(bytes) => match rawzip::ZipArchive::from_slice(bytes) {
                Ok(archive) => self.extract_zip(
                    &archive.into_reader_archive(),
                    &mut buffer,
                    logical,
                    depth,
                    cancellation,
                    emit,
                ),
                Err(error) => emit_issue(corrupt(self.physical_path, error.to_string()), emit),
            },
            Input::File(file) => {
                let file = match file.try_clone() {
                    Ok(file) => file,
                    Err(error) => return self.emit_failure(Failure::Read(error.to_string()), emit),
                };
                match rawzip::ZipArchive::from_file(file, &mut buffer) {
                    Ok(archive) => {
                        self.extract_zip(&archive, &mut buffer, logical, depth, cancellation, emit)
                    }
                    Err(error) => emit_issue(corrupt(self.physical_path, error.to_string()), emit),
                }
            }
            Input::Stream(_) | Input::Chunked(_) => self.emit_failure(
                Failure::Read("archive input needs random access".to_owned()),
                emit,
            ),
        }
    }

    #[allow(clippy::too_many_lines)] // One ZIP directory, member and check loop.
    fn extract_zip<R: rawzip::ReaderAt>(
        &mut self,
        archive: &rawzip::ZipArchive<R>,
        buffer: &mut [u8],
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut entries = archive.entries(buffer);
        loop {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            let entry = match entries.next_entry() {
                Ok(Some(entry)) => entry,
                Ok(None) => return Ok(SourceControl::Continue),
                Err(error) => {
                    return emit_issue(corrupt(self.physical_path, error.to_string()), emit);
                }
            };
            if let Err(issue) = self.bump_entry() {
                return emit_issue(issue, emit);
            }
            if entry.is_dir() {
                continue;
            }
            let name = clean_member_name(entry.file_path().as_bytes());
            let wayfinder = entry.wayfinder();
            let method = entry.compression_method();
            let size = entry.uncompressed_size_hint();
            let crc = entry.crc32();
            if self.complete_member_excluded(&name, logical, depth) {
                // Retain local-header and compressed-range validation even when
                // the payload itself is outside the selected path domain.
                if let Err(error) = archive.get_entry(wayfinder) {
                    return emit_issue(member_issue(self.physical_path, error.to_string()), emit);
                }
                continue;
            }
            if size > self.options.limits.member_bytes.get() as u64 {
                return emit_issue(
                    limit_issue(self.physical_path, "ZIP member size exceeds limit"),
                    emit,
                );
            }
            let local = match archive.get_entry(wayfinder) {
                Ok(local) => local,
                Err(error) => {
                    return emit_issue(member_issue(self.physical_path, error.to_string()), emit);
                }
            };
            let Ok(size_bytes) = usize::try_from(size) else {
                return emit_issue(
                    limit_issue(self.physical_path, "ZIP member size exceeds limit"),
                    emit,
                );
            };
            if size_bytes > self.budget.remaining() {
                if emit_issue(
                    limit_issue(self.physical_path, "ZIP member size exceeds limit"),
                    emit,
                )? == SourceControl::Stop
                {
                    return Ok(SourceControl::Stop);
                }
                continue;
            }
            let mut compressed = ReadErrors(local.reader());
            let mut inflater;
            let decoded: &mut dyn Read = if method == rawzip::CompressionMethod::STORE {
                &mut compressed
            } else if method == rawzip::CompressionMethod::DEFLATE {
                inflater =
                    Inflater::new(&mut compressed, miniz_oxide::DataFormat::Raw, "ZIP member");
                &mut inflater
            } else {
                let issue = issue(
                    self.physical_path,
                    SourceStage::ArchiveMember,
                    SourceIssueKind::UnsupportedArchive,
                    format!("unsupported ZIP compression method {method:?}"),
                );
                if emit_issue(issue, emit)? == SourceControl::Stop {
                    return Ok(SourceControl::Stop);
                }
                continue;
            };
            let mut check = ZipCheck::new(decoded, size, crc);
            let control = self.member(
                Input::Stream(&mut check),
                Account::Known(size_bytes),
                &name,
                logical,
                depth,
                cancellation,
                emit,
            )?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
            // Verify the rest of a member that the scan did not read.
            if !check.failed
                && let Err(failure) = stream::drain(&mut check, cancellation)
                && self.emit_failure(failure, emit)? == SourceControl::Stop
            {
                return Ok(SourceControl::Stop);
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Keep the complete dependency containment boundary adjacent.
    fn extract_7z(
        &mut self,
        source: &mut dyn ReadSeek,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let memory_limit = self.memory_limit();
        if let Err(failure) = preflight_7z(source, memory_limit) {
            let issue = match failure {
                SevenPreflightFailure::Limit(message) => limit_issue(self.physical_path, message),
                SevenPreflightFailure::Corrupt(message) => corrupt(self.physical_path, message),
            };
            return emit_issue(issue, emit);
        }
        let mut reader = match open_7z(source, memory_limit) {
            Ok(reader) => reader,
            Err(failure) => {
                return emit_issue(
                    issue(
                        self.physical_path,
                        SourceStage::Decode,
                        failure.kind(),
                        failure.into_message(),
                    ),
                    emit,
                );
            }
        };
        reader.set_thread_count(1);
        let archive_entries = reader.archive().files.len();
        match self.budget.entries.get().checked_add(archive_entries) {
            Some(entries) if entries <= self.options.limits.entries.get() => {
                self.budget.entries.set(entries);
            }
            _ => {
                return emit_issue(
                    limit_issue(self.physical_path, "7z entry limit exceeded"),
                    emit,
                );
            }
        }
        if let Err(message) = preflight_7z_archive(
            reader.archive(),
            self.options.limits,
            self.budget.remaining(),
            memory_limit,
        ) {
            return emit_issue(limit_issue(self.physical_path, message), emit);
        }
        let member_limit = self.options.limits.member_bytes.get();
        let chunk = self.file_options.chunk_size().min(member_limit);
        let strict = self.options.strict_7z_member_lengths;
        let budget = self.budget;
        // Set when a member ended the traversal; its issue is already sent.
        let mut outcome: Option<Result<SourceControl, SourceError>> = None;
        #[cfg(panic = "unwind")]
        let mut panicked = None;
        let mut visit = |entry: &rustleaks_sevenz::ArchiveEntry, stream: &mut dyn Read| {
            // Returning false ends only the current block, so an error ends
            // the traversal once it has an outcome.
            if outcome.is_some() {
                return Err(seven_error("archive traversal ended"));
            }
            if cancellation.is_cancelled() {
                outcome = Some(Err(SourceError::Cancelled));
                return Err(seven_error("source cancelled"));
            }
            if entry.is_directory() {
                return Ok(true);
            }
            if entry.size() > member_limit as u64 {
                return Err(rustleaks_sevenz::Error::from(
                    Failure::Limit("archive resource limit exceeded".to_owned()).into_io(),
                ));
            }
            let name = clean_member_name(entry.name().as_bytes());
            let mut decoded = DecodeErrors(stream);
            let mut metered = Metered::new(
                &mut decoded,
                budget,
                member_limit,
                "archive member limit exceeded",
                cancellation,
            );
            let mut replay = match Replay::new(&mut metered, chunk, strict.then_some(entry.size()))
            {
                Ok(replay) => replay,
                Err(failure) => {
                    outcome = Some(self.emit_failure(failure, emit));
                    return Err(seven_error("archive member failed"));
                }
            };
            // A panic in the scan is not a decoder panic; raise it again after
            // the decoder returns.
            #[cfg(panic = "unwind")]
            let result = match catch_unwind(AssertUnwindSafe(|| {
                self.seven_member(&mut replay, &name, logical, depth, cancellation, emit)
            })) {
                Ok(result) => result,
                Err(payload) => {
                    panicked = Some(payload);
                    return Err(seven_error("archive member scan panicked"));
                }
            };
            #[cfg(panic = "abort")]
            let result = self.seven_member(&mut replay, &name, logical, depth, cancellation, emit);
            match result {
                Ok(SourceControl::Continue) if !replay.failed => Ok(true),
                other => {
                    outcome = Some(other);
                    Err(seven_error("archive traversal ended"))
                }
            }
        };
        #[cfg(panic = "unwind")]
        let decoded = catch_unwind(AssertUnwindSafe(|| reader.for_each_entries(&mut visit)));
        #[cfg(panic = "unwind")]
        if let Some(payload) = panicked {
            resume_unwind(payload);
        }
        #[cfg(panic = "unwind")]
        let Ok(result) = decoded else {
            if let Some(outcome) = outcome {
                return outcome;
            }
            return emit_issue(
                corrupt(self.physical_path, "7z decoder panicked on untrusted input"),
                emit,
            );
        };
        #[cfg(panic = "abort")]
        let result = reader.for_each_entries(&mut visit);
        if let Some(outcome) = outcome {
            return outcome;
        }
        if let Err(error) = result {
            return emit_issue(seven_traversal_issue(self.physical_path, &error), emit);
        }
        Ok(SourceControl::Continue)
    }

    /// Scans one 7z member and reads the rest of it, which the next member needs.
    fn seven_member(
        &mut self,
        replay: &mut Replay<'_>,
        name: &[u8],
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let control = self.member(
            Input::Chunked(replay),
            Account::Counted,
            name,
            logical,
            depth,
            cancellation,
            emit,
        )?;
        if replay.failed || control == SourceControl::Stop {
            return Ok(control);
        }
        match stream::drain(replay, cancellation) {
            Ok(()) => Ok(control),
            Err(failure) => self.emit_failure(failure, emit),
        }
    }
}

impl Codec {
    /// Zstandard and LZ4 check their frame structure before decoding.
    const fn walks_frames(self) -> bool {
        matches!(self, Self::Zstd | Self::Lz4)
    }
}

/// Opens a streaming decoder for `codec` and passes it to `use_reader`.
fn with_codec<T>(
    codec: Codec,
    input: Input<'_>,
    memory_limit: usize,
    cancellation: &dyn Cancellation,
    use_reader: impl FnOnce(&mut dyn Read) -> T,
) -> Result<T, Failure> {
    if codec.walks_frames() {
        let mut random = Random::open(input)?;
        if matches!(codec, Codec::Lz4) {
            check_lz4_frames(random.reader())
                .map_err(|message| Failure::Decode(message.to_owned()))?;
            let mut reader = DecodeErrors(lz4_flex::frame::FrameDecoder::new(random.reader()));
            return Ok(use_reader(&mut reader));
        }
        let history = zstd_history_len(random.reader(), memory_limit)?;
        let mut buffers = ZstdBuffers::new(history)?;
        let mut reader = ZstdReader::new(&mut buffers, random.reader())?;
        return Ok(use_reader(&mut reader));
    }
    let mut sequential = Sequential::open(input)?;
    let mut filled = FillInput::new(sequential.reader());
    let input: &mut dyn Read = &mut filled;
    Ok(match codec {
        Codec::Gzip => use_reader(&mut GzipReader::new(input)),
        Codec::Zlib => use_reader(&mut Inflater::new(
            input,
            miniz_oxide::DataFormat::Zlib,
            "zlib",
        )),
        Codec::Bzip2 => use_reader(&mut DecodeErrors(bzip2_rs::DecoderReader::new(input))),
        Codec::Xz => use_reader(&mut DecodeErrors(lzma_rust2::XzReader::new(input, true))),
        Codec::Lzip => use_reader(&mut LzipReader::new(input, memory_limit)),
        Codec::Brotli => {
            let mut first = [0_u8; 1];
            let count = stream::read_full(input, &mut first)?;
            if count == 1 && first[0] == BROTLI_LARGE_WINDOW_HEADER {
                return Err(Failure::Limit(
                    "archive expansion limit exceeded".to_owned(),
                ));
            }
            let chained = (&first[..count]).chain(input);
            use_reader(&mut DecodeErrors(brotli_decompressor::Decompressor::new(
                chained,
                COPY_BUFFER,
            )))
        }
        Codec::Snappy | Codec::MinLz => {
            // These framed decoders work on whole inputs, so both the
            // compressed and the decoded stream stay within the memory limit.
            let compressed = read_bounded(input, memory_limit)?;
            let decoded = if matches!(codec, Codec::Snappy) {
                crate::snappy::decode_framed(&compressed, memory_limit, cancellation)
            } else {
                crate::snappy::decode_minlz_framed(&compressed, memory_limit, cancellation)
            }
            .map_err(|error| match error {
                crate::snappy::SnappyFailure::Cancelled => Failure::Cancelled,
                crate::snappy::SnappyFailure::Limit => {
                    Failure::Limit("archive expansion limit exceeded".to_owned())
                }
                crate::snappy::SnappyFailure::Decode(message) => {
                    Failure::Decode(message.to_owned())
                }
            })?;
            drop(compressed);
            use_reader(&mut decoded.as_slice())
        }
        Codec::Zstd | Codec::Lz4 => unreachable!("frame-walking codecs return above"),
    })
}

/// Reads a whole stream that must fit in memory.
fn read_bounded(reader: &mut dyn Read, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut output = Vec::new();
    let mut buffer = vec![0_u8; COPY_BUFFER];
    loop {
        let count = stream::read_full(reader, &mut buffer)?;
        if output
            .len()
            .checked_add(count)
            .is_none_or(|size| size > limit)
        {
            return Err(Failure::Limit(
                "archive expansion limit exceeded".to_owned(),
            ));
        }
        output
            .try_reserve(count)
            .map_err(|_| Failure::Limit("archive expansion limit exceeded".to_owned()))?;
        output.extend_from_slice(&buffer[..count]);
        if count < buffer.len() {
            return Ok(output);
        }
    }
}

enum SevenPreflightFailure {
    Limit(&'static str),
    Corrupt(&'static str),
}

struct SevenOpenFailure {
    kind: SourceIssueKind,
    message: String,
}

impl SevenOpenFailure {
    const fn kind(&self) -> SourceIssueKind {
        self.kind
    }

    fn into_message(self) -> String {
        self.message
    }
}

fn open_7z<R: Read + Seek>(
    source: R,
    memory_limit: usize,
) -> Result<rustleaks_sevenz::ArchiveReader<R>, SevenOpenFailure> {
    #[cfg(panic = "abort")]
    {
        let _ = (source, memory_limit);
        return Err(SevenOpenFailure {
            kind: SourceIssueKind::UnsupportedArchive,
            message: "7z decoding is unavailable when dependency panics abort the process"
                .to_owned(),
        });
    }

    #[cfg(panic = "unwind")]
    {
        let memory_limit_kb = memory_limit.div_ceil(1024).max(1);
        let parsed = catch_unwind(AssertUnwindSafe(|| {
            rustleaks_sevenz::ArchiveReader::new_with_memory_limit_kb(
                source,
                rustleaks_sevenz::Password::empty(),
                memory_limit_kb,
            )
        }));
        let Ok(reader) = parsed else {
            return Err(SevenOpenFailure {
                kind: SourceIssueKind::CorruptArchive,
                message: "7z parser panicked on untrusted input".to_owned(),
            });
        };
        reader.map_err(|error| SevenOpenFailure {
            kind: SourceIssueKind::CorruptArchive,
            message: error.to_string(),
        })
    }
}

/// Checks decoded sizes against the limits before any member is read.
///
/// A solid block decodes as one stream while its members are scanned, so
/// only the remaining total bounds it. Each file must fit the member limit,
/// and its name stays in memory with the archive header.
fn preflight_7z_archive(
    archive: &rustleaks_sevenz::Archive,
    limits: ArchiveLimits,
    remaining: usize,
    memory_limit: usize,
) -> Result<(), &'static str> {
    if archive
        .blocks
        .iter()
        .any(|block| usize::try_from(block.get_unpack_size()).map_or(true, |size| size > remaining))
    {
        return Err("7z block size exceeds limit");
    }
    if archive.files.iter().any(|entry| {
        usize::try_from(entry.size()).map_or(true, |size| {
            size > limits.member_bytes.get() || entry.name().len() > memory_limit
        })
    }) {
        return Err("7z entry metadata exceeds limit");
    }
    Ok(())
}

fn preflight_7z(
    source: &mut dyn ReadSeek,
    memory_limit: usize,
) -> Result<(), SevenPreflightFailure> {
    const SIGNATURE: &[u8; 6] = b"7z\xbc\xaf'\x1c";
    const HEADER_BYTES: usize = 32;
    const UNREADABLE: SevenPreflightFailure =
        SevenPreflightFailure::Corrupt("could not read 7z input");

    let length = source.seek(SeekFrom::End(0)).map_err(|_| UNREADABLE)?;
    source.seek(SeekFrom::Start(0)).map_err(|_| UNREADABLE)?;
    let mut data = [0_u8; HEADER_BYTES];
    let read = stream::read_full(source, &mut data).map_err(|_| UNREADABLE)?;
    source.seek(SeekFrom::Start(0)).map_err(|_| UNREADABLE)?;
    if read < HEADER_BYTES || &data[..SIGNATURE.len()] != SIGNATURE {
        return Err(SevenPreflightFailure::Corrupt(
            "invalid 7z signature header",
        ));
    }
    if data[6] != 0 {
        return Err(SevenPreflightFailure::Corrupt(
            "unsupported 7z major version",
        ));
    }
    if data[8..12] == [0; 4] {
        return Err(SevenPreflightFailure::Limit(
            "7z recovery-header scan is outside the bounded profile",
        ));
    }
    let offset = u64::from_le_bytes(data[12..20].try_into().expect("fixed 7z offset"));
    let size = u64::from_le_bytes(data[20..28].try_into().expect("fixed 7z size"));
    if usize::try_from(size).map_or(true, |size| size > memory_limit) {
        return Err(SevenPreflightFailure::Limit(
            "7z next-header size exceeds limit",
        ));
    }
    let start = (HEADER_BYTES as u64)
        .checked_add(offset)
        .ok_or(SevenPreflightFailure::Limit(
            "7z next-header offset overflow",
        ))?;
    let end = start
        .checked_add(size)
        .ok_or(SevenPreflightFailure::Limit("7z next-header size overflow"))?;
    if end > length {
        return Err(SevenPreflightFailure::Corrupt(
            "7z next-header range exceeds input",
        ));
    }
    Ok(())
}

fn seven_error(message: impl Into<String>) -> rustleaks_sevenz::Error {
    rustleaks_sevenz::Error::from(std::io::Error::other(message.into()))
}

/// Builds the issue for an error that ended a 7z traversal.
///
/// A decoder that needs more memory than the 7z memory limit, and a limit
/// of this crate, give a limit issue. Any other error is a decode issue.
fn seven_traversal_issue(path: &Path, error: &rustleaks_sevenz::Error) -> SourceIssue {
    if let rustleaks_sevenz::Error::Io(inner, _) = error
        && let Some(message) = stream::limit(inner)
    {
        return limit_issue(path, message);
    }
    if matches!(error, rustleaks_sevenz::Error::MaxMemLimited { .. }) {
        return limit_issue(path, error.to_string());
    }
    issue(
        path,
        SourceStage::Decode,
        SourceIssueKind::Decode,
        error.to_string(),
    )
}

const LZ4_FRAME_MAGIC: u32 = 0x184D_2204;
const LZ4_LEGACY_MAGIC: u32 = 0x184C_2102;
const LZ4_SKIPPABLE_MAGIC: std::ops::RangeInclusive<u32> = 0x184D_2A50..=0x184D_2A5F;

/// Checks the frame structure of a complete LZ4 input before decoding.
///
/// The frame decoder treats the end of input at a frame start or at a block
/// size word as a clean end, so a truncated stream would decode in part
/// without an error. This walk follows the LZ4 frame format: a standard frame
/// needs its descriptor, every block, its end mark and, when its descriptor
/// says so, block and content checksums. A skippable frame needs its declared
/// length. A legacy frame has no end mark and ends at a block boundary. Empty
/// input is an empty stream. The decoder still verifies checksums and blocks.
/// The walk seeks over payloads and leaves the input at its start.
fn check_lz4_frames(input: &mut dyn ReadSeek) -> Result<(), &'static str> {
    let mut walker = Walker::new(input).map_err(|_| "could not read LZ4 stream")?;
    let result = walk_lz4_frames(&mut walker);
    walker.rewind().map_err(|_| "could not read LZ4 stream")?;
    result
}

fn walk_lz4_frames(walker: &mut Walker<'_>) -> Result<(), &'static str> {
    const TRUNCATED: &str = "truncated LZ4 stream";
    let word = |walker: &mut Walker<'_>| -> Result<u32, &'static str> {
        let mut bytes = [0_u8; 4];
        walker.take(&mut bytes).ok_or(TRUNCATED)?;
        Ok(u32::from_le_bytes(bytes))
    };
    while !walker.at_end() {
        let magic = word(walker)?;
        if magic == LZ4_FRAME_MAGIC {
            let mut flags = [0_u8; 2];
            walker.take(&mut flags).ok_or(TRUNCATED)?;
            let flags = flags[0];
            if flags >> 6 != 0b01 {
                return Err("unsupported LZ4 frame version");
            }
            let block_checksums = flags & 0x10 != 0;
            let content_checksum = flags & 0x04 != 0;
            // Optional content size and dictionary ID, then the header checksum.
            let optional = u64::from(flags & 0x08 != 0) * 8 + u64::from(flags & 0x01 != 0) * 4;
            walker.skip(optional + 1).ok_or(TRUNCATED)?;
            loop {
                let size = word(walker)?;
                if size == 0 {
                    break;
                }
                walker
                    .skip(u64::from(size & 0x7FFF_FFFF))
                    .ok_or(TRUNCATED)?;
                if block_checksums {
                    walker.skip(4).ok_or(TRUNCATED)?;
                }
            }
            if content_checksum {
                walker.skip(4).ok_or(TRUNCATED)?;
            }
        } else if LZ4_SKIPPABLE_MAGIC.contains(&magic) {
            let size = word(walker)?;
            walker.skip(u64::from(size)).ok_or(TRUNCATED)?;
        } else if magic == LZ4_LEGACY_MAGIC {
            while !walker.at_end() {
                let size = word(walker)?;
                walker.skip(u64::from(size)).ok_or(TRUNCATED)?;
            }
        } else {
            return Err("unknown LZ4 frame magic");
        }
    }
    Ok(())
}

/// Returns the decoder history length for `input` under a positive `limit`.
///
/// The decoder rejects a frame whose window exceeds its history and reports
/// both lengths, so the full limit stays in place unless the whole stream can
/// be walked and every window fits. Past that check the history length is not
/// observable: a match offset is bounded by the frame window, each block
/// produces at most one window of output, and output is released per block.
/// The walk seeks over payloads and leaves the input at its start.
fn zstd_history_len(input: &mut dyn ReadSeek, limit: usize) -> Result<usize, Failure> {
    let unreadable = |error: std::io::Error| Failure::Read(error.to_string());
    let mut walker = Walker::new(input).map_err(unreadable)?;
    let window = zstd_maximum_window(&mut walker);
    walker.rewind().map_err(unreadable)?;
    Ok(match window {
        Some(window) if window <= limit => window.max(1),
        _ => limit,
    })
}

/// Follows the decoder's frame and block walk without decoding payloads.
///
/// Returns the largest declared window, or `None` unless the walk ends exactly
/// at the end of the input after at least one Zstandard frame.
fn zstd_maximum_window(walker: &mut Walker<'_>) -> Option<usize> {
    let mut maximum = None;
    while !walker.at_end() {
        let mut prefix = [0_u8; zstd_zero::MAX_FRAME_HEADER_SIZE];
        let count = walker.peek(&mut prefix)?;
        let zstd_zero::HeaderStatus::Complete { header, size } =
            zstd_zero::inspect_frame(&prefix[..count]).ok()?
        else {
            return None;
        };
        walker.skip(u64::try_from(size).ok()?)?;
        match header {
            zstd_zero::StreamHeader::Skippable { size, .. } => {
                walker.skip(u64::from(size))?;
            }
            zstd_zero::StreamHeader::Zstandard(frame) => {
                let window = usize::try_from(frame.window_size).ok()?;
                maximum = maximum.max(Some(window));
                zstd_skip_blocks(walker)?;
                if frame.has_checksum {
                    walker.skip(4)?;
                }
            }
        }
    }
    maximum
}

fn zstd_skip_blocks(walker: &mut Walker<'_>) -> Option<()> {
    const RAW: u8 = 0;
    const RLE: u8 = 1;
    const COMPRESSED: u8 = 2;

    loop {
        let mut header = [0_u8; 3];
        walker.take(&mut header)?;
        let last = header[0] & 1 != 0;
        let kind = (header[0] >> 1) & 3;
        let size =
            u64::from(header[0] >> 3) | u64::from(header[1]) << 5 | u64::from(header[2]) << 13;
        let payload = match kind {
            RAW | COMPRESSED => size,
            RLE => 1,
            _ => return None,
        };
        walker.skip(payload)?;
        if last {
            return Some(());
        }
    }
}

#[derive(Clone, Copy)]
enum Codec {
    Brotli,
    Bzip2,
    Gzip,
    Lz4,
    Snappy,
    MinLz,
    Xz,
    Lzip,
    Zstd,
    Zlib,
}

enum Format {
    Tar,
    Zip,
    SevenZip,
    Rar,
    CompressedTar(Codec),
    Stream(Codec),
}

pub(crate) fn complete_path_is_leaf(path: &Path) -> bool {
    is_leaf_name(&native_file_name_bytes(path), true)
}

fn is_leaf_name(name: &[u8], complete: bool) -> bool {
    matches!(
        identify_for_mode(name, complete),
        None | Some(Format::Stream(_))
    )
}

fn identify_for_mode(name: &[u8], complete: bool) -> Option<Format> {
    // Complete targets extend the pinned name-only profile with this alias.
    // Require a final suffix so directory names and backups do not opt in.
    if complete && name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(b".tgz") {
        return Some(Format::CompressedTar(Codec::Gzip));
    }
    identify(name)
}

fn identify(name: &[u8]) -> Option<Format> {
    let lower = name.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    let compression = if contains(&lower, b".gz") {
        Some(Codec::Gzip)
    } else if contains(&lower, b".xz") {
        Some(Codec::Xz)
    } else if contains(&lower, b".zst") {
        Some(Codec::Zstd)
    } else if final_extension(&lower, b".lz") {
        Some(Codec::Lzip)
    } else if contains(&lower, b".zz") {
        Some(Codec::Zlib)
    } else if contains(&lower, b".br") {
        Some(Codec::Brotli)
    } else if contains(&lower, b".bz2") {
        Some(Codec::Bzip2)
    } else if contains(&lower, b".lz4") {
        Some(Codec::Lz4)
    } else if contains(&lower, b".sz") || contains(&lower, b".s2") {
        Some(Codec::Snappy)
    } else if final_extension(&lower, b".mz") {
        Some(Codec::MinLz)
    } else {
        None
    };
    if contains(&lower, b".tar") {
        return Some(compression.map_or(Format::Tar, Format::CompressedTar));
    }
    if contains(&lower, b".7z") {
        return Some(Format::SevenZip);
    }
    if contains(&lower, b".zip") {
        return Some(Format::Zip);
    }
    if contains(&lower, b".rar") {
        return Some(Format::Rar);
    }
    if let Some(codec) = compression {
        return Some(Format::Stream(codec));
    }
    None
}

pub(crate) fn name_is_archive(name: &[u8], complete: bool) -> bool {
    identify_for_mode(name, complete).is_some()
}

/// Whether [`ArchiveSource`] reads the file at `path` as an archive or a
/// compressed stream, judged by its file name as when it is visited.
pub(crate) fn path_is_archive(path: &Path, complete: bool) -> bool {
    name_is_archive(&native_file_name_bytes(path), complete)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn final_extension(name: &[u8], extension: &[u8]) -> bool {
    let base = name
        .rsplit(|byte| matches!(*byte, b'/' | b'\\'))
        .next()
        .unwrap_or(name);
    base.ends_with(extension)
}

fn clean_member_name(name: &[u8]) -> Vec<u8> {
    let rooted = name.first().is_some_and(|byte| is_separator(*byte));
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in name.split(|byte| is_separator(*byte)) {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            if parts.last().is_some_and(|last| *last != b"..") {
                parts.pop();
            } else if !rooted {
                parts.push(part);
            }
        } else {
            parts.push(part);
        }
    }
    let separator = if cfg!(windows) { b'\\' } else { b'/' };
    let mut result = Vec::new();
    if rooted {
        result.push(separator);
    }
    for (index, part) in parts.iter().enumerate() {
        if index != 0 {
            result.push(separator);
        }
        result.extend_from_slice(part);
    }
    if result.is_empty() {
        result.push(b'.');
    }
    result
}

const fn is_separator(byte: u8) -> bool {
    if cfg!(windows) {
        matches!(byte, b'/' | b'\\')
    } else {
        byte == b'/'
    }
}

fn normalize_member(name: &[u8]) -> Vec<u8> {
    #[cfg(windows)]
    {
        name.iter()
            .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
            .collect()
    }
    #[cfg(not(windows))]
    {
        name.to_vec()
    }
}

fn tar_name(header: &[u8]) -> Vec<u8> {
    let name = nul_terminated(&header[..100]);
    let prefix = nul_terminated(&header[345..500]);
    if prefix.is_empty() {
        return name.to_vec();
    }
    let mut result = prefix.to_vec();
    result.push(b'/');
    result.extend_from_slice(name);
    result
}

fn nul_terminated(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())]
}

fn parse_tar_octal(bytes: &[u8]) -> Option<usize> {
    let trimmed = bytes
        .iter()
        .copied()
        .skip_while(|byte| matches!(*byte, 0 | b' '))
        .take_while(|byte| matches!(*byte, b'0'..=b'7'));
    let mut value = 0_usize;
    for byte in trimmed {
        value = value.checked_mul(8)?.checked_add((byte - b'0') as usize)?;
    }
    Some(value)
}

fn tar_checksum_valid(header: &[u8]) -> bool {
    let Some(expected) = parse_tar_octal(&header[148..156]) else {
        return false;
    };
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' ' as usize
            } else {
                *byte as usize
            }
        })
        .sum::<usize>();
    actual == expected
}

fn native_file_name_bytes(path: &Path) -> Vec<u8> {
    LogicalPath::from_native(Path::new(path.file_name().unwrap_or(path.as_os_str())))
        .normalized()
        .as_bytes()
        .to_vec()
}

fn issue(
    path: &Path,
    stage: SourceStage,
    kind: SourceIssueKind,
    message: impl Into<String>,
) -> SourceIssue {
    SourceIssue::new(stage, kind, Some(path.to_path_buf()), message)
}

fn corrupt(path: &Path, message: impl Into<String>) -> SourceIssue {
    issue(
        path,
        SourceStage::Archive,
        SourceIssueKind::CorruptArchive,
        message,
    )
}

fn member_issue(path: &Path, message: impl Into<String>) -> SourceIssue {
    issue(
        path,
        SourceStage::ArchiveMember,
        SourceIssueKind::ArchiveMember,
        message,
    )
}

fn limit_issue(path: &Path, message: impl Into<String>) -> SourceIssue {
    issue(path, SourceStage::Limit, SourceIssueKind::Limit, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    enum DecodeFailure {
        Cancelled,
        Limit,
        Decode(String),
    }

    impl From<Failure> for DecodeFailure {
        fn from(failure: Failure) -> Self {
            match failure {
                Failure::Cancelled => Self::Cancelled,
                Failure::Limit(_) => Self::Limit,
                Failure::Decode(message) | Failure::Corrupt(message) | Failure::Read(message) => {
                    Self::Decode(message)
                }
            }
        }
    }

    /// Slice form of the LZ4 frame walk.
    fn check_lz4_frames(input: &[u8]) -> Result<(), &'static str> {
        super::check_lz4_frames(&mut Cursor::new(input))
    }

    /// Slice form of the Zstandard window walk.
    fn zstd_history_len(input: &[u8], limit: usize) -> usize {
        super::zstd_history_len(&mut Cursor::new(input), limit)
            .ok()
            .unwrap()
    }

    /// Decodes a whole input with the streaming decoder and an output limit.
    fn decode_codec(
        codec: Codec,
        input: &[u8],
        limit: usize,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, DecodeFailure> {
        let budget = Budget::new(usize::MAX);
        let mut output = Vec::new();
        match with_codec(codec, Input::Memory(input), limit, cancellation, |reader| {
            Metered::new(reader, &budget, limit, "limit", cancellation).read_to_end(&mut output)
        }) {
            Ok(Ok(_)) => Ok(output),
            Ok(Err(error)) => Err(Failure::from_io(error).into()),
            Err(failure) => Err(failure.into()),
        }
    }

    fn decode_zstd(
        input: &[u8],
        limit: usize,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, DecodeFailure> {
        decode_codec(Codec::Zstd, input, limit, cancellation)
    }

    fn allocate_zeroed<T: Clone + Default>(size: usize) -> Result<Vec<T>, DecodeFailure> {
        let mut value = Vec::new();
        value
            .try_reserve_exact(size)
            .map_err(|_| DecodeFailure::Limit)?;
        value.resize(size, T::default());
        Ok(value)
    }

    fn extend_bounded(
        output: &mut Vec<u8>,
        input: &[u8],
        limit: usize,
    ) -> Result<(), DecodeFailure> {
        if output
            .len()
            .checked_add(input.len())
            .is_none_or(|size| size > limit)
        {
            return Err(DecodeFailure::Limit);
        }
        output.extend_from_slice(input);
        Ok(())
    }

    fn zstd_failure(error: zstd_zero::StreamError<DecodeFailure>) -> DecodeFailure {
        match error {
            zstd_zero::StreamError::Output(error) => error,
            zstd_zero::StreamError::Decode(error) => DecodeFailure::Decode(error.to_string()),
            zstd_zero::StreamError::DecoderStalled => {
                DecodeFailure::Decode("Zstandard decoder stalled".to_owned())
            }
        }
    }

    fn lz4_frame(payload: &[u8], info: lz4_flex::frame::FrameInfo) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::new());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn lz4_frames_need_their_end_mark_and_declared_checksums() {
        use lz4_flex::frame::{BlockSize, FrameInfo};
        let payload = b"portable safe lz4 payload\n".repeat(4_000);
        let checked = |length: usize| {
            FrameInfo::new()
                .block_size(BlockSize::Max64KB)
                .block_checksums(true)
                .content_checksum(true)
                .content_size(Some(u64::try_from(length).unwrap()))
        };
        let first = lz4_frame(&payload, FrameInfo::new());
        let second = lz4_frame(b"second frame\n", checked(13));
        let multi_block = lz4_frame(&payload, checked(payload.len()));
        let mut skippable = 0x184D_2A5A_u32.to_le_bytes().to_vec();
        skippable.extend_from_slice(&3_u32.to_le_bytes());
        skippable.extend_from_slice(b"abc");
        let concatenated = [first.clone(), skippable.clone(), second.clone()].concat();
        // Whole streams, and streams that end exactly between frames, pass.
        let boundaries = [
            0,
            first.len(),
            first.len() + skippable.len(),
            concatenated.len(),
        ];
        for stream in [&first, &second, &multi_block, &skippable] {
            assert_eq!(check_lz4_frames(stream), Ok(()));
            for cut in 1..stream.len() {
                assert_eq!(
                    check_lz4_frames(&stream[..cut]),
                    Err("truncated LZ4 stream"),
                    "cut {cut}"
                );
            }
        }
        for cut in 0..=concatenated.len() {
            assert_eq!(
                check_lz4_frames(&concatenated[..cut]).is_ok(),
                boundaries.contains(&cut),
                "cut {cut}"
            );
        }
        let cancellation = crate::CancellationToken::new();
        let decoded = decode_codec(Codec::Lz4, &multi_block, 1 << 20, &cancellation)
            .ok()
            .unwrap();
        assert!(decoded == payload);
    }

    #[test]
    fn lz4_legacy_frames_end_at_block_boundaries_and_unknown_magic_fails() {
        let block = lz4_flex::block::compress(b"legacy lz4 block payload\n");
        let mut legacy = 0x184C_2102_u32.to_le_bytes().to_vec();
        for _ in 0..2 {
            legacy.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
            legacy.extend_from_slice(&block);
        }
        let boundaries = [0, 4, 4 + 4 + block.len(), legacy.len()];
        for cut in 0..=legacy.len() {
            assert_eq!(
                check_lz4_frames(&legacy[..cut]).is_ok(),
                boundaries.contains(&cut),
                "cut {cut}"
            );
        }
        assert_eq!(
            check_lz4_frames(b"not lz4 at all"),
            Err("unknown LZ4 frame magic")
        );
        let mut version = 0x184D_2204_u32.to_le_bytes().to_vec();
        version.extend_from_slice(&[0x00, 0x40, 0x00, 0, 0, 0, 0]);
        assert_eq!(
            check_lz4_frames(&version),
            Err("unsupported LZ4 frame version")
        );
    }

    #[test]
    fn rejects_large_window_brotli_before_decoder_construction() {
        let cancellation = crate::CancellationToken::new();
        assert!(matches!(
            decode_codec(
                Codec::Brotli,
                &[BROTLI_LARGE_WINDOW_HEADER],
                1,
                &cancellation
            ),
            Err(DecodeFailure::Limit)
        ));
    }

    #[test]
    fn unsupported_7z_disposition_is_not_misclassified_as_corrupt() {
        let failure = SevenOpenFailure {
            kind: SourceIssueKind::UnsupportedArchive,
            message: "7z decoding is unavailable when dependency panics abort the process"
                .to_owned(),
        };
        assert_eq!(failure.kind(), SourceIssueKind::UnsupportedArchive);
        assert!(failure.into_message().contains("panics abort"));
    }

    #[cfg(panic = "abort")]
    #[test]
    fn abort_profile_rejects_7z_before_dependency_construction() {
        match open_7z(Cursor::new(Vec::new()), MEMORY_BYTES) {
            Err(failure) if failure.kind() == SourceIssueKind::UnsupportedArchive => {
                assert!(failure.into_message().contains("panics abort"));
            }
            Err(failure) => panic!(
                "abort profile misclassified 7z as {:?}: {}",
                failure.kind(),
                failure.into_message()
            ),
            Ok(_) => panic!("abort profile entered the 7z dependency"),
        }
    }

    #[test]
    fn validates_every_positive_resource_ceiling() {
        for values in [
            (8, 0, 1, 1, 1),
            (8, 1, 0, 1, 1),
            (8, 1, 1, 0, 1),
            (8, 1, 1, 1, 0),
        ] {
            assert!(ArchiveLimits::new(values.0, values.1, values.2, values.3, values.4).is_err());
        }
        assert!(ArchiveLimits::new(0, 1, 1, 1, 1).is_ok());
    }

    #[test]
    fn tgz_alias_is_a_complete_only_container_with_a_final_suffix() {
        for name in [b"x.tgz".as_slice(), b"x.TGZ", b"dir/x.tGz"] {
            assert!(matches!(
                identify_for_mode(name, true),
                Some(Format::CompressedTar(Codec::Gzip))
            ));
            assert!(identify_for_mode(name, false).is_none());
            assert!(!is_leaf_name(name, true));
            assert!(is_leaf_name(name, false));
        }
        for name in [b"x.tgz.backup".as_slice(), b"x.tgz/file", b"x.tgz\\file"] {
            assert!(identify_for_mode(name, true).is_none());
        }
    }

    #[test]
    fn recognizes_complete_pinned_name_profile() {
        for name in [
            "x.7Z",
            "x.br",
            "x.bz2",
            "x.gz",
            "x.lz",
            "x.lz4",
            "x.mz",
            "x.rar",
            "x.s2",
            "x.sz",
            "x.tar",
            "x.xz",
            "x.zip",
            "x.zst",
            "x.zz",
            "x.tar.gz",
            "x.tar.xz",
            "x.tar.zst",
            "x.tar.bz2",
        ] {
            assert!(identify(name.as_bytes()).is_some(), "{name}");
        }
        assert!(identify(b"x.lz.backup").is_none());
        assert!(identify(b"x.mz.backup").is_none());
        assert!(identify(b"plain").is_none());
    }

    #[test]
    fn cleans_member_names_without_touching_the_filesystem() {
        let cleaned = if cfg!(windows) { b"a\\c" } else { b"a/c" };
        assert_eq!(clean_member_name(b"a/./b/../c"), cleaned);
        let leading_parent = if cfg!(windows) {
            b"..\\..\\a"
        } else {
            b"../../a"
        };
        assert_eq!(clean_member_name(b"../../a"), leading_parent);
    }

    fn zstd_outcome(result: Result<Vec<u8>, DecodeFailure>) -> Result<Vec<u8>, String> {
        result.map_err(|failure| match failure {
            DecodeFailure::Cancelled => "cancelled".to_owned(),
            DecodeFailure::Limit => "limit".to_owned(),
            DecodeFailure::Decode(message) => format!("decode: {message}"),
        })
    }

    /// The full-limit history decoder that `zstd_history_len` must stay
    /// indistinguishable from.
    fn reference_zstd(
        input: &[u8],
        limit: usize,
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, DecodeFailure> {
        let mut history = allocate_zeroed(limit)?;
        let mut block = allocate_zeroed(zstd_zero::MAX_BLOCK_SIZE)?;
        let mut literals = allocate_zeroed(zstd_zero::MAX_BLOCK_SIZE)?;
        let mut fse = allocate_zeroed(zstd_zero::FSE_ENTRIES)?;
        let mut huffman = allocate_zeroed(zstd_zero::HUFFMAN_ENTRIES)?;
        let mut fse_scratch = allocate_zeroed(zstd_zero::FSE_SCRATCH_LEN)?;
        let mut decoder = zstd_zero::Decoder::new(zstd_zero::DecoderBuffers {
            history: &mut history,
            block: &mut block,
            literals: &mut literals,
            fse: &mut fse,
            huffman: &mut huffman,
            fse_scratch: &mut fse_scratch,
        })
        .map_err(|error| DecodeFailure::Decode(error.to_string()))?;
        let mut output = Vec::new();
        let mut append = |bytes: &[u8]| -> Result<(), DecodeFailure> {
            if cancellation.is_cancelled() {
                return Err(DecodeFailure::Cancelled);
            }
            extend_bounded(&mut output, bytes, limit)
        };
        decoder.push(input, &mut append).map_err(zstd_failure)?;
        decoder.finish_with(&mut append).map_err(zstd_failure)?;
        Ok(output)
    }

    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    const ZSTD_RAW: u32 = 0;
    const ZSTD_RLE: u32 = 1;
    const ZSTD_RESERVED: u32 = 3;

    fn zstd_block(last: bool, kind: u32, size: usize, payload: &[u8]) -> Vec<u8> {
        let header = u32::from(last) | (kind << 1) | (u32::try_from(size).unwrap() << 3);
        let mut block = header.to_le_bytes()[..3].to_vec();
        block.extend_from_slice(payload);
        block
    }

    fn zstd_raw(last: bool, payload: &[u8]) -> Vec<u8> {
        zstd_block(last, ZSTD_RAW, payload.len(), payload)
    }

    /// A frame with a `Window_Descriptor`; the window is `1024 << exponent`.
    fn zstd_windowed(exponent: u8, blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut frame = ZSTD_MAGIC.to_vec();
        frame.push(0);
        frame.push(exponent << 3);
        frame.extend(blocks.iter().flatten());
        frame
    }

    /// A frame whose window equals its one-byte declared content size.
    fn zstd_single_segment(content_size: u8, blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut frame = ZSTD_MAGIC.to_vec();
        frame.push(0x20);
        frame.push(content_size);
        frame.extend(blocks.iter().flatten());
        frame
    }

    fn zstd_skippable(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x50, 0x2a, 0x4d, 0x18];
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn assert_zstd_matches(
        name: &str,
        input: &[u8],
        limit: usize,
        expected: &Result<Vec<u8>, String>,
    ) {
        let cancellation = crate::CancellationToken::new();
        let actual = zstd_outcome(decode_zstd(input, limit, &cancellation));
        let reference = zstd_outcome(reference_zstd(input, limit, &cancellation));
        assert_eq!(&actual, expected, "{name}");
        assert_eq!(actual, reference, "{name}: differs from full-limit history");
    }

    type ZstdCase<'a> = (&'a str, &'a [u8], usize, Result<Vec<u8>, String>);

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table of crafted frames and expected outcomes"
    )]
    fn zstd_history_shrink_is_indistinguishable_from_full_limit_history() {
        let ab = [vec![b'a'; 600], vec![b'b'; 400]].concat();
        let one_block = zstd_windowed(0, &[zstd_raw(true, &ab)]);

        // Output past the window wraps the ring without changing the bytes.
        let block = |fill| vec![fill; 1000];
        let wrapping = zstd_windowed(
            0,
            &[
                zstd_raw(false, &block(1)),
                zstd_raw(false, &block(2)),
                zstd_raw(true, &block(3)),
            ],
        );
        let wrapped_output = [block(1), block(2), block(3)].concat();

        let two_frames = [
            zstd_windowed(0, &[zstd_raw(true, b"first")]),
            zstd_windowed(1, &[zstd_raw(true, b"second")]),
        ]
        .concat();
        let skippable_around = [
            zstd_skippable(b"ignored"),
            zstd_windowed(0, &[zstd_raw(true, b"body")]),
            zstd_skippable(b""),
        ]
        .concat();
        let rle = zstd_windowed(0, &[zstd_block(true, ZSTD_RLE, 700, b"z")]);
        let empty_window = zstd_single_segment(0, &[zstd_raw(true, b"")]);

        let mut truncated = wrapping.clone();
        truncated.pop();
        let mut trailing_garbage = one_block.clone();
        trailing_garbage.extend_from_slice(b"garbage!");
        let oversized_block = zstd_windowed(0, &[zstd_raw(true, &[7; 1025])]);
        let reserved_block = zstd_windowed(0, &[zstd_block(true, ZSTD_RESERVED, 0, b"")]);

        let cases: Vec<ZstdCase<'_>> = vec![
            (
                "one block, ample limit",
                &one_block,
                1 << 20,
                Ok(ab.clone()),
            ),
            ("window equals limit", &one_block, 1024, Ok(ab.clone())),
            (
                "window one above limit",
                &one_block,
                1023,
                Err("decode: history buffer is too small: need 1024 bytes, have 1023".to_owned()),
            ),
            (
                "ring wraps within ample limit",
                &wrapping,
                1 << 20,
                Ok(wrapped_output.clone()),
            ),
            ("output equals limit", &wrapping, 3000, Ok(wrapped_output)),
            (
                "output one above limit",
                &wrapping,
                2999,
                Err("limit".to_owned()),
            ),
            (
                "largest window of two frames",
                &two_frames,
                1 << 20,
                Ok(b"firstsecond".to_vec()),
            ),
            (
                "later frame window above limit",
                &two_frames,
                1500,
                Err("decode: history buffer is too small: need 2048 bytes, have 1500".to_owned()),
            ),
            (
                "skippable frames",
                &skippable_around,
                1 << 20,
                Ok(b"body".to_vec()),
            ),
            ("run-length block", &rle, 1 << 20, Ok(vec![b'z'; 700])),
            ("zero window", &empty_window, 1, Ok(Vec::new())),
            (
                "truncated stream",
                &truncated,
                1 << 20,
                Err("decode: unexpected end of zstd stream".to_owned()),
            ),
            (
                "trailing garbage",
                &trailing_garbage,
                1 << 20,
                Err("decode: invalid zstd frame magic".to_owned()),
            ),
            (
                "block larger than window",
                &oversized_block,
                1 << 20,
                Err("decode: invalid zstd block".to_owned()),
            ),
            (
                "reserved block type",
                &reserved_block,
                1 << 20,
                Err("decode: invalid zstd block".to_owned()),
            ),
            (
                "empty input",
                b"",
                1 << 20,
                Err("decode: unexpected end of zstd stream".to_owned()),
            ),
        ];
        for (name, input, limit, expected) in &cases {
            assert_zstd_matches(name, input, *limit, expected);
        }
    }

    #[test]
    fn zstd_history_len_follows_declared_windows_and_keeps_the_limit_otherwise() {
        let body = zstd_raw(true, b"x");
        let window_1k = zstd_windowed(0, std::slice::from_ref(&body));
        let window_2k = zstd_windowed(1, std::slice::from_ref(&body));
        let both = [window_1k.clone(), window_2k.clone()].concat();

        assert_eq!(zstd_history_len(&window_1k, 1 << 20), 1024);
        assert_eq!(zstd_history_len(&both, 1 << 20), 2048);
        assert_eq!(zstd_history_len(&window_1k, 1024), 1024);
        // A window above the limit keeps the limit for the decoder's report.
        assert_eq!(zstd_history_len(&window_2k, 2047), 2047);
        assert_eq!(zstd_history_len(&both, 1500), 1500);
        // Zero-length windows still need a nonempty ring.
        let empty = zstd_single_segment(0, &[zstd_raw(true, b"")]);
        assert_eq!(zstd_history_len(&empty, 1 << 20), 1);

        // Anything but a complete walk keeps the limit.
        let mut truncated = window_1k.clone();
        truncated.pop();
        let mut garbage = window_1k.clone();
        garbage.push(0xff);
        let only_skippable = zstd_skippable(b"ignored");
        let reserved = zstd_windowed(0, &[zstd_block(true, ZSTD_RESERVED, 0, b"")]);
        for input in [&truncated, &garbage, &only_skippable, &reserved] {
            assert_eq!(zstd_history_len(input, 1 << 20), 1 << 20);
        }
        assert_eq!(zstd_history_len(b"", 1 << 20), 1 << 20);
    }

    #[test]
    fn zstd_compressed_fixture_decodes_identically_with_a_smaller_history() {
        let input = include_bytes!(concat!(
            "../../../compat/fixtures/upstream/testdata/archives",
            "/files/main.go.zst"
        ));
        let limit = 64 * 1024 * 1024;
        let history = zstd_history_len(input, limit);
        assert!(
            history < limit,
            "the fixture must exercise a smaller history"
        );

        let cancellation = crate::CancellationToken::new();
        let actual = zstd_outcome(decode_zstd(input, limit, &cancellation));
        let reference = zstd_outcome(reference_zstd(input, limit, &cancellation));
        assert!(actual.as_ref().is_ok_and(|bytes| !bytes.is_empty()));
        assert_eq!(actual, reference);
    }
}
