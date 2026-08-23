use std::io::{Cursor, Read};
use std::num::NonZeroUsize;
#[cfg(panic = "unwind")]
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustleaks_core::config::CompiledConfig;

use crate::{
    CallbackError, Cancellation, FileOptions, FileSource, LogicalPath, Source, SourceConfigError,
    SourceControl, SourceError, SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

const DEFAULT_MAX_DEPTH: usize = 8;
const DEFAULT_MAX_ENTRIES: usize = 10_000;
const DEFAULT_MAX_MEMBER_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_SPOOL_BYTES: usize = 64 * 1024 * 1024;
const COPY_BUFFER: usize = 16 * 1024;

/// Checked resource ceilings applied across one archive traversal.
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

    /// Maximum bytes retained to provide a seekable in-memory archive spool.
    #[must_use]
    pub const fn maximum_spool_bytes(self) -> usize {
        self.spool_bytes.get()
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            depth: DEFAULT_MAX_DEPTH,
            entries: NonZeroUsize::new(DEFAULT_MAX_ENTRIES).expect("positive default"),
            member_bytes: NonZeroUsize::new(DEFAULT_MAX_MEMBER_BYTES).expect("positive default"),
            total_bytes: NonZeroUsize::new(DEFAULT_MAX_TOTAL_BYTES).expect("positive default"),
            spool_bytes: NonZeroUsize::new(DEFAULT_MAX_SPOOL_BYTES).expect("positive default"),
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
    emit_limit_issues: bool,
}

impl ArchiveOptions {
    /// Creates options from checked traversal ceilings.
    #[must_use]
    pub const fn new(limits: ArchiveLimits) -> Self {
        Self {
            limits,
            path_config: None,
            emit_limit_issues: false,
        }
    }

    /// Installs configuration for the first extracted member-name allowlist check.
    #[must_use]
    pub fn path_config(mut self, config: Arc<CompiledConfig>) -> Self {
        self.path_config = Some(config);
        self
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
pub struct ArchiveSource {
    reader: Option<Box<dyn Read + Send>>,
    physical_path: PathBuf,
    logical_path: LogicalPath,
    symlink_path: Option<PathBuf>,
    file_options: FileOptions,
    options: ArchiveOptions,
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
        let physical_path = path.into();
        let logical_path = LogicalPath::from_native(&physical_path);
        Self {
            reader: Some(Box::new(reader)),
            physical_path,
            logical_path,
            symlink_path: None,
            file_options,
            options,
        }
    }

    /// Records a discovered symlink alias without changing archive inner paths.
    #[must_use]
    pub fn with_symlink_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.symlink_path = Some(path.into());
        self
    }
}

impl Source for ArchiveSource {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let reader = self.reader.take().ok_or_else(|| SourceError::Terminal {
            stage: SourceStage::Open,
            path: Some(self.physical_path.clone()),
            message: "archive source was already consumed".to_owned(),
        })?;
        let name = native_file_name_bytes(&self.physical_path);
        if identify(&name).is_none() {
            return plain_source(
                reader,
                &self.physical_path,
                &self.logical_path,
                self.symlink_path.as_ref(),
                self.file_options,
                cancellation,
                emit,
            );
        }
        if self.options.limits.depth == 0 {
            return Ok(SourceControl::Continue);
        }
        let data = match read_bounded(reader, self.options.limits.spool_bytes.get(), cancellation) {
            Ok(data) => data,
            Err(ReadBoundedError::Cancelled) => return Err(SourceError::Cancelled),
            Err(ReadBoundedError::Io(message)) => {
                return emit_issue(
                    issue(
                        &self.physical_path,
                        SourceStage::Spool,
                        SourceIssueKind::Read,
                        message,
                    ),
                    emit,
                );
            }
            Err(ReadBoundedError::Limit) => {
                return emit_issue(
                    limit_issue(&self.physical_path, "archive spool limit exceeded"),
                    emit,
                );
            }
        };
        let mut state = ArchiveState {
            physical_path: &self.physical_path,
            symlink_path: self.symlink_path.as_ref(),
            file_options: self.file_options,
            options: &self.options,
            entries: 0,
            expanded: 0,
        };
        state.process(data, &name, &self.logical_path, 0, cancellation, emit)
    }
}

struct ArchiveState<'a> {
    physical_path: &'a Path,
    symlink_path: Option<&'a PathBuf>,
    file_options: FileOptions,
    options: &'a ArchiveOptions,
    entries: usize,
    expanded: usize,
}

impl ArchiveState<'_> {
    fn process(
        &mut self,
        data: Vec<u8>,
        name: &[u8],
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let Some(format) = identify(name) else {
            return plain_source(
                Box::new(Cursor::new(data)),
                self.physical_path,
                logical,
                self.symlink_path,
                self.file_options,
                cancellation,
                emit,
            );
        };
        if depth >= self.options.limits.depth {
            if !self.options.emit_limit_issues {
                return Ok(SourceControl::Continue);
            }
            return emit_issue(
                limit_issue(
                    self.physical_path,
                    "skipping archive: exceeds maximum archive depth",
                ),
                emit,
            );
        }
        match format {
            Format::Tar => self.extract_tar(&data, logical, depth, cancellation, emit),
            Format::Zip => self.extract_zip(&data, logical, depth, cancellation, emit),
            Format::SevenZip => self.extract_7z(data, logical, depth, cancellation, emit),
            Format::Rar => self.extract_rar(&data, logical, depth, cancellation, emit),
            Format::CompressedTar(codec) => {
                let decoded = match self.decode(codec, &data, cancellation) {
                    Ok(decoded) => decoded,
                    Err(DecodeFailure::Cancelled) => return Err(SourceError::Cancelled),
                    Err(kind) => return emit_issue(kind.into_issue(self.physical_path), emit),
                };
                self.extract_tar(&decoded, logical, depth, cancellation, emit)
            }
            Format::Stream(codec) => {
                let decoded = match self.decode(codec, &data, cancellation) {
                    Ok(decoded) => decoded,
                    Err(DecodeFailure::Cancelled) => return Err(SourceError::Cancelled),
                    Err(kind) => return emit_issue(kind.into_issue(self.physical_path), emit),
                };
                plain_source(
                    Box::new(Cursor::new(decoded)),
                    self.physical_path,
                    logical,
                    self.symlink_path,
                    self.file_options,
                    cancellation,
                    emit,
                )
            }
        }
    }

    fn member(
        &mut self,
        data: Vec<u8>,
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
        if let Err(issue) = self.account(data.len()) {
            return emit_issue(issue, emit);
        }
        let logical = outer.joined_archive(&normalized_name, native_name);
        self.process(data, native_name, &logical, depth + 1, cancellation, emit)
    }

    #[allow(clippy::too_many_arguments)]
    fn member_with_read_chunks(
        &mut self,
        data: Vec<u8>,
        read_chunks: Vec<usize>,
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
        if let Err(issue) = self.account(data.len()) {
            return emit_issue(issue, emit);
        }
        let logical = outer.joined_archive(&normalized_name, native_name);
        if identify(native_name).is_some() {
            return self.process(data, native_name, &logical, depth + 1, cancellation, emit);
        }
        plain_source(
            Box::new(ChunkedCursor::new(data, read_chunks)),
            self.physical_path,
            &logical,
            self.symlink_path,
            self.file_options,
            cancellation,
            emit,
        )
    }

    fn account(&mut self, bytes: usize) -> Result<(), SourceIssue> {
        if bytes > self.options.limits.member_bytes.get() {
            return Err(limit_issue(
                self.physical_path,
                "archive member limit exceeded",
            ));
        }
        self.expanded = self.expanded.checked_add(bytes).ok_or_else(|| {
            limit_issue(self.physical_path, "archive cumulative byte count overflow")
        })?;
        if self.expanded > self.options.limits.total_bytes.get() {
            return Err(limit_issue(
                self.physical_path,
                "archive cumulative limit exceeded",
            ));
        }
        Ok(())
    }

    fn bump_entry(&mut self) -> Result<(), SourceIssue> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| limit_issue(self.physical_path, "archive entry count overflow"))?;
        if self.entries > self.options.limits.entries.get() {
            return Err(limit_issue(
                self.physical_path,
                "archive entry limit exceeded",
            ));
        }
        Ok(())
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

    fn decode(
        &mut self,
        codec: Codec,
        input: &[u8],
        cancellation: &dyn Cancellation,
    ) -> Result<Vec<u8>, DecodeFailure> {
        if cancellation.is_cancelled() {
            return Err(DecodeFailure::Cancelled);
        }
        let remaining = self
            .options
            .limits
            .total_bytes
            .get()
            .saturating_sub(self.expanded);
        let limit = remaining.min(self.options.limits.member_bytes.get());
        if limit == 0 {
            return Err(DecodeFailure::Limit);
        }
        let result = match codec {
            Codec::Brotli => decode_reader(
                brotli_decompressor::Decompressor::new(input, COPY_BUFFER),
                limit,
                cancellation,
            ),
            Codec::Bzip2 => decode_reader(bzip2_rs::DecoderReader::new(input), limit, cancellation),
            Codec::Gzip => decode_gzip(input, limit, cancellation),
            Codec::Lz4 => decode_reader(
                lz4_flex::frame::FrameDecoder::new(input),
                limit,
                cancellation,
            ),
            Codec::Snappy => crate::snappy::decode_framed(input, limit, cancellation).map_err(
                |error| match error {
                    crate::snappy::SnappyFailure::Cancelled => DecodeFailure::Cancelled,
                    crate::snappy::SnappyFailure::Limit => DecodeFailure::Limit,
                    crate::snappy::SnappyFailure::Decode(message) => {
                        DecodeFailure::Decode(message.to_owned())
                    }
                },
            ),
            Codec::MinLz => {
                crate::snappy::decode_minlz_framed(input, limit, cancellation).map_err(|error| {
                    match error {
                        crate::snappy::SnappyFailure::Cancelled => DecodeFailure::Cancelled,
                        crate::snappy::SnappyFailure::Limit => DecodeFailure::Limit,
                        crate::snappy::SnappyFailure::Decode(message) => {
                            DecodeFailure::Decode(message.to_owned())
                        }
                    }
                })
            }
            Codec::Xz => decode_reader(lzma_rust2::XzReader::new(input, true), limit, cancellation),
            Codec::Lzip => decode_lzip(input, limit, cancellation),
            Codec::Zstd => decode_zstd(input, limit, cancellation),
            Codec::Zlib => inflate_checked(
                input,
                limit,
                miniz_oxide::DataFormat::Zlib,
                cancellation,
                "zlib",
            ),
        }?;
        self.account(result.len())
            .map_err(|_| DecodeFailure::Limit)?;
        Ok(result)
    }

    fn extract_tar(
        &mut self,
        data: &[u8],
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut offset = 0_usize;
        let mut pending_long_name = None;
        let mut saw_header = false;
        while offset < data.len() {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            let header_end = offset
                .checked_add(512)
                .ok_or_else(|| limit_terminal(self.physical_path))?;
            if header_end > data.len() {
                return emit_issue(corrupt(self.physical_path, "truncated TAR header"), emit);
            }
            let header = &data[offset..header_end];
            if header.iter().all(|byte| *byte == 0) {
                return Ok(SourceControl::Continue);
            }
            saw_header = true;
            if !tar_checksum_valid(header) {
                return emit_issue(
                    corrupt(self.physical_path, "invalid TAR header checksum"),
                    emit,
                );
            }
            let Some(size) = parse_tar_octal(&header[124..136]) else {
                return emit_issue(corrupt(self.physical_path, "invalid TAR member size"), emit);
            };
            let body_start = header_end;
            let body_end = match body_start.checked_add(size) {
                Some(end) if end <= data.len() => end,
                _ => return emit_issue(corrupt(self.physical_path, "truncated TAR member"), emit),
            };
            let typeflag = header[156];
            if let Err(issue) = self.bump_entry() {
                return emit_issue(issue, emit);
            }
            let mut name = pending_long_name.take().unwrap_or_else(|| tar_name(header));
            if typeflag == b'L' {
                let Ok(long_name) = copy_bounded(
                    &data[body_start..body_end],
                    self.options.limits.member_bytes.get(),
                ) else {
                    return emit_issue(
                        limit_issue(self.physical_path, "TAR long name exceeds limit"),
                        emit,
                    );
                };
                name = long_name;
                while name.last() == Some(&0) {
                    name.pop();
                }
                pending_long_name = Some(name);
            } else if !matches!(typeflag, b'5' | b'x' | b'g') {
                let name = clean_member_name(&name);
                let remaining = self
                    .options
                    .limits
                    .total_bytes
                    .get()
                    .saturating_sub(self.expanded);
                let member_limit = remaining.min(self.options.limits.member_bytes.get());
                let Ok(member_data) = copy_bounded(&data[body_start..body_end], member_limit)
                else {
                    return emit_issue(
                        limit_issue(self.physical_path, "TAR member exceeds limit"),
                        emit,
                    );
                };
                let control =
                    self.member(member_data, &name, logical, depth, cancellation, emit)?;
                if control == SourceControl::Stop {
                    return Ok(control);
                }
            }
            let padded = size
                .checked_add(511)
                .ok_or_else(|| limit_terminal(self.physical_path))?
                / 512
                * 512;
            let next = body_start
                .checked_add(padded)
                .ok_or_else(|| limit_terminal(self.physical_path))?;
            if next > data.len() {
                return emit_issue(
                    corrupt(self.physical_path, "truncated TAR member padding"),
                    emit,
                );
            }
            offset = next;
        }
        if saw_header {
            Ok(SourceControl::Continue)
        } else {
            emit_issue(corrupt(self.physical_path, "empty TAR stream"), emit)
        }
    }

    fn extract_rar(
        &mut self,
        data: &[u8],
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
            .saturating_sub(self.entries);
        let remaining_bytes = self
            .options
            .limits
            .total_bytes
            .get()
            .saturating_sub(self.expanded);
        let entries = match crate::rar::extract(
            data,
            remaining_entries,
            self.options.limits.member_bytes.get(),
            remaining_bytes,
            cancellation,
        ) {
            Ok(entries) => entries,
            Err(crate::rar::RarFailure::Cancelled) => return Err(SourceError::Cancelled),
            Err(crate::rar::RarFailure::Limit(message)) => {
                return emit_issue(limit_issue(self.physical_path, message), emit);
            }
            Err(crate::rar::RarFailure::Unsupported(message)) => {
                return emit_issue(
                    issue(
                        self.physical_path,
                        SourceStage::ArchiveMember,
                        SourceIssueKind::UnsupportedArchive,
                        message,
                    ),
                    emit,
                );
            }
            Err(crate::rar::RarFailure::Corrupt(message)) => {
                return emit_issue(corrupt(self.physical_path, message), emit);
            }
        };
        for entry in entries {
            if let Err(issue) = self.bump_entry() {
                return emit_issue(issue, emit);
            }
            if entry.is_directory {
                continue;
            }
            let name = clean_member_name(&entry.name);
            let control = self.member(entry.data, &name, logical, depth, cancellation, emit)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        Ok(SourceControl::Continue)
    }

    fn extract_zip(
        &mut self,
        data: &[u8],
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let archive = match rawzip::ZipArchive::from_slice(&data) {
            Ok(archive) => archive,
            Err(error) => return emit_issue(corrupt(self.physical_path, error.to_string()), emit),
        };
        for entry_result in archive.entries() {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            let entry = match entry_result {
                Ok(entry) => entry,
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
            if entry.uncompressed_size_hint() > self.options.limits.member_bytes.get() as u64 {
                return emit_issue(
                    limit_issue(self.physical_path, "ZIP member size exceeds limit"),
                    emit,
                );
            }
            let local = match archive.get_entry(entry.wayfinder()) {
                Ok(local) => local,
                Err(error) => {
                    return emit_issue(member_issue(self.physical_path, error.to_string()), emit);
                }
            };
            let decoded = match self.decode_zip_member(
                local.data(),
                entry.compression_method(),
                cancellation,
                emit,
            )? {
                ZipMemberDecode::Data(value) => value,
                ZipMemberDecode::Skip => continue,
                ZipMemberDecode::Stop => return Ok(SourceControl::Stop),
            };
            if decoded.len() as u64 != entry.uncompressed_size_hint()
                || crc32(&decoded) != entry.crc32()
            {
                let control = emit_issue(
                    issue(
                        self.physical_path,
                        SourceStage::Decode,
                        SourceIssueKind::Decode,
                        "ZIP member size or CRC mismatch",
                    ),
                    emit,
                )?;
                if control == SourceControl::Stop {
                    return Ok(control);
                }
                continue;
            }
            let name = clean_member_name(entry.file_path().as_bytes());
            let control = self.member(decoded, &name, logical, depth, cancellation, emit)?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        Ok(SourceControl::Continue)
    }

    fn decode_zip_member(
        &self,
        input: &[u8],
        method: rawzip::CompressionMethod,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<ZipMemberDecode, SourceError> {
        let remaining = self
            .options
            .limits
            .total_bytes
            .get()
            .saturating_sub(self.expanded);
        let member_limit = remaining.min(self.options.limits.member_bytes.get());
        let Some(result) = decode_zip_data(input, method, member_limit, cancellation) else {
            let issue = issue(
                self.physical_path,
                SourceStage::ArchiveMember,
                SourceIssueKind::UnsupportedArchive,
                format!("unsupported ZIP compression method {method:?}"),
            );
            return emit_issue(issue, emit).map(ZipMemberDecode::from_control);
        };
        match result {
            Ok(value) => Ok(ZipMemberDecode::Data(value)),
            Err(DecodeFailure::Cancelled) => Err(SourceError::Cancelled),
            Err(DecodeFailure::Limit) => emit_issue(
                limit_issue(self.physical_path, "ZIP member size exceeds limit"),
                emit,
            )
            .map(ZipMemberDecode::from_control),
            Err(DecodeFailure::Decode(message)) => emit_issue(
                issue(
                    self.physical_path,
                    SourceStage::Decode,
                    SourceIssueKind::Decode,
                    message,
                ),
                emit,
            )
            .map(ZipMemberDecode::from_control),
        }
    }

    #[allow(clippy::too_many_lines)] // Keep the complete dependency containment boundary adjacent.
    fn extract_7z(
        &mut self,
        data: Vec<u8>,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        if let Err(failure) = preflight_7z(&data, self.options.limits) {
            let issue = match failure {
                SevenPreflightFailure::Limit(message) => limit_issue(self.physical_path, message),
                SevenPreflightFailure::Corrupt(message) => corrupt(self.physical_path, message),
            };
            return emit_issue(issue, emit);
        }
        let mut reader = match open_7z(data, self.options.limits) {
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
        self.entries = match self.entries.checked_add(archive_entries) {
            Some(entries) if entries <= self.options.limits.entries.get() => entries,
            _ => {
                return emit_issue(
                    limit_issue(self.physical_path, "7z entry limit exceeded"),
                    emit,
                );
            }
        };
        if let Err(message) =
            preflight_7z_archive(reader.archive(), self.options.limits, self.expanded)
        {
            return emit_issue(limit_issue(self.physical_path, message), emit);
        }
        let entry_limit = archive_entries;
        let member_limit = self.options.limits.member_bytes.get();
        let total_limit = self
            .options
            .limits
            .total_bytes
            .get()
            .saturating_sub(self.expanded);
        let mut extracted = Vec::<(Vec<u8>, Vec<u8>, Vec<usize>)>::new();
        if extracted.try_reserve_exact(archive_entries).is_err() {
            return emit_issue(
                limit_issue(self.physical_path, "could not retain 7z entry metadata"),
                emit,
            );
        }
        let mut local_total = 0_usize;
        let mut cancelled = false;
        let mut visit = |entry: &rustleaks_sevenz::ArchiveEntry, stream: &mut dyn Read| {
            if cancellation.is_cancelled() {
                cancelled = true;
                return Err(seven_error("source cancelled"));
            }
            if entry.is_directory() {
                return Ok(true);
            }
            if extracted.len() >= entry_limit || entry.size() > member_limit as u64 {
                return Err(seven_error("archive resource limit exceeded"));
            }
            let (bytes, read_chunks) = read_member(
                stream,
                member_limit,
                self.file_options.chunk_size().min(member_limit),
                cancellation,
            )
            .map_err(seven_error)?;
            local_total = local_total
                .checked_add(bytes.len())
                .ok_or_else(|| seven_error("archive resource limit overflow"))?;
            if local_total > total_limit {
                return Err(seven_error("archive cumulative limit exceeded"));
            }
            let name = copy_bounded(entry.name().as_bytes(), member_limit)
                .map_err(|_| seven_error("archive entry name exceeds resource limit"))?;
            extracted.push((name, bytes, read_chunks));
            Ok(true)
        };
        #[cfg(panic = "unwind")]
        let Ok(result) = catch_unwind(AssertUnwindSafe(|| reader.for_each_entries(&mut visit)))
        else {
            return emit_issue(
                corrupt(self.physical_path, "7z decoder panicked on untrusted input"),
                emit,
            );
        };
        #[cfg(panic = "abort")]
        let result = reader.for_each_entries(&mut visit);
        if cancelled {
            return Err(SourceError::Cancelled);
        }
        if let Err(error) = result {
            let message = error.to_string();
            let kind = if message.contains("limit") {
                limit_issue(self.physical_path, message)
            } else {
                issue(
                    self.physical_path,
                    SourceStage::Decode,
                    SourceIssueKind::Decode,
                    message,
                )
            };
            return emit_issue(kind, emit);
        }
        self.emit_7z_members(extracted, logical, depth, cancellation, emit)
    }

    fn emit_7z_members(
        &mut self,
        extracted: Vec<(Vec<u8>, Vec<u8>, Vec<usize>)>,
        logical: &LogicalPath,
        depth: usize,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        for (name, bytes, read_chunks) in extracted {
            let name = clean_member_name(&name);
            let control = self.member_with_read_chunks(
                bytes,
                read_chunks,
                &name,
                logical,
                depth,
                cancellation,
                emit,
            )?;
            if control == SourceControl::Stop {
                return Ok(control);
            }
        }
        Ok(SourceControl::Continue)
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

fn open_7z(
    data: Vec<u8>,
    limits: ArchiveLimits,
) -> Result<rustleaks_sevenz::ArchiveReader<Cursor<Vec<u8>>>, SevenOpenFailure> {
    #[cfg(panic = "abort")]
    {
        let _ = (data, limits);
        return Err(SevenOpenFailure {
            kind: SourceIssueKind::UnsupportedArchive,
            message: "7z decoding is unavailable when dependency panics abort the process"
                .to_owned(),
        });
    }

    #[cfg(panic = "unwind")]
    {
        let memory_limit_kb = limits.member_bytes.get().div_ceil(1024).max(1);
        let parsed = catch_unwind(AssertUnwindSafe(|| {
            rustleaks_sevenz::ArchiveReader::new_with_memory_limit_kb(
                Cursor::new(data),
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

fn preflight_7z_archive(
    archive: &rustleaks_sevenz::Archive,
    limits: ArchiveLimits,
    expanded: usize,
) -> Result<(), &'static str> {
    let remaining = limits.total_bytes.get().saturating_sub(expanded);
    if archive.blocks.iter().any(|block| {
        usize::try_from(block.get_unpack_size()).map_or(true, |size| {
            size > limits.member_bytes.get() || size > remaining
        })
    }) {
        return Err("7z block size exceeds limit");
    }
    if archive.files.iter().any(|entry| {
        usize::try_from(entry.size()).map_or(true, |size| {
            size > limits.member_bytes.get() || entry.name().len() > limits.spool_bytes.get()
        })
    }) {
        return Err("7z entry metadata exceeds limit");
    }
    Ok(())
}

fn preflight_7z(data: &[u8], limits: ArchiveLimits) -> Result<(), SevenPreflightFailure> {
    const SIGNATURE: &[u8; 6] = b"7z\xbc\xaf'\x1c";
    const HEADER_BYTES: usize = 32;

    if data.len() < HEADER_BYTES || &data[..SIGNATURE.len()] != SIGNATURE {
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
    let offset = usize::try_from(offset)
        .map_err(|_| SevenPreflightFailure::Limit("7z next-header offset exceeds limit"))?;
    let size = usize::try_from(size)
        .map_err(|_| SevenPreflightFailure::Limit("7z next-header size exceeds limit"))?;
    if size > limits.member_bytes.get() || size > limits.spool_bytes.get() {
        return Err(SevenPreflightFailure::Limit(
            "7z next-header size exceeds limit",
        ));
    }
    let start = HEADER_BYTES
        .checked_add(offset)
        .ok_or(SevenPreflightFailure::Limit(
            "7z next-header offset overflow",
        ))?;
    let end = start
        .checked_add(size)
        .ok_or(SevenPreflightFailure::Limit("7z next-header size overflow"))?;
    if end > data.len() {
        return Err(SevenPreflightFailure::Corrupt(
            "7z next-header range exceeds input",
        ));
    }
    Ok(())
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

pub(crate) fn name_is_archive(name: &[u8]) -> bool {
    identify(name).is_some()
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

fn decode_gzip(
    input: &[u8],
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, DecodeFailure> {
    let mut position = 0_usize;
    let mut output = Vec::new();
    while position < input.len() {
        let body = gzip_body_offset(input, position)?;
        let remaining = limit.saturating_sub(output.len());
        let (member, compressed_bytes) = inflate_member_checked(
            &input[body..],
            remaining,
            miniz_oxide::DataFormat::Raw,
            cancellation,
            "gzip",
        )?;
        let trailer_start = body
            .checked_add(compressed_bytes)
            .ok_or(DecodeFailure::Limit)?;
        let trailer_end = trailer_start.checked_add(8).ok_or(DecodeFailure::Limit)?;
        let trailer = input
            .get(trailer_start..trailer_end)
            .ok_or_else(|| DecodeFailure::Decode("truncated gzip trailer".to_owned()))?;
        let expected_crc = u32::from_le_bytes(trailer[..4].try_into().expect("four bytes"));
        let expected_size = u32::from_le_bytes(trailer[4..].try_into().expect("four bytes"));
        if crc32(&member) != expected_crc
            || usize::try_from(expected_size).ok() != Some(member.len())
        {
            return Err(DecodeFailure::Decode(
                "gzip size or CRC mismatch".to_owned(),
            ));
        }
        extend_bounded(&mut output, &member, limit)?;
        position = trailer_end;
    }
    if output.is_empty() && input.is_empty() {
        return Err(DecodeFailure::Decode("empty gzip stream".to_owned()));
    }
    Ok(output)
}

fn gzip_body_offset(input: &[u8], start: usize) -> Result<usize, DecodeFailure> {
    let header = input
        .get(start..start.saturating_add(10))
        .ok_or_else(|| DecodeFailure::Decode("invalid gzip header".to_owned()))?;
    if header.get(..2) != Some(&[0x1f, 0x8b]) || header[2] != 8 {
        return Err(DecodeFailure::Decode("invalid gzip header".to_owned()));
    }
    let flags = header[3];
    if flags & 0xe0 != 0 {
        return Err(DecodeFailure::Decode("invalid gzip flags".to_owned()));
    }
    let mut offset = start.checked_add(10).ok_or(DecodeFailure::Limit)?;
    if flags & 4 != 0 {
        let size = read_le_u16(input, offset)
            .ok_or_else(|| DecodeFailure::Decode("truncated gzip extra field".to_owned()))?
            as usize;
        offset = offset
            .checked_add(2)
            .and_then(|value| value.checked_add(size))
            .ok_or(DecodeFailure::Limit)?;
    }
    for bit in [8_u8, 16] {
        if flags & bit != 0 {
            offset = input
                .get(offset..)
                .and_then(|rest| rest.iter().position(|byte| *byte == 0))
                .and_then(|at| offset.checked_add(at + 1))
                .ok_or_else(|| DecodeFailure::Decode("truncated gzip string field".to_owned()))?;
        }
    }
    if flags & 2 != 0 {
        offset = offset.checked_add(2).ok_or(DecodeFailure::Limit)?;
    }
    if offset > input.len() {
        return Err(DecodeFailure::Decode("truncated gzip header".to_owned()));
    }
    Ok(offset)
}

fn decode_zip_data(
    input: &[u8],
    method: rawzip::CompressionMethod,
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Option<Result<Vec<u8>, DecodeFailure>> {
    if method == rawzip::CompressionMethod::STORE {
        Some(copy_bounded(input, limit))
    } else if method == rawzip::CompressionMethod::DEFLATE {
        Some(inflate_checked(
            input,
            limit,
            miniz_oxide::DataFormat::Raw,
            cancellation,
            "ZIP member",
        ))
    } else {
        None
    }
}

fn inflate_checked(
    input: &[u8],
    limit: usize,
    format: miniz_oxide::DataFormat,
    cancellation: &dyn Cancellation,
    label: &str,
) -> Result<Vec<u8>, DecodeFailure> {
    inflate_member_checked(input, limit, format, cancellation, label).map(|(output, _)| output)
}

fn inflate_member_checked(
    input: &[u8],
    limit: usize,
    format: miniz_oxide::DataFormat,
    cancellation: &dyn Cancellation,
    label: &str,
) -> Result<(Vec<u8>, usize), DecodeFailure> {
    use miniz_oxide::inflate::stream::{InflateState, inflate};
    use miniz_oxide::{MZFlush, MZStatus};

    let mut state = InflateState::new_boxed(format);
    let mut input_position = 0_usize;
    let mut output = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER];
    loop {
        if cancellation.is_cancelled() {
            return Err(DecodeFailure::Cancelled);
        }
        let result = inflate(
            &mut state,
            &input[input_position..],
            &mut buffer,
            MZFlush::None,
        );
        input_position = input_position
            .checked_add(result.bytes_consumed)
            .ok_or(DecodeFailure::Limit)?;
        extend_bounded(&mut output, &buffer[..result.bytes_written], limit)?;
        match result.status {
            Ok(MZStatus::StreamEnd) => return Ok((output, input_position)),
            Ok(MZStatus::Ok) => {}
            Ok(status) => {
                return Err(DecodeFailure::Decode(format!(
                    "{label} decode returned unexpected status {status:?}"
                )));
            }
            Err(error) => {
                return Err(DecodeFailure::Decode(format!(
                    "{label} decode failed: {error:?}"
                )));
            }
        }
        if result.bytes_consumed == 0 && result.bytes_written == 0 {
            return Err(DecodeFailure::Decode(format!(
                "{label} decoder stopped making progress"
            )));
        }
    }
}

fn decode_reader(
    mut reader: impl Read,
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, DecodeFailure> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER];
    loop {
        if cancellation.is_cancelled() {
            return Err(DecodeFailure::Cancelled);
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|error| DecodeFailure::Decode(error.to_string()))?;
        if count == 0 {
            return Ok(output);
        }
        extend_bounded(&mut output, &buffer[..count], limit)?;
    }
}

fn decode_lzip(
    input: &[u8],
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, DecodeFailure> {
    let limit_kb = limit
        .checked_add(1023)
        .map(|bytes| bytes / 1024)
        .and_then(|kilobytes| u32::try_from(kilobytes).ok())
        .unwrap_or(u32::MAX);
    let mut stream = lzma_rust2::LzipStream::new_mem_limit(limit_kb);
    let mut input_position = 0_usize;
    let mut output = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER];
    loop {
        if cancellation.is_cancelled() {
            return Err(DecodeFailure::Cancelled);
        }
        let result = stream
            .process(
                &input[input_position..],
                &mut buffer,
                lzma_rust2::Action::Finish,
            )
            .map_err(|error| DecodeFailure::Decode(error.to_string()))?;
        input_position = input_position
            .checked_add(result.bytes_consumed)
            .ok_or(DecodeFailure::Limit)?;
        extend_bounded(&mut output, &buffer[..result.bytes_produced], limit)?;
        if result.status == lzma_rust2::Status::StreamEnd {
            return Ok(output);
        }
        if result.bytes_consumed == 0 && result.bytes_produced == 0 {
            return Err(DecodeFailure::Decode(
                "LZIP decoder stopped making progress".to_owned(),
            ));
        }
    }
}

fn decode_zstd(
    input: &[u8],
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, DecodeFailure> {
    let mut history = allocate_zeroed(limit)?;
    let mut block = allocate_zeroed(zstd_zero::MAX_BLOCK_SIZE)?;
    let mut literals = allocate_zeroed(zstd_zero::MAX_BLOCK_SIZE)?;
    let mut decoder = zstd_zero::Decoder::new(zstd_zero::DecoderBuffers {
        history: &mut history,
        block: &mut block,
        literals: &mut literals,
    });
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

fn allocate_zeroed(size: usize) -> Result<Vec<u8>, DecodeFailure> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| DecodeFailure::Limit)?;
    value.resize(size, 0);
    Ok(value)
}

fn copy_bounded(input: &[u8], limit: usize) -> Result<Vec<u8>, DecodeFailure> {
    if input.len() > limit {
        return Err(DecodeFailure::Limit);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| DecodeFailure::Limit)?;
    output.extend_from_slice(input);
    Ok(output)
}

fn extend_bounded(output: &mut Vec<u8>, input: &[u8], limit: usize) -> Result<(), DecodeFailure> {
    if output
        .len()
        .checked_add(input.len())
        .is_none_or(|size| size > limit)
    {
        return Err(DecodeFailure::Limit);
    }
    output
        .try_reserve(input.len())
        .map_err(|_| DecodeFailure::Limit)?;
    output.extend_from_slice(input);
    Ok(())
}

fn crc32(input: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let polynomial = 0xedb8_8320 & 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ polynomial;
        }
    }
    !crc
}

enum DecodeFailure {
    Cancelled,
    Limit,
    Decode(String),
}

enum ZipMemberDecode {
    Data(Vec<u8>),
    Skip,
    Stop,
}

impl ZipMemberDecode {
    fn from_control(control: SourceControl) -> Self {
        match control {
            SourceControl::Continue => Self::Skip,
            SourceControl::Stop => Self::Stop,
        }
    }
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

fn seven_error(message: impl Into<String>) -> rustleaks_sevenz::Error {
    rustleaks_sevenz::Error::from(std::io::Error::other(message.into()))
}

impl DecodeFailure {
    fn into_issue(self, path: &Path) -> SourceIssue {
        match self {
            Self::Cancelled => issue(
                path,
                SourceStage::Decode,
                SourceIssueKind::Decode,
                "source cancelled during archive decode",
            ),
            Self::Limit => limit_issue(path, "archive expansion limit exceeded"),
            Self::Decode(message) => {
                issue(path, SourceStage::Decode, SourceIssueKind::Decode, message)
            }
        }
    }
}

fn plain_source(
    reader: Box<dyn Read + Send>,
    physical: &Path,
    logical: &LogicalPath,
    symlink: Option<&PathBuf>,
    options: FileOptions,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    let mut source = FileSource::with_options(reader, physical.to_path_buf(), options)
        .with_logical_path(logical.clone());
    if let Some(symlink) = symlink {
        source = source.with_symlink_path(symlink.clone());
    }
    source.visit(cancellation, emit)
}

enum ReadBoundedError {
    Cancelled,
    Limit,
    Io(String),
}

fn read_bounded(
    mut reader: Box<dyn Read + Send>,
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, ReadBoundedError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER];
    loop {
        if cancellation.is_cancelled() {
            return Err(ReadBoundedError::Cancelled);
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|error| ReadBoundedError::Io(error.to_string()))?;
        if count == 0 {
            return Ok(output);
        }
        if output
            .len()
            .checked_add(count)
            .is_none_or(|size| size > limit)
        {
            return Err(ReadBoundedError::Limit);
        }
        output
            .try_reserve(count)
            .map_err(|_| ReadBoundedError::Limit)?;
        output.extend_from_slice(&buffer[..count]);
    }
}

fn read_member(
    reader: &mut dyn Read,
    limit: usize,
    buffer_size: usize,
    cancellation: &dyn Cancellation,
) -> Result<(Vec<u8>, Vec<usize>), String> {
    let mut output = Vec::new();
    let mut read_chunks = Vec::new();
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(buffer_size)
        .map_err(|_| "could not allocate archive member read buffer".to_owned())?;
    buffer.resize(buffer_size, 0);
    loop {
        if cancellation.is_cancelled() {
            return Err("source cancelled".to_owned());
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Ok((output, read_chunks));
        }
        if output
            .len()
            .checked_add(count)
            .is_none_or(|size| size > limit)
        {
            return Err("archive member limit exceeded".to_owned());
        }
        output
            .try_reserve(count)
            .map_err(|_| "could not allocate archive member buffer".to_owned())?;
        output.extend_from_slice(&buffer[..count]);
        read_chunks
            .try_reserve(1)
            .map_err(|_| "could not retain archive member read boundaries".to_owned())?;
        read_chunks.push(count);
    }
}

struct ChunkedCursor {
    data: Vec<u8>,
    chunks: Vec<usize>,
    position: usize,
    chunk_index: usize,
    chunk_end: usize,
}

impl ChunkedCursor {
    fn new(data: Vec<u8>, chunks: Vec<usize>) -> Self {
        let chunk_end = chunks
            .first()
            .copied()
            .unwrap_or(data.len())
            .min(data.len());
        Self {
            data,
            chunks,
            position: 0,
            chunk_index: 0,
            chunk_end,
        }
    }
}

impl Read for ChunkedCursor {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.position == self.data.len() {
            return Ok(0);
        }
        while self.position == self.chunk_end && self.chunk_index + 1 < self.chunks.len() {
            self.chunk_index += 1;
            self.chunk_end = self
                .chunk_end
                .checked_add(self.chunks[self.chunk_index])
                .ok_or_else(|| std::io::Error::other("archive read-boundary overflow"))?
                .min(self.data.len());
        }
        if self.position == self.chunk_end {
            self.chunk_end = self.data.len();
        }
        let count = output
            .len()
            .min(self.chunk_end.saturating_sub(self.position));
        output[..count].copy_from_slice(&self.data[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
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

fn read_le_u16(input: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        input.get(offset..offset + 2)?.try_into().ok()?,
    ))
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

fn limit_terminal(path: &Path) -> SourceError {
    limit_terminal_message(path, "archive arithmetic overflow")
}

fn limit_terminal_message(path: &Path, message: impl Into<String>) -> SourceError {
    SourceError::Terminal {
        stage: SourceStage::Limit,
        path: Some(path.to_path_buf()),
        message: message.into(),
    }
}

fn emit_issue(
    issue: SourceIssue,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    emit(SourceEvent::Issue(issue)).map_err(SourceError::Callback)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        match open_7z(Vec::new(), ArchiveLimits::default()) {
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
        assert_eq!(clean_member_name(b"a/./b/../c"), b"a/c");
        assert_eq!(clean_member_name(b"../../a"), b"../../a");
    }

    #[test]
    fn owned_crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
