use std::collections::VecDeque;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use rustleaks_core::model::Fragment;

use crate::mime;
use crate::{
    CallbackError, Cancellation, LogicalPath, Source, SourceConfigError, SourceControl,
    SourceError, SourceEvent, SourceIssue, SourceIssueKind, SourceStage,
};

/// Pinned nominal file-fragment size in bytes.
pub const DEFAULT_CHUNK_SIZE: usize = 100_000;

/// Maximum number of bytes appended while seeking a safe split boundary.
pub const MAX_BOUNDARY_READ_AHEAD: usize = 25_000;

const BUFFERED_READER_CAPACITY: usize = 4_096;

/// Status returned with bytes from a [`SourceReader`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadStatus {
    /// More bytes may be available.
    Continue,
    /// End of input was observed with this read.
    Eof,
    /// A non-EOF read error was observed with this read.
    Error {
        /// Portable standard-library error category.
        kind: io::ErrorKind,
        /// Reader diagnostic.
        message: String,
    },
}

impl ReadStatus {
    /// Converts a standard I/O error into a read status.
    #[must_use]
    pub fn error(error: &io::Error) -> Self {
        Self::Error {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

/// One source-reader operation, including Go-observable data-plus-error states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOutcome {
    count: usize,
    status: ReadStatus,
}

impl ReadOutcome {
    /// Creates an outcome for `count` initialized bytes in the supplied buffer.
    #[must_use]
    pub const fn new(count: usize, status: ReadStatus) -> Self {
        Self { count, status }
    }

    /// Returns the initialized byte count.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns the accompanying status.
    #[must_use]
    pub const fn status(&self) -> &ReadStatus {
        &self.status
    }
}

/// Read protocol capable of representing bytes and an error simultaneously.
///
/// Standard Rust readers can use [`FileSource::new`]. This lower-level seam is
/// useful for compatibility adapters and deterministic fault injection.
pub trait SourceReader: Send {
    /// Fills at most `buffer.len()` bytes and reports their status.
    fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome;
}

struct StandardReader<R>(R);

impl<R: Read + Send> SourceReader for StandardReader<R> {
    fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
        match self.0.read(buffer) {
            Ok(0) => ReadOutcome::new(0, ReadStatus::Eof),
            Ok(count) => ReadOutcome::new(count, ReadStatus::Continue),
            Err(error) => ReadOutcome::new(0, ReadStatus::error(&error)),
        }
    }
}

struct BufferedSourceReader {
    inner: Box<dyn SourceReader>,
    buffered: VecDeque<u8>,
    pending: Option<ReadStatus>,
    overreported: Option<usize>,
}

enum ByteOutcome {
    Byte(u8),
    Status(ReadStatus),
    Overreported,
}

impl BufferedSourceReader {
    fn new(inner: Box<dyn SourceReader>) -> Self {
        Self {
            inner,
            buffered: VecDeque::with_capacity(BUFFERED_READER_CAPACITY),
            pending: None,
            overreported: None,
        }
    }

    fn read(&mut self, output: &mut [u8]) -> ReadOutcome {
        if output.is_empty() {
            return ReadOutcome::new(0, ReadStatus::Continue);
        }
        if let Some(count) = self.overreported.take() {
            return ReadOutcome::new(count, ReadStatus::Continue);
        }
        if !self.buffered.is_empty() {
            let count = drain(&mut self.buffered, output);
            return ReadOutcome::new(count, ReadStatus::Continue);
        }
        if let Some(status) = self.pending.take() {
            return ReadOutcome::new(0, status);
        }
        if output.len() >= BUFFERED_READER_CAPACITY {
            return self.inner.read_source(output);
        }

        self.fill();
        if let Some(count) = self.overreported.take() {
            return ReadOutcome::new(count, ReadStatus::Continue);
        }
        if self.buffered.is_empty() {
            return ReadOutcome::new(0, self.pending.take().unwrap_or(ReadStatus::Continue));
        }
        let count = drain(&mut self.buffered, output);
        ReadOutcome::new(count, ReadStatus::Continue)
    }

    fn read_byte(&mut self) -> ByteOutcome {
        if self.overreported.take().is_some() {
            return ByteOutcome::Overreported;
        }
        if self.buffered.is_empty() {
            if let Some(status) = self.pending.take() {
                return ByteOutcome::Status(status);
            }
            self.fill();
        }
        if self.overreported.take().is_some() {
            return ByteOutcome::Overreported;
        }
        if let Some(byte) = self.buffered.pop_front() {
            return ByteOutcome::Byte(byte);
        }
        ByteOutcome::Status(self.pending.take().unwrap_or(ReadStatus::Continue))
    }

    fn fill(&mut self) {
        let mut temporary = [0_u8; BUFFERED_READER_CAPACITY];
        let outcome = self.inner.read_source(&mut temporary);
        if outcome.count > temporary.len() {
            self.overreported = Some(outcome.count);
            return;
        }
        self.buffered.extend(&temporary[..outcome.count]);
        if !matches!(outcome.status, ReadStatus::Continue) {
            self.pending = Some(outcome.status);
        }
    }
}

fn drain(buffered: &mut VecDeque<u8>, output: &mut [u8]) -> usize {
    let count = buffered.len().min(output.len());
    for slot in &mut output[..count] {
        if let Some(byte) = buffered.pop_front() {
            *slot = byte;
        }
    }
    count
}

/// Validated file chunking options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOptions {
    chunk_size: NonZeroUsize,
    max_boundary_read_ahead: usize,
}

impl FileOptions {
    /// Creates options with an exact positive nominal chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`SourceConfigError`] when `chunk_size` is zero.
    pub fn new(chunk_size: usize) -> Result<Self, SourceConfigError> {
        let chunk_size = NonZeroUsize::new(chunk_size)
            .ok_or_else(|| SourceConfigError::positive("chunk_size"))?;
        Ok(Self {
            chunk_size,
            max_boundary_read_ahead: MAX_BOUNDARY_READ_AHEAD,
        })
    }

    /// Returns the exact nominal chunk size.
    #[must_use]
    pub const fn chunk_size(self) -> usize {
        self.chunk_size.get()
    }

    /// Sets the maximum bytes appended while seeking a safe split boundary.
    #[must_use]
    pub const fn max_boundary_read_ahead(mut self, maximum: usize) -> Self {
        self.max_boundary_read_ahead = maximum;
        self
    }

    /// Returns the configured boundary read-ahead ceiling.
    #[must_use]
    pub const fn maximum_boundary_read_ahead(self) -> usize {
        self.max_boundary_read_ahead
    }
}

impl Default for FileOptions {
    fn default() -> Self {
        Self {
            chunk_size: NonZeroUsize::new(DEFAULT_CHUNK_SIZE)
                .expect("the pinned default chunk size is positive"),
            max_boundary_read_ahead: MAX_BOUNDARY_READ_AHEAD,
        }
    }
}

/// One safe, synchronous reader-backed file source.
pub struct FileSource {
    reader: BufferedSourceReader,
    physical_path: PathBuf,
    logical_path: LogicalPath,
    symlink_path: Option<PathBuf>,
    options: FileOptions,
}

impl FileSource {
    /// Creates a file source from a standard Rust reader using pinned defaults.
    #[must_use]
    pub fn new<R>(reader: R, path: impl Into<PathBuf>) -> Self
    where
        R: Read + Send + 'static,
    {
        Self::with_options(reader, path, FileOptions::default())
    }

    /// Creates a file source from a standard reader and validated options.
    #[must_use]
    pub fn with_options<R>(reader: R, path: impl Into<PathBuf>, options: FileOptions) -> Self
    where
        R: Read + Send + 'static,
    {
        Self::from_source_reader(Box::new(StandardReader(reader)), path, options)
    }

    /// Creates a source from the compatibility read protocol.
    #[must_use]
    pub fn from_source_reader(
        reader: Box<dyn SourceReader>,
        path: impl Into<PathBuf>,
        options: FileOptions,
    ) -> Self {
        let physical_path = path.into();
        let logical_path = LogicalPath::from_native(&physical_path);
        Self {
            reader: BufferedSourceReader::new(reader),
            physical_path,
            logical_path,
            symlink_path: None,
            options,
        }
    }

    /// Records the discovered symlink alias while retaining the target path as
    /// the fragment's file path.
    #[must_use]
    pub fn with_symlink_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.symlink_path = Some(path.into());
        self
    }

    #[cfg(feature = "archives")]
    pub(crate) fn with_logical_path(mut self, path: LogicalPath) -> Self {
        self.logical_path = path;
        self
    }

    /// Returns the physical path used for diagnostics.
    #[must_use]
    pub fn physical_path(&self) -> &Path {
        &self.physical_path
    }

    fn issue(
        &self,
        stage: SourceStage,
        kind: SourceIssueKind,
        message: impl Into<String>,
    ) -> SourceIssue {
        SourceIssue::new(stage, kind, Some(self.physical_path.clone()), message)
    }

    fn emit(
        event: SourceEvent,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        emit(event).map_err(SourceError::Callback)
    }

    fn fragment(&self, bytes: Vec<u8>, start_line: usize) -> Fragment {
        let mut builder = Fragment::builder(bytes)
            .file_path(self.logical_path.normalized().clone())
            .start_line(start_line);
        if let Some(original) = self.logical_path.windows_original() {
            builder = builder.windows_file_path(original.clone());
        }
        if let Some(symlink) = &self.symlink_path {
            builder = builder.symlink_file(LogicalPath::from_native(symlink).normalized().clone());
        }
        builder.build()
    }

    fn error_fragment(&self) -> Fragment {
        let path = self
            .logical_path
            .windows_original()
            .unwrap_or_else(|| self.logical_path.normalized());
        Fragment::builder(Vec::<u8>::new())
            .file_path(path.clone())
            .build()
    }
}

impl Source for FileSource {
    fn visit(
        &mut self,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut total_lines = 0_usize;
        let mut nominal = allocate_nominal(self.options.chunk_size(), &self.physical_path)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }

            let outcome = self.reader.read(&mut nominal);
            if outcome.count > nominal.len() {
                let issue = self.issue(
                    SourceStage::Limit,
                    SourceIssueKind::Limit,
                    "reader returned more bytes than the supplied buffer",
                );
                return Self::emit(SourceEvent::Issue(issue), emit);
            }
            if outcome.count == 0 {
                if let ReadStatus::Error { message, .. } = outcome.status {
                    let issue = self.issue(SourceStage::Read, SourceIssueKind::Read, message);
                    return Self::emit(
                        SourceEvent::Fragment {
                            fragment: Box::new(self.error_fragment()),
                            issue: Some(issue),
                        },
                        emit,
                    );
                }
                return Ok(SourceControl::Continue);
            }

            let original = &nominal[..outcome.count];
            if total_lines == 0 && mime::is_application(original) {
                return Ok(SourceControl::Continue);
            }

            let fragment_capacity = outcome
                .count
                .checked_add(self.options.max_boundary_read_ahead)
                .ok_or_else(|| SourceError::Terminal {
                    stage: SourceStage::Limit,
                    path: Some(self.physical_path.clone()),
                    message: "fragment buffer capacity overflow".to_owned(),
                })?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(fragment_capacity)
                .map_err(|error| SourceError::Terminal {
                    stage: SourceStage::Limit,
                    path: Some(self.physical_path.clone()),
                    message: format!("could not allocate fragment buffer: {error}"),
                })?;
            bytes.extend_from_slice(original);
            if let Err(issue) = read_until_safe_boundary(
                &mut self.reader,
                outcome.count,
                &mut bytes,
                &self.physical_path,
                self.options.max_boundary_read_ahead,
                cancellation,
            ) {
                if cancellation.is_cancelled() {
                    return Err(SourceError::Cancelled);
                }
                return Self::emit(
                    SourceEvent::Fragment {
                        fragment: Box::new(self.error_fragment()),
                        issue: Some(issue),
                    },
                    emit,
                );
            }

            let start_line = total_lines
                .checked_add(1)
                .ok_or_else(|| SourceError::Terminal {
                    stage: SourceStage::Limit,
                    path: Some(self.physical_path.clone()),
                    message: "fragment start line overflow".to_owned(),
                })?;
            let line_count = count_lf(&bytes);
            total_lines =
                total_lines
                    .checked_add(line_count)
                    .ok_or_else(|| SourceError::Terminal {
                        stage: SourceStage::Limit,
                        path: Some(self.physical_path.clone()),
                        message: "line count overflow".to_owned(),
                    })?;

            let issue = match &outcome.status {
                ReadStatus::Error { message, .. } => {
                    Some(self.issue(SourceStage::Read, SourceIssueKind::Read, message.clone()))
                }
                ReadStatus::Continue | ReadStatus::Eof => None,
            };
            let fragment = Box::new(self.fragment(bytes, start_line));
            let control = Self::emit(SourceEvent::Fragment { fragment, issue }, emit)?;
            if control == SourceControl::Stop || matches!(outcome.status, ReadStatus::Eof) {
                return Ok(control);
            }
        }
    }
}

fn allocate_nominal(size: usize, path: &Path) -> Result<Vec<u8>, SourceError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size)
        .map_err(|error| SourceError::Terminal {
            stage: SourceStage::Limit,
            path: Some(path.to_path_buf()),
            message: format!("could not allocate nominal chunk buffer: {error}"),
        })?;
    buffer.resize(size, 0);
    Ok(buffer)
}

fn read_until_safe_boundary(
    reader: &mut BufferedSourceReader,
    nominal_count: usize,
    bytes: &mut Vec<u8>,
    path: &Path,
    maximum: usize,
    cancellation: &dyn Cancellation,
) -> Result<(), SourceIssue> {
    if bytes.is_empty() || suffix_is_safe(bytes) {
        return Ok(());
    }

    let mut newline_count = 0_u8;
    loop {
        let last = bytes[bytes.len() - 1];
        if last == b'\n' {
            newline_count += 1;
            if newline_count >= 2 {
                break;
            }
        } else if !is_boundary_whitespace(last) {
            newline_count = 0;
        }

        let appended = bytes.len().checked_sub(nominal_count).ok_or_else(|| {
            SourceIssue::new(
                SourceStage::Limit,
                SourceIssueKind::Limit,
                Some(path.to_path_buf()),
                "boundary byte accounting underflow",
            )
        })?;
        if appended >= maximum {
            break;
        }
        if cancellation.is_cancelled() {
            return Err(SourceIssue::new(
                SourceStage::BoundaryRead,
                SourceIssueKind::Read,
                Some(path.to_path_buf()),
                "source cancelled during boundary read",
            ));
        }

        match reader.read_byte() {
            ByteOutcome::Byte(byte) => {
                bytes.push(byte);
            }
            ByteOutcome::Status(ReadStatus::Eof) => break,
            ByteOutcome::Status(ReadStatus::Error { message, .. }) => {
                return Err(SourceIssue::new(
                    SourceStage::BoundaryRead,
                    SourceIssueKind::BoundaryRead,
                    Some(path.to_path_buf()),
                    message,
                ));
            }
            ByteOutcome::Status(ReadStatus::Continue) => {
                return Err(SourceIssue::new(
                    SourceStage::BoundaryRead,
                    SourceIssueKind::BoundaryRead,
                    Some(path.to_path_buf()),
                    "reader made no progress during boundary read",
                ));
            }
            ByteOutcome::Overreported => {
                return Err(SourceIssue::new(
                    SourceStage::Limit,
                    SourceIssueKind::Limit,
                    Some(path.to_path_buf()),
                    "reader returned more bytes than the supplied buffer",
                ));
            }
        }
    }
    Ok(())
}

fn suffix_is_safe(bytes: &[u8]) -> bool {
    if !bytes.last().copied().is_some_and(is_boundary_whitespace) {
        return false;
    }
    let mut newlines = 0_u8;
    for byte in bytes.iter().rev().copied() {
        if byte == b'\n' {
            newlines += 1;
            if newlines >= 2 {
                return true;
            }
        } else if !is_boundary_whitespace(byte) {
            break;
        }
    }
    false
}

const fn is_boundary_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn count_lf(bytes: &[u8]) -> usize {
    let mut count = 0;
    for byte in bytes {
        if *byte == b'\n' {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;

    struct OverreportingReader;

    impl SourceReader for OverreportingReader {
        fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
            ReadOutcome::new(buffer.len().saturating_add(1), ReadStatus::Continue)
        }
    }

    struct BurstThenError {
        emitted: bool,
    }

    impl SourceReader for BurstThenError {
        fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
            if self.emitted {
                return ReadOutcome::new(0, ReadStatus::Eof);
            }
            self.emitted = true;
            buffer[..15].fill(b'x');
            ReadOutcome::new(
                15,
                ReadStatus::Error {
                    kind: io::ErrorKind::InvalidData,
                    message: "scheduled reader failure".to_owned(),
                },
            )
        }
    }

    fn fragments(mut source: FileSource) -> Vec<Fragment> {
        let mut result = Vec::new();
        source
            .visit(&CancellationToken::new(), &mut |event| {
                if let SourceEvent::Fragment { fragment, .. } = event {
                    result.push(*fragment);
                }
                Ok(SourceControl::Continue)
            })
            .expect("source visit succeeds");
        result
    }

    #[test]
    fn boundary_cases_match_upstream_bytes() {
        let cases = [
            (
                b"abc\n\ndefghijklmnop\n\nqrstuvwxyz".as_slice(),
                b"abc\n\n".as_slice(),
            ),
            (
                b"a\r\n\r\nbcdefghijklmnop\n".as_slice(),
                b"a\r\n\r\n".as_slice(),
            ),
            (
                b"abcdefg\nhijklmnop\n\nqrstuvwxyz".as_slice(),
                b"abcdefg\nhijklmnop\n\n".as_slice(),
            ),
            (
                b"abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz".as_slice(),
                b"abcdefg\nhijklmnop\n\t  \t\n".as_slice(),
            ),
        ];
        for (input, expected) in cases {
            let options = FileOptions::new(5).expect("positive");
            let actual = fragments(FileSource::with_options(input, "input", options));
            assert_eq!(actual[0].content().as_bytes(), expected);
        }
    }

    #[test]
    fn hard_ceiling_is_exact() {
        let input = vec![b'a'; DEFAULT_CHUNK_SIZE + MAX_BOUNDARY_READ_AHEAD + 1];
        let actual = fragments(FileSource::new(std::io::Cursor::new(input), "input"));
        assert_eq!(actual[0].content().len(), 125_000);
        assert_eq!(actual[1].content().len(), 1);
        assert_eq!(actual[0].start_line(), 1);
        assert_eq!(actual[1].start_line(), 1);
    }

    #[test]
    fn only_lf_advances_start_line() {
        let options = FileOptions::new(3).expect("positive");
        let mut input = b"a\r\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_BOUNDARY_READ_AHEAD));
        input.push(b'c');
        let actual = fragments(FileSource::with_options(
            std::io::Cursor::new(input),
            "input",
            options,
        ));
        assert_eq!(
            actual.iter().map(Fragment::start_line).collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn mime_check_repeats_until_a_lf_is_seen() {
        let mut input = vec![b'x'; BUFFERED_READER_CAPACITY + MAX_BOUNDARY_READ_AHEAD];
        input.extend_from_slice(b"%PDF remainder");
        let options = FileOptions::new(BUFFERED_READER_CAPACITY).expect("positive");
        let actual = fragments(FileSource::with_options(
            std::io::Cursor::new(input),
            "input",
            options,
        ));
        assert_eq!(actual.len(), 1);
        assert_eq!(
            actual[0].content().len(),
            BUFFERED_READER_CAPACITY + MAX_BOUNDARY_READ_AHEAD
        );
    }

    #[test]
    fn buffered_reader_preserves_overreported_count_as_a_limit_issue() {
        let options = FileOptions::new(1)
            .expect("positive")
            .max_boundary_read_ahead(0);
        let mut source =
            FileSource::from_source_reader(Box::new(OverreportingReader), "input", options);
        let mut issues = Vec::new();
        source
            .visit(&CancellationToken::new(), &mut |event| {
                if let SourceEvent::Issue(issue) = event {
                    issues.push(issue);
                }
                Ok(SourceControl::Continue)
            })
            .expect("overreport is a recoverable issue");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].stage(), SourceStage::Limit);
        assert_eq!(issues[0].kind(), SourceIssueKind::Limit);
    }

    #[test]
    fn buffered_data_plus_error_can_emit_sixteen_events() {
        let options = FileOptions::new(1)
            .expect("positive")
            .max_boundary_read_ahead(0);
        let mut source = FileSource::from_source_reader(
            Box::new(BurstThenError { emitted: false }),
            "input",
            options,
        );
        let mut events = 0_usize;
        source
            .visit(&CancellationToken::new(), &mut |_| {
                events += 1;
                Ok(SourceControl::Continue)
            })
            .expect("buffered burst is observable");
        assert_eq!(events, 16);
    }

    #[test]
    fn zero_chunk_size_is_rejected() {
        assert_eq!(
            FileOptions::new(0).expect_err("zero fails").field(),
            "chunk_size"
        );
    }
}
