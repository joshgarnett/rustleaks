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
    storage: Vec<u8>,
    start: usize,
    end: usize,
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
            storage: Vec::new(),
            start: 0,
            end: 0,
            pending: None,
            overreported: None,
        }
    }

    /// Bytes already pulled from the inner reader and not yet delivered.
    fn buffered(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    fn consume(&mut self, count: usize) {
        self.start += count;
    }

    fn drain_into(&mut self, output: &mut [u8]) -> usize {
        let count = self.buffered().len().min(output.len());
        output[..count].copy_from_slice(&self.buffered()[..count]);
        self.consume(count);
        count
    }

    fn read(&mut self, output: &mut [u8]) -> ReadOutcome {
        if output.is_empty() {
            return ReadOutcome::new(0, ReadStatus::Continue);
        }
        if let Some(count) = self.overreported.take() {
            return ReadOutcome::new(count, ReadStatus::Continue);
        }
        if !self.buffered().is_empty() {
            let count = self.drain_into(output);
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
        if self.buffered().is_empty() {
            return ReadOutcome::new(0, self.pending.take().unwrap_or(ReadStatus::Continue));
        }
        let count = self.drain_into(output);
        ReadOutcome::new(count, ReadStatus::Continue)
    }

    fn read_byte(&mut self) -> ByteOutcome {
        if self.overreported.take().is_some() {
            return ByteOutcome::Overreported;
        }
        if self.buffered().is_empty() {
            if let Some(status) = self.pending.take() {
                return ByteOutcome::Status(status);
            }
            self.fill();
        }
        if self.overreported.take().is_some() {
            return ByteOutcome::Overreported;
        }
        if let Some(&byte) = self.buffered().first() {
            self.consume(1);
            return ByteOutcome::Byte(byte);
        }
        ByteOutcome::Status(self.pending.take().unwrap_or(ReadStatus::Continue))
    }

    /// Replaces the empty buffer with one read from the inner reader.
    ///
    /// The reader always receives a zeroed slice of the full capacity.
    fn fill(&mut self) {
        self.storage.clear();
        self.storage.resize(BUFFERED_READER_CAPACITY, 0);
        self.start = 0;
        self.end = 0;
        let outcome = self.inner.read_source(&mut self.storage);
        if outcome.count > BUFFERED_READER_CAPACITY {
            self.overreported = Some(outcome.count);
            return;
        }
        self.end = outcome.count;
        if !matches!(outcome.status, ReadStatus::Continue) {
            self.pending = Some(outcome.status);
        }
    }
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
        self.visit_with_buffer(&mut Vec::new(), cancellation, emit)
    }
}

impl FileSource {
    /// Visits the file using a nominal read buffer retained by the caller.
    ///
    /// Sources that visit many files keep one buffer across them. The buffer
    /// is resized and zeroed only when its length differs from the chunk size,
    /// so callers must pass readers that do not inspect the supplied bytes.
    pub(crate) fn visit_with_buffer(
        &mut self,
        nominal: &mut Vec<u8>,
        cancellation: &dyn Cancellation,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        let mut total_lines = 0_usize;
        if nominal.len() != self.options.chunk_size() {
            *nominal = allocate_nominal(self.options.chunk_size(), &self.physical_path)?;
        }
        let nominal = nominal.as_mut_slice();
        loop {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }

            let outcome = self.reader.read(nominal);
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
    if boundary_reached(&mut newline_count, bytes[bytes.len() - 1]) {
        return Ok(());
    }
    loop {
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

        // Copying bytes already pulled from the reader makes no reader call,
        // so one buffered slice is one work unit between polls. The first byte
        // after a refill stays separate because the refill itself can request
        // cancellation before the next poll.
        let window = reader.buffered();
        if !window.is_empty() {
            let window = &window[..window.len().min(maximum - appended)];
            let (count, found) = scan_boundary(window, &mut newline_count);
            bytes.extend_from_slice(&window[..count]);
            reader.consume(count);
            if found {
                break;
            }
            continue;
        }

        match reader.read_byte() {
            ByteOutcome::Byte(byte) => {
                bytes.push(byte);
                if boundary_reached(&mut newline_count, byte) {
                    break;
                }
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

/// Applies one byte to the boundary state; returns true on the second newline
/// separated from the first only by boundary whitespace.
fn boundary_reached(newline_count: &mut u8, byte: u8) -> bool {
    if byte == b'\n' {
        *newline_count += 1;
        *newline_count >= 2
    } else {
        if !is_boundary_whitespace(byte) {
            *newline_count = 0;
        }
        false
    }
}

/// Returns how many bytes of `window` to append and whether they end at a
/// safe boundary.
fn scan_boundary(window: &[u8], newline_count: &mut u8) -> (usize, bool) {
    for (index, byte) in window.iter().copied().enumerate() {
        if boundary_reached(newline_count, byte) {
            return (index + 1, true);
        }
    }
    (window.len(), false)
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
    fn single_line_chunking_follows_the_short_read_formula() {
        // The nominal read takes 100,000 bytes and read-ahead takes 25,000 from
        // 4,096-byte refills, which leaves 28,672 - 25,000 = 3,672 buffered
        // bytes. Each later read returns only that leftover, then appends
        // 25,000 more, so later fragments are 28,672 bytes.
        let input = vec![b'a'; 125_000 + 3 * 28_672 + 5];
        let actual = fragments(FileSource::new(std::io::Cursor::new(input), "input"));
        let lengths = actual
            .iter()
            .map(|fragment| fragment.content().len())
            .collect::<Vec<_>>();
        assert_eq!(lengths, [125_000, 28_672, 28_672, 28_672, 5]);
    }

    /// Reader whose calls, statuses and cancellation are fully scripted.
    struct ScriptedReader {
        data: Vec<u8>,
        position: usize,
        plan: Vec<(usize, ScriptedStatus)>,
        call: usize,
        cancel_on_call: Option<usize>,
        token: CancellationToken,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum ScriptedStatus {
        Normal,
        Error,
        Overreport,
    }

    impl SourceReader for ScriptedReader {
        fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
            let call = self.call;
            self.call += 1;
            if self.cancel_on_call == Some(call) {
                self.token.cancel();
            }
            let (requested, status) = self
                .plan
                .get(call)
                .copied()
                .unwrap_or((buffer.len(), ScriptedStatus::Normal));
            if status == ScriptedStatus::Overreport {
                return ReadOutcome::new(buffer.len() + 1, ReadStatus::Continue);
            }
            let count = requested
                .min(buffer.len())
                .min(self.data.len() - self.position);
            buffer[..count].copy_from_slice(&self.data[self.position..self.position + count]);
            self.position += count;
            let status = if status == ScriptedStatus::Error {
                ReadStatus::Error {
                    kind: io::ErrorKind::InvalidData,
                    message: format!("injected failure at call {call}"),
                }
            } else if self.position == self.data.len() {
                ReadStatus::Eof
            } else {
                ReadStatus::Continue
            };
            ReadOutcome::new(count, status)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Recorded {
        Fragment {
            content: Vec<u8>,
            start_line: usize,
            issue: Option<(SourceStage, SourceIssueKind, String)>,
        },
        Issue(SourceStage, SourceIssueKind, String),
    }

    fn issue_parts(issue: &SourceIssue) -> (SourceStage, SourceIssueKind, String) {
        (issue.stage(), issue.kind(), issue.message().to_owned())
    }

    fn visit_recording(
        source: &mut FileSource,
        cancellation: &dyn Cancellation,
    ) -> (Vec<Recorded>, Result<SourceControl, SourceError>) {
        let mut events = Vec::new();
        let result = source.visit(cancellation, &mut |event| {
            events.push(match event {
                SourceEvent::Fragment { fragment, issue } => Recorded::Fragment {
                    content: fragment.content().as_bytes().to_vec(),
                    start_line: fragment.start_line(),
                    issue: issue.as_ref().map(issue_parts),
                },
                SourceEvent::Issue(issue) => {
                    let (stage, kind, message) = issue_parts(&issue);
                    Recorded::Issue(stage, kind, message)
                }
            });
            Ok(SourceControl::Continue)
        });
        (events, result)
    }

    fn scripted(
        data: &[u8],
        plan: Vec<(usize, ScriptedStatus)>,
        cancel_on_call: Option<usize>,
        token: &CancellationToken,
    ) -> Box<dyn SourceReader> {
        Box::new(ScriptedReader {
            data: data.to_vec(),
            position: 0,
            plan,
            call: 0,
            cancel_on_call,
            token: token.clone(),
        })
    }

    fn fragment_bytes(content: &[u8], start_line: usize) -> Recorded {
        Recorded::Fragment {
            content: content.to_vec(),
            start_line,
            issue: None,
        }
    }

    #[test]
    fn cancellation_during_a_refill_is_seen_after_its_first_byte() {
        // The refilled slice contains a boundary, but cancellation requested
        // by the refill must win as soon as its first byte is appended.
        let token = CancellationToken::new();
        let plan = vec![(3, ScriptedStatus::Normal), (1_000, ScriptedStatus::Normal)];
        let mut source = FileSource::from_source_reader(
            scripted(b"abcd\n\nrest", plan, Some(1), &token),
            "input",
            FileOptions::new(3).unwrap(),
        );
        let (events, result) = visit_recording(&mut source, &token);
        assert_eq!(events, []);
        assert_eq!(result, Err(SourceError::Cancelled));
    }

    #[test]
    fn a_refill_whose_first_byte_ends_the_boundary_still_emits_before_cancelling() {
        let token = CancellationToken::new();
        let plan = vec![(3, ScriptedStatus::Normal), (1_000, ScriptedStatus::Normal)];
        let mut source = FileSource::from_source_reader(
            scripted(b"ab\n\nrest", plan, Some(1), &token),
            "input",
            FileOptions::new(3).unwrap(),
        );
        let (events, result) = visit_recording(&mut source, &token);
        assert_eq!(events, [fragment_bytes(b"ab\n\n", 1)]);
        assert_eq!(result, Err(SourceError::Cancelled));
    }

    #[test]
    fn cancellation_before_read_ahead_discards_the_nominal_chunk() {
        let token = CancellationToken::new();
        let plan = vec![(3, ScriptedStatus::Normal)];
        let mut source = FileSource::from_source_reader(
            scripted(b"abcdefgh", plan, Some(0), &token),
            "input",
            FileOptions::new(3).unwrap(),
        );
        let (events, result) = visit_recording(&mut source, &token);
        assert_eq!(events, []);
        assert_eq!(result, Err(SourceError::Cancelled));
    }

    #[test]
    fn boundary_search_stops_at_the_exact_byte_inside_a_buffered_slice() {
        // Only the whitespace-separated second newline ends the read-ahead,
        // and a newline before the nominal end does not count toward it.
        let input = b"ab\ncd \t\r\n \nrest";
        let options = FileOptions::new(4).unwrap();
        let actual = fragments(FileSource::with_options(input.as_slice(), "input", options));
        assert_eq!(actual[0].content().as_bytes(), b"ab\ncd \t\r\n \n");
        assert_eq!(actual[1].content().as_bytes(), b"rest");
    }

    #[test]
    fn data_plus_error_during_read_ahead_is_a_boundary_issue_after_the_buffered_bytes() {
        let token = CancellationToken::new();
        let plan = vec![(3, ScriptedStatus::Normal), (2, ScriptedStatus::Error)];
        let mut source = FileSource::from_source_reader(
            scripted(b"abcde", plan, None, &token),
            "input",
            FileOptions::new(3).unwrap(),
        );
        let (events, result) = visit_recording(&mut source, &token);
        assert_eq!(
            events,
            [Recorded::Fragment {
                content: Vec::new(),
                start_line: Fragment::builder(Vec::<u8>::new()).build().start_line(),
                issue: Some((
                    SourceStage::BoundaryRead,
                    SourceIssueKind::BoundaryRead,
                    "injected failure at call 1".to_owned()
                )),
            }]
        );
        assert_eq!(result, Ok(SourceControl::Continue));
    }

    #[test]
    fn one_nominal_buffer_serves_successive_files_without_stale_bytes() {
        let options = FileOptions::new(8).unwrap();
        let mut nominal = Vec::new();
        let mut contents = Vec::new();
        let mut retained = None;
        for input in [b"first file body".as_slice(), b"b".as_slice()] {
            FileSource::with_options(input, "input", options)
                .visit_with_buffer(&mut nominal, &CancellationToken::new(), &mut |event| {
                    if let SourceEvent::Fragment { fragment, .. } = event {
                        contents.push(fragment.content().as_bytes().to_vec());
                    }
                    Ok(SourceControl::Continue)
                })
                .unwrap();
            let pointer = nominal.as_ptr();
            assert_eq!(*retained.get_or_insert(pointer), pointer);
            assert_eq!(nominal.len(), 8);
        }
        assert_eq!(contents.last().unwrap().as_slice(), b"b");

        let larger = FileOptions::new(16).unwrap();
        FileSource::with_options(b"c".as_slice(), "input", larger)
            .visit_with_buffer(&mut nominal, &CancellationToken::new(), &mut |_| {
                Ok(SourceControl::Continue)
            })
            .unwrap();
        assert_eq!(nominal.len(), 16);
    }

    #[test]
    fn boundary_read_matches_the_retained_byte_at_a_time_reader() {
        for seed in 0..4_000_u64 {
            let scenario = reference::Scenario::generate(seed);
            let token = CancellationToken::new();
            let mut source = FileSource::from_source_reader(
                scripted(
                    &scenario.data,
                    scenario.plan.clone(),
                    scenario.cancel_on_call,
                    &token,
                ),
                "input",
                scenario.options,
            );
            let (events, result) = visit_recording(&mut source, &token);

            let reference_token = CancellationToken::new();
            let (expected_events, expected_result) = reference::visit(
                scripted(
                    &scenario.data,
                    scenario.plan.clone(),
                    scenario.cancel_on_call,
                    &reference_token,
                ),
                scenario.options,
                &reference_token,
            );
            assert_eq!(events, expected_events, "seed {seed}");
            assert_eq!(result, expected_result, "seed {seed}");
        }
    }

    /// The previous byte-at-a-time reader and boundary search, retained as the
    /// specification for fragment boundaries, statuses and cancellation.
    mod reference {
        use std::collections::VecDeque;

        use super::{Recorded, ScriptedStatus, issue_parts};
        use crate::file::{
            BUFFERED_READER_CAPACITY, ReadOutcome, ReadStatus, SourceReader, count_lf,
            is_boundary_whitespace, suffix_is_safe,
        };
        use crate::{
            Cancellation, FileOptions, SourceControl, SourceError, SourceIssue, SourceIssueKind,
            SourceStage, mime,
        };
        use rustleaks_core::model::Fragment;

        pub(super) struct Scenario {
            pub(super) data: Vec<u8>,
            pub(super) plan: Vec<(usize, ScriptedStatus)>,
            pub(super) cancel_on_call: Option<usize>,
            pub(super) options: FileOptions,
        }

        struct Generator(u64);

        impl Generator {
            fn below(&mut self, bound: usize) -> usize {
                self.0 = self
                    .0
                    .wrapping_mul(0x5851_f42d_4c95_7f2d)
                    .wrapping_add(0x14_0577);
                let high = usize::try_from(self.0 >> 40).expect("24-bit value fits usize");
                high % bound
            }

            fn pick<T: Copy>(&mut self, values: &[T]) -> T {
                values[self.below(values.len())]
            }
        }

        impl Scenario {
            pub(super) fn generate(seed: u64) -> Self {
                let mut random = Generator(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
                for _ in 0..4 {
                    random.below(2);
                }
                let length = random.below(12_000);
                let alphabet: &[u8] = random.pick(&[
                    b"xx\n \t\r".as_slice(),
                    b"\n\n \n".as_slice(),
                    b"abcdefgh".as_slice(),
                    b"a\nb\r\n c\t\n".as_slice(),
                ]);
                let data = (0..length).map(|_| random.pick(alphabet)).collect();
                let plan = (0..16)
                    .map(|_| {
                        let requested =
                            random.pick(&[0, 1, 3, 64, 1_000, 4_095, 4_096, 5_000, 100_000]);
                        let status = random.pick(&[
                            ScriptedStatus::Normal,
                            ScriptedStatus::Normal,
                            ScriptedStatus::Normal,
                            ScriptedStatus::Normal,
                            ScriptedStatus::Error,
                            ScriptedStatus::Overreport,
                        ]);
                        (requested, status)
                    })
                    .collect();
                let cancel_on_call = (random.below(4) == 0).then(|| random.below(10));
                let chunk = random.pick(&[1, 2, 5, 16, 64, 1_024, 4_095, 4_096, 4_097, 5_000]);
                let ahead = random.pick(&[0, 1, 3, 16, 300, 5_000, 25_000]);
                let options = FileOptions::new(chunk)
                    .expect("positive")
                    .max_boundary_read_ahead(ahead);
                Self {
                    data,
                    plan,
                    cancel_on_call,
                    options,
                }
            }
        }

        struct Reader {
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

        impl Reader {
            fn read(&mut self, output: &mut [u8]) -> ReadOutcome {
                if output.is_empty() {
                    return ReadOutcome::new(0, ReadStatus::Continue);
                }
                if let Some(count) = self.overreported.take() {
                    return ReadOutcome::new(count, ReadStatus::Continue);
                }
                if !self.buffered.is_empty() {
                    let count = self.drain(output);
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
                    return ReadOutcome::new(
                        0,
                        self.pending.take().unwrap_or(ReadStatus::Continue),
                    );
                }
                let count = self.drain(output);
                ReadOutcome::new(count, ReadStatus::Continue)
            }

            fn drain(&mut self, output: &mut [u8]) -> usize {
                let count = self.buffered.len().min(output.len());
                for slot in &mut output[..count] {
                    *slot = self.buffered.pop_front().expect("counted byte");
                }
                count
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
                if outcome.count() > temporary.len() {
                    self.overreported = Some(outcome.count());
                    return;
                }
                self.buffered.extend(&temporary[..outcome.count()]);
                if !matches!(outcome.status(), ReadStatus::Continue) {
                    self.pending = Some(outcome.status().clone());
                }
            }
        }

        fn issue(
            stage: SourceStage,
            kind: SourceIssueKind,
            message: impl Into<String>,
        ) -> SourceIssue {
            SourceIssue::new(stage, kind, Some("input".into()), message)
        }

        fn read_until_safe_boundary(
            reader: &mut Reader,
            nominal_count: usize,
            bytes: &mut Vec<u8>,
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
                if bytes.len() - nominal_count >= maximum {
                    break;
                }
                if cancellation.is_cancelled() {
                    return Err(issue(
                        SourceStage::BoundaryRead,
                        SourceIssueKind::Read,
                        "source cancelled during boundary read",
                    ));
                }
                match reader.read_byte() {
                    ByteOutcome::Byte(byte) => bytes.push(byte),
                    ByteOutcome::Status(ReadStatus::Eof) => break,
                    ByteOutcome::Status(ReadStatus::Error { message, .. }) => {
                        return Err(issue(
                            SourceStage::BoundaryRead,
                            SourceIssueKind::BoundaryRead,
                            message,
                        ));
                    }
                    ByteOutcome::Status(ReadStatus::Continue) => {
                        return Err(issue(
                            SourceStage::BoundaryRead,
                            SourceIssueKind::BoundaryRead,
                            "reader made no progress during boundary read",
                        ));
                    }
                    ByteOutcome::Overreported => {
                        return Err(issue(
                            SourceStage::Limit,
                            SourceIssueKind::Limit,
                            "reader returned more bytes than the supplied buffer",
                        ));
                    }
                }
            }
            Ok(())
        }

        fn empty_fragment_line() -> usize {
            Fragment::builder(Vec::<u8>::new()).build().start_line()
        }

        pub(super) fn visit(
            inner: Box<dyn SourceReader>,
            options: FileOptions,
            cancellation: &dyn Cancellation,
        ) -> (Vec<Recorded>, Result<SourceControl, SourceError>) {
            let mut reader = Reader {
                inner,
                buffered: VecDeque::new(),
                pending: None,
                overreported: None,
            };
            let mut events = Vec::new();
            let mut nominal = vec![0; options.chunk_size()];
            let mut total_lines = 0_usize;
            loop {
                if cancellation.is_cancelled() {
                    return (events, Err(SourceError::Cancelled));
                }
                let outcome = reader.read(&mut nominal);
                if outcome.count() > nominal.len() {
                    events.push(Recorded::Issue(
                        SourceStage::Limit,
                        SourceIssueKind::Limit,
                        "reader returned more bytes than the supplied buffer".to_owned(),
                    ));
                    return (events, Ok(SourceControl::Continue));
                }
                if outcome.count() == 0 {
                    if let ReadStatus::Error { message, .. } = outcome.status() {
                        events.push(Recorded::Fragment {
                            content: Vec::new(),
                            start_line: empty_fragment_line(),
                            issue: Some((
                                SourceStage::Read,
                                SourceIssueKind::Read,
                                message.clone(),
                            )),
                        });
                    }
                    return (events, Ok(SourceControl::Continue));
                }
                let original = &nominal[..outcome.count()];
                if total_lines == 0 && mime::is_application(original) {
                    return (events, Ok(SourceControl::Continue));
                }
                let mut bytes = original.to_vec();
                if let Err(failure) = read_until_safe_boundary(
                    &mut reader,
                    outcome.count(),
                    &mut bytes,
                    options.maximum_boundary_read_ahead(),
                    cancellation,
                ) {
                    if cancellation.is_cancelled() {
                        return (events, Err(SourceError::Cancelled));
                    }
                    events.push(Recorded::Fragment {
                        content: Vec::new(),
                        start_line: empty_fragment_line(),
                        issue: Some(issue_parts(&failure)),
                    });
                    return (events, Ok(SourceControl::Continue));
                }
                let start_line = total_lines + 1;
                total_lines += count_lf(&bytes);
                let read_issue = match outcome.status() {
                    ReadStatus::Error { message, .. } => {
                        Some((SourceStage::Read, SourceIssueKind::Read, message.clone()))
                    }
                    ReadStatus::Continue | ReadStatus::Eof => None,
                };
                events.push(Recorded::Fragment {
                    content: bytes,
                    start_line,
                    issue: read_issue,
                });
                if matches!(outcome.status(), ReadStatus::Eof) {
                    return (events, Ok(SourceControl::Continue));
                }
            }
        }
    }

    #[test]
    fn zero_chunk_size_is_rejected() {
        assert_eq!(
            FileOptions::new(0).expect_err("zero fails").field(),
            "chunk_size"
        );
    }
}
