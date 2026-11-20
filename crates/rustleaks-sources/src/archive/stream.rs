//! Streaming readers for archive traversal.
//!
//! Each reader keeps a bounded buffer and passes failures on as
//! [`Failure`] values inside `io::Error`, so a container can tell a limit, a
//! damaged stream and cancellation apart after a member has been read.

use std::cell::Cell;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use rustleaks_rar_codec::crc32::Crc32;

use crate::Cancellation;

/// Bytes read from an input at a time while decoding or skipping.
pub(super) const INPUT_BUFFER: usize = 64 * 1024;

/// Why an archive read stopped.
#[derive(Debug)]
pub(super) enum Failure {
    /// The caller cancelled the scan.
    Cancelled,
    /// A size, entry or storage limit was reached.
    Limit(String),
    /// A compressed stream or member could not be decoded or verified.
    Decode(String),
    /// The container structure is damaged.
    Corrupt(String),
    /// The input itself could not be read.
    Read(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("source cancelled"),
            Self::Limit(message)
            | Self::Decode(message)
            | Self::Corrupt(message)
            | Self::Read(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Failure {}

impl Failure {
    /// Wraps the failure so it can pass through `Read` implementations.
    pub(super) fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// Recovers a wrapped failure; any other error is an input read failure.
    pub(super) fn from_io(error: io::Error) -> Self {
        let message = error.to_string();
        match error
            .into_inner()
            .map(<dyn std::error::Error + Send + Sync>::downcast::<Self>)
        {
            Some(Ok(failure)) => *failure,
            _ => Self::Read(message),
        }
    }

    /// Recovers a wrapped failure; any other error is a decode failure.
    pub(super) fn decode_io(error: io::Error) -> io::Error {
        if is_failure(&error) {
            error
        } else {
            Self::Decode(error.to_string()).into_io()
        }
    }
}

fn is_failure(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<Failure>)
}

/// Byte and entry counters shared by every reader of one archive traversal.
pub(super) struct Budget {
    pub(super) entries: Cell<usize>,
    pub(super) expanded: Cell<usize>,
    pub(super) spooled: Cell<usize>,
    total_limit: usize,
}

impl Budget {
    pub(super) const fn new(total_limit: usize) -> Self {
        Self {
            entries: Cell::new(0),
            expanded: Cell::new(0),
            spooled: Cell::new(0),
            total_limit,
        }
    }

    /// Bytes that can still be decompressed in this traversal.
    pub(super) fn remaining(&self) -> usize {
        self.total_limit.saturating_sub(self.expanded.get())
    }

    /// Adds decompressed bytes to the traversal total.
    pub(super) fn charge(&self, bytes: usize) -> Result<(), &'static str> {
        let total = self
            .expanded
            .get()
            .checked_add(bytes)
            .ok_or("archive cumulative byte count overflow")?;
        self.expanded.set(total);
        if total > self.total_limit {
            return Err("archive cumulative limit exceeded");
        }
        Ok(())
    }
}

/// Reads until `buffer` is full or the reader ends.
pub(super) fn read_full(reader: &mut dyn Read, buffer: &mut [u8]) -> Result<usize, Failure> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Failure::from_io(error)),
        }
    }
    Ok(filled)
}

/// Reads and drops up to `count` bytes; returns how many were there.
pub(super) fn skip(
    reader: &mut dyn Read,
    count: u64,
    cancellation: &dyn Cancellation,
) -> Result<u64, Failure> {
    let mut buffer =
        vec![0_u8; usize::try_from(count).map_or(INPUT_BUFFER, |count| count.min(INPUT_BUFFER))];
    let mut skipped = 0_u64;
    while skipped < count {
        if cancellation.is_cancelled() {
            return Err(Failure::Cancelled);
        }
        let wanted =
            usize::try_from(count - skipped).map_or(buffer.len(), |left| left.min(buffer.len()));
        let read = read_full(reader, &mut buffer[..wanted])?;
        skipped += read as u64;
        if read < wanted {
            break;
        }
    }
    Ok(skipped)
}

/// Reads and drops the rest of a stream.
pub(super) fn drain(reader: &mut dyn Read, cancellation: &dyn Cancellation) -> Result<(), Failure> {
    skip(reader, u64::MAX, cancellation).map(|_| ())
}

/// The body of one TAR member: exactly `remaining` bytes of the TAR stream.
pub(super) struct Body<'a> {
    inner: &'a mut dyn Read,
    remaining: u64,
    /// A read failed or the TAR stream ended inside the body. Whoever read
    /// the error reported it.
    pub(super) failed: bool,
}

impl<'a> Body<'a> {
    pub(super) fn new(inner: &'a mut dyn Read, size: u64) -> Self {
        Self {
            inner,
            remaining: size,
            failed: false,
        }
    }
}

impl Read for Body<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buffer.is_empty() || self.failed {
            return Ok(0);
        }
        let wanted =
            usize::try_from(self.remaining).map_or(buffer.len(), |left| left.min(buffer.len()));
        match self.inner.read(&mut buffer[..wanted]) {
            Ok(0) => {
                // A short member is an error, so a complete target never
                // publishes it.
                self.failed = true;
                Err(Failure::Corrupt("truncated TAR member".to_owned()).into_io())
            }
            Ok(count) => {
                self.remaining -= count as u64;
                Ok(count)
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(error),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
}

/// Feeds one member to the file scanner and keeps its first failure.
///
/// With `fill`, each read fills the buffer unless the member ends, so
/// fragments do not depend on how the decoder splits its output. Without
/// `fill`, read sizes pass through. A failure ends the member: a chunked scan
/// sees the end of input and keeps the bytes before it. With `complete`, the
/// reader is part of a complete scan, which sees an error.
pub(super) struct MemberReader<'a> {
    inner: &'a mut dyn Read,
    fill: bool,
    complete: bool,
    ended: bool,
    failure: Option<Failure>,
}

impl<'a> MemberReader<'a> {
    pub(super) fn new(inner: &'a mut dyn Read, fill: bool, complete: bool) -> Self {
        Self {
            inner,
            fill,
            complete,
            ended: false,
            failure: None,
        }
    }

    pub(super) fn into_failure(self) -> Option<Failure> {
        self.failure
    }

    fn fail(&mut self, error: io::Error) -> io::Result<()> {
        self.ended = true;
        self.failure = Some(Failure::from_io(error));
        if self.complete {
            return Err(io::Error::other("archive member could not be read"));
        }
        Ok(())
    }
}

impl Read for MemberReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.ended || buffer.is_empty() {
            return Ok(0);
        }
        let mut filled = 0;
        while filled < buffer.len() {
            match self.inner.read(&mut buffer[filled..]) {
                Ok(0) => {
                    self.ended = true;
                    break;
                }
                Ok(count) => {
                    filled += count;
                    if !self.fill {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.fail(error)?;
                    break;
                }
            }
        }
        Ok(filled)
    }
}

/// Counts decompressed bytes against the member and traversal limits.
pub(super) struct Metered<'a> {
    inner: &'a mut dyn Read,
    budget: &'a Budget,
    produced: usize,
    limit: usize,
    message: &'static str,
    cancellation: &'a dyn Cancellation,
    /// The limit message for the next read, after the bytes before a limit.
    failed_next: Option<&'static str>,
    /// A read failed; whoever read the error reported it.
    pub(super) failed: bool,
}

impl<'a> Metered<'a> {
    pub(super) fn new(
        inner: &'a mut dyn Read,
        budget: &'a Budget,
        limit: usize,
        message: &'static str,
        cancellation: &'a dyn Cancellation,
    ) -> Self {
        Self {
            inner,
            budget,
            produced: 0,
            limit,
            message,
            cancellation,
            failed_next: None,
            failed: false,
        }
    }

    /// Passes on bytes up to the limit, then fails on the next read, so the
    /// bytes before a limit do not depend on read sizes.
    fn read_counted(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(Failure::Cancelled.into_io());
        }
        let member_left = self.limit.saturating_sub(self.produced);
        let total_left = self.budget.remaining();
        let allowed = member_left.min(total_left);
        let count = self.inner.read(buffer)?;
        if count > allowed {
            let message = if member_left <= total_left {
                self.message
            } else {
                "archive cumulative limit exceeded"
            };
            if allowed == 0 {
                return Err(Failure::Limit(message.to_owned()).into_io());
            }
            self.failed_next = Some(message);
        }
        let count = count.min(allowed);
        self.produced += count;
        self.budget
            .charge(count)
            .map_err(|message| Failure::Limit(message.to_owned()).into_io())?;
        Ok(count)
    }
}

impl Read for Metered<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Ok(0);
        }
        if let Some(message) = self.failed_next.take() {
            self.failed = true;
            return Err(Failure::Limit(message.to_owned()).into_io());
        }
        self.read_counted(buffer).inspect_err(|error| {
            if error.kind() != io::ErrorKind::Interrupted {
                self.failed = true;
            }
        })
    }
}

/// Reads a 7z member in reads of one chunk, as the decoder returns them.
///
/// The file scanner sees reads of one chunk from a 7z member. This reader
/// keeps one chunk and gives the scanner those read sizes without holding
/// the whole member.
pub(super) struct Replay<'a> {
    inner: &'a mut dyn Read,
    chunk: Vec<u8>,
    start: usize,
    end: usize,
    produced: u64,
    expected: Option<u64>,
    done: bool,
    /// A read failed; the reader that saw the error reported it.
    pub(super) failed: bool,
}

impl<'a> Replay<'a> {
    /// `expected` checks the declared member length at the end.
    pub(super) fn new(
        inner: &'a mut dyn Read,
        chunk: usize,
        expected: Option<u64>,
    ) -> Result<Self, Failure> {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(chunk).map_err(|_| {
            Failure::Read("could not allocate archive member read buffer".to_owned())
        })?;
        buffer.resize(chunk, 0);
        Ok(Self {
            inner,
            chunk: buffer,
            start: 0,
            end: 0,
            produced: 0,
            expected,
            done: false,
            failed: false,
        })
    }
}

impl Read for Replay<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.done || self.failed {
            return Ok(0);
        }
        if self.start == self.end {
            let count = loop {
                match self.inner.read(&mut self.chunk) {
                    Ok(count) => break count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        self.failed = true;
                        return Err(error);
                    }
                }
            };
            if count == 0 {
                self.done = true;
                if self
                    .expected
                    .is_some_and(|expected| expected != self.produced)
                {
                    self.failed = true;
                    return Err(Failure::Decode(
                        "7z member length differs from declared size".to_owned(),
                    )
                    .into_io());
                }
                return Ok(0);
            }
            self.start = 0;
            self.end = count;
            self.produced += count as u64;
        }
        let count = buffer.len().min(self.end - self.start);
        buffer[..count].copy_from_slice(&self.chunk[self.start..self.start + count]);
        self.start += count;
        Ok(count)
    }
}

/// Checks the size and CRC-32 of a ZIP member while it is read.
pub(super) struct ZipCheck<'a> {
    inner: &'a mut dyn Read,
    crc: Crc32,
    size: u64,
    expected_size: u64,
    expected_crc: u32,
    /// A read failed or the member did not match its header.
    pub(super) failed: bool,
}

impl<'a> ZipCheck<'a> {
    pub(super) const fn new(
        inner: &'a mut dyn Read,
        expected_size: u64,
        expected_crc: u32,
    ) -> Self {
        Self {
            inner,
            crc: Crc32::new(),
            size: 0,
            expected_size,
            expected_crc,
            failed: false,
        }
    }

    fn mismatch(&mut self) -> io::Error {
        self.failed = true;
        Failure::Decode("ZIP member size or CRC mismatch".to_owned()).into_io()
    }
}

impl Read for ZipCheck<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.failed || buffer.is_empty() {
            return Ok(0);
        }
        // Ask for one byte past the declared size so a longer member is seen.
        let room = self
            .expected_size
            .saturating_sub(self.size)
            .saturating_add(1);
        let wanted = usize::try_from(room).map_or(buffer.len(), |room| room.min(buffer.len()));
        let count = match self.inner.read(&mut buffer[..wanted]) {
            Ok(count) => count,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.size += count as u64;
        if self.size > self.expected_size {
            return Err(self.mismatch());
        }
        self.crc.update(&buffer[..count]);
        if count == 0 && (self.size != self.expected_size || self.crc.finish() != self.expected_crc)
        {
            return Err(self.mismatch());
        }
        Ok(count)
    }
}

/// A read buffer over a compressed input, for push-style decoders.
pub(super) struct InputBuffer<'a> {
    reader: &'a mut dyn Read,
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
}

impl<'a> InputBuffer<'a> {
    pub(super) fn new(reader: &'a mut dyn Read) -> Self {
        Self {
            reader,
            buffer: vec![0; INPUT_BUFFER],
            start: 0,
            end: 0,
            eof: false,
        }
    }

    pub(super) fn available(&self) -> &[u8] {
        &self.buffer[self.start..self.end]
    }

    pub(super) fn consume(&mut self, count: usize) {
        self.start = (self.start + count).min(self.end);
    }

    pub(super) const fn at_eof(&self) -> bool {
        self.eof
    }

    /// Reads more input after the buffered bytes; returns false at the end.
    pub(super) fn fill(&mut self) -> Result<bool, Failure> {
        if self.eof {
            return Ok(false);
        }
        if self.start > 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        if self.end == self.buffer.len() {
            return Ok(true);
        }
        loop {
            match self.reader.read(&mut self.buffer[self.end..]) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(count) => {
                    self.end += count;
                    return Ok(true);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Failure::from_io(error)),
            }
        }
    }

    /// Returns the next byte, or `None` at the end of input.
    pub(super) fn byte(&mut self) -> Result<Option<u8>, Failure> {
        while self.start == self.end {
            if !self.fill()? {
                return Ok(None);
            }
        }
        let byte = self.buffer[self.start];
        self.start += 1;
        Ok(Some(byte))
    }

    /// Fills `output` completely; returns false if the input ends first.
    pub(super) fn exact(&mut self, output: &mut [u8]) -> Result<bool, Failure> {
        let mut filled = 0;
        while filled < output.len() {
            if self.start == self.end && !self.fill()? {
                return Ok(false);
            }
            let count = (output.len() - filled).min(self.end - self.start);
            output[filled..filled + count]
                .copy_from_slice(&self.buffer[self.start..self.start + count]);
            self.start += count;
            filled += count;
        }
        Ok(true)
    }

    /// Returns true when no input is left.
    pub(super) fn is_empty(&mut self) -> Result<bool, Failure> {
        while self.start == self.end {
            if !self.fill()? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Decompresses one DEFLATE stream (raw or zlib) and ignores input after it.
pub(super) struct Inflater<'a> {
    input: InputBuffer<'a>,
    state: Box<miniz_oxide::inflate::stream::InflateState>,
    label: &'static str,
    ended: bool,
}

impl<'a> Inflater<'a> {
    pub(super) fn new(
        reader: &'a mut dyn Read,
        format: miniz_oxide::DataFormat,
        label: &'static str,
    ) -> Self {
        Self {
            input: InputBuffer::new(reader),
            state: miniz_oxide::inflate::stream::InflateState::new_boxed(format),
            label,
            ended: false,
        }
    }
}

/// Inflates into `output`; returns the bytes written and whether the stream ended.
fn inflate_step(
    input: &mut InputBuffer<'_>,
    state: &mut miniz_oxide::inflate::stream::InflateState,
    output: &mut [u8],
    label: &str,
) -> Result<(usize, bool), Failure> {
    use miniz_oxide::inflate::stream::inflate;
    use miniz_oxide::{MZError, MZFlush, MZStatus};

    loop {
        if input.available().is_empty() && !input.at_eof() {
            input.fill()?;
        }
        // At the end of the input, `Finish` decodes every bit that is left,
        // so a truncated stream gives the same bytes for any read sizes.
        let flush = if input.at_eof() {
            MZFlush::Finish
        } else {
            MZFlush::None
        };
        let result = inflate(state, input.available(), output, flush);
        input.consume(result.bytes_consumed);
        // Pass on decoded bytes before any error, so the bytes before a
        // damaged part do not depend on how the input was read. A data
        // error stays in the state and returns on the next call.
        if result.bytes_written > 0 && !matches!(result.status, Ok(MZStatus::StreamEnd)) {
            return Ok((result.bytes_written, false));
        }
        match result.status {
            Ok(MZStatus::StreamEnd) => return Ok((result.bytes_written, true)),
            Ok(MZStatus::Ok) => {}
            Ok(status) => {
                return Err(Failure::Decode(format!(
                    "{label} decode returned unexpected status {status:?}"
                )));
            }
            Err(MZError::Buf) if !input.at_eof() => {
                input.fill()?;
                continue;
            }
            Err(error) => {
                return Err(Failure::Decode(format!("{label} decode failed: {error:?}")));
            }
        }
        if result.bytes_consumed == 0 {
            if input.at_eof() {
                return Err(Failure::Decode(format!(
                    "{label} decoder stopped making progress"
                )));
            }
            input.fill()?;
        }
    }
}

impl Read for Inflater<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.ended || output.is_empty() {
            return Ok(0);
        }
        let (written, ended) = inflate_step(&mut self.input, &mut self.state, output, self.label)
            .map_err(Failure::into_io)?;
        self.ended = ended;
        Ok(written)
    }
}

/// Decompresses a gzip stream of one or more members and checks each trailer.
pub(super) struct GzipReader<'a> {
    input: InputBuffer<'a>,
    state: Box<miniz_oxide::inflate::stream::InflateState>,
    in_member: bool,
    trailer_pending: bool,
    crc: Crc32,
    size: u32,
    members: usize,
    done: bool,
}

impl<'a> GzipReader<'a> {
    pub(super) fn new(reader: &'a mut dyn Read) -> Self {
        Self {
            input: InputBuffer::new(reader),
            state: miniz_oxide::inflate::stream::InflateState::new_boxed(
                miniz_oxide::DataFormat::Raw,
            ),
            in_member: false,
            trailer_pending: false,
            crc: Crc32::new(),
            size: 0,
            members: 0,
            done: false,
        }
    }

    fn header(&mut self) -> Result<(), Failure> {
        let invalid = || Failure::Decode("invalid gzip header".to_owned());
        let mut fixed = [0_u8; 10];
        if !self.input.exact(&mut fixed)? {
            return Err(invalid());
        }
        if fixed[..2] != [0x1f, 0x8b] || fixed[2] != 8 {
            return Err(invalid());
        }
        let flags = fixed[3];
        if flags & 0xe0 != 0 {
            return Err(Failure::Decode("invalid gzip flags".to_owned()));
        }
        let truncated = || Failure::Decode("truncated gzip header".to_owned());
        if flags & 4 != 0 {
            let mut length = [0_u8; 2];
            if !self.input.exact(&mut length)? {
                return Err(Failure::Decode("truncated gzip extra field".to_owned()));
            }
            let mut extra = [0_u8; 256];
            let mut left = usize::from(u16::from_le_bytes(length));
            while left > 0 {
                let count = left.min(extra.len());
                if !self.input.exact(&mut extra[..count])? {
                    return Err(truncated());
                }
                left -= count;
            }
        }
        for bit in [8_u8, 16] {
            if flags & bit != 0 {
                loop {
                    match self.input.byte()? {
                        Some(0) => break,
                        Some(_) => {}
                        None => {
                            return Err(Failure::Decode("truncated gzip string field".to_owned()));
                        }
                    }
                }
            }
        }
        if flags & 2 != 0 && !self.input.exact(&mut [0_u8; 2])? {
            return Err(truncated());
        }
        Ok(())
    }

    fn trailer(&mut self) -> Result<(), Failure> {
        let mut trailer = [0_u8; 8];
        if !self.input.exact(&mut trailer)? {
            return Err(Failure::Decode("truncated gzip trailer".to_owned()));
        }
        let crc = self.crc.finish();
        self.crc = Crc32::new();
        let expected_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let expected_size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        // The trailer stores the member size modulo 2^32.
        if crc != expected_crc || self.size != expected_size {
            return Err(Failure::Decode("gzip size or CRC mismatch".to_owned()));
        }
        self.size = 0;
        Ok(())
    }

    fn read_step(&mut self, output: &mut [u8]) -> Result<usize, Failure> {
        loop {
            if self.trailer_pending {
                self.trailer_pending = false;
                self.trailer()?;
                self.in_member = false;
                self.members += 1;
            }
            if !self.in_member {
                if self.input.is_empty()? {
                    if self.members == 0 {
                        return Err(Failure::Decode("empty gzip stream".to_owned()));
                    }
                    self.done = true;
                    return Ok(0);
                }
                self.header()?;
                self.state.reset(miniz_oxide::DataFormat::Raw);
                self.in_member = true;
            }
            let (written, ended) = inflate_step(&mut self.input, &mut self.state, output, "gzip")?;
            self.crc.update(&output[..written]);
            #[allow(clippy::cast_possible_truncation)] // The gzip size field wraps at 2^32.
            {
                self.size = self.size.wrapping_add(written as u32);
            }
            // Check the trailer on the next read, so the bytes of a member
            // come out before a trailer failure for any read sizes.
            self.trailer_pending = ended;
            if written > 0 {
                return Ok(written);
            }
        }
    }
}

impl Read for GzipReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.done || output.is_empty() {
            return Ok(0);
        }
        self.read_step(output).map_err(Failure::into_io)
    }
}

/// Decompresses an LZIP stream with a memory limit for its dictionary.
pub(super) struct LzipReader<'a> {
    input: InputBuffer<'a>,
    stream: lzma_rust2::LzipStream,
    done: bool,
}

impl<'a> LzipReader<'a> {
    pub(super) fn new(reader: &'a mut dyn Read, memory_limit: usize) -> Self {
        let limit_kb = memory_limit
            .checked_add(1023)
            .map(|bytes| bytes / 1024)
            .and_then(|kilobytes| u32::try_from(kilobytes).ok())
            .unwrap_or(u32::MAX);
        Self {
            input: InputBuffer::new(reader),
            stream: lzma_rust2::LzipStream::new_mem_limit(true, limit_kb),
            done: false,
        }
    }

    fn read_step(&mut self, output: &mut [u8]) -> Result<usize, Failure> {
        loop {
            if self.input.available().is_empty() && !self.input.at_eof() {
                self.input.fill()?;
            }
            let action = if self.input.at_eof() {
                lzma_rust2::Action::Finish
            } else {
                lzma_rust2::Action::Run
            };
            let result = self
                .stream
                .process(self.input.available(), output, action)
                .map_err(|error| Failure::Decode(error.to_string()))?;
            self.input.consume(result.bytes_consumed);
            if result.status == lzma_rust2::Status::StreamEnd {
                self.done = true;
                return Ok(result.bytes_produced);
            }
            if result.bytes_produced > 0 {
                return Ok(result.bytes_produced);
            }
            if result.bytes_consumed == 0 {
                if self.input.at_eof() {
                    return Err(Failure::Decode(
                        "LZIP decoder stopped making progress".to_owned(),
                    ));
                }
                self.input.fill()?;
            }
        }
    }
}

impl Read for LzipReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.done || output.is_empty() {
            return Ok(0);
        }
        self.read_step(output).map_err(Failure::into_io)
    }
}

/// Owned working memory for one Zstandard decoder.
pub(super) struct ZstdBuffers {
    history: Vec<u8>,
    block: Vec<u8>,
    literals: Vec<u8>,
    fse: Vec<zstd_zero::FseEntry>,
    huffman: Vec<zstd_zero::HuffmanEntry>,
    fse_scratch: Vec<i16>,
}

fn allocate_zeroed<T: Clone + Default>(size: usize) -> Result<Vec<T>, Failure> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| Failure::Limit("archive expansion limit exceeded".to_owned()))?;
    value.resize(size, T::default());
    Ok(value)
}

impl ZstdBuffers {
    pub(super) fn new(history: usize) -> Result<Self, Failure> {
        Ok(Self {
            history: allocate_zeroed(history)?,
            block: allocate_zeroed(zstd_zero::MAX_BLOCK_SIZE)?,
            literals: allocate_zeroed(zstd_zero::MAX_BLOCK_SIZE)?,
            fse: allocate_zeroed(zstd_zero::FSE_ENTRIES)?,
            huffman: allocate_zeroed(zstd_zero::HUFFMAN_ENTRIES)?,
            fse_scratch: allocate_zeroed(zstd_zero::FSE_SCRATCH_LEN)?,
        })
    }
}

/// Decompresses a Zstandard stream one block at a time.
pub(super) struct ZstdReader<'d, 'a> {
    decoder: zstd_zero::Decoder<'d>,
    input: InputBuffer<'a>,
    pending: Vec<u8>,
    pending_start: usize,
    idle: usize,
    done: bool,
}

impl<'d, 'a> ZstdReader<'d, 'a> {
    pub(super) fn new(
        buffers: &'d mut ZstdBuffers,
        reader: &'a mut dyn Read,
    ) -> Result<Self, Failure> {
        let decoder = zstd_zero::Decoder::new(zstd_zero::DecoderBuffers {
            history: &mut buffers.history,
            block: &mut buffers.block,
            literals: &mut buffers.literals,
            fse: &mut buffers.fse,
            huffman: &mut buffers.huffman,
            fse_scratch: &mut buffers.fse_scratch,
        })
        .map_err(|error| Failure::Decode(error.to_string()))?;
        Ok(Self {
            decoder,
            input: InputBuffer::new(reader),
            pending: Vec::new(),
            pending_start: 0,
            idle: 0,
            done: false,
        })
    }

    fn read_step(&mut self, output: &mut [u8]) -> Result<usize, Failure> {
        loop {
            if self.pending_start < self.pending.len() {
                let count = output.len().min(self.pending.len() - self.pending_start);
                output[..count]
                    .copy_from_slice(&self.pending[self.pending_start..self.pending_start + count]);
                self.pending_start += count;
                return Ok(count);
            }
            if self.input.available().is_empty() && !self.input.at_eof() {
                self.input.fill()?;
            }
            let available = self.input.available().len();
            let step = self
                .decoder
                .decode(self.input.available())
                .map_err(|error| Failure::Decode(error.to_string()))?;
            let consumed = step.consumed();
            if consumed > available {
                return Err(stalled());
            }
            let needs_input = matches!(step, zstd_zero::DecodeStep::NeedInput { .. });
            if let zstd_zero::DecodeStep::Output { bytes, .. } = step
                && !bytes.is_empty()
            {
                let count = output.len().min(bytes.len());
                output[..count].copy_from_slice(&bytes[..count]);
                self.pending.clear();
                self.pending_start = 0;
                if count < bytes.len() {
                    self.pending.try_reserve(bytes.len() - count).map_err(|_| {
                        Failure::Limit("archive expansion limit exceeded".to_owned())
                    })?;
                    self.pending.extend_from_slice(&bytes[count..]);
                }
                self.input.consume(consumed);
                self.idle = 0;
                return Ok(count);
            }
            self.input.consume(consumed);
            if needs_input {
                if consumed < available {
                    return Err(stalled());
                }
                if self.input.at_eof() || !self.input.fill()? {
                    self.decoder
                        .finish()
                        .map_err(|error| Failure::Decode(error.to_string()))?;
                    self.done = true;
                    return Ok(0);
                }
                self.idle = 0;
                continue;
            }
            if consumed != 0 {
                self.idle = 0;
            } else {
                self.idle += 1;
                if self.idle > 16 {
                    return Err(stalled());
                }
            }
        }
    }
}

fn stalled() -> Failure {
    Failure::Decode("Zstandard decoder stalled".to_owned())
}

impl Read for ZstdReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.done || output.is_empty() {
            return Ok(0);
        }
        self.read_step(output).map_err(Failure::into_io)
    }
}

/// Fills every read of a decoder's input unless the input ends.
///
/// A decoder then sees the same input reads however the source splits its
/// bytes, so its output, and the point where a damaged stream fails, do not
/// depend on the source's read sizes. An error after some bytes is returned
/// on the next read.
pub(super) struct FillInput<'a> {
    inner: &'a mut dyn Read,
    pending: Option<io::Error>,
}

impl<'a> FillInput<'a> {
    pub(super) fn new(inner: &'a mut dyn Read) -> Self {
        Self {
            inner,
            pending: None,
        }
    }
}

impl Read for FillInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = self.pending.take() {
            return Err(error);
        }
        let mut filled = 0;
        while filled < output.len() {
            match self.inner.read(&mut output[filled..]) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if filled == 0 => return Err(error),
                Err(error) => {
                    self.pending = Some(error);
                    break;
                }
            }
        }
        Ok(filled)
    }
}

/// Maps errors of a third-party decoder to decode failures.
pub(super) struct DecodeErrors<R>(pub(super) R);

impl<R: Read> Read for DecodeErrors<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0.read(output).map_err(Failure::decode_io)
    }
}

/// Maps errors of a raw input, such as a file, to read failures.
pub(super) struct ReadErrors<R>(pub(super) R);

impl<R: Read> Read for ReadErrors<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.0
            .read(output)
            .map_err(|error| Failure::Read(error.to_string()).into_io())
    }
}

impl<R: Seek> Seek for ReadErrors<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.0.seek(position)
    }
}

/// Sequential and random access to a seekable archive input.
pub(super) trait ReadSeek: Read + Seek {}

impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// A position-tracking view used to walk frame structures without decoding.
pub(super) struct Walker<'a> {
    reader: &'a mut dyn ReadSeek,
    position: u64,
    length: u64,
}

impl<'a> Walker<'a> {
    pub(super) fn new(reader: &'a mut dyn ReadSeek) -> io::Result<Self> {
        let length = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            position: 0,
            length,
        })
    }

    pub(super) const fn at_end(&self) -> bool {
        self.position == self.length
    }

    /// Reads exactly `output.len()` bytes at the current position.
    pub(super) fn take(&mut self, output: &mut [u8]) -> Option<()> {
        let end = self.position.checked_add(output.len() as u64)?;
        if end > self.length {
            return None;
        }
        self.reader.seek(SeekFrom::Start(self.position)).ok()?;
        self.reader.read_exact(output).ok()?;
        self.position = end;
        Some(())
    }

    /// Reads up to `output.len()` bytes without moving the position.
    pub(super) fn peek(&mut self, output: &mut [u8]) -> Option<usize> {
        let left = usize::try_from(self.length - self.position).unwrap_or(usize::MAX);
        let count = output.len().min(left);
        self.reader.seek(SeekFrom::Start(self.position)).ok()?;
        self.reader.read_exact(&mut output[..count]).ok()?;
        Some(count)
    }

    /// Moves forward `count` bytes, which must exist.
    pub(super) fn skip(&mut self, count: u64) -> Option<()> {
        let end = self.position.checked_add(count)?;
        if end > self.length {
            return None;
        }
        self.position = end;
        Some(())
    }

    /// Rewinds the reader to the start for decoding.
    pub(super) fn rewind(self) -> io::Result<()> {
        self.reader.seek(SeekFrom::Start(0)).map(|_| ())
    }
}
