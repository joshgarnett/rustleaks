//! bzip2 decoding state machine

use std::io;

pub use self::reader::DecoderReader;
use crate::bitreader::BitReader;
use crate::block::Block;
use crate::header::Header;

mod reader;

/// Length of the `BZh1` to `BZh9` stream header.
const HEADER_LEN: usize = 4;

/// A decoder that does no IO by itself.
///
/// Compressed input is passed to [`Decoder::write`]. An empty write marks the
/// end of the input. [`Decoder::read`] decodes the next block once enough
/// input is buffered and returns its bytes.
pub(crate) struct Decoder {
    header_block: Option<(Header, Block)>,

    /// Number of bits of `in_buf` that are already decoded.
    skip_bits: usize,
    in_buf: Vec<u8>,

    /// An empty write was seen, so no more input follows.
    input_done: bool,
    eof: bool,
}

/// State returned by [`Decoder::read`]
pub(crate) enum ReadState {
    /// More input is needed to decode the next block or header. Write at
    /// most this many bytes, or an empty buffer at the end of the input.
    NeedsWrite(usize),
    /// This many decoded bytes are in the output buffer.
    Read(usize),
    /// The stream is decoded.
    Eof,
}

impl Decoder {
    /// Construct a new [`Decoder`], ready to decompress a new bzip2 file
    pub(crate) fn new() -> Self {
        Self {
            header_block: None,

            skip_bits: 0,
            in_buf: Vec::new(),

            input_done: false,
            eof: false,
        }
    }

    /// Adds compressed input. An empty `buf` marks the end of the input.
    pub(crate) fn write(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            self.input_done = true;
        } else {
            self.in_buf.extend_from_slice(buf);
        }
    }

    /// Bytes of `in_buf` that are not yet decoded, counting a partly decoded
    /// byte as not decoded.
    fn available(&self) -> usize {
        self.in_buf.len() - self.skip_bits / 8
    }

    /// Drops the decoded whole bytes at the start of `in_buf` once they are
    /// more than half of it. Each byte is then moved at most once for each
    /// byte decoded, and `in_buf` stays below twice the bytes it must hold.
    fn compact(&mut self) {
        let bytes = self.skip_bits / 8;
        if bytes > self.in_buf.len() / 2 {
            self.in_buf.drain(..bytes);
            self.skip_bits -= bytes * 8;
        }
    }

    /// Reads decoded bytes into `buf`.
    ///
    /// See [`ReadState`] for what to do next.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<ReadState, io::Error> {
        if self.eof {
            return Ok(ReadState::Eof);
        }
        if buf.is_empty() {
            return Ok(ReadState::Read(0));
        }

        loop {
            match &mut self.header_block {
                None => {
                    self.compact();
                    let available = self.available();
                    if available >= HEADER_LEN {
                        // A stream starts at a whole byte.
                        let start = self.skip_bits / 8;
                        let mut header_bytes = [0_u8; HEADER_LEN];
                        header_bytes.copy_from_slice(&self.in_buf[start..start + HEADER_LEN]);
                        let header = Header::parse(header_bytes)?;
                        let block = Block::new(header.clone());
                        self.header_block = Some((header, block));
                        self.skip_bits = (start + HEADER_LEN) * 8;
                    } else if !self.input_done {
                        return Ok(ReadState::NeedsWrite(HEADER_LEN - available));
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "bzip2 input is empty or shorter than its header",
                        ));
                    }
                }
                Some((header, block)) if block.is_not_ready() => {
                    let bound = block_input_bound(header);
                    self.compact();
                    let available = self.available();
                    if available >= bound || self.input_done {
                        if let Some((_, block)) = &mut self.header_block {
                            block.set_ready_for_read();
                        }
                    } else {
                        return Ok(ReadState::NeedsWrite(bound - available));
                    }
                }
                Some((_, block)) => {
                    let mut reader = BitReader::new(&self.in_buf);
                    reader.advance_by(self.skip_bits);

                    let read = block.read(&mut reader, buf)?;
                    self.skip_bits = reader.position();

                    if read > 0 {
                        return Ok(ReadState::Read(read));
                    }
                    if block.is_stream_end() {
                        // The end-of-stream marker and combined CRC were read.
                        self.eof = true;
                        return Ok(ReadState::Eof);
                    }
                }
            }
        }
    }
}

/// Number of input bytes that always hold one whole compressed block and the
/// 8 bytes the cached bit reader looks ahead.
///
/// A block has at most `max_blocksize + 1` symbols of at most 20 bits, at
/// most 32,767 selectors of at most 6 bits, and 6 tables of at most 258
/// lengths that a bzip2 encoder writes in at most 39 bits each. With the
/// fixed fields this is under `max_blocksize * 5 / 2 + 32,200` bytes.
/// Incompressible data makes a block larger than `max_blocksize`.
fn block_input_bound(header: &Header) -> usize {
    header.max_blocksize() as usize * 5 / 2 + 32 * 1024
}

#[cfg(test)]
mod tests;
