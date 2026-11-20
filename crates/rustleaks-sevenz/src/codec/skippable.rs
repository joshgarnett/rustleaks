//! Input reader for the zstdmt framing that LZ4 and Brotli 7z streams can use.
//!
//! A framed stream is a sequence of skippable frames. Each frame header holds
//! the skippable-frame magic, the size of the rest of the header and the size
//! of the compressed frame that follows. A stream without that magic is read
//! as one standard compressed stream.

use std::io::{self, Cursor, Read};

use crate::ByteReader;

/// Magic bytes of a skippable frame as used by zstdmt.
pub(super) const SKIPPABLE_FRAME_MAGIC: u32 = 0x184D2A50;
/// "BR" in little-endian, the Brotli marker inside a skippable frame header.
pub(super) const BROTLI_MAGIC: u16 = 0x5242;

/// The codec-specific part of a skippable frame header.
#[derive(Clone, Copy)]
pub(super) enum FrameFormat {
    /// Four header bytes after the magic and size: the compressed size.
    Lz4,
    /// Eight header bytes after the magic and size: the compressed size, the
    /// `BR` marker and a 16-bit uncompressed size hint.
    Brotli,
}

impl FrameFormat {
    /// The skippable size field that this format writes.
    pub(super) fn skippable_size(self) -> u32 {
        match self {
            FrameFormat::Lz4 => 4,
            FrameFormat::Brotli => 8,
        }
    }

    /// Reads the header bytes after the compressed size. Returns `false` when
    /// they do not belong to this format.
    fn read_header_tail<R: Read>(self, reader: &mut R) -> io::Result<bool> {
        match self {
            FrameFormat::Lz4 => Ok(true),
            FrameFormat::Brotli => {
                if reader.read_u16()? != BROTLI_MAGIC {
                    return Ok(false);
                }
                let _uncompressed_hint = reader.read_u16()?;
                Ok(true)
            }
        }
    }
}

pub(super) enum InnerReader<R: Read> {
    Empty,
    Standard {
        reader: R,
        header_buffer: Cursor<Vec<u8>>,
        header_finished: bool,
    },
    Skippable {
        reader: R,
        format: FrameFormat,
        remaining_in_frame: u32,
        frame_finished: bool,
    },
}

impl<R: Read> InnerReader<R> {
    pub(super) fn empty() -> Self {
        InnerReader::Empty
    }

    pub(super) fn new_standard(reader: R, header: Vec<u8>) -> Self {
        InnerReader::Standard {
            reader,
            header_buffer: Cursor::new(header),
            header_finished: false,
        }
    }

    pub(super) fn new_skippable(reader: R, format: FrameFormat, remaining_in_frame: u32) -> Self {
        InnerReader::Skippable {
            reader,
            format,
            remaining_in_frame,
            frame_finished: false,
        }
    }

    /// Reads the header of the next skippable frame after the current frame
    /// ends. Returns `false` at the end of the stream or when the next bytes
    /// are not a frame header of the same format.
    pub(super) fn read_next_frame_header(&mut self) -> io::Result<bool> {
        match self {
            InnerReader::Empty => Ok(false),
            InnerReader::Standard { .. } => Ok(false),
            InnerReader::Skippable {
                reader,
                format,
                remaining_in_frame,
                frame_finished,
            } => {
                if !*frame_finished {
                    return Ok(false);
                }

                match reader.read_u32() {
                    Ok(magic) => {
                        if magic != SKIPPABLE_FRAME_MAGIC {
                            return Ok(false);
                        }

                        let skippable_size = reader.read_u32()?;
                        if skippable_size != format.skippable_size() {
                            return Ok(false);
                        }

                        let compressed_size = reader.read_u32()?;
                        if !format.read_header_tail(reader)? {
                            return Ok(false);
                        }

                        *remaining_in_frame = compressed_size;
                        *frame_finished = false;

                        Ok(true)
                    }
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

impl<R: Read> Read for InnerReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            InnerReader::Empty => Ok(0),
            InnerReader::Standard {
                reader,
                header_buffer,
                header_finished,
            } => {
                if !*header_finished {
                    let bytes_read = header_buffer.read(buf)?;
                    if bytes_read > 0 {
                        return Ok(bytes_read);
                    }
                    *header_finished = true;
                }
                reader.read(buf)
            }
            InnerReader::Skippable {
                reader,
                remaining_in_frame,
                frame_finished,
                ..
            } => {
                if *frame_finished || *remaining_in_frame == 0 {
                    return Ok(0);
                }

                let bytes_to_read = std::cmp::min(*remaining_in_frame as usize, buf.len());
                let bytes_read = reader.read(&mut buf[..bytes_to_read])?;

                if bytes_read == 0 {
                    *frame_finished = true;
                    return Ok(0);
                }

                *remaining_in_frame -= bytes_read as u32;
                if *remaining_in_frame == 0 {
                    *frame_finished = true;
                }

                Ok(bytes_read)
            }
        }
    }
}
