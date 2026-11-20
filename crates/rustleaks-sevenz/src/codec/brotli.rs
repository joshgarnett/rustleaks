use std::io::{self, Read};

use super::skippable::{BROTLI_MAGIC, FrameFormat, InnerReader, SKIPPABLE_FRAME_MAGIC};
use crate::Error;

const BROTLI_LARGE_WINDOW_HEADER: u8 = 0x11;

/// Custom decoder to support the custom format first implemented by zstdmt, which allows to have
/// optional skippable frames.
pub(crate) struct BrotliDecoder<R: Read> {
    inner: Option<brotli_decompressor::Decompressor<StrictBrotliReader<R>>>,
    buffer_size: usize,
}

impl<R: Read> BrotliDecoder<R> {
    pub(crate) fn new(mut input: R, buffer_size: usize) -> Result<Self, Error> {
        let mut header = [0u8; 16];
        let header_read = match Read::read(&mut input, &mut header) {
            Ok(n) if n >= 4 => n,
            Ok(_) => return Err(Error::other("Input too short")),
            Err(e) => return Err(e.into()),
        };

        let magic_value = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);

        let inner_reader = if magic_value == SKIPPABLE_FRAME_MAGIC && header_read >= 16 {
            let skippable_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if skippable_size != FrameFormat::Brotli.skippable_size() {
                return Err(Error::other("Invalid brotli skippable frame size"));
            }

            let compressed_size =
                u32::from_le_bytes([header[8], header[9], header[10], header[11]]);

            let brotli_magic_value = u16::from_le_bytes([header[12], header[13]]);
            if brotli_magic_value != BROTLI_MAGIC {
                return Err(Error::other("Invalid brotli magic value"));
            }

            InnerReader::new_skippable(input, FrameFormat::Brotli, compressed_size)
        } else {
            InnerReader::new_standard(input, header[..header_read].to_vec())
        };

        let decompressor = brotli_decompressor::Decompressor::new(
            StrictBrotliReader::new(inner_reader),
            buffer_size,
        );

        Ok(BrotliDecoder {
            inner: Some(decompressor),
            buffer_size,
        })
    }
}

impl<R: Read> Read for BrotliDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(inner) = &mut self.inner {
            match inner.read(buf) {
                Ok(0) => {
                    let inner_reader = inner.get_mut();

                    if inner_reader.read_next_frame_header()? {
                        let reader = std::mem::replace(inner_reader, StrictBrotliReader::empty());
                        let mut decompressor =
                            brotli_decompressor::Decompressor::new(reader, self.buffer_size);
                        let result = decompressor.read(buf);
                        self.inner = Some(decompressor);
                        result
                    } else {
                        self.inner = None;
                        Ok(0)
                    }
                }
                result => result,
            }
        } else {
            Ok(0)
        }
    }
}

struct StrictBrotliReader<R: Read> {
    inner: InnerReader<R>,
    header_checked: bool,
}

impl<R: Read> StrictBrotliReader<R> {
    fn new(inner: InnerReader<R>) -> Self {
        Self {
            inner,
            header_checked: false,
        }
    }

    fn empty() -> Self {
        Self::new(InnerReader::empty())
    }

    fn read_next_frame_header(&mut self) -> io::Result<bool> {
        let has_frame = self.inner.read_next_frame_header()?;
        if has_frame {
            self.header_checked = false;
        }
        Ok(has_frame)
    }
}

impl<R: Read> Read for StrictBrotliReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        if !self.header_checked && count != 0 {
            self.header_checked = true;
            if buf[0] == BROTLI_LARGE_WINDOW_HEADER {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "large-window Brotli is unsupported",
                ));
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_large_window_brotli_before_decoder_allocation() {
        let input = [BROTLI_LARGE_WINDOW_HEADER, 0, 0, 0];
        let mut decoder =
            BrotliDecoder::new(&input[..], 4096).expect("reader construction is lazy");
        let error = decoder.read(&mut [0_u8; 1]).expect_err("large window");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn checks_each_skippable_brotli_frame_header() {
        let mut input = Vec::new();
        for compressed in [&[0x06][..], &[BROTLI_LARGE_WINDOW_HEADER, 0, 0, 0][..]] {
            input.extend_from_slice(&SKIPPABLE_FRAME_MAGIC.to_le_bytes());
            input.extend_from_slice(&8_u32.to_le_bytes());
            input.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            input.extend_from_slice(&BROTLI_MAGIC.to_le_bytes());
            input.extend_from_slice(&0_u16.to_le_bytes());
            input.extend_from_slice(compressed);
        }

        let mut decoder = BrotliDecoder::new(&input[..], 4096).expect("framed reader");
        let error = decoder
            .read(&mut [0_u8; 1])
            .expect_err("second frame uses a large window");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
