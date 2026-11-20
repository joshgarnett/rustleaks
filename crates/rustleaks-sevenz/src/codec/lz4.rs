use std::io::Read;

use super::skippable::{FrameFormat, InnerReader, SKIPPABLE_FRAME_MAGIC};
use crate::Error;
use lz4_flex::frame::FrameDecoder;

/// Custom decoder to support the custom format first implemented by zstdmt, which allows to have
/// optional skippable frames.
pub(crate) struct Lz4Decoder<R: Read> {
    inner: Option<FrameDecoder<InnerReader<R>>>,
}

impl<R: Read> Lz4Decoder<R> {
    pub(crate) fn new(mut input: R) -> Result<Self, Error> {
        let mut header = [0u8; 12];
        let header_read = match Read::read(&mut input, &mut header) {
            Ok(n) if n >= 4 => n,
            Ok(_) => return Err(Error::other("Input too short")),
            Err(e) => return Err(e.into()),
        };

        let magic_value = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);

        let inner_reader = if magic_value == SKIPPABLE_FRAME_MAGIC && header_read >= 12 {
            let skippable_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            if skippable_size != FrameFormat::Lz4.skippable_size() {
                return Err(Error::other("Invalid lz4 skippable frame size"));
            }

            let compressed_size =
                u32::from_le_bytes([header[8], header[9], header[10], header[11]]);

            InnerReader::new_skippable(input, FrameFormat::Lz4, compressed_size)
        } else {
            InnerReader::new_standard(input, header[..header_read].to_vec())
        };

        let decoder = FrameDecoder::new(inner_reader);

        Ok(Lz4Decoder {
            inner: Some(decoder),
        })
    }
}

impl<R: Read> Read for Lz4Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(inner) = &mut self.inner {
            match inner.read(buf) {
                Ok(0) => {
                    let inner_reader = inner.get_mut();

                    if inner_reader.read_next_frame_header()? {
                        let reader = std::mem::replace(inner_reader, InnerReader::empty());
                        let mut decoder = FrameDecoder::new(reader);
                        let result = decoder.read(buf);
                        self.inner = Some(decoder);
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lz4_flex::frame::FrameEncoder;

    use super::*;

    fn lz4_frame(data: &[u8]) -> Vec<u8> {
        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(data).expect("encode");
        encoder.finish().expect("finish")
    }

    fn skippable_frame(skippable_size: u32, compressed: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&SKIPPABLE_FRAME_MAGIC.to_le_bytes());
        frame.extend_from_slice(&skippable_size.to_le_bytes());
        frame.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        frame.extend_from_slice(compressed);
        frame
    }

    fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut decoder = Lz4Decoder::new(input)?;
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(output)
    }

    #[test]
    fn decodes_a_standard_frame() {
        assert_eq!(decode(&lz4_frame(b"plain frame")).unwrap(), b"plain frame");
    }

    #[test]
    fn decodes_every_skippable_frame() {
        let mut input = skippable_frame(4, &lz4_frame(b"first "));
        input.extend(skippable_frame(4, &lz4_frame(b"second")));
        assert_eq!(decode(&input).unwrap(), b"first second");
    }

    #[test]
    fn stops_at_a_frame_header_of_another_format() {
        let mut input = skippable_frame(4, &lz4_frame(b"first"));
        input.extend(skippable_frame(8, &lz4_frame(b"ignored")));
        assert_eq!(decode(&input).unwrap(), b"first");
    }

    #[test]
    fn rejects_a_first_frame_with_the_wrong_header_size() {
        let input = skippable_frame(8, &lz4_frame(b"data"));
        assert!(decode(&input).is_err());
    }
}
