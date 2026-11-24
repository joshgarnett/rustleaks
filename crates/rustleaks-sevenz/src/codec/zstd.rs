use std::io::{self, Read};

use crate::Error;

const INPUT_BUFFER_SIZE: usize = 8 * 1024;
const MAX_IDLE_STEPS: usize = 16;

/// Working memory for one Zstandard coder.
///
/// The decoder borrows these buffers, so the caller that builds a decode
/// stack owns one set for each Zstandard coder in the block. None of them
/// grows with the size of the member.
pub(crate) struct ZstdBuffers {
    history: Vec<u8>,
    block: Vec<u8>,
    literals: Vec<u8>,
    fse: Vec<zstd_zero::FseEntry>,
    huffman: Vec<zstd_zero::HuffmanEntry>,
    fse_scratch: Vec<i16>,
    input: Vec<u8>,
    pending: Vec<u8>,
}

impl ZstdBuffers {
    pub(crate) fn new(memory_limit_kb: usize) -> Result<Self, Error> {
        let memory_limit = memory_limit_kb
            .checked_mul(1024)
            .ok_or_else(|| Error::other("7z decoder memory limit overflow"))?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(zstd_zero::MAX_BLOCK_SIZE)
            .map_err(|_| Error::other("unable to allocate the 7z Zstandard output buffer"))?;
        Ok(Self {
            history: try_zeroed(memory_limit, "Zstandard history")?,
            block: try_zeroed(zstd_zero::MAX_BLOCK_SIZE, "Zstandard block scratch")?,
            literals: try_zeroed(zstd_zero::MAX_BLOCK_SIZE, "Zstandard literal scratch")?,
            fse: try_zeroed(zstd_zero::FSE_ENTRIES, "Zstandard FSE scratch")?,
            huffman: try_zeroed(zstd_zero::HUFFMAN_ENTRIES, "Zstandard Huffman scratch")?,
            fse_scratch: try_zeroed(zstd_zero::FSE_SCRATCH_LEN, "Zstandard FSE counters")?,
            input: try_zeroed(INPUT_BUFFER_SIZE, "Zstandard input")?,
            pending,
        })
    }
}

/// Decodes a 7z Zstandard coder as a stream.
///
/// Compressed input is read in chunks of at most 8 KiB, and decoded output
/// waits in a buffer of at most one Zstandard block (128 KiB). The output
/// must have the size that the 7z header declares. When the last declared
/// byte is decoded, the rest of the input is checked, including the frame
/// checksum, before that byte is returned. An error before that point comes
/// after the bytes decoded before it.
pub(crate) struct ZstdDecoder<'b, R> {
    input: R,
    decoder: zstd_zero::Decoder<'b>,
    input_buffer: &'b mut [u8],
    input_start: usize,
    input_end: usize,
    input_done: bool,
    pending: &'b mut Vec<u8>,
    pending_start: usize,
    decoded: usize,
    expected: usize,
    done: bool,
    error: Option<Error>,
}

impl<'b, R: Read> ZstdDecoder<'b, R> {
    pub(crate) fn new(
        input: R,
        uncompressed_len: usize,
        buffers: &'b mut ZstdBuffers,
    ) -> Result<Self, Error> {
        let ZstdBuffers {
            history,
            block,
            literals,
            fse,
            huffman,
            fse_scratch,
            input: input_buffer,
            pending,
        } = buffers;
        pending.clear();
        let decoder = zstd_zero::Decoder::new(zstd_zero::DecoderBuffers {
            history,
            block,
            literals,
            fse,
            huffman,
            fse_scratch,
        })
        .map_err(|error| Error::other(format!("Zstandard initialization failed: {error}")))?;
        Ok(Self {
            input,
            decoder,
            input_buffer,
            input_start: 0,
            input_end: 0,
            input_done: false,
            pending,
            pending_start: 0,
            decoded: 0,
            expected: uncompressed_len,
            done: false,
            error: None,
        })
    }

    /// Capacity of the buffer that holds decoded bytes for later reads.
    #[cfg(test)]
    pub(crate) fn pending_capacity(&self) -> usize {
        self.pending.capacity()
    }

    /// Reads more compressed input when the buffer is empty.
    fn fill(&mut self) -> Result<(), Error> {
        if self.input_start == self.input_end && !self.input_done {
            let count = loop {
                match self.input.read(self.input_buffer) {
                    Ok(count) => break count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            };
            self.input_start = 0;
            self.input_end = count;
            self.input_done = count == 0;
        }
        Ok(())
    }

    /// Runs one decoder step. Decoded bytes go to `output`, and the bytes
    /// that do not fit go to the pending buffer.
    fn step(&mut self, output: &mut [u8]) -> Result<Step, Error> {
        self.fill()?;
        let available = &self.input_buffer[self.input_start..self.input_end];
        let length = available.len();
        let step = self.decoder.decode(available).map_err(decode_error)?;
        let consumed = step.consumed();
        if consumed > length {
            return Err(stalled());
        }
        let result = match step {
            zstd_zero::DecodeStep::Output { bytes, .. } if !bytes.is_empty() => {
                if self
                    .decoded
                    .checked_add(bytes.len())
                    .is_none_or(|size| size > self.expected)
                {
                    return Err(Error::other(
                        "Zstandard output exceeds the 7z-declared unpack size",
                    ));
                }
                let count = output.len().min(bytes.len());
                output[..count].copy_from_slice(&bytes[..count]);
                // One step returns at most one block, which fits the
                // capacity reserved for the pending buffer.
                self.pending.clear();
                self.pending_start = 0;
                self.pending.extend_from_slice(&bytes[count..]);
                self.decoded += bytes.len();
                Step::Output(count)
            }
            zstd_zero::DecodeStep::NeedInput { .. } => {
                if consumed < length {
                    return Err(stalled());
                }
                if self.input_done {
                    Step::End
                } else {
                    Step::Progress
                }
            }
            _ if consumed == 0 => Step::Idle,
            _ => Step::Progress,
        };
        self.input_start += consumed;
        Ok(result)
    }

    /// Decodes the input after the last declared byte. It must produce no
    /// output, and every frame must end, with a valid checksum if it has one.
    fn finish(&mut self) -> Result<(), Error> {
        let mut idle = 0;
        loop {
            match self.step(&mut [])? {
                Step::End => break,
                Step::Idle => {
                    idle += 1;
                    if idle > MAX_IDLE_STEPS {
                        return Err(stalled());
                    }
                }
                Step::Output(_) | Step::Progress => idle = 0,
            }
        }
        self.decoder.finish().map_err(decode_error)?;
        self.done = true;
        Ok(())
    }

    fn read_some(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        let mut filled = output.len().min(self.pending.len() - self.pending_start);
        output[..filled]
            .copy_from_slice(&self.pending[self.pending_start..self.pending_start + filled]);
        self.pending_start += filled;
        if let Err(error) = self.decode_into(output, &mut filled) {
            // Bytes decoded before an error are returned first, as other
            // decoders do. The error comes on the next read.
            if filled == 0 {
                return Err(error);
            }
            self.error = Some(error);
            return Ok(filled);
        }
        // Check the end of the stream before the last byte is returned.
        if !self.done && self.decoded == self.expected {
            self.finish()?;
        }
        Ok(filled)
    }

    fn decode_into(&mut self, output: &mut [u8], filled: &mut usize) -> Result<(), Error> {
        let mut idle = 0;
        while *filled < output.len() && self.decoded < self.expected {
            match self.step(&mut output[*filled..])? {
                Step::Output(count) => {
                    *filled += count;
                    idle = 0;
                }
                Step::Progress => idle = 0,
                Step::Idle => {
                    idle += 1;
                    if idle > MAX_IDLE_STEPS {
                        return Err(stalled());
                    }
                }
                Step::End => {
                    return Err(Error::other(format!(
                        "Zstandard output size mismatch: expected {}, got {}",
                        self.expected, self.decoded
                    )));
                }
            }
        }
        Ok(())
    }
}

enum Step {
    /// Decoded bytes, of which this many were copied to the output.
    Output(usize),
    /// Input was consumed, or more input is needed.
    Progress,
    /// The step consumed and produced nothing.
    Idle,
    /// The input ended and the decoder needs more.
    End,
}

impl<R: Read> Read for ZstdDecoder<'_, R> {
    /// Fills `output` unless the stream ends, as a reader over the whole
    /// decoded member would.
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = self.error.take() {
            return Err(io::Error::other(error));
        }
        if output.is_empty() {
            return Ok(0);
        }
        self.read_some(output).map_err(io::Error::other)
    }
}

fn decode_error(error: zstd_zero::DecodeError) -> Error {
    Error::other(format!("Zstandard decode failed: {error}"))
}

fn stalled() -> Error {
    Error::other("Zstandard decoder stopped making progress")
}

fn try_zeroed<T: Clone + Default>(size: usize, label: &'static str) -> Result<Vec<T>, Error> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(size)
        .map_err(|_| Error::other(format!("unable to allocate the 7z {label} buffer")))?;
    value.resize(size, T::default());
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Zstandard block header (RFC 8878): last flag, type and size.
    fn block_header(last: bool, kind: u32, size: usize) -> [u8; 3] {
        let value = u32::from(last) | (kind << 1) | ((size as u32) << 3);
        let bytes = value.to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    }

    /// A frame header with a 128 KiB window and no content size.
    fn frame_header(checksum: bool) -> Vec<u8> {
        let descriptor = if checksum { 0x04 } else { 0x00 };
        vec![0x28, 0xb5, 0x2f, 0xfd, descriptor, 7 << 3]
    }

    /// One frame of raw blocks holding `bytes`.
    fn raw_frame(bytes: &[u8]) -> Vec<u8> {
        let mut frame = frame_header(false);
        if bytes.is_empty() {
            frame.extend_from_slice(&block_header(true, 0, 0));
        }
        let mut chunks = bytes.chunks(zstd_zero::MAX_BLOCK_SIZE).peekable();
        while let Some(chunk) = chunks.next() {
            frame.extend_from_slice(&block_header(chunks.peek().is_none(), 0, chunk.len()));
            frame.extend_from_slice(chunk);
        }
        frame
    }

    /// One frame of `blocks` full-size RLE blocks of `byte`.
    fn rle_frame(byte: u8, blocks: usize) -> Vec<u8> {
        let mut frame = frame_header(false);
        for index in 0..blocks {
            let last = index + 1 == blocks;
            frame.extend_from_slice(&block_header(last, 1, zstd_zero::MAX_BLOCK_SIZE));
            frame.push(byte);
        }
        frame
    }

    fn decode_all(input: &[u8], declared: usize, read_size: usize) -> io::Result<Vec<u8>> {
        let mut buffers = ZstdBuffers::new(1024).unwrap();
        let mut decoder = ZstdDecoder::new(input, declared, &mut buffers).unwrap();
        let mut output = Vec::new();
        let mut buffer = vec![0; read_size];
        loop {
            let count = decoder.read(&mut buffer)?;
            if count == 0 {
                return Ok(output);
            }
            output.extend_from_slice(&buffer[..count]);
        }
    }

    #[test]
    fn streams_output_larger_than_the_memory_limit() {
        // 128 RLE blocks decode to 16 MiB from about 1 KiB of input. The
        // memory limit is 1 MiB, and decoded bytes wait in one block buffer.
        let blocks = 128;
        let size = blocks * zstd_zero::MAX_BLOCK_SIZE;
        let input = rle_frame(b'a', blocks);
        let mut buffers = ZstdBuffers::new(1024).unwrap();
        let mut decoder = ZstdDecoder::new(input.as_slice(), size, &mut buffers).unwrap();
        let mut buffer = vec![0; 100_000];
        let mut total = 0;
        loop {
            let count = decoder.read(&mut buffer).unwrap();
            assert_eq!(decoder.pending_capacity(), zstd_zero::MAX_BLOCK_SIZE);
            if count == 0 {
                break;
            }
            // Every read fills the buffer until the output ends.
            assert_eq!(count, buffer.len().min(size - total));
            assert!(buffer[..count].iter().all(|byte| *byte == b'a'));
            total += count;
        }
        assert_eq!(total, size);
    }

    #[test]
    fn decodes_raw_blocks_across_frames_for_any_read_size() {
        let first: Vec<u8> = (0..300_000_u32).map(|value| (value % 251) as u8).collect();
        let second = b"second synthetic frame".to_vec();
        let mut input = raw_frame(&first);
        input.extend_from_slice(&raw_frame(&second));
        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        for read_size in [1, 7, 4096, 131_072, 1_000_000] {
            assert_eq!(
                decode_all(&input, expected.len(), read_size).unwrap(),
                expected,
                "{read_size}"
            );
        }
    }

    #[test]
    fn output_must_match_the_declared_size() {
        let content = vec![b'x'; 1000];
        let input = raw_frame(&content);
        assert_eq!(decode_all(&input, 1000, 4096).unwrap(), content);
        let error = decode_all(&input, 999, 4096).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
        let error = decode_all(&input, 1001, 4096).unwrap_err();
        assert!(error.to_string().contains("size mismatch"), "{error}");
        // A second frame after the declared bytes is also too much output.
        let mut extra = input.clone();
        extra.extend_from_slice(&raw_frame(b"y"));
        let error = decode_all(&extra, 1000, 4096).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
        // An input that ends inside a block is not a complete stream.
        let error = decode_all(&input[..500], 1000, 4096).unwrap_err();
        assert!(error.to_string().contains("size mismatch"), "{error}");
    }

    #[test]
    fn frame_checksum_is_checked_before_the_last_byte_is_returned() {
        let mut input = frame_header(true);
        input.extend_from_slice(&block_header(true, 0, 1000));
        input.extend_from_slice(&[b'z'; 1000]);
        // Zero is not the checksum of this content.
        input.extend_from_slice(&[0; 4]);
        let mut buffers = ZstdBuffers::new(1024).unwrap();
        let mut decoder = ZstdDecoder::new(input.as_slice(), 1000, &mut buffers).unwrap();
        // The block decodes in one step that reaches the declared size, so
        // the frame end is checked before the first read returns.
        let error = decoder.read(&mut [0; 10]).unwrap_err();
        assert!(error.to_string().contains("decode failed"), "{error}");
    }

    #[test]
    fn a_zero_length_coder_still_needs_a_frame() {
        assert_eq!(decode_all(&raw_frame(&[]), 0, 16).unwrap(), b"");
        assert!(decode_all(&[], 0, 16).is_err());
    }
}
