use std::io::{Read, Result};

use super::{Decoder, ReadState};

/// Size of the buffer that carries compressed input to the decoder.
const INPUT_CHUNK: usize = 8 * 1024;

/// A high-level decoder that wraps a [`Read`] and implements [`Read`], yielding decompressed bytes
///
/// Streams that follow each other in the input, as `pbzip2` or `cat` write
/// them, are decoded in order. Data after the last stream that is not
/// another bzip2 stream is an error.
///
/// ```no_run
/// use std::fs::File;
/// use std::io;
///
/// use rustleaks_bzip2::DecoderReader;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let compressed_file = File::open("input.bz2")?;
/// let mut output = File::create("output.ref")?;
///
/// let mut reader = DecoderReader::new(compressed_file);
/// io::copy(&mut reader, &mut output)?;
/// #
/// # Ok(())
/// # }
/// ```
pub struct DecoderReader<R> {
    decoder: Decoder,

    reader: R,
}

impl<R> DecoderReader<R> {
    /// Construct a new decoder from something implementing [`Read`]
    pub fn new(reader: R) -> Self {
        Self {
            decoder: Decoder::new(),

            reader,
        }
    }
}

impl<R: Read> Read for DecoderReader<R> {
    /// Decompress bzip2 data from the underlying reader
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut input = [0; INPUT_CHUNK];

        loop {
            match self.decoder.read(buf)? {
                ReadState::NeedsWrite(space) => {
                    let read = self.reader.read(&mut input[..space.min(INPUT_CHUNK)])?;
                    self.decoder.write(&input[..read]);
                }
                ReadState::Read(n) => return Ok(n),
                ReadState::Eof => return Ok(0),
            }
        }
    }
}
