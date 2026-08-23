use std::io::{self, Read, Result};

use super::{Decoder, ReadState, WriteState};

/// A high-level decoder that wraps a [`Read`] and implements [`Read`], yielding decompressed bytes
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
        let mut read_zero = false;
        let mut tmp_buf = [0; 1024];

        loop {
            match self.decoder.read(buf)? {
                ReadState::NeedsWrite(space) => {
                    let read = self.reader.read(&mut tmp_buf[..space.min(1024)])?;

                    if read_zero && self.decoder.header_block.is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "The reader is empty?",
                        ));
                    }
                    read_zero = read == 0;

                    match self.decoder.write(&tmp_buf[..read])? {
                        WriteState::NeedsRead => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "decoder requested output while accepting input",
                            ));
                        }
                        WriteState::Written(written) if written == read => {}
                        WriteState::Written(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "decoder did not consume the accepted input",
                            ));
                        }
                    }
                }
                ReadState::Read(n) => return Ok(n),
                ReadState::Eof => return Ok(0),
            }
        }
    }
}
