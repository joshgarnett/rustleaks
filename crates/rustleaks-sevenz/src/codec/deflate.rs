use std::io::{self, Read};

use miniz_oxide::{
    DataFormat, MZFlush, MZStatus,
    inflate::stream::{InflateState, inflate},
};

const INPUT_BUFFER_SIZE: usize = 8 * 1024;
const DEFLATE_WINDOW_SIZE: usize = 32 * 1024;

/// Streaming raw-DEFLATE reader for the 7z Deflate method.
pub(crate) struct DeflateDecoder<R> {
    input: R,
    state: Box<InflateState>,
    buffer: [u8; INPUT_BUFFER_SIZE],
    start: usize,
    end: usize,
    input_finished: bool,
    stream_finished: bool,
    emitted: usize,
}

impl<R: Read> DeflateDecoder<R> {
    pub(crate) fn new(input: R) -> Self {
        Self {
            input,
            state: InflateState::new_boxed(DataFormat::Raw),
            buffer: [0; INPUT_BUFFER_SIZE],
            start: 0,
            end: 0,
            input_finished: false,
            stream_finished: false,
            emitted: 0,
        }
    }
}

impl<R: Read> Read for DeflateDecoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.stream_finished {
            return Ok(0);
        }

        loop {
            if self.start == self.end && !self.input_finished {
                self.start = 0;
                self.end = self.input.read(&mut self.buffer)?;
                self.input_finished = self.end == 0;
            }

            let flush = if self.input_finished {
                MZFlush::Finish
            } else {
                MZFlush::None
            };
            // Go's compress/flate reader exposes output at its 32 KiB history-window
            // flushes. Keeping the same boundary matters because the pinned source
            // fragmenter observes short reads before applying its safe-boundary peek.
            let until_window_flush = DEFLATE_WINDOW_SIZE - self.emitted % DEFLATE_WINDOW_SIZE;
            let output_limit = output.len().min(until_window_flush);
            let result = inflate(
                &mut self.state,
                &self.buffer[self.start..self.end],
                &mut output[..output_limit],
                flush,
            );
            self.start = self
                .start
                .checked_add(result.bytes_consumed)
                .ok_or_else(|| io::Error::other("DEFLATE input position overflow"))?;

            match result.status {
                Ok(MZStatus::StreamEnd) => self.stream_finished = true,
                Ok(MZStatus::Ok) => {}
                Ok(status) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected DEFLATE status {status:?}"),
                    ));
                }
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("DEFLATE decode failed: {error:?}"),
                    ));
                }
            }

            if result.bytes_written != 0 {
                self.emitted = self
                    .emitted
                    .checked_add(result.bytes_written)
                    .ok_or_else(|| io::Error::other("DEFLATE output position overflow"))?;
                return Ok(result.bytes_written);
            }
            if self.stream_finished {
                return Ok(0);
            }
            if result.bytes_consumed == 0 {
                if self.input_finished {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated DEFLATE stream",
                    ));
                }
                if self.start != self.end {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DEFLATE decoder stopped making progress",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_stream() {
        let mut decoder = DeflateDecoder::new(&[0x01, 0x02][..]);
        let mut output = [0; 16];
        assert!(decoder.read(&mut output).is_err());
    }
}
