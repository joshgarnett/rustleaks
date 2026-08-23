//! RAR 2.x (1997-2002) - reverse-engineered - decoder-only.
//!
//! Reference: The Unarchiver's `XADRAR20Handle` (LGPL - patterns copied,
//! not code), at <https://github.com/MacPaw/XADMaster>.
//!
//! # Format overview
//!
//! RAR 2.x is an LZ77 codec with Huffman-coded literal/length/offset
//! alphabets and an optional per-channel delta-prediction "audio" mode.
//! Each compressed block carries its Huffman trees via a 19-symbol pretree
//! plus delta-coded length values; the window is a fixed 1 MiB and offsets
//! are LRU-tracked across symbols.
//!
//! Unlike RAR3/RAR5, the window size and bit format are constants - the
//! container hands the decoder a raw byte stream and the unpacked length;
//! everything else is inferred from the bitstream.
//!
//! # Encoder is intentionally unsupported
//!
//! RARLAB's unRAR license explicitly forbids using its source code to
//! reconstruct the RAR compression algorithm. Even clean-room
//! implementations of RAR decoders (libarchive, The Unarchiver) ship
//! decoder-only for that reason. The encoder in this module will
//! permanently return [`Error::Unsupported`].
//!
//! # Decoder calling convention
//!
//! RAR2 streams do not carry an in-band decompressed length, so callers
//! must supply it out of band:
//!
//! ```
//! use compcol::rar2::Decoder;
//! use compcol::{Decoder as _, Status};
//!
//! let mut decoder = Decoder::with_unpack_size(0);
//! let (progress, status) = decoder.finish(&mut []).unwrap();
//! assert_eq!(progress.written, 0);
//! assert_eq!(status, Status::StreamEnd);
//! ```
//!
//! `decode` buffers input but never emits output; once the caller switches
//! to `finish` the decoder runs the actual decompression in one shot and
//! drains the result across however many `finish` calls the caller makes.
//!
//! # Fixture famine and verification scope
//!
//! Genuine RAR2 archives are very rare today and no broad public test-vector
//! suite exists. Each component (bit reader, Huffman decoder, audio predictor)
//! is exercised by unit tests against hand-built inputs. End-to-end source
//! integration also decodes an exact payload produced by historical `rar
//! 2.60` and differentially compares its bytes and path with the pinned Go
//! backend. The audio block and uncommon long-distance branches still lack a
//! comparable real-world fixture.

use crate::error::Error;
use crate::traits::{Algorithm, RawEncoder, RawProgress};

mod audio;
mod bitreader;
mod decoder;
mod huffman;
mod tables;

pub use decoder::Decoder;

/// Zero-sized marker type implementing [`Algorithm`] for Rar2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rar2;

impl Algorithm for Rar2 {
    const NAME: &'static str = "rar2";
    type Encoder = Encoder;
    type Decoder = Decoder;
    type EncoderConfig = ();
    type DecoderConfig = ();
    fn encoder_with(_: ()) -> Encoder {
        Encoder::new()
    }
    fn decoder_with(_: ()) -> Decoder {
        Decoder::new()
    }
}

/// Permanently-unsupported encoder. See module docs for the licence reason.
#[derive(Debug, Default)]
pub struct Encoder;
impl Encoder {
    pub const fn new() -> Self {
        Self
    }
}
impl RawEncoder for Encoder {
    fn raw_encode(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_finish(&mut self, _output: &mut [u8]) -> Result<RawProgress, Error> {
        Err(Error::Unsupported)
    }
    fn raw_reset(&mut self) {}
}
