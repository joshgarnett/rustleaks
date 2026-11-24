//! Safe, bounded 7z decoding for the `rustleaks-sources` archive feature.
//!
//! The crate decodes only. It has no encoder, no file system extraction and
//! no worker threads.
//!
//! The code is derived from `sevenz-rust2` 0.20.2 (Apache-2.0) and changed
//! for Rustleaks. The changes are listed in `docs/dev/dependencies.md`, in
//! the "Fork changes" section.
#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod reader;

mod codec;

pub(crate) mod archive;
pub(crate) mod bitset;
pub(crate) mod block;
mod crc;
pub(crate) mod decoder;

use std::io::Read;

pub use archive::{Archive, ArchiveEntry};
pub use block::Block;
pub use error::Error;
pub use reader::ArchiveReader;

trait ByteReader {
    fn read_u8(&mut self) -> std::io::Result<u8>;

    fn read_u16(&mut self) -> std::io::Result<u16>;

    fn read_u32(&mut self) -> std::io::Result<u32>;

    fn read_u64(&mut self) -> std::io::Result<u64>;
}

impl<T: Read> ByteReader for T {
    #[inline(always)]
    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    #[inline(always)]
    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(buf.as_mut())?;
        Ok(u16::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(buf.as_mut())?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline(always)]
    fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(buf.as_mut())?;
        Ok(u64::from_le_bytes(buf))
    }
}
