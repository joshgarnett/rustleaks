//! Safe, bounded 7z decoding for the `rustleaks-sources` archive feature.
//!
//! This in-tree fork retains the portable decompression methods used by the
//! pinned Go source profile. It contains no encoder, filesystem extraction
//! helper, or parallel runtime.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

#[cfg(target_arch = "wasm32")]
extern crate wasm_bindgen;

mod encryption;
mod error;
mod reader;

mod codec;

pub(crate) mod archive;
pub(crate) mod bitset;
pub(crate) mod block;
mod crc;
pub(crate) mod decoder;

mod time;

use std::io::Read;

pub use archive::*;
pub use block::*;
pub use encryption::Password;
pub use error::Error;
pub use reader::{ArchiveReader, BlockDecoder};
pub use time::NtTime;

trait ByteReader {
    fn read_u8(&mut self) -> std::io::Result<u8>;

    #[cfg(feature = "brotli")]
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

    #[cfg(feature = "brotli")]
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
