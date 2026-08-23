//! `rustleaks_bzip2` is a pure Rust bzip2 decoder.
//!
//! ## Main APIs
//!
//! * [`Decoder`]: low-level, no IO, bzip2 decoder
//! * [`DecoderReader`]: high-level synchronous bzip2 decoder
//!
//! ## Features
//!
//! All feature profiles use the workspace MSRV, Rust 1.85. The retained
//! `rustc_1_37`, `rustc_1_40`, and `rustc_1_51` names preserve the forked
//! crate's feature interface; they do not lower the supported compiler.
//! `nightly` selects the fixed-array decoder path without changing the
//! workspace compiler policy.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::fs::File;
//! use std::io;
//! use rustleaks_bzip2::DecoderReader;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut compressed_file = File::open("input.bz2")?;
//! let mut decompressed_output = File::create("output")?;
//!
//! let mut reader = DecoderReader::new(compressed_file);
//! io::copy(&mut reader, &mut decompressed_output)?;
//! # Ok(())
//! # }
//! ```
//!
//! [`Decoder`]: crate::decoder::Decoder

#![deny(
    trivial_casts,
    trivial_numeric_casts,
    rust_2018_idioms,
    clippy::cast_lossless,
    clippy::doc_markdown,
    missing_docs
)]
#![deny(rustdoc::broken_intra_doc_links)]
#![forbid(unsafe_code)]
#![allow(clippy::manual_range_contains)]

#[doc(no_inline)]
pub use self::decoder::DecoderReader;

mod bitreader;
pub mod block;
mod crc;
pub mod decoder;
pub mod header;
mod huffman;
mod move_to_front;

#[cfg(feature = "nightly")]
const LEN_258: usize = 258;
#[cfg(not(feature = "nightly"))]
const LEN_258: usize = 512;
