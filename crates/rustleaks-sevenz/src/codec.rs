#[cfg(feature = "brotli")]
pub mod brotli;
#[cfg(feature = "deflate")]
pub mod deflate;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "zstd")]
pub mod zstd;
