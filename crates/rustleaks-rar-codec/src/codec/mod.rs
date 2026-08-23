//! RAR compression codecs, filters, PPMd, and RARVM components.

mod fast;
mod filters;
mod huffman;
mod match_finder;
mod ppmd;
pub mod rar29;
pub mod rar50;
pub mod rarvm;

/// Codec result.
pub type Result<T> = std::result::Result<T, Error>;

/// Invalid compressed-stream outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The compressed stream violates its format.
    InvalidData(&'static str),
    /// More compressed input is required.
    NeedMoreInput,
    /// The operation was cancelled.
    Cancelled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(message) => formatter.write_str(message),
            Self::NeedMoreInput => formatter.write_str("codec input is truncated"),
            Self::Cancelled => formatter.write_str("codec operation was cancelled"),
        }
    }
}

impl std::error::Error for Error {}
