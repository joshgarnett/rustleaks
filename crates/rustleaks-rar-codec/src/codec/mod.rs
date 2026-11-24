//! RAR compression codecs, filters, PPMd, and RARVM components.

mod filters;
#[cfg(test)]
mod huffman;
#[cfg(test)]
mod match_finder;
mod ppmd;
pub mod rar29;
pub mod rar50;
pub(crate) mod rarvm;
mod x86;

/// Copies `input` into a new vector. A failed allocation returns
/// `InvalidData(message)`.
fn try_copy_bytes(input: &[u8], message: &'static str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| Error::InvalidData(message))?;
    output.extend_from_slice(input);
    Ok(output)
}

/// Checks that Huffman code-length counts (index = length) do not
/// oversubscribe the code space. Returns `InvalidData(message)` if they do.
fn validate_huffman_counts(count: &[u16; 16], message: &'static str) -> Result<()> {
    let mut available = 1i32;
    for &len_count in count.iter().skip(1) {
        available = (available << 1) - i32::from(len_count);
        if available < 0 {
            return Err(Error::InvalidData(message));
        }
    }
    Ok(())
}

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
