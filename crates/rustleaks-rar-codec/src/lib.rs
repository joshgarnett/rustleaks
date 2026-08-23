#![forbid(unsafe_code)]
#![allow(dead_code, missing_docs)]
// The decoder is retained close to its pinned upstream form so provenance and
// differential review remain mechanical. Workspace style lints are enforced
// at the checked container boundary instead of rewriting format arithmetic.
#![allow(clippy::all, clippy::pedantic)]
//! Safe RAR3 and RAR5 compression codecs.

use std::ops::Range;

pub mod codec;
pub mod crc32;

/// A reversible transform carried by a compressed RAR member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterKind {
    /// Channel delta transform.
    Delta { channels: usize },
    /// x86 E8 transform.
    E8,
    /// x86 E8/E9 transform.
    E8E9,
    /// ARM branch transform.
    Arm,
    /// Itanium branch transform.
    Itanium,
    /// RGB predictor transform.
    Rgb { width: usize, pos_r: usize },
    /// Audio predictor transform.
    Audio { channels: usize },
}

/// A transform and the member byte range it covers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilterSpec {
    /// Transform kind.
    pub kind: FilterKind,
    /// Covered range, or the whole member when absent.
    pub range: Option<Range<usize>>,
}

impl FilterSpec {
    /// Covers a whole member.
    pub const fn whole(kind: FilterKind) -> Self {
        Self { kind, range: None }
    }

    /// Covers an explicit member range.
    pub const fn range(kind: FilterKind, range: Range<usize>) -> Self {
        Self {
            kind,
            range: Some(range),
        }
    }
}

impl From<FilterKind> for FilterSpec {
    fn from(kind: FilterKind) -> Self {
        Self::whole(kind)
    }
}

/// A transform the selected RAR family cannot encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedFilterKind(pub FilterKind);

/// Compatibility error used only by retained private encoder helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An operation was cancelled.
    Cancelled,
    /// A generated header is invalid.
    InvalidHeader(&'static str),
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::InvalidHeader("RAR codec I/O failed")
    }
}

impl From<codec::Error> for Error {
    fn from(_: codec::Error) -> Self {
        Self::InvalidHeader("RAR codec encoding failed")
    }
}

/// Compatibility result used only by retained private encoder helpers.
pub type Result<T> = std::result::Result<T, Error>;
