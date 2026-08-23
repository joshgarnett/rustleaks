use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::io;

/// An error returned by the block decoder
///
/// The specific decoder reason is available through its `Display`
/// implementation rather than a structured public field.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockError {
    reason: &'static str,
}

impl BlockError {
    #[inline(always)]
    pub(super) fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl Display for BlockError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl StdError for BlockError {}

impl From<BlockError> for io::Error {
    fn from(err: BlockError) -> io::Error {
        io::Error::other(err)
    }
}
