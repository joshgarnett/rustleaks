/// A Windows file time as stored in the 7z archive format: the number of
/// 100-nanosecond intervals since 0001-01-01.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NtTime(pub(crate) u64);

impl Default for NtTime {
    fn default() -> Self {
        Self::NT_TIME_EPOCH
    }
}

impl NtTime {
    /// The epoch of the [`NtTime`] (0001-01-01).
    pub const NT_TIME_EPOCH: NtTime = NtTime::new(0);

    /// Creates a new [`NtTime`] with the given file time.
    #[must_use]
    #[inline]
    pub const fn new(ft: u64) -> Self {
        Self(ft)
    }
}

impl From<u64> for NtTime {
    /// Converts the file time to a [`NtTime`].
    #[inline]
    fn from(file_time: u64) -> Self {
        Self::new(file_time)
    }
}

impl From<NtTime> for u64 {
    /// Converts the [`NtTime`] into a file time.
    #[inline]
    fn from(nt_time: NtTime) -> Self {
        nt_time.0
    }
}
