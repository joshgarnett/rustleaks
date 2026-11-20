use std::{borrow::Cow, fmt::Display};

/// The error type of the crate.
#[derive(Debug)]
pub enum Error {
    /// Invalid 7z signature found in file header.
    BadSignature([u8; 6]),
    /// Unsupported 7z format version.
    UnsupportedVersion {
        /// Major version number.
        major: u8,
        /// Minor version number.
        minor: u8,
    },
    /// Checksum verification failed during decompression.
    ChecksumVerificationFailed,
    /// Next header CRC mismatch.
    NextHeaderCrcMismatch,
    /// IO error with optional context message.
    Io(std::io::Error, Cow<'static, str>),
    /// Other error with description.
    Other(Cow<'static, str>),
    /// Bad terminated streams info.
    BadTerminatedStreamsInfo(u8),
    /// Bad terminated unpack info.
    BadTerminatedUnpackInfo,
    /// Bad terminated pack info.
    BadTerminatedPackInfo(u8),
    /// Bad terminated sub streams info.
    BadTerminatedSubStreamsInfo,
    /// Bad terminated header.
    BadTerminatedHeader(u8),
    /// External compression method not supported.
    ExternalUnsupported,
    /// Unsupported compression method.
    UnsupportedCompressionMethod(String),
    /// Memory limit exceeded.
    MaxMemLimited {
        /// Maximum allowed memory in KB.
        max_kb: usize,
        /// Actual required memory in KB.
        actaul_kb: usize,
    },
    /// Feature or operation not supported.
    Unsupported(Cow<'static, str>),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::io_msg(value, "")
    }
}

impl Error {
    #[inline]
    pub(crate) fn other<S: Into<Cow<'static, str>>>(s: S) -> Self {
        Self::Other(s.into())
    }

    #[inline]
    pub(crate) fn unsupported<S: Into<Cow<'static, str>>>(s: S) -> Self {
        Self::Unsupported(s.into())
    }

    #[inline]
    pub(crate) fn io_msg(e: std::io::Error, msg: impl Into<Cow<'static, str>>) -> Self {
        Self::Io(e, msg.into())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for Error {}
