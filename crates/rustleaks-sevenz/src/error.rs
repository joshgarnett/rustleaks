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
        actual_kb: usize,
    },
    /// Feature or operation not supported.
    Unsupported(Cow<'static, str>),
    /// The declared decoded size of an encoded header is above the memory limit.
    HeaderSizeLimited {
        /// Maximum allowed size in bytes.
        max_bytes: usize,
        /// Declared size in bytes.
        actual_bytes: u64,
    },
    /// The archive declares more entries than the entry limit.
    MaxEntriesLimited {
        /// Maximum allowed entries.
        max: usize,
        /// Declared entries.
        actual: usize,
    },
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
        match self {
            Self::BadSignature(_) => f.write_str("invalid 7z signature"),
            Self::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported 7z format version {major}.{minor}")
            }
            Self::ChecksumVerificationFailed => f.write_str("7z CRC mismatch"),
            Self::NextHeaderCrcMismatch => f.write_str("7z next header CRC mismatch"),
            Self::Io(error, message) if message.is_empty() => write!(f, "{error}"),
            Self::Io(error, message) => write!(f, "{message}: {error}"),
            Self::Other(message) | Self::Unsupported(message) => f.write_str(message),
            Self::BadTerminatedStreamsInfo(id) => {
                write!(f, "7z streams info has unexpected property {id:#04x}")
            }
            Self::BadTerminatedUnpackInfo => f.write_str("7z unpack info has no end marker"),
            Self::BadTerminatedPackInfo(id) => {
                write!(f, "7z pack info has unexpected property {id:#04x}")
            }
            Self::BadTerminatedSubStreamsInfo => {
                f.write_str("7z sub-streams info has no end marker")
            }
            Self::BadTerminatedHeader(id) => {
                write!(f, "7z header has unexpected property {id:#04x}")
            }
            Self::ExternalUnsupported => f.write_str("7z external header data is unsupported"),
            Self::UnsupportedCompressionMethod(method) => {
                write!(f, "unsupported 7z compression method {method}")
            }
            Self::MaxMemLimited { max_kb, actual_kb } => write!(
                f,
                "7z decoder needs {actual_kb} KiB, above the {max_kb} KiB memory limit"
            ),
            Self::HeaderSizeLimited {
                max_bytes,
                actual_bytes,
            } => write!(
                f,
                "7z encoded header declares {actual_bytes} bytes, above the {max_bytes} byte limit"
            ),
            Self::MaxEntriesLimited { max, actual } => write!(
                f,
                "7z archive declares {actual} entries, above the limit of {max}"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn display_is_a_plain_sentence() {
        let limited = Error::MaxMemLimited {
            max_kb: 65_536,
            actual_kb: 131_072,
        };
        assert_eq!(
            limited.to_string(),
            "7z decoder needs 131072 KiB, above the 65536 KiB memory limit"
        );
        assert_eq!(
            Error::UnsupportedCompressionMethod("PPMD".into()).to_string(),
            "unsupported 7z compression method PPMD"
        );
        let io = std::io::Error::other("short read");
        assert_eq!(Error::from(io).to_string(), "short read");
        let io = std::io::Error::other("short read");
        assert_eq!(
            Error::io_msg(io, "pack stream").to_string(),
            "pack stream: short read"
        );
        assert_eq!(
            Error::BadTerminatedHeader(0x42).to_string(),
            "7z header has unexpected property 0x42"
        );
    }
}
