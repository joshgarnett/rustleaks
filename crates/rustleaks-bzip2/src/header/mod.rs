//! bzip2 stream header

pub(crate) use self::error::HeaderError;

mod error;

/// A bzip2 header
#[derive(Clone)]
pub(crate) struct Header {
    max_blocksize: u32,
}

impl Header {
    /// Parse a bzip2 header
    pub(crate) fn parse(buf: [u8; 4]) -> Result<Self, HeaderError> {
        let signature = &buf[..2];
        if signature != b"BZ" {
            return Err(HeaderError::InvalidSignature);
        }

        let version = buf[2];
        if version != b'h' {
            return Err(HeaderError::UnsupportedVersion);
        }

        let hundred_k_blocksize = buf[3];
        match hundred_k_blocksize {
            b'1'..=b'9' => {
                let raw_blocksize = hundred_k_blocksize - b'0';
                Ok(Self {
                    max_blocksize: 100 * 1000 * u32::from(raw_blocksize),
                })
            }
            _ => Err(HeaderError::InvalidBlockSize),
        }
    }

    /// The maximum blocksize
    ///
    /// The returned value is always `100000..=900000`
    pub(crate) fn max_blocksize(&self) -> u32 {
        self.max_blocksize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_9k() {
        let header = Header::parse(*b"BZh9").unwrap();
        assert_eq!(header.max_blocksize(), 900000);
        assert_eq!(Header::parse(*b"BZh1").unwrap().max_blocksize(), 100000);
    }
}
