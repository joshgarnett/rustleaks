//! A small zip reader and writer for Go module zips and Python wheels.
//!
//! The writer produces deterministic archives: entries in the given order,
//! DOS time 1980-01-01 00:00, UTF-8 names and no extra fields. The reader
//! accepts the stored and deflate methods and archives under 4 GiB, which
//! covers what Bazel's wheel maker and this writer produce.

use std::io::{Read as _, Write as _};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

const LOCAL_HEADER: u32 = 0x0403_4b50;
const CENTRAL_HEADER: u32 = 0x0201_4b50;
const END_OF_DIRECTORY: u32 = 0x0605_4b50;
const STORED: u16 = 0;
const DEFLATE: u16 = 8;

/// Writes a zip archive. With `compress`, entries use deflate; otherwise
/// they are stored. Go reads either, and a Go module hash depends only on
/// the names and contents.
pub(super) fn write(entries: &[(String, Vec<u8>)], compress: bool) -> Result<Vec<u8>, String> {
    let mut archive = Vec::new();
    let mut directory = Vec::new();
    for (name, bytes) in entries {
        let offset = u32::try_from(archive.len()).map_err(|_| "zip archive over 4 GiB")?;
        let size = u32::try_from(bytes.len()).map_err(|_| format!("{name} is over 4 GiB"))?;
        let name_length = u16::try_from(name.len()).map_err(|_| format!("{name} is too long"))?;
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        let crc = crc.sum();
        let (method, data) = if compress {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
            encoder
                .write_all(bytes)
                .map_err(|error| format!("cannot compress {name}: {error}"))?;
            let data = encoder
                .finish()
                .map_err(|error| format!("cannot compress {name}: {error}"))?;
            (DEFLATE, data)
        } else {
            (STORED, bytes.clone())
        };
        let compressed = u32::try_from(data.len()).map_err(|_| format!("{name} is over 4 GiB"))?;
        // Version 2.0, UTF-8 names, DOS date 1980-01-01.
        let mut fields = Vec::new();
        fields.extend_from_slice(&20_u16.to_le_bytes());
        fields.extend_from_slice(&0x0800_u16.to_le_bytes());
        fields.extend_from_slice(&method.to_le_bytes());
        fields.extend_from_slice(&0_u16.to_le_bytes());
        fields.extend_from_slice(&0x0021_u16.to_le_bytes());
        fields.extend_from_slice(&crc.to_le_bytes());
        fields.extend_from_slice(&compressed.to_le_bytes());
        fields.extend_from_slice(&size.to_le_bytes());
        fields.extend_from_slice(&name_length.to_le_bytes());
        fields.extend_from_slice(&0_u16.to_le_bytes());
        archive.extend_from_slice(&LOCAL_HEADER.to_le_bytes());
        archive.extend_from_slice(&fields);
        archive.extend_from_slice(name.as_bytes());
        archive.extend_from_slice(&data);

        directory.extend_from_slice(&CENTRAL_HEADER.to_le_bytes());
        directory.extend_from_slice(&20_u16.to_le_bytes());
        directory.extend_from_slice(&fields);
        directory.extend_from_slice(&0_u16.to_le_bytes());
        directory.extend_from_slice(&0_u16.to_le_bytes());
        directory.extend_from_slice(&0_u16.to_le_bytes());
        // Regular file, mode 0644, in the high half of the external
        // attributes, as Unix zip tools write it.
        directory.extend_from_slice(&(0o100_644_u32 << 16).to_le_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let count = u16::try_from(entries.len()).map_err(|_| "too many zip entries")?;
    let directory_offset = u32::try_from(archive.len()).map_err(|_| "zip archive over 4 GiB")?;
    let directory_size = u32::try_from(directory.len()).map_err(|_| "zip directory over 4 GiB")?;
    archive.extend_from_slice(&directory);
    archive.extend_from_slice(&END_OF_DIRECTORY.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&count.to_le_bytes());
    archive.extend_from_slice(&directory_size.to_le_bytes());
    archive.extend_from_slice(&directory_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    Ok(archive)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .map(|field| u16::from_le_bytes([field[0], field[1]]))
        .ok_or_else(|| "zip archive is truncated".to_owned())
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .map(|field| u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
        .ok_or_else(|| "zip archive is truncated".to_owned())
}

fn usize_at(bytes: &[u8], at: usize, width: usize) -> Result<usize, String> {
    let value = if width == 2 {
        u32::from(u16_at(bytes, at)?)
    } else {
        u32_at(bytes, at)?
    };
    usize::try_from(value).map_err(|error| error.to_string())
}

/// Reads every file of a zip archive, in central directory order.
pub(super) fn read(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let end = (0..bytes.len().saturating_sub(21))
        .rev()
        .find(|&at| u32_at(bytes, at).ok() == Some(END_OF_DIRECTORY))
        .ok_or("zip archive has no end of central directory")?;
    let count = usize_at(bytes, end + 10, 2)?;
    let mut at = usize_at(bytes, end + 16, 4)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(bytes, at)? != CENTRAL_HEADER {
            return Err("zip central directory is damaged".into());
        }
        let method = u16_at(bytes, at + 10)?;
        let crc = u32_at(bytes, at + 16)?;
        let compressed = usize_at(bytes, at + 20, 4)?;
        let size = usize_at(bytes, at + 24, 4)?;
        let name_length = usize_at(bytes, at + 28, 2)?;
        let extra_length = usize_at(bytes, at + 30, 2)?;
        let comment_length = usize_at(bytes, at + 32, 2)?;
        let local = usize_at(bytes, at + 42, 4)?;
        let name = bytes
            .get(at + 46..at + 46 + name_length)
            .ok_or("zip archive is truncated")?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| "zip entry name is not UTF-8")?;
        at += 46 + name_length + extra_length + comment_length;
        if u32_at(bytes, local)? != LOCAL_HEADER {
            return Err(format!("zip entry {name} has no local header"));
        }
        let start = local + 30 + usize_at(bytes, local + 26, 2)? + usize_at(bytes, local + 28, 2)?;
        let data = bytes
            .get(start..start + compressed)
            .ok_or_else(|| format!("zip entry {name} is truncated"))?;
        let contents = match method {
            STORED => data.to_vec(),
            DEFLATE => {
                let mut contents = Vec::with_capacity(size);
                DeflateDecoder::new(data)
                    .read_to_end(&mut contents)
                    .map_err(|error| format!("cannot inflate {name}: {error}"))?;
                contents
            }
            other => return Err(format!("zip entry {name} uses compression method {other}")),
        };
        let mut check = flate2::Crc::new();
        check.update(&contents);
        if contents.len() != size || check.sum() != crc {
            return Err(format!("zip entry {name} fails its size or CRC check"));
        }
        if !name.ends_with('/') {
            entries.push((name, contents));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    #[test]
    fn written_archives_read_back_with_and_without_compression() {
        let entries = vec![
            ("a/b.txt".to_owned(), b"alpha alpha alpha alpha".to_vec()),
            ("c.txt".to_owned(), Vec::new()),
        ];
        for compress in [false, true] {
            let archive = super::write(&entries, compress).unwrap();
            assert_eq!(super::read(&archive).unwrap(), entries);
            assert_eq!(archive, super::write(&entries, compress).unwrap());
        }
    }

    #[test]
    fn damaged_archives_are_rejected() {
        let mut archive = super::write(&[("a".to_owned(), b"abc".to_vec())], false).unwrap();
        archive[30 + 1] = b'X';
        assert!(super::read(&archive).is_err());
        assert!(super::read(b"not a zip").is_err());
    }
}
