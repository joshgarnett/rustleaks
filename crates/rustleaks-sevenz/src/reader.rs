use std::{
    cell::RefCell,
    io,
    io::{BufReader, Read, Seek, SeekFrom},
    rc::Rc,
};

use lzma_rust2::filter::bcj2::Bcj2Reader;

use crate::{
    ByteReader,
    archive::*,
    bitset::BitSet,
    block::*,
    crc,
    crc::Hasher,
    decoder::{ZstdBufferCache, ZstdPool, add_decoder},
    error::Error,
};

const DEFAULT_MEMORY_LIMIT_KB: usize = 64 * 1024;

/// Limits that apply while the archive header is parsed.
#[derive(Clone, Copy)]
struct HeaderLimits {
    /// Codec working memory, and the decoded size of an encoded header, in KiB.
    memory_kb: usize,
    /// Entries the file table may declare.
    entries: usize,
}

// Each packed stream is read through a 4 KiB buffer. 7z member reads reach
// the scanner with the sizes the decoder returns (see `Replay` in
// `rustleaks-sources`), so this value sets fragment boundaries.
const PACKED_STREAM_BUFFER_SIZE: usize = 4_096;

fn allocation_error(context: &'static str) -> Error {
    Error::other(context)
}

fn try_vec_with_capacity<T>(capacity: usize, context: &'static str) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| allocation_error(context))?;
    Ok(values)
}

fn try_vec_filled<T: Clone>(len: usize, value: T, context: &'static str) -> Result<Vec<T>, Error> {
    let mut values = try_vec_with_capacity(len, context)?;
    values.resize(len, value);
    Ok(values)
}

pub struct BoundedReader<R: Read> {
    inner: R,
    remain: usize,
}

impl<R: Read> BoundedReader<R> {
    pub fn new(inner: R, max_size: usize) -> Self {
        Self {
            inner,
            remain: max_size,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remain == 0 {
            return Ok(0);
        }
        let bound = buf.len().min(self.remain);
        let size = self.inner.read(&mut buf[..bound])?;
        self.remain -= size;
        Ok(size)
    }
}

/// A special reader that shares its inner reader with other instances and
/// needs to re-seek every read operation.
#[derive(Debug)]
pub(crate) struct SharedBoundedReader<'a, R> {
    inner: Rc<RefCell<&'a mut R>>,
    cur: u64,
    bounds: (u64, u64),
}

impl<R> Clone for SharedBoundedReader<'_, R> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            cur: self.cur,
            bounds: self.bounds,
        }
    }
}

impl<R: Read + Seek> Seek for SharedBoundedReader<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => self.bounds.0 as i64 + pos as i64,
            SeekFrom::End(pos) => self.bounds.1 as i64 + pos,
            SeekFrom::Current(pos) => self.cur as i64 + pos,
        };
        if new_pos < 0 {
            return Err(io::Error::other("SeekBeforeStart"));
        }
        self.cur = new_pos as u64;
        self.inner.borrow_mut().seek(SeekFrom::Start(self.cur))
    }
}

impl<R: Read + Seek> Read for SharedBoundedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cur >= self.bounds.1 {
            return Ok(0);
        }

        let mut inner = self.inner.borrow_mut();

        inner.seek(SeekFrom::Start(self.cur))?;

        let bound = buf.len().min((self.bounds.1 - self.cur) as usize);
        let size = inner.read(&mut buf[..bound])?;
        self.cur += size as u64;
        Ok(size)
    }
}

impl<'a, R: Read + Seek> SharedBoundedReader<'a, R> {
    fn new(inner: Rc<RefCell<&'a mut R>>, bounds: (u64, u64)) -> Self {
        Self {
            inner,
            cur: bounds.0,
            bounds,
        }
    }
}

struct Crc32VerifyingReader<R> {
    inner: R,
    crc_digest: Hasher,
    expected_value: u64,
    remaining: i64,
}

impl<R: Read> Crc32VerifyingReader<R> {
    fn new(inner: R, remaining: usize, expected_value: u64) -> Self {
        Self {
            inner,
            crc_digest: Hasher::new(),
            expected_value,
            remaining: remaining as i64,
        }
    }
}

impl<R: Read> Read for Crc32VerifyingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining <= 0 {
            return Ok(0);
        }
        let size = self.inner.read(buf)?;
        if size > 0 {
            self.remaining -= size as i64;
            self.crc_digest.update(&buf[..size]);
        }
        if self.remaining <= 0 {
            let d = std::mem::replace(&mut self.crc_digest, Hasher::new()).finalize();
            if d as u64 != self.expected_value {
                return Err(std::io::Error::other(Error::ChecksumVerificationFailed));
            }
        }
        Ok(size)
    }
}

impl Archive {
    /// Reads archive metadata while bounding codec working memory and the
    /// number of entries.
    ///
    /// The memory limit also bounds the decoded size of an encoded header.
    /// An archive that declares more than `max_entries` entries is rejected
    /// with [`Error::MaxEntriesLimited`] before its file table is allocated.
    pub(crate) fn read_with_limits<R: Read + Seek>(
        reader: &mut R,
        memory_limit_kb: usize,
        max_entries: usize,
    ) -> Result<Archive, Error> {
        let limits = HeaderLimits {
            memory_kb: memory_limit_kb,
            entries: max_entries,
        };
        if memory_limit_kb == 0 {
            return Err(Error::other("7z memory limit must be positive"));
        }
        reader.seek(SeekFrom::Start(0))?;

        let mut signature = [0; 6];
        reader.read_exact(&mut signature)?;
        if signature != SEVEN_Z_SIGNATURE {
            return Err(Error::BadSignature(signature));
        }
        let mut versions = [0; 2];
        reader.read_exact(&mut versions)?;
        let version_major = versions[0];
        let version_minor = versions[1];
        if version_major != 0 {
            return Err(Error::UnsupportedVersion {
                major: version_major,
                minor: version_minor,
            });
        }

        let start_header_crc = reader.read_u32()?;
        let start_header = Self::read_start_header(reader, start_header_crc)?;
        Self::init_archive(reader, start_header, limits)
    }

    fn read_start_header<R: Read>(
        reader: &mut R,
        start_header_crc: u32,
    ) -> Result<StartHeader, Error> {
        let mut buf = [0; 20];
        reader.read_exact(&mut buf)?;
        // An empty start header gives no next-header location. This reader
        // does not search the file for the end header.
        if start_header_crc == 0 && buf == [0; 20] {
            return Err(Error::other("7z start header is empty"));
        }
        let crc32 = crc::hash(&buf);
        if crc32 != start_header_crc {
            return Err(Error::ChecksumVerificationFailed);
        }
        let mut buf_read = buf.as_slice();
        let offset = buf_read.read_u64()?;

        let size = buf_read.read_u64()?;
        let crc = buf_read.read_u32()?;
        Ok(StartHeader {
            next_header_offset: offset,
            next_header_size: size,
            next_header_crc: crc as u64,
        })
    }

    fn read_header<R: Read + Seek>(
        header: &mut R,
        archive: &mut Archive,
        limit: usize,
        max_entries: usize,
    ) -> Result<(), Error> {
        let mut nid = header.read_u8()?;
        if nid == K_ARCHIVE_PROPERTIES {
            Self::read_archive_properties(header, limit)?;
            nid = header.read_u8()?;
        }

        if nid == K_ADDITIONAL_STREAMS_INFO {
            return Err(Error::other("Additional streams unsupported"));
        }
        if nid == K_MAIN_STREAMS_INFO {
            Self::read_streams_info(header, archive, limit, max_entries)?;
            nid = header.read_u8()?;
        }
        if nid == K_FILES_INFO {
            Self::read_files_info(header, archive, limit, max_entries)?;
            nid = header.read_u8()?;
        }
        if nid != K_END {
            return Err(Error::BadTerminatedHeader(nid));
        }

        Ok(())
    }

    fn read_archive_properties<R: Read + Seek>(header: &mut R, limit: usize) -> Result<(), Error> {
        let mut nid = header.read_u8()?;
        while nid != K_END {
            // Bound the skip length against the buffer: an unbounded value cast to `i64`
            // could go negative and seek backwards, re-reading the same bytes forever.
            let property_size = bounded_count(read_variable_u64(header)?, limit, "propertySize")?;
            header.seek(SeekFrom::Current(property_size as i64))?;
            nid = header.read_u8()?;
        }
        Ok(())
    }

    fn init_archive<R: Read + Seek>(
        reader: &mut R,
        start_header: StartHeader,
        limits: HeaderLimits,
    ) -> Result<Self, Error> {
        // Bound the declared next-header size against the actual file length before allocating.
        let reader_len = reader.seek(SeekFrom::End(0))?;
        if start_header.next_header_size > usize::MAX as u64
            || start_header.next_header_size > reader_len
        {
            return Err(Error::other(format!(
                "Cannot handle next_header_size {}",
                start_header.next_header_size
            )));
        }

        let next_header_size_int = start_header.next_header_size as usize;

        // Bound the header position too: `next_header_offset` is an unbounded `u64`, so the
        // addition can overflow (a panic under overflow checks) and any value past the file
        // end is invalid anyway.
        let header_pos = SIGNATURE_HEADER_SIZE
            .checked_add(start_header.next_header_offset)
            .filter(|pos| *pos <= reader_len)
            .ok_or_else(|| Error::other("next header offset out of range"))?;
        reader.seek(SeekFrom::Start(header_pos))?;

        let mut buf = try_vec_filled(
            next_header_size_int,
            0,
            "unable to allocate the 7z next-header buffer",
        )?;
        reader.read_exact(&mut buf)?;
        if u64::from(crc::hash(&buf)) != start_header.next_header_crc {
            return Err(Error::NextHeaderCrcMismatch);
        }

        let mut archive = Archive::default();
        let mut buf_reader = buf.as_slice();
        let mut nid = buf_reader.read_u8()?;
        let mut header = if nid == K_ENCODED_HEADER {
            let decoded = Self::read_encoded_header(
                &mut buf_reader,
                reader,
                &mut archive,
                next_header_size_int,
                limits.memory_kb,
                limits.entries,
            )?;
            buf = decoded;
            archive = Archive::default();
            buf_reader = buf.as_slice();
            nid = buf_reader.read_u8()?;
            buf_reader
        } else {
            buf_reader
        };
        // Upper bound for any header-declared count/size: it can never exceed the number
        // of bytes in the header buffer, since every counted element consumes at least
        // one header byte. This kills the "tiny file declares a huge count" OOM vector
        // without rejecting any legitimate archive.
        let header_len_bound = header.len();
        let mut header = std::io::Cursor::new(&mut header);
        if nid == K_HEADER {
            Self::read_header(&mut header, &mut archive, header_len_bound, limits.entries)?;
        } else {
            return Err(Error::other("Broken or unsupported archive: no Header"));
        }

        Ok(archive)
    }

    /// Decodes an encoded header.
    ///
    /// The decoded header is held in memory, so its declared size must fit
    /// the memory limit. This is checked before any decoder is built.
    fn read_encoded_header<R: Read, RI: Read + Seek>(
        header: &mut R,
        reader: &mut RI,
        archive: &mut Archive,
        limit: usize,
        memory_limit_kb: usize,
        max_entries: usize,
    ) -> Result<Vec<u8>, Error> {
        Self::read_streams_info(header, archive, limit, max_entries)?;
        let block = archive
            .blocks
            .first()
            .ok_or(Error::other("no blocks, can't read encoded header"))?;
        let first_pack_stream_index = 0;
        let block_offset = SIGNATURE_HEADER_SIZE
            .checked_add(archive.pack_pos)
            .ok_or_else(|| Error::other("pack position out of range"))?;
        if archive.pack_sizes.is_empty() {
            return Err(Error::other("no packed streams, can't read encoded header"));
        }
        let declared_size = block.get_unpack_size();
        let max_bytes = memory_limit_kb.saturating_mul(1024);
        let unpack_size = usize::try_from(declared_size)
            .ok()
            .filter(|size| *size <= max_bytes)
            .ok_or(Error::HeaderSizeLimited {
                max_bytes,
                actual_bytes: declared_size,
            })?;

        reader.seek(SeekFrom::Start(block_offset))?;
        let mut zstd_cache = ZstdBufferCache::default();
        let mut zstd = zstd_cache.for_block(block, memory_limit_kb)?;
        let coder_len = block.coders.len();
        let pack_size = archive.pack_sizes[first_pack_stream_index] as usize;
        let input_reader = BufReader::with_capacity(
            PACKED_STREAM_BUFFER_SIZE,
            BoundedReader::new(reader, pack_size),
        );
        let mut decoder: Box<dyn Read> = Box::new(input_reader);
        let mut decoder = if coder_len > 0 {
            for (index, coder) in block.ordered_coder_iter() {
                if coder.num_in_streams != 1 || coder.num_out_streams != 1 {
                    return Err(Error::other(
                        "7z multi-stream coders are unsupported in an encoded header",
                    ));
                }
                let next = add_decoder(
                    decoder,
                    block.get_unpack_size_at_index(index) as usize,
                    coder,
                    memory_limit_kb,
                    &mut zstd,
                )?;
                decoder = Box::new(next);
            }
            decoder
        } else {
            decoder
        };
        if block.has_crc {
            decoder = Box::new(Crc32VerifyingReader::new(decoder, unpack_size, block.crc));
        }

        // Grow the buffer as bytes are decoded, so a header that decodes to
        // fewer bytes than it declares fails without allocating the
        // declared size.
        let mut decoded = Vec::new();
        decoder.take(unpack_size as u64).read_to_end(&mut decoded)?;
        if decoded.len() != unpack_size {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        Ok(decoded)
    }

    fn read_streams_info<R: Read>(
        header: &mut R,
        archive: &mut Archive,
        limit: usize,
        max_entries: usize,
    ) -> Result<(), Error> {
        let mut nid = header.read_u8()?;
        if nid == K_PACK_INFO {
            Self::read_pack_info(header, archive, limit)?;
            nid = header.read_u8()?;
        }

        if nid == K_UNPACK_INFO {
            Self::read_unpack_info(header, archive, limit, max_entries)?;
            nid = header.read_u8()?;
        } else {
            archive.blocks.clear();
        }
        if nid == K_SUB_STREAMS_INFO {
            Self::read_sub_streams_info(header, archive, limit)?;
            nid = header.read_u8()?;
        }
        if nid != K_END {
            return Err(Error::BadTerminatedStreamsInfo(nid));
        }

        Ok(())
    }

    fn read_files_info<R: Read + Seek>(
        header: &mut R,
        archive: &mut Archive,
        limit: usize,
        max_entries: usize,
    ) -> Result<(), Error> {
        let num_files = bounded_count(read_variable_u64(header)?, limit, "num files")?;
        // Each entry takes far more memory than the header byte it needs, so
        // apply the entry limit before the file table is allocated.
        if num_files > max_entries {
            return Err(Error::MaxEntriesLimited {
                max: max_entries,
                actual: num_files,
            });
        }
        let mut files: Vec<ArchiveEntry> = try_vec_filled(
            num_files,
            Default::default(),
            "unable to allocate the 7z file table",
        )?;

        let mut is_empty_stream: Option<BitSet> = None;
        let mut is_empty_file: Option<BitSet> = None;
        loop {
            let prop_type = header.read_u8()?;
            if prop_type == 0 {
                break;
            }
            let size = read_variable_u64(header)?;
            match prop_type {
                K_EMPTY_STREAM => {
                    is_empty_stream = Some(read_bits(header, num_files)?);
                }
                K_EMPTY_FILE => {
                    let n = if let Some(s) = &is_empty_stream {
                        s.len()
                    } else {
                        return Err(Error::other(
                            "Header format error: kEmptyStream must appear before kEmptyFile",
                        ));
                    };
                    is_empty_file = Some(read_bits(header, n)?);
                }
                K_ANTI => {
                    // Anti-items mark deletions in an update archive. They have
                    // no data, so the bits are read and discarded.
                    let n = if let Some(s) = is_empty_stream.as_ref() {
                        s.len()
                    } else {
                        return Err(Error::other(
                            "Header format error: kEmptyStream must appear before kAnti",
                        ));
                    };
                    read_bits(header, n)?;
                }
                K_NAME => {
                    let external = header.read_u8()?;
                    if external != 0 {
                        return Err(Error::other("7z external file names are unsupported"));
                    }
                    // A zero `size` would underflow `size - 1`; reject it explicitly.
                    if size == 0 || (size - 1) & 1 != 0 {
                        return Err(Error::other("file names length invalid"));
                    }

                    let size = bounded_count(size, limit, "file names length")?;
                    let names_reader = NamesReader::new(header, size - 1);

                    let mut next_file = 0;
                    for s in names_reader {
                        // The names blob is an independent length, so it can yield more
                        // names than `num_files`. Bail with an error instead of letting
                        // `files[next_file]` panic with an out-of-bounds index.
                        if next_file >= files.len() {
                            return Err(Error::other("Error parsing file names"));
                        }
                        files[next_file].name = s?;
                        next_file += 1;
                    }

                    if next_file != files.len() {
                        return Err(Error::other("Error parsing file names"));
                    }
                }
                K_C_TIME | K_A_TIME | K_M_TIME => {
                    // Timestamps are read and discarded.
                    skip_file_values(header, num_files, prop_type, 8)?;
                }
                K_WIN_ATTRIBUTES => {
                    // Attributes are read and discarded.
                    skip_file_values(header, num_files, prop_type, 4)?;
                }
                K_START_POS => return Err(Error::other("7z kStartPos property is unsupported")),
                _ => {
                    // Bound the skip against the buffer: an unbounded value cast to `i64`
                    // could go negative and seek backwards, re-reading the same bytes forever.
                    let skip = bounded_count(size, limit, "files-info property size")?;
                    header.seek(SeekFrom::Current(skip as i64))?;
                }
            };
        }

        let mut non_empty_file_counter = 0;
        let mut empty_file_counter = 0;
        for (i, file) in files.iter_mut().enumerate() {
            file.has_stream = is_empty_stream
                .as_ref()
                .map(|s| !s.contains(i))
                .unwrap_or(true);
            if file.has_stream {
                let sub_stream_info = if let Some(s) = archive.sub_streams_info.as_ref() {
                    s
                } else {
                    return Err(Error::other(
                        "Archive contains file with streams but no subStreamsInfo",
                    ));
                };
                file.is_directory = false;
                // The count of streamed files and `total_unpack_streams` are independent
                // header quantities. Reject a mismatch instead of indexing out of bounds.
                let (Some(&crc), Some(&size)) = (
                    sub_stream_info.crcs.get(non_empty_file_counter),
                    sub_stream_info.unpack_sizes.get(non_empty_file_counter),
                ) else {
                    return Err(Error::other(
                        "Archive declares more streamed files than sub-streams",
                    ));
                };
                file.has_crc = sub_stream_info.has_crc.contains(non_empty_file_counter);
                file.crc = crc;
                file.size = size;
                non_empty_file_counter += 1;
            } else {
                file.is_directory = if let Some(s) = &is_empty_file {
                    !s.contains(empty_file_counter)
                } else {
                    true
                };
                file.has_crc = false;
                file.size = 0;
                empty_file_counter += 1;
            }
        }
        archive.files = files;

        Self::calculate_stream_map(archive)?;
        Ok(())
    }

    fn calculate_stream_map(archive: &mut Archive) -> Result<(), Error> {
        let mut stream_map = StreamMap::default();

        let mut next_block_pack_stream_index = 0;
        let num_blocks = archive.blocks.len();
        stream_map.block_first_pack_stream_index =
            try_vec_filled(num_blocks, 0, "unable to allocate the 7z block-to-pack map")?;
        for i in 0..num_blocks {
            stream_map.block_first_pack_stream_index[i] = next_block_pack_stream_index;
            // A block's pack-stream span `[first .. first + packed_streams.len())` is later
            // used to slice `pack_stream_offsets`/`pack_sizes` in `build_decode_stack{,2}`.
            // Reject a block whose span runs past the available pack streams instead of
            // panicking there.
            next_block_pack_stream_index = next_block_pack_stream_index
                .checked_add(archive.blocks[i].packed_streams.len())
                .ok_or_else(|| Error::other("pack stream index overflow"))?;
            if next_block_pack_stream_index > archive.pack_sizes.len() {
                return Err(Error::other(
                    "block references pack streams beyond the available pack sizes",
                ));
            }
        }

        let mut next_pack_stream_offset: u64 = 0;
        let num_pack_sizes = archive.pack_sizes.len();
        stream_map.pack_stream_offsets = try_vec_filled(
            num_pack_sizes,
            0,
            "unable to allocate the 7z pack-stream offset table",
        )?;
        for i in 0..num_pack_sizes {
            stream_map.pack_stream_offsets[i] = next_pack_stream_offset;
            next_pack_stream_offset = next_pack_stream_offset
                .checked_add(archive.pack_sizes[i])
                .ok_or_else(|| Error::other("pack stream offset overflow"))?;
        }

        stream_map.block_first_file_index =
            try_vec_filled(num_blocks, 0, "unable to allocate the 7z block-to-file map")?;
        stream_map.file_block_index = try_vec_filled(
            archive.files.len(),
            None,
            "unable to allocate the 7z file-to-block map",
        )?;
        let mut next_block_index = 0;
        let mut next_block_unpack_stream_index = 0;
        for i in 0..archive.files.len() {
            if !archive.files[i].has_stream && next_block_unpack_stream_index == 0 {
                stream_map.file_block_index[i] = None;
                continue;
            }
            if next_block_unpack_stream_index == 0 {
                while next_block_index < archive.blocks.len() {
                    stream_map.block_first_file_index[next_block_index] = i;
                    if archive.blocks[next_block_index].num_unpack_sub_streams > 0 {
                        break;
                    }
                    next_block_index += 1;
                }
                if next_block_index >= archive.blocks.len() {
                    return Err(Error::other("Too few blocks in archive"));
                }
            }
            stream_map.file_block_index[i] = Some(next_block_index);
            if !archive.files[i].has_stream {
                continue;
            }

            // The first file of a block needs the block's first pack stream.
            if stream_map.block_first_file_index[next_block_index] == i {
                let first_pack_stream_index =
                    stream_map.block_first_pack_stream_index[next_block_index];
                if first_pack_stream_index >= archive.pack_sizes.len() {
                    return Err(Error::other(
                        "block references a pack stream index beyond pack_sizes",
                    ));
                }
            }

            next_block_unpack_stream_index += 1;
            if next_block_unpack_stream_index
                >= archive.blocks[next_block_index].num_unpack_sub_streams
            {
                next_block_index += 1;
                next_block_unpack_stream_index = 0;
            }
        }

        // Each block's file span `[first_file .. first_file + num_unpack_sub_streams)` is
        // later iterated directly against `archive.files` (in `BlockDecoder`). The
        // sub-stream count is an independent header quantity, so reject a block that
        // declares more sub-streams than there are files instead of indexing out of bounds.
        for (b, block) in archive.blocks.iter().enumerate() {
            let start = stream_map.block_first_file_index[b];
            let end = start
                .checked_add(block.num_unpack_sub_streams)
                .ok_or_else(|| Error::other("block file span overflow"))?;
            if end > archive.files.len() {
                return Err(Error::other(
                    "block declares more sub-streams than the archive has files",
                ));
            }
        }

        archive.stream_map = stream_map;
        Ok(())
    }

    fn read_pack_info<R: Read>(
        header: &mut R,
        archive: &mut Archive,
        limit: usize,
    ) -> Result<(), Error> {
        archive.pack_pos = read_variable_u64(header)?;
        let num_pack_streams =
            bounded_count(read_variable_u64(header)?, limit, "num pack streams")?;
        let mut nid = header.read_u8()?;
        if nid == K_SIZE {
            archive.pack_sizes = try_vec_filled(
                num_pack_streams,
                0u64,
                "unable to allocate the 7z pack-size table",
            )?;
            for i in 0..archive.pack_sizes.len() {
                archive.pack_sizes[i] = read_variable_u64(header)?;
            }
            nid = header.read_u8()?;
        }

        if nid == K_CRC {
            // Pack stream CRCs are read and not checked. Decoded data is
            // checked with the block and file CRCs.
            let crcs_defined = read_all_or_bits(header, num_pack_streams)?;
            for i in 0..num_pack_streams {
                if crcs_defined.contains(i) {
                    header.read_u32()?;
                }
            }
            nid = header.read_u8()?;
        }

        if nid != K_END {
            return Err(Error::BadTerminatedPackInfo(nid));
        }

        Ok(())
    }
    /// Reads the block table. Each block decodes at least one entry, so an
    /// archive with more blocks than `max_entries` is rejected with
    /// [`Error::MaxEntriesLimited`] before the table is allocated.
    fn read_unpack_info<R: Read>(
        header: &mut R,
        archive: &mut Archive,
        limit: usize,
        max_entries: usize,
    ) -> Result<(), Error> {
        let nid = header.read_u8()?;
        if nid != K_FOLDER {
            return Err(Error::other(format!("Expected kFolder, got {nid}")));
        }
        let num_blocks = bounded_count(read_variable_u64(header)?, limit, "num blocks")?;
        if num_blocks > max_entries {
            return Err(Error::MaxEntriesLimited {
                max: max_entries,
                actual: num_blocks,
            });
        }

        archive
            .blocks
            .try_reserve_exact(num_blocks)
            .map_err(|_| allocation_error("unable to allocate the 7z block table"))?;
        let external = header.read_u8()?;
        if external != 0 {
            return Err(Error::ExternalUnsupported);
        }

        for _ in 0..num_blocks {
            archive.blocks.push(Self::read_block(header, limit)?);
        }

        let nid = header.read_u8()?;
        if nid != K_CODERS_UNPACK_SIZE {
            return Err(Error::other(format!(
                "Expected kCodersUnpackSize, got {nid}"
            )));
        }

        for block in archive.blocks.iter_mut() {
            // `total_output_streams` is bounded in `read_block`, but clamp the eager
            // reservation to `limit` as well so it can never over-allocate.
            let tos = block.total_output_streams;
            block
                .unpack_sizes
                .try_reserve_exact(tos.min(limit))
                .map_err(|_| allocation_error("unable to allocate 7z block sizes"))?;
            for _ in 0..tos {
                block.unpack_sizes.push(read_variable_u64(header)?);
            }
        }

        let mut nid = header.read_u8()?;
        if nid == K_CRC {
            let crcs_defined = read_all_or_bits(header, num_blocks)?;
            for i in 0..num_blocks {
                if crcs_defined.contains(i) {
                    archive.blocks[i].has_crc = true;
                    archive.blocks[i].crc = header.read_u32()? as u64;
                } else {
                    archive.blocks[i].has_crc = false;
                }
            }
            nid = header.read_u8()?;
        }
        if nid != K_END {
            return Err(Error::BadTerminatedUnpackInfo);
        }

        Ok(())
    }

    fn read_sub_streams_info<R: Read>(
        header: &mut R,
        archive: &mut Archive,
        limit: usize,
    ) -> Result<(), Error> {
        for block in archive.blocks.iter_mut() {
            block.num_unpack_sub_streams = 1;
        }
        let mut total_unpack_streams = archive.blocks.len();

        let mut nid = header.read_u8()?;
        if nid == K_NUM_UNPACK_STREAM {
            total_unpack_streams = 0;
            for block in archive.blocks.iter_mut() {
                let num_streams = bounded_count(read_variable_u64(header)?, limit, "numStreams")?;
                block.num_unpack_sub_streams = num_streams;
                // Each sub-stream still consumes header bytes downstream, so the running
                // total stays bounded by `limit`; reject anything larger up front.
                total_unpack_streams = total_unpack_streams
                    .checked_add(num_streams)
                    .ok_or_else(|| Error::other("total unpack stream count overflow"))?;
                if total_unpack_streams > limit {
                    return Err(Error::other("total unpack streams exceeds available input"));
                }
            }
            nid = header.read_u8()?;
        }

        let mut sub_streams_info = SubStreamsInfo {
            unpack_sizes: try_vec_filled(
                total_unpack_streams,
                Default::default(),
                "unable to allocate 7z sub-stream sizes",
            )?,
            ..Default::default()
        };
        sub_streams_info
            .has_crc
            .try_reserve_len_exact(total_unpack_streams)
            .map_err(|_| allocation_error("unable to allocate 7z sub-stream CRC bits"))?;
        sub_streams_info.crcs = try_vec_filled(
            total_unpack_streams,
            0,
            "unable to allocate 7z sub-stream CRCs",
        )?;

        let mut next_unpack_stream = 0;
        for block in archive.blocks.iter() {
            if block.num_unpack_sub_streams == 0 {
                continue;
            }
            let mut sum: u64 = 0;
            if nid == K_SIZE {
                for _i in 0..block.num_unpack_sub_streams - 1 {
                    let size = read_variable_u64(header)?;
                    sub_streams_info.unpack_sizes[next_unpack_stream] = size;
                    next_unpack_stream += 1;
                    sum = sum
                        .checked_add(size)
                        .ok_or_else(|| Error::other("sub-stream size sum overflow"))?;
                }
            }
            if sum > block.get_unpack_size() {
                return Err(Error::other(
                    "sum of unpack sizes of block exceeds total unpack size",
                ));
            }
            // Calculate the last size from the total minus the sum of N-1 sizes.
            sub_streams_info.unpack_sizes[next_unpack_stream] = block.get_unpack_size() - sum;
            next_unpack_stream += 1;
        }
        if nid == K_SIZE {
            nid = header.read_u8()?;
        }

        let mut num_digests = 0;
        for block in archive.blocks.iter() {
            if block.num_unpack_sub_streams != 1 || !block.has_crc {
                num_digests += block.num_unpack_sub_streams;
            }
        }

        if nid == K_CRC {
            let has_missing_crc = read_all_or_bits(header, num_digests)?;
            let mut missing_crcs = try_vec_filled(
                num_digests,
                0,
                "unable to allocate the 7z missing-CRC table",
            )?;
            for (i, missing_crc) in missing_crcs.iter_mut().enumerate() {
                if has_missing_crc.contains(i) {
                    *missing_crc = header.read_u32()? as u64;
                }
            }
            let mut next_crc = 0;
            let mut next_missing_crc = 0;
            for block in archive.blocks.iter() {
                if block.num_unpack_sub_streams == 1 && block.has_crc {
                    sub_streams_info.has_crc.insert(next_crc);
                    sub_streams_info.crcs[next_crc] = block.crc;
                    next_crc += 1;
                } else {
                    for _i in 0..block.num_unpack_sub_streams {
                        if has_missing_crc.contains(next_missing_crc) {
                            sub_streams_info.has_crc.insert(next_crc);
                        } else {
                            sub_streams_info.has_crc.remove(next_crc);
                        }
                        sub_streams_info.crcs[next_crc] = missing_crcs[next_missing_crc];
                        next_crc += 1;
                        next_missing_crc += 1;
                    }
                }
            }

            nid = header.read_u8()?;
        }

        if nid != K_END {
            return Err(Error::BadTerminatedSubStreamsInfo);
        }

        archive.sub_streams_info = Some(sub_streams_info);
        Ok(())
    }

    fn read_block<R: Read>(header: &mut R, limit: usize) -> Result<Block, Error> {
        let mut block = Block::default();

        let num_coders = bounded_count(read_variable_u64(header)?, limit, "num coders")?;
        let mut coders =
            try_vec_with_capacity(num_coders, "unable to allocate the 7z coder table")?;
        let mut total_in_streams: u64 = 0;
        let mut total_out_streams: u64 = 0;
        for _i in 0..num_coders {
            let mut coder = Coder::default();
            let bits = header.read_u8()?;
            let id_size = bits & 0xF;
            let is_simple = (bits & 0x10) == 0;
            let has_attributes = (bits & 0x20) != 0;
            let more_alternative_methods = (bits & 0x80) != 0;

            coder.id_size = id_size as usize;

            header.read_exact(coder.decompression_method_id_mut())?;
            if is_simple {
                coder.num_in_streams = 1;
                coder.num_out_streams = 1;
            } else {
                coder.num_in_streams = read_variable_u64(header)?;
                coder.num_out_streams = read_variable_u64(header)?;
            }
            // Each stream is referenced by a bind-pair/packed-stream entry that consumes
            // header bytes, so the totals cannot legitimately exceed `limit`. Bounding
            // the checked sums also prevents wrapping before the limit check.
            total_in_streams = total_in_streams
                .checked_add(coder.num_in_streams)
                .ok_or_else(|| Error::other("coder stream counts exceed available input"))?;
            total_out_streams = total_out_streams
                .checked_add(coder.num_out_streams)
                .ok_or_else(|| Error::other("coder stream counts exceed available input"))?;
            if total_in_streams > limit as u64 || total_out_streams > limit as u64 {
                return Err(Error::other("coder stream counts exceed available input"));
            }
            if has_attributes {
                let properties_size =
                    bounded_count(read_variable_u64(header)?, limit, "properties size")?;
                let mut props = try_vec_filled(
                    properties_size,
                    0u8,
                    "unable to allocate 7z coder properties",
                )?;
                header.read_exact(&mut props)?;
                coder.properties = props;
            }
            coders.push(coder);
            if more_alternative_methods {
                return Err(Error::other("7z alternative coder methods are unsupported"));
            }
        }
        block.coders = coders;
        let total_in_streams = total_in_streams as usize;
        let total_out_streams = total_out_streams as usize;
        block.total_input_streams = total_in_streams;
        block.total_output_streams = total_out_streams;

        if total_out_streams == 0 {
            return Err(Error::other("Total output streams can't be 0"));
        }
        let num_bind_pairs = total_out_streams - 1;
        let mut bind_pairs =
            try_vec_with_capacity(num_bind_pairs, "unable to allocate the 7z bind-pair table")?;
        for _ in 0..num_bind_pairs {
            let bp = BindPair {
                in_index: read_variable_u64(header)?,
                out_index: read_variable_u64(header)?,
            };
            // Bind-pair indices are later used to index fixed-size coder arrays and the
            // coder graph. Validate them at parse time so decoding cannot panic on an
            // out-of-range index.
            if bp.in_index >= total_in_streams as u64 || bp.out_index >= total_out_streams as u64 {
                return Err(Error::other("bind pair references an out-of-range stream"));
            }
            bind_pairs.push(bp);
        }
        block.bind_pairs = bind_pairs;

        if total_in_streams < num_bind_pairs {
            return Err(Error::other(
                "Total input streams can't be less than the number of bind pairs",
            ));
        }
        let num_packed_streams = total_in_streams - num_bind_pairs;
        let mut packed_streams = try_vec_filled(
            num_packed_streams,
            0,
            "unable to allocate the 7z packed-stream table",
        )?;
        if num_packed_streams == 1 {
            let mut index = u64::MAX;
            for i in 0..total_in_streams {
                if block.find_bind_pair_for_in_stream(i as u64).is_none() {
                    index = i as u64;
                    break;
                }
            }
            if index == u64::MAX {
                return Err(Error::other("Couldn't find stream's bind pair index"));
            }
            packed_streams[0] = index;
        } else {
            for packed_stream in packed_streams.iter_mut() {
                *packed_stream = read_variable_u64(header)?;
            }
        }
        block.packed_streams = packed_streams;
        validate_coder_graph(&block)?;

        Ok(block)
    }
}

/// Rejects repeated stream bindings and cycles before constructing any decoder.
/// The tables and traversal are linear in the header-bounded stream counts.
fn validate_coder_graph(block: &Block) -> Result<(), Error> {
    let allocation = "unable to allocate the 7z coder graph";
    let mut input_owner = try_vec_filled(block.total_input_streams, 0usize, allocation)?;
    let mut output_owner = try_vec_filled(block.total_output_streams, 0usize, allocation)?;
    let mut input = 0;
    let mut output = 0;
    for (index, coder) in block.coders.iter().enumerate() {
        let input_end = input + coder.num_in_streams as usize;
        let output_end = output + coder.num_out_streams as usize;
        input_owner[input..input_end].fill(index);
        output_owner[output..output_end].fill(index);
        input = input_end;
        output = output_end;
    }
    let mut bound_inputs = try_vec_filled(block.total_input_streams, false, allocation)?;
    let mut bound_outputs = try_vec_filled(block.total_output_streams, false, allocation)?;
    let mut incoming = try_vec_filled(block.coders.len(), 0usize, allocation)?;
    let mut first_edge = try_vec_filled(block.coders.len(), None, allocation)?;
    let mut next_edge = try_vec_with_capacity(block.bind_pairs.len(), allocation)?;
    for (edge, pair) in block.bind_pairs.iter().enumerate() {
        let input = pair.in_index as usize;
        let output = pair.out_index as usize;
        if std::mem::replace(&mut bound_inputs[input], true)
            || std::mem::replace(&mut bound_outputs[output], true)
        {
            return Err(Error::other("duplicate 7z stream binding"));
        }
        let source = output_owner[output];
        let destination = input_owner[input];
        incoming[destination] += 1;
        next_edge.push(first_edge[source].replace(edge));
    }
    for &packed in &block.packed_streams {
        let packed = usize::try_from(packed)
            .map_err(|_| Error::other("packed stream index out of range"))?;
        let Some(bound) = bound_inputs.get_mut(packed) else {
            return Err(Error::other("packed stream index out of range"));
        };
        if std::mem::replace(bound, true) {
            return Err(Error::other("duplicate or bound 7z packed stream"));
        }
    }
    if bound_inputs.iter().any(|bound| !bound) {
        return Err(Error::other("unbound 7z coder input"));
    }
    let mut ready = try_vec_with_capacity(block.coders.len(), allocation)?;
    for (index, &count) in incoming.iter().enumerate() {
        if count == 0 {
            ready.push(index);
        }
    }
    let mut visited = 0;
    while let Some(coder) = ready.pop() {
        visited += 1;
        let mut edge = first_edge[coder];
        while let Some(index) = edge {
            let destination = input_owner[block.bind_pairs[index].in_index as usize];
            incoming[destination] -= 1;
            if incoming[destination] == 0 {
                ready.push(destination);
            }
            edge = next_edge[index];
        }
    }
    if visited != block.coders.len() {
        return Err(Error::other("cyclic 7z coder graph"));
    }
    Ok(())
}

/// Validates an attacker-controlled count/size decoded from the header against an upper
/// bound derived from the input (the number of bytes in the header buffer).
///
/// Every counted element (a file, pack stream, coder, sub-stream, name byte, …) consumes
/// at least one header byte downstream, so a legitimate count can never exceed the buffer
/// length. Rejecting anything larger stops a tiny archive from declaring a huge count and
/// forcing an out-of-memory allocation, without rejecting any valid archive.
#[inline]
fn bounded_count(value: u64, limit: usize, field: &str) -> Result<usize, Error> {
    if value > limit as u64 {
        return Err(Error::other(format!(
            "{field} ({value}) exceeds the available input ({limit} bytes)"
        )));
    }
    Ok(value as usize)
}

fn read_variable_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8()? as u64;
    let mut mask = 0x80_u64;
    let mut value = 0;
    for i in 0..8 {
        if (first & mask) == 0 {
            return Ok(value | ((first & (mask - 1)) << (8 * i)));
        }
        let b = reader.read_u8()? as u64;
        value |= b << (8 * i);
        mask >>= 1;
    }
    Ok(value)
}

/// Reads and discards a files-info property that holds one value of `width`
/// bytes for each file whose bit is set.
fn skip_file_values<R: Read>(
    header: &mut R,
    num_files: usize,
    property: u8,
    width: usize,
) -> Result<(), Error> {
    let defined = read_all_or_bits(header, num_files)?;
    let external = header.read_u8()?;
    if external != 0 {
        return Err(Error::other(format!(
            "7z external data for property {property:#04x} is unsupported"
        )));
    }
    let mut value = [0_u8; 8];
    for i in 0..num_files {
        if defined.contains(i) {
            header.read_exact(&mut value[..width])?;
        }
    }
    Ok(())
}

fn read_all_or_bits<R: Read>(header: &mut R, size: usize) -> io::Result<BitSet> {
    let all = header.read_u8()?;
    if all != 0 {
        let mut bits = BitSet::try_with_capacity(size)
            .map_err(|_| io::Error::other("unable to allocate a 7z bitset"))?;
        for i in 0..size {
            bits.insert(i);
        }
        Ok(bits)
    } else {
        read_bits(header, size)
    }
}

fn read_bits<R: Read>(header: &mut R, size: usize) -> io::Result<BitSet> {
    let mut bits = BitSet::try_with_capacity(size)
        .map_err(|_| io::Error::other("unable to allocate a 7z bitset"))?;
    let mut mask = 0u32;
    let mut cache = 0u32;
    for i in 0..size {
        if mask == 0 {
            mask = 0x80;
            cache = header.read_u8()? as u32;
        }
        if (cache & mask) != 0 {
            bits.insert(i);
        }
        mask >>= 1;
    }
    Ok(bits)
}

struct NamesReader<'a, R: Read> {
    max_bytes: usize,
    read_bytes: usize,
    cache: Vec<u16>,
    reader: &'a mut R,
}

impl<'a, R: Read> NamesReader<'a, R> {
    fn new(reader: &'a mut R, max_bytes: usize) -> Self {
        Self {
            max_bytes,
            reader,
            read_bytes: 0,
            cache: Vec::new(),
        }
    }
}

impl<R: Read> Iterator for NamesReader<'_, R> {
    type Item = Result<String, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.max_bytes <= self.read_bytes {
            return None;
        }
        self.cache.clear();
        let mut buf = [0; 2];
        while self.read_bytes < self.max_bytes {
            let r = self.reader.read_exact(&mut buf);
            self.read_bytes += 2;
            if let Err(e) = r {
                return Some(Err(e.into()));
            }
            let u = u16::from_le_bytes(buf);
            if u == 0 {
                break;
            }
            if self.cache.try_reserve(1).is_err() {
                return Some(Err(allocation_error(
                    "unable to allocate a 7z file-name buffer",
                )));
            }
            self.cache.push(u);
        }

        let capacity = match self.cache.len().checked_mul(3) {
            Some(capacity) => capacity,
            None => {
                return Some(Err(allocation_error(
                    "7z decoded file-name length overflow",
                )));
            }
        };
        let mut decoded = String::new();
        if decoded.try_reserve_exact(capacity).is_err() {
            return Some(Err(allocation_error(
                "unable to allocate a decoded 7z file name",
            )));
        }
        for character in char::decode_utf16(self.cache.iter().copied()) {
            match character {
                Ok(character) => decoded.push(character),
                Err(_) => return Some(Err(Error::other("invalid UTF-16 in a 7z file name"))),
            }
        }
        Some(Ok(decoded))
    }
}

/// Reads a 7z archive file.
pub struct ArchiveReader<R: Read + Seek> {
    source: R,
    archive: Archive,
    memory_limit_kb: usize,
}

impl<R: Read + Seek> ArchiveReader<R> {
    /// Creates a [`ArchiveReader`] to read a 7z archive file from the given `source` reader.
    #[inline]
    pub fn new(source: R) -> Result<Self, Error> {
        Self::new_with_memory_limit_kb(source, DEFAULT_MEMORY_LIMIT_KB)
    }

    /// Creates a reader with a positive codec working-memory ceiling.
    pub fn new_with_memory_limit_kb(source: R, memory_limit_kb: usize) -> Result<Self, Error> {
        Self::new_with_limits(source, memory_limit_kb, usize::MAX)
    }

    /// Creates a reader with a positive codec working-memory ceiling and a
    /// ceiling on the entries the archive may declare.
    ///
    /// The memory limit also bounds the decoded size of an encoded header.
    /// An archive that declares more than `max_entries` entries is rejected
    /// with [`Error::MaxEntriesLimited`] before its file table is allocated.
    pub fn new_with_limits(
        mut source: R,
        memory_limit_kb: usize,
        max_entries: usize,
    ) -> Result<Self, Error> {
        let archive = Archive::read_with_limits(&mut source, memory_limit_kb, max_entries)?;
        Ok(Self {
            source,
            archive,
            memory_limit_kb,
        })
    }

    /// Returns a reference to the underlying [`Archive`] structure.
    ///
    /// This provides access to the archive metadata including files, blocks,
    /// and compression information.
    #[inline]
    pub fn archive(&self) -> &Archive {
        &self.archive
    }

    fn build_decode_stack<'r>(
        source: &'r mut R,
        archive: &Archive,
        block_index: usize,
        memory_limit_kb: usize,
        zstd: &mut ZstdPool<'r>,
    ) -> Result<Box<dyn Read + 'r>, Error> {
        let block = &archive.blocks[block_index];
        if block.total_input_streams > block.total_output_streams {
            return Self::build_decode_stack2(source, archive, block_index, memory_limit_kb, zstd);
        }
        let first_pack_stream_index = archive.stream_map.block_first_pack_stream_index[block_index];
        let block_offset = SIGNATURE_HEADER_SIZE
            .checked_add(archive.pack_pos)
            .and_then(|v| {
                v.checked_add(archive.stream_map.pack_stream_offsets[first_pack_stream_index])
            })
            .ok_or_else(|| Error::other("block offset out of range"))?;

        let (mut has_crc, mut crc) = (block.has_crc, block.crc);

        // A block with one sub-stream may store its CRC in the sub-stream info.
        if !has_crc
            && block.num_unpack_sub_streams == 1
            && let Some(sub_streams_info) = archive.sub_streams_info.as_ref()
        {
            let mut substream_index = 0;
            for i in 0..block_index {
                substream_index += archive.blocks[i].num_unpack_sub_streams;
            }

            // With several sub-streams, those CRCs belong to the files, so they
            // cannot check the block.
            if sub_streams_info.has_crc.contains(substream_index) {
                has_crc = true;
                crc = sub_streams_info.crcs[substream_index];
            }
        }

        source.seek(SeekFrom::Start(block_offset))?;
        let pack_size = archive.pack_sizes[first_pack_stream_index] as usize;

        let mut decoder: Box<dyn Read> = Box::new(BufReader::with_capacity(
            PACKED_STREAM_BUFFER_SIZE,
            BoundedReader::new(source, pack_size),
        ));
        let block = &archive.blocks[block_index];
        for (index, coder) in block.ordered_coder_iter() {
            if coder.num_in_streams != 1 || coder.num_out_streams != 1 {
                return Err(Error::unsupported(
                    "Multi input/output stream coders are not supported",
                ));
            }
            let next = add_decoder(
                decoder,
                block.get_unpack_size_at_index(index) as usize,
                coder,
                memory_limit_kb,
                zstd,
            )?;
            decoder = Box::new(next);
        }
        if has_crc {
            decoder = Box::new(Crc32VerifyingReader::new(
                decoder,
                block.get_unpack_size() as usize,
                crc,
            ));
        }

        Ok(decoder)
    }

    fn build_decode_stack2<'r>(
        source: &'r mut R,
        archive: &Archive,
        block_index: usize,
        memory_limit_kb: usize,
        zstd: &mut ZstdPool<'r>,
    ) -> Result<Box<dyn Read + 'r>, Error> {
        const MAX_CODER_COUNT: usize = 32;
        let block = &archive.blocks[block_index];
        if block.coders.len() > MAX_CODER_COUNT {
            return Err(Error::unsupported(format!(
                "Too many coders: {}",
                block.coders.len()
            )));
        }

        assert!(block.total_input_streams > block.total_output_streams);
        let shared_source = Rc::new(RefCell::new(source));
        let first_pack_stream_index = archive.stream_map.block_first_pack_stream_index[block_index];
        let start_pos = SIGNATURE_HEADER_SIZE
            .checked_add(archive.pack_pos)
            .ok_or_else(|| Error::other("pack position out of range"))?;
        let offsets = &archive.stream_map.pack_stream_offsets[first_pack_stream_index..];

        let mut sources = try_vec_with_capacity(
            block.packed_streams.len(),
            "unable to allocate the 7z packed-source table",
        )?;

        for (i, offset) in offsets[..block.packed_streams.len()].iter().enumerate() {
            let pack_pos = start_pos
                .checked_add(*offset)
                .ok_or_else(|| Error::other("pack stream offset out of range"))?;
            let pack_size = archive.pack_sizes[first_pack_stream_index + i];
            let pack_end = pack_pos
                .checked_add(pack_size)
                .ok_or_else(|| Error::other("pack stream size out of range"))?;

            let pack_reader =
                SharedBoundedReader::new(Rc::clone(&shared_source), (pack_pos, pack_end));

            sources.push(pack_reader);
        }

        let mut coder_to_stream_map = [usize::MAX; MAX_CODER_COUNT];

        let mut si = 0;
        for (i, coder) in block.coders.iter().enumerate() {
            coder_to_stream_map[i] = si;
            si += coder.num_in_streams as usize;
        }

        let main_coder_index = {
            let mut coder_used = [false; MAX_CODER_COUNT];
            for bp in block.bind_pairs.iter() {
                // `out_index` is validated `< total_output_streams` at parse time, but the
                // `coder_used` array indexes coders (max `MAX_CODER_COUNT`); reject an
                // index that would fall outside it instead of panicking.
                let out_index = bp.out_index as usize;
                if out_index >= block.coders.len() {
                    return Err(Error::other("bind pair out index exceeds coder count"));
                }
                coder_used[out_index] = true;
            }
            let mut mci = 0;
            for (i, used) in coder_used[..block.coders.len()].iter().enumerate() {
                if !used {
                    mci = i;
                    break;
                }
            }
            mci
        };

        // Build the decoder for the folder's final output by resolving the main coder's
        // output stream. `get_in_stream2` recursively wires up the whole coder graph,
        // so this also handles single-input filters (e.g. Delta) layered on top of a
        // BCJ2 coder's output, not just a bare BCJ2 main coder.
        let mut decoder = Self::get_in_stream2(
            block,
            &sources,
            &coder_to_stream_map,
            main_coder_index,
            0,
            memory_limit_kb,
            zstd,
        )?;
        if block.has_crc {
            decoder = Box::new(Crc32VerifyingReader::new(
                decoder,
                block.get_unpack_size() as usize,
                block.crc,
            ));
        }
        Ok(decoder)
    }

    fn get_in_stream<'r>(
        block: &Block,
        sources: &[SharedBoundedReader<'r, R>],
        coder_to_stream_map: &[usize],
        in_stream_index: usize,
        depth: usize,
        memory_limit_kb: usize,
        zstd: &mut ZstdPool<'r>,
    ) -> Result<Box<dyn Read + 'r>, Error>
    where
        R: 'r,
    {
        let index = block
            .packed_streams
            .iter()
            .position(|&i| i == in_stream_index as u64);
        if let Some(index) = index {
            return Ok(Box::new(BufReader::with_capacity(
                PACKED_STREAM_BUFFER_SIZE,
                sources[index].clone(),
            )));
        }

        let bp = block
            .find_bind_pair_for_in_stream(in_stream_index as u64)
            .ok_or_else(|| {
                Error::other(format!(
                    "Couldn't find bind pair for stream {in_stream_index}"
                ))
            })?;
        let index = bp.out_index as usize;

        Self::get_in_stream2(
            block,
            sources,
            coder_to_stream_map,
            index,
            depth,
            memory_limit_kb,
            zstd,
        )
    }

    fn get_in_stream2<'r>(
        block: &Block,
        sources: &[SharedBoundedReader<'r, R>],
        coder_to_stream_map: &[usize],
        in_stream_index: usize,
        depth: usize,
        memory_limit_kb: usize,
        zstd: &mut ZstdPool<'r>,
    ) -> Result<Box<dyn Read + 'r>, Error>
    where
        R: 'r,
    {
        // Each coder is visited at most once in an acyclic graph, so a traversal deeper
        // than the coder count means the bind pairs form a cycle. Bail out instead of
        // recursing until the stack overflows (an uncatchable abort).
        if depth > block.coders.len() {
            return Err(Error::other("cyclic coder bind-pair graph"));
        }
        let (Some(coder), Some(&start_index)) = (
            block.coders.get(in_stream_index),
            coder_to_stream_map.get(in_stream_index),
        ) else {
            return Err(Error::other("in_stream_index out of range"));
        };
        if start_index == usize::MAX {
            return Err(Error::other("in_stream_index out of range"));
        }
        let uncompressed_len = *block
            .unpack_sizes
            .get(in_stream_index)
            .ok_or_else(|| Error::other("in_stream_index out of range"))?
            as usize;
        if coder.num_in_streams == 1 {
            let input = Self::get_in_stream(
                block,
                sources,
                coder_to_stream_map,
                start_index,
                depth + 1,
                memory_limit_kb,
                zstd,
            )?;

            let decoder = add_decoder(input, uncompressed_len, coder, memory_limit_kb, zstd)?;
            return Ok(Box::new(decoder));
        }

        // BCJ2 is the only multi-input coder we support. It takes four input streams
        // (main, call, jump and range-coder) and produces a single output stream.
        if coder.encoder_method_id() == EncoderMethod::ID_BCJ2 {
            let num_in_streams = coder.num_in_streams as usize;
            // The BCJ2 decoder indexes exactly four input streams; reject a malformed count
            // up front instead of handing a short/long input list to the upstream decoder.
            if num_in_streams != 4 {
                return Err(Error::other(
                    "BCJ2 coder must declare exactly four input streams",
                ));
            }
            let mut inputs: Vec<Box<dyn Read>> = try_vec_with_capacity(
                num_in_streams,
                "unable to allocate the 7z BCJ2 input table",
            )?;
            for i in start_index..start_index + num_in_streams {
                inputs.push(Self::get_in_stream(
                    block,
                    sources,
                    coder_to_stream_map,
                    i,
                    depth + 1,
                    memory_limit_kb,
                    zstd,
                )?);
            }
            return Ok(Box::new(Bcj2Reader::new(inputs, uncompressed_len as u64)));
        }

        Err(Error::unsupported(format!(
            "Unsupported multi-input coder: {:?}",
            coder.encoder_method_id()
        )))
    }

    /// Takes a closure to decode each files in the archive.
    ///
    /// Attention about solid archive:
    /// When decoding a solid archive, the data to be decompressed depends on the data in front of it,
    /// you cannot simply skip the previous data and only decompress the data in the back.
    ///
    /// Returning `Ok(false)` from the closure skips the rest of the current
    /// block only, and decoding goes on with the next block. Return an error
    /// to stop.
    pub fn for_each_entries<F: FnMut(&ArchiveEntry, &mut dyn Read) -> Result<bool, Error>>(
        &mut self,
        mut each: F,
    ) -> Result<(), Error> {
        let block_count = self.archive.blocks.len();
        let mut zstd = ZstdBufferCache::default();
        for block_index in 0..block_count {
            let block_decoder = BlockDecoder::new(
                self.memory_limit_kb,
                block_index,
                &self.archive,
                &mut self.source,
                &mut zstd,
            );
            block_decoder.for_each_entries(&mut each)?;
        }
        // decode empty files
        for file_index in 0..self.archive.files.len() {
            let block_index = self.archive.stream_map.file_block_index[file_index];
            if block_index.is_none() {
                let file = &self.archive.files[file_index];
                let empty_reader: &mut dyn Read = &mut ([0u8; 0].as_slice());
                if !each(file, empty_reader)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Decoder for a specific block within a 7z archive.
///
/// Provides access to entries within a single compression block and allows
/// decoding files from that block.
pub(crate) struct BlockDecoder<'a, R: Read + Seek> {
    memory_limit_kb: usize,
    block_index: usize,
    archive: &'a Archive,
    source: &'a mut R,
    zstd: &'a mut ZstdBufferCache,
}

impl<'a, R: Read + Seek> BlockDecoder<'a, R> {
    /// Creates a new [`BlockDecoder`] for decoding a specific block in the archive.
    ///
    /// # Arguments
    /// * `memory_limit_kb` - Codec working-memory ceiling in KiB
    /// * `block_index` - Index of the block to decode within the archive
    /// * `archive` - Reference to the archive containing the block
    /// * `source` - Mutable reference to the reader providing archive data
    /// * `zstd` - Zstandard working memory, reused from block to block
    pub(crate) fn new(
        memory_limit_kb: usize,
        block_index: usize,
        archive: &'a Archive,
        source: &'a mut R,
        zstd: &'a mut ZstdBufferCache,
    ) -> Self {
        Self {
            memory_limit_kb,
            block_index,
            archive,
            source,
            zstd,
        }
    }

    /// Takes a closure to decode each files in this block.
    ///
    /// When decoding files in a block, the data to be decompressed depends on the data in front of
    /// it, you cannot simply skip the previous data and only decompress the data in the back.
    ///
    /// Non-solid archives use one block per file and allow more effective decoding of single files.
    pub(crate) fn for_each_entries<
        F: FnMut(&ArchiveEntry, &mut dyn Read) -> Result<bool, Error>,
    >(
        self,
        each: &mut F,
    ) -> Result<bool, Error> {
        let Self {
            memory_limit_kb,
            block_index,
            archive,
            source,
            zstd,
        } = self;
        let mut zstd = zstd.for_block(&archive.blocks[block_index], memory_limit_kb)?;
        let mut block_reader = ArchiveReader::build_decode_stack(
            source,
            archive,
            block_index,
            memory_limit_kb,
            &mut zstd,
        )?;
        let start = archive.stream_map.block_first_file_index[block_index];
        let file_count = archive.blocks[block_index].num_unpack_sub_streams;

        for file_index in start..(file_count + start) {
            let file = &archive.files[file_index];
            if file.has_stream && file.size > 0 {
                let mut decoder: Box<dyn Read> =
                    Box::new(BoundedReader::new(&mut block_reader, file.size as usize));
                if file.has_crc {
                    decoder = Box::new(Crc32VerifyingReader::new(
                        decoder,
                        file.size as usize,
                        file.crc,
                    ));
                }
                if !each(file, &mut decoder)? {
                    return Ok(false);
                }
            } else {
                let empty_reader: &mut dyn Read = &mut ([0u8; 0].as_slice());
                if !each(file, empty_reader)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{Archive, try_vec_filled};
    use crate::{crc, error::Error};

    /// Writes a 7z number in its full-width form.
    fn number(output: &mut Vec<u8>, value: u64) {
        output.push(0xff);
        output.extend_from_slice(&value.to_le_bytes());
    }

    /// Builds an archive whose next header is `next`, after `packed`.
    fn archive(packed: &[u8], next: &[u8]) -> Vec<u8> {
        let mut start = Vec::new();
        start.extend_from_slice(&(packed.len() as u64).to_le_bytes());
        start.extend_from_slice(&(next.len() as u64).to_le_bytes());
        start.extend_from_slice(&crc::hash(next).to_le_bytes());
        let mut bytes = b"7z\xbc\xaf'\x1c\x00\x04".to_vec();
        bytes.extend_from_slice(&crc::hash(&start).to_le_bytes());
        bytes.extend_from_slice(&start);
        bytes.extend_from_slice(packed);
        bytes.extend_from_slice(next);
        bytes
    }

    /// An encoded header: one Copy coder over `packed` that declares
    /// `declared` decoded bytes.
    fn encoded_header(packed: &[u8], declared: u64) -> Vec<u8> {
        let mut next = vec![0x17, 6, 0, 1, 9]; // Encoded header, PackInfo, one stream.
        number(&mut next, packed.len() as u64);
        next.extend_from_slice(&[0, 7, 11, 1, 0, 1, 1, 0, 12]); // One folder, one Copy coder.
        number(&mut next, declared);
        next.extend_from_slice(&[0, 0]); // End UnpackInfo, end StreamsInfo.
        archive(packed, &next)
    }

    #[test]
    fn encoded_header_above_the_memory_limit_is_rejected_before_decoding() {
        // Header, End: an empty archive in two decoded bytes.
        let packed = [1, 0];
        let small = encoded_header(&packed, 2);
        let parsed = Archive::read_with_limits(&mut Cursor::new(small), 1, usize::MAX).unwrap();
        assert!(parsed.files.is_empty());

        // A 1 KiB memory limit allows a 1,024-byte header. The Copy input
        // is shorter, so that header fails as truncated, not as too large.
        let exact = encoded_header(&packed, 1024);
        let result = Archive::read_with_limits(&mut Cursor::new(exact), 1, usize::MAX);
        assert!(matches!(result, Err(Error::Io(..))), "{result:?}");

        for declared in [1025, 256 << 20, u64::MAX] {
            let large = encoded_header(&packed, declared);
            let result = Archive::read_with_limits(&mut Cursor::new(large), 1, usize::MAX);
            assert!(
                matches!(
                    result,
                    Err(Error::HeaderSizeLimited {
                        max_bytes: 1024,
                        actual_bytes,
                    }) if actual_bytes == declared
                ),
                "{declared}: {result:?}"
            );
        }
    }

    #[test]
    fn file_count_above_the_entry_limit_is_rejected_before_the_file_table() {
        // A file count and the end of the properties. The header bound is
        // set above the count, so only the entry limit applies.
        for (count, max_entries) in [(11, 10), (5_000_000, 1_000_000)] {
            let mut header = Vec::new();
            number(&mut header, count as u64);
            header.push(0);
            let result = Archive::read_files_info(
                &mut Cursor::new(header),
                &mut Archive::default(),
                usize::MAX,
                max_entries,
            );
            assert!(
                matches!(
                    result,
                    Err(Error::MaxEntriesLimited { max, actual })
                        if max == max_entries && actual == count
                ),
                "{result:?}"
            );
        }
        // At the limit, the table is built. These files have streams but
        // the header has no sub-streams, which is a later error.
        let result = Archive::read_files_info(
            &mut Cursor::new(vec![10, 0]),
            &mut Archive::default(),
            usize::MAX,
            10,
        );
        assert!(matches!(result, Err(Error::Other(_))), "{result:?}");
        // A count above the header length is still a header error.
        let result = Archive::read_files_info(
            &mut Cursor::new(vec![11, 0]),
            &mut Archive::default(),
            2,
            10,
        );
        assert!(matches!(result, Err(Error::Other(_))), "{result:?}");
    }

    #[test]
    fn block_count_above_the_entry_limit_is_rejected_before_the_block_table() {
        // kFolder, a block count, then the external flag.
        for (count, max_entries) in [(11, 10), (5_000_000, 1_000_000)] {
            let mut header = vec![crate::archive::K_FOLDER];
            number(&mut header, count as u64);
            header.push(0);
            let mut archive = Archive::default();
            let result = Archive::read_unpack_info(
                &mut Cursor::new(header),
                &mut archive,
                usize::MAX,
                max_entries,
            );
            assert!(
                matches!(
                    result,
                    Err(Error::MaxEntriesLimited { max, actual })
                        if max == max_entries && actual == count
                ),
                "{result:?}"
            );
            assert_eq!(archive.blocks.capacity(), 0);
        }
        // At the limit, the blocks are read; this header ends early.
        let result = Archive::read_unpack_info(
            &mut Cursor::new(vec![crate::archive::K_FOLDER, 10, 0]),
            &mut Archive::default(),
            usize::MAX,
            10,
        );
        assert!(
            !matches!(result, Err(Error::MaxEntriesLimited { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn coder_stream_totals_reject_overflow_before_graph_construction() {
        for counts in [(2, 1, u64::MAX, 1), (1, 2, 1, u64::MAX)] {
            let mut header = vec![2];
            for (inputs, outputs) in [(counts.0, counts.1), (counts.2, counts.3)] {
                header.extend_from_slice(&[0x11, 0]); // Explicit stream counts, Copy method.
                for count in [inputs, outputs] {
                    header.push(0xff); // Full-width 7z integer encoding.
                    header.extend_from_slice(&count.to_le_bytes());
                }
            }
            header.extend_from_slice(&[0, 0, 0, 1]);
            assert!(Archive::read_block(&mut header.as_slice(), header.len()).is_err());
        }

        // Two connected, single-input Copy coders remain valid at the exact
        // stream-count ceiling, with no additional graph data consumed.
        let header = [2, 1, 0, 1, 0, 1, 0];
        let mut input = header.as_slice();
        let block = Archive::read_block(&mut input, 2).unwrap();
        assert_eq!(block.total_input_streams, 2);
        assert_eq!(block.total_output_streams, 2);
        assert!(input.is_empty());
        assert!(Archive::read_block(&mut header.as_slice(), 1).is_err());
    }

    #[test]
    fn empty_start_header_is_an_error() {
        let mut input = b"7z\xbc\xaf\x27\x1c\x00\x04".to_vec();
        input.extend_from_slice(&[0; 24]);
        let result = Archive::read_with_limits(&mut Cursor::new(input), 1024, usize::MAX);
        assert!(
            matches!(&result, Err(Error::Other(message)) if message == "7z start header is empty")
        );
    }

    #[test]
    fn impossible_parser_allocation_is_an_error() {
        let result = try_vec_filled::<u8>(usize::MAX, 0, "allocation failed");
        assert!(result.is_err());
    }
}
