//! Safe, bounded RAR container parsing and native decompression.

use compcol::Status;
#[cfg(panic = "unwind")]
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::Cancellation;

const RAR_PREFIX: &[u8] = b"Rar!\x1a\x07";
const MAX_SFX_BYTES: usize = 1 << 20;

const V15_BLOCK_ARCHIVE: u8 = 0x73;
const V15_BLOCK_FILE: u8 = 0x74;
const V15_BLOCK_COMMENT: u8 = 0x75;
const V15_BLOCK_SERVICE: u8 = 0x7a;
const V15_BLOCK_END: u8 = 0x7b;
const V15_BLOCK_HAS_DATA: u16 = 0x8000;
const V15_ARCHIVE_SOLID: u16 = 0x0008;
const V15_ARCHIVE_ENCRYPTED: u16 = 0x0080;
const V15_ARCHIVE_COMMENT: u16 = 0x0002;
const V15_FILE_SPLIT_BEFORE: u16 = 0x0001;
const V15_FILE_SPLIT_AFTER: u16 = 0x0002;
const V15_FILE_ENCRYPTED: u16 = 0x0004;
const V15_FILE_SOLID: u16 = 0x0010;
const V15_FILE_WINDOW_MASK: u16 = 0x00e0;
const V15_FILE_LARGE: u16 = 0x0100;
const V15_FILE_UNICODE: u16 = 0x0200;

const V5_BLOCK_ARCHIVE: u64 = 1;
const V5_BLOCK_FILE: u64 = 2;
const V5_BLOCK_ENCRYPT: u64 = 4;
const V5_BLOCK_END: u64 = 5;
const V5_BLOCK_HAS_EXTRA: u64 = 0x0001;
const V5_BLOCK_HAS_DATA: u64 = 0x0002;
const V5_DATA_NOT_FIRST: u64 = 0x0008;
const V5_DATA_NOT_LAST: u64 = 0x0010;
const V5_ARCHIVE_SOLID: u64 = 0x0004;
const V5_FILE_IS_DIRECTORY: u64 = 0x0001;
const V5_FILE_HAS_MTIME: u64 = 0x0002;
const V5_FILE_HAS_CRC32: u64 = 0x0004;
const V5_FILE_UNKNOWN_SIZE: u64 = 0x0008;
const V5_FILE_SOLID: u64 = 0x0040;
const V5_FILE_V7_COMPAT: u64 = 0x0010_0000;

#[derive(Debug)]
pub(crate) enum RarFailure {
    Cancelled,
    Limit(&'static str),
    Unsupported(String),
    Corrupt(String),
}

pub(crate) struct RarEntry {
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) is_directory: bool,
}

pub(crate) fn extract(
    input: &[u8],
    entry_limit: usize,
    member_limit: usize,
    total_limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<RarEntry>, RarFailure> {
    if cancellation.is_cancelled() {
        return Err(RarFailure::Cancelled);
    }
    let search_end = input
        .len()
        .min(MAX_SFX_BYTES.saturating_add(RAR_PREFIX.len() + 2));
    let signature = input[..search_end]
        .windows(RAR_PREFIX.len())
        .position(|window| window == RAR_PREFIX)
        .ok_or_else(|| corrupt("RAR signature not found"))?;
    let version_offset = signature
        .checked_add(RAR_PREFIX.len())
        .ok_or(RarFailure::Limit("RAR signature offset overflow"))?;
    match input.get(version_offset..) {
        Some([0, rest @ ..]) => {
            extract_v15(rest, entry_limit, member_limit, total_limit, cancellation)
        }
        Some([1, 0, rest @ ..]) => {
            extract_v5(rest, entry_limit, member_limit, total_limit, cancellation)
        }
        _ => Err(unsupported("unsupported RAR container version")),
    }
}

fn extract_v15(
    input: &[u8],
    entry_limit: usize,
    member_limit: usize,
    total_limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<RarEntry>, RarFailure> {
    let mut cursor = 0;
    let archive = read_v15_header(input, &mut cursor)?;
    if archive.kind != V15_BLOCK_ARCHIVE {
        return Err(corrupt("RAR archive header is missing"));
    }
    if archive.flags & V15_ARCHIVE_ENCRYPTED != 0 {
        return Err(unsupported("encrypted RAR headers are unsupported"));
    }
    let archive_solid = archive.flags & V15_ARCHIVE_SOLID != 0;
    let mut decoder29 = rustleaks_rar_codec::codec::rar29::Unpack29::new();
    let mut entries = Vec::new();
    entries
        .try_reserve(entry_limit.min(64))
        .map_err(|_| RarFailure::Limit("could not retain RAR entry metadata"))?;
    let mut decoded_total = 0usize;

    while cursor < input.len() {
        if cancellation.is_cancelled() {
            return Err(RarFailure::Cancelled);
        }
        let header = read_v15_header(input, &mut cursor)?;
        let data_end = cursor
            .checked_add(header.data_size)
            .ok_or(RarFailure::Limit("RAR packed-data range overflow"))?;
        let packed = input
            .get(cursor..data_end)
            .ok_or_else(|| corrupt("truncated RAR packed data"))?;
        cursor = data_end;
        match header.kind {
            V15_BLOCK_FILE => {
                if entries.len() >= entry_limit {
                    return Err(RarFailure::Limit("RAR entry limit exceeded"));
                }
                let parsed = parse_v15_file(
                    header.flags,
                    header.data,
                    packed,
                    archive_solid,
                    &mut decoder29,
                    member_limit,
                    cancellation,
                )?;
                decoded_total = decoded_total
                    .checked_add(parsed.data.len())
                    .ok_or(RarFailure::Limit("RAR cumulative size overflow"))?;
                if decoded_total > total_limit {
                    return Err(RarFailure::Limit("RAR cumulative limit exceeded"));
                }
                entries
                    .try_reserve(1)
                    .map_err(|_| RarFailure::Limit("could not retain RAR entry metadata"))?;
                entries.push(parsed);
            }
            V15_BLOCK_END => break,
            _ => {}
        }
    }
    Ok(entries)
}

struct V15Header<'a> {
    kind: u8,
    flags: u16,
    data_size: usize,
    data: &'a [u8],
}

fn read_v15_header<'a>(input: &'a [u8], cursor: &mut usize) -> Result<V15Header<'a>, RarFailure> {
    let start = *cursor;
    let base = input
        .get(start..start.saturating_add(7))
        .ok_or_else(|| corrupt("truncated RAR block header"))?;
    let expected_crc = u16::from_le_bytes([base[0], base[1]]);
    let kind = base[2];
    let flags = u16::from_le_bytes([base[3], base[4]]);
    let declared_size = usize::from(u16::from_le_bytes([base[5], base[6]]));
    let size = if kind == V15_BLOCK_ARCHIVE && flags & V15_ARCHIVE_COMMENT != 0 {
        if declared_size < 13 {
            return Err(corrupt("invalid RAR archive-comment header"));
        }
        13
    } else {
        declared_size
    };
    if size < 7 {
        return Err(corrupt("invalid RAR block-header size"));
    }
    let end = start
        .checked_add(size)
        .ok_or(RarFailure::Limit("RAR block-header range overflow"))?;
    let full = input
        .get(start..end)
        .ok_or_else(|| corrupt("truncated RAR block header"))?;
    let crc_data = if kind == V15_BLOCK_COMMENT && full.len() > 13 {
        &full[2..13]
    } else {
        &full[2..]
    };
    if crc32(crc_data) & u32::from(u16::MAX) != u32::from(expected_crc) {
        return Err(corrupt("invalid RAR block-header CRC"));
    }
    let mut data = &full[7..];
    let mut data_size = if flags & V15_BLOCK_HAS_DATA != 0 {
        let size = take_u32(&mut data)?;
        usize::try_from(size).map_err(|_| RarFailure::Limit("RAR packed size exceeds usize"))?
    } else {
        0
    };
    if matches!(kind, V15_BLOCK_FILE | V15_BLOCK_SERVICE) && flags & V15_FILE_LARGE != 0 {
        let high_bytes = data
            .get(21..25)
            .ok_or_else(|| corrupt("truncated large RAR packed size"))?;
        let high = u64::from(u32::from_le_bytes(
            high_bytes.try_into().expect("four-byte slice"),
        ));
        let combined = (high << 32) | data_size as u64;
        data_size = usize::try_from(combined)
            .map_err(|_| RarFailure::Limit("RAR packed size exceeds usize"))?;
    }
    *cursor = end;
    Ok(V15Header {
        kind,
        flags,
        data_size,
        data,
    })
}

fn parse_v15_file(
    flags: u16,
    mut header: &[u8],
    packed: &[u8],
    archive_solid: bool,
    decoder29: &mut rustleaks_rar_codec::codec::rar29::Unpack29,
    member_limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<RarEntry, RarFailure> {
    if flags & (V15_FILE_SPLIT_BEFORE | V15_FILE_SPLIT_AFTER) != 0 {
        return Err(unsupported("multi-volume RAR members are unsupported"));
    }
    if flags & V15_FILE_ENCRYPTED != 0 {
        return Err(unsupported("encrypted RAR members are unsupported"));
    }
    if header.len() < 21 {
        return Err(corrupt("truncated RAR file header"));
    }
    let unpacked_low = u64::from(take_u32(&mut header)?);
    let _host = take_u8(&mut header)?;
    let expected_crc = take_u32(&mut header)?;
    let _mtime = take_u32(&mut header)?;
    let unpack_version = take_u8(&mut header)?;
    let method = take_u8(&mut header)?;
    let name_size = usize::from(take_u16(&mut header)?);
    let _attributes = take_u32(&mut header)?;
    let (packed_high, unpacked_high) = if flags & V15_FILE_LARGE != 0 {
        (
            u64::from(take_u32(&mut header)?),
            u64::from(take_u32(&mut header)?),
        )
    } else {
        (0, 0)
    };
    if packed_high != (packed.len() as u64 >> 32) {
        return Err(corrupt("RAR packed-size mismatch"));
    }
    let unpacked = (unpacked_high << 32) | unpacked_low;
    let unpacked = bounded_size(unpacked, member_limit)?;
    let encoded_name = take(&mut header, name_size)?;
    let name = if flags & V15_FILE_UNICODE != 0 {
        decode_v15_name(encoded_name)?
    } else {
        copy_bytes(encoded_name, "could not allocate RAR file name")?
    };
    let is_directory = flags & V15_FILE_WINDOW_MASK == V15_FILE_WINDOW_MASK;
    if is_directory {
        return Ok(RarEntry {
            name,
            data: Vec::new(),
            is_directory: true,
        });
    }
    let solid = archive_solid || flags & V15_FILE_SOLID != 0;
    let window_shift = u32::from((flags & V15_FILE_WINDOW_MASK) >> 5);
    let window = 0x1_0000usize
        .checked_shl(window_shift)
        .ok_or(RarFailure::Limit("RAR dictionary size overflow"))?;
    if method != 0x30 && window > member_limit {
        return Err(RarFailure::Limit("RAR dictionary exceeds member limit"));
    }
    let data = if method == 0x30 {
        copy_exact_stored(packed, unpacked)?
    } else {
        match unpack_version {
            20 | 26 => decode_with(
                compcol::rar2::Decoder::with_unpack_size(unpacked as u64),
                packed,
                unpacked,
                cancellation,
            )?,
            29 => decode_rar3(decoder29, packed, unpacked, solid, cancellation)?,
            _ => {
                return Err(unsupported(format!(
                    "unsupported RAR decoder version {unpack_version}"
                )));
            }
        }
    };
    if crc32(&data) != expected_crc {
        return Err(corrupt("RAR member CRC mismatch"));
    }
    Ok(RarEntry {
        name,
        data,
        is_directory: false,
    })
}

fn decode_rar3(
    decoder: &mut rustleaks_rar_codec::codec::rar29::Unpack29,
    packed: &[u8],
    unpacked: usize,
    solid: bool,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, RarFailure> {
    #[cfg(panic = "abort")]
    {
        let _ = (decoder, packed, unpacked, solid, cancellation);
        return Err(unsupported(
            "compressed RAR3 decoding is unavailable when dependency panics abort the process",
        ));
    }

    #[cfg(panic = "unwind")]
    {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut cancelled = || cancellation.is_cancelled();
            if solid {
                decoder.decode_member_with_cancel(packed, unpacked, &mut cancelled)
            } else {
                decoder.decode_non_solid_member_with_cancel(packed, unpacked, &mut cancelled)
            }
        }))
        .map_err(|_| corrupt("RAR3 decoder panicked"))?;
        match result {
            Ok(output) => Ok(output),
            Err(rustleaks_rar_codec::codec::Error::Cancelled) => Err(RarFailure::Cancelled),
            Err(error) => Err(corrupt(format!("RAR3 decompression failed: {error}"))),
        }
    }
}

fn extract_v5(
    input: &[u8],
    entry_limit: usize,
    member_limit: usize,
    total_limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<RarEntry>, RarFailure> {
    let mut cursor = 0;
    let archive = read_v5_header(input, &mut cursor)?;
    if archive.kind == V5_BLOCK_ENCRYPT {
        return Err(unsupported("encrypted RAR headers are unsupported"));
    }
    if archive.kind != V5_BLOCK_ARCHIVE {
        return Err(corrupt("RAR5 archive header is missing"));
    }
    let mut archive_data = archive.data;
    let archive_flags = take_vint(&mut archive_data)?;
    let archive_solid = archive_flags & V5_ARCHIVE_SOLID != 0;
    let mut decoder50 = rustleaks_rar_codec::codec::rar50::Unpack50Decoder::new();
    let mut decode_state = V5DecodeState {
        archive_solid,
        decoder: &mut decoder50,
    };
    let mut entries = Vec::new();
    entries
        .try_reserve(entry_limit.min(64))
        .map_err(|_| RarFailure::Limit("could not retain RAR entry metadata"))?;
    let mut decoded_total = 0usize;

    while cursor < input.len() {
        if cancellation.is_cancelled() {
            return Err(RarFailure::Cancelled);
        }
        let header = read_v5_header(input, &mut cursor)?;
        let data_end = cursor
            .checked_add(header.data_size)
            .ok_or(RarFailure::Limit("RAR5 packed-data range overflow"))?;
        let packed = input
            .get(cursor..data_end)
            .ok_or_else(|| corrupt("truncated RAR5 packed data"))?;
        cursor = data_end;
        match header.kind {
            V5_BLOCK_FILE => {
                if entries.len() >= entry_limit {
                    return Err(RarFailure::Limit("RAR entry limit exceeded"));
                }
                let parsed = parse_v5_file(
                    header.flags,
                    header.data,
                    header.extra,
                    packed,
                    &mut decode_state,
                    member_limit,
                    cancellation,
                )?;
                decoded_total = decoded_total
                    .checked_add(parsed.data.len())
                    .ok_or(RarFailure::Limit("RAR cumulative size overflow"))?;
                if decoded_total > total_limit {
                    return Err(RarFailure::Limit("RAR cumulative limit exceeded"));
                }
                entries
                    .try_reserve(1)
                    .map_err(|_| RarFailure::Limit("could not retain RAR entry metadata"))?;
                entries.push(parsed);
            }
            V5_BLOCK_ENCRYPT => {
                return Err(unsupported("encrypted RAR headers are unsupported"));
            }
            V5_BLOCK_END => break,
            _ => {}
        }
    }
    Ok(entries)
}

struct V5Header<'a> {
    kind: u64,
    flags: u64,
    data_size: usize,
    data: &'a [u8],
    extra: &'a [u8],
}

fn read_v5_header<'a>(input: &'a [u8], cursor: &mut usize) -> Result<V5Header<'a>, RarFailure> {
    let start = *cursor;
    let crc_bytes = input
        .get(start..start.saturating_add(4))
        .ok_or_else(|| corrupt("truncated RAR5 block header"))?;
    let expected_crc = u32::from_le_bytes(crc_bytes.try_into().expect("four-byte slice"));
    let mut position = start + 4;
    let size_start = position;
    let header_size = take_vint_at(input, &mut position)?;
    let header_size = bounded_size(header_size, input.len())?;
    let data_start = position;
    let data_end = data_start
        .checked_add(header_size)
        .ok_or(RarFailure::Limit("RAR5 block-header range overflow"))?;
    input
        .get(data_start..data_end)
        .ok_or_else(|| corrupt("truncated RAR5 block header"))?;
    if crc32(&input[size_start..data_end]) != expected_crc {
        return Err(corrupt("invalid RAR5 block-header CRC"));
    }
    let mut header = &input[data_start..data_end];
    let kind = take_vint(&mut header)?;
    let flags = take_vint(&mut header)?;
    let extra_size = if flags & V5_BLOCK_HAS_EXTRA != 0 {
        bounded_size(take_vint(&mut header)?, header_size)?
    } else {
        0
    };
    let data_size = if flags & V5_BLOCK_HAS_DATA != 0 {
        bounded_size(take_vint(&mut header)?, input.len())?
    } else {
        0
    };
    if extra_size > header.len() {
        return Err(corrupt("invalid RAR5 extra-data size"));
    }
    let split = header.len() - extra_size;
    let (data, extra) = header.split_at(split);
    *cursor = data_end;
    Ok(V5Header {
        kind,
        flags,
        data_size,
        data,
        extra,
    })
}

#[allow(clippy::too_many_lines)] // Keep the mutually exclusive unwind/abort decode policies adjacent.
fn parse_v5_file(
    block_flags: u64,
    mut header: &[u8],
    extra: &[u8],
    packed: &[u8],
    decode_state: &mut V5DecodeState<'_>,
    member_limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<RarEntry, RarFailure> {
    if block_flags & (V5_DATA_NOT_FIRST | V5_DATA_NOT_LAST) != 0 {
        return Err(unsupported("multi-volume RAR5 members are unsupported"));
    }
    let file_flags = take_vint(&mut header)?;
    if file_flags & V5_FILE_UNKNOWN_SIZE != 0 {
        return Err(unsupported(
            "RAR5 members with unknown size are unsupported",
        ));
    }
    let unpacked = bounded_size(take_vint(&mut header)?, member_limit)?;
    let _attributes = take_vint(&mut header)?;
    if file_flags & V5_FILE_HAS_MTIME != 0 {
        let _ = take_u32(&mut header)?;
    }
    let expected_crc = if file_flags & V5_FILE_HAS_CRC32 != 0 {
        Some(take_u32(&mut header)?)
    } else {
        None
    };
    let compression = take_vint(&mut header)?;
    let method = (compression >> 7) & 7;
    let _host = take_vint(&mut header)?;
    let name_size = bounded_size(take_vint(&mut header)?, member_limit)?;
    let name = copy_bytes(
        take(&mut header, name_size)?,
        "could not allocate RAR5 file name",
    )?;
    if extra_has_encryption(extra)? {
        return Err(unsupported("encrypted RAR5 members are unsupported"));
    }
    let is_directory = file_flags & V5_FILE_IS_DIRECTORY != 0;
    if is_directory {
        return Ok(RarEntry {
            name,
            data: Vec::new(),
            is_directory: true,
        });
    }
    #[cfg(panic = "abort")]
    let _ = (
        V5_FILE_SOLID,
        V5_FILE_V7_COMPAT,
        decode_state.archive_solid,
        &decode_state.decoder,
        cancellation,
    );
    let data = if method == 0 {
        copy_exact_stored(packed, unpacked)?
    } else {
        #[cfg(panic = "abort")]
        return Err(unsupported(
            "compressed RAR5 decoding is unavailable when dependency panics abort the process",
        ));

        #[cfg(panic = "unwind")]
        {
            let algorithm = compression & 0x3f;
            let solid = compression & V5_FILE_SOLID != 0 || decode_state.archive_solid;
            let window = match algorithm {
                0 => 0x2_0000usize
                    .checked_shl(((compression >> 10) & 0x0f) as u32)
                    .ok_or(RarFailure::Limit("RAR5 dictionary size overflow"))?,
                1 => {
                    let base = 0x2_0000usize
                        .checked_shl(((compression >> 10) & 0x1f) as u32)
                        .ok_or(RarFailure::Limit("RAR7 dictionary size overflow"))?;
                    base.checked_add(base / 32 * ((compression >> 15) & 0x1f) as usize)
                        .ok_or(RarFailure::Limit("RAR7 dictionary size overflow"))?
                }
                _ => return Err(unsupported("unsupported RAR5 compression algorithm")),
            };
            if window > member_limit {
                return Err(RarFailure::Limit("RAR5 dictionary exceeds member limit"));
            }
            if algorithm == 1 && compression & V5_FILE_V7_COMPAT == 0 {
                return Err(unsupported("RAR7 compressed members are unsupported"));
            }
            let algorithm = u8::try_from(algorithm)
                .map_err(|_| unsupported("unsupported RAR5 compression algorithm"))?;
            let decoded = catch_unwind(AssertUnwindSafe(|| {
                let mut cancelled = || cancellation.is_cancelled();
                decode_state
                    .decoder
                    .decode_member_with_dictionary_and_cancel(
                        packed,
                        algorithm,
                        unpacked,
                        window,
                        solid,
                        rustleaks_rar_codec::codec::rar50::DecodeMode::Lz,
                        &mut cancelled,
                    )
            }))
            .map_err(|_| corrupt("RAR5 decoder panicked"))?;
            match decoded {
                Ok(decoded) => decoded,
                Err(rustleaks_rar_codec::codec::Error::Cancelled) => {
                    return Err(RarFailure::Cancelled);
                }
                Err(error) => {
                    return Err(corrupt(format!("RAR5 decompression failed: {error}")));
                }
            }
        }
    };
    if expected_crc.is_some_and(|expected| crc32(&data) != expected) {
        return Err(corrupt("RAR5 member CRC mismatch"));
    }
    Ok(RarEntry {
        name,
        data,
        is_directory: false,
    })
}

struct V5DecodeState<'a> {
    archive_solid: bool,
    decoder: &'a mut rustleaks_rar_codec::codec::rar50::Unpack50Decoder,
}

fn extra_has_encryption(mut extra: &[u8]) -> Result<bool, RarFailure> {
    while !extra.is_empty() {
        let record_size = bounded_size(take_vint(&mut extra)?, extra.len())?;
        let mut record = take(&mut extra, record_size)?;
        if take_vint(&mut record)? == 1 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn decode_with<D: compcol::Decoder>(
    mut decoder: D,
    packed: &[u8],
    unpacked: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, RarFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(unpacked)
        .map_err(|_| RarFailure::Limit("could not allocate RAR member output"))?;
    output.resize(unpacked, 0);
    let mut consumed = 0usize;
    let mut written = 0usize;
    let mut ended = false;
    while consumed < packed.len() || written < unpacked {
        if cancellation.is_cancelled() {
            return Err(RarFailure::Cancelled);
        }
        let (progress, status) = decoder
            .decode(&packed[consumed..], &mut output[written..])
            .map_err(|error| corrupt(format!("RAR decompression failed: {error:?}")))?;
        consumed = consumed
            .checked_add(progress.consumed)
            .ok_or(RarFailure::Limit("RAR decoder input count overflow"))?;
        written = written
            .checked_add(progress.written)
            .ok_or(RarFailure::Limit("RAR decoder output count overflow"))?;
        if consumed > packed.len() || written > unpacked {
            return Err(corrupt("RAR decoder reported invalid progress"));
        }
        if status == Status::StreamEnd {
            ended = true;
            break;
        }
        if progress.consumed == 0 && progress.written == 0 {
            break;
        }
    }
    while !ended {
        if cancellation.is_cancelled() {
            return Err(RarFailure::Cancelled);
        }
        let (progress, status) = decoder
            .finish(&mut output[written..])
            .map_err(|error| corrupt(format!("RAR decompression failed: {error:?}")))?;
        written = written
            .checked_add(progress.written)
            .ok_or(RarFailure::Limit("RAR decoder output count overflow"))?;
        if written > unpacked {
            return Err(corrupt("RAR decoder exceeded the declared output size"));
        }
        if status == Status::StreamEnd {
            ended = true;
            break;
        }
        if progress.written == 0 {
            break;
        }
    }
    if !ended || written != unpacked {
        return Err(corrupt("RAR decoded size mismatch"));
    }
    Ok(output)
}

fn copy_exact_stored(packed: &[u8], unpacked: usize) -> Result<Vec<u8>, RarFailure> {
    if packed.len() != unpacked {
        return Err(corrupt("stored RAR member size mismatch"));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(unpacked)
        .map_err(|_| RarFailure::Limit("could not allocate stored RAR member"))?;
    output.extend_from_slice(packed);
    Ok(output)
}

fn decode_v15_name(encoded: &[u8]) -> Result<Vec<u8>, RarFailure> {
    let separator = encoded.iter().position(|byte| *byte == 0);
    let Some(separator) = separator else {
        return copy_bytes(encoded, "could not allocate RAR file name");
    };
    let plain = &encoded[..separator];
    let mut coded = &encoded[separator + 1..];
    if coded.len() < 2 {
        return Err(corrupt("invalid encoded RAR file name"));
    }
    let high = u16::from(take_u8(&mut coded)?) << 8;
    let mut flags = take_u8(&mut coded)?;
    let mut remaining_flag_bits = 8u8;
    let mut units = Vec::new();
    units
        .try_reserve(plain.len())
        .map_err(|_| RarFailure::Limit("could not allocate RAR file name"))?;
    while units.len() < plain.len() && !coded.is_empty() {
        if remaining_flag_bits == 0 {
            flags = take_u8(&mut coded)?;
            remaining_flag_bits = 8;
        }
        match flags >> 6 {
            0 => units.push(u16::from(take_u8(&mut coded)?)),
            1 => units.push(u16::from(take_u8(&mut coded)?) | high),
            2 => units.push(take_u16(&mut coded)?),
            _ => {
                let count = take_u8(&mut coded)?;
                let wanted = usize::from(count & 0x7f).saturating_add(2);
                let available = plain.len().saturating_sub(units.len());
                let amount = wanted.min(available);
                if count & 0x80 != 0 {
                    let correction = take_u8(&mut coded)?;
                    for byte in &plain[units.len()..units.len() + amount] {
                        units.push(u16::from(byte.wrapping_add(correction)) | high);
                    }
                } else {
                    for byte in &plain[units.len()..units.len() + amount] {
                        units.push(u16::from(*byte));
                    }
                }
            }
        }
        flags <<= 2;
        remaining_flag_bits -= 2;
    }
    let mut name = String::new();
    name.try_reserve(units.len().saturating_mul(3))
        .map_err(|_| RarFailure::Limit("could not allocate decoded RAR file name"))?;
    for unit in char::decode_utf16(units) {
        name.push(unit.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    Ok(name.into_bytes())
}

fn bounded_size(value: u64, limit: usize) -> Result<usize, RarFailure> {
    let value =
        usize::try_from(value).map_err(|_| RarFailure::Limit("RAR size exceeds platform usize"))?;
    if value > limit {
        return Err(RarFailure::Limit(
            "RAR declared size exceeds resource limit",
        ));
    }
    Ok(value)
}

fn copy_bytes(input: &[u8], message: &'static str) -> Result<Vec<u8>, RarFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| RarFailure::Limit(message))?;
    output.extend_from_slice(input);
    Ok(output)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], RarFailure> {
    let (head, tail) = input
        .split_at_checked(count)
        .ok_or_else(|| corrupt("truncated RAR header field"))?;
    *input = tail;
    Ok(head)
}

fn take_u8(input: &mut &[u8]) -> Result<u8, RarFailure> {
    Ok(take(input, 1)?[0])
}

fn take_u16(input: &mut &[u8]) -> Result<u16, RarFailure> {
    Ok(u16::from_le_bytes(
        take(input, 2)?.try_into().expect("two-byte slice"),
    ))
}

fn take_u32(input: &mut &[u8]) -> Result<u32, RarFailure> {
    Ok(u32::from_le_bytes(
        take(input, 4)?.try_into().expect("four-byte slice"),
    ))
}

fn take_vint(input: &mut &[u8]) -> Result<u64, RarFailure> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = take_u8(input)?;
        if shift == 63 && byte > 1 {
            return Err(corrupt("RAR variable integer overflow"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(corrupt("RAR variable integer is too long"))
}

fn take_vint_at(input: &[u8], cursor: &mut usize) -> Result<u64, RarFailure> {
    let mut remaining = input
        .get(*cursor..)
        .ok_or_else(|| corrupt("truncated RAR variable integer"))?;
    let before = remaining.len();
    let value = take_vint(&mut remaining)?;
    *cursor = cursor
        .checked_add(before - remaining.len())
        .ok_or(RarFailure::Limit("RAR cursor overflow"))?;
    Ok(value)
}

fn crc32(input: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in input {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn corrupt(message: impl Into<String>) -> RarFailure {
    RarFailure::Corrupt(message.into())
}

fn unsupported(message: impl Into<String>) -> RarFailure {
    RarFailure::Unsupported(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    const RAR5_COMPRESSED_A: &[u8] = &[
        0xc0, 0x97, 0x0d, 0x02, 0x3f, 0xd3, 0x1f, 0xf1, 0x5e, 0x7f, 0x49, 0x81, 0xa9, 0xbf, 0x15,
        0x00,
    ];

    #[test]
    fn extracts_stored_v15_and_v5_members() {
        let cancelled = AtomicBool::new(false);
        for archive in [
            stored_v15(b"nested/value.txt", b"portable RAR\n"),
            stored_v5(b"nested/value.txt", b"portable RAR\n"),
        ] {
            let entries = extract(&archive, 4, 4096, 4096, &cancelled).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].name, b"nested/value.txt");
            assert_eq!(entries[0].data, b"portable RAR\n");
            assert!(!entries[0].is_directory);
        }
    }

    #[test]
    fn extracts_compressed_rar5_member_with_safe_decoder() {
        let cancelled = AtomicBool::new(false);
        let expected = [b'A'; 200]
            .into_iter()
            .chain(std::iter::once(b'\n'))
            .collect::<Vec<_>>();
        let archive = compressed_v5(b"value.txt", RAR5_COMPRESSED_A, &expected);
        let entries = extract(&archive, 4, 1 << 20, 4096, &cancelled).unwrap();
        assert_eq!(entries[0].data, expected);
    }

    #[test]
    fn extracts_rar3_rar5_and_solid_oracle_fixtures() {
        type Fixture<'a> = (&'a str, &'a [u8], &'a [&'a [u8]]);

        let cancelled = AtomicBool::new(false);
        let expected_text = include_bytes!(concat!(
            "../../../compat/fixtures/oracle/rar-test-files-16b785c",
            "/expected/testfile.txt"
        ));
        let expected_jpeg = include_bytes!(concat!(
            "../../../compat/fixtures/oracle/rar-test-files-16b785c",
            "/expected/testfile.jpg"
        ));
        let expected_png = include_bytes!(concat!(
            "../../../compat/fixtures/oracle/rar-test-files-16b785c",
            "/expected/testfile.png"
        ));
        let fixtures: &[Fixture<'_>] = &[
            (
                "testfile.rar3.rar",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar3.rar"
                ),
                &[expected_text],
            ),
            (
                "testfile.rar3.solid.rar",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar3.solid.rar"
                ),
                &[expected_text],
            ),
            (
                "testfile.rar3.cbr",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar3.cbr"
                ),
                &[expected_jpeg, expected_png],
            ),
            (
                "testfile.rar3.solid.cbr",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar3.solid.cbr"
                ),
                &[expected_png, expected_jpeg],
            ),
            (
                "testfile.rar5.rar",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar5.rar"
                ),
                &[expected_text],
            ),
            (
                "testfile.rar5.solid.rar",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar5.solid.rar"
                ),
                &[expected_text],
            ),
            (
                "testfile.rar5.cbr",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar5.cbr"
                ),
                &[expected_jpeg, expected_png],
            ),
            (
                "testfile.rar5.solid.cbr",
                include_bytes!(
                    "../../../compat/fixtures/oracle/rar-test-files-16b785c/testfile.rar5.solid.cbr"
                ),
                &[expected_jpeg, expected_png],
            ),
        ];

        for &(name, archive, expected) in fixtures {
            let entries = extract(archive, 4, 1 << 20, 1 << 20, &cancelled)
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let actual = entries
                .iter()
                .filter(|entry| !entry.is_directory)
                .map(|entry| entry.data.as_slice())
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{name}");
        }
    }

    #[test]
    fn rejects_crc_corruption_and_resource_excess() {
        let cancelled = AtomicBool::new(false);
        let mut archive = stored_v5(b"value.txt", b"payload");
        let last = archive.len() - 1;
        archive[last] ^= 1;
        assert!(matches!(
            extract(&archive, 4, 4096, 4096, &cancelled),
            Err(RarFailure::Corrupt(_))
        ));
        let archive = stored_v15(b"value.txt", b"payload");
        assert!(matches!(
            extract(&archive, 4, 3, 4096, &cancelled),
            Err(RarFailure::Limit(_))
        ));
        let unsupported = v5_archive(b"value.txt", b"packed", b"payload", (3 << 7) | 2);
        assert!(matches!(
            extract(&unsupported, 4, 1 << 20, 4096, &cancelled),
            Err(RarFailure::Unsupported(_))
        ));
        let cancelled = AtomicBool::new(true);
        assert!(matches!(
            extract(&archive, 4, 4096, 4096, &cancelled),
            Err(RarFailure::Cancelled)
        ));
    }

    #[test]
    fn rejects_rar5_name_above_member_limit_before_copying_it() {
        let cancelled = AtomicBool::new(false);
        let archive = stored_v5(&vec![b'n'; 4096], b"payload");

        assert!(matches!(
            extract(&archive, 4, 1024, 4096, &cancelled),
            Err(RarFailure::Limit(_))
        ));
    }

    fn stored_v15(name: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut archive = b"Rar!\x1a\x07\x00".to_vec();
        append_v15_header(&mut archive, V15_BLOCK_ARCHIVE, 0, &[], &[]);
        let mut body = Vec::new();
        let payload_size = u32::try_from(payload.len()).unwrap();
        body.extend_from_slice(&payload_size.to_le_bytes());
        body.extend_from_slice(&payload_size.to_le_bytes());
        body.push(2);
        body.extend_from_slice(&crc32(payload).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(20);
        body.push(0x30);
        body.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(name);
        append_v15_header(
            &mut archive,
            V15_BLOCK_FILE,
            V15_BLOCK_HAS_DATA,
            &body,
            payload,
        );
        append_v15_header(&mut archive, V15_BLOCK_END, 0, &[], &[]);
        archive
    }

    fn append_v15_header(output: &mut Vec<u8>, kind: u8, flags: u16, data: &[u8], payload: &[u8]) {
        let size = 7 + data.len();
        let mut checked = Vec::new();
        checked.push(kind);
        checked.extend_from_slice(&flags.to_le_bytes());
        checked.extend_from_slice(&u16::try_from(size).unwrap().to_le_bytes());
        checked.extend_from_slice(data);
        let crc = u16::try_from(crc32(&checked) & u32::from(u16::MAX)).unwrap();
        output.extend_from_slice(&crc.to_le_bytes());
        output.extend_from_slice(&checked);
        output.extend_from_slice(payload);
    }

    fn stored_v5(name: &[u8], payload: &[u8]) -> Vec<u8> {
        v5_archive(name, payload, payload, 0)
    }

    fn compressed_v5(name: &[u8], packed: &[u8], unpacked: &[u8]) -> Vec<u8> {
        v5_archive(name, packed, unpacked, 3 << 7)
    }

    fn v5_archive(name: &[u8], packed: &[u8], unpacked: &[u8], compression: u64) -> Vec<u8> {
        let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
        append_v5_block(&mut archive, V5_BLOCK_ARCHIVE, 0, &[0], &[]);
        let mut file = Vec::new();
        put_vint(&mut file, V5_FILE_HAS_CRC32);
        put_vint(&mut file, unpacked.len() as u64);
        put_vint(&mut file, 0);
        file.extend_from_slice(&crc32(unpacked).to_le_bytes());
        put_vint(&mut file, compression);
        put_vint(&mut file, 1);
        put_vint(&mut file, name.len() as u64);
        file.extend_from_slice(name);
        append_v5_block(
            &mut archive,
            V5_BLOCK_FILE,
            V5_BLOCK_HAS_DATA,
            &file,
            packed,
        );
        append_v5_block(&mut archive, V5_BLOCK_END, 0, &[0], &[]);
        archive
    }

    fn append_v5_block(output: &mut Vec<u8>, kind: u64, flags: u64, data: &[u8], payload: &[u8]) {
        let mut header = Vec::new();
        put_vint(&mut header, kind);
        put_vint(&mut header, flags);
        if flags & V5_BLOCK_HAS_DATA != 0 {
            put_vint(&mut header, payload.len() as u64);
        }
        header.extend_from_slice(data);
        let mut checked = Vec::new();
        put_vint(&mut checked, header.len() as u64);
        checked.extend_from_slice(&header);
        output.extend_from_slice(&crc32(&checked).to_le_bytes());
        output.extend_from_slice(&checked);
        output.extend_from_slice(payload);
    }

    fn put_vint(output: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                return;
            }
        }
    }
}
