use crate::Cancellation;

const STREAM_IDENTIFIER: u8 = 0xff;
const COMPRESSED_DATA: u8 = 0x00;
const UNCOMPRESSED_DATA: u8 = 0x01;
const SNAPPY_MAGIC: &[u8; 6] = b"sNaPpY";
const S2_MAGIC: &[u8; 6] = b"S2sTwO";
const SNAPPY_BLOCK_LIMIT: usize = 64 * 1024;
const S2_BLOCK_LIMIT: usize = 4 * 1024 * 1024;
const MINLZ_BLOCK_LIMIT: usize = 8 * 1024 * 1024;
const MINLZ_MAGIC: &[u8; 5] = b"MinLz";

#[derive(Debug)]
pub(crate) enum SnappyFailure {
    Cancelled,
    Limit,
    Decode(&'static str),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Flavor {
    Snappy,
    S2,
}

pub(crate) fn decode_framed(
    input: &[u8],
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, SnappyFailure> {
    let mut position = 0_usize;
    let mut flavor = None;
    let mut output = Vec::new();

    while position < input.len() {
        cancelled(cancellation)?;
        let header_end = position.checked_add(4).ok_or(SnappyFailure::Limit)?;
        let header = input
            .get(position..header_end)
            .ok_or(SnappyFailure::Decode("truncated Snappy chunk header"))?;
        position = header_end;
        let chunk_type = header[0];
        let chunk_length =
            usize::from(header[1]) | (usize::from(header[2]) << 8) | (usize::from(header[3]) << 16);
        let chunk_end = position
            .checked_add(chunk_length)
            .ok_or(SnappyFailure::Limit)?;
        let chunk = input
            .get(position..chunk_end)
            .ok_or(SnappyFailure::Decode("truncated Snappy chunk"))?;
        position = chunk_end;

        match chunk_type {
            STREAM_IDENTIFIER => {
                flavor = Some(if chunk == SNAPPY_MAGIC {
                    Flavor::Snappy
                } else if chunk == S2_MAGIC {
                    Flavor::S2
                } else {
                    return Err(SnappyFailure::Decode("invalid Snappy stream identifier"));
                });
            }
            COMPRESSED_DATA | UNCOMPRESSED_DATA => {
                let selected = flavor.ok_or(SnappyFailure::Decode(
                    "Snappy data precedes the stream identifier",
                ))?;
                let (checksum_bytes, payload) = chunk
                    .split_at_checked(4)
                    .ok_or(SnappyFailure::Decode("Snappy data chunk lacks a checksum"))?;
                let expected = u32::from_le_bytes(
                    checksum_bytes
                        .try_into()
                        .map_err(|_| SnappyFailure::Decode("invalid Snappy checksum"))?,
                );
                let remaining = limit
                    .checked_sub(output.len())
                    .ok_or(SnappyFailure::Limit)?;
                let decoded = if chunk_type == COMPRESSED_DATA {
                    decode_block(payload, remaining, selected, cancellation)?
                } else {
                    let block_limit = match selected {
                        Flavor::Snappy => SNAPPY_BLOCK_LIMIT,
                        Flavor::S2 => S2_BLOCK_LIMIT,
                    };
                    if payload.len() > remaining || payload.len() > block_limit {
                        return Err(SnappyFailure::Limit);
                    }
                    copy_fallible(payload)?
                };
                if masked_crc32c(&decoded) != expected {
                    return Err(SnappyFailure::Decode("Snappy checksum mismatch"));
                }
                append_fallible(&mut output, &decoded, limit)?;
            }
            0x02..=0x7f => {
                return Err(SnappyFailure::Decode(
                    "unsupported unskippable Snappy chunk",
                ));
            }
            _ => {}
        }
    }

    if flavor.is_none() {
        return Err(SnappyFailure::Decode("Snappy stream identifier is missing"));
    }
    Ok(output)
}

// This implements the MinLZ specification v1.0.
//
// The archive source intentionally supports only native MinLZ framing. The
// optional legacy Snappy/S2 fallback is rejected, matching the pinned Go
// archive reader's default configuration. Keeping the framing state machine
// together makes the resource and transition checks directly auditable.
#[allow(clippy::too_many_lines)]
pub(crate) fn decode_minlz_framed(
    input: &[u8],
    limit: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, SnappyFailure> {
    let mut position = 0_usize;
    let mut stream_header = false;
    let mut want_eof = false;
    let mut block_limit = 0_usize;
    let mut stream_length = 0_u64;
    let mut output = Vec::new();

    while position < input.len() {
        cancelled(cancellation)?;
        let header_end = position.checked_add(4).ok_or(SnappyFailure::Limit)?;
        let header = input
            .get(position..header_end)
            .ok_or(SnappyFailure::Decode("truncated MinLZ chunk header"))?;
        position = header_end;
        let chunk_type = header[0];
        let chunk_length =
            usize::from(header[1]) | (usize::from(header[2]) << 8) | (usize::from(header[3]) << 16);
        let chunk_end = position
            .checked_add(chunk_length)
            .ok_or(SnappyFailure::Limit)?;
        let chunk = input
            .get(position..chunk_end)
            .ok_or(SnappyFailure::Decode("truncated MinLZ chunk"))?;
        position = chunk_end;

        if !stream_header && chunk_type <= 0x3f && chunk_type != 0x20 {
            return Err(SnappyFailure::Decode(
                "MinLZ data precedes the stream identifier",
            ));
        }

        match chunk_type {
            0x00 => {
                return Err(SnappyFailure::Decode(
                    "legacy Snappy/S2 fallback is disabled for MinLZ",
                ));
            }
            0x01 => {
                let (checksum_bytes, payload) = chunk
                    .split_at_checked(4)
                    .ok_or(SnappyFailure::Decode("MinLZ data chunk lacks a checksum"))?;
                let expected = little_u32(checksum_bytes, "invalid MinLZ checksum")?;
                let remaining = limit
                    .checked_sub(output.len())
                    .ok_or(SnappyFailure::Limit)?;
                if payload.len() > remaining || payload.len() > block_limit {
                    return Err(SnappyFailure::Limit);
                }
                if masked_crc32c(payload) != expected {
                    return Err(SnappyFailure::Decode("MinLZ checksum mismatch"));
                }
                append_fallible(&mut output, payload, limit)?;
                stream_length = stream_length
                    .checked_add(u64::try_from(payload.len()).map_err(|_| SnappyFailure::Limit)?)
                    .ok_or(SnappyFailure::Limit)?;
            }
            0x02 | 0x03 => {
                let (checksum_bytes, encoded) = chunk
                    .split_at_checked(4)
                    .ok_or(SnappyFailure::Decode("MinLZ data chunk lacks a checksum"))?;
                let expected = little_u32(checksum_bytes, "invalid MinLZ checksum")?;
                let (decoded_length, header_length) = read_varint(encoded)?;
                let decoded_length =
                    usize::try_from(decoded_length).map_err(|_| SnappyFailure::Limit)?;
                let block = encoded
                    .get(header_length..)
                    .ok_or(SnappyFailure::Decode("truncated MinLZ block"))?;
                let remaining = limit
                    .checked_sub(output.len())
                    .ok_or(SnappyFailure::Limit)?;
                if decoded_length == 0 || decoded_length < block.len() {
                    return Err(SnappyFailure::Decode("invalid MinLZ decoded length"));
                }
                if decoded_length > remaining
                    || decoded_length > block_limit
                    || decoded_length > MINLZ_BLOCK_LIMIT
                {
                    return Err(SnappyFailure::Limit);
                }
                let decoded = decode_minlz_block(block, decoded_length, cancellation)?;
                let checksum_input = if chunk_type == 0x03 { block } else { &decoded };
                if masked_crc32c(checksum_input) != expected {
                    return Err(SnappyFailure::Decode("MinLZ checksum mismatch"));
                }
                append_fallible(&mut output, &decoded, limit)?;
                stream_length = stream_length
                    .checked_add(u64::try_from(decoded_length).map_err(|_| SnappyFailure::Limit)?)
                    .ok_or(SnappyFailure::Limit)?;
            }
            0x20 => {
                if chunk.len() > 10 {
                    return Err(SnappyFailure::Decode("invalid MinLZ EOF chunk"));
                }
                if !chunk.is_empty() {
                    let (expected_length, consumed) = read_varint64(chunk)?;
                    if consumed != chunk.len() || expected_length != stream_length {
                        return Err(SnappyFailure::Decode("MinLZ EOF length mismatch"));
                    }
                }
                want_eof = false;
                stream_header = false;
            }
            0x04..=0x1f | 0x21..=0x3f | 0xc0..=0xfd => {
                return Err(SnappyFailure::Decode("unsupported unskippable MinLZ chunk"));
            }
            0x40..=0xbf | 0xfe => {}
            STREAM_IDENTIFIER => {
                if chunk.len() != 6 || chunk.get(..5) != Some(MINLZ_MAGIC.as_slice()) {
                    return Err(SnappyFailure::Decode("invalid MinLZ stream identifier"));
                }
                let info = chunk[5];
                if info & 0xc0 != 0 {
                    return Err(SnappyFailure::Decode("invalid MinLZ stream parameters"));
                }
                let block_log = u32::from(info & 0x0f)
                    .checked_add(10)
                    .ok_or(SnappyFailure::Limit)?;
                if block_log > 23 {
                    return Err(SnappyFailure::Decode("invalid MinLZ block size"));
                }
                block_limit = 1_usize.checked_shl(block_log).ok_or(SnappyFailure::Limit)?;
                stream_length = 0;
                stream_header = true;
                want_eof = true;
            }
        }
    }

    if want_eof {
        return Err(SnappyFailure::Decode("MinLZ EOF chunk is missing"));
    }
    Ok(output)
}

// Keep the tag state machine aligned with sections 2.1 through 2.5 of the
// MinLZ specification so each bounds check remains adjacent to its encoding.
#[allow(clippy::too_many_lines)]
fn decode_minlz_block(
    input: &[u8],
    decoded_length: usize,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, SnappyFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(decoded_length)
        .map_err(|_| SnappyFailure::Limit)?;
    let mut position = 0_usize;
    let mut offset = 1_usize;

    while position < input.len() {
        cancelled(cancellation)?;
        let tag = input[position];
        match tag & 0x03 {
            0 => {
                let (length, next) = minlz_length(input, position, tag >> 3, 30)?;
                position = next;
                if tag & 0x04 != 0 {
                    copy_from_back(
                        &mut output,
                        offset,
                        length,
                        decoded_length,
                        "MinLZ",
                        cancellation,
                    )?;
                } else {
                    let end = position.checked_add(length).ok_or(SnappyFailure::Limit)?;
                    let literal = input
                        .get(position..end)
                        .ok_or(SnappyFailure::Decode("truncated MinLZ literal"))?;
                    append_exact_named(&mut output, literal, decoded_length, "MinLZ")?;
                    position = end;
                }
            }
            1 => {
                let second_position = position.checked_add(1).ok_or(SnappyFailure::Limit)?;
                let second = *input
                    .get(second_position)
                    .ok_or(SnappyFailure::Decode("truncated MinLZ short copy"))?;
                let encoded = u16::from(tag) | (u16::from(second) << 8);
                offset = usize::from(encoded >> 6)
                    .checked_add(1)
                    .ok_or(SnappyFailure::Limit)?;
                let code = usize::from((tag >> 2) & 0x0f);
                let length = if code == 15 {
                    let extra_position = position.checked_add(2).ok_or(SnappyFailure::Limit)?;
                    let extra = usize::from(
                        *input
                            .get(extra_position)
                            .ok_or(SnappyFailure::Decode("truncated MinLZ short copy length"))?,
                    );
                    position = position.checked_add(3).ok_or(SnappyFailure::Limit)?;
                    extra.checked_add(18).ok_or(SnappyFailure::Limit)?
                } else {
                    position = position.checked_add(2).ok_or(SnappyFailure::Limit)?;
                    code.checked_add(4).ok_or(SnappyFailure::Limit)?
                };
                copy_from_back(
                    &mut output,
                    offset,
                    length,
                    decoded_length,
                    "MinLZ",
                    cancellation,
                )?;
            }
            2 => {
                let offset_position = position.checked_add(1).ok_or(SnappyFailure::Limit)?;
                let (stored_offset, next) = read_little(input, offset_position, 2)?;
                offset = stored_offset.checked_add(64).ok_or(SnappyFailure::Limit)?;
                let (length, after_length) = minlz_copy_length(input, next, tag >> 2)?;
                position = after_length;
                copy_from_back(
                    &mut output,
                    offset,
                    length,
                    decoded_length,
                    "MinLZ",
                    cancellation,
                )?;
            }
            3 => {
                let end = position.checked_add(4).ok_or(SnappyFailure::Limit)?;
                let bytes = input
                    .get(position..end)
                    .ok_or(SnappyFailure::Decode("truncated MinLZ long copy"))?;
                let value = little_u32(bytes, "truncated MinLZ long copy")?;
                let mut literal_length =
                    usize::try_from((value >> 3) & 0x03).map_err(|_| SnappyFailure::Limit)?;
                let length;
                if value & 0x04 == 0 {
                    length = usize::try_from((value >> 5) & 0x07)
                        .map_err(|_| SnappyFailure::Limit)?
                        .checked_add(4)
                        .ok_or(SnappyFailure::Limit)?;
                    offset = usize::try_from((value >> 8) & 0xffff)
                        .map_err(|_| SnappyFailure::Limit)?
                        .checked_add(64)
                        .ok_or(SnappyFailure::Limit)?;
                    position = position.checked_add(3).ok_or(SnappyFailure::Limit)?;
                    literal_length = literal_length.checked_add(1).ok_or(SnappyFailure::Limit)?;
                } else {
                    offset = usize::try_from(value >> 11)
                        .map_err(|_| SnappyFailure::Limit)?
                        .checked_add(65_536)
                        .ok_or(SnappyFailure::Limit)?;
                    let (decoded, next) =
                        minlz_copy_length(input, end, ((value >> 5) & 0x3f) as u8)?;
                    length = decoded;
                    position = next;
                }
                if literal_length != 0 {
                    let literal_end = position
                        .checked_add(literal_length)
                        .ok_or(SnappyFailure::Limit)?;
                    let literal = input
                        .get(position..literal_end)
                        .ok_or(SnappyFailure::Decode("truncated MinLZ fused literal"))?;
                    append_exact_named(&mut output, literal, decoded_length, "MinLZ")?;
                    position = literal_end;
                }
                copy_from_back(
                    &mut output,
                    offset,
                    length,
                    decoded_length,
                    "MinLZ",
                    cancellation,
                )?;
            }
            _ => return Err(SnappyFailure::Decode("invalid MinLZ tag")),
        }
    }

    if position != input.len() || output.len() != decoded_length {
        return Err(SnappyFailure::Decode("MinLZ decoded length mismatch"));
    }
    Ok(output)
}

fn minlz_length(
    input: &[u8],
    position: usize,
    code: u8,
    base: usize,
) -> Result<(usize, usize), SnappyFailure> {
    if code < 29 {
        return Ok((
            usize::from(code)
                .checked_add(1)
                .ok_or(SnappyFailure::Limit)?,
            position.checked_add(1).ok_or(SnappyFailure::Limit)?,
        ));
    }
    let width = usize::from(code - 28);
    let value_position = position.checked_add(1).ok_or(SnappyFailure::Limit)?;
    let (extra, next) = read_little(input, value_position, width)?;
    Ok((base.checked_add(extra).ok_or(SnappyFailure::Limit)?, next))
}

fn minlz_copy_length(
    input: &[u8],
    position: usize,
    code: u8,
) -> Result<(usize, usize), SnappyFailure> {
    if code <= 60 {
        return Ok((usize::from(code) + 4, position));
    }
    let width = usize::from(code - 60);
    let (extra, next) = read_little(input, position, width)?;
    Ok((extra.checked_add(64).ok_or(SnappyFailure::Limit)?, next))
}

// Snappy and S2 share a compact tag state machine whose flavor-dependent
// repeat behavior is clearer when audited in one place.
#[allow(clippy::too_many_lines)]
fn decode_block(
    input: &[u8],
    limit: usize,
    flavor: Flavor,
    cancellation: &dyn Cancellation,
) -> Result<Vec<u8>, SnappyFailure> {
    let (decoded_length, mut position) = read_varint(input)?;
    let decoded_length = usize::try_from(decoded_length).map_err(|_| SnappyFailure::Limit)?;
    let block_limit = match flavor {
        Flavor::Snappy => SNAPPY_BLOCK_LIMIT,
        Flavor::S2 => S2_BLOCK_LIMIT,
    };
    if decoded_length > limit || decoded_length > block_limit {
        return Err(SnappyFailure::Limit);
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(decoded_length)
        .map_err(|_| SnappyFailure::Limit)?;
    let mut last_offset = 0_usize;

    while position < input.len() {
        cancelled(cancellation)?;
        let tag = *input
            .get(position)
            .ok_or(SnappyFailure::Decode("truncated Snappy tag"))?;
        position = position.checked_add(1).ok_or(SnappyFailure::Limit)?;
        match tag & 0x03 {
            0 => {
                let upper = u32::from(tag >> 2);
                let length = if upper < 60 {
                    usize::try_from(upper + 1).map_err(|_| SnappyFailure::Limit)?
                } else {
                    let extra = usize::try_from(upper - 59).map_err(|_| SnappyFailure::Limit)?;
                    let end = position.checked_add(extra).ok_or(SnappyFailure::Limit)?;
                    let encoded = input
                        .get(position..end)
                        .ok_or(SnappyFailure::Decode("truncated Snappy literal length"))?;
                    position = end;
                    let mut value = 0_u32;
                    for (shift, byte) in encoded.iter().enumerate() {
                        value |= u32::from(*byte) << (shift * 8);
                    }
                    usize::try_from(value)
                        .map_err(|_| SnappyFailure::Limit)?
                        .checked_add(1)
                        .ok_or(SnappyFailure::Limit)?
                };
                let end = position.checked_add(length).ok_or(SnappyFailure::Limit)?;
                let literal = input
                    .get(position..end)
                    .ok_or(SnappyFailure::Decode("truncated Snappy literal"))?;
                append_exact(&mut output, literal, decoded_length)?;
                position = end;
            }
            1 => {
                let low = usize::from(
                    *input
                        .get(position)
                        .ok_or(SnappyFailure::Decode("truncated Snappy short copy"))?,
                );
                position = position.checked_add(1).ok_or(SnappyFailure::Limit)?;
                let code = usize::from((tag >> 2) & 0x07);
                let encoded_offset = (usize::from(tag & 0xe0) << 3) | low;
                let length = if encoded_offset == 0 && flavor == Flavor::S2 {
                    match code {
                        5 => {
                            let extra = usize::from(
                                *input
                                    .get(position)
                                    .ok_or(SnappyFailure::Decode("truncated S2 repeat length"))?,
                            );
                            position = position.checked_add(1).ok_or(SnappyFailure::Limit)?;
                            extra.checked_add(8).ok_or(SnappyFailure::Limit)?
                        }
                        6 => {
                            let (extra, next) = read_little(input, position, 2)?;
                            position = next;
                            extra.checked_add(260).ok_or(SnappyFailure::Limit)?
                        }
                        7 => {
                            let (extra, next) = read_little(input, position, 3)?;
                            position = next;
                            extra.checked_add(65_540).ok_or(SnappyFailure::Limit)?
                        }
                        _ => code.checked_add(4).ok_or(SnappyFailure::Limit)?,
                    }
                } else {
                    last_offset = encoded_offset;
                    code.checked_add(4).ok_or(SnappyFailure::Limit)?
                };
                copy_from_back(
                    &mut output,
                    last_offset,
                    length,
                    decoded_length,
                    "Snappy",
                    cancellation,
                )?;
            }
            2 => {
                let (offset, next) = read_little(input, position, 2)?;
                position = next;
                last_offset = offset;
                let length = usize::from(tag >> 2)
                    .checked_add(1)
                    .ok_or(SnappyFailure::Limit)?;
                copy_from_back(
                    &mut output,
                    last_offset,
                    length,
                    decoded_length,
                    "Snappy",
                    cancellation,
                )?;
            }
            3 => {
                let (offset, next) = read_little(input, position, 4)?;
                position = next;
                last_offset = offset;
                let length = usize::from(tag >> 2)
                    .checked_add(1)
                    .ok_or(SnappyFailure::Limit)?;
                copy_from_back(
                    &mut output,
                    last_offset,
                    length,
                    decoded_length,
                    "Snappy",
                    cancellation,
                )?;
            }
            _ => return Err(SnappyFailure::Decode("invalid Snappy tag")),
        }
    }

    if output.len() != decoded_length {
        return Err(SnappyFailure::Decode("Snappy decoded length mismatch"));
    }
    Ok(output)
}

fn read_varint(input: &[u8]) -> Result<(u32, usize), SnappyFailure> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for (index, byte) in input.iter().copied().enumerate().take(6) {
        if index == 5 {
            return Err(SnappyFailure::Decode("Snappy length varint overflows"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return u32::try_from(value)
                .map(|decoded| (decoded, index + 1))
                .map_err(|_| SnappyFailure::Decode("Snappy length varint overflows"));
        }
        shift += 7;
    }
    Err(SnappyFailure::Decode("truncated Snappy length varint"))
}

fn read_varint64(input: &[u8]) -> Result<(u64, usize), SnappyFailure> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().enumerate().take(10) {
        if index == 9 && byte > 1 {
            return Err(SnappyFailure::Decode("MinLZ varint overflows"));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(SnappyFailure::Decode("truncated MinLZ varint"))
}

fn little_u32(input: &[u8], message: &'static str) -> Result<u32, SnappyFailure> {
    input
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| SnappyFailure::Decode(message))
}

fn read_little(
    input: &[u8],
    position: usize,
    width: usize,
) -> Result<(usize, usize), SnappyFailure> {
    let end = position.checked_add(width).ok_or(SnappyFailure::Limit)?;
    let encoded = input
        .get(position..end)
        .ok_or(SnappyFailure::Decode("truncated Snappy copy offset"))?;
    let mut value = 0_u64;
    for (shift, byte) in encoded.iter().enumerate() {
        value |= u64::from(*byte) << (shift * 8);
    }
    Ok((
        usize::try_from(value).map_err(|_| SnappyFailure::Limit)?,
        end,
    ))
}

fn copy_from_back(
    output: &mut Vec<u8>,
    offset: usize,
    length: usize,
    decoded_length: usize,
    codec: &'static str,
    cancellation: &dyn Cancellation,
) -> Result<(), SnappyFailure> {
    if offset == 0 || offset > output.len() {
        return Err(SnappyFailure::Decode(match codec {
            "MinLZ" => "invalid MinLZ copy offset",
            _ => "invalid Snappy copy offset",
        }));
    }
    if output
        .len()
        .checked_add(length)
        .is_none_or(|end| end > decoded_length)
    {
        return Err(SnappyFailure::Decode(match codec {
            "MinLZ" => "MinLZ copy exceeds decoded length",
            _ => "Snappy copy exceeds decoded length",
        }));
    }
    for copied in 0..length {
        if copied.trailing_zeros() >= 12 {
            cancelled(cancellation)?;
        }
        let index = output
            .len()
            .checked_sub(offset)
            .ok_or(SnappyFailure::Decode("invalid back-reference offset"))?;
        let byte = *output
            .get(index)
            .ok_or(SnappyFailure::Decode("invalid back-reference offset"))?;
        output.push(byte);
    }
    Ok(())
}

fn append_exact(
    output: &mut Vec<u8>,
    bytes: &[u8],
    decoded_length: usize,
) -> Result<(), SnappyFailure> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|end| end > decoded_length)
    {
        return Err(SnappyFailure::Decode(
            "Snappy literal exceeds decoded length",
        ));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn append_exact_named(
    output: &mut Vec<u8>,
    bytes: &[u8],
    decoded_length: usize,
    codec: &'static str,
) -> Result<(), SnappyFailure> {
    if output
        .len()
        .checked_add(bytes.len())
        .is_none_or(|end| end > decoded_length)
    {
        return Err(SnappyFailure::Decode(match codec {
            "MinLZ" => "MinLZ literal exceeds decoded length",
            _ => "Snappy literal exceeds decoded length",
        }));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn copy_fallible(input: &[u8]) -> Result<Vec<u8>, SnappyFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| SnappyFailure::Limit)?;
    output.extend_from_slice(input);
    Ok(output)
}

fn append_fallible(output: &mut Vec<u8>, input: &[u8], limit: usize) -> Result<(), SnappyFailure> {
    if output
        .len()
        .checked_add(input.len())
        .is_none_or(|end| end > limit)
    {
        return Err(SnappyFailure::Limit);
    }
    output
        .try_reserve(input.len())
        .map_err(|_| SnappyFailure::Limit)?;
    output.extend_from_slice(input);
    Ok(())
}

fn cancelled(cancellation: &dyn Cancellation) -> Result<(), SnappyFailure> {
    if cancellation.is_cancelled() {
        Err(SnappyFailure::Cancelled)
    } else {
        Ok(())
    }
}

fn masked_crc32c(input: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let polynomial = 0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ polynomial;
        }
    }
    let crc = !crc;
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CancellationToken;

    fn chunk_length(length: usize) -> [u8; 3] {
        [
            u8::try_from(length & 0xff).expect("low chunk-length byte"),
            u8::try_from((length >> 8) & 0xff).expect("middle chunk-length byte"),
            u8::try_from((length >> 16) & 0xff).expect("high chunk-length byte"),
        ]
    }

    fn frame(magic: [u8; 6], decoded: &[u8], block: &[u8]) -> Vec<u8> {
        let mut result = vec![STREAM_IDENTIFIER, 6, 0, 0];
        result.extend_from_slice(&magic);
        let length = block.len() + 4;
        result.push(COMPRESSED_DATA);
        result.extend_from_slice(&chunk_length(length));
        result.extend_from_slice(&masked_crc32c(decoded).to_le_bytes());
        result.extend_from_slice(block);
        result
    }

    fn minlz_frame(chunk_type: u8, decoded: &[u8], block: &[u8]) -> Vec<u8> {
        let mut result = vec![STREAM_IDENTIFIER, 6, 0, 0];
        result.extend_from_slice(MINLZ_MAGIC);
        result.push(0);
        let decoded_length = u8::try_from(decoded.len()).expect("one-byte test length");
        let mut encoded = vec![decoded_length];
        encoded.extend_from_slice(block);
        let checksum_input = if chunk_type == 0x03 { block } else { decoded };
        let length = encoded.len() + 4;
        result.push(chunk_type);
        result.extend_from_slice(&chunk_length(length));
        result.extend_from_slice(&masked_crc32c(checksum_input).to_le_bytes());
        result.extend_from_slice(&encoded);
        result.extend_from_slice(&[0x20, 1, 0, 0, decoded_length]);
        result
    }

    #[test]
    fn decodes_standard_snappy_framing() {
        let input = frame(*SNAPPY_MAGIC, b"hello", b"\x05\x10hello");
        assert_eq!(
            decode_framed(&input, 32, &CancellationToken::new()).expect("valid frame"),
            b"hello"
        );
    }

    #[test]
    fn s2_repeat_offsets_are_not_accepted_as_standard_snappy() {
        let block = b"\x10\x0cabcd\x01\x04\x11\x00";
        let decoded = b"abcdabcdabcdabcd";
        let s2 = frame(*S2_MAGIC, decoded, block);
        assert_eq!(
            decode_framed(&s2, 32, &CancellationToken::new()).expect("valid S2 frame"),
            decoded
        );
        let snappy = frame(*SNAPPY_MAGIC, decoded, block);
        assert!(decode_framed(&snappy, 32, &CancellationToken::new()).is_err());
    }

    #[test]
    fn checksum_and_output_limits_fail_closed() {
        let mut input = frame(*SNAPPY_MAGIC, b"hello", b"\x05\x10hello");
        input[14] ^= 1;
        assert!(decode_framed(&input, 32, &CancellationToken::new()).is_err());
        let input = frame(*SNAPPY_MAGIC, b"hello", b"\x05\x10hello");
        assert!(matches!(
            decode_framed(&input, 4, &CancellationToken::new()),
            Err(SnappyFailure::Limit)
        ));
    }

    #[test]
    fn decodes_minlz_output_and_compressed_checksums() {
        for chunk_type in [0x02, 0x03] {
            let input = minlz_frame(chunk_type, b"xxxxx", b"\x00x\x1c");
            assert_eq!(
                decode_minlz_framed(&input, 32, &CancellationToken::new())
                    .expect("valid MinLZ frame"),
                b"xxxxx"
            );
        }
    }

    #[test]
    fn decodes_every_minlz_copy_form() {
        let cancellation = CancellationToken::new();
        assert_eq!(
            decode_minlz_block(b"\x00x\x1c", 5, &cancellation).expect("repeat block"),
            b"xxxxx"
        );
        assert_eq!(
            decode_minlz_block(b"\x18abcd\xc1\x00", 8, &cancellation).expect("copy1 block"),
            b"abcdabcd"
        );

        let mut copy2 = vec![0xe8, 34];
        copy2.extend_from_slice(&[b'a'; 64]);
        copy2.extend_from_slice(&[0x02, 0, 0]);
        assert_eq!(
            decode_minlz_block(&copy2, 68, &cancellation).expect("copy2 block"),
            vec![b'a'; 68]
        );

        let mut fused = vec![0xe8, 34];
        fused.extend_from_slice(&[b'a'; 64]);
        fused.extend_from_slice(&[0x03, 0, 0, b'X']);
        let mut fused_expected = vec![b'a'; 64];
        fused_expected.push(b'X');
        fused_expected.extend_from_slice(&[b'a'; 4]);
        assert_eq!(
            decode_minlz_block(&fused, 69, &cancellation).expect("fused copy2 block"),
            fused_expected
        );

        let mut copy3 = vec![0xf8, 0xe2, 0xff, 0x00];
        copy3.extend_from_slice(&vec![b'a'; 65_536]);
        copy3.extend_from_slice(&[0x07, 0, 0, 0]);
        assert_eq!(
            decode_minlz_block(&copy3, 65_540, &cancellation).expect("copy3 block"),
            vec![b'a'; 65_540]
        );
    }

    #[test]
    fn minlz_requires_valid_checksum_eof_and_limits() {
        let mut input = minlz_frame(0x02, b"xxxxx", b"\x00x\x1c");
        input[14] ^= 1;
        assert!(decode_minlz_framed(&input, 32, &CancellationToken::new()).is_err());

        let mut input = minlz_frame(0x02, b"xxxxx", b"\x00x\x1c");
        input.truncate(input.len() - 5);
        assert!(decode_minlz_framed(&input, 32, &CancellationToken::new()).is_err());

        let input = minlz_frame(0x02, b"xxxxx", b"\x00x\x1c");
        assert!(matches!(
            decode_minlz_framed(&input, 4, &CancellationToken::new()),
            Err(SnappyFailure::Limit)
        ));
    }
}
