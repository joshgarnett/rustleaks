//! Counts ordinary cl100k tokens only for the complete Vercel ASCII capture
//! domain. Generated data retains source merge ranks. See data/README.md.
//! Algorithm behavior follows the MIT-licensed tiktoken and tiktoken-rs
//! projects. See data/LICENSE.tiktoken and data/LICENSE.tiktoken-rs for
//! attribution.

#![forbid(unsafe_code)]

use std::cmp::Ordering;

const ENTRY_COUNT: usize = 34_471;
const POOL_BYTES: usize = 194_315;
const HEADER_BYTES: usize = 16;
const RANK_START: usize = HEADER_BYTES + 4 * (ENTRY_COUNT + 1);
const POOL_START: usize = RANK_START + 4 * ENTRY_COUNT;
const NONE: u32 = u32::MAX;
static TABLE: &[u8; POOL_START + POOL_BYTES] =
    include_bytes!("../../../data/cl100k-vercel60-v1.bin");

fn table_u32(offset: usize) -> u32 {
    u32::from_le_bytes([
        TABLE[offset],
        TABLE[offset + 1],
        TABLE[offset + 2],
        TABLE[offset + 3],
    ])
}

fn rank(piece: &[u8]) -> u32 {
    if piece.len() > 48 {
        return NONE;
    }
    let mut low = 0;
    let mut high = ENTRY_COUNT;
    while low < high {
        let middle = low + (high - low) / 2;
        let start = table_u32(HEADER_BYTES + middle * 4) as usize;
        let end = table_u32(HEADER_BYTES + (middle + 1) * 4) as usize;
        match TABLE[POOL_START + start..POOL_START + end].cmp(piece) {
            Ordering::Less => low = middle + 1,
            Ordering::Greater => high = middle,
            Ordering::Equal => return table_u32(RANK_START + middle * 4),
        }
    }
    NONE
}

fn punctuation(byte: u8) -> bool {
    matches!(byte, b'_' | b'-')
}

fn piece_end(secret: &[u8], start: usize) -> usize {
    let mut end = start;
    if secret[start].is_ascii_alphabetic()
        || (punctuation(secret[start])
            && secret.get(start + 1).is_some_and(u8::is_ascii_alphabetic))
    {
        if punctuation(secret[start]) {
            end += 1;
        }
        while end < secret.len() && secret[end].is_ascii_alphabetic() {
            end += 1;
        }
    } else if secret[start].is_ascii_digit() {
        while end < secret.len() && end - start < 3 && secret[end].is_ascii_digit() {
            end += 1;
        }
    } else {
        // Domain validation establishes that the remaining bytes are '-' or '_'.
        // Consume the whole punctuation run. Do not attach its final byte to
        // a following letter run: the original possessive alternative does not.
        while end < secret.len() && punctuation(secret[end]) {
            end += 1;
        }
    }
    end
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "validated pieces are at most 57 bytes"
)]
fn piece_token_count<E>(
    piece: &[u8],
    work: &mut impl FnMut() -> Result<(), E>,
) -> Result<usize, E> {
    if piece.len() == 1 || piece[0].is_ascii_digit() || rank(piece) != NONE {
        // Generator exhaustively verifies all 1..3-digit strings are whole
        // vocabulary tokens. Their ranks do not enter a merge comparison.
        return Ok(1);
    }
    // Only this stack scratch is retained. All candidate pieces are <=57 bytes;
    // capacity 60 follows the capture bound and makes the local invariant clear.
    let mut offsets = [0_u8; 61];
    let mut ranks = [NONE; 60];
    let mut count = piece.len();
    for (offset, slot) in offsets.iter_mut().enumerate().take(count + 1) {
        *slot = offset as u8;
    }
    for (index, slot) in ranks.iter_mut().enumerate().take(count - 1) {
        *slot = rank(&piece[index..index + 2]);
    }
    loop {
        work()?;
        let mut best_rank = NONE;
        let mut best_index = 0;
        for (index, &candidate_rank) in ranks.iter().enumerate().take(count - 1) {
            // Strict comparison preserves the earliest position for equal ranks.
            if candidate_rank < best_rank {
                best_rank = candidate_rank;
                best_index = index;
            }
        }
        if best_rank == NONE {
            return Ok(count);
        }
        let index = best_index;
        // Only the neighboring candidate pairs change. Compute them while all
        // old boundaries still exist, then remove the interior merge boundary.
        if index > 0 {
            ranks[index - 1] =
                rank(&piece[usize::from(offsets[index - 1])..usize::from(offsets[index + 2])]);
        }
        ranks[index] = if index + 2 < count {
            rank(&piece[usize::from(offsets[index])..usize::from(offsets[index + 3])])
        } else {
            NONE
        };
        for next in index + 1..count {
            offsets[next] = offsets[next + 1];
            ranks[next] = if next + 1 < count {
                ranks[next + 1]
            } else {
                NONE
            };
        }
        count -= 1;
        ranks[count] = NONE;
    }
}

/// None means out of this versioned predicate's exact domain.
/// The source rule's entropy and all other filtering remain separate.
pub(crate) fn token_count<E>(
    secret: &[u8],
    work: &mut impl FnMut() -> Result<(), E>,
) -> Result<Option<usize>, E> {
    work()?;
    if secret.len() != 60
        || !secret[..4].eq_ignore_ascii_case(b"vck_")
        || !secret[4..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation(*byte))
    {
        return Ok(None);
    }
    let mut position = 0;
    let mut tokens = 0;
    while position < secret.len() {
        work()?;
        let end = piece_end(secret, position);
        tokens += piece_token_count(&secret[position..end], work)?;
        position = end;
    }
    Ok(Some(tokens))
}

/// Exactly the source token-ratio component for this fixed 60-byte domain.
pub(crate) fn accepts<E>(
    secret: &[u8],
    work: &mut impl FnMut() -> Result<(), E>,
) -> Result<bool, E> {
    Ok(token_count(secret, work)?.is_some_and(|tokens| tokens > 24))
}

#[cfg(test)]
mod tests;
