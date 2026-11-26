//! Byte scanner for the decoder's candidate pattern (`ENCODINGS_PATTERN` in
//! the tests).
//!
//! The pattern has four alternatives, tried in order at each start:
//!
//! 1. percent: `%[0-9A-Fa-f]{2}(?:.*%[0-9A-Fa-f]{2})?`
//! 2. unicode: `(?:U\+[a-fA-F0-9]{4}(?:\s|$))+` or, ignoring case,
//!    `(?:\\{1,2}u[a-fA-F0-9]{4})+`
//! 3. hex: `[0-9A-Fa-f]{32,}`
//! 4. base64: `[\w\/+-]{16,}={0,2}`
//!
//! Go `\s` is `[\t\n\f\r ]` and `\w` is `[0-9A-Za-z_]`, and `(?i)` adds no
//! non-ASCII form of `u` or of a hex digit. So every class is ASCII, and the
//! only non-ASCII input that matters is what `.` crosses. `.` matches any
//! character except `\n`, including the U+FFFD that stands for an invalid
//! byte. The scanner therefore reads the raw bytes and returns the same byte
//! offsets as a leftmost-first search over the normalized haystack.
//!
//! A search returns the leftmost start, and at that start the first
//! alternative that matches, with the extent its greedy repetitions give.
//! Every alternative is non-empty, so the next search starts at the match
//! end. No alternative can start at a byte other than `%`, `\` or a base64
//! class byte (which includes `U` and every hex digit).
//!
//! [`Scanner`] tests blocks of bytes for places where a match can start.
//! The test `scanner_matches_the_encoding_regex` compares it with the regex
//! on generated inputs, and the `scanner_matches_the_reference` tests compare
//! it with a scanner that reads every candidate byte.

use crate::regex::ByteSpan;

const HEX_MINIMUM: usize = 32;
const BASE64_MINIMUM: usize = 16;

/// Returns `keep(span)` for every match, in order. `admit` runs before each
/// match is kept and stops the scan with its error.
pub(super) fn find_encodings<T, E>(
    data: &[u8],
    mut admit: impl FnMut() -> Result<(), E>,
    mut keep: impl FnMut(ByteSpan) -> T,
) -> Result<Vec<T>, E> {
    let mut kept = Vec::new();
    let mut scanner = Scanner::new(data);
    let mut position = 0;
    while position < data.len() {
        let Some((start, end)) = scanner.next_match(position) else {
            break;
        };
        admit()?;
        kept.push(keep(ByteSpan { start, end }));
        position = end;
    }
    Ok(kept)
}

/// A base64 class byte, which includes `U` and every hex digit.
const BASE64: u8 = 1;
/// `%` or `\`, the only other bytes that can start a match.
const OTHER_START: u8 = 2;
/// A hex digit.
const HEX: u8 = 4;
/// `U`, which can start `U+hhhh`.
const UPPER_U: u8 = 8;
/// The kind of each byte.
static KINDS: [u8; 256] = kinds();

const fn kinds() -> [u8; 256] {
    let mut kinds = [0; 256];
    let mut index = 0;
    while index < 256 {
        #[allow(clippy::cast_possible_truncation)] // `index` is below 256.
        let byte = index as u8;
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'+' | b'-') {
            kinds[index] = BASE64;
            if byte.is_ascii_hexdigit() {
                kinds[index] |= HEX;
            }
            if byte == b'U' {
                kinds[index] |= UPPER_U;
            }
        } else if matches!(byte, b'%' | b'\\') {
            kinds[index] = OTHER_START;
        }
        index += 1;
    }
    kinds
}

fn kind(byte: u8) -> u8 {
    KINDS[usize::from(byte)]
}

fn is_base64(byte: u8) -> bool {
    kind(byte) & BASE64 != 0
}

/// Finds matches by testing blocks of bytes, not one byte at a time.
///
/// A match starts at a marker or at the start of a long run, which is a run
/// of at least [`BASE64_MINIMUM`] base64 class bytes. A marker is a `%`
/// before two hex digits, a `\` that starts escaped unicode, or a `U` that
/// starts `U+hhhh`. A run counts from the search start, as the regex search
/// counts it, so a run that began before the search start counts from it.
///
/// A search finds the first long run, then the first marker before it. A
/// marker inside the run never decides the result, because the run starts
/// first. A `U` marker at the run start gives the same match either way,
/// because the run tries `U+hhhh` first.
struct Scanner<'a> {
    data: &'a [u8],
    /// The first long run start at or after every search start so far:
    /// `None` before the first search, and `Some(None)` when no long run
    /// remains.
    long_run: Option<Option<usize>>,
}

impl<'a> Scanner<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            long_run: None,
        }
    }

    /// Returns the leftmost match that starts at or after `from`. Each
    /// `from` must be at least the one before it.
    fn next_match(&mut self, from: usize) -> Option<(usize, usize)> {
        let data = self.data;
        // When no long run starts in `earlier..run`, none starts in
        // `from..run` for a `from` in that range, so the run found for an
        // earlier start still holds. When no long run remains for an earlier
        // start, none remains for a later one.
        let long_run = match self.long_run {
            Some(Some(run)) if run >= from => Some(run),
            Some(None) => None,
            _ => {
                let run = long_run_start(data, from);
                self.long_run = Some(run);
                run
            }
        };
        let limit = long_run.unwrap_or(data.len());
        if let Some(start) = next_marker(data, from, limit) {
            let end = match data[start] {
                b'%' => percent_at(data, start),
                b'\\' => escaped_unicode_at(data, start),
                _ => plus_unicode_at(data, start),
            };
            return end.map(|end| (start, end));
        }
        let start = long_run?;
        Some((start, long_run_end(data, start)))
    }
}

/// Returns the first marker in `from..limit`.
fn next_marker(data: &[u8], from: usize, limit: usize) -> Option<usize> {
    let mut index = from;
    loop {
        index = next_marker_pair(data, index, limit)?;
        let starts = match data[index] {
            b'%' => hex_pair_at(data, index + 1),
            b'\\' => escaped_unicode_at(data, index).is_some(),
            _ => plus_unicode_at(data, index).is_some(),
        };
        if starts {
            return Some(index);
        }
        index += 1;
    }
}

/// Whether `first` and the byte after it, `second` (0 at the end), can begin
/// a marker: `%` and a hex digit, `\` and `\` or `u` in either case, or
/// `U+`. Every marker begins this way. The test has no branches, so a loop
/// over blocks of bytes can compile to vector instructions.
fn begins_marker(first: u8, second: u8) -> bool {
    let second_hex = (second.wrapping_sub(b'0') < 10) | ((second | 0x20).wrapping_sub(b'a') < 6);
    let percent = (first == b'%') & second_hex;
    let escape = (first == b'\\') & ((second == b'\\') | ((second | 0x20) == b'u'));
    let plus = (first == b'U') & (second == b'+');
    percent | escape | plus
}

/// Returns the first index in `from..limit` where [`begins_marker`] holds.
fn next_marker_pair(data: &[u8], from: usize, limit: usize) -> Option<usize> {
    const BLOCK: usize = 16;
    let mut offset = from;
    // Each block reads one byte past its end, for the second byte of its
    // last pair.
    while offset + BLOCK <= limit
        && let Some(window) = data.get(offset..=offset + BLOCK)
    {
        let mut any = false;
        for pair in window.windows(2) {
            any |= begins_marker(pair[0], pair[1]);
        }
        if any {
            return window
                .windows(2)
                .position(|pair| begins_marker(pair[0], pair[1]))
                .map(|index| offset + index);
        }
        offset += BLOCK;
    }
    (offset..limit)
        .find(|&index| begins_marker(data[index], data.get(index + 1).copied().unwrap_or(0)))
}

/// The bytes that [`long_run_start`] classifies at a time.
const RUN_BLOCK: usize = 64;
/// The block offsets at which a long run is seen whole within the block.
const RUN_STARTS: usize = RUN_BLOCK - BASE64_MINIMUM + 1;

/// Returns the first long run start at or after `from`. A run that started
/// before `from` counts from `from`.
///
/// The search classifies a block of bytes at a time into a bit mask and finds
/// the first offset where [`BASE64_MINIMUM`] bits in a row are set. Only the
/// first [`RUN_STARTS`] offsets are seen whole, so the next block starts at
/// the next offset that is not seen whole, or after the last byte of the
/// block that is not of the class when that is later. No run that starts
/// between the two is long enough, since it would reach that byte.
///
/// The first offset found starts a run. If the byte before it, at or after
/// `from`, were of the class, the run would also be long from that byte, and
/// that byte was seen whole in this block or in an earlier one.
fn long_run_start(data: &[u8], from: usize) -> Option<usize> {
    let mut offset = from;
    loop {
        let rest = data.get(offset..)?;
        if rest.len() < BASE64_MINIMUM {
            return None;
        }
        let block = &rest[..rest.len().min(RUN_BLOCK)];
        let class = match <&[u8; RUN_BLOCK]>::try_from(block) {
            Ok(block) => base64_mask(block),
            Err(_) => block.iter().enumerate().fold(0, |mask, (index, byte)| {
                mask | (u64::from(is_base64(*byte)) << index)
            }),
        };
        // Bit `i` of `long` is set when bits `i..i + 16` of `class` are.
        let mut long = class;
        for shift in [1, 2, 4, 8] {
            long &= long >> shift;
        }
        let starts = long & ((1 << RUN_STARTS) - 1);
        if starts != 0 {
            return Some(offset + starts.trailing_zeros() as usize);
        }
        if block.len() < RUN_BLOCK {
            return None;
        }
        // A full block with no long run has a byte that is not of the class.
        let last_other = (RUN_BLOCK - 1) - (!class).leading_zeros() as usize;
        offset += RUN_STARTS.max(last_other + 1);
    }
}

/// Whether `byte` is of the base64 class, with no branches or table, so a
/// loop over a block can compile to vector instructions.
fn is_base64_lane(byte: u8) -> bool {
    (byte.wrapping_sub(b'0') < 10)
        | ((byte | 0x20).wrapping_sub(b'a') < 26)
        | (byte == b'_')
        | (byte == b'+')
        | (byte == b'-')
        | (byte == b'/')
}

/// Returns a mask with bit `i` set when `block[i]` is of the base64 class.
fn base64_mask(block: &[u8; RUN_BLOCK]) -> u64 {
    let mut flags = [0u8; RUN_BLOCK];
    for (flag, byte) in flags.iter_mut().zip(block) {
        *flag = u8::from(is_base64_lane(*byte));
    }
    // Multiplying eight bytes that are each 0 or 1 by this constant moves
    // byte `k` to bit `56 + k`, with no carries.
    let mut mask = 0;
    for (index, group) in flags.chunks_exact(8).enumerate() {
        let group = u64::from_le_bytes(group.try_into().unwrap());
        mask |= (group.wrapping_mul(0x0102_0408_1020_4080) >> 56) << (8 * index);
    }
    mask
}

/// Returns the end of the match at `start`, where a long run starts.
/// `U+hhhh` is tried first, then hex, then base64.
fn long_run_end(data: &[u8], start: usize) -> usize {
    if data[start] == b'U'
        && let Some(end) = plus_unicode_at(data, start)
    {
        return end;
    }
    let run_end = run_end(data, start);
    let hex_end = start
        + data[start..run_end]
            .iter()
            .position(|byte| kind(*byte) & HEX == 0)
            .unwrap_or(run_end - start);
    if hex_end - start >= HEX_MINIMUM {
        return hex_end;
    }
    let padding = data[run_end..]
        .iter()
        .take(2)
        .take_while(|byte| **byte == b'=')
        .count();
    run_end + padding
}

/// Returns the first index at or after `from` of a byte that is not of the
/// base64 class, or the input length.
fn run_end(data: &[u8], from: usize) -> usize {
    let mut offset = from;
    while let Some(block) = data.get(offset..offset + RUN_BLOCK) {
        let class = base64_mask(block.try_into().unwrap());
        if class != u64::MAX {
            return offset + class.trailing_ones() as usize;
        }
        offset += RUN_BLOCK;
    }
    let rest = &data[offset..];
    offset
        + rest
            .iter()
            .position(|byte| !is_base64(*byte))
            .unwrap_or(rest.len())
}

// The bytes of Go regexp `\s`: tab, LF, FF, CR and space.
fn is_go_regex_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn hex_pair_at(data: &[u8], index: usize) -> bool {
    data.get(index..index + 2)
        .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
}

fn hex_quad_at(data: &[u8], index: usize) -> bool {
    data.get(index..index + 4)
        .is_some_and(|quad| quad.iter().all(u8::is_ascii_hexdigit))
}

/// `%hh`, then greedily the last `%hh` on the same line, if any.
fn percent_at(data: &[u8], start: usize) -> Option<usize> {
    if !hex_pair_at(data, start + 1) {
        return None;
    }
    let first_end = start + 3;
    let line_end =
        memchr::memchr(b'\n', &data[first_end..]).map_or(data.len(), |offset| first_end + offset);
    // `.*` is greedy, so the optional group takes the last `%hh` that ends
    // before the newline.
    let limit = line_end.saturating_sub(2).max(first_end);
    let last = memchr::memrchr_iter(b'%', &data[first_end..limit])
        .map(|offset| first_end + offset)
        .find(|&index| hex_pair_at(data, index + 1));
    Some(last.map_or(first_end, |index| index + 3))
}

/// `(?:U\+hhhh(?:\s|$))+`: one or more groups, each ending in one Go space
/// or at the end of the input.
fn plus_unicode_at(data: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    loop {
        let group = data.get(end..end + 2) == Some(b"U+") && hex_quad_at(data, end + 2);
        if !group {
            break;
        }
        let after = end + 6;
        if after == data.len() {
            end = after;
            break;
        }
        if !is_go_regex_space(data[after]) {
            break;
        }
        end = after + 1;
    }
    (end > start).then_some(end)
}

/// `(?i)(?:\\{1,2}u[a-fA-F0-9]{4})+`. Two backslashes are tried before one.
fn escaped_unicode_at(data: &[u8], start: usize) -> Option<usize> {
    let mut end = start;
    loop {
        let unit = |slashes: usize| {
            data.get(end..end + slashes)
                .is_some_and(|run| run.iter().all(|byte| *byte == b'\\'))
                && data
                    .get(end + slashes)
                    .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'u'))
                && hex_quad_at(data, end + slashes + 1)
        };
        if unit(2) {
            end += 7;
        } else if unit(1) {
            end += 6;
        } else {
            break;
        }
    }
    (end > start).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regex::{GoRegex, NormalizedHaystack};

    fn regex_spans(regex: &GoRegex, data: &[u8]) -> Vec<(usize, usize)> {
        regex
            .find_all_normalized(&NormalizedHaystack::new(data), None)
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect()
    }

    fn scanner_spans(data: &[u8]) -> Vec<(usize, usize)> {
        find_encodings(data, || Ok::<(), ()>(()), |span| span)
            .unwrap()
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect()
    }

    /// A small deterministic generator, so failures reproduce.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next()).unwrap() % bound
        }
    }

    /// The scanner that reads every candidate byte, kept to check
    /// [`Scanner`]. It returns the leftmost match that starts at or after
    /// `from`.
    fn reference_next_match(data: &[u8], from: usize) -> Option<(usize, usize)> {
        let mut index = from;
        loop {
            // Bytes of no kind start nothing.
            index += data
                .get(index..)?
                .iter()
                .position(|byte| kind(*byte) != 0)?;
            let byte = data[index];
            if kind(byte) & BASE64 != 0 {
                // One read of the run finds its end, the end of its leading
                // hex digits and its first `U`.
                let run = &data[index..];
                let run_len = run
                    .iter()
                    .position(|byte| kind(*byte) & BASE64 == 0)
                    .unwrap_or(run.len());
                let run = &run[..run_len];
                let run_end = index + run_len;
                if run_end - index >= BASE64_MINIMUM {
                    // Base64 matches at the run start, so the match starts
                    // there. `U+hhhh` is tried first, then hex, then base64.
                    if byte == b'U'
                        && let Some(end) = plus_unicode_at(data, index)
                    {
                        return Some((index, end));
                    }
                    let hex_end = index
                        + run
                            .iter()
                            .position(|byte| kind(*byte) & HEX == 0)
                            .unwrap_or(run_len);
                    if hex_end - index >= HEX_MINIMUM {
                        return Some((index, hex_end));
                    }
                    let padding = data[run_end..]
                        .iter()
                        .take(2)
                        .take_while(|byte| **byte == b'=')
                        .count();
                    return Some((index, run_end + padding));
                }
                // Fewer than 16 run bytes remain from any start in this run,
                // so only `U+hhhh` can start a match here.
                if let Some(offset) = memchr::memchr(b'U', run) {
                    let mut start = index + offset;
                    while let Some(offset) = memchr::memchr(b'U', &data[start..run_end]) {
                        start += offset;
                        if let Some(end) = plus_unicode_at(data, start) {
                            return Some((start, end));
                        }
                        start += 1;
                    }
                }
                index = run_end;
            } else {
                let end = if byte == b'%' {
                    percent_at(data, index)
                } else {
                    escaped_unicode_at(data, index)
                };
                if let Some(end) = end {
                    return Some((index, end));
                }
                index += 1;
            }
        }
    }

    fn reference_spans(data: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut position = 0;
        while position < data.len() {
            let Some((start, end)) = reference_next_match(data, position) else {
                break;
            };
            spans.push((start, end));
            position = end;
        }
        spans
    }

    /// Compares the scanner with the reference on the whole input, and from
    /// starts `step` apart, since a search can start inside a run. Short
    /// inputs are also searched from every start.
    fn assert_matches_reference(data: &[u8], step: usize) {
        assert_eq!(
            scanner_spans(data),
            reference_spans(data),
            "{:?}",
            String::from_utf8_lossy(data)
        );
        let every_start = if data.len() <= 512 { 1 } else { step };
        for step in [every_start, step.max(1)] {
            let mut scanner = Scanner::new(data);
            for from in (0..=data.len()).step_by(step) {
                assert_eq!(
                    scanner.next_match(from),
                    reference_next_match(data, from),
                    "from {from} in {:?}",
                    String::from_utf8_lossy(data)
                );
            }
        }
    }

    /// Bytes from every class: hex digits, other base64 bytes, padding,
    /// markers, `u`, Go spaces, a vertical tab, a newline, an invalid byte
    /// and the bytes of a multi-byte rune.
    const ALPHABET: &[u8] = b"0123456789abcdefABCDEFgzGZuU_/+-=%\\ \t\n\x0b\x0c\r.;\"\xff\xc3\xa9";

    /// A mix of pieces that reach every branch, runs of lengths around the
    /// minimums, and plain text.
    fn generated_input(random: &mut Lcg, pieces: usize) -> Vec<u8> {
        const BASE64_BYTES: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/+-";
        const HEX_BYTES: &[u8] = b"0123456789abcdefABCDEF";
        let mut data = Vec::new();
        for _ in 0..pieces {
            match random.below(12) {
                0 => {
                    let len = BASE64_MINIMUM - 3 + random.below(7);
                    data.extend((0..len).map(|_| BASE64_BYTES[random.below(BASE64_BYTES.len())]));
                }
                1 => {
                    let len = HEX_MINIMUM - 3 + random.below(7);
                    data.extend((0..len).map(|_| HEX_BYTES[random.below(HEX_BYTES.len())]));
                }
                2 => data.extend_from_slice(
                    [b"%41".as_slice(), b"%4", b"%", b"%zz", b"%0a%0A"][random.below(5)],
                ),
                3 => data.extend_from_slice(
                    [
                        b"U+00e9 ".as_slice(),
                        b"U+00E9",
                        b"U+00e",
                        b"U+",
                        b"U+0041\nU+0042\t",
                        b"XU+0041 ",
                    ][random.below(6)],
                ),
                4 => data.extend_from_slice(
                    [
                        b"\\u0041".as_slice(),
                        b"\\\\U00e9",
                        b"\\\\\\u0041",
                        b"\\u004",
                        b"\\n",
                        b"\\",
                    ][random.below(6)],
                ),
                5 => data.extend_from_slice([b"=".as_slice(), b"==", b"==="][random.below(3)]),
                6 => data.extend_from_slice(
                    [b"int x = y + 1;\n".as_slice(), b"word ", b"a_b-c/d "][random.below(3)],
                ),
                7 => {
                    data.extend_from_slice(["\u{e9}".as_bytes(), b"\xff", b"\xc3"][random.below(3)])
                }
                _ => data.push(ALPHABET[random.below(ALPHABET.len())]),
            }
        }
        data
    }

    #[test]
    fn block_classes_match_the_byte_table() {
        for byte in 0..=u8::MAX {
            assert_eq!(is_base64_lane(byte), is_base64(byte), "{byte:#04x}");
        }
        let mut random = Lcg(0xb10c);
        for round in 0..2_000 {
            let block: [u8; RUN_BLOCK] = std::array::from_fn(|_| {
                if round % 2 == 0 {
                    u8::try_from(random.below(256)).unwrap()
                } else {
                    ALPHABET[random.below(ALPHABET.len())]
                }
            });
            let expected = block
                .iter()
                .enumerate()
                .filter(|(_, byte)| is_base64(**byte))
                .fold(0u64, |mask, (index, _)| mask | (1 << index));
            assert_eq!(base64_mask(&block), expected, "{block:?}");
        }
    }

    #[test]
    fn scanner_matches_the_reference_on_generated_inputs() {
        let mut random = Lcg(0xdec0de);
        let mut compared = 0;
        for _ in 0..5_000 {
            let len = random.below(200);
            let data = (0..len)
                .map(|_| u8::try_from(random.below(256)).unwrap())
                .collect::<Vec<_>>();
            assert_matches_reference(&data, 7);
            compared += 1;
        }
        for _ in 0..10_000 {
            let len = random.below(120);
            let data = (0..len)
                .map(|_| ALPHABET[random.below(ALPHABET.len())])
                .collect::<Vec<_>>();
            assert_matches_reference(&data, 5);
            compared += 1;
        }
        for _ in 0..10_000 {
            let pieces = random.below(30);
            assert_matches_reference(&generated_input(&mut random, pieces), 3);
            compared += 1;
        }
        // Larger inputs cross many search blocks and windows.
        for _ in 0..300 {
            let pieces = random.below(600);
            let data = generated_input(&mut random, pieces);
            assert_matches_reference(&data, 1 + data.len() / 100);
            compared += 1;
        }
        assert_eq!(compared, 25_300);
    }

    #[test]
    fn scanner_matches_the_reference_at_boundaries() {
        let tails: [&[u8]; 12] = [
            b"%41",
            b"%4",
            b"U+0041",
            b"U+0041 ",
            b"\\u0041",
            b"\\\\u0041",
            b"0123456789abcdef",
            b"0123456789abcde",
            b"0123456789abcdef0123456789abcdef",
            b"0123456789abcdef0123456789abcde",
            b"abcdefghijklmnop==",
            b"",
        ];
        let fillers: [&[u8]; 4] = [b" ", b"a", b"a ", b"\xff"];
        for tail in tails {
            for filler in fillers {
                for repeat in 0..70 {
                    let mut data = filler.repeat(repeat);
                    data.extend_from_slice(tail);
                    assert_matches_reference(&data, 1);
                    data.extend_from_slice(b" ");
                    data.extend_from_slice(&filler.repeat(repeat));
                    assert_matches_reference(&data, 1);
                }
            }
        }
        // Runs of every length near the minimums, alone and before a marker.
        for len in 0..40 {
            for byte in [b'a', b'g', b'U', b'+'] {
                let run = vec![byte; len];
                assert_matches_reference(&run, 1);
                for marker in [b"U+0041 ".as_slice(), b"%41", b"=="] {
                    let mut data = run.clone();
                    data.extend_from_slice(marker);
                    assert_matches_reference(&data, 1);
                }
            }
        }
    }

    /// Every string in the decoder and detect corpora, and the bytes of
    /// every base64 field, are scanned by both scanners.
    #[test]
    fn scanner_matches_the_reference_on_the_corpora() {
        use base64::Engine as _;

        fn visit(value: &serde_json::Value, key: &str, inputs: &mut usize) {
            match value {
                serde_json::Value::String(text) => {
                    assert_matches_reference(text.as_bytes(), 1 + text.len() / 64);
                    *inputs += 1;
                    if key.ends_with("base64")
                        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text)
                    {
                        assert_matches_reference(&bytes, 1 + bytes.len() / 64);
                        *inputs += 1;
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        visit(item, key, inputs);
                    }
                }
                serde_json::Value::Object(fields) => {
                    for (key, field) in fields {
                        visit(field, key, inputs);
                    }
                }
                _ => {}
            }
        }

        let corpora = [
            include_str!("../../../../testdata/decoder-corpus/requests-v1.jsonl"),
            include_str!("../../../../testdata/decoder-corpus/outcomes-v1.jsonl"),
            include_str!("../../../../testdata/detect-corpus/requests-v1.jsonl"),
        ];
        let mut inputs = 0;
        for corpus in corpora {
            for line in corpus.lines() {
                let value = serde_json::from_str::<serde_json::Value>(line).unwrap();
                visit(&value, "", &mut inputs);
            }
        }
        assert!(inputs > 10_000, "{inputs}");
    }

    #[test]
    fn scanner_matches_the_encoding_regex() {
        let regex = GoRegex::compile(super::super::ENCODINGS_PATTERN).unwrap();
        // Pieces that reach every branch and boundary: hex digits, base64
        // bytes, `U+`, backslashes, `%`, padding, Go spaces, a vertical tab
        // (not a Go space), newlines, invalid bytes and a multi-byte rune.
        let pieces: [&[u8]; 24] = [
            b"0",
            b"9",
            b"a",
            b"F",
            b"g",
            b"Z",
            b"_",
            b"/",
            b"+",
            b"-",
            b"=",
            b"%",
            b"%4",
            b"%41",
            b"U",
            b"U+",
            b"U+00e9",
            b"u",
            b"\\",
            b"\\\\u0041",
            b" ",
            b"\n",
            b"\x0b",
            b"\xff",
        ];
        let runs: [&[u8]; 4] = [
            b"0123456789abcdef0123456789ABCDEF",
            b"abcdefghijklmnop",
            b"0123456789abcde",
            "\u{e9}".as_bytes(),
        ];
        let mut random = Lcg(0x5eed);
        let mut compared = 0;
        for _ in 0..40_000 {
            let mut data = Vec::new();
            for _ in 0..random.below(24) {
                if random.below(6) == 0 {
                    let run = runs[random.below(runs.len())];
                    data.extend_from_slice(&run[..random.below(run.len()) + 1]);
                } else {
                    data.extend_from_slice(pieces[random.below(pieces.len())]);
                }
            }
            assert_eq!(
                scanner_spans(&data),
                regex_spans(&regex, &data),
                "{:?}",
                String::from_utf8_lossy(&data)
            );
            compared += 1;
        }
        assert_eq!(compared, 40_000);
        for data in [
            b"".as_slice(),
            b"%41 text %42\n%43",
            b"U+0041 U+0042\tU+0043",
            b"U+0041",
            b"U+0041x",
            b"\\\\\\u0041\\U0042",
            b"0123456789abcdef0123456789abcdefXYZ0123456789abcdef==",
            b"0123456789abcdef0123456789abcde=",
            b"aaaaaaaaaaaaaaaU+0041 ",
            b"id c2VjcmV0LXZhbHVlLWhlcmU=;",
        ] {
            assert_eq!(scanner_spans(data), regex_spans(&regex, data), "{data:?}");
        }
    }

    #[test]
    fn admit_runs_before_each_match_and_can_stop_the_scan() {
        let mut admitted = 0;
        let result = find_encodings(
            b"%41 %42\nabcdefghijklmnopq",
            || {
                if admitted == 1 {
                    return Err(());
                }
                admitted += 1;
                Ok(())
            },
            |span| span,
        );
        assert!(result.is_err());
        assert_eq!(admitted, 1);
    }
}
