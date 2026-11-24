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
//! The test `scanner_matches_the_encoding_regex` compares this scanner with
//! the regex on generated inputs.

use crate::regex::ByteSpan;

const HEX_MINIMUM: usize = 32;
const BASE64_MINIMUM: usize = 16;

/// Returns every match in order. `admit` runs before each match is kept and
/// stops the scan with its error.
pub(super) fn find_encodings<E>(
    data: &[u8],
    mut admit: impl FnMut() -> Result<(), E>,
) -> Result<Vec<ByteSpan>, E> {
    let mut spans = Vec::new();
    let mut position = 0;
    while position < data.len() {
        let Some((start, end)) = next_match(data, position) else {
            break;
        };
        admit()?;
        spans.push(ByteSpan { start, end });
        position = end;
    }
    Ok(spans)
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

/// Returns the leftmost match that starts at or after `from`.
fn next_match(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut index = from;
    loop {
        // Bytes of no kind start nothing.
        index += data
            .get(index..)?
            .iter()
            .position(|byte| kind(*byte) != 0)?;
        let byte = data[index];
        if kind(byte) & BASE64 != 0 {
            // One read of the run finds its end, the end of its leading hex
            // digits and its first `U`.
            let run = &data[index..];
            let run_len = run
                .iter()
                .position(|byte| kind(*byte) & BASE64 == 0)
                .unwrap_or(run.len());
            let run = &run[..run_len];
            let run_end = index + run_len;
            if run_end - index >= BASE64_MINIMUM {
                // Base64 matches at the run start, so the match starts there.
                // `U+hhhh` is tried first, then hex, then base64.
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
            // Fewer than 16 run bytes remain from any start in this run, so
            // only `U+hhhh` can start a match here.
            if let Some(offset) = run.iter().position(|byte| *byte == b'U') {
                let mut start = index + offset;
                while let Some(offset) = data[start..run_end].iter().position(|byte| *byte == b'U')
                {
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
    let line_end = data[first_end..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(data.len(), |offset| first_end + offset);
    // `.*` is greedy, so the optional group takes the last `%hh` that ends
    // before the newline.
    let last = (first_end..line_end.saturating_sub(2))
        .rev()
        .find(|&index| data[index] == b'%' && hex_pair_at(data, index + 1));
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
            .find_all_normalized(&NormalizedHaystack::new(data))
            .into_iter()
            .map(|span| (span.start, span.end))
            .collect()
    }

    fn scanner_spans(data: &[u8]) -> Vec<(usize, usize)> {
        find_encodings(data, || Ok::<(), ()>(()))
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
        let result = find_encodings(b"%41 %42\nabcdefghijklmnopq", || {
            if admitted == 1 {
                return Err(());
            }
            admitted += 1;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(admitted, 1);
    }
}
