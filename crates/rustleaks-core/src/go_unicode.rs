//! Go Unicode helpers used outside regular expressions: rune decoding as in
//! Go's `unicode/utf8` package and Go's simple lowercase mapping.

include!("go_lowercase_tables.rs");

pub(crate) fn lowercase(value: &str) -> String {
    value.chars().map(simple_lowercase).collect()
}

pub(crate) fn lowercase_bytes(bytes: &[u8]) -> Vec<u8> {
    lowercase_bytes_keeping_ascii(bytes).bytes
}

/// Converts `bytes` to text as Go's JSON encoder does: each byte that is not
/// part of valid UTF-8 becomes one U+FFFD.
pub(crate) fn utf8_lossy(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    if let Ok(valid) = std::str::from_utf8(bytes) {
        return std::borrow::Cow::Borrowed(valid);
    }
    let mut output = String::with_capacity(bytes.len().saturating_add(2));
    for chunk in bytes.utf8_chunks() {
        output.push_str(chunk.valid());
        // A Rust UTF-8 error can cover several bytes. The bytes after the
        // first are continuation bytes, which never start a rune, so Go
        // replaces each of them on its own.
        for _ in chunk.invalid() {
            output.push(char::REPLACEMENT_CHARACTER);
        }
    }
    std::borrow::Cow::Owned(output)
}

/// A lowercased pass and what it keeps of the input's ASCII text.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Lowered {
    pub(crate) bytes: Vec<u8>,
    /// Every ASCII byte of the output is an input ASCII byte, lowercased.
    ///
    /// It is false when a non-ASCII rune lowercases to ASCII, such as the
    /// Kelvin sign to `k`. When it is true, an ASCII string occurs in the
    /// output exactly where it occurs in the input ignoring ASCII case, as
    /// runes: each rune maps to one rune, and an ASCII input byte is always a
    /// rune of its own.
    pub(crate) kept_ascii: bool,
    /// The input is valid UTF-8, every rune keeps its encoded length, and no
    /// rune is one that case-insensitive matching pairs with an ASCII letter
    /// (U+017F for `s`, U+212A for `k`). Then output offsets are input
    /// offsets, and only ASCII input bytes can match an ASCII letter.
    pub(crate) same_offsets: bool,
}

/// Lowercases like [`lowercase_bytes`] and reports what the output keeps.
pub(crate) fn lowercase_bytes_keeping_ascii(bytes: &[u8]) -> Lowered {
    let mut output = Vec::new();
    let flags = lowercase_into(bytes, &mut output);
    Lowered {
        bytes: output,
        kept_ascii: flags.kept_ascii,
        same_offsets: flags.same_offsets,
    }
}

/// What a lowercased pass keeps of the input's ASCII text; see [`Lowered`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoweredFlags {
    pub(crate) kept_ascii: bool,
    pub(crate) same_offsets: bool,
}

/// Lowercases like [`lowercase_bytes_keeping_ascii`] into `output`, which
/// is cleared first, so that a caller can reuse its storage.
pub(crate) fn lowercase_into(bytes: &[u8], output: &mut Vec<u8>) -> LoweredFlags {
    output.clear();
    if bytes.is_ascii() {
        output.extend_from_slice(bytes);
        output.make_ascii_lowercase();
        return LoweredFlags {
            kept_ascii: true,
            same_offsets: true,
        };
    }
    output.reserve(bytes.len());
    let text = std::str::from_utf8(bytes).ok();
    let mut kept_ascii = true;
    let mut same_offsets = text.is_some();
    let mut encoded = [0; 4];
    let mut offset = 0;
    while offset < bytes.len() {
        // Each ASCII byte is a rune of its own, so a run of them lowercases
        // as one slice.
        let run = ascii_run(&bytes[offset..]);
        let start = output.len();
        output.extend_from_slice(&bytes[offset..offset + run]);
        output[start..].make_ascii_lowercase();
        offset += run;
        // Runes until the next ASCII byte. A non-ASCII first byte decodes to
        // a non-ASCII rune or U+FFFD. Valid text decodes the same way without
        // checking each rune again.
        while offset < bytes.len() && !bytes[offset].is_ascii() {
            let (character, width) = match text.and_then(|text| text[offset..].chars().next()) {
                Some(character) => (character, character.len_utf8()),
                None => decode_rune(&bytes[offset..]),
            };
            offset += width;
            let lowered = simple_lowercase(character);
            kept_ascii &= !lowered.is_ascii();
            same_offsets &= lowered.len_utf8() == character.len_utf8()
                && !matches!(character, '\u{17f}' | '\u{212a}');
            output.extend_from_slice(lowered.encode_utf8(&mut encoded).as_bytes());
        }
    }
    LoweredFlags {
        kept_ascii,
        same_offsets: same_offsets && kept_ascii,
    }
}

/// The length of the ASCII bytes that start `bytes`.
fn ascii_run(bytes: &[u8]) -> usize {
    let whole = bytes
        .chunks_exact(16)
        .take_while(|chunk| chunk.is_ascii())
        .count()
        * 16;
    whole
        + bytes[whole..]
            .iter()
            .position(|byte| !byte.is_ascii())
            .unwrap_or(bytes.len() - whole)
}

/// Decodes the first rune like Go's `utf8.DecodeRune`.
///
/// Returns the rune and its width in bytes. An invalid or truncated encoding
/// is one `U+FFFD` of width 1. Empty input returns `U+FFFD` of width 0.
pub(crate) fn decode_rune(bytes: &[u8]) -> (char, usize) {
    let Some(&first) = bytes.first() else {
        return (char::REPLACEMENT_CHARACTER, 0);
    };
    if first.is_ascii() {
        return (char::from(first), 1);
    }
    let width = match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (char::REPLACEMENT_CHARACTER, 1),
    };
    if let Some(candidate) = bytes.get(..width)
        && let Ok(valid) = std::str::from_utf8(candidate)
        && let Some(character) = valid.chars().next()
    {
        return (character, width);
    }
    (char::REPLACEMENT_CHARACTER, 1)
}

/// Decodes the last rune like Go's `utf8.DecodeLastRune`.
///
/// Returns the rune and its width in bytes. An invalid or truncated encoding
/// is one `U+FFFD` of width 1. Empty input returns `U+FFFD` of width 0.
pub(crate) fn decode_last_rune(bytes: &[u8]) -> (char, usize) {
    let Some(&last) = bytes.last() else {
        return (char::REPLACEMENT_CHARACTER, 0);
    };
    if last.is_ascii() {
        return (char::from(last), 1);
    }
    for width in 2..=4.min(bytes.len()) {
        if let Ok(valid) = std::str::from_utf8(&bytes[bytes.len() - width..]) {
            let mut characters = valid.chars();
            if let (Some(character), None) = (characters.next(), characters.next()) {
                return (character, width);
            }
        }
    }
    (char::REPLACEMENT_CHARACTER, 1)
}

pub(crate) fn chars(mut bytes: &[u8]) -> impl Iterator<Item = char> + '_ {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let (character, width) = decode_rune(bytes);
        bytes = &bytes[width..];
        Some(character)
    })
}

#[inline]
fn simple_lowercase(character: char) -> char {
    if character.is_ascii() {
        return character.to_ascii_lowercase();
    }
    let value = u32::from(character);
    let index = GO_LOWERCASE_RANGES.partition_point(|range| range.0 <= value);
    let Some(&(low, high, step, delta)) = index
        .checked_sub(1)
        .and_then(|index| GO_LOWERCASE_RANGES.get(index))
    else {
        return character;
    };
    if value > high || (value - low) % step != 0 {
        return character;
    }
    let mapped = i64::from(value) + i64::from(delta);
    u32::try_from(mapped)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or(character)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rune_decoding_matches_go_utf8() {
        let replacement = char::REPLACEMENT_CHARACTER;
        for (bytes, first, last) in [
            (b"".as_slice(), (replacement, 0), (replacement, 0)),
            (b"a", ('a', 1), ('a', 1)),
            ("\u{e9}".as_bytes(), ('\u{e9}', 2), ('\u{e9}', 2)),
            ("\u{20ac}x".as_bytes(), ('\u{20ac}', 3), ('x', 1)),
            ("x\u{1f600}".as_bytes(), ('x', 1), ('\u{1f600}', 4)),
            (b"\xff", (replacement, 1), (replacement, 1)),
            (b"\xc0\x80", (replacement, 1), (replacement, 1)),
            (b"\xe2\x82", (replacement, 1), (replacement, 1)),
            (b"\xed\xa0\x80", (replacement, 1), (replacement, 1)),
            (b"\xf4\x90\x80\x80", (replacement, 1), (replacement, 1)),
            (b"\x80\x80\x80\x80\x80", (replacement, 1), (replacement, 1)),
        ] {
            assert_eq!(decode_rune(bytes), first, "{bytes:?}");
            assert_eq!(decode_last_rune(bytes), last, "{bytes:?}");
        }
    }

    #[test]
    fn only_two_non_ascii_runes_lowercase_to_ascii() {
        let lowering = (0x80..=0x10_ffff)
            .filter_map(char::from_u32)
            .filter(|character| simple_lowercase(*character).is_ascii())
            .collect::<Vec<_>>();
        assert_eq!(lowering, ['\u{130}', '\u{212a}']);
        let lowered = |input: &[u8]| {
            let lowered = lowercase_bytes_keeping_ascii(input);
            (lowered.bytes, lowered.kept_ascii, lowered.same_offsets)
        };
        assert_eq!(
            lowered("Key \u{c9}".as_bytes()),
            ("key \u{e9}".as_bytes().to_vec(), true, true)
        );
        // An invalid byte becomes a three-byte U+FFFD.
        assert_eq!(
            lowered(b"A\xffB"),
            ("a\u{fffd}b".as_bytes().to_vec(), true, false)
        );
        assert_eq!(
            lowered("\u{212a}ey".as_bytes()),
            (b"key".to_vec(), false, false)
        );
        // U+017F stays itself, but `(?i)s` matches it.
        assert_eq!(
            lowered("\u{17f}ecret".as_bytes()),
            ("\u{17f}ecret".as_bytes().to_vec(), true, false)
        );
        // U+023A (two bytes) lowercases to U+2C65 (three bytes).
        assert!(!lowered("\u{23a}".as_bytes()).2);
    }

    #[test]
    fn mapping_is_pinned_and_invalid_bytes_are_individual_rune_errors() {
        assert_eq!(lowercase("ABCÉİ"), "abcéi");
        assert_eq!(
            lowercase_bytes(b"A\xff\x80B"),
            "a\u{fffd}\u{fffd}b".as_bytes()
        );
    }

    #[test]
    fn ascii_fast_paths_map_only_uppercase_letters() {
        let input = (0_u8..=127).collect::<Vec<_>>();
        // The ASCII contract is independent of the optimized standard-library
        // helpers: only A through Z change, by exactly 32 code points.
        let expected = input
            .iter()
            .map(|&byte| match byte {
                b'A'..=b'Z' => byte + 32,
                _ => byte,
            })
            .collect::<Vec<_>>();
        assert_eq!(lowercase_bytes(&input), expected);
        assert_eq!(
            lowercase(std::str::from_utf8(&input).unwrap()).as_bytes(),
            expected
        );
        for (&input, &expected) in input.iter().zip(&expected) {
            assert_eq!(simple_lowercase(char::from(input)), char::from(expected));
        }
        assert!(lowercase_bytes(b"").is_empty());
    }

    /// Lowercases one rune at a time, as `lowercase_into` is specified.
    fn lowercase_by_rune(bytes: &[u8]) -> (Vec<u8>, bool, bool) {
        let mut output = String::new();
        let mut kept_ascii = true;
        let mut same_offsets = std::str::from_utf8(bytes).is_ok();
        for character in chars(bytes) {
            let lowered = simple_lowercase(character);
            kept_ascii &= character.is_ascii() || !lowered.is_ascii();
            same_offsets &= lowered.len_utf8() == character.len_utf8()
                && !matches!(character, '\u{17f}' | '\u{212a}');
            output.push(lowered);
        }
        (output.into_bytes(), kept_ascii, same_offsets && kept_ascii)
    }

    #[test]
    fn ascii_runs_lowercase_like_one_rune_at_a_time() {
        let pieces: &[&[u8]] = &[
            b"",
            b"a",
            b"KEY=Value ",
            // Longer than one 16-byte chunk of the ASCII scan.
            b"Some ASCII Text, 0123456789",
            b"\n",
            "\u{c9}".as_bytes(),
            "\u{130}".as_bytes(),
            "\u{212a}".as_bytes(),
            "\u{17f}".as_bytes(),
            "\u{23a}".as_bytes(),
            "\u{3a3}".as_bytes(),
            "\u{1f600}".as_bytes(),
            "\u{fffd}".as_bytes(),
            b"\xff",
            b"\x80",
            b"\xc0\x80",
            b"\xe2\x82",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
        ];
        // Every sequence of up to three pieces, so that each kind of rune
        // appears at the start, the end and between ASCII runs.
        let mut inputs = vec![Vec::new()];
        for _ in 0..3 {
            let mut longer = Vec::new();
            for input in &inputs {
                for piece in pieces {
                    let mut next = input.clone();
                    next.extend_from_slice(piece);
                    longer.push(next);
                }
            }
            inputs.extend(longer);
        }
        let mut output = b"left over".to_vec();
        for input in &inputs {
            let flags = lowercase_into(input, &mut output);
            assert_eq!(
                (output.clone(), flags.kept_ascii, flags.same_offsets),
                lowercase_by_rune(input),
                "{input:?}"
            );
        }
    }

    /// Replaces one invalid byte at a time, as `utf8_lossy` is specified.
    fn utf8_lossy_by_byte(bytes: &[u8]) -> String {
        let mut output = String::new();
        let mut remaining = bytes;
        while !remaining.is_empty() {
            match std::str::from_utf8(remaining) {
                Ok(valid) => {
                    output.push_str(valid);
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    output.push_str(std::str::from_utf8(&remaining[..valid]).unwrap());
                    output.push(char::REPLACEMENT_CHARACTER);
                    remaining = &remaining[valid + 1..];
                }
            }
        }
        output
    }

    #[test]
    fn lossy_text_replaces_each_invalid_byte() {
        let pieces: &[&[u8]] = &[
            b"",
            b"a",
            "\u{e9}".as_bytes(),
            "\u{20ac}".as_bytes(),
            "\u{1f600}".as_bytes(),
            b"\xff",
            b"\x80",
            b"\xc0\x80",
            b"\xe2\x82",
            b"\xed\xa0\x80",
            b"\xf0\x9f\x98",
            b"\xf4\x90\x80\x80",
        ];
        let mut inputs = vec![Vec::new()];
        for _ in 0..3 {
            let mut longer = Vec::new();
            for input in &inputs {
                for piece in pieces {
                    let mut next = input.clone();
                    next.extend_from_slice(piece);
                    longer.push(next);
                }
            }
            inputs.extend(longer);
        }
        for input in &inputs {
            let lossy = utf8_lossy(input);
            assert_eq!(lossy, utf8_lossy_by_byte(input), "{input:?}");
            assert_eq!(
                matches!(lossy, std::borrow::Cow::Borrowed(_)),
                std::str::from_utf8(input).is_ok()
            );
        }
    }

    #[test]
    fn mixed_inputs_keep_go_unicode_mapping_and_one_rune_error_per_invalid_byte() {
        // Go simple lowercase maps dotted I to one i and sigma without word
        // context. The decomposed accent remains decomposed; no normalization
        // or Rust full-string lowercase mapping is introduced by either path.
        let prefix = "AÉİ ΟΣ \u{212a} E\u{301} ";
        let expected_prefix = "aéi οσ k e\u{301} ";
        assert_eq!(lowercase(prefix), expected_prefix);
        let malformed: &[(&[u8], &str)] = &[
            (b"\xff", "\u{fffd}"),
            (b"\xc0\x80", "\u{fffd}\u{fffd}"),
            (b"\xe2\x82", "\u{fffd}\u{fffd}"),
            (b"\xed\xa0\x80", "\u{fffd}\u{fffd}\u{fffd}"),
            (b"\xf4\x90\x80\x80", "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"),
            ("\u{fffd}".as_bytes(), "\u{fffd}"),
        ];
        for &(bytes, replacement) in malformed {
            let mut input = prefix.as_bytes().to_vec();
            input.extend_from_slice(bytes);
            input.extend_from_slice(b" Z");
            let expected = format!("{expected_prefix}{replacement} z");
            assert_eq!(lowercase_bytes(&input), expected.as_bytes());
        }
    }
}
