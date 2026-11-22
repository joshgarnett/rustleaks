//! Go Unicode helpers used outside regular expressions: rune decoding as in
//! Go's `unicode/utf8` package and Go's simple lowercase mapping.

include!("go_lowercase_tables.rs");

pub(crate) fn lowercase(value: &str) -> String {
    value.chars().map(simple_lowercase).collect()
}

pub(crate) fn lowercase_bytes(bytes: &[u8]) -> Vec<u8> {
    lowercase_bytes_keeping_ascii(bytes).bytes
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
    if bytes.is_ascii() {
        return Lowered {
            bytes: bytes.to_ascii_lowercase(),
            kept_ascii: true,
            same_offsets: true,
        };
    }
    let mut output = String::with_capacity(bytes.len());
    let mut kept_ascii = true;
    let mut same_offsets = std::str::from_utf8(bytes).is_ok();
    for character in chars(bytes) {
        let lowered = simple_lowercase(character);
        kept_ascii &= character.is_ascii() || !lowered.is_ascii();
        same_offsets &= lowered.len_utf8() == character.len_utf8()
            && !matches!(character, '\u{17f}' | '\u{212a}');
        output.push(lowered);
    }
    Lowered {
        bytes: output.into_bytes(),
        kept_ascii,
        same_offsets: same_offsets && kept_ascii,
    }
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
