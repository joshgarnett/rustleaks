//! Pinned Go-compatible Unicode helpers used outside regular expressions.

include!("go_lowercase_tables.rs");

pub(crate) fn lowercase(value: &str) -> String {
    value.chars().map(simple_lowercase).collect()
}

pub(crate) fn lowercase_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_ascii() {
        return bytes.to_ascii_lowercase();
    }
    let mut output = String::with_capacity(bytes.len());
    for character in chars(bytes) {
        output.push(simple_lowercase(character));
    }
    output.into_bytes()
}

pub(crate) fn chars(mut bytes: &[u8]) -> impl Iterator<Item = char> + '_ {
    std::iter::from_fn(move || {
        let (&first, remaining) = bytes.split_first()?;
        if first.is_ascii() {
            bytes = remaining;
            return Some(char::from(first));
        }
        for width in 2..=4 {
            if let Some(candidate) = bytes.get(..width)
                && let Ok(valid) = std::str::from_utf8(candidate)
                && let Some(character) = valid.chars().next()
                && character.len_utf8() == width
            {
                bytes = &bytes[width..];
                return Some(character);
            }
        }
        bytes = remaining;
        Some('\u{fffd}')
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
