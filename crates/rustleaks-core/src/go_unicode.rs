//! Pinned Go-compatible Unicode helpers used outside regular expressions.

include!("go_lowercase_tables.rs");

pub(crate) fn lowercase(value: &str) -> String {
    value.chars().map(simple_lowercase).collect()
}

pub(crate) fn lowercase_bytes(bytes: &[u8]) -> Vec<u8> {
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
            if let Some(candidate) = bytes.get(..width) {
                if let Ok(valid) = std::str::from_utf8(candidate) {
                    if let Some(character) = valid.chars().next() {
                        if character.len_utf8() == width {
                            bytes = &bytes[width..];
                            return Some(character);
                        }
                    }
                }
            }
        }
        bytes = remaining;
        Some('\u{fffd}')
    })
}

fn simple_lowercase(character: char) -> char {
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
}
