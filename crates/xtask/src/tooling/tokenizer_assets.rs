//! Regenerate the complete bounded Vercel lookup table from pinned cl100k data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

const DIRECTORY: &str = "crates/rustleaks-core/data";
const SOURCE_SHA256: &str = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7";
const TABLE_SHA256: &str = "ad1a8cb135ace0e3dd9507246248658d2d99761353d96e31b1f33626d677ab28";

pub(crate) fn generate(root: &Path, check: bool) -> Result<(), String> {
    let directory = root.join(DIRECTORY);
    for (name, hash) in [
        (
            "LICENSE.tiktoken",
            "418cb499b436128d653d79941333a5437b7be2ea9213dcc2f04d15d5d2c51d86",
        ),
        (
            "LICENSE.tiktoken-rs",
            "f7c6ddf9d84fd7b8ad5917e4074d4c05e4c1dfb752a28a0058f06bd0f5e2edcc",
        ),
    ] {
        if super::sha256_file(&directory.join(name))? != hash {
            return Err(format!("tokenizer license identity differs: {name}"));
        }
    }
    let source = std::fs::read(directory.join("cl100k_base.tiktoken"))
        .map_err(|error| format!("cannot read tokenizer source: {error}"))?;
    let table = derive(&source)?;
    let path = directory.join("cl100k-vercel60-v1.bin");
    if check {
        let retained =
            std::fs::read(path).map_err(|error| format!("cannot read tokenizer table: {error}"))?;
        if retained != table {
            return Err("tokenizer table differs; run xtask generate native-pack-identity".into());
        }
    } else {
        std::fs::write(path, table)
            .map_err(|error| format!("cannot write tokenizer table: {error}"))?;
    }
    Ok(())
}

fn derive(source: &[u8]) -> Result<Vec<u8>, String> {
    // Bind the original bytes, not merely a reduced table or an untrusted
    // manifest. Source updates require a separately reviewed version change.
    if source.len() != 1_681_126 || super::sha256_bytes(source) != SOURCE_SHA256 {
        return Err("tokenizer original asset identity differs".into());
    }
    let text = std::str::from_utf8(source).map_err(|_| "invalid tokenizer source text")?;
    let mut vocabulary = BTreeMap::new();
    let mut ranks = BTreeSet::new();
    for line in text.lines() {
        let (token, rank) = line.split_once(' ').ok_or("invalid tokenizer record")?;
        let token = STANDARD
            .decode(token)
            .map_err(|_| "invalid tokenizer token")?;
        let parsed = rank.parse::<u32>().map_err(|_| "invalid tokenizer rank")?;
        if token.is_empty()
            || parsed.to_string() != rank
            || !ranks.insert(parsed)
            || vocabulary.insert(token, parsed).is_some()
        {
            return Err("duplicate or malformed tokenizer record".into());
        }
    }
    if vocabulary.len() != 100_256
        || !ranks.iter().copied().eq(0..100_256)
        || !(0..=255_u8).all(|byte| vocabulary.contains_key(&[byte][..]))
    {
        return Err("tokenizer vocabulary inventory differs".into());
    }
    // Every numeric pretoken is a direct whole-token hit. This exhaustive
    // assertion permits omitting its rank from the count-only runtime table.
    for width in 1..=3 {
        for number in 0..10_usize.pow(u32::try_from(width).map_err(|_| "invalid width")?) {
            let token = format!("{number:0width$}");
            if !vocabulary.contains_key(token.as_bytes()) {
                return Err("tokenizer numeric shortcut is not valid".into());
            }
        }
    }
    let applicable = vocabulary
        .iter()
        .filter(|(token, _)| possible_substring(token));
    if applicable.clone().count() != 35_635 {
        return Err("tokenizer domain inventory differs".into());
    }
    let selected = applicable
        .filter(|(token, _)| token.len() > 1 && !token.iter().all(u8::is_ascii_digit))
        .collect::<Vec<_>>();
    let mut pool = Vec::new();
    let mut offsets = vec![0_u32];
    for (token, _) in &selected {
        pool.extend_from_slice(token);
        offsets.push(u32::try_from(pool.len()).map_err(|_| "tokenizer pool overflows")?);
    }
    if selected.len() != 34_471
        || pool.len() != 194_315
        || selected.iter().map(|(token, _)| token.len()).max() != Some(48)
    {
        return Err("tokenizer reduced inventory differs".into());
    }
    let mut table = b"RLVCBPE1".to_vec();
    table.extend_from_slice(&34_471_u32.to_le_bytes());
    table.extend_from_slice(&194_315_u32.to_le_bytes());
    for offset in offsets {
        table.extend_from_slice(&offset.to_le_bytes());
    }
    for (_, rank) in selected {
        table.extend_from_slice(&rank.to_le_bytes());
    }
    table.extend_from_slice(&pool);
    if table.len() != 470_103 || super::sha256_bytes(&table) != TABLE_SHA256 {
        return Err("tokenizer derived bytes differ from reviewed identity".into());
    }
    Ok(table)
}

fn possible_substring(token: &[u8]) -> bool {
    let letters = |bytes: &[u8], limit| {
        !bytes.is_empty() && bytes.len() <= limit && bytes.iter().all(u8::is_ascii_alphabetic)
    };
    let punctuation = |bytes: &[u8]| bytes.iter().all(|byte| matches!(byte, b'-' | b'_'));
    letters(token, 56)
        || token
            .strip_prefix(b"_")
            .is_some_and(|rest| letters(rest, 56))
        || token
            .strip_prefix(b"-")
            .is_some_and(|rest| letters(rest, 54))
        || (!token.is_empty() && token.len() <= 3 && token.iter().all(u8::is_ascii_digit))
        || (!token.is_empty() && token.len() <= 56 && punctuation(token))
        || (token.len() == 57 && token[0] == b'_' && punctuation(token))
}

#[cfg(test)]
mod tests {
    use super::{derive, possible_substring};

    #[test]
    fn source_identity_is_verified_before_parsing() {
        assert_eq!(
            derive(b"YQ== 0\n").unwrap_err(),
            "tokenizer original asset identity differs"
        );
    }

    #[test]
    fn reduction_bounds_follow_the_complete_capture_language() {
        assert!(possible_substring(&[b'A'; 56]));
        assert!(!possible_substring(&[b'A'; 57]));
        assert!(possible_substring(&[b'_'; 57]));
        assert!(!possible_substring(&[b'-'; 57]));
        assert!(possible_substring(b"-Ab"));
        assert!(!possible_substring(b"--Ab"));
        assert!(possible_substring(b"001"));
        assert!(!possible_substring(b"0001"));
        assert!(!possible_substring(b"A1"));
    }
}
