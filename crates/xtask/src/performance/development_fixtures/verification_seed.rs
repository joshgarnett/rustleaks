//! Independently bind literal identities to the fixed development seed recipe.
//! The verifier streams each domain field into SHA-256 instead of calling the
//! generator's formatted-key helper, and never derives values from scanner output.

use sha2::{Digest, Sha256};

pub(super) fn value(family: &str, ordinal: usize, length: usize) -> Vec<u8> {
    let ordinal = ordinal.to_string();
    let mut result = Vec::with_capacity(length);
    if length == 0 {
        return result;
    }
    for counter in 0_u64.. {
        let mut hash = Sha256::new();
        for field in [
            b"rustleaks.kingfisher-expansion.v1.dev.2026-11-13".as_slice(),
            family.as_bytes(),
            b"development",
            ordinal.as_bytes(),
        ] {
            hash.update(field);
            hash.update([0_u8]);
        }
        hash.update(counter.to_string().as_bytes());
        for byte in hash.finalize() {
            if byte >= 248 {
                continue;
            }
            let residue = byte % 62;
            result.push(match residue {
                0..=25 => b'A' + residue,
                26..=51 => b'a' + residue - 26,
                _ => b'0' + residue - 52,
            });
            if result.len() == length {
                return result;
            }
        }
    }
    unreachable!("finite fixture values require only a bounded prefix of the hash stream")
}

pub(super) fn pat(family: &str, ordinal: usize, class: &str) -> Vec<u8> {
    let mut result = vec![b'g', b'h', b'p', b'_'];
    result.extend(value(family, ordinal, 36));
    match class {
        "prefix-negative" => result[0] = b'z',
        "internal-negative" => result[22] = b'_',
        "positive" => {}
        _ => unreachable!("verifier supplies the three declared PAT classes"),
    }
    result
}

pub(super) fn connection_password(form: &str, class: &str) -> Result<Vec<u8>, String> {
    let form = [
        "uri-userinfo",
        "jdbc-query",
        "odbc-properties",
        "libpq-keyword",
    ]
    .iter()
    .position(|candidate| *candidate == form)
    .ok_or("unknown connection seed form")?;
    let class = [
        "literal",
        "percent-encoded",
        "empty",
        "omitted",
        "environment-placeholder",
        "template-placeholder",
        "public-url",
        "prose",
        "malformed-delimiter",
    ]
    .iter()
    .position(|candidate| *candidate == class)
    .ok_or("unknown connection seed class")?;
    Ok(value("connection-password", form * 9 + class, 24))
}
