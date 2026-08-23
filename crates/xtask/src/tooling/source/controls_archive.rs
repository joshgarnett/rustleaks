//! Archive, decompressor, corruption, and depth controls.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::read;
use super::validation::{finding_files, fragment_values, outcome_for, required_array};

const SAFE_CODECS: &[&str] = &["br", "bz2", "lz4", "mz", "s2", "sz"];
const SEVENZIP_CODECS: &[&str] = &[
    "copy", "delta", "lzma", "deflate", "bzip2", "brotli", "lz4", "zstd", "bcj", "bcj2", "arm",
    "ppc", "sparc",
];

pub(super) fn validate(root: &Path, outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    validate_identification_and_depth(outcomes)?;
    validate_streams_and_seekable(outcomes)?;
    validate_rar(root, outcomes)?;
    validate_corruption(outcomes)?;
    Ok(())
}

fn validate_identification_and_depth(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    if len(outcomes, "archive-uppercase-name", "fragments")? != 4
        || len(outcomes, "archive-substring-name", "fragments")? != 4
        || len(outcomes, "archive-magic-without-name", "fragments")? != 0
    {
        return Err("SRC-018 name-only archive identification changed".into());
    }
    if len(outcomes, "nested-depth-0", "findings")? != 0
        || len(outcomes, "nested-depth-1", "findings")? != 2
        || len(outcomes, "nested-depth-2", "findings")? != 15
    {
        return Err("SRC-019 archive depth accounting changed".into());
    }
    let zip = fragment_values(outcomes, "archive-files-zip", "file_base64")?;
    let expected = [
        "../testdata/archives/files.zip!files/.gitleaksignore",
        "../testdata/archives/files.zip!files/api.go",
        "../testdata/archives/files.zip!files/main.go",
    ]
    .map(|value| value.as_bytes().to_vec());
    if zip != expected {
        return Err("SRC-020 extractor order or path cleaning changed".into());
    }
    let files = finding_files(outcomes, "archive-files-zip")?;
    if files.iter().any(|path| !path.contains(&b'!')) {
        return Err("SRC-021 inner finding path changed".into());
    }
    for finding in required_array(
        outcome_for(outcomes, "archive-files-zip")?,
        "findings",
        "archive-files-zip",
    )? {
        let fingerprint =
            super::validation::decode(finding, "fingerprint_base64", "archive fingerprint")?;
        if !fingerprint.contains(&b'!') {
            return Err("SRC-021 archive fingerprint path changed".into());
        }
    }
    if fragment_values(outcomes, "archive-inner-allowlist-scope", "raw_base64")? != [b"deep"]
        || fragment_values(outcomes, "archive-inner-allowlist-scope", "file_base64")?
            != [b"outer.tar!nested.tar!skip/deep.txt"]
    {
        return Err("SRC-023 child allowlist propagation changed".into());
    }
    let nested = finding_files(outcomes, "nested-depth-8")?;
    if !nested.iter().any(|path| contains(path, b"files.zip!"))
        || !nested.iter().any(|path| contains(path, b"files.7z!"))
    {
        return Err("SRC-024 nested seekable archive spooling changed".into());
    }
    Ok(())
}

fn validate_streams_and_seekable(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    for name in ["main.go.gz", "main.go.xz", "main.go.zst"] {
        let id = format!("decompress-{}", name.replace('.', "-"));
        let expected = format!("archives/files/{name}").into_bytes();
        if finding_files(outcomes, &id)? != [expected] {
            return Err(format!("{id}: retained outer filename changed"));
        }
    }
    for extension in SAFE_CODECS {
        let id = format!("decompress-safe-{extension}");
        if fragment_values(outcomes, &id, "raw_base64")? != [b"portable safe codec payload\n"]
            || fragment_values(outcomes, &id, "file_base64")?
                != [format!("portable.{extension}").into_bytes()]
        {
            return Err(format!("{id}: safe stream codec behavior changed"));
        }
        let id = format!("decompress-safe-tar-{extension}");
        if fragment_values(outcomes, &id, "raw_base64")? != [b"portable safe codec payload\n"]
            || fragment_values(outcomes, &id, "file_base64")?
                != [format!("portable.tar.{extension}!value.txt").into_bytes()]
        {
            return Err(format!("{id}: compressed TAR behavior changed"));
        }
    }
    for codec in SEVENZIP_CODECS {
        let id = format!("archive-7z-{codec}");
        if !outcome_for(outcomes, &id)?["error"].is_null() || len(outcomes, &id, "issues")? != 0 {
            return Err(format!("{id}: safe 7z codec profile changed"));
        }
    }
    if fragment_values(outcomes, "archive-rar5-stored", "raw_base64")?
        != [b"portable safe RAR payload\n"]
        || fragment_values(outcomes, "archive-rar5-stored", "file_base64")?
            != [b"portable-stored.rar!value.txt"]
        || fragment_values(outcomes, "archive-rar5-compressed", "raw_base64")?
            != [format!("{}\n", "A".repeat(200)).into_bytes()]
        || fragment_values(outcomes, "archive-rar5-compressed", "file_base64")?
            != [b"portable-compressed.rar!compressed.txt"]
    {
        return Err("SRC-022 generated RAR decoding changed".into());
    }
    Ok(())
}

fn validate_rar(root: &Path, outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let fixture = root.join("compat/fixtures/oracle/rar-test-files-16b785c/expected");
    let text = read(&fixture.join("testfile.txt"))?;
    let jpeg = read(&fixture.join("testfile.jpg"))?;
    let png = read(&fixture.join("testfile.png"))?;
    for id in [
        "archive-rar-rar3",
        "archive-rar-rar3-solid",
        "archive-rar-rar5",
        "archive-rar-rar5-solid",
    ] {
        if fragment_values(outcomes, id, "raw_base64")? != [text.clone()]
            || !outcome_for(outcomes, id)?["error"].is_null()
            || len(outcomes, id, "issues")? != 0
        {
            return Err(format!("{id}: ordinary/solid RAR member changed"));
        }
    }
    for (id, expected) in [
        ("archive-rar-rar3-multi", vec![jpeg.clone(), png.clone()]),
        (
            "archive-rar-rar3-solid-multi",
            vec![png.clone(), jpeg.clone()],
        ),
        ("archive-rar-rar5-multi", vec![jpeg.clone(), png.clone()]),
        ("archive-rar-rar5-solid-multi", vec![jpeg, png]),
    ] {
        if fragment_values(outcomes, id, "raw_base64")? != expected {
            return Err(format!("{id}: RAR backend entry order changed"));
        }
    }
    let rar2 = b"Hello, RAR2 world!\nThis is a test of the RAR 2.x decoder.\nLine three with some repetition: ABCABCABCABC.\n";
    if fragment_values(outcomes, "archive-rar2-compressed", "raw_base64")? != [rar2]
        || fragment_values(outcomes, "archive-rar2-compressed", "file_base64")?
            != [b"portable-rar2.rar!hello.txt"]
    {
        return Err("SRC-022 RAR2 compressed member changed".into());
    }
    let encrypted = outcome_for(outcomes, "archive-rar5-encrypted-headers")?;
    let volume = outcome_for(outcomes, "archive-rar5-multivolume")?;
    if encrypted.pointer("/error/class").and_then(Value::as_str) != Some("source")
        || encrypted.pointer("/error/message").and_then(Value::as_str)
            != Some("rardecode: archive encrypted, password required")
        || volume.pointer("/error/class").and_then(Value::as_str) != Some("panic")
    {
        return Err("SRC-025 RAR failure classes changed".into());
    }
    Ok(())
}

fn validate_corruption(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    if len(outcomes, "file-malformed-archive", "fragments")? != 0
        || !outcome_for(outcomes, "file-malformed-archive")?["error"].is_null()
        || outcome_for(outcomes, "archive-direct-corrupt-tar")?
            .pointer("/error/message")
            .and_then(Value::as_str)
            != Some("unexpected EOF")
        || len(outcomes, "files-corrupt-tar", "fragments")? != 0
    {
        return Err("SRC-025 direct/directory corruption behavior changed".into());
    }
    for extension in ["zip", "7z"] {
        if error_class(outcomes, &format!("archive-direct-corrupt-{extension}")) != Some("source") {
            return Err(format!("corrupt {extension} error class changed"));
        }
    }
    for extension in ["gz", "xz", "lz", "zz"] {
        let id = format!("archive-direct-corrupt-{extension}");
        if !outcome_for(outcomes, &id)?["error"].is_null() || len(outcomes, &id, "fragments")? != 0
        {
            return Err(format!("corrupt {extension} behavior changed"));
        }
    }
    for extension in SAFE_CODECS {
        let id = format!("archive-direct-corrupt-{extension}");
        if len(outcomes, &id, "fragments")? != 1 || len(outcomes, &id, "issues")? != 1 {
            return Err(format!("corrupt {extension} issue behavior changed"));
        }
    }
    if len(outcomes, "files-corrupt-archive-matrix", "fragments")? != 7 {
        return Err("directory corruption matrix changed".into());
    }
    Ok(())
}

fn len(outcomes: &BTreeMap<&str, &Value>, id: &str, field: &str) -> Result<usize, String> {
    Ok(required_array(outcome_for(outcomes, id)?, field, id)?.len())
}

fn error_class<'a>(outcomes: &'a BTreeMap<&str, &Value>, id: &str) -> Option<&'a str> {
    outcomes.get(id)?.pointer("/error/class")?.as_str()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::contains;

    #[test]
    fn byte_substrings_do_not_require_utf8() {
        assert!(contains(b"a\xfffiles.zip!b", b"files.zip!"));
        assert!(!contains(b"files.zip", b"files.zip!"));
    }
}
