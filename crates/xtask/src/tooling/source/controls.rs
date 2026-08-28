//! Reader, filesystem, path, engine, and negative controls.

use std::collections::BTreeMap;

use serde_json::Value;

use super::validation::{decode, fragment_values, outcome_for, required_array, required_str};

pub(super) fn validate(
    outcomes: &BTreeMap<&str, &Value>,
    all: &[Value],
    _negative: &Value,
) -> Result<(), String> {
    let platform = required_str(&all[0], "platform", "first outcome")?;
    let windows = platform.starts_with("windows/");
    validate_boundaries(outcomes)?;
    validate_readers(outcomes)?;
    validate_files(outcomes)?;
    validate_paths_and_symlinks(outcomes, windows)?;
    validate_directory_and_engine(outcomes, windows)?;
    validate_negative_controls(outcomes, windows)?;
    if !platform.contains('/')
        || all
            .iter()
            .any(|entry| entry.get("platform") != Some(&Value::String(platform.into())))
    {
        return Err("SRC-030 native platform provenance changed".into());
    }
    Ok(())
}

fn validate_boundaries(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let expected: &[(&str, &[u8])] = &[
        ("boundary-original-lf", b"abc\n\n"),
        ("boundary-original-crlf", b"a\r\n\r\n"),
        ("boundary-lf", b"abcdefg\nhijklmnop\n\n"),
        ("boundary-crlf", b"abcdefg\r\nhijklmnop\r\n\r\n"),
        ("boundary-blank", b"abcdefg\nhijklmnop\n\t  \t\n"),
        ("boundary-none", b"abcdefg\nhijklmnopqrstuvwx"),
    ];
    for (id, bytes) in expected {
        if fragment_values(outcomes, id, "raw_base64")?
            .first()
            .map(Vec::as_slice)
            != Some(*bytes)
        {
            return Err(format!("{id}: SRC-004/005 boundary changed"));
        }
    }
    if fragment_values(outcomes, "boundary-25000-ceiling", "raw_base64")?[0].len() != 125_000 {
        return Err("boundary lookahead ceiling changed".into());
    }
    Ok(())
}

fn validate_readers(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let counts = [
        ("stream-single", 1),
        ("stream-empty", 0),
        ("stream-error", 0),
        ("stream-multiple", 2),
        ("stream-eof", 1),
        ("stream-split", 1),
        ("stream-late-error", 0),
    ];
    for (id, count) in counts {
        if array_len(outcomes, id, "findings")? != count {
            return Err(format!("{id}: SRC-009 reader result changed"));
        }
    }
    if array_len(outcomes, "detect-reader-eof", "findings")? != 1
        || array_len(outcomes, "stream-error", "issues")? != 1
        || array_len(outcomes, "stream-late-error", "issues")? != 1
        || array_len(outcomes, "file-data-plus-error", "issues")? != 1
    {
        return Err("SRC-006 reader EOF/error matrix changed".into());
    }
    Ok(())
}

fn validate_files(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let invalid = required_array(
        outcome_for(outcomes, "file-invalid-bytes")?,
        "fragments",
        "file-invalid-bytes",
    )?;
    if invalid.iter().any(|fragment| {
        fragment["raw_base64"] != fragment["bytes_base64"]
            || fragment["bytes_nil"] != Value::Bool(false)
    }) {
        return Err("SRC-002 owned fragment projection changed".into());
    }
    if fragment_values(outcomes, "file-default-buffer", "raw_base64")?
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>()
        != [100_002, 1]
        || fragment_values(outcomes, "file-custom-buffer", "raw_base64")?
            != [b"abc\n\n".to_vec(), b"def".to_vec()]
    {
        return Err("SRC-003 buffer behavior changed".into());
    }
    let starts = required_array(
        outcome_for(outcomes, "file-lf-line-count")?,
        "fragments",
        "file-lf-line-count",
    )?
    .iter()
    .map(|fragment| fragment["start_line"].as_u64())
    .collect::<Option<Vec<_>>>();
    if starts != Some(vec![1, 3]) {
        return Err("SRC-007 LF-only line accounting changed".into());
    }
    if array_len(outcomes, "file-mime-skip", "fragments")? != 0
        || fragment_values(outcomes, "file-repeat-mime-before-first-lf", "raw_base64")?[0].len()
            != 125_000
        || array_len(outcomes, "archive-magic-without-name", "fragments")? != 0
    {
        return Err("SRC-008 MIME identification changed".into());
    }
    if error_class(outcomes, "file-yield-error")? != Some("yield")
        || array_len(outcomes, "file-yield-error", "fragments")? != 1
    {
        return Err("SRC-001 callback termination changed".into());
    }
    Ok(())
}

fn validate_paths_and_symlinks(
    outcomes: &BTreeMap<&str, &Value>,
    windows: bool,
) -> Result<(), String> {
    if fragment_values(outcomes, "file-path-nfc", "file_base64")? != ["paths/café.txt".as_bytes()]
        || fragment_values(outcomes, "file-path-nfd", "file_base64")?
            != ["paths/cafe\u{301}.txt".as_bytes()]
    {
        return Err("SRC-017 Unicode path normalization changed".into());
    }
    let invalid = outcome_for(outcomes, "file-invalid-bytes")?
        .pointer("/fragments/0")
        .ok_or("invalid-byte fragment missing")?;
    if decode(invalid, "file_base64", "invalid-byte path")? != b"src/\xff.bin" {
        return Err("SRC-017 invalid path bytes changed".into());
    }
    let expected_followed = usize::from(!windows);
    if array_len(outcomes, "files-symlink-disabled", "fragments")? != 0
        || array_len(outcomes, "files-directory-symlink", "fragments")? != 1
        || array_len(outcomes, "files-symlink-enabled", "findings")? != expected_followed
        || array_len(outcomes, "files-chained-symlink", "fragments")? != expected_followed
    {
        return Err("SRC-014/015 symlink behavior changed".into());
    }
    for id in ["files-dangling-symlink", "files-looping-symlink"] {
        if array_len(outcomes, id, "fragments")? != 0 {
            return Err(format!("{id}: SRC-016 invalid symlink emitted data"));
        }
        if let Some(class) = error_class(outcomes, id)? {
            if !["panic", "source"].contains(&class) {
                return Err(format!("{id}: invalid symlink error class changed"));
            }
        }
    }
    Ok(())
}

fn validate_directory_and_engine(
    outcomes: &BTreeMap<&str, &Value>,
    windows: bool,
) -> Result<(), String> {
    if array_len(outcomes, "files-nogit-main", "fragments")? != 1 {
        return Err("SRC-010 root-file discovery changed".into());
    }
    let paths = fragment_values(outcomes, "files-nogit-directory", "file_base64")?;
    let mut sorted = paths.clone();
    sorted.sort();
    if paths != sorted {
        return Err("SRC-010 lexical traversal changed".into());
    }
    if array_len(outcomes, "file-empty", "fragments")? != 0
        || fragment_values(outcomes, "files-size-boundary", "raw_base64")? != [b"12345"]
        || !fragment_values(outcomes, "files-symlink-alias-size-skip", "raw_base64")?.is_empty()
        || fragment_values(outcomes, "files-symlink-target-size-bypass", "raw_base64")?
            != if windows {
                Vec::<Vec<u8>>::new()
            } else {
                vec![b"1234567890".to_vec()]
            }
    {
        return Err("SRC-011 exact size gates changed".into());
    }
    for id in [
        "files-missing",
        "files-dangling-symlink",
        "files-looping-symlink",
    ] {
        if array_len(outcomes, id, "fragments")? != 0 {
            return Err(format!("{id}: SRC-012 unsafe filesystem result changed"));
        }
    }
    if array_len(outcomes, "files-prune-directory", "fragments")? != 1 {
        return Err("SRC-013 directory pruning changed".into());
    }
    if outcome_for(outcomes, "files-bounded-order")?["max_concurrent_callbacks"] != 1
        || fragment_values(outcomes, "files-bounded-order", "raw_base64")? != [b"same", b"same"]
    {
        return Err("SRC-026 bounded duplicate handling changed".into());
    }
    for id in ["file-canceled", "files-canceled", "nested-canceled"] {
        if error_class(outcomes, id)? != Some("canceled") {
            return Err(format!("{id}: SRC-027 cancellation changed"));
        }
    }
    if array_len(outcomes, "files-nogit-directory", "findings")? != 1
        || array_len(outcomes, "files-nogit-api", "findings")? != 0
    {
        return Err("SRC-028 engine/session behavior changed".into());
    }
    let fingerprint = decode(
        outcome_for(outcomes, "files-nogit-main")?
            .pointer("/findings/0")
            .ok_or("files-nogit-main finding missing")?,
        "fingerprint_base64",
        "main fingerprint",
    )?;
    if !fingerprint.ends_with(b"main.go:aws-access-key:20") {
        return Err("SRC-028 fingerprint changed".into());
    }
    Ok(())
}

fn validate_negative_controls(
    outcomes: &BTreeMap<&str, &Value>,
    windows: bool,
) -> Result<(), String> {
    if array_len(outcomes, "detect-reader-eof", "findings")?
        == array_len(outcomes, "stream-error", "findings")?
        || fragment_values(outcomes, "files-size-boundary", "raw_base64")? != [b"12345"]
        || (!windows
            && array_len(outcomes, "files-symlink-enabled", "findings")?
                == array_len(outcomes, "files-symlink-disabled", "findings")?)
        || array_len(outcomes, "nested-depth-8", "findings")?
            == array_len(outcomes, "nested-depth-1", "findings")?
        || array_len(outcomes, "files-prune-directory", "fragments")? != 1
    {
        return Err("source negative controls no longer distinguish their dimensions".into());
    }
    Ok(())
}

fn array_len(outcomes: &BTreeMap<&str, &Value>, id: &str, field: &str) -> Result<usize, String> {
    Ok(required_array(outcome_for(outcomes, id)?, field, id)?.len())
}

fn error_class<'a>(
    outcomes: &'a BTreeMap<&str, &Value>,
    id: &str,
) -> Result<Option<&'a str>, String> {
    Ok(outcome_for(outcomes, id)?
        .pointer("/error/class")
        .and_then(Value::as_str))
}
