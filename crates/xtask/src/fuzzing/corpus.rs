//! Bounded content-addressed corpora and explicit local review receipts.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::private;
use crate::tooling::sha256_bytes;

pub(super) const MAX_FILES: usize = 16_384;
pub(super) const MAX_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn check_bounds(directory: &Path, max_len: u64) -> Result<(), String> {
    check_bounds_with_metadata(directory, max_len, |path| fs::symlink_metadata(path))
}

fn check_bounds_with_metadata(
    directory: &Path,
    max_len: u64,
    mut metadata: impl FnMut(&Path) -> std::io::Result<fs::Metadata>,
) -> Result<(), String> {
    let mut count = 0;
    let mut bytes = 0_u64;
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let metadata = match metadata(&entry.path()) {
            Ok(metadata) => metadata,
            // libFuzzer may remove a redundant output-corpus unit after this
            // live iterator yielded it. Stable inventory/import stays strict.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        count += 1;
        bytes = bytes.saturating_add(metadata.len());
        if !metadata.is_file() || metadata.len() > max_len || count > MAX_FILES || bytes > MAX_BYTES
        {
            return Err("live corpus or artifact limit exceeded".into());
        }
    }
    Ok(())
}

pub(super) fn inventory(directory: &Path, max_len: u64) -> Result<Value, String> {
    private::checked_path(directory)?;
    let mut entries = BTreeMap::new();
    let mut bytes = 0_u64;
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entries.len() >= MAX_FILES {
            return Err("corpus file limit exceeded".into());
        }
        private::regular_file(&entry.path(), max_len)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF-8 corpus name")?;
        let content = fs::read(entry.path()).map_err(|error| error.to_string())?;
        bytes = bytes
            .checked_add(content.len() as u64)
            .ok_or("corpus size overflow")?;
        if bytes > MAX_BYTES {
            return Err("corpus byte limit exceeded".into());
        }
        entries.insert(
            name,
            json!({"sha256": sha256_bytes(&content), "bytes": content.len()}),
        );
    }
    let records = serde_json::to_vec(&entries).map_err(|error| error.to_string())?;
    Ok(json!({"sha256": sha256_bytes(&records), "bytes": bytes, "files": entries}))
}

pub(super) fn copy(source: &Path, destination: &Path, max_len: u64) -> Result<Value, String> {
    let before = inventory(source, max_len)?;
    for (name, record) in before["files"]
        .as_object()
        .ok_or("missing corpus records")?
    {
        let content = fs::read(source.join(name)).map_err(|error| error.to_string())?;
        if record["sha256"] != sha256_bytes(&content) {
            return Err("corpus changed while importing".into());
        }
        // Hash names eliminate path and filename collisions across seed sets.
        let destination = destination.join(record["sha256"].as_str().ok_or("invalid corpus hash")?);
        if destination.exists() {
            private::regular_file(&destination, max_len)?;
            if fs::read(&destination).map_err(|error| error.to_string())? != content {
                return Err("corpus content hash collision".into());
            }
        } else {
            private::write(&destination, &content)?;
        }
    }
    inventory(destination, max_len)
}

pub(super) fn verify(directory: &Path, expected: &Value, max_len: u64) -> Result<(), String> {
    if &inventory(directory, max_len)? != expected {
        return Err("corpus provenance mismatch".into());
    }
    Ok(())
}

pub(super) fn import(
    reviewed: &Path,
    destination: &Path,
    identity: &Value,
    target: &str,
    max_len: u64,
) -> Result<(), String> {
    let manifest = private::read_json(&reviewed.join("review.json"))?;
    if manifest["schema_version"] != 1
        || manifest["state"] != "reviewed-local-corpus"
        || &manifest["identity"] != identity
        || manifest["target"] != target
        || manifest["reviewed_sha256"] != manifest["corpus"]["sha256"]
    {
        return Err("reviewed corpus identity or review receipt mismatch".into());
    }
    verify(&reviewed.join("corpus"), &manifest["corpus"], max_len)?;
    copy(&reviewed.join("corpus"), destination, max_len)?;
    Ok(())
}

pub(super) fn promote(
    source: &Path,
    destination: &Path,
    record: &Value,
    reviewed_hash: &str,
    max_len: u64,
) -> Result<(), String> {
    // A CI-produced receipt is not a human content/provenance review. This
    // command is intentionally local; the receipt is not a signature or an
    // authorization mechanism against malicious code running as this user.
    if std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some() {
        return Err("corpus promotion is a local manual review operation".into());
    }
    promote_reviewed(source, destination, record, reviewed_hash, max_len)
}

pub(super) fn promote_reviewed(
    source: &Path,
    destination: &Path,
    record: &Value,
    reviewed_hash: &str,
    max_len: u64,
) -> Result<(), String> {
    if record["operation"] != "minimize"
        || record["outcome"] != "success"
        || record["final_corpus"]["sha256"].as_str() != Some(reviewed_hash)
    {
        return Err(
            "promotion requires a successful minimized corpus and its reviewed content hash".into(),
        );
    }
    verify(source, &record["final_corpus"], max_len)?;
    let corpus = destination.join("corpus");
    private::directory(&corpus)?;
    let inventory = copy(source, &corpus, max_len)?;
    // Input is already hash-named after minimization, so the reviewed digest
    // must survive the promotion unchanged.
    if inventory != record["final_corpus"] {
        return Err("promotion changed the reviewed corpus identity".into());
    }
    private::json(
        &destination.join("review.json"),
        &json!({
            "schema_version": 1, "state": "reviewed-local-corpus",
            "target": record["target"], "identity": record["identity"],
            "source_record_sha256": sha256_bytes(&serde_json::to_vec(record).map_err(|error| error.to_string())?),
            "reviewed_sha256": reviewed_hash, "corpus": inventory,
            "review_scope": "operator acknowledged content and provenance after private review; no public promotion",
        }),
    )
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod live_tests {
    use super::*;
    use std::io;

    #[test]
    fn live_monitor_tolerates_an_enumerated_unit_removed_before_stat() {
        let bundle = private::Bundle::new(None).unwrap();
        let corpus = bundle.path.join("corpus");
        private::directory(&corpus).unwrap();
        private::write(&corpus.join("transient"), b"unit").unwrap();
        let stable = inventory(&corpus, 4).unwrap();
        let mut observed = 0;
        check_bounds_with_metadata(&corpus, 4, |path| {
            observed += 1;
            fs::remove_file(path)?;
            fs::symlink_metadata(path)
        })
        .unwrap();
        assert_eq!(observed, 1);
        assert!(verify(&corpus, &stable, 4).is_err());
        fs::remove_dir_all(&bundle.path).unwrap();
    }

    #[test]
    fn missing_unit_does_not_hide_a_surviving_oversized_unit() {
        let bundle = private::Bundle::new(None).unwrap();
        let corpus = bundle.path.join("corpus");
        private::directory(&corpus).unwrap();
        for name in ["first", "second"] {
            private::write(&corpus.join(name), b"large").unwrap();
        }
        let mut observed = 0;
        let error = check_bounds_with_metadata(&corpus, 4, |path| {
            observed += 1;
            if observed == 1 {
                fs::remove_file(path)?;
            }
            fs::symlink_metadata(path)
        })
        .unwrap_err();
        assert_eq!(observed, 2);
        assert_eq!(error, "live corpus or artifact limit exceeded");
        fs::remove_dir_all(&bundle.path).unwrap();
    }

    #[test]
    fn live_monitor_preserves_other_stat_errors_and_missing_directory_errors() {
        let bundle = private::Bundle::new(None).unwrap();
        let corpus = bundle.path.join("corpus");
        private::directory(&corpus).unwrap();
        private::write(&corpus.join("unit"), b"unit").unwrap();
        let error = check_bounds_with_metadata(&corpus, 4, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic stat denied",
            ))
        })
        .unwrap_err();
        assert_eq!(error, "synthetic stat denied");
        let mut called = false;
        assert!(
            check_bounds_with_metadata(&bundle.path.join("missing"), 4, |path| {
                called = true;
                fs::symlink_metadata(path)
            })
            .is_err()
        );
        assert!(!called);
        assert!(inventory(&bundle.path.join("missing"), 4).is_err());
        fs::remove_dir_all(&bundle.path).unwrap();
    }

    #[test]
    fn live_monitor_still_rejects_symlinks_and_subdirectories() {
        let bundle = private::Bundle::new(None).unwrap();
        let corpus = bundle.path.join("corpus");
        private::directory(&corpus).unwrap();
        private::write(&bundle.path.join("target"), b"unit").unwrap();
        std::os::unix::fs::symlink(bundle.path.join("target"), corpus.join("link")).unwrap();
        assert!(check_bounds(&corpus, 4).is_err());
        fs::remove_file(corpus.join("link")).unwrap();
        private::directory(&corpus.join("nested")).unwrap();
        assert!(check_bounds(&corpus, 4).is_err());
        fs::remove_dir_all(&bundle.path).unwrap();
    }

    #[test]
    fn live_monitor_keeps_aggregate_byte_limit_inclusive() {
        let bundle = private::Bundle::new(None).unwrap();
        let corpus = bundle.path.join("corpus");
        private::directory(&corpus).unwrap();
        for name in ["first", "second"] {
            private::write(&corpus.join(name), b"unit").unwrap();
        }
        let backing = bundle.path.join("sparse-metadata-control");
        let file = private::file(&backing).unwrap();
        file.set_len(MAX_BYTES / 2).unwrap();
        check_bounds_with_metadata(&corpus, MAX_BYTES, |_| fs::symlink_metadata(&backing)).unwrap();
        file.set_len(MAX_BYTES / 2 + 1).unwrap();
        assert!(
            check_bounds_with_metadata(&corpus, MAX_BYTES, |_| fs::symlink_metadata(&backing))
                .is_err()
        );
        fs::remove_dir_all(&bundle.path).unwrap();
    }
}
