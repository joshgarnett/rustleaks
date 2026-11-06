//! Offline integrity of immutable historical compatibility evidence.
//!
//! This validates stored evidence and its retained Rust test mappings. It does
//! not observe upstream code, generate expected outcomes, or claim fresh parity.

#[path = "frozen_manifest.rs"]
mod manifest;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::support::sha256_bytes;

const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
const CONFIG_SHA256: &str = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

pub(crate) fn check_frozen_evidence(root: &Path) -> Result<(), String> {
    verify_tree(root, manifest::ARTIFACTS, manifest::DIRECTORIES)?;
    super::fixtures::verify_fixtures(root)?;
    super::inventory::check_inventory(root, &root.join("compat/test-manifest.toml"))?;
    super::traceability::api::self_test_api_dispositions(
        root,
        &root.join("compat/api-dispositions-v1.jsonl"),
    )?;
    super::traceability::generator_samples::check_generator_samples(
        &root.join("compat/generator-corpus"),
    )?;
    let assertion_root = root.join("compat/assertion-corpus");
    super::traceability::assertions::validate_final_traceability(
        &read_text(&assertion_root.join("assertions.jsonl"))?,
        &read_text(&assertion_root.join("benchmark-links.jsonl"))?,
        &read_text(&assertion_root.join("platform-skips.jsonl"))?,
    )?;
    for scope in ["regex", "detect", "allowlist", "decoder"] {
        let corpus = root.join(format!("compat/{scope}-corpus"));
        validate_pairs(
            &read_rows(&corpus.join("requests-v1.jsonl"))?,
            &read_rows(&corpus.join("outcomes-v1.jsonl"))?,
            Some(scope),
        )?;
    }
    validate_bootstrap(root)?;
    super::config::check_config_corpus(root)?;
    super::composite::check_composite_corpus(root)?;
    super::session::check_session_corpus(root)?;
    super::source::check_source_corpus(root)?;
    super::git_corpus::check_git_corpus(root)?;
    super::report::check_report_corpus(root)?;
    println!(
        "verified {} immutable evidence files and retained local integrity controls; runtime replays run separately",
        manifest::ARTIFACTS.len()
    );
    Ok(())
}

pub(super) fn verify_artifact(root: &Path, relative: &str) -> Result<(), String> {
    let (_, mode, hash) = manifest::ARTIFACTS
        .iter()
        .find(|(path, _, _)| *path == relative)
        .ok_or_else(|| format!("unregistered frozen artifact {relative}"))?;
    verify_file(root, relative, mode, hash)
}

fn verify_tree(
    root: &Path,
    entries: &[(&str, &str, &str)],
    directories: &[&str],
) -> Result<(), String> {
    let mut expected = BTreeSet::new();
    for (path, mode, hash) in entries {
        if !expected.insert(PathBuf::from(path)) {
            return Err(format!("duplicate frozen artifact {path}"));
        }
        verify_file(root, path, mode, hash)?;
    }
    for directory in directories {
        let expected = expected
            .iter()
            .filter(|path| path.starts_with(directory))
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut actual = BTreeSet::new();
        collect_paths(root, &root.join(directory), &mut actual)?;
        if expected != actual {
            return Err(format!("frozen artifact path set changed in {directory}"));
        }
    }
    Ok(())
}

fn verify_file(root: &Path, relative: &str, mode: &str, expected: &str) -> Result<(), String> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect frozen artifact {relative}: {error}"))?;
    let bytes = if mode == "120000" {
        if !metadata.file_type().is_symlink() {
            return Err(format!("frozen symlink was flattened: {relative}"));
        }
        fs::read_link(&path)
            .map_err(|error| format!("cannot read symlink {relative}: {error}"))?
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 symlink target: {relative}"))?
            .as_bytes()
            .to_vec()
    } else {
        if !metadata.file_type().is_file() || !matches!(mode, "100644" | "100755") {
            return Err(format!("frozen artifact kind changed: {relative}"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let executable = metadata.permissions().mode() & 0o111 != 0;
            if executable != (mode == "100755") {
                return Err(format!("frozen executable mode changed: {relative}"));
            }
        }
        fs::read(&path)
            .map_err(|error| format!("cannot read frozen artifact {relative}: {error}"))?
    };
    if sha256_bytes(&bytes) != expected {
        return Err(format!("frozen artifact bytes changed: {relative}"));
    }
    Ok(())
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    paths: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            collect_paths(root, &entry.path(), paths)?;
        } else {
            paths.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn validate_pairs(
    requests: &[Value],
    outcomes: &[Value],
    mode: Option<&str>,
) -> Result<(), String> {
    if requests.is_empty() || requests.len() != outcomes.len() {
        return Err("frozen request/outcome count mismatch".into());
    }
    let mut ids = BTreeSet::new();
    for (request, outcome) in requests.iter().zip(outcomes) {
        let id = request["id"].as_str().ok_or("frozen request lacks ID")?;
        if !ids.insert(id) || outcome["id"].as_str() != Some(id) {
            return Err(format!(
                "frozen outcome ID missing, duplicated, or reordered: {id}"
            ));
        }
        if outcome["upstream_revision"] != REVISION
            || outcome["default_config_sha256"] != CONFIG_SHA256
            || mode.is_some_and(|mode| outcome["oracle_mode"] != mode)
        {
            return Err(format!("frozen outcome provenance changed: {id}"));
        }
    }
    Ok(())
}

fn validate_bootstrap(root: &Path) -> Result<(), String> {
    let corpus = root.join("compat/oracle-corpus");
    let requests = read_rows(&corpus.join("bootstrap-input.jsonl"))?;
    let outcomes = read_rows(&corpus.join("bootstrap-golden.jsonl"))?;
    validate_pairs(&requests, &outcomes, None)?;
    let dispositions = BTreeMap::from([
        ("custom-basic", "detector-and-source-link"),
        ("custom-invalid-utf8", "detector"),
        ("custom-allow-marker", "detector"),
        ("malformed-regex-panic", "safe-config-error"),
        ("wrong-protocol", "retired-go-adapter"),
    ]);
    if requests.len() != dispositions.len()
        || requests.iter().any(|request| {
            !request["id"]
                .as_str()
                .is_some_and(|id| dispositions.contains_key(id))
        })
    {
        return Err("bootstrap disposition identity set changed".into());
    }
    println!(
        "bootstrap accounting: 3 Rust detector cases, 1 source-link delegate, 1 safe configuration error, 1 retired Go protocol adapter"
    );
    Ok(())
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn read_rows(path: &Path) -> Result<Vec<Value>, String> {
    let text = read_text(path)?;
    if !text.ends_with('\n') {
        return Err(format!("{} lacks final newline", path.display()));
    }
    text.lines()
        .map(|line| {
            serde_json::from_str(line).map_err(|error| format!("{}: {error}", path.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{sha256_bytes, validate_pairs, verify_tree};
    use crate::tooling::support::TempDir;
    use serde_json::json;
    use std::fs;

    #[test]
    fn frozen_tree_rejects_changed_missing_extra_and_substituted_files() {
        let temporary = TempDir::new("frozen-integrity").unwrap();
        let root = &temporary.path;
        fs::create_dir(root.join("corpus")).unwrap();
        fs::write(root.join("corpus/outcomes"), b"accepted\n").unwrap();
        let hash = sha256_bytes(b"accepted\n");
        let entries = [("corpus/outcomes", "100644", hash.as_str())];
        verify_tree(root, &entries, &["corpus"]).unwrap();
        fs::write(root.join("corpus/outcomes"), b"changed\n").unwrap();
        assert!(verify_tree(root, &entries, &["corpus"]).is_err());
        fs::remove_file(root.join("corpus/outcomes")).unwrap();
        assert!(verify_tree(root, &entries, &["corpus"]).is_err());
        fs::write(root.join("corpus/outcomes"), b"accepted\n").unwrap();
        fs::write(root.join("corpus/extra"), b"accepted\n").unwrap();
        assert!(verify_tree(root, &entries, &["corpus"]).is_err());
    }

    #[test]
    fn frozen_identity_join_rejects_missing_swapped_and_duplicate_ids() {
        let requests = [json!({"id":"first"}), json!({"id":"second"})];
        let outcomes = requests
            .iter()
            .map(|request| {
                json!({"id":request["id"],
            "upstream_revision":super::REVISION, "default_config_sha256":super::CONFIG_SHA256,
            "oracle_mode":"detect"})
            })
            .collect::<Vec<_>>();
        validate_pairs(&requests, &outcomes, Some("detect")).unwrap();
        assert!(validate_pairs(&requests, &outcomes[..1], Some("detect")).is_err());
        assert!(
            validate_pairs(
                &requests,
                &[outcomes[1].clone(), outcomes[0].clone()],
                Some("detect")
            )
            .is_err()
        );
        assert!(
            validate_pairs(
                &[requests[0].clone(), requests[0].clone()],
                &[outcomes[0].clone(), outcomes[0].clone()],
                Some("detect")
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn frozen_tree_rejects_executable_and_symlink_mutations() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let temporary = TempDir::new("frozen-modes").unwrap();
        let root = &temporary.path;
        fs::create_dir(root.join("corpus")).unwrap();
        fs::write(root.join("corpus/file"), b"frozen").unwrap();
        symlink("file", root.join("corpus/link")).unwrap();
        let file_hash = sha256_bytes(b"frozen");
        let link_hash = sha256_bytes(b"file");
        let entries = [
            ("corpus/file", "100644", file_hash.as_str()),
            ("corpus/link", "120000", link_hash.as_str()),
        ];
        verify_tree(root, &entries, &["corpus"]).unwrap();
        fs::set_permissions(root.join("corpus/file"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_tree(root, &entries, &["corpus"]).is_err());
        fs::set_permissions(root.join("corpus/file"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(root.join("corpus/link")).unwrap();
        fs::write(root.join("corpus/link"), b"file").unwrap();
        assert!(verify_tree(root, &entries, &["corpus"]).is_err());
        fs::remove_file(root.join("corpus/link")).unwrap();
        symlink("elsewhere", root.join("corpus/link")).unwrap();
        assert!(verify_tree(root, &entries, &["corpus"]).is_err());
    }
}
