//! Offline integrity of immutable historical compatibility evidence.
//!
//! It does not observe upstream code, generate expected outcomes, or claim
//! fresh parity.

#[path = "frozen_manifest.rs"]
mod manifest;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::support::sha256_bytes;

/// Directories of frozen historical evidence.
pub(crate) const FROZEN_DIRECTORIES: &[&str] = manifest::DIRECTORIES;

/// Returns the paths of individually listed frozen historical artifacts.
pub(crate) fn frozen_artifact_paths() -> impl Iterator<Item = &'static str> {
    manifest::ARTIFACTS.iter().map(|(path, _, _)| *path)
}

/// Checks frozen evidence. The frozen bytes, modes and path sets are pinned by
/// [`verify_tree`]; the other checks read state that those hashes do not cover:
/// the Git index modes of the upstream fixtures, the maintained presentation
/// ledger, and the Rust source symbols that the API dispositions name.
pub(crate) fn check_frozen_evidence(root: &Path) -> Result<(), String> {
    verify_tree(root, manifest::ARTIFACTS, manifest::DIRECTORIES)?;
    super::presentation::check_ledger(root)?;
    super::fixtures::verify_fixtures(root)?;
    check_api_source_symbols(root)?;
    println!(
        "verified {} immutable evidence files, fixture Git modes, the presentation ledger and API source symbols; runtime replays run separately",
        manifest::ARTIFACTS.len()
    );
    Ok(())
}

/// Checks that the `rustleaks-sources` symbols that implemented API
/// dispositions name still exist in the current source.
fn check_api_source_symbols(root: &Path) -> Result<(), String> {
    let path = root.join("compat/api-dispositions-v1.jsonl");
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut implemented = BTreeSet::new();
    for line in text.lines() {
        let row: Value =
            serde_json::from_str(line).map_err(|error| format!("{}: {error}", path.display()))?;
        if row["implementation_status"] == "implemented"
            && let Some(rust_path) = row["rust_path"].as_str()
        {
            implemented.insert(rust_path.to_owned());
        }
    }
    for (symbol, relative, needle) in [
        (
            "rustleaks_sources::FileSource",
            "file.rs",
            "pub struct FileSource",
        ),
        (
            "rustleaks_sources::DirectorySource",
            "directory.rs",
            "pub struct DirectorySource",
        ),
        (
            "rustleaks_sources::SourceRunner",
            "runner.rs",
            "pub struct SourceRunner",
        ),
        (
            "rustleaks_sources::ArchiveLimits::new",
            "archive.rs",
            "pub fn new(",
        ),
        (
            "rustleaks_sources::DirectoryOptions::follow_symlinks",
            "directory.rs",
            "pub const fn follow_symlinks(",
        ),
    ] {
        if implemented.contains(symbol) {
            let path = root.join("crates/rustleaks-sources/src").join(relative);
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            if !source.contains(needle) {
                return Err(format!("implemented source symbol disappeared: {symbol}"));
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{check_api_source_symbols, sha256_bytes, verify_tree};
    use crate::tooling::support::ScopedTempDir;
    use std::fs;

    #[test]
    fn frozen_tree_rejects_changed_missing_extra_and_substituted_files() {
        let temporary = ScopedTempDir::new("frozen-integrity").unwrap();
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

    #[cfg(unix)]
    #[test]
    fn frozen_tree_rejects_executable_and_symlink_mutations() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let temporary = ScopedTempDir::new("frozen-modes").unwrap();
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

    #[test]
    fn api_source_symbols_exist() {
        check_api_source_symbols(&crate::workspace_root().unwrap()).unwrap();
    }
}
