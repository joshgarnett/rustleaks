//! Verification of the independent pinned-upstream fixture copy.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::{REVISION, command_output};

use super::support::TempDir;

const FIXTURE_RECORD_SHA256: &str =
    "a29bcb807fc5466fb38bba0134fe6d5f41364e9efeae4980225cc21524fd4ed1";
#[allow(clippy::too_many_lines)] // Kept linear so every fixture invariant remains auditable.
pub(crate) fn verify_fixtures(root: &Path, oracle: &Path) -> Result<(), String> {
    let source = oracle.join("testdata");
    let copied = root.join("compat/fixtures/upstream/testdata");
    let temporary = TempDir::new("fixture-self-test")?;
    let flattened = temporary.path.join("flattened-link");
    fs::write(&flattened, b"../target")
        .map_err(|error| format!("cannot write fixture negative control: {error}"))?;
    if fs::symlink_metadata(&flattened)
        .map_err(|error| format!("cannot inspect fixture negative control: {error}"))?
        .file_type()
        .is_symlink()
    {
        return Err("flattened-symlink negative self-test unexpectedly passed".into());
    }

    let revision = command_output(
        Command::new("git")
            .current_dir(oracle)
            .args(["rev-parse", "HEAD"]),
    )?;
    if revision != REVISION {
        return Err(format!(
            "upstream revision mismatch: expected {REVISION}, got {revision}"
        ));
    }
    if !copied.is_dir() {
        return Err(format!("fixture copy is missing: {}", copied.display()));
    }
    let source_paths = fixture_entries(&source)?;
    let copy_paths = fixture_entries(&copied)?;
    if source_paths != copy_paths {
        let missing = source_paths
            .iter()
            .find(|path| copy_paths.binary_search(path).is_err())
            .map_or("<none>", String::as_str);
        let extra = copy_paths
            .iter()
            .find(|path| source_paths.binary_search(path).is_err())
            .map_or("<none>", String::as_str);
        return Err(format!(
            "fixture path mismatch; missing={missing}; extra={extra}"
        ));
    }
    let source_modes = git_modes(oracle, "testdata", "testdata/")?;
    let copy_modes = git_modes(
        root,
        "compat/fixtures/upstream/testdata",
        "compat/fixtures/upstream/testdata/",
    )?;
    if copy_modes.keys().cloned().collect::<Vec<_>>() != copy_paths {
        return Err("fixture copy is not completely tracked in Git".into());
    }

    let mut regular_records = Vec::new();
    let mut regular_count = 0_usize;
    let mut symlink_count = 0_usize;
    for relative in &source_paths {
        let source_path = source.join(relative);
        let copy_path = copied.join(relative);
        let mode = source_modes
            .get(relative)
            .ok_or_else(|| format!("upstream fixture is not tracked: {relative}"))?;
        let copy_mode = copy_modes
            .get(relative)
            .ok_or_else(|| format!("copied fixture is not tracked: {relative}"))?;
        if copy_mode != mode {
            return Err(format!(
                "fixture Git mode mismatch for {relative}: expected {mode}, got {copy_mode}"
            ));
        }
        if mode == "120000" {
            symlink_count += 1;
            let expected = symlink_target(&source_path, "upstream")?;
            let actual = symlink_target(&copy_path, "copied")?;
            if actual != expected {
                return Err(format!("symlink target mismatch for {relative}"));
            }
            continue;
        }
        regular_count += 1;
        let expected = fs::read(&source_path)
            .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
        let actual = fs::read(&copy_path)
            .map_err(|error| format!("cannot read {}: {error}", copy_path.display()))?;
        if actual.len() != expected.len() {
            return Err(format!("fixture size mismatch for {relative}"));
        }
        let expected_hash = hex_sha256(&expected);
        if hex_sha256(&actual) != expected_hash {
            return Err(format!("fixture content mismatch for {relative}"));
        }
        let expected_permissions = if mode == "100755" { 0o755 } else { 0o644 };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let actual_permissions = fs::metadata(&copy_path)
                .map_err(|error| format!("cannot inspect {}: {error}", copy_path.display()))?
                .permissions()
                .mode()
                & 0o777;
            if actual_permissions != expected_permissions {
                return Err(format!(
                    "fixture mode mismatch for {relative}: expected {expected_permissions:o}, got {actual_permissions:o}"
                ));
            }
        }
        regular_records.extend_from_slice(
            format!(
                "testdata/{relative}\t{expected_hash}\t{expected_permissions:o}\t{}\n",
                expected.len()
            )
            .as_bytes(),
        );
    }
    if regular_count != 214 {
        return Err(format!(
            "expected 214 regular fixtures, got {regular_count}"
        ));
    }
    if symlink_count != 1 {
        return Err(format!("expected one symlink fixture, got {symlink_count}"));
    }
    let record_hash = hex_sha256(&regular_records);
    if record_hash != FIXTURE_RECORD_SHA256 {
        return Err(format!(
            "fixture record digest mismatch: expected {FIXTURE_RECORD_SHA256}, got {record_hash}"
        ));
    }
    eprintln!(
        "verified {regular_count} regular fixtures and {symlink_count} symlink at upstream {REVISION}"
    );
    Ok(())
}

fn fixture_entries(root: &Path) -> Result<Vec<String>, String> {
    fn visit(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<(), String> {
        for entry in fs::read_dir(directory).map_err(|error| {
            format!(
                "cannot read fixture directory {}: {error}",
                directory.display()
            )
        })? {
            let entry = entry.map_err(|error| {
                format!(
                    "cannot read fixture entry in {}: {error}",
                    directory.display()
                )
            })?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            if file_type.is_dir() {
                visit(root, &entry.path(), output)?;
            } else {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| format!("cannot relativize fixture path: {error}"))?
                    .components()
                    .map(|component| match component {
                        Component::Normal(value) => value.to_string_lossy().into_owned(),
                        _ => String::new(),
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                output.push(relative);
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    visit(root, root, &mut output)?;
    output.sort();
    Ok(output)
}

fn git_modes(root: &Path, path: &str, prefix: &str) -> Result<BTreeMap<String, String>, String> {
    let listing = command_output(
        Command::new("git")
            .current_dir(root)
            .args(["ls-files", "-z", "-s", "--", path]),
    )?;
    parse_git_modes(&listing, prefix)
}

fn parse_git_modes(listing: &str, prefix: &str) -> Result<BTreeMap<String, String>, String> {
    let mut modes = BTreeMap::new();
    for line in listing.split('\0').filter(|line| !line.is_empty()) {
        let (metadata, listed_path) = line
            .split_once('\t')
            .ok_or_else(|| format!("malformed git ls-files line: {line}"))?;
        let mode = metadata
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("git ls-files line has no mode: {line}"))?;
        let relative = listed_path
            .strip_prefix(prefix)
            .ok_or_else(|| format!("git fixture path lacks {prefix} prefix: {listed_path}"))?;
        modes.insert(relative.to_owned(), mode.to_owned());
    }
    Ok(modes)
}

fn symlink_target(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} symlink {}: {error}", path.display()))?;
    if !metadata.file_type().is_symlink() {
        return Err(format!("{label} symlink is flattened: {}", path.display()));
    }
    fs::read_link(path)
        .map_err(|error| format!("cannot read {label} symlink {}: {error}", path.display()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::parse_git_modes;

    #[test]
    fn git_mode_records_preserve_spaces_and_non_ascii_paths() {
        let modes = parse_git_modes(
            "100644 abcdef 0\troot/path with spaces ü\0\
             120000 fedcba 0\troot/link\0",
            "root/",
        )
        .unwrap();
        assert_eq!(
            modes.get("path with spaces ü").map(String::as_str),
            Some("100644")
        );
        assert_eq!(modes.get("link").map(String::as_str), Some("120000"));
        assert!(parse_git_modes("100644 abcdef 0\twrong/path\0", "root/").is_err());
    }
}
