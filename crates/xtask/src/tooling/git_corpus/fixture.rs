//! Byte-stable fingerprinting of the shared repository fixtures.

use std::fs;
use std::path::Path;

use serde_json::json;

use crate::tooling::support::sha256_bytes;

const PORTABLE_SYMLINKS: &[(&str, &str)] = &[(
    "symlinks/file_symlink/symlinked_id_ed25519",
    "../source_file/id_ed25519",
)];

pub(super) fn tree_fingerprint(root: &Path) -> Result<String, String> {
    let mut records = Vec::new();
    visit(root, root, &mut records)?;
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let projected = records
        .into_iter()
        .map(|(path, mode, payload)| json!([path, mode, payload]))
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&projected)
        .map_err(|error| format!("cannot serialize fixture fingerprint: {error}"))?;
    Ok(sha256_bytes(&bytes))
}

fn visit(
    root: &Path,
    directory: &Path,
    records: &mut Vec<(String, u32, String)>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot walk {}: {error}", directory.display()))?
    {
        let path = entry
            .map_err(|error| format!("cannot read entry in {}: {error}", directory.display()))?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("cannot relativize {}: {error}", path.display()))?
            .to_str()
            .ok_or_else(|| format!("fixture path {} is not UTF-8", path.display()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let symlink_target = projected_symlink_target(&relative, &path, &metadata)?;
        let payload = if let Some(target) = &symlink_target {
            format!("link:{target}")
        } else if metadata.is_file() {
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            format!("file:{}", sha256_bytes(&bytes))
        } else {
            "dir".to_owned()
        };
        records.push((
            relative,
            permission_mode(&metadata, symlink_target.is_some()),
            payload,
        ));
        if metadata.is_dir() {
            visit(root, &path, records)?;
        }
    }
    Ok(())
}

fn projected_symlink_target(
    relative: &str,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<String>, String> {
    let expected = PORTABLE_SYMLINKS
        .iter()
        .find_map(|(candidate, target)| (*candidate == relative).then_some(*target));
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)
            .map_err(|error| format!("cannot read symlink {}: {error}", path.display()))?;
        let target = target
            .to_str()
            .ok_or_else(|| format!("symlink target {} is not UTF-8", target.display()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if expected.is_some_and(|expected| expected != target) {
            return Err(format!("fixture symlink {relative} target changed"));
        }
        return Ok(Some(target));
    }
    if let Some(_expected) = expected {
        #[cfg(windows)]
        {
            if fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?
                != _expected.as_bytes()
            {
                return Err(format!("materialized fixture symlink {relative} changed"));
            }
            return Ok(Some(_expected.to_owned()));
        }
        #[cfg(not(windows))]
        {
            return Err(format!("fixture path {relative} is not a symlink"));
        }
    }
    Ok(None)
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata, projected_symlink: bool) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    portable_permission_mode(projected_symlink, metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn permission_mode(metadata: &fs::Metadata, projected_symlink: bool) -> u32 {
    portable_windows_permission_mode(
        projected_symlink,
        metadata.is_dir(),
        metadata.permissions().readonly(),
    )
}

fn portable_permission_mode(is_symlink: bool, mode: u32) -> u32 {
    // Symlink permission bits are not portable or chmod-controlled. The link
    // type and target remain in the fingerprint, while the accepted fixture
    // projection uses one stable value on every host.
    if is_symlink { 0o755 } else { mode }
}

#[cfg(any(not(unix), test))]
fn portable_windows_permission_mode(is_symlink: bool, is_directory: bool, readonly: bool) -> u32 {
    if is_symlink || is_directory {
        0o755
    } else if readonly {
        0o444
    } else {
        0o644
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{portable_permission_mode, portable_windows_permission_mode, tree_fingerprint};

    #[test]
    fn normalizes_host_symlink_permission_bits() {
        assert_eq!(portable_permission_mode(true, 0o755), 0o755);
        assert_eq!(portable_permission_mode(true, 0o777), 0o755);
        assert_eq!(portable_permission_mode(false, 0o644), 0o644);
    }

    #[test]
    fn projects_windows_fixture_permissions() {
        assert_eq!(portable_windows_permission_mode(true, false, false), 0o755);
        assert_eq!(portable_windows_permission_mode(false, true, false), 0o755);
        assert_eq!(portable_windows_permission_mode(false, false, false), 0o644);
        assert_eq!(portable_windows_permission_mode(false, false, true), 0o444);
    }

    #[test]
    fn fingerprints_spaces_unicode_and_bytes() {
        let root = std::env::temp_dir().join(format!("git fixture Ω {}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("é file.bin"), [0, 255, 10]).unwrap();
        let first = tree_fingerprint(&root).unwrap();
        let second = tree_fingerprint(&root).unwrap();
        assert_eq!(first, second);
        fs::remove_dir_all(root).unwrap();
    }
}
