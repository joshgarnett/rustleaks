//! Byte-stable fingerprinting of the shared repository fixtures.

use std::fs;
use std::path::Path;

use serde_json::json;

use crate::tooling::support::sha256_bytes;

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
        let payload = if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|error| format!("cannot read symlink {}: {error}", path.display()))?;
            format!("link:{}", target.display())
        } else if metadata.is_file() {
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            format!("file:{}", sha256_bytes(&bytes))
        } else {
            "dir".to_owned()
        };
        records.push((relative, permission_mode(&metadata), payload));
        if metadata.is_dir() {
            visit(root, &path, records)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o666
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::tree_fingerprint;

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
