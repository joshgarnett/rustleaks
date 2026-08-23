//! Exact recursive file-set discovery for the copied configuration fixtures.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn recursive_files(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("cannot read fixture entry: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            if kind.is_dir() {
                visit(root, &entry.path(), files)?;
            } else if kind.is_file() {
                files.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|error| format!("cannot relativize config fixture: {error}"))?
                        .to_owned(),
                );
            } else {
                return Err(format!(
                    "unsupported config fixture: {}",
                    entry.path().display()
                ));
            }
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    visit(root, root, &mut files)?;
    Ok(files)
}
