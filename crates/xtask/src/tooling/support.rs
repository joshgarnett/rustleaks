//! Shared filesystem support for repository tooling.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct TempDir {
    pub(super) path: PathBuf,
}

impl TempDir {
    pub(super) fn new(label: &str) -> Result<Self, String> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rustleaks-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).map_err(|error| {
            format!(
                "cannot create temporary directory {}: {error}",
                path.display()
            )
        })?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let is_scoped = self.path.parent() == Some(std::env::temp_dir().as_path())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rustleaks-"));
        if is_scoped {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
