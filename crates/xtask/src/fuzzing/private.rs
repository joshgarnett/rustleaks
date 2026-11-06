//! Private local storage. This deliberately has no Windows ACL fallback.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

pub(crate) fn supported() -> Result<(), String> {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        Ok(())
    } else {
        Err("private fuzz retention is unsupported on this host; Linux/macOS permission and process-group support is required".into())
    }
}

pub(crate) fn directory(path: &Path) -> Result<(), String> {
    supported()?;
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    builder.create(path).map_err(|error| error.to_string())
}

pub(crate) fn file(path: &Path) -> Result<File, String> {
    supported()?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| error.to_string())
}

pub(crate) fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    file(path)?
        .write_all(bytes)
        .map_err(|error| error.to_string())
}

pub(crate) fn json(path: &Path, value: &Value) -> Result<(), String> {
    // The destination directory is private and owned by this process. A new
    // file and atomic rename preserve the previous complete record on errors.
    let temporary = path.with_extension(format!("{}.tmp", nonce()?));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write(&temporary, &bytes)?;
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

pub(crate) fn read_json(path: &Path) -> Result<Value, String> {
    regular_file(path, 16 * 1024 * 1024)?;
    serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|_| "invalid private manifest".into())
}

/// Reject traversal and symlinks in every user-supplied path component.
/// Callers on macOS should use /private/tmp instead of its /tmp symlink.
pub(crate) fn checked_path(path: &Path) -> Result<PathBuf, String> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(path)
    };
    let mut inspected = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err("path traversal is forbidden".into());
        }
        inspected.push(component);
        let metadata = fs::symlink_metadata(&inspected).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("symlinks are forbidden in private fuzz inputs".into());
        }
    }
    Ok(path)
}

pub(crate) fn regular_file(path: &Path, maximum: u64) -> Result<(), String> {
    checked_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err("fuzz input is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err("hard-linked fuzz inputs are forbidden".into());
        }
    }
    Ok(())
}

fn nonce() -> Result<String, String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    Ok(format!(
        "{}-{time}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(crate) struct Bundle {
    pub(crate) path: PathBuf,
    pub(crate) id: String,
    keep_success: bool,
}

impl Bundle {
    pub(crate) fn new(output: Option<&Path>) -> Result<Self, String> {
        supported()?;
        let id = nonce()?;
        let path = if let Some(output) = output {
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
            checked_path(&parent)?;
            parent.join(output.file_name().ok_or("output has no file name")?)
        } else {
            fs::canonicalize(std::env::temp_dir())
                .map_err(|error| error.to_string())?
                .join(format!("rustleaks-private-fuzz-{id}"))
        };
        directory(&path)?;
        Ok(Self {
            path,
            id,
            keep_success: output.is_some(),
        })
    }

    pub(crate) fn retaining_success(mut self) -> Self {
        self.keep_success = true;
        self
    }

    // No Drop cleanup: unexpected returns and unwinding must retain evidence.
    pub(crate) fn finish(self, result: Result<(), String>) -> Result<(), String> {
        self.finish_named(result, "fuzz")
    }

    pub(crate) fn finish_named(
        self,
        result: Result<(), String>,
        label: &str,
    ) -> Result<(), String> {
        match result {
            Ok(()) => {
                if self.keep_success {
                    println!("{label}: success; private bundle {} retained", self.id);
                } else {
                    fs::remove_dir_all(&self.path).map_err(|_| {
                        format!(
                            "{label}: cleanup-failure; private bundle {} retained",
                            self.id
                        )
                    })?;
                    println!("{label}: success; private scratch bundle cleaned");
                }
                Ok(())
            }
            Err(error) => {
                let _ = write(&self.path.join("failure.txt"), error.as_bytes());
                let mut manifest = read_json(&self.path.join("bundle.json"))
                    .unwrap_or_else(|_| serde_json::json!({"schema_version": 1, "id": self.id}));
                manifest["state"] = serde_json::json!("failure");
                let _ = json(&self.path.join("bundle.json"), &manifest);
                Err(format!(
                    "{label}: failure; private bundle {} retained; inspect its manifest locally",
                    self.id
                ))
            }
        }
    }
}
