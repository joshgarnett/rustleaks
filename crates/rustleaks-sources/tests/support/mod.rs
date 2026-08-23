//! Bazel runfile helpers shared by native Git integration tests.
#![allow(
    dead_code,
    reason = "each integration binary uses a different subset of these helpers"
)]

use std::path::{Path, PathBuf};

use rustleaks_sources::{Cancellation, GitSource, RemoteMetadata, ScmError, ScmPlatform};

pub fn git_executable() -> PathBuf {
    let runfile = PathBuf::from(
        std::env::var_os("RUSTLEAKS_TEST_GIT_RUNFILE").unwrap_or_else(|| "git".into()),
    );
    if runfile.is_absolute() {
        return runfile;
    }
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            let root = PathBuf::from(root);
            for candidate in [root.join(&runfile), root.join("_main").join(&runfile)] {
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        let key = runfile.to_string_lossy();
        let contents = std::fs::read_to_string(manifest).expect("read Bazel runfiles manifest");
        let external_key = key.strip_prefix("../");
        if let Some(resolved) = contents.lines().find_map(|line| {
            let (entry, resolved) = line.split_once(' ')?;
            (entry == key || external_key == Some(entry)).then_some(resolved)
        }) {
            return PathBuf::from(resolved);
        }
    }
    if runfile == Path::new("git") {
        return runfile;
    }
    panic!("cannot resolve declared Git runfile {runfile:?}");
}

pub fn git_source(repository: impl Into<PathBuf>) -> GitSource {
    GitSource::new(repository).executable(git_executable())
}

pub fn discover_remote(
    platform: ScmPlatform,
    repository: impl AsRef<Path>,
    cancellation: &dyn Cancellation,
) -> Result<RemoteMetadata, ScmError> {
    RemoteMetadata::discover_with_executable(
        platform,
        repository,
        git_executable().as_os_str(),
        cancellation,
    )
}

pub fn command() -> std::process::Command {
    std::process::Command::new(git_executable())
}
