//! Bounded subprocess capture with deterministic Go environment settings.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::tooling::support::{command_status_with_timeout, diagnostic_tail};

const DIAGNOSTIC_LIMIT: usize = 16 * 1024;

pub(super) struct Runner {
    workspace: PathBuf,
    next: AtomicUsize,
}

impl Runner {
    pub(super) fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            next: AtomicUsize::new(0),
        }
    }

    pub(super) fn go_env(&self, command: &mut Command) {
        command
            .env("GOCACHE", self.workspace.join("go cache ü"))
            .env(
                "GOMODCACHE",
                std::env::var_os("GOMODCACHE").map_or_else(
                    || std::env::temp_dir().join("rustleaks-go-mod-cache"),
                    PathBuf::from,
                ),
            )
            .env("GOMAXPROCS", "2")
            .env("LC_ALL", "C")
            .env("TZ", "UTC");
    }

    pub(super) fn capture(
        &self,
        command: &mut Command,
        label: &str,
        timeout: Duration,
        limit: u64,
    ) -> Result<Vec<u8>, String> {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let stdout = self.workspace.join(format!("capture-{index:04}.stdout"));
        let stderr = self.workspace.join(format!("capture-{index:04}.stderr"));
        command
            .stdout(Stdio::from(create(&stdout)?))
            .stderr(Stdio::from(create(&stderr)?));
        command_status_with_timeout(command, timeout, label).map_err(|error| {
            let out = fs::read(&stdout).unwrap_or_default();
            let err = fs::read(&stderr).unwrap_or_default();
            format!(
                "{error}\nstdout:\n{}\nstderr:\n{}",
                diagnostic_tail(&out, DIAGNOSTIC_LIMIT),
                diagnostic_tail(&err, DIAGNOSTIC_LIMIT)
            )
        })?;
        let output = read_bounded(&stdout, limit)?;
        read_bounded(&stderr, limit)?;
        Ok(output)
    }
}

fn create(path: &Path) -> Result<File, String> {
    File::create(path).map_err(|error| format!("cannot create {}: {error}", path.display()))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
        .len();
    if size > limit {
        return Err(format!("{} exceeded {limit} bytes", path.display()));
    }
    let capacity = usize::try_from(size)
        .map_err(|error| format!("{} size does not fit usize: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::Runner;

    #[test]
    fn runner_workspace_accepts_spaces_and_unicode() {
        let runner = Runner::new("/tmp/composite runner ü".into());
        assert!(runner.workspace.ends_with("composite runner ü"));
    }
}
