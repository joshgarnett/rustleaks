//! Timeout-bounded child processes with bounded diagnostics.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::tooling::support::{TempDir, command_status_with_timeout, diagnostic_tail};

pub(super) fn capture(
    command: &mut Command,
    label: &str,
    timeout: Duration,
) -> Result<String, String> {
    let temporary = TempDir::new("generator-command")?;
    let stdout_path = temporary.path.join("stdout");
    let stderr_path = temporary.path.join("stderr");
    let stdout = File::create(&stdout_path)
        .map_err(|error| format!("cannot create command stdout: {error}"))?;
    let stderr = File::create(&stderr_path)
        .map_err(|error| format!("cannot create command stderr: {error}"))?;
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Err(error) = command_status_with_timeout(command, timeout, label) {
        let diagnostic = read_diagnostic(&stderr_path);
        return Err(format!("{error}; stderr: {diagnostic}"));
    }
    let bytes =
        fs::read(&stdout_path).map_err(|error| format!("cannot read {label} stdout: {error}"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(format!("{label} stdout exceeded 1 MiB"));
    }
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{label} returned non-UTF-8 stdout: {error}"))
}

pub(super) fn status(command: &mut Command, label: &str, timeout: Duration) -> Result<(), String> {
    capture(command, label, timeout).map(|_| ())
}

fn read_diagnostic(path: &Path) -> String {
    fs::read(path).map_or_else(
        |error| format!("<cannot read: {error}>"),
        |bytes| diagnostic_tail(&bytes, 16 * 1024),
    )
}
