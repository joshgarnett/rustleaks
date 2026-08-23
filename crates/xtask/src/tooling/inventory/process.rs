use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::tooling::support::{TempDir, command_status_with_timeout};

pub(super) fn capture(
    command: &mut Command,
    temporary: &TempDir,
    label: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let safe_label = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let stdout_path = temporary.path.join(format!("{safe_label}.stdout"));
    let stderr_path = temporary.path.join(format!("{safe_label}.stderr"));
    let stdout = fs::File::create(&stdout_path)
        .map_err(|error| format!("cannot create {}: {error}", stdout_path.display()))?;
    let stderr = fs::File::create(&stderr_path)
        .map_err(|error| format!("cannot create {}: {error}", stderr_path.display()))?;
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Err(error) = command_status_with_timeout(command, timeout, label) {
        let diagnostics = fs::read(&stderr_path).unwrap_or_default();
        return Err(format!(
            "{error}\nstderr:\n{}",
            String::from_utf8_lossy(&diagnostics)
        ));
    }
    fs::read(&stdout_path)
        .map_err(|error| format!("cannot read {}: {error}", stdout_path.display()))
}

pub(super) fn git_capture(
    upstream: &Path,
    temporary: &TempDir,
    label: &str,
    args: &[&str],
) -> Result<Vec<u8>, String> {
    capture(
        Command::new("git").current_dir(upstream).args(args),
        temporary,
        label,
        Duration::from_secs(30),
    )
}
