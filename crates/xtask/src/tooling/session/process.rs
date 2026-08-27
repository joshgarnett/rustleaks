//! Fresh, bounded execution of every declarative session request.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use super::spec::{REQUEST_COUNT, REVISION};
use super::validation::{required_str, validate_envelope};
use super::{TempDir, newline_records, read};
use crate::tooling::support::{command_status_with_timeout, diagnostic_tail, go_module_cache};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const BUILD_TIMEOUT: Duration = Duration::from_secs(180);
const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;

pub(super) struct Observed {
    pub(super) bytes: Vec<u8>,
    pub(super) values: Vec<Value>,
}

pub(super) fn observe(
    root: &Path,
    upstream: &Path,
    requests: &[Value],
    request_bytes: &[u8],
    manifest: &Value,
    temporary: &TempDir,
) -> Result<Observed, String> {
    let go_version = selected_runtime(upstream, temporary)?;
    if required_str(manifest, "go_version", "manifest")? != go_version {
        return Err(format!(
            "selected Go version {go_version} differs from the committed session manifest"
        ));
    }
    let oracle_root = root.join("crates/rustleaks-compat/oracle");
    let binary = temporary.path.join(if cfg!(windows) {
        "session-oracle.exe"
    } else {
        "session-oracle"
    });
    let mut test = Command::new("go");
    test.current_dir(&oracle_root).args(["test", "./..."]);
    configure_go(&mut test, temporary);
    capture(&mut test, temporary, "oracle-test", BUILD_TIMEOUT)?;
    let mut build = Command::new("go");
    build
        .current_dir(&oracle_root)
        .args(["build", "-o"])
        .arg(&binary)
        .arg(".");
    configure_go(&mut build, temporary);
    capture(&mut build, temporary, "oracle-build", BUILD_TIMEOUT)?;

    let lines = newline_records(request_bytes, "session requests")?;
    if lines.len() != REQUEST_COUNT || lines.len() != requests.len() {
        return Err("session request parsing changed before oracle execution".into());
    }
    let mut bytes = Vec::new();
    let mut values = Vec::with_capacity(lines.len());
    for (index, (line, request)) in lines.iter().zip(requests).enumerate() {
        let id = required_str(request, "id", "request")?;
        let request_path = temporary.path.join(format!("request-{index:02}.jsonl"));
        fs::write(&request_path, line)
            .map_err(|error| format!("cannot write {}: {error}", request_path.display()))?;
        let stdin = File::open(&request_path)
            .map_err(|error| format!("cannot open {}: {error}", request_path.display()))?;
        let mut command = Command::new(&binary);
        command
            .current_dir(&oracle_root)
            .arg("--session")
            .stdin(Stdio::from(stdin));
        configure_go(&mut command, temporary);
        let raw = capture(
            &mut command,
            temporary,
            &format!("session-{index:02}"),
            PROCESS_TIMEOUT,
        )?;
        let outcome_lines = newline_records(&raw, &format!("{id} oracle output"))?;
        if outcome_lines.len() != 1 {
            return Err(format!(
                "{id}: oracle emitted {} JSONL records",
                outcome_lines.len()
            ));
        }
        let outcome: Value = serde_json::from_slice(outcome_lines[0])
            .map_err(|error| format!("{id}: invalid oracle JSON: {error}"))?;
        validate_envelope(request, &outcome, &go_version)?;
        bytes.extend_from_slice(outcome_lines[0]);
        values.push(outcome);
    }
    Ok(Observed { bytes, values })
}

pub(super) fn git_status(
    upstream: &Path,
    temporary: &TempDir,
    suffix: &str,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new("git");
    command
        .current_dir(upstream)
        .args(["status", "--short", "--untracked-files=no"]);
    capture(
        &mut command,
        temporary,
        &format!("upstream-status-{suffix}"),
        Duration::from_secs(30),
    )
}

fn selected_runtime(upstream: &Path, temporary: &TempDir) -> Result<String, String> {
    let mut command = Command::new("go");
    command.current_dir(upstream).args(["env", "GOVERSION"]);
    configure_go(&mut command, temporary);
    let output = capture(&mut command, temporary, "go-runtime", BUILD_TIMEOUT)?;
    let version = std::str::from_utf8(&output)
        .map_err(|error| format!("go env returned non-UTF-8 output: {error}"))?
        .trim();
    if !go_1_26(version) {
        return Err(format!(
            "selected Go toolchain {version} is not pinned to Go 1.26"
        ));
    }
    Ok(version.to_owned())
}

fn configure_go(command: &mut Command, temporary: &TempDir) {
    command
        .env("GOCACHE", temporary.path.join("go-cache"))
        .env("GOMODCACHE", go_module_cache(REVISION))
        .env(
            "GOMEMLIMIT",
            std::env::var_os("GOMEMLIMIT").unwrap_or_else(|| "512MiB".into()),
        )
        .env(
            "GOMAXPROCS",
            std::env::var_os("GOMAXPROCS").unwrap_or_else(|| "2".into()),
        );
}

pub(super) fn capture(
    command: &mut Command,
    temporary: &TempDir,
    label: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let safe_label = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let stdout_path = temporary.path.join(format!("{safe_label}.stdout"));
    let stderr_path = temporary.path.join(format!("{safe_label}.stderr"));
    let stdout = File::create(&stdout_path)
        .map_err(|error| format!("cannot create {}: {error}", stdout_path.display()))?;
    let stderr = File::create(&stderr_path)
        .map_err(|error| format!("cannot create {}: {error}", stderr_path.display()))?;
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Err(error) = command_status_with_timeout(command, timeout, label) {
        let stdout = fs::read(&stdout_path).unwrap_or_default();
        let stderr = fs::read(&stderr_path).unwrap_or_default();
        return Err(format!(
            "{error}\nstdout:\n{}\nstderr:\n{}",
            diagnostic_tail(&stdout, 16 * 1024),
            diagnostic_tail(&stderr, 16 * 1024)
        ));
    }
    let output = read(&stdout_path)?;
    if output.len() > OUTPUT_LIMIT {
        return Err(format!("{label}: stdout exceeded {OUTPUT_LIMIT} bytes"));
    }
    if fs::metadata(&stderr_path)
        .map_err(|error| format!("cannot inspect {}: {error}", stderr_path.display()))?
        .len()
        > OUTPUT_LIMIT as u64
    {
        return Err(format!("{label}: stderr exceeded {OUTPUT_LIMIT} bytes"));
    }
    Ok(output)
}

fn go_1_26(version: &str) -> bool {
    version == "go1.26"
        || version.strip_prefix("go1.26.").is_some_and(|patch| {
            !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::go_1_26;

    #[test]
    fn runtime_pin_rejects_other_release_shapes() {
        assert!(go_1_26("go1.26"));
        assert!(go_1_26("go1.26.0"));
        assert!(!go_1_26("go1.25"));
        assert!(!go_1_26("go1.26rc1"));
    }
}
