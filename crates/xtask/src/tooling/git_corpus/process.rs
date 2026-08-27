//! Fresh, bounded execution of each Git request.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use super::spec::{REQUEST_COUNT, REVISION};
use super::validation::{required_str, validate_envelope};
use super::{TempDir, newline_records, read};
use crate::tooling::support::{command_status_with_timeout, diagnostic_tail, go_module_cache};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(45);
const BUILD_TIMEOUT: Duration = Duration::from_secs(180);
const OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

pub(super) struct Observed {
    pub(super) bytes: Vec<u8>,
    pub(super) values: Vec<Value>,
}

pub(super) fn observe(
    root: &Path,
    upstream: &Path,
    requests: &[Value],
    request_bytes: &[u8],
    _manifest: &Value,
    temporary: &TempDir,
) -> Result<Observed, String> {
    let (go_version, platform) = selected_runtime(upstream, temporary)?;
    let oracle_root = root.join("crates/rustleaks-compat/oracle");
    let binary = temporary.path.join(if cfg!(windows) {
        "git-oracle.exe"
    } else {
        "git-oracle"
    });
    let mut build = Command::new("go");
    build
        .current_dir(&oracle_root)
        .args(["build", "-trimpath", "-o"])
        .arg(&binary)
        .arg(".");
    configure(&mut build, temporary);
    capture(&mut build, temporary, "oracle-build", BUILD_TIMEOUT)?;

    let lines = newline_records(request_bytes, "Git requests")?;
    if lines.len() != REQUEST_COUNT || lines.len() != requests.len() {
        return Err("Git request parsing changed before oracle execution".into());
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
            .arg("--git")
            .stdin(Stdio::from(stdin));
        configure(&mut command, temporary);
        let raw = capture(
            &mut command,
            temporary,
            &format!("git-{index:02}"),
            PROCESS_TIMEOUT,
        )?;
        let output = newline_records(&raw, &format!("{id} oracle output"))?;
        if output.len() != 1 {
            return Err(format!(
                "{id}: oracle emitted {} JSONL records",
                output.len()
            ));
        }
        let outcome: Value = serde_json::from_slice(output[0])
            .map_err(|error| format!("{id}: invalid oracle JSON: {error}"))?;
        validate_envelope(request, &outcome, &go_version, &platform)?;
        if output[0]
            .windows(b"gitleaks git \xce\xa9 oracle-".len())
            .any(|window| window == b"gitleaks git \xce\xa9 oracle-")
        {
            return Err(format!("{id}: private temporary path leaked"));
        }
        bytes.extend_from_slice(output[0]);
        values.push(outcome);
    }
    Ok(Observed { bytes, values })
}

pub(super) fn git_status(
    directory: &Path,
    pathspec: Option<&str>,
    temporary: &TempDir,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new("git");
    command.current_dir(directory).args(["status", "--short"]);
    if let Some(pathspec) = pathspec {
        command.arg("--").arg(pathspec);
    }
    configure(&mut command, temporary);
    capture(&mut command, temporary, label, Duration::from_secs(30))
}

fn selected_runtime(upstream: &Path, temporary: &TempDir) -> Result<(String, String), String> {
    let mut command = Command::new("go");
    command
        .current_dir(upstream)
        .args(["env", "GOVERSION", "GOOS", "GOARCH"]);
    configure(&mut command, temporary);
    let output = capture(&mut command, temporary, "go-runtime", BUILD_TIMEOUT)?;
    let fields = std::str::from_utf8(&output)
        .map_err(|error| format!("go env returned non-UTF-8 output: {error}"))?
        .lines()
        .collect::<Vec<_>>();
    if fields.len() != 3 || !go_1_26(fields[0]) {
        return Err("selected Go toolchain is not pinned to Go 1.26".into());
    }
    let platform = format!("{}/{}", fields[1], fields[2]);
    if !valid_platform(&platform) {
        return Err(format!("go env returned invalid platform {platform:?}"));
    }
    Ok((fields[0].to_owned(), platform))
}

fn configure(command: &mut Command, temporary: &TempDir) {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    command
        .env("GOCACHE", temporary.path.join("go-cache"))
        .env("GOMODCACHE", go_module_cache(REVISION))
        .env(
            "GOMEMLIMIT",
            std::env::var_os("GOMEMLIMIT").unwrap_or_else(|| "768MiB".into()),
        )
        .env(
            "GOMAXPROCS",
            std::env::var_os("GOMAXPROCS").unwrap_or_else(|| "2".into()),
        )
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_CONFIG_SYSTEM", null)
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
}

pub(super) fn capture(
    command: &mut Command,
    temporary: &TempDir,
    label: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let safe = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    let stdout_path = temporary.path.join(format!("{safe}.stdout"));
    let stderr_path = temporary.path.join(format!("{safe}.stderr"));
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
    let stderr_size = fs::metadata(&stderr_path)
        .map_err(|error| format!("cannot inspect {}: {error}", stderr_path.display()))?
        .len();
    if output.len() > OUTPUT_LIMIT || stderr_size > OUTPUT_LIMIT as u64 {
        return Err(format!(
            "{label}: output exceeded {OUTPUT_LIMIT} bytes per stream"
        ));
    }
    Ok(output)
}

fn go_1_26(version: &str) -> bool {
    version == "go1.26"
        || version.strip_prefix("go1.26.").is_some_and(|patch| {
            !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn valid_platform(value: &str) -> bool {
    let Some((os, arch)) = value.split_once('/') else {
        return false;
    };
    [os, arch].iter().all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::{go_1_26, valid_platform};

    #[test]
    fn runtime_and_platform_fail_closed() {
        assert!(go_1_26("go1.26.0"));
        assert!(!go_1_26("go1.26rc1"));
        assert!(valid_platform("darwin/arm64"));
        assert!(!valid_platform("Darwin/arm64"));
    }
}
