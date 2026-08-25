//! Fresh, bounded execution of every declarative source request.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use super::spec::REQUEST_COUNT;
use super::validation::{required_str, validate_envelope};
use super::{TempDir, newline_records, read};
use crate::tooling::support::{command_status_with_timeout, diagnostic_tail};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const BUILD_TIMEOUT: Duration = Duration::from_secs(180);
const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

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
    let (go_version, platform) = selected_runtime(upstream, temporary)?;
    if required_str(manifest, "go_version", "manifest")? != go_version {
        return Err(format!(
            "selected Go version {go_version} differs from the committed source manifest"
        ));
    }
    let oracle_root = root.join("crates/rustleaks-compat/oracle");
    let binary = temporary.path.join(if cfg!(windows) {
        "source-oracle.exe"
    } else {
        "source-oracle"
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

    let lines = newline_records(request_bytes, "source requests")?;
    if lines.len() != REQUEST_COUNT || lines.len() != requests.len() {
        return Err("source request parsing changed before oracle execution".into());
    }
    let mut bytes = Vec::new();
    let mut values = Vec::with_capacity(lines.len());
    for (index, (line, request)) in lines.iter().zip(requests).enumerate() {
        let id = required_str(request, "id", "request")?;
        let request_path = temporary.path.join(format!("request-{index:03}.jsonl"));
        fs::write(&request_path, line)
            .map_err(|error| format!("cannot write {}: {error}", request_path.display()))?;
        let stdin = File::open(&request_path)
            .map_err(|error| format!("cannot open {}: {error}", request_path.display()))?;
        let mut command = Command::new(&binary);
        command
            .current_dir(&oracle_root)
            .arg("--source")
            .stdin(Stdio::from(stdin));
        configure_go(&mut command, temporary);
        let raw = capture(
            &mut command,
            temporary,
            &format!("source-{index:03}"),
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
        bytes.extend_from_slice(output[0]);
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
    command.current_dir(upstream).args(["status", "--short"]);
    capture(
        &mut command,
        temporary,
        &format!("upstream-status-{suffix}"),
        Duration::from_secs(30),
    )
}

fn selected_runtime(upstream: &Path, temporary: &TempDir) -> Result<(String, String), String> {
    let mut command = Command::new("go");
    command
        .current_dir(upstream)
        .args(["env", "GOVERSION", "GOOS", "GOARCH"]);
    configure_go(&mut command, temporary);
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

fn configure_go(command: &mut Command, temporary: &TempDir) {
    let module_cache = std::env::var_os("GOMODCACHE").map_or_else(
        || std::env::temp_dir().join("rustleaks-go-mod-cache"),
        PathBuf::from,
    );
    command
        .env("GOCACHE", temporary.path.join("go-cache"))
        .env("GOMODCACHE", module_cache)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
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
    for (name, size) in [
        ("stdout", output.len() as u64),
        (
            "stderr",
            fs::metadata(&stderr_path)
                .map_err(|error| format!("cannot inspect {}: {error}", stderr_path.display()))?
                .len(),
        ),
    ] {
        if size > OUTPUT_LIMIT as u64 {
            return Err(format!("{label}: {name} exceeded {OUTPUT_LIMIT} bytes"));
        }
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
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
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
        assert!(valid_platform("windows/amd64"));
        assert!(!valid_platform("Darwin/arm64"));
        assert!(!valid_platform("linux/arm64/extra"));
    }
}
