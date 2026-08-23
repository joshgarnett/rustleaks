//! Bounded, isolated execution of the pinned report oracle.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use super::spec::CASE_COUNT;
use super::validation::{runtime_negative_control, validate_envelope};
use super::{TempDir, newline_records, read};
use crate::tooling::support::{command_status_with_timeout, diagnostic_tail};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
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
    temporary: &TempDir,
) -> Result<Observed, String> {
    let (go_version, platform) = selected_runtime(upstream, temporary)?;
    let oracle_root = root.join("crates/rustleaks-compat/oracle");
    let binary = temporary.path.join(if cfg!(windows) {
        "oracle.exe"
    } else {
        "oracle"
    });
    let mut build = Command::new("go");
    build
        .current_dir(&oracle_root)
        .args(["build", "-trimpath", "-o"])
        .arg(&binary)
        .arg(".");
    configure_go(&mut build, temporary);
    capture(&mut build, temporary, "oracle-build", BUILD_TIMEOUT)?;

    let request_lines = newline_records(request_bytes, "report requests")?;
    if request_lines.len() != requests.len() || requests.len() != CASE_COUNT {
        return Err("report request parsing changed before oracle execution".into());
    }
    let mut bytes = Vec::new();
    let mut values = Vec::with_capacity(requests.len());
    for (index, (request_line, request)) in request_lines.iter().zip(requests).enumerate() {
        let id = request
            .get("id")
            .and_then(Value::as_str)
            .ok_or("report request id is missing")?;
        let request_path = temporary.path.join(format!("request-{index:02}.jsonl"));
        fs::write(&request_path, request_line)
            .map_err(|error| format!("cannot write {}: {error}", request_path.display()))?;
        let stdin = File::open(&request_path)
            .map_err(|error| format!("cannot open {}: {error}", request_path.display()))?;
        let mut command = Command::new(&binary);
        command
            .current_dir(&oracle_root)
            .arg("--report")
            .stdin(Stdio::from(stdin));
        configure_go(&mut command, temporary);
        let raw = capture(
            &mut command,
            temporary,
            &format!("report-{index:02}"),
            PROCESS_TIMEOUT,
        )?;
        let lines = newline_records(&raw, &format!("{id} oracle output"))?;
        if lines.len() != 1 {
            return Err(format!(
                "{id}: oracle emitted {} JSONL records",
                lines.len()
            ));
        }
        let outcome: Value = serde_json::from_slice(lines[0])
            .map_err(|error| format!("{id}: invalid oracle JSON: {error}"))?;
        validate_envelope(request, &outcome, &go_version, &platform)?;
        if index == 0 {
            runtime_negative_control(&outcome, &go_version, &platform)?;
        }
        let normalized = strip_runtime_provenance(lines[0], &go_version, &platform)?;
        let value = serde_json::from_slice(&normalized)
            .map_err(|error| format!("{id}: normalized oracle JSON is invalid: {error}"))?;
        bytes.extend_from_slice(&normalized);
        values.push(value);
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
    let text = std::str::from_utf8(&output)
        .map_err(|error| format!("go env returned non-UTF-8 output: {error}"))?;
    let fields = text.lines().map(str::trim).collect::<Vec<_>>();
    if fields.len() != 3 {
        return Err("selected Go runtime provenance was incomplete".into());
    }
    if !go_1_25(fields[0]) {
        return Err(format!(
            "selected Go toolchain {} is not pinned to Go 1.25",
            fields[0]
        ));
    }
    if !platform_component(fields[1]) || !platform_component(fields[2]) {
        return Err("selected Go platform is malformed".into());
    }
    Ok((fields[0].to_owned(), format!("{}/{}", fields[1], fields[2])))
}

fn configure_go(command: &mut Command, temporary: &TempDir) {
    let module_cache = std::env::var_os("GOMODCACHE").map_or_else(
        || std::env::temp_dir().join("rustleaks-go-mod-cache"),
        PathBuf::from,
    );
    command
        .env("GOCACHE", temporary.path.join("go-cache"))
        .env("GOMODCACHE", module_cache)
        .env(
            "GOMEMLIMIT",
            std::env::var_os("GOMEMLIMIT").unwrap_or_else(|| "768MiB".into()),
        )
        .env(
            "GOMAXPROCS",
            std::env::var_os("GOMAXPROCS").unwrap_or_else(|| "2".into()),
        )
        .env("LC_ALL", "C")
        .env("TZ", "UTC");
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

/// Remove only the host-specific fields, retaining every other byte and key order.
fn strip_runtime_provenance(
    raw: &[u8],
    go_version: &str,
    platform: &str,
) -> Result<Vec<u8>, String> {
    let needle = format!(",\"go_version\":\"{go_version}\",\"platform\":\"{platform}\"");
    let occurrences = raw
        .windows(needle.len())
        .filter(|window| *window == needle.as_bytes())
        .count();
    if occurrences != 1 {
        return Err(format!(
            "oracle outcome contains {occurrences} exact runtime provenance sequences"
        ));
    }
    let offset = raw
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())
        .ok_or("runtime provenance sequence disappeared")?;
    let mut normalized = Vec::with_capacity(raw.len() - needle.len());
    normalized.extend_from_slice(&raw[..offset]);
    normalized.extend_from_slice(&raw[offset + needle.len()..]);
    Ok(normalized)
}

fn go_1_25(version: &str) -> bool {
    version == "go1.25"
        || version.strip_prefix("go1.25.").is_some_and(|patch| {
            !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn platform_component(component: &str) -> bool {
    !component.is_empty()
        && component
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{go_1_25, platform_component, strip_runtime_provenance};

    #[test]
    fn provenance_normalization_preserves_all_other_bytes() {
        let raw = b"{\"a\":1,\"go_version\":\"go1.25.1\",\"platform\":\"darwin/arm64\",\"z\":2}\n";
        assert_eq!(
            strip_runtime_provenance(raw, "go1.25.1", "darwin/arm64").unwrap(),
            b"{\"a\":1,\"z\":2}\n"
        );
        assert!(strip_runtime_provenance(raw, "go1.25.2", "darwin/arm64").is_err());
        let duplicate = b"{\"a\":0,\"go_version\":\"go1.25\",\"platform\":\"x/y\",\"x\":1,\"go_version\":\"go1.25\",\"platform\":\"x/y\"}\n";
        assert!(strip_runtime_provenance(duplicate, "go1.25", "x/y").is_err());
    }

    #[test]
    fn runtime_values_fail_closed() {
        assert!(go_1_25("go1.25"));
        assert!(go_1_25("go1.25.3"));
        assert!(!go_1_25("go1.26"));
        assert!(!go_1_25("go1.25rc1"));
        assert!(platform_component("arm64"));
        assert!(!platform_component("arm-64"));
    }
}
