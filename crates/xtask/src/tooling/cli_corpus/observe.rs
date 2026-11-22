//! One CLI run reduced to the compared observation.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};

use super::ScopedTempDir;
use super::fixture;
use super::normalize;
use super::process::{self, CASE_TIMEOUT, OUTPUT_LIMIT};
use super::validation::{required_array, required_str};
use crate::tooling::support::sha256_bytes;

/// Synthetic inline configuration marker that CLI output must never disclose.
const DISCLOSURE_MARKER: &str = "CLI_CORPUS_DISCLOSURE_MARKER_8F20C3";

/// Returns true when a request prints only help on stdout: the bare command
/// or an explicit help flag. Help text is presentation, so its stdout is not
/// compared.
pub(super) fn help_stdout(request: &Value) -> bool {
    request["args"].as_array().is_some_and(|args| {
        args.is_empty()
            || args
                .iter()
                .any(|arg| matches!(arg.as_str(), Some("-h" | "--help")))
    })
}

/// Runs one request variant and returns the observation that the replay
/// compares: exit status, stdout bytes outside help output, stderr event
/// severity, class and fields, whether a usage block was printed, the
/// disclosure check, the report, findings and child cleanup.
pub(super) fn observe(
    binary: &Path,
    case_id: &str,
    spec: &Value,
    fake_git_binary: &Path,
) -> Result<Value, String> {
    let temporary = ScopedTempDir::new(&format!("cli-{}", case_id.to_ascii_lowercase()))?;
    let capture = ScopedTempDir::new(&format!("cli-io-{}", case_id.to_ascii_lowercase()))?;
    let root = &temporary.path;
    fixture::setup(root, required_str(spec, "setup", case_id)?, &capture)?;
    let prepared = fixture::prepare(
        root,
        spec.get("prepare").and_then(Value::as_str),
        fake_git_binary,
        &capture,
        &format!("{case_id}-{}", required_str(spec, "id", case_id)?),
    )?;
    let args = required_array(spec, "args", case_id)?
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| format!("{case_id}: non-string CLI argument"))?;
            if value == "__NATIVE_PATH__" {
                prepared
                    .native_path
                    .clone()
                    .ok_or_else(|| format!("{case_id}: native-byte path was not prepared"))
            } else {
                Ok(OsString::from(value))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut env = decode_env(spec, case_id)?;
    env.extend(prepared.env);
    let mut stdin = BASE64
        .decode(required_str(spec, "stdin_base64", case_id)?)
        .map_err(|error| format!("{case_id}: invalid stdin base64: {error}"))?;
    if stdin == b"__GENERATED__" {
        stdin = prepared
            .stdin
            .ok_or_else(|| format!("{case_id}: generated stdin was not prepared"))?;
    }
    let variant_id = required_str(spec, "id", case_id)?;
    let result = process::run(
        binary,
        &args,
        root,
        &env,
        &stdin,
        &capture,
        &format!("{case_id}-{variant_id}-rust"),
        CASE_TIMEOUT,
        OUTPUT_LIMIT,
    )?;
    let report = report(root, spec.get("report_path").and_then(Value::as_str))?;
    let executable = binary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("rustleaks");
    let finding_bytes = match spec.get("finding_source").and_then(Value::as_str) {
        Some("report") => report.bytes.as_deref(),
        Some("stdout") => Some(result.stdout.as_slice()),
        None => None,
        Some(other) => return Err(format!("{case_id}: unknown finding source {other}")),
    };
    let findings = finding_bytes
        .map(normalize::canonical_findings)
        .transpose()?;
    let child_reaped = child_reaped(root, prepared.child_pid_file.as_deref())?;
    let native_negative = spec
        .pointer("/expectation/native_negative_one")
        .and_then(Value::as_bool)
        == Some(true);
    if native_negative && !native_negative_one_exit(result.exit) {
        return Err(format!("{case_id}/{variant_id}: native -1 status changed"));
    }
    let exit = if native_negative {
        json!("native-negative-one")
    } else {
        json!(result.exit)
    };
    let stderr = normalize::stderr(&result.stderr, root, executable);
    let mut observation = json!({
        "exit": exit,
        "stderr_events": stderr.events.iter().map(normalize::event_value).collect::<Vec<_>>(),
        "stderr_usage_printed": stderr.usage_printed,
        "stderr_contains_disclosure_marker":
            contains(&result.stderr, DISCLOSURE_MARKER.as_bytes()),
        "report": report.value(),
        "finding_count": findings.as_ref().map(Vec::len),
        "findings": findings,
        "child_reaped": child_reaped,
    });
    if !help_stdout(spec) {
        let stdout = normalize::version_token(&normalize::normalize_bytes(
            &result.stdout,
            root,
            executable,
        ));
        observation["stdout_base64"] = json!(BASE64.encode(&stdout));
        observation["stdout_bytes"] = json!(stdout.len());
        observation["stdout_sha256"] = json!(sha256_bytes(&stdout));
    }
    Ok(observation)
}

fn native_negative_one_exit(exit: i64) -> bool {
    #[cfg(windows)]
    {
        exit == -1
    }
    #[cfg(not(windows))]
    {
        exit == 255
    }
}

struct Report {
    state: &'static str,
    bytes: Option<Vec<u8>>,
}

impl Report {
    fn value(&self) -> Value {
        match (&self.bytes, self.state) {
            (_, "null") => Value::Null,
            (Some(bytes), _) => json!({
                "state": "present",
                "bytes_base64": BASE64.encode(bytes),
                "bytes": bytes.len(),
                "sha256": sha256_bytes(bytes),
            }),
            (None, state) => json!({"state": state}),
        }
    }
}

fn report(root: &Path, path: Option<&str>) -> Result<Report, String> {
    let Some(path) = path else {
        return Ok(Report {
            state: "null",
            bytes: None,
        });
    };
    if path == "-" {
        return Ok(Report {
            state: "null",
            bytes: None,
        });
    }
    let path = root.join(path);
    if !path.is_file() {
        return Ok(Report {
            state: "absent",
            bytes: None,
        });
    }
    let bytes = fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(Report {
        state: "present",
        bytes: Some(normalize::version_token(&bytes)),
    })
}

fn decode_env(spec: &Value, label: &str) -> Result<BTreeMap<String, Vec<u8>>, String> {
    spec.get("env")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}: env is not an object"))?
        .iter()
        .map(|(key, value)| {
            let encoded = value
                .as_str()
                .ok_or_else(|| format!("{label}: env value is not a string"))?;
            BASE64
                .decode(encoded)
                .map(|bytes| (key.clone(), bytes))
                .map_err(|e| format!("{label}: invalid env base64: {e}"))
        })
        .collect()
}

fn child_reaped(root: &Path, file: Option<&str>) -> Result<Option<bool>, String> {
    let Some(file) = file else { return Ok(None) };
    let path = root.join(file);
    if !path.is_file() {
        return Ok(None);
    }
    let pid = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read child PID: {e}"))?
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("invalid child PID: {e}"))?;
    let alive = reap_if_alive(pid);
    Ok(Some(!alive))
}

#[cfg(unix)]
fn reap_if_alive(pid: u32) -> bool {
    let null = || std::process::Stdio::null();
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(null())
        .stderr(null())
        .status()
        .is_ok_and(|status| status.success());
    if alive {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(null())
            .stderr(null())
            .status();
    }
    alive
}

#[cfg(windows)]
fn reap_if_alive(pid: u32) -> bool {
    Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::native_negative_one_exit;

    #[test]
    fn native_negative_one_status_is_platform_exact() {
        #[cfg(windows)]
        {
            assert!(native_negative_one_exit(-1));
            assert!(!native_negative_one_exit(255));
        }
        #[cfg(not(windows))]
        {
            assert!(native_negative_one_exit(255));
            assert!(!native_negative_one_exit(-1));
        }
    }
}
