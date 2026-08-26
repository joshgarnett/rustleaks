//! Per-implementation observation and ordered corpus JSON serialization.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::TempDir;
use super::fixture;
use super::normalize::{self, Event};
use super::process::{self, CASE_TIMEOUT, OUTPUT_LIMIT};
use super::validation::{required_array, required_str};
use crate::tooling::support::sha256_bytes;

const MARKER: &[u8] = b"CLI_CORPUS_DISCLOSURE_MARKER_8F20C3";

pub(super) struct Observation {
    pub(super) json: String,
    exit: String,
    finding_count: Option<usize>,
    stdout: String,
    event_projection: String,
    usage: String,
    report: String,
    findings: String,
    child: String,
}

#[allow(clippy::too_many_lines)] // Observation keeps the ordered black-box protocol in one place.
pub(super) fn observe(
    binary: &Path,
    implementation: &str,
    case_id: &str,
    spec: &Value,
    go_binary: &Path,
) -> Result<Observation, String> {
    let temporary = TempDir::new(&format!("cli-{}", case_id.to_ascii_lowercase()))?;
    let capture = TempDir::new(&format!("cli-io-{}", case_id.to_ascii_lowercase()))?;
    let root = &temporary.path;
    fixture::setup(root, required_str(spec, "setup", case_id)?, &capture)?;
    let prepared = fixture::prepare(
        root,
        spec.get("prepare").and_then(Value::as_str),
        go_binary,
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
        &format!("{case_id}-{variant_id}-{implementation}"),
        CASE_TIMEOUT,
        OUTPUT_LIMIT,
    )?;
    let report = report(root, spec.get("report_path").and_then(Value::as_str))?;
    let executable = binary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("gitleaks");
    let names = [executable, "rustleaks", "gitleaks"];
    let stdout = normalize::normalize_bytes(&result.stdout, root, &names);
    let events = normalize::events(&result.stderr, root, &names);
    let usage = normalize::usage(&result.stderr, root, &names);
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
    if native_negative && ![255, 4_294_967_295].contains(&result.exit) {
        return Err(format!("{case_id}/{variant_id}: native -1 status changed"));
    }
    let exit = if native_negative {
        quote("native-negative-one")
    } else {
        result.exit.to_string()
    };
    let stdout_b64 = BASE64.encode(&stdout);
    let event_json = events.iter().map(normalize::event_json).collect::<Vec<_>>();
    let event_projection = events.iter().map(event_projection_json).collect::<Vec<_>>();
    let usage_json = usage
        .as_ref()
        .map_or_else(|| "null".into(), |bytes| byte_record(bytes));
    let report_json = report.json();
    let findings_json = findings
        .as_ref()
        .map_or_else(|| "null".into(), |items| format!("[{}]", items.join(",")));
    let finding_count = findings
        .as_ref()
        .map(Vec::len)
        .map_or_else(|| "null".into(), |n| n.to_string());
    let child_json = child_reaped.map_or_else(|| "null".into(), |value| value.to_string());
    let json = format!(
        "{{\"implementation\":{},\"exit\":{exit},\"stdout_base64\":{},\"stdout_bytes\":{},\"stdout_sha256\":{},\"stderr_events\":[{}],\"stderr_usage\":{usage_json},\"stderr_contains_disclosure_marker\":{},\"report\":{report_json},\"findings\":{findings_json},\"finding_count\":{finding_count},\"child_reaped\":{child_json}}}",
        quote(implementation),
        quote(&stdout_b64),
        stdout.len(),
        quote(&sha256_bytes(&stdout)),
        event_json.join(","),
        contains(&result.stderr, MARKER)
    );
    Ok(Observation {
        json,
        exit,
        finding_count: findings.as_ref().map(Vec::len),
        stdout: quote(&stdout_b64),
        event_projection: format!("[{}]", event_projection.join(",")),
        usage: usage_json,
        report: report_json,
        findings: findings_json,
        child: child_json,
    })
}

pub(super) fn comparison(
    go: &Observation,
    rust: &Observation,
    disposition: Option<&str>,
) -> String {
    let axes = [
        ("exit", go.exit == rust.exit),
        ("stdout", go.stdout == rust.stdout),
        (
            "stderr_events",
            go.event_projection == rust.event_projection,
        ),
        ("stderr_usage", go.usage == rust.usage),
        ("report", go.report == rust.report),
        ("findings", go.findings == rust.findings),
        ("child_cleanup", go.child == rust.child),
    ];
    let axes = axes
        .iter()
        .map(|(name, equal)| {
            format!(
                "{}:{}",
                quote(name),
                quote(if *equal { "equal" } else { "different" })
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"axes\":{{{axes}}},\"status\":{},\"disposition\":{}}}",
        quote(if disposition.is_some() {
            "accepted-versioned-disposition"
        } else {
            "exact"
        }),
        disposition.map_or_else(|| "null".into(), quote)
    )
}

pub(super) fn row_json(
    row: &Value,
    go_binary: &Path,
    rust_binary: &Path,
) -> Result<String, String> {
    let case_id = required_str(row, "id", "CLI request")?;
    let mut variants = Vec::new();
    for spec in required_array(row, "variants", case_id)? {
        let variant_id = required_str(spec, "id", case_id)?;
        if native_followup(spec) {
            if validate_linux_followup(spec) {
                let go = observe(go_binary, "go", case_id, spec, go_binary)?;
                let rust = observe(rust_binary, "rust", case_id, spec, go_binary)?;
                validate_omitted_native_pair(case_id, variant_id, spec, &go, &rust)?;
            }
            variants.push(format!(
                "{{\"id\":{},\"status\":\"native-runtime-followup\",\"disposition\":\"FOLLOWUP-NATIVE-M11-001\"}}",
                quote(variant_id)
            ));
            continue;
        }
        let go = observe(go_binary, "go", case_id, spec, go_binary)?;
        let rust = observe(rust_binary, "rust", case_id, spec, go_binary)?;
        let disposition = spec.get("disposition").and_then(Value::as_str);
        variants.push(format!(
            "{{\"id\":{},\"go\":{},\"rust\":{},\"comparison\":{}}}",
            quote(variant_id),
            go.json,
            rust.json,
            comparison(&go, &rust, disposition)
        ));
    }
    Ok(format!(
        "{{\"protocol_version\":1,\"id\":{},\"title\":{},\"variants\":[{}]}}\n",
        quote(case_id),
        quote(required_str(row, "title", case_id)?),
        variants.join(",")
    ))
}

struct Report {
    state: &'static str,
    bytes: Option<Vec<u8>>,
}

impl Report {
    fn json(&self) -> String {
        if self.state == "null" {
            return "null".into();
        }
        match &self.bytes {
            Some(bytes) => format!(
                "{{\"state\":\"present\",\"bytes_base64\":{},\"bytes\":{},\"sha256\":{}}}",
                quote(&BASE64.encode(bytes)),
                bytes.len(),
                quote(&sha256_bytes(bytes))
            ),
            None => format!("{{\"state\":{}}}", quote(self.state)),
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
    Ok(Report {
        state: "present",
        bytes: Some(fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?),
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

fn native_followup(spec: &Value) -> bool {
    native_followup_for_target(spec, cfg!(windows))
}

fn native_followup_for_target(spec: &Value, windows: bool) -> bool {
    let expected = spec.get("expectation").unwrap_or(&Value::Null);
    expected.get("unix_only").and_then(Value::as_bool) == Some(true) && windows
        || expected.get("linux_only").and_then(Value::as_bool) == Some(true)
}

fn validate_linux_followup(spec: &Value) -> bool {
    validate_linux_followup_for_target(spec, cfg!(target_os = "linux"))
}

fn validate_linux_followup_for_target(spec: &Value, linux: bool) -> bool {
    linux
        && spec
            .pointer("/expectation/linux_only")
            .and_then(Value::as_bool)
            == Some(true)
}

fn validate_omitted_native_pair(
    case_id: &str,
    variant_id: &str,
    spec: &Value,
    go: &Observation,
    rust: &Observation,
) -> Result<(), String> {
    let label = format!("{case_id}/{variant_id}");
    let expected = spec.get("expectation").unwrap_or(&Value::Null);
    if let Some(exit) = expected.get("exit").and_then(Value::as_i64) {
        let exit = exit.to_string();
        if go.exit != exit || rust.exit != exit {
            return Err(format!("{label}: omitted native exit changed"));
        }
    }
    if let Some(findings) = expected.get("findings").and_then(Value::as_u64) {
        let findings = usize::try_from(findings)
            .map_err(|_| format!("{label}: native finding expectation is too large"))?;
        if go.finding_count != Some(findings) || rust.finding_count != Some(findings) {
            return Err(format!("{label}: omitted native finding count changed"));
        }
    }
    if go.exit != rust.exit
        || go.stdout != rust.stdout
        || go.event_projection != rust.event_projection
        || go.usage != rust.usage
        || go.report != rust.report
        || go.findings != rust.findings
        || go.child != rust.child
    {
        return Err(format!("{label}: omitted native comparison changed"));
    }
    Ok(())
}

fn event_projection_json(event: &Event) -> String {
    let fields = event
        .fields
        .iter()
        .map(|(key, value)| format!("{}:{}", quote(key), serde_json::to_string(value).unwrap()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"severity\":{},\"class\":{},\"fields\":{{{fields}}}}}",
        quote(&event.severity),
        quote(&event.class)
    )
}

fn byte_record(bytes: &[u8]) -> String {
    format!(
        "{{\"bytes_base64\":{},\"bytes\":{},\"sha256\":{}}}",
        quote(&BASE64.encode(bytes)),
        bytes.len(),
        quote(&sha256_bytes(bytes))
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn quote(value: &str) -> String {
    serde_json::to_string(value)
        .expect("string JSON")
        .replace("\\u0026", "&")
        .replace("\\u003c", "<")
        .replace("\\u003e", ">")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{native_followup_for_target, validate_linux_followup_for_target};

    #[test]
    fn linux_native_observation_is_validated_but_omitted() {
        let spec = json!({"expectation": {"linux_only": true}});
        assert!(native_followup_for_target(&spec, false));
        assert!(validate_linux_followup_for_target(&spec, true));
        assert!(!validate_linux_followup_for_target(&spec, false));
    }

    #[test]
    fn unix_observation_is_only_omitted_on_windows() {
        let spec = json!({"expectation": {"unix_only": true}});
        assert!(!native_followup_for_target(&spec, false));
        assert!(native_followup_for_target(&spec, true));
    }
}
