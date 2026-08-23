//! Fresh, isolated execution of every composite request and private probe.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::overlay;
use super::runner::Runner;
use super::serialize::{self, Template};
use super::spec::{Canonical, DEFAULT_SHA256, REVISION};
use crate::tooling::support::{TempDir, sha256_bytes};

const ORDINARY_TIMEOUT: Duration = Duration::from_secs(20);
const PRIVATE_TIMEOUT: Duration = Duration::from_secs(60);
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_OUTPUT_LIMIT: u64 = 64 * 1024 * 1024;

pub(super) struct Observed {
    pub(super) outcomes: Vec<u8>,
}

struct OrdinaryContext<'a> {
    binary: &'a Path,
    oracle: &'a Path,
    canonical: &'a Canonical,
    runner: &'a Runner,
    workspace: &'a Path,
}

pub(super) fn observe(
    root: &Path,
    upstream: &Path,
    canonical: &Canonical,
    temporary: &TempDir,
) -> Result<Observed, String> {
    if !upstream.is_dir() {
        return Err(format!(
            "missing pinned upstream checkout: {}",
            upstream.display()
        ));
    }
    let workspace = temporary.path.join("composite workspace ü with spaces");
    fs::create_dir_all(&workspace)
        .map_err(|error| format!("cannot create {}: {error}", workspace.display()))?;
    let runner = Runner::new(workspace.clone());
    let revision_before = git(upstream, &runner, &["rev-parse", "HEAD"], "revision-before")?;
    if trim(&revision_before)? != REVISION {
        return Err(format!(
            "upstream revision differs: expected {REVISION}, got {}",
            trim(&revision_before)?
        ));
    }
    let status_before = git(
        upstream,
        &runner,
        &["status", "--short", "--untracked-files=no"],
        "status-before",
    )?;
    if !status_before.is_empty() {
        return Err(format!(
            "pinned upstream checkout is dirty:\n{}",
            String::from_utf8_lossy(&status_before)
        ));
    }
    let default = git(
        upstream,
        &runner,
        &["show", &format!("{REVISION}:config/gitleaks.toml")],
        "default-config",
    )?;
    if sha256_bytes(&default) != DEFAULT_SHA256 {
        return Err("fresh pinned default configuration hash changed".into());
    }

    let binaries = overlay::build(root, upstream, &workspace, &runner)?;
    let outcomes = observe_requests(root, upstream, canonical, &workspace, &runner, &binaries)?;
    let revision_after = git(upstream, &runner, &["rev-parse", "HEAD"], "revision-after")?;
    let status_after = git(
        upstream,
        &runner,
        &["status", "--short", "--untracked-files=no"],
        "status-after",
    )?;
    if revision_after != revision_before || status_after != status_before {
        return Err("upstream checkout changed while observing composite corpus".into());
    }
    Ok(Observed { outcomes })
}

fn observe_requests(
    root: &Path,
    upstream: &Path,
    canonical: &Canonical,
    workspace: &Path,
    runner: &Runner,
    binaries: &overlay::Binaries,
) -> Result<Vec<u8>, String> {
    let mut outcomes = Vec::new();
    let mut template = None;
    let oracle = root.join("crates/rustleaks-compat/oracle");
    let ordinary = OrdinaryContext {
        binary: &binaries.composite,
        oracle: &oracle,
        canonical,
        runner,
        workspace,
    };
    for (index, (line, request)) in canonical
        .request_lines
        .iter()
        .zip(&canonical.request_values)
        .enumerate()
    {
        let id = request["id"]
            .as_str()
            .ok_or_else(|| format!("request {index} has no ID"))?;
        let operation = request["operation"]
            .as_str()
            .ok_or_else(|| format!("{id}: request has no operation"))?;
        let outcome = match operation {
            "mask_secret" => {
                observe_mask(request, template.as_ref(), &binaries.mask, upstream, runner)?
            }
            "filter_probe" => observe_filter(
                request,
                template.as_ref(),
                &binaries.filter,
                upstream,
                runner,
            )?,
            _ => {
                let fresh = ordinary.observe(index, id, line)?;
                if template.is_none() {
                    let value: Value = serde_json::from_slice(&fresh)
                        .map_err(|error| format!("{id}: invalid fresh template JSON: {error}"))?;
                    template = Some(serialize::template(&value)?);
                }
                fresh
            }
        };
        let parsed: Value = serde_json::from_slice(&outcome)
            .map_err(|error| format!("{id}: fresh outcome is invalid JSON: {error}"))?;
        if parsed["id"] != id {
            return Err(format!(
                "{id}: fresh oracle returned wrong response identity"
            ));
        }
        outcomes.extend_from_slice(&outcome);
    }
    Ok(outcomes)
}

impl OrdinaryContext<'_> {
    fn observe(&self, index: usize, id: &str, request: &[u8]) -> Result<Vec<u8>, String> {
        let input = self.workspace.join(format!("request {index:03} ü.jsonl"));
        fs::write(&input, request)
            .map_err(|error| format!("cannot write {}: {error}", input.display()))?;
        let mut command = Command::new(self.binary);
        command
            .current_dir(self.oracle)
            .arg("--composite")
            .stdin(Stdio::from(File::open(&input).map_err(|error| {
                format!("cannot open {}: {error}", input.display())
            })?));
        self.runner.go_env(&mut command);
        let (timeout, limit) = self.canonical.resources.get(id).map_or(
            (ORDINARY_TIMEOUT, DEFAULT_OUTPUT_LIMIT),
            |contract| {
                command.env("GOMEMLIMIT", format!("{}B", contract.allocation_bytes));
                (
                    Duration::from_secs(contract.timeout_seconds),
                    contract.output_bytes,
                )
            },
        );
        let raw = self.runner.capture(&mut command, id, timeout, limit)?;
        let records = records(&raw, id)?;
        if records.len() != 1 {
            return Err(format!("{id}: oracle returned {} records", records.len()));
        }
        serialize::ruby_json_number_format(records[0])
    }
}

fn observe_mask(
    request: &Value,
    template: Option<&Template>,
    binary: &Path,
    upstream: &Path,
    runner: &Runner,
) -> Result<Vec<u8>, String> {
    let id = request["id"].as_str().ok_or("mask request has no ID")?;
    let template = template.ok_or_else(|| format!("{id}: mask template unavailable"))?;
    let encoded = request["redaction"]["secret_base64"]
        .as_str()
        .ok_or_else(|| format!("{id}: mask secret is missing"))?;
    let secret = BASE64
        .decode(encoded)
        .map_err(|error| format!("{id}: mask secret is invalid base64: {error}"))?;
    let percent = request["redact_percent"]
        .as_u64()
        .ok_or_else(|| format!("{id}: mask percent is not unsigned"))?;
    let mut command = Command::new(binary);
    command
        .current_dir(upstream)
        .args(["-test.run", "^TestM7MaskOracle$", "-test.v"])
        .env("M7_SECRET", encoded)
        .env("M7_PERCENT", percent.to_string());
    runner.go_env(&mut command);
    let output = runner.capture(&mut command, id, PRIVATE_TIMEOUT, DEFAULT_OUTPUT_LIMIT)?;
    let mask = marker(&output, b"M7MASK:", id)?;
    serialize::synthesized(request, template, &sha256_bytes(&secret), b"[]", mask)
}

fn observe_filter(
    request: &Value,
    template: Option<&Template>,
    binary: &Path,
    upstream: &Path,
    runner: &Runner,
) -> Result<Vec<u8>, String> {
    let id = request["id"].as_str().ok_or("filter request has no ID")?;
    let template = template.ok_or_else(|| format!("{id}: filter template unavailable"))?;
    let input = serialize::filter_input(request)?;
    let input_text = std::str::from_utf8(&input)
        .map_err(|error| format!("{id}: filter input is not UTF-8: {error}"))?;
    let mut command = Command::new(binary);
    command
        .current_dir(upstream)
        .args(["-test.run", "^TestM7FilterOracle$", "-test.v"])
        .env("M7_FILTER", input_text);
    runner.go_env(&mut command);
    let output = runner.capture(&mut command, id, PRIVATE_TIMEOUT, DEFAULT_OUTPUT_LIMIT)?;
    let encoded = marker(&output, b"M7FILTER:", id)?;
    let findings = BASE64
        .decode(encoded)
        .map_err(|error| format!("{id}: filter marker is invalid base64: {error}"))?;
    serialize::synthesized(request, template, &sha256_bytes(&input), &findings, "")
}

fn git(upstream: &Path, runner: &Runner, args: &[&str], label: &str) -> Result<Vec<u8>, String> {
    let mut command = Command::new("git");
    command.current_dir(upstream).args(args);
    runner.capture(&mut command, label, GIT_TIMEOUT, 8 * 1024 * 1024)
}

fn records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label}: output lacks final newline"));
    }
    let rows = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    if rows.iter().any(|row| *row == b"\n") {
        return Err(format!("{label}: output contains blank record"));
    }
    Ok(rows)
}

fn marker<'a>(output: &'a [u8], prefix: &[u8], id: &str) -> Result<&'a str, String> {
    let start = output
        .windows(prefix.len())
        .position(|window| window == prefix)
        .map(|position| position + prefix.len())
        .ok_or_else(|| {
            format!(
                "{id}: private probe marker missing in {}",
                String::from_utf8_lossy(output)
            )
        })?;
    let end = output[start..]
        .iter()
        .position(u8::is_ascii_whitespace)
        .map_or(output.len(), |offset| start + offset);
    std::str::from_utf8(&output[start..end])
        .map_err(|error| format!("{id}: private marker is not UTF-8: {error}"))
}

fn trim(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|error| format!("command output is not UTF-8: {error}"))
}

#[cfg(test)]
mod tests {
    use super::marker;

    #[test]
    fn marker_extracts_bounded_token() {
        assert_eq!(
            marker(b"noise M7MASK:c2UuLi4=\nPASS\n", b"M7MASK:", "x").unwrap(),
            "c2UuLi4="
        );
        assert!(marker(b"missing\n", b"M7MASK:", "x").is_err());
    }
}
