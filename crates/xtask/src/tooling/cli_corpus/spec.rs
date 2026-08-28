//! CLI request, source-pin, runtime, and binary-build contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use super::process::{self, OUTPUT_LIMIT};
use super::validation::{required_array, required_object, required_str, required_u64};
use super::{TempDir, newline_records, read};
use crate::tooling::support::sha256_bytes;

pub(super) const CASE_COUNT: usize = 34;
pub(super) const VARIANT_COUNT: usize = 119;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
pub(super) const LEGACY_BUILD_VERSION: &str = "0.1.0-alpha.2";
pub(super) const BUILD_VERSION: &str = "0.1.0-alpha.3";

pub(super) struct Binaries {
    pub(super) go: PathBuf,
    pub(super) rust: PathBuf,
}

#[derive(PartialEq, Eq)]
pub(super) struct Runtime {
    go_version: String,
    go_platform: String,
    rust_host: String,
    cleanup: &'static str,
}

pub(super) fn validate_inputs(
    requests: &[u8],
    negative: &[u8],
    negative_value: &Value,
    manifest: &Value,
) -> Result<Vec<Value>, String> {
    if required_str(manifest, "corpus_version", "manifest")? != "rustleaks-cli-corpus-v1"
        || required_u64(manifest, "protocol_version", "manifest")? != 1
        || required_str(manifest, "upstream_revision", "manifest")? != REVISION
        || required_str(manifest, "default_config_sha256", "manifest")? != CONFIG_SHA256
        || ![LEGACY_BUILD_VERSION, BUILD_VERSION].contains(&required_str(
            manifest,
            "build_version",
            "manifest",
        )?)
        || required_u64(manifest, "case_count", "manifest")? != CASE_COUNT as u64
        || required_u64(manifest, "variant_count", "manifest")? != VARIANT_COUNT as u64
        || required_str(manifest, "requests_sha256", "manifest")? != sha256_bytes(requests)
        || required_str(manifest, "negative_controls_sha256", "manifest")? != sha256_bytes(negative)
    {
        return Err("CLI manifest provenance or canonical hashes changed".into());
    }
    validate_accounting(manifest)?;
    validate_negative(negative_value)?;
    let lines = newline_records(requests, "CLI requests")?;
    if lines.len() != CASE_COUNT {
        return Err(format!("CLI case count changed to {}", lines.len()));
    }
    let mut rows = Vec::with_capacity(lines.len());
    let mut variant_count = 0;
    let mut dispositions = BTreeMap::<String, usize>::new();
    for (number, line) in (1..=CASE_COUNT).zip(lines) {
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| format!("invalid CLI request {number}: {e}"))?;
        let expected_id = format!("CLI-BB-{number:03}");
        if required_u64(&row, "protocol_version", &expected_id)? != 1
            || required_str(&row, "id", "CLI request")? != expected_id
            || required_str(&row, "title", &expected_id)?.is_empty()
        {
            return Err(format!("{expected_id}: request envelope changed"));
        }
        let variants = required_array(&row, "variants", &expected_id)?;
        let mut ids = BTreeSet::new();
        for variant in variants {
            let id = required_str(variant, "id", &expected_id)?;
            if !ids.insert(id) {
                return Err(format!("{expected_id}: duplicate variant {id}"));
            }
            validate_variant(variant, &expected_id)?;
            if let Some(disposition) = variant.get("disposition").and_then(Value::as_str) {
                *dispositions.entry(disposition.into()).or_default() += 1;
            }
        }
        variant_count += variants.len();
        rows.push(row);
    }
    if variant_count != VARIANT_COUNT {
        return Err(format!("CLI variant count changed to {variant_count}"));
    }
    let manifest_dispositions = required_object(manifest, "disposition_counts", "manifest")?;
    for (id, count) in dispositions {
        if manifest_dispositions.get(&id).and_then(Value::as_u64) != Some(count as u64) {
            return Err(format!("CLI disposition count changed for {id}"));
        }
    }
    Ok(rows)
}

fn validate_variant(value: &Value, label: &str) -> Result<(), String> {
    for field in ["id", "setup", "stdin_base64"] {
        required_str(value, field, label)?;
    }
    if !value.get("args").is_some_and(Value::is_array)
        || !value.get("env").is_some_and(Value::is_object)
        || !value.get("expectation").is_some_and(Value::is_object)
        || !(value["report_path"].is_string() || value["report_path"].is_null())
        || !(value["disposition"].is_string() || value["disposition"].is_null())
        || !(value["finding_source"].is_string() || value["finding_source"].is_null())
        || !(value["prepare"].is_string() || value["prepare"].is_null())
    {
        return Err(format!("{label}: variant shape changed"));
    }
    Ok(())
}

fn validate_accounting(manifest: &Value) -> Result<(), String> {
    for (field, value) in [
        ("paired_observation_pair_count", 119),
        ("paired_observation_process_count", 238),
        ("auxiliary_cli_process_count", 4),
        ("fresh_cli_process_count", 242),
        ("exact_variant_count", 101),
        ("versioned_disposition_variant_count", 18),
        (
            "complete_duplicate_preserving_finding_count_both_implementations",
            102,
        ),
        ("raw_report_byte_count_both_implementations", 49_540),
        ("parser_usage_byte_count_both_implementations", 19_508),
        ("stderr_event_count_both_implementations", 888),
        ("mutation_control_count", 20),
    ] {
        if required_u64(manifest, field, "manifest")? != value {
            return Err(format!("CLI manifest {field} changed"));
        }
    }
    if ![
        "independently-validated-then-omitted",
        "independently-validated-with-native-linux-record",
    ]
    .contains(&required_str(
        manifest,
        "runtime_provenance_policy",
        "manifest",
    )?) {
        return Err("CLI runtime provenance policy changed".into());
    }
    Ok(())
}

fn validate_negative(negative: &Value) -> Result<(), String> {
    let controls = required_array(negative, "controls", "negative controls")?;
    if controls.len() != 20 {
        return Err("CLI mutation-control count changed".into());
    }
    let mut ids = BTreeSet::new();
    for control in controls {
        let id = required_str(control, "id", "negative control")?;
        if !ids.insert(id) || !id.starts_with("MUT-CLI-") {
            return Err(format!("invalid CLI mutation control {id}"));
        }
        for field in [
            "case_id",
            "variant_id",
            "expected_failure_class",
            "observed_rejection_sha256",
        ] {
            if required_str(control, field, id)?.is_empty() {
                return Err(format!("{id}: incomplete mutation control"));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_sources(
    root: &Path,
    upstream: &Path,
    manifest: &Value,
) -> Result<(), String> {
    verify_map(
        upstream,
        required_object(manifest, "go_source_sha256", "manifest")?,
    )?;
    verify_map(
        root,
        required_object(manifest, "rust_source_sha256", "manifest")?,
    )?;
    if sha256_bytes(&read(&upstream.join("config/gitleaks.toml"))?) != CONFIG_SHA256 {
        return Err("pinned Go default configuration changed".into());
    }
    Ok(())
}

pub(super) fn selected_runtime(
    root: &Path,
    upstream: &Path,
    temporary: &TempDir,
) -> Result<Runtime, String> {
    let go = process::command(
        Path::new("go"),
        &strings(&["env", "GOVERSION", "GOOS", "GOARCH"]),
        upstream,
        &process::default_go_env(temporary),
        temporary,
        "go-provenance",
        Duration::from_secs(120),
        OUTPUT_LIMIT,
    )?;
    let fields = String::from_utf8(go)
        .map_err(|e| format!("go env is not UTF-8: {e}"))?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if fields.len() != 3
        || !(fields[0] == "go1.26"
            || fields[0]
                .strip_prefix("go1.26.")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())))
    {
        return Err("selected Go runtime is outside 1.26".into());
    }
    let rust = process::command(
        Path::new("rustc"),
        &strings(&["-vV"]),
        root,
        &BTreeMap::new(),
        temporary,
        "rust-provenance",
        Duration::from_secs(120),
        OUTPUT_LIMIT,
    )?;
    let rust = String::from_utf8(rust).map_err(|e| format!("rustc output is not UTF-8: {e}"))?;
    let host = rust
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc host provenance missing")?;
    let runtime = Runtime {
        go_version: fields[0].clone(),
        go_platform: format!("{}/{}", fields[1], fields[2]),
        rust_host: host.into(),
        cleanup: if cfg!(windows) {
            "bounded-taskkill-tree"
        } else {
            "bounded-process-group"
        },
    };
    runtime.validate()?;
    Ok(runtime)
}

impl Runtime {
    fn validate(&self) -> Result<(), String> {
        if !self.go_platform.split_once('/').is_some_and(|(a, b)| {
            [a, b].iter().all(|v| {
                !v.is_empty()
                    && v.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            })
        }) || self.rust_host.is_empty()
            || !self
                .rust_host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || !["bounded-taskkill-tree", "bounded-process-group"].contains(&self.cleanup)
        {
            return Err("selected runtime provenance invalid".into());
        }
        Ok(())
    }
}

pub(super) fn build(
    root: &Path,
    upstream: &Path,
    temporary: &TempDir,
    runtime: &Runtime,
) -> Result<Binaries, String> {
    let go = temporary.path.join(if cfg!(windows) {
        "gitleaks-go.exe"
    } else {
        "gitleaks-go"
    });
    let target = temporary.path.join("rust-target");
    let rust = target.join("debug").join(if cfg!(windows) {
        "rustleaks.exe"
    } else {
        "rustleaks"
    });
    let mut args = strings(&["build", "-trimpath", "-buildvcs=true", "-ldflags"]);
    args.push(format!(
        "-X github.com/zricethezav/gitleaks/v8/version.Version={BUILD_VERSION}"
    ));
    args.extend(["-o".into(), go.to_string_lossy().into_owned(), ".".into()]);
    process::command(
        Path::new("go"),
        &args,
        upstream,
        &process::default_go_env(temporary),
        temporary,
        "go-build",
        Duration::from_secs(300),
        OUTPUT_LIMIT,
    )?;
    let env = BTreeMap::from([
        (
            "CARGO_TARGET_DIR".into(),
            target.to_string_lossy().into_owned().into_bytes(),
        ),
        ("CARGO_TERM_COLOR".into(), b"never".to_vec()),
    ]);
    process::command(
        Path::new("cargo"),
        &strings(&["build", "--locked", "--offline", "-p", "rustleaks-cli"]),
        root,
        &env,
        temporary,
        "rust-build",
        Duration::from_secs(900),
        32 * 1024 * 1024,
    )?;
    for (name, binary) in [("go", &go), ("rust", &rust)] {
        let probe = process::run(
            binary,
            &strings(&["version"]),
            &temporary.path,
            &BTreeMap::new(),
            b"",
            temporary,
            &format!("{name}-version"),
            Duration::from_secs(15),
            OUTPUT_LIMIT,
        )?;
        if probe.exit != 0 || probe.stdout != format!("{BUILD_VERSION}\n").as_bytes() {
            return Err(format!("{name} build version mismatch"));
        }
    }
    let module = process::command(
        Path::new("go"),
        &[
            "version".into(),
            "-m".into(),
            go.to_string_lossy().into_owned(),
        ],
        root,
        &BTreeMap::new(),
        temporary,
        "go-module",
        Duration::from_secs(120),
        OUTPUT_LIMIT,
    )?;
    if !String::from_utf8_lossy(&module).contains(&format!("vcs.revision={REVISION}")) {
        return Err("built Go binary lacks pinned revision".into());
    }
    let current = selected_runtime(root, upstream, temporary)?;
    if current.go_version != runtime.go_version
        || current.go_platform != runtime.go_platform
        || current.rust_host != runtime.rust_host
        || current.cleanup != runtime.cleanup
    {
        return Err("runtime provenance changed during build".into());
    }
    Ok(Binaries { go, rust })
}

pub(super) fn git_status(
    upstream: &Path,
    temporary: &TempDir,
    label: &str,
) -> Result<Vec<u8>, String> {
    process::command(
        Path::new("git"),
        &strings(&["status", "--porcelain=v1", "--untracked-files=all"]),
        upstream,
        &BTreeMap::new(),
        temporary,
        label,
        Duration::from_secs(30),
        OUTPUT_LIMIT,
    )
}

fn verify_map(root: &Path, hashes: &serde_json::Map<String, Value>) -> Result<(), String> {
    for (path, hash) in hashes {
        let expected = hash.as_str().ok_or("invalid source hash")?;
        let actual = sha256_bytes(&read(&root.join(path))?);
        if actual != expected && !declared_transition(path, expected, &actual) {
            return Err(format!("source pin changed for {path}"));
        }
    }
    Ok(())
}

pub(super) const DECLARED_TRANSITIONS: [(&str, &str, &str); 4] = [
    (
        "Cargo.toml",
        "7a3c9b9d1802ee4c76f10395b7b9aef5cc38833ee1b783f73571e6826c1174b2",
        "7a4da4825aee1dd319e5450233c25bfc5a5e9a953bf502b4a6cc491fabba3730",
    ),
    (
        "Cargo.lock",
        "693e0834d122c0f611f9a4a344770fcad9fd49bf476307f679fae038b13be7ed",
        "e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82",
    ),
    (
        "crates/rustleaks-cli/Cargo.toml",
        "b7315db74ada15efc2eead6e2be517cc77110f811fe570a9c61e4afb1dd17483",
        "1b8c67bcb3bb8cb4567295e665bea6b77aefae5dcfde48012c7e9ecd51dd17fb",
    ),
    (
        "crates/rustleaks-cli/src/config.rs",
        "ccabcea38b0fdbedcd8f88fa34686215b2840b67a8d5e691554f2a47969349ec",
        "6a083b4e5647f7899d2a13f03624fc91f0e1f0816bfaba200a142811ca320442",
    ),
];

fn declared_transition(path: &str, expected: &str, actual: &str) -> bool {
    DECLARED_TRANSITIONS.contains(&(path, expected, actual))
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::{DECLARED_TRANSITIONS, declared_transition};

    #[test]
    fn only_declared_coordinator_transitions_are_accepted() {
        for &(path, expected, actual) in &DECLARED_TRANSITIONS {
            assert!(declared_transition(path, expected, actual));
        }
        assert!(!declared_transition("Cargo.lock", "wrong", "wrong"));
        assert!(!declared_transition("crates/rustleaks-cli", "old", "new"));
    }
}
