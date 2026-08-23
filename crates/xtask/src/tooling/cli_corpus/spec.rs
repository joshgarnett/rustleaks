//! CLI request, source-pin, runtime, and binary-build contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::process::{self, OUTPUT_LIMIT};
use super::validation::{required_array, required_object, required_str, required_u64};
use super::{TempDir, newline_records, read};
use crate::tooling::support::sha256_bytes;

pub(super) const CASE_COUNT: usize = 34;
pub(super) const VARIANT_COUNT: usize = 119;
pub(super) const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
pub(super) const BUILD_VERSION: &str = "0.1.0-alpha.1";

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
        || required_str(manifest, "build_version", "manifest")? != BUILD_VERSION
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
        ("paired_observation_pair_count", 118),
        ("paired_observation_process_count", 236),
        ("auxiliary_cli_process_count", 4),
        ("fresh_cli_process_count", 240),
        ("exact_variant_count", 100),
        ("versioned_disposition_variant_count", 19),
        (
            "complete_duplicate_preserving_finding_count_both_implementations",
            100,
        ),
        ("raw_report_byte_count_both_implementations", 48_732),
        ("parser_usage_byte_count_both_implementations", 19_508),
        ("stderr_event_count_both_implementations", 884),
        ("mutation_control_count", 20),
    ] {
        if required_u64(manifest, field, "manifest")? != value {
            return Err(format!("CLI manifest {field} changed"));
        }
    }
    if required_str(manifest, "runtime_provenance_policy", "manifest")?
        != "independently-validated-then-omitted"
    {
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
    verify_trees(
        upstream,
        required_object(manifest, "go_runtime_tree_sha256", "manifest")?,
    )?;
    verify_trees(
        root,
        required_object(manifest, "rust_runtime_tree_sha256", "manifest")?,
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
        || !(fields[0] == "go1.25"
            || fields[0]
                .strip_prefix("go1.25.")
                .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())))
    {
        return Err("selected Go runtime is outside 1.25".into());
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

fn verify_trees(root: &Path, hashes: &serde_json::Map<String, Value>) -> Result<(), String> {
    for (path, hash) in hashes {
        let expected = hash.as_str().ok_or("invalid tree hash")?;
        let actual = tree_hash(root, path)?;
        if actual != expected && !declared_transition(path, expected, &actual) {
            return Err(format!("runtime tree pin changed for {path}"));
        }
    }
    Ok(())
}

pub(super) const DECLARED_TRANSITIONS: [(&str, &str, &str); 10] = [
    (
        "Cargo.lock",
        "8b3054f67f1b52a8bda4ffab8f5ce9a961c091d924f5b75880624bbd125ae567",
        "81059f032e7b4e4330dbc035d6fff09f52c0d2a1fb7af20d36437a993cc64320",
    ),
    (
        "crates/rustleaks-cli/src/output.rs",
        "800a1c3350f56b4f7af25193e6c5d1a54e3cb44d8273ecdebd5f4bbb45b000ba",
        "b237b1f765275d3ebd9b6fe83bc4c78aaf6cb70701b8d1bcda983c51398340e7",
    ),
    (
        "crates/rustleaks-cli",
        "c175d8ecdafddb9676df724db36a61ecde033bca37b37497ea7ece18a9c306ae",
        "673205da570d79a356069e4b2f07f37aa0c18fc21f101888d29b0d02460a790e",
    ),
    (
        "crates/rustleaks-core",
        "9d1d5883df0730eae8cdbc7008257083a6e8fc7521d3a313f8674cab2a9959a8",
        "294fef4563ca3c85bec379bd17c59e9e7ad7bf83bbcf82a429a294f1a106ecd9",
    ),
    (
        "crates/rustleaks-report",
        "6a4ebf0277309b3e8bbf6e52b3d04be8fee323014ab7a341e816532d12da0d8c",
        "b6fe16e5ea5b7a5434717c3ce7c161a49fd8e26460367670b37af1c5deebe9d9",
    ),
    (
        "crates/rustleaks-sources",
        "599c67b9289eb073c864c7fa3ca0e860d4bb4355aaa66c7e1a05d7d226109b64",
        "81b2a3e05aacf7d3d806163099e59a2bfeb30f16ccfaa420c90fa9be540befde",
    ),
    (
        "crates/rustleaks-bzip2",
        "eff6fa1410ebf53eebe2052cb48ca1f42e72e16230407490b86f171fac9e6d32",
        "0ef028bb702d4714b78432d0cbc9f8f7cce3c2db3dc4a220b562eae00189e185",
    ),
    (
        "crates/rustleaks-compcol",
        "244e1c88bc0eaa9866f92f5c851781d5273cd911d7fd6218a7d6f79a03fcdaf6",
        "2317ab99087e5f721638bb5a41134c2784d73ac93dcc782af34085823c7ad9fa",
    ),
    (
        "crates/rustleaks-rar-codec",
        "188596cdee2d5b251ac88c6a7d55d3f9ebb6c95d21c5f99abecbf8e50d7e9586",
        "ddffa1487347c797fc035bd018ded0189e6fbb6c360258ca18f1a19beefe8ae1",
    ),
    (
        "crates/rustleaks-sevenz",
        "4fde1e7cc679c93d6cad1714da6961b4d20e0215854b0b1016a9fea721ba33ce",
        "ae212024414a86cf443f5ae54c3f7dfcdabcfceb05b2cf9d75a3062208e106f7",
    ),
];

fn declared_transition(path: &str, expected: &str, actual: &str) -> bool {
    DECLARED_TRANSITIONS.contains(&(path, expected, actual))
}

pub(super) fn tree_hash(root: &Path, relative: &str) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(&root.join(relative), &mut files)?;
    files.sort_by_key(|path| {
        path.strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    });
    let mut digest = Sha256::new();
    for path in files {
        let name = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/")
            .into_bytes();
        if name.windows(b"/fuzz/".len()).any(|part| part == b"/fuzz/") {
            continue;
        }
        let bytes = read(&path)?;
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(&name);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    let digest = digest.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|e| format!("cannot walk {}: {e}", path.display()))? {
        let path = entry.map_err(|e| format!("walk error: {e}"))?.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if meta.is_dir() {
            collect_files(&path, out)?;
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
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
