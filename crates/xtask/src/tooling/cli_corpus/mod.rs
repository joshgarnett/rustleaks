//! Rust CLI replay against immutable historical observations.

mod fixture;
mod normalize;
mod observe;
mod process;
mod spec;
mod validation;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::presentation::{self, Disposition};
use super::support::{TempDir, sha256_bytes};

// Historical corpus bytes are accepted once. A replay never refreshes them
// from the implementation under test or the retired external oracle.
const FROZEN_FILES: &[(&str, &str)] = &[
    (
        "manifest-v1.json",
        "d43854767a13d8a128480d820ba4c9beaa86c8192ac8e633f0353d74833da356",
    ),
    (
        "native-linux-v1.json",
        "b13c67ca0b0fba8dd62364699c898be335ac174f494b3be6450b33a30dbeb240",
    ),
    (
        "native-windows-v1.json",
        "af498655aa66898f52a6ce4981d1ea975c4f46d4d08a2b79af4e13b31b16a335",
    ),
    (
        "negative-controls-v1.json",
        "fd24952e9e8e28dae4f8a581ae6bbb20bfa720ac75e2028a717850cc9ac6f152",
    ),
    (
        "outcomes-v1.jsonl",
        "00bd41d862e473847a40373d89f79aa597aa5be7414fa4a1248d12cd3a497de9",
    ),
    (
        "requests-v1.jsonl",
        "32126f7d65e15f526836391b681811809d799eaf79066b5e60f9bb48191eb6c4",
    ),
    (
        "unix-logical-name-v1.json",
        "9fb7a94501f91ecd7a1cb68658b5497e99993c644d818b117eb1f2770d0ae30b",
    ),
    (
        "unix-path-v1.json",
        "0e1a0b277a71bbd09e5a24473a8b20c7feebafebd56389220ca493b7928bda61",
    ),
];

pub(crate) fn check_cli_corpus(
    root: &Path,
    rust_binary: &Path,
    fake_git_binary: &Path,
) -> Result<(), String> {
    let rust_binary = executable_path(rust_binary, "Rust CLI")?;
    let fake_git_binary = executable_path(fake_git_binary, "CLI fixture helper")?;
    let git = git_executable()?;
    let files = read_frozen_files(&root.join("compat/cli-corpus"))?;
    let manifest = parse_json(&files["manifest-v1.json"], "CLI manifest")?;
    let negative = parse_json(&files["negative-controls-v1.json"], "CLI controls")?;
    let rows = spec::validate_inputs(
        &files["requests-v1.jsonl"],
        &files["negative-controls-v1.json"],
        &negative,
        &manifest,
    )?;
    let variants = validation::bind_expected(&rows, &files["outcomes-v1.jsonl"])?;
    let ledger = presentation::load_ledger(root)?;
    let mut records = Vec::new();
    let mut executed = 0;
    let mut inapplicable = 0;
    let mut native_dispositions = 0;
    let mut used = BTreeSet::new();
    let mut skipped = BTreeSet::new();
    for variant in variants {
        if let Some(reason) =
            validation::inapplicable(&variant.request, cfg!(windows), cfg!(target_os = "linux"))
        {
            inapplicable += 1;
            skipped.insert(variant.id.clone());
            records.push(
                json!({"id": variant.id, "status": "platform-inapplicable", "reason": reason}),
            );
            continue;
        }
        let actual = observe::observe(
            &rust_binary,
            &variant.case_id,
            &variant.request,
            &fake_git_binary,
        )?;
        let (expected, build_version_expectation) = validation::current_build_expectation(
            &variant.id,
            &variant.expected,
            env!("CARGO_PKG_VERSION"),
        )?;
        let dispositions = ledger
            .dispositions
            .iter()
            .filter(|disposition| disposition.variant == variant.id)
            .collect::<Vec<_>>();
        let presentation_dispositions = validation::compare(
            &variant.id,
            &actual,
            &expected,
            cfg!(windows),
            &dispositions,
        )?;
        check_usage_range(&variant.id, &actual, &dispositions)?;
        used.extend(presentation_dispositions.iter().cloned());
        executed += 1;
        let disposition = validation::native_disposition(&variant.id, cfg!(windows));
        native_dispositions += usize::from(disposition.is_some());
        records.push(json!({
            "id": variant.id, "status": "executed", "native_disposition": disposition,
            "build_version_expectation": build_version_expectation,
            "presentation_dispositions": presentation_dispositions,
            "observation": safe_observation_summary(&actual.value, &variant.id)?
        }));
    }
    if executed + inapplicable != spec::VARIANT_COUNT {
        return Err("CLI executed and inapplicable identity counts do not reconcile".into());
    }
    require_used(&ledger.dispositions, &used, &skipped)?;
    let ledger = json!({
        "schema_version": 1, "mode": "rust-cli-regression",
        "historical_upstream_revision": spec::REVISION,
        "historical_build_version": spec::BUILD_VERSION,
        "current_build_version": env!("CARGO_PKG_VERSION"),
        "default_config_sha256": spec::CONFIG_SHA256,
        "frozen_outcomes_sha256": sha256_bytes(&files["outcomes-v1.jsonl"]),
        "cli_binary_sha256": sha256_bytes(&read(&rust_binary)?),
        "fixture_binary_sha256": sha256_bytes(&read(&fake_git_binary)?),
        "git_binary_sha256": sha256_bytes(&read(&git)?),
        "platform": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        "declared_variants": spec::VARIANT_COUNT, "executed_variants": executed,
        "platform_inapplicable_variants": inapplicable, "native_disposition_variants": native_dispositions,
        "presentation_dispositions": used.len(),
        "records": records
    });
    write_observation_ledger(&ledger)?;
    println!(
        "CLI regression: {} declared variants, {executed} executed, {inapplicable} platform-inapplicable, {native_dispositions} native dispositions, {} presentation dispositions",
        spec::VARIANT_COUNT,
        used.len()
    );
    Ok(())
}

/// Reads every frozen corpus file and rejects any whose digest changed.
fn read_frozen_files(corpus: &Path) -> Result<BTreeMap<&'static str, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    for (name, digest) in FROZEN_FILES {
        let bytes = read(&corpus.join(name))?;
        if sha256_bytes(&bytes) != *digest {
            return Err(format!("frozen CLI evidence changed: {name}"));
        }
        files.insert(*name, bytes);
    }
    Ok(files)
}

/// Checks that the usage event range inferred from recorded text agrees with
/// the range found while parsing stderr lines.
///
/// A usage disposition removes frozen usage events by the inferred range, so
/// the two must agree on every variant whose usage text is unchanged. This
/// runs after the comparison so that a real usage change reports its field.
fn check_usage_range(
    id: &str,
    actual: &observe::Observed,
    dispositions: &[&Disposition],
) -> Result<(), String> {
    if dispositions
        .iter()
        .any(|disposition| disposition.field == presentation::Field::StderrUsage)
        || actual.native.usage_events == presentation::usage_event_range(&actual.value, id)?
    {
        Ok(())
    } else {
        Err(format!("{id}: usage event ranges disagree"))
    }
}

/// Rejects ledger dispositions that the replay did not use, except those for
/// variants that are not applicable on this platform.
fn require_used(
    dispositions: &[Disposition],
    used: &BTreeSet<String>,
    skipped: &BTreeSet<String>,
) -> Result<(), String> {
    let unused = dispositions
        .iter()
        .filter(|disposition| {
            !used.contains(&disposition.id) && !skipped.contains(&disposition.variant)
        })
        .map(|disposition| disposition.id.as_str())
        .collect::<Vec<_>>();
    if unused.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unused presentation dispositions: {}",
            unused.join(", ")
        ))
    }
}

fn executable_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = std::path::absolute(path)
        .map_err(|error| format!("cannot resolve {label} executable: {error}"))?;
    if !path.is_file() {
        return Err(format!("{label} is not a file"));
    }
    Ok(path)
}

fn write_observation_ledger(ledger: &Value) -> Result<(), String> {
    let path = std::env::var_os("RUSTLEAKS_CLI_LEDGER_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("TEST_UNDECLARED_OUTPUTS_DIR")
                .map(|root| PathBuf::from(root).join("cli-regression-ledger.json"))
        });
    if let Some(path) = path {
        let mut bytes = serde_json::to_vec_pretty(ledger)
            .map_err(|error| format!("cannot encode CLI ledger: {error}"))?;
        bytes.push(b'\n');
        fs::write(path, bytes).map_err(|error| format!("cannot write CLI ledger: {error}"))?;
    }
    Ok(())
}

fn safe_observation_summary(observation: &Value, label: &str) -> Result<Value, String> {
    let events = validation::required_array(observation, "stderr_events", label)?;
    let event_projections = events
        .iter()
        .map(|event| {
            Ok(json!({
                "severity": validation::required_str(event, "severity", label)?,
                "class": validation::required_str(event, "class", label)?,
                "fields": event
                    .get("fields")
                    .ok_or_else(|| format!("{label}: event fields missing"))?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let message_hashes = events
        .iter()
        .map(|event| {
            validation::required_str(event, "normalized_message_base64", label)
                .map(|message| crate::tooling::support::sha256_bytes(message.as_bytes()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let report = observation.get("report").unwrap_or(&Value::Null);
    let report_summary = if report.is_null() {
        Value::Null
    } else {
        json!({
            "state": report.get("state"),
            "bytes": report.get("bytes"),
            "sha256": report.get("sha256"),
        })
    };
    let findings = observation.get("findings").unwrap_or(&Value::Null);
    let findings_bytes = serde_json::to_vec(findings)
        .map_err(|error| format!("cannot hash {label} findings: {error}"))?;
    let projection_bytes = serde_json::to_vec(&event_projections)
        .map_err(|error| format!("cannot hash {label} event projection: {error}"))?;
    Ok(json!({
        "exit": observation.get("exit"),
        "stdout_bytes": observation.get("stdout_bytes"),
        "stdout_sha256": observation.get("stdout_sha256"),
        "stderr_event_count": events.len(),
        "stderr_event_projection_sha256": crate::tooling::support::sha256_bytes(&projection_bytes),
        "stderr_event_projections": event_projections,
        "normalized_message_base64_sha256": message_hashes,
        "stderr_usage_bytes": observation.pointer("/stderr_usage/bytes"),
        "stderr_usage_sha256": observation.pointer("/stderr_usage/sha256"),
        "report": report_summary,
        "finding_count": observation.get("finding_count"),
        "findings_sha256": crate::tooling::support::sha256_bytes(&findings_bytes),
        "child_reaped": observation.get("child_reaped"),
        "stderr_contains_disclosure_marker": observation.get("stderr_contains_disclosure_marker"),
    }))
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn newline_records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} JSONL lacks final newline"));
    }
    let mut records = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            if index == start {
                return Err(format!("{label} contains blank line"));
            }
            records.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    Ok(records)
}

fn git_executable() -> Result<PathBuf, String> {
    runfile("RUSTLEAKS_CLI_GIT_RUNFILE")
}

fn runfile(name: &str) -> Result<PathBuf, String> {
    let key = std::env::var_os(name).ok_or_else(|| format!("missing required {name}"))?;
    if Path::new(&key).is_absolute() {
        return executable_path(Path::new(&key), name);
    }
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            for path in [
                PathBuf::from(&root).join(&key),
                PathBuf::from(root).join("_main").join(&key),
            ] {
                if path.is_file() {
                    return executable_path(&path, name);
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        for line in fs::read_to_string(manifest)
            .map_err(|error| format!("cannot read runfile manifest: {error}"))?
            .lines()
        {
            if let Some((candidate, path)) = line.split_once(' ')
                && (candidate == key.to_string_lossy()
                    || candidate == format!("_main/{}", key.to_string_lossy())
                    || key.to_string_lossy().strip_prefix("../") == Some(candidate))
            {
                return executable_path(Path::new(path), name);
            }
        }
    }
    if cfg!(windows) && key == "git" {
        for parent in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let path = parent.join("git.exe");
            if path.is_file() {
                return executable_path(&path, name);
            }
        }
    }
    Err(format!("cannot resolve required runfile {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "runs in the dedicated Bazel cli_regression_test with native binary runfiles"]
    fn frozen_cli_corpus_replays_with_native_binaries() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let cli = runfile("RUSTLEAKS_CLI_RUNFILE").expect("Bazel Rust CLI runfile");
        let helper =
            runfile("RUSTLEAKS_CLI_FIXTURE_RUNFILE").expect("Bazel native fixture runfile");
        check_cli_corpus(&root, &cli, &helper).expect("frozen Rust CLI regression replay");
    }

    #[test]
    fn usage_range_inference_must_agree_with_parsed_lines() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        let event = |message: &str| {
            json!({"severity": "error", "class": "diagnostic.other", "fields": {},
                "normalized_message_base64": BASE64.encode(message)})
        };
        let usage = "Usage:\n  gitleaks dir [flags]\n";
        let mut actual = observe::Observed {
            value: json!({
                "stderr_usage": {"bytes_base64": BASE64.encode(usage)},
                "stderr_events": [event("Error: synthetic"), event("Usage:"),
                    event("gitleaks dir [flags]"), event("synthetic")],
            }),
            native: observe::NativePresentation {
                usage_events: Some(1..3),
                ..observe::NativePresentation::default()
            },
        };
        check_usage_range("SYN/usage", &actual, &[]).unwrap();
        actual.native.usage_events = Some(1..4);
        assert!(check_usage_range("SYN/usage", &actual, &[]).is_err());
        actual.native.usage_events = None;
        assert!(check_usage_range("SYN/usage", &actual, &[]).is_err());
        let disposition = Disposition {
            id: "SYN-USAGE".into(),
            variant: "SYN/usage".into(),
            field: presentation::Field::StderrUsage,
            frozen_sha256: String::new(),
            expected: "synthetic".into(),
            reason: "synthetic".into(),
        };
        check_usage_range("SYN/usage", &actual, &[&disposition]).unwrap();
        actual.value["stderr_usage"] = Value::Null;
        check_usage_range("SYN/usage", &actual, &[]).unwrap();
    }

    #[test]
    fn unused_dispositions_are_rejected() {
        let disposition = |id: &str, variant: &str| Disposition {
            id: id.into(),
            variant: variant.into(),
            field: presentation::Field::Stdout,
            frozen_sha256: String::new(),
            expected: "synthetic".into(),
            reason: "synthetic".into(),
        };
        let dispositions = [
            disposition("SYN-1", "CASE/used"),
            disposition("SYN-2", "CASE/skipped"),
        ];
        let used = BTreeSet::from(["SYN-1".to_owned()]);
        let skipped = BTreeSet::from(["CASE/skipped".to_owned()]);
        require_used(&dispositions, &used, &skipped).unwrap();
        let error = require_used(&dispositions, &BTreeSet::new(), &skipped).unwrap_err();
        assert!(error.contains("SYN-1"), "{error}");
        assert!(require_used(&dispositions, &used, &BTreeSet::new()).is_err());
    }

    #[test]
    fn jsonl_boundaries_fail_closed() {
        assert!(newline_records(b"{}", "test").is_err());
        assert!(newline_records(b"{}\n\n", "test").is_err());
        assert_eq!(newline_records(b"{}\n[]\n", "test").unwrap().len(), 2);
    }

    #[test]
    fn observation_summary_omits_payloads() {
        let observation = json!({
            "exit": 7, "stdout_base64": "secret-stdout", "stdout_bytes": 14, "stdout_sha256": "a",
            "stderr_events": [{"severity": "error", "class": "diagnostic.other", "fields": {}, "normalized_message_base64": "secret-message"}],
            "stderr_usage": {"bytes": 3, "sha256": "b"},
            "report": {"state": "present", "bytes_base64": "secret-report", "bytes": 16, "sha256": "c"},
            "findings": [{"Secret": "secret-finding"}], "finding_count": 1, "child_reaped": true
        });
        let summary = safe_observation_summary(&observation, "test")
            .unwrap()
            .to_string();
        for payload in [
            "secret-stdout",
            "secret-message",
            "secret-report",
            "secret-finding",
        ] {
            assert!(!summary.contains(payload));
        }
        assert!(summary.contains("findings_sha256"));
    }
}
