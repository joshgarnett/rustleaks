//! Pinned-Go generation and verification of the source compatibility corpus.

mod controls;
mod controls_archive;
mod process;
mod spec;
mod validation;

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::artifacts::{GeneratedTree, OutcomeBaseline};
use super::support::TempDir;

const README: &str = r"# Source oracle corpus v1

This corpus freezes reader, file, directory, symlink, and archive behavior from
pinned Gitleaks `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. Each of its 124 requests runs in a
fresh Go child with a 15-second deadline, an 8 MiB per-stream ceiling, a 512 MiB
Go memory limit, and at most two Go scheduler threads.

Byte-bearing fragment and finding fields are base64 encoded. Both emission-order
and canonical fragment views preserve duplicates; `bytes_nil` distinguishes nil
from empty byte slices. Archive requests use provenance-tracked copies under
`compat/fixtures/upstream`, whose hashes are frozen in `coverage-v1.json`.
`coverage-v1.json` embeds the authoritative definition for every `SRC-001`
through `SRC-030`, material assertions aligned to those definitions, and an
explicit per-ID gap list for unresolved behavior that still needs separately
controlled evidence.

Regenerate or verify from the repository root:

```sh
cargo xtask generate source
cargo xtask generate source --check
```

Outcomes record the generating GOOS/GOARCH. Native Linux and Windows workflows
replay the pinned source oracle and target-specific Bazel tests; the Windows
suite directly checks raw and slash-normalized path matching. The payload-free
`native-windows-v1.json` ledger binds complete x64 and ARM64 observations by
raw and platform-neutral SHA-256 values while listing every semantic and
structural difference from the committed Darwin baseline. The pinned Go oracle
cannot produce Unix-equivalent followed-symlink observations on Windows, so
the ledger records target-only or empty results as an unavailable dimension,
not as fabricated equality. Each successful Windows replay also publishes a
payload-free per-record hash ledger for review.
";

pub(crate) fn check_source_corpus(root: &Path) -> Result<(), String> {
    generate_and_apply(root, &root.join("compat/source-corpus"), true)
}

pub(crate) fn write_source_corpus(root: &Path, output_root: &Path) -> Result<(), String> {
    generate_and_apply(root, output_root, false)
}

fn generate_and_apply(root: &Path, output_root: &Path, check: bool) -> Result<(), String> {
    let generated = generate(root, check)?;
    generated.tree.write_or_check(output_root, check)?;
    println!("{}", String::from_utf8_lossy(&generated.manifest));
    Ok(())
}

struct Generated {
    tree: GeneratedTree,
    manifest: Vec<u8>,
}

fn generate(root: &Path, check: bool) -> Result<Generated, String> {
    let corpus = root.join("compat/source-corpus");
    let requests = read(&corpus.join("requests-v1.jsonl"))?;
    let legacy_coverage = read(&corpus.join("coverage-v1.json"))?;
    let coverage = transition_coverage(&legacy_coverage)?;
    let negative = read(&corpus.join("negative-controls-v1.json"))?;
    let native_windows = read(&corpus.join("native-windows-v1.json"))?;
    let legacy_readme = read(&corpus.join("README.md"))?;
    let legacy_manifest = read(&corpus.join("manifest-v1.json"))?;
    let legacy_outcomes = read(&corpus.join("outcomes-v1.jsonl"))?;
    let coverage_value = parse_json(&coverage, "source coverage")?;
    let negative_value = parse_json(&negative, "source negative controls")?;
    let native_windows_value = parse_json(&native_windows, "native Windows source ledger")?;
    let manifest_value = parse_json(&legacy_manifest, "source manifest")?;
    let legacy_outcome_values = parse_jsonl(&legacy_outcomes, "committed source outcomes")?;
    let request_values = spec::validate_inputs(
        &requests,
        &coverage,
        &coverage_value,
        &negative,
        &negative_value,
        &legacy_readme,
        &manifest_value,
    )?;
    spec::validate_native_windows_manifest(&native_windows, &manifest_value)?;

    let upstream = root
        .parent()
        .ok_or_else(|| format!("repository root {} has no parent", root.display()))?
        .join("gitleaks");
    let temporary = TempDir::new("source-corpus")?;
    spec::validate_upstream(root, &upstream, &coverage_value, &temporary)?;
    let status_before = process::git_status(&upstream, &temporary, "before")?;
    if status_before
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .any(|line| !line.starts_with(b"?? "))
    {
        return Err("pinned upstream checkout has tracked changes".into());
    }
    let observed = process::observe(
        root,
        &upstream,
        &request_values,
        &requests,
        &manifest_value,
        &temporary,
    )?;
    write_observation_ledger(&observed)?;
    validation::validate_all(
        root,
        &request_values,
        OutcomeBaseline {
            values: &observed.values,
            bytes: &observed.bytes,
        },
        OutcomeBaseline {
            values: &legacy_outcome_values,
            bytes: &legacy_outcomes,
        },
        validation::ValidationMetadata {
            coverage: &coverage_value,
            negative: &negative_value,
            native_windows: &native_windows_value,
            manifest: &manifest_value,
        },
    )?;
    validate_regeneration_platform(check, &observed, &manifest_value)?;
    if process::git_status(&upstream, &temporary, "after")? != status_before {
        return Err("upstream checkout changed during source generation".into());
    }

    let (outcome_bytes, outcome_values) =
        selected_outcomes(check, &legacy_outcomes, &legacy_outcome_values, &observed);
    let manifest = validation::render_manifest(
        &legacy_manifest,
        &manifest_value,
        README.as_bytes(),
        &coverage,
        &native_windows,
        outcome_bytes,
        outcome_values,
    )?;
    let tree = generated_tree(
        requests,
        outcome_bytes,
        coverage,
        negative,
        native_windows,
        manifest.clone(),
    )?;
    Ok(Generated { tree, manifest })
}

fn selected_outcomes<'a>(
    check: bool,
    legacy_bytes: &'a [u8],
    legacy_values: &'a [Value],
    observed: &'a process::Observed,
) -> (&'a [u8], &'a [Value]) {
    if check {
        (legacy_bytes, legacy_values)
    } else {
        (&observed.bytes, &observed.values)
    }
}

fn generated_tree(
    requests: Vec<u8>,
    outcomes: &[u8],
    coverage: Vec<u8>,
    negative: Vec<u8>,
    native_windows: Vec<u8>,
    manifest: Vec<u8>,
) -> Result<GeneratedTree, String> {
    let mut tree = GeneratedTree::default();
    tree.insert("requests-v1.jsonl", requests)?;
    tree.insert("outcomes-v1.jsonl", outcomes)?;
    tree.insert("coverage-v1.json", coverage)?;
    tree.insert("negative-controls-v1.json", negative)?;
    tree.insert("native-windows-v1.json", native_windows)?;
    tree.insert("README.md", README.as_bytes())?;
    tree.insert("manifest-v1.json", manifest)?;
    Ok(tree)
}

fn observation_ledger(observed: &process::Observed) -> Result<Vec<u8>, String> {
    let lines = newline_records(&observed.bytes, "observed source outcomes")?;
    if lines.len() != observed.values.len() {
        return Err("source observation ledger count changed".into());
    }
    let mut semantic_outcomes = Vec::new();
    let mut records = Vec::with_capacity(lines.len());
    for (line, value) in lines.iter().zip(&observed.values) {
        let id = validation::required_str(value, "id", "source outcome")?;
        let mut semantic = value.clone();
        semantic
            .as_object_mut()
            .ok_or_else(|| format!("source outcome {id} is not an object"))?
            .remove("platform")
            .ok_or_else(|| format!("source outcome {id} has no platform"))?;
        let mut semantic_bytes = serde_json::to_vec(&semantic)
            .map_err(|error| format!("cannot render source outcome {id}: {error}"))?;
        semantic_bytes.push(b'\n');
        let count = |field: &str| -> Result<usize, String> {
            value
                .get(field)
                .and_then(Value::as_array)
                .map(Vec::len)
                .ok_or_else(|| format!("source outcome {id} has no {field} array"))
        };
        records.push(json!({
            "id": id,
            "outcome_sha256": crate::tooling::support::sha256_bytes(line),
            "semantic_sha256": crate::tooling::support::sha256_bytes(&semantic_bytes),
            "fragment_count": count("fragments")?,
            "canonical_fragment_count": count("canonical_fragments")?,
            "finding_count": count("findings")?,
            "issue_count": count("issues")?,
            "has_error": !value.get("error").is_some_and(Value::is_null),
        }));
        semantic_outcomes.extend_from_slice(&semantic_bytes);
    }
    let first = observed
        .values
        .first()
        .ok_or("source observations are empty")?;
    let ledger = json!({
        "schema_version": 1,
        "protocol_version": spec::PROTOCOL_VERSION,
        "oracle_mode": "source",
        "upstream_revision": spec::REVISION,
        "default_config_sha256": spec::CONFIG_SHA256,
        "go_version": validation::required_str(first, "go_version", "source outcome")?,
        "platform": validation::required_str(first, "platform", "source outcome")?,
        "record_count": records.len(),
        "outcomes_sha256": crate::tooling::support::sha256_bytes(&observed.bytes),
        "semantic_outcomes_sha256": crate::tooling::support::sha256_bytes(&semantic_outcomes),
        "records": records,
    });
    let mut bytes = serde_json::to_vec_pretty(&ledger)
        .map_err(|error| format!("cannot render source observation ledger: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_observation_ledger(observed: &process::Observed) -> Result<(), String> {
    if let Some(path) = std::env::var_os("RUSTLEAKS_SOURCE_LEDGER_PATH") {
        fs::write(&path, observation_ledger(observed)?)
            .map_err(|error| format!("cannot write source observation ledger: {error}"))?;
    }
    Ok(())
}

fn validate_regeneration_platform(
    check: bool,
    observed: &process::Observed,
    manifest: &Value,
) -> Result<(), String> {
    if check {
        return Ok(());
    }
    let observed_platform = validation::required_str(
        observed
            .values
            .first()
            .ok_or("source observations are empty")?,
        "platform",
        "observed source outcome",
    )?;
    let committed_platform = validation::required_str(manifest, "platform", "source manifest")?;
    if observed_platform != committed_platform {
        return Err(format!(
            "canonical source regeneration requires {committed_platform}, got {observed_platform}; use --check for native replay"
        ));
    }
    Ok(())
}

fn transition_coverage(legacy: &[u8]) -> Result<Vec<u8>, String> {
    let mut rendered = replace_text_transition(
        legacy,
        "  \"platform_contract\": \"host GOOS/GOARCH is recorded; Windows symlink creation/metadata remains a native CI lane obligation\",\n",
        "  \"platform_contract\": \"host GOOS/GOARCH is recorded; native Linux and Windows workflows replay pinned oracle generation and target-specific Bazel tests\",\n",
        "source platform contract",
    )?;
    rendered = replace_text_transition(
        &rendered,
        "    \"SRC-012\": \"native Unix permission denial is covered; metadata TOCTOU still requires deterministic filesystem fault injection\",\n    \"SRC-013\": \"Windows raw-plus-slash allowlist fallback requires native Windows\",\n    \"SRC-016\": \"chained, dangling, and looping links are covered; an escaping-but-valid target requires a separately controlled parent fixture\",\n    \"SRC-017\": \"NFC/NFD and Windows drive/UNC/extended/mixed spellings are generated natively; Windows evidence requires the declared native workflow to run\",\n",
        "    \"SRC-012\": \"native Unix permission denial is covered; metadata TOCTOU still requires deterministic filesystem fault injection\",\n    \"SRC-016\": \"chained, dangling, and looping links are covered; an escaping-but-valid target requires a separately controlled parent fixture\",\n",
        "resolved Windows source gaps",
    )?;
    replace_text_transition(
        &rendered,
        "    \"SRC-029\": \"Go size/depth gates are covered; Rust checked-overflow, expansion, entry, and spool limits are implementation obligations\",\n    \"SRC-030\": \"native path and permission overlays carry platform provenance; safe Rust crate boundaries and dependency audits are implementation evidence\"\n",
        "    \"SRC-029\": \"Go size/depth gates are covered; Rust checked-overflow, expansion, entry, and spool limits are implementation obligations\"\n",
        "resolved native source workflow gap",
    )
}

fn replace_text_transition(
    bytes: &[u8],
    old: &str,
    new: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let old_count = bytes
        .windows(old.len())
        .filter(|value| *value == old.as_bytes())
        .count();
    let new_count = bytes
        .windows(new.len())
        .filter(|value| *value == new.as_bytes())
        .count();
    match (old_count, new_count) {
        (1, 0) => {
            let start = bytes
                .windows(old.len())
                .position(|value| value == old.as_bytes())
                .expect("counted transition");
            let mut result = Vec::with_capacity(bytes.len() - old.len() + new.len());
            result.extend_from_slice(&bytes[..start]);
            result.extend_from_slice(new.as_bytes());
            result.extend_from_slice(&bytes[start + old.len()..]);
            Ok(result)
        }
        (0, 1) => Ok(bytes.to_vec()),
        _ => Err(format!(
            "expected exactly one old or current {label}, found {old_count}/{new_count}"
        )),
    }
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn parse_jsonl(bytes: &[u8], label: &str) -> Result<Vec<Value>, String> {
    newline_records(bytes, label)?
        .iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_slice(line)
                .map_err(|error| format!("invalid {label} record {}: {error}", index + 1))
        })
        .collect()
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn newline_records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} JSONL lacks a final newline"));
    }
    let mut records = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            if index == start {
                return Err(format!("{label} JSONL contains a blank line"));
            }
            records.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::process::Observed;
    use super::{newline_records, observation_ledger};
    use crate::tooling::support::sha256_bytes;

    #[test]
    fn jsonl_boundaries_fail_closed() {
        assert!(newline_records(b"{}", "test").is_err());
        assert!(newline_records(b"{}\n\n", "test").is_err());
        assert_eq!(newline_records(b"{}\n[]\n", "test").unwrap().len(), 2);
    }

    #[test]
    fn observation_ledger_retains_hashes_without_payloads() {
        let bytes = br#"{"id":"case","go_version":"go1.26.7","platform":"windows/amd64","payload":"reviewed-fixture-value","fragments":[],"canonical_fragments":[],"findings":[],"issues":[],"error":null}
"#
        .to_vec();
        let observed = Observed {
            values: vec![serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap()],
            bytes: bytes.clone(),
        };
        let rendered = observation_ledger(&observed).unwrap();
        assert!(
            !rendered
                .windows(b"reviewed-fixture-value".len())
                .any(|window| window == b"reviewed-fixture-value")
        );
        let ledger: Value = serde_json::from_slice(&rendered).unwrap();
        assert_eq!(ledger["platform"], json!("windows/amd64"));
        assert_eq!(ledger["outcomes_sha256"], json!(sha256_bytes(&bytes)));
        assert_eq!(ledger["records"][0]["id"], json!("case"));
        assert_eq!(
            ledger["records"][0]["outcome_sha256"],
            json!(sha256_bytes(&bytes))
        );
        assert!(ledger["records"][0]["semantic_sha256"].is_string());
    }
}
