//! Pinned-Go generation and verification of the source compatibility corpus.

mod controls;
mod controls_archive;
mod process;
mod spec;
mod validation;

use std::fs;
use std::path::Path;

use serde_json::Value;

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
explicit per-ID gap list where native or Rust implementation evidence is still
mandatory.

Regenerate or verify from the repository root:

```sh
cargo xtask generate source
cargo xtask generate source --check
```

Outcomes record the generating GOOS/GOARCH. Windows symlink behavior and native
separator metadata require native Windows CI confirmation rather than emulation.
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
    let coverage = read(&corpus.join("coverage-v1.json"))?;
    let negative = read(&corpus.join("negative-controls-v1.json"))?;
    let legacy_readme = read(&corpus.join("README.md"))?;
    let legacy_manifest = read(&corpus.join("manifest-v1.json"))?;
    let legacy_outcomes = read(&corpus.join("outcomes-v1.jsonl"))?;
    let coverage_value = parse_json(&coverage, "source coverage")?;
    let negative_value = parse_json(&negative, "source negative controls")?;
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
    validation::validate_all(
        root,
        &request_values,
        &observed.values,
        OutcomeBaseline {
            values: &legacy_outcome_values,
            bytes: &legacy_outcomes,
        },
        &coverage_value,
        &negative_value,
        &manifest_value,
    )?;
    if process::git_status(&upstream, &temporary, "after")? != status_before {
        return Err("upstream checkout changed during source generation".into());
    }

    let (outcome_bytes, outcome_values) = if check {
        (&legacy_outcomes[..], &legacy_outcome_values[..])
    } else {
        (&observed.bytes[..], &observed.values[..])
    };
    let manifest = validation::render_manifest(
        &legacy_manifest,
        &manifest_value,
        README.as_bytes(),
        outcome_bytes,
        outcome_values,
    )?;
    let mut tree = GeneratedTree::default();
    tree.insert("requests-v1.jsonl", requests)?;
    tree.insert("outcomes-v1.jsonl", outcome_bytes)?;
    tree.insert("coverage-v1.json", coverage)?;
    tree.insert("negative-controls-v1.json", negative)?;
    tree.insert("README.md", README.as_bytes())?;
    tree.insert("manifest-v1.json", manifest.clone())?;
    Ok(Generated { tree, manifest })
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
    use super::newline_records;

    #[test]
    fn jsonl_boundaries_fail_closed() {
        assert!(newline_records(b"{}", "test").is_err());
        assert!(newline_records(b"{}\n\n", "test").is_err());
        assert_eq!(newline_records(b"{}\n[]\n", "test").unwrap().len(), 2);
    }
}
