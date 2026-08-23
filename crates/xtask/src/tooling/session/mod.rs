//! Pinned-Go generation and verification of the scan-session corpus.

mod controls;
mod process;
mod spec;
mod validation;

use std::fs;
use std::path::Path;

use serde_json::Value;

use super::artifacts::GeneratedTree;
use super::support::TempDir;

const README: &str = r"# Session oracle corpus v1

This corpus freezes pinned Gitleaks `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` session behavior. The generator
runs every one of its 45 requests in a fresh Go child with a
10-second deadline, 4 MiB per-stream output ceiling, 512 MiB Go memory limit,
and explicit input bytes for cross-platform path cases.

`outcomes-v1.jsonl` preserves every Finding field, duplicates, original collection
order, fingerprint mutation, and a separate stable canonical-sort view. Baseline
comparisons mutate each compared and ignored field individually; ignore cases
cover global and commit forms, slash normalization, comments, blanks, malformed
entries, duplicate collapse, and precedence.

Regenerate or verify from the repository root:

```sh
cargo xtask generate session
cargo xtask generate session --check
```

Production safety/unsafe design and Rust implementation claims are outside this packet.
";

pub(crate) fn check_session_corpus(root: &Path) -> Result<(), String> {
    generate_and_apply(root, &root.join("compat/session-corpus"), true)
}

pub(crate) fn write_session_corpus(root: &Path, output_root: &Path) -> Result<(), String> {
    generate_and_apply(root, output_root, false)
}

fn generate_and_apply(root: &Path, output_root: &Path, check: bool) -> Result<(), String> {
    let generated = generate(root)?;
    generated.tree.write_or_check(output_root, check)?;
    println!("{}", String::from_utf8_lossy(&generated.manifest));
    Ok(())
}

struct Generated {
    tree: GeneratedTree,
    manifest: Vec<u8>,
}

fn generate(root: &Path) -> Result<Generated, String> {
    let corpus = root.join("compat/session-corpus");
    let requests = read(&corpus.join("requests-v1.jsonl"))?;
    let coverage = read(&corpus.join("coverage-v1.json"))?;
    let negative = read(&corpus.join("negative-controls-v1.json"))?;
    let legacy_readme = read(&corpus.join("README.md"))?;
    let legacy_manifest = read(&corpus.join("manifest-v1.json"))?;
    let coverage_value = parse_json(&coverage, "session coverage")?;
    let negative_value = parse_json(&negative, "session negative controls")?;
    let manifest_value = parse_json(&legacy_manifest, "session manifest")?;
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
    let temporary = TempDir::new("session-corpus")?;
    spec::validate_upstream(root, &upstream, &coverage_value, &temporary)?;
    let status_before = process::git_status(&upstream, &temporary, "before")?;
    if !status_before.is_empty() {
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
        &request_values,
        &observed.values,
        &observed.bytes,
        &coverage_value,
        &negative_value,
        &manifest_value,
    )?;
    if process::git_status(&upstream, &temporary, "after")? != status_before {
        return Err("upstream checkout changed during session generation".into());
    }

    let manifest =
        validation::render_manifest(&legacy_manifest, &manifest_value, README.as_bytes())?;
    let mut tree = GeneratedTree::default();
    tree.insert("requests-v1.jsonl", requests)?;
    tree.insert("outcomes-v1.jsonl", observed.bytes)?;
    tree.insert("coverage-v1.json", coverage)?;
    tree.insert("negative-controls-v1.json", negative)?;
    tree.insert("README.md", README.as_bytes())?;
    tree.insert("manifest-v1.json", manifest.clone())?;
    Ok(Generated { tree, manifest })
}

fn parse_json(bytes: &[u8], label: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
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
