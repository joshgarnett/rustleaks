//! Exact extraction of semantic assertions from the pinned Go test sources.

#[path = "assertions/model.rs"]
mod model;
#[path = "assertions/spec.rs"]
mod spec;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::super::artifacts::GeneratedTree;
use super::super::support::{command_output, sha256_file};
use model::{Json, jsonl};
use model::{
    array, boolean, byte_text, deep_bytes, float, integer, object, record, source_lines, strings,
    text,
};

const PIN: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
const SOURCE_HASHES: &[(&str, &str)] = &[
    (
        "cmd/generate/config/base/config_test.go",
        "c5e88dcf113ac382043cf037643b142e52d7ccb7523754c8e61aa52bd4bf739f",
    ),
    (
        "cmd/generate/config/utils/generate_test.go",
        "2188f0d2ade645f6996273991a70b1c95e265dd1f0136adaf3e2bdb7affdc077",
    ),
    (
        "config/allowlist_test.go",
        "5cfabc25ece05a39268ba81ca4209d98dc85df828acadfd4927b231f49fe2e7c",
    ),
    (
        "detect/baseline_test.go",
        "4e6e40bae1d71f14acf66f8ebeb1f328607e1ca01b675c28a8447284f5068895",
    ),
    (
        "detect/location_test.go",
        "e04b3bf5d7ca6807b28e2f246d2dc9e52c089d893064782afded9c1202006597",
    ),
    (
        "detect/detect_test.go",
        "191e7178827d790ae7c72f7b17824e3d368fe66b263fb12a9b8f3ede225124d3",
    ),
    (
        "report/finding_test.go",
        "60f6950823fd227c77d65c630b540fdb3dba46b947bda5bf98f5a72d9d513874",
    ),
    (
        "report/junit_test.go",
        "dc298993221456d5b023b6af4d200e6ade47bab1272b92d441d29f27124da558",
    ),
    (
        "report/report_test.go",
        "16763fa5d4794ce1bb11292a2d4d47a90c6fa1fd661d9b621230b25d53835d89",
    ),
];

/// Counts emitted by assertion extraction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AssertionSummary {
    pub(crate) assertions: usize,
    pub(crate) benchmark_links: usize,
    pub(crate) platform_skips: usize,
}

/// Regenerate all three assertion-corpus files into `output`.
pub(crate) fn write_assertions(
    root: &Path,
    upstream: &Path,
    output: &Path,
) -> Result<AssertionSummary, String> {
    generate(root, upstream)?.apply(output, false)
}

/// Compare a candidate assertion-corpus directory with fresh extraction.
pub(crate) fn check_assertions(
    root: &Path,
    upstream: &Path,
    candidate: &Path,
) -> Result<AssertionSummary, String> {
    generate(root, upstream)?.apply(candidate, true)
}

struct Generated {
    tree: GeneratedTree,
    summary: AssertionSummary,
}

impl Generated {
    fn apply(self, root: &Path, check: bool) -> Result<AssertionSummary, String> {
        self.tree.write_or_check(root, check)?;
        Ok(self.summary)
    }
}

fn generate(root: &Path, upstream: &Path) -> Result<Generated, String> {
    validate_sources(upstream)?;
    let mut assertions = spec::build_assertions(upstream)?;
    for row in &mut assertions {
        finalize_assertion(row)?;
    }
    let benchmarks = spec::build_benchmarks();
    let skips = spec::build_skips();
    validate_rows(root, &assertions, &benchmarks, &skips)?;

    let assertion_bytes = jsonl(&assertions)?;
    let mut substituted = assertions.clone();
    substituted[0].set("id", text("AS-SAME-COUNT-SUBSTITUTION"))?;
    if jsonl(&substituted)? == assertion_bytes {
        return Err("same-count identity substitution was not rejected".into());
    }

    let mut tree = GeneratedTree::default();
    let readme = fs::read(root.join("compat/assertion-corpus/README.md"))
        .map_err(|error| format!("cannot read assertion-corpus README: {error}"))?;
    tree.insert("README.md", readme)?;
    tree.insert("assertions.jsonl", assertion_bytes)?;
    tree.insert("benchmark-links.jsonl", jsonl(&benchmarks)?)?;
    tree.insert("platform-skips.jsonl", jsonl(&skips)?)?;
    Ok(Generated {
        tree,
        summary: AssertionSummary {
            assertions: assertions.len(),
            benchmark_links: benchmarks.len(),
            platform_skips: skips.len(),
        },
    })
}

fn validate_sources(upstream: &Path) -> Result<(), String> {
    let revision = command_output(
        Command::new("git")
            .args(["-C"])
            .arg(upstream)
            .args(["rev-parse", "HEAD"]),
    )?;
    if revision != PIN {
        return Err(format!("upstream revision {revision} != {PIN}"));
    }
    for (relative, expected) in SOURCE_HASHES {
        let path = upstream.join(relative);
        let actual = sha256_file(&path)?;
        if &actual != expected {
            return Err(format!("source drift {relative}: {actual} != {expected}"));
        }
    }
    Ok(())
}

fn validate_rows(
    root: &Path,
    assertions: &[Json],
    benchmarks: &[Json],
    skips: &[Json],
) -> Result<(), String> {
    if assertions.len() != 283 || benchmarks.len() != 6 || skips.len() != 2 {
        return Err(format!(
            "assertion corpus count mismatch: assertions={} benchmark_links={} platform_skips={}",
            assertions.len(),
            benchmarks.len(),
            skips.len()
        ));
    }
    let ids = assertions
        .iter()
        .map(|row| required_text(row, "id"))
        .collect::<Result<Vec<_>, _>>()?;
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("duplicate assertion identities".into());
    }
    let manifest = fs::read_to_string(root.join("compat/test-manifest.toml"))
        .map_err(|error| format!("cannot read test manifest: {error}"))?;
    let cases = manifest_ids(&manifest, "case");
    let benchmark_ids = manifest_ids(&manifest, "benchmark");
    let fixtures = manifest_ids(&manifest, "fixture");
    for row in assertions {
        let id = required_text(row, "id")?;
        let parent = required_text(row, "parent_case_id")?;
        if !cases.contains(parent) {
            return Err(format!("missing manifest parent {parent}"));
        }
        for fixture in required_array(row, "fixture_ids")? {
            let fixture = fixture
                .as_text()
                .ok_or_else(|| format!("assertion {id} has non-string fixture"))?;
            if !fixtures.contains(fixture) {
                return Err(format!("missing manifest fixture {fixture}"));
            }
        }
        let status = required_text(row, "status")?;
        match status {
            "implemented" => {
                for field in ["rust_test", "rust_evidence"] {
                    if required_text(row, field)?.is_empty() {
                        return Err(format!("implemented assertion {id} lacks {field}"));
                    }
                }
            }
            "final-disposition"
                if required_text(row, "rust_evidence")?
                    .starts_with("Final release disposition:") => {}
            _ => return Err(format!("assertion {id} has non-final status {status}")),
        }
    }
    for row in benchmarks {
        let id = required_text(row, "id")?;
        let benchmark = required_text(row, "benchmark_id")?;
        if !benchmark_ids.contains(benchmark) {
            return Err(format!("missing manifest benchmark {benchmark}"));
        }
        validate_implemented(row, "benchmark link", id, true)?;
    }
    for row in skips {
        let id = required_text(row, "id")?;
        let parent = required_text(row, "parent_case_id")?;
        if !cases.contains(parent) {
            return Err(format!("missing skip case {parent}"));
        }
        for child in required_array(row, "child_case_ids")? {
            let child = child
                .as_text()
                .ok_or_else(|| format!("skip {id} has non-string child"))?;
            if !cases.contains(child) {
                return Err(format!("missing skip case {child}"));
            }
        }
        validate_implemented(row, "platform branch", id, false)?;
    }
    Ok(())
}

fn validate_implemented(
    row: &Json,
    label: &str,
    id: &str,
    require_test: bool,
) -> Result<(), String> {
    if required_text(row, "status")? != "implemented" {
        return Err(format!("{label} {id} is not implemented"));
    }
    if require_test && required_text(row, "rust_test")?.is_empty() {
        return Err(format!("{label} {id} lacks Rust test"));
    }
    if required_text(row, "rust_evidence")?.is_empty() {
        return Err(format!("{label} {id} lacks Rust evidence"));
    }
    Ok(())
}

fn finalize_assertion(row: &mut Json) -> Result<(), String> {
    if required_text(row, "status")? != "pending" {
        return Ok(());
    }
    let domain = required_text(row, "domain")?;
    let (test, evidence) = match domain {
        "config-global-allowlist-path" | "config-global-allowlist-regex" | "config-allowlist" => (
            "frozen_allowlist_corpus_matches_go",
            "crates/rustleaks-core/tests/allowlist.rs; cargo xtask allowlist-check",
        ),
        "baseline-load" | "baseline-suppression" | "ignore-normalization" => (
            "session_corpus_matches_every_frozen_oracle_outcome",
            "crates/rustleaks-core/tests/session_corpus.rs; cargo xtask session-check",
        ),
        "report-junit" | "report-json" => (
            "every_representable_builtin_report_case_replays_exact_oracle_bytes",
            "crates/rustleaks-report/tests/report_corpus.rs; cargo xtask report-check",
        ),
        "source-git-staged" => (
            "valid_git_corpus_fragments_match_and_failures_have_safe_dispositions",
            "crates/rustleaks-sources/tests/git_corpus.rs; cargo xtask git-check",
        ),
        "source-symlink" => (
            "complete_source_corpus_matches_frozen_go_outcomes_or_exact_safe_dispositions",
            "crates/rustleaks-sources/tests/source_corpus.rs; cargo xtask source-check",
        ),
        "regex-generator-semi-generic" | "regex-generator-unique-token" => {
            row.set("rust_evidence", text("Final release disposition: this upstream Go-only default-construction helper is not part of the Rustleaks API; the byte-exact packaged configuration and every emitted default-rule sample are replayed by crates/rustleaks-core/tests/default_rule_corpus.rs"))?;
            row.set("status", text("final-disposition"))?;
            return Ok(());
        }
        _ => return Err(format!("unmapped assertion domain {domain}")),
    };
    row.set("rust_test", text(test))?;
    row.set("rust_evidence", text(evidence))?;
    row.set("status", text("implemented"))
}

fn manifest_ids(manifest: &str, section: &str) -> BTreeSet<String> {
    let marker = format!("[[{section}]]");
    manifest
        .split(&marker)
        .skip(1)
        .filter_map(|block| {
            block.lines().find_map(|line| {
                line.strip_prefix("id = \"")?
                    .strip_suffix('"')
                    .map(str::to_owned)
            })
        })
        .collect()
}

fn required_text<'a>(row: &'a Json, key: &str) -> Result<&'a str, String> {
    row.get(key)
        .and_then(Json::as_text)
        .ok_or_else(|| format!("row lacks string {key}"))
}

fn required_array<'a>(row: &'a Json, key: &str) -> Result<&'a [Json], String> {
    row.get(key)
        .and_then(Json::as_array)
        .ok_or_else(|| format!("row lacks array {key}"))
}

/// Validate the final Rust evidence fields in serialized assertion artifacts.
pub(crate) fn validate_final_traceability(
    assertions: &str,
    benchmarks: &str,
    platform_skips: &str,
) -> Result<(), String> {
    fn rows(contents: &str, label: &str) -> Result<Vec<serde_json::Value>, String> {
        contents
            .lines()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_str(line)
                    .map_err(|error| format!("invalid {label} JSONL row {}: {error}", index + 1))
            })
            .collect()
    }

    let assertion_rows = rows(assertions, "assertion")?;
    if assertion_rows.len() != 283 {
        return Err(format!(
            "semantic assertion count mismatch: expected 283, got {}",
            assertion_rows.len()
        ));
    }
    for row in &assertion_rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        match row["status"].as_str() {
            Some("implemented") => {
                if row["rust_test"].as_str().is_none_or(str::is_empty)
                    || row["rust_evidence"].as_str().is_none_or(str::is_empty)
                {
                    return Err(format!("implemented assertion {id} lacks Rust evidence"));
                }
            }
            Some("final-disposition") => {
                if !row["rust_evidence"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("Final release disposition:"))
                {
                    return Err(format!("assertion {id} lacks a precise final disposition"));
                }
            }
            status => {
                return Err(format!(
                    "assertion {id} has non-final status {}",
                    status.unwrap_or("<missing>")
                ));
            }
        }
    }

    let benchmark_rows = rows(benchmarks, "benchmark assertion link")?;
    if benchmark_rows.len() != 6 {
        return Err(format!(
            "benchmark assertion-link count mismatch: expected 6, got {}",
            benchmark_rows.len()
        ));
    }
    for row in &benchmark_rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        if row["status"].as_str() != Some("implemented")
            || row["rust_test"].as_str().is_none_or(str::is_empty)
            || row["rust_evidence"].as_str().is_none_or(str::is_empty)
        {
            return Err(format!(
                "benchmark assertion link {id} lacks final Rust evidence"
            ));
        }
    }

    let platform_rows = rows(platform_skips, "platform branch")?;
    if platform_rows.len() != 2 {
        return Err(format!(
            "platform branch count mismatch: expected 2, got {}",
            platform_rows.len()
        ));
    }
    for row in &platform_rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        if row["status"].as_str() != Some("implemented")
            || row["rust_evidence"].as_str().is_none_or(str::is_empty)
        {
            return Err(format!("platform branch {id} lacks final Rust evidence"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod final_traceability_tests {
    use super::validate_final_traceability;

    #[test]
    fn pending_and_missing_evidence_fail_closed() {
        let assertion = serde_json::json!({"id":"AS-TEST","status":"implemented","rust_test":"tests::exact_case","rust_evidence":"tests/exact.rs"});
        let benchmark = serde_json::json!({"id":"AS-BM-TEST","status":"implemented","rust_test":"tests::exact_benchmark","rust_evidence":"tests/perf.rs"});
        let platform = serde_json::json!({"id":"SKIP-TEST","status":"implemented","rust_evidence":"tests/platform.rs"});
        let assertions = std::iter::repeat_n(format!("{assertion}\n"), 283).collect::<String>();
        let benchmarks = std::iter::repeat_n(format!("{benchmark}\n"), 6).collect::<String>();
        let platforms = std::iter::repeat_n(format!("{platform}\n"), 2).collect::<String>();
        validate_final_traceability(&assertions, &benchmarks, &platforms).unwrap();
        assert!(
            validate_final_traceability(
                &assertions.replacen("implemented", "pending", 1),
                &benchmarks,
                &platforms
            )
            .is_err()
        );
        assert!(
            validate_final_traceability(
                &assertions,
                &benchmarks.replacen("tests/perf.rs", "", 1),
                &platforms
            )
            .is_err()
        );
        assert!(
            validate_final_traceability(
                &assertions,
                &benchmarks,
                &platforms.replacen("tests/platform.rs", "", 1)
            )
            .is_err()
        );
    }
}
