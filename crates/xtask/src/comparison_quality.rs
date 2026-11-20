//! Labeled quality inputs for the cross-scanner comparison.
//!
//! `cargo xtask compare-quality` runs the Python 3.9 standard-library modules
//! under `comparison_quality/` through [`crate::embedded_python`]. It writes a
//! constructed labeled corpus, checks it against the committed digests, and
//! converts Samsung `CredData` metadata into the shared labels format. Output
//! goes to a cache folder outside the repository; nothing it writes is
//! committed.

use std::path::Path;
use std::process::{Command, Output};

use crate::embedded_python::{Program, source_root_arguments};
use crate::tooling::sha256_bytes;

/// Python modules in load order. The support module and the first four
/// modules decide the constructed corpus bytes.
const PROGRAM: Program = Program {
    modules: &[
        (
            "comparison_quality/common.py",
            include_str!("comparison_quality/common.py"),
        ),
        (
            "comparison_quality/formats.py",
            include_str!("comparison_quality/formats.py"),
        ),
        (
            "comparison_quality/contexts.py",
            include_str!("comparison_quality/contexts.py"),
        ),
        (
            "comparison_quality/generator.py",
            include_str!("comparison_quality/generator.py"),
        ),
        (
            "comparison_quality/creddata.py",
            include_str!("comparison_quality/creddata.py"),
        ),
        (
            "comparison_quality/main.py",
            include_str!("comparison_quality/main.py"),
        ),
    ],
};

/// Number of leading quality modules, after the support module, that decide
/// the constructed corpus bytes.
const GENERATOR_MODULES: usize = 4;

/// Committed digests of the default constructed corpus.
#[cfg(test)]
const EXPECTED_PATH: &str = "benchmarks/comparison/quality/constructed-v1.expected.json";

/// SHA-256 of the support module and the generator sources, concatenated. A
/// change here requires regenerating the committed digests with `generate`
/// and `verify`.
fn generator_sha256() -> String {
    let sources = PROGRAM
        .sources()
        .take(GENERATOR_MODULES + 1)
        .map(|(_, source)| source)
        .collect::<String>();
    sha256_bytes(sources.as_bytes())
}

fn invoke(command: Command, capture: bool) -> Result<Output, String> {
    PROGRAM.run(
        command,
        &[("QUALITY_GENERATOR_SHA256", generator_sha256())],
        capture,
    )
}

fn command(root: &Path, arguments: &[String]) -> Command {
    let mut command = Program::command(&source_root_arguments(root));
    command.args(arguments);
    command
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    if invoke(command(root, arguments), false)?.status.success() {
        Ok(())
    } else {
        Err("compare-quality failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn quality_tools_pass_their_self_test_on_tiny_data() {
        let root = crate::workspace_root().expect("workspace root");
        let mut command = command(&root, &["self-test".to_owned()]);
        if let Some(temporary) = std::env::var_os("TEST_TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        let output = invoke(command, true).expect("python3 must start");
        assert!(
            output.status.success(),
            "compare-quality self-test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"comparison quality self-test passed\n");
    }

    #[test]
    fn committed_corpus_digests_match_the_generator_sources() {
        let root = crate::workspace_root().expect("workspace root");
        let text = std::fs::read_to_string(root.join(EXPECTED_PATH))
            .expect("committed constructed corpus digests must be readable");
        let expected: serde_json::Value =
            serde_json::from_str(&text).expect("committed digests must be JSON");
        assert_eq!(
            expected["generator_sha256"].as_str(),
            Some(generator_sha256().as_str()),
            "the generator changed; run `cargo xtask compare-quality generate` and `verify`, \
             then update {EXPECTED_PATH} and the labeled workload manifest"
        );
    }
}
