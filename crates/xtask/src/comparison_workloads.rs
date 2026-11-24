//! Workload sets for the cross-tool comparison: pinned public repositories,
//! generated synthetic workloads and the home-fixtures matrix.
//!
//! The work is done by the Python 3.9 standard-library modules under
//! `comparison_workloads/`, run by [`crate::embedded_python`]. All data goes to
//! a cache folder outside the repository. See `docs/dev/comparison-workloads.md`.

use std::path::Path;
use std::process::Output;

use crate::embedded_python::{Program, source_root_arguments};

/// Python modules in load order. Later modules use names from earlier ones.
const PROGRAM: Program = Program {
    modules: &[
        (
            "comparison_workloads/common.py",
            include_str!("comparison_workloads/common.py"),
        ),
        (
            "comparison_workloads/tuned_synthetic.py",
            include_str!("comparison_workloads/tuned_synthetic.py"),
        ),
        (
            "comparison_workloads/repos.py",
            include_str!("comparison_workloads/repos.py"),
        ),
        (
            "comparison_workloads/synthetic.py",
            include_str!("comparison_workloads/synthetic.py"),
        ),
        (
            "comparison_workloads/matrix.py",
            include_str!("comparison_workloads/matrix.py"),
        ),
        (
            "comparison_workloads/main.py",
            include_str!("comparison_workloads/main.py"),
        ),
    ],
};

/// Subcommands of `compare-workloads`. The documentation command check reads this
/// list, and a unit test keeps it in step with the argument parser in
/// `main.py`.
pub(crate) const SUBCOMMANDS: &[&str] = &["fetch", "generate", "matrix", "verify", "self-test"];

/// Runs the program with the source root and the given arguments.
fn invoke(root: &Path, arguments: &[String], capture: bool) -> Result<Output, String> {
    let mut command = Program::command(&source_root_arguments(root));
    command.args(arguments);
    PROGRAM.run(command, &[], capture)
}

/// Entry point for `cargo xtask compare-workloads <fetch|generate|matrix|verify>`.
pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    let output = invoke(root, arguments, false)?;
    if output.status.success() {
        Ok(())
    } else {
        Err("compare-workloads failed".into())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn listed_subcommands_match_the_argument_parser() {
        let main = PROGRAM
            .modules
            .iter()
            .find(|(name, _)| name.ends_with("/main.py"))
            .map(|(_, source)| *source)
            .unwrap();
        let pattern = "add_parser('";
        let parsed = main
            .match_indices(pattern)
            .filter_map(|(index, _)| main[index + pattern.len()..].split_once('\''))
            .map(|(name, _)| name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(parsed, SUBCOMMANDS.iter().copied().collect());
    }

    #[test]
    fn workload_tools_pass_their_offline_self_test() {
        let root = crate::workspace_root().expect("workspace root");
        let output = invoke(&root, &["self-test".to_owned()], true).expect("python3 must start");
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Shows in the test log whether the Git checks ran.
        println!("{}", stdout.lines().last().unwrap_or_default());
        assert!(
            output.status.success(),
            "compare-workloads self-test failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout
                .lines()
                .last()
                .is_some_and(|line| line.starts_with("compare-workloads self-test passed: ")),
            "unexpected self-test output: {stdout}"
        );
    }

    #[test]
    fn manifest_names_the_generator_files() {
        let root = crate::workspace_root().expect("workspace root");
        let text =
            std::fs::read_to_string(root.join("benchmarks/comparison/workloads/synthetic.json"))
                .expect("synthetic workload manifest is readable");
        let manifest: serde_json::Value = serde_json::from_str(&text).expect("manifest is JSON");
        let generators = manifest["generators"].as_object().expect("generators");
        assert!(!generators.is_empty());
        for path in generators.values() {
            let path = path.as_str().expect("generator path");
            assert!(
                PROGRAM
                    .modules
                    .iter()
                    .any(|(name, _)| format!("crates/xtask/src/{name}") == path),
                "{path} is not an embedded module"
            );
        }
    }
}
