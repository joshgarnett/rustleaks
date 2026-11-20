//! Cross-scanner comparison harness.
//!
//! The harness is Python 3.9 standard-library code under `comparison/`, run
//! by [`crate::embedded_python`]. It never downloads or builds a scanner. See
//! `docs/dev/comparison.md`.

use std::path::Path;
use std::process::Output;

use crate::embedded_python::Program;

/// Python modules in load order. They share one global namespace.
const PROGRAM: Program = Program {
    modules: &[
        ("comparison/common.py", include_str!("comparison/common.py")),
        (
            "comparison/manifests.py",
            include_str!("comparison/manifests.py"),
        ),
        (
            "comparison/adapters.py",
            include_str!("comparison/adapters.py"),
        ),
        (
            "comparison/measure.py",
            include_str!("comparison/measure.py"),
        ),
        ("comparison/stats.py", include_str!("comparison/stats.py")),
        ("comparison/score.py", include_str!("comparison/score.py")),
        ("comparison/lanes.py", include_str!("comparison/lanes.py")),
        ("comparison/run.py", include_str!("comparison/run.py")),
        ("comparison/report.py", include_str!("comparison/report.py")),
        (
            "comparison/selftest.py",
            include_str!("comparison/selftest.py"),
        ),
        ("comparison/main.py", include_str!("comparison/main.py")),
    ],
};

/// Subcommands accepted after `compare`.
pub(crate) const COMPARE_SUBCOMMANDS: &[&str] = &["run", "score", "report", "self-test"];

/// Runs the harness with `arguments`. The harness records its own SHA-256 in
/// every run, and reads the source root from the environment.
fn run_python(root: &Path, arguments: &[String], capture: bool) -> Result<Output, String> {
    let mut command = Program::command(arguments);
    command.env("RUSTLEAKS_COMPARISON_SOURCE_ROOT", root);
    PROGRAM.run(command, &[("HARNESS_SHA256", PROGRAM.sha256())], capture)
}

/// Runs `cargo xtask compare ARGS`.
pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    if !cfg!(unix) {
        return Err("the comparison harness needs Unix wait4 and process groups".into());
    }
    match arguments.first() {
        Some(command) if COMPARE_SUBCOMMANDS.contains(&command.as_str()) => {}
        _ => {
            return Err(format!(
                "usage: cargo xtask compare <{}> [OPTIONS]",
                COMPARE_SUBCOMMANDS.join("|")
            ));
        }
    }
    if run_python(root, arguments, false)?.status.success() {
        Ok(())
    } else {
        Err(format!("compare {} failed", arguments[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn comparison_self_test_passes_on_synthetic_tools() {
        let output =
            run_python(Path::new("."), &["self-test".to_owned()], true).expect("python3 runs");
        assert!(
            output.status.success(),
            "comparison self-test failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"comparison self-test passed\n");
    }

    #[test]
    fn example_tools_manifest_names_every_family() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/comparison/tools.example.json");
        let path = if path.exists() {
            path
        } else {
            Path::new("benchmarks/comparison/tools.example.json").to_path_buf()
        };
        let text = std::fs::read_to_string(&path).expect("example tools manifest is readable");
        let manifest: serde_json::Value = serde_json::from_str(&text).expect("example is JSON");
        assert_eq!(manifest["schema"], "rustleaks-comparison-tools-v1");
        let tools = manifest["tools"].as_array().expect("tools list");
        for family in ["rustleaks", "gitleaks", "betterleaks", "kingfisher"] {
            assert!(
                tools.iter().any(|tool| tool["family"] == family),
                "example names a {family} tool"
            );
        }
        for tool in tools {
            for key in ["id", "family", "version", "binary", "sha256", "build"] {
                assert!(tool[key].is_string(), "{key} is a string in {tool}");
            }
            let hash = tool["sha256"].as_str().expect("hash");
            assert!(
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{hash} is a SHA-256"
            );
        }
    }

    #[test]
    fn harness_lists_every_module_once() {
        let names = PROGRAM
            .modules
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }
}
