//! Workload sets for the cross-tool comparison: pinned public repositories,
//! generated synthetic workloads and the home-fixtures matrix.
//!
//! The work is done by Python 3.9 standard-library modules embedded below and
//! run with `python3 -I`. All data goes to a cache folder outside the
//! repository. See `docs/dev/comparison-workloads.md`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Python modules in load order. Later modules use names from earlier ones.
const MODULES: &[(&str, &str)] = &[
    ("common", include_str!("comparison_workloads/common.txt")),
    ("legacy", include_str!("comparison_workloads/legacy.txt")),
    ("repos", include_str!("comparison_workloads/repos.txt")),
    (
        "synthetic",
        include_str!("comparison_workloads/synthetic.txt"),
    ),
    ("matrix", include_str!("comparison_workloads/matrix.txt")),
    ("main", include_str!("comparison_workloads/main.txt")),
];

/// Joins the modules into one program.
fn program() -> String {
    MODULES
        .iter()
        .map(|(name, source)| format!("# module: {name}\n{source}"))
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Runs the program with the source root and the given arguments. The program
/// text goes to standard input so its size is not limited by the command line.
fn invoke(root: &Path, arguments: &[String], capture: bool) -> Result<Output, String> {
    let mut command = Command::new("python3");
    command
        .args(["-I", "-", "--source-root"])
        .arg(root)
        .args(arguments)
        .stdin(Stdio::piped());
    if capture {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start python3 for compare-workloads: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "cannot open the python3 standard input".to_owned())?;
    stdin.write_all(program().as_bytes()).map_err(|error| {
        format!("cannot send the compare-workloads program to python3: {error}")
    })?;
    drop(stdin);
    child
        .wait_with_output()
        .map_err(|error| format!("compare-workloads did not finish: {error}"))
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
    fn program_lists_every_module_once() {
        let text = program();
        for (name, _) in MODULES {
            assert_eq!(text.matches(&format!("# module: {name}\n")).count(), 1);
        }
        assert!(text.contains("if __name__ == '__main__':"));
    }
}
