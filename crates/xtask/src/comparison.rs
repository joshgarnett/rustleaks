//! Cross-scanner comparison harness.
//!
//! The harness is Python 3.9 standard-library code under `comparison/`. It is
//! embedded here and run with `python3 -I -`, so it needs no installed
//! package and ignores Python environment variables. The program is written
//! to standard input, not passed as an argument, because it is larger than
//! some platforms allow for one command-line argument. It never downloads or
//! builds a scanner. See `docs/dev/comparison.md`.

use std::env;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::tooling::sha256_bytes;

/// Python modules in load order. They share one global namespace.
const MODULES: &[(&str, &str)] = &[
    ("common.py", include_str!("comparison/common.py")),
    ("manifests.py", include_str!("comparison/manifests.py")),
    ("adapters.py", include_str!("comparison/adapters.py")),
    ("measure.py", include_str!("comparison/measure.py")),
    ("stats.py", include_str!("comparison/stats.py")),
    ("score.py", include_str!("comparison/score.py")),
    ("lanes.py", include_str!("comparison/lanes.py")),
    ("run.py", include_str!("comparison/run.py")),
    ("report.py", include_str!("comparison/report.py")),
    ("selftest.py", include_str!("comparison/selftest.py")),
    ("main.py", include_str!("comparison/main.py")),
];

/// Subcommands accepted after `compare`.
pub(crate) const COMPARE_SUBCOMMANDS: &[&str] = &["run", "score", "report", "self-test"];

/// Returns the SHA-256 of the embedded harness, recorded in every run.
fn harness_sha256() -> String {
    let mut joined = Vec::new();
    for (name, text) in MODULES {
        joined.extend_from_slice(name.as_bytes());
        joined.push(0);
        joined.extend_from_slice(text.as_bytes());
        joined.push(0);
    }
    sha256_bytes(&joined)
}

/// Builds the `python3 -I -` program that loads every module with its own
/// file name, so tracebacks name the module and line.
fn bootstrap() -> String {
    let sources = serde_json::to_string(MODULES).expect("module table serializes");
    let encoded = STANDARD.encode(sources);
    format!(
        "import base64, json, sys\n\
         _modules = json.loads(base64.b64decode('{encoded}').decode('utf-8'))\n\
         _namespace = {{'__name__': 'rustleaks_comparison', '__builtins__': __builtins__, \
         'HARNESS_SHA256': '{sha}'}}\n\
         for _name, _text in _modules:\n\
         \x20   exec(compile(_text, 'comparison/' + _name, 'exec'), _namespace)\n\
         sys.exit(_namespace['comparison_main'](sys.argv[1:]))\n",
        sha = harness_sha256()
    )
}

fn python_command(root: &Path) -> Command {
    let mut command = Command::new("python3");
    command
        .args(["-I", "-"])
        .env("RUSTLEAKS_COMPARISON_SOURCE_ROOT", root)
        .stdin(Stdio::piped());
    // Under `bazelisk run`, relative paths are relative to where the user ran
    // the command, not to the runfiles tree.
    if let Some(directory) =
        env::var_os("BUILD_WORKING_DIRECTORY").filter(|value| !value.is_empty())
    {
        command.current_dir(directory);
    }
    command
}

/// Runs the harness with `arguments`, writing the program to its standard
/// input. Python reads the whole program before it starts, so closing the
/// pipe after the write cannot block. Output is captured only when asked.
fn run_python(root: &Path, arguments: &[String], capture: bool) -> Result<Output, String> {
    let mut command = python_command(root);
    command.args(arguments);
    if capture {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start python3 (3.9 or newer): {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("python3 standard input is not available")?;
    let written = stdin.write_all(bootstrap().as_bytes());
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for python3: {error}"))?;
    written.map_err(|error| format!("cannot write the harness to python3: {error}"))?;
    Ok(output)
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
    fn bootstrap_embeds_every_module_once() {
        let names = MODULES.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
        assert!(bootstrap().contains(&harness_sha256()));
        let arguments = python_command(Path::new("."))
            .get_args()
            .map(std::ffi::OsStr::len)
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            [2, 1],
            "the program is not a command-line argument"
        );
    }
}
