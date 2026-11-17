//! Labeled quality inputs for the cross-scanner comparison.
//!
//! `cargo xtask compare-quality` runs an embedded Python 3.9 standard-library
//! program with `python3 -I -`, passing the program on standard input. It writes a constructed labeled corpus, checks
//! it against the committed digests, and converts Samsung `CredData` metadata
//! into the shared labels format. Output goes to a cache folder outside the
//! repository; nothing it writes is committed.

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::tooling::sha256_bytes;

/// Sources that decide the constructed corpus bytes, in concatenation order.
const GENERATOR_SOURCES: [&str; 4] = [
    include_str!("comparison_quality/common.py"),
    include_str!("comparison_quality/formats.py"),
    include_str!("comparison_quality/contexts.py"),
    include_str!("comparison_quality/generator.py"),
];
const CREDDATA_SOURCE: &str = include_str!("comparison_quality/creddata.py");
const MAIN_SOURCE: &str = include_str!("comparison_quality/main.py");

/// Committed digests of the default constructed corpus.
#[cfg(test)]
const EXPECTED_PATH: &str = "benchmarks/comparison/quality/constructed-v1.expected.json";

/// SHA-256 of the generator sources. A change here requires regenerating the
/// committed digests with `generate` and `verify`.
fn generator_sha256() -> String {
    sha256_bytes(GENERATOR_SOURCES.concat().as_bytes())
}

fn payload() -> String {
    let mut script = format!("QUALITY_GENERATOR_SHA256 = '{}'\n", generator_sha256());
    for source in GENERATOR_SOURCES
        .iter()
        .chain([CREDDATA_SOURCE, MAIN_SOURCE].iter())
    {
        script.push_str(source);
        script.push('\n');
    }
    script
}

/// Builds the interpreter command. The program arrives on standard input
/// (`python3 -I -`), because it is larger than a command-line argument may be
/// on Windows.
fn python_command(root: &Path) -> Command {
    let mut command = Command::new("python3");
    command
        .args(["-I", "-", "--source-root"])
        .arg(root)
        .stdin(Stdio::piped());
    command
}

/// Starts the command and writes the program to its standard input.
fn spawn_with_payload(command: &mut Command) -> Result<Child, String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start python3 (Python 3.9 or later): {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "python3 standard input is not available".to_owned())?;
    let written = stdin.write_all(payload().as_bytes());
    drop(stdin);
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "cannot send the compare-quality program to python3: {error}"
        ));
    }
    Ok(child)
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    let mut command = python_command(root);
    command.args(arguments);
    let status = spawn_with_payload(&mut command)?
        .wait()
        .map_err(|error| format!("cannot wait for python3: {error}"))?;
    if status.success() {
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
        let mut command = python_command(&root);
        command.arg("self-test");
        if let Some(temporary) = std::env::var_os("TEST_TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let output = spawn_with_payload(&mut command)
            .expect("python3 must start")
            .wait_with_output()
            .expect("python3 must finish");
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
