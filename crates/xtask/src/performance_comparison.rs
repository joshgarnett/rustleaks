//! Optional external CLI comparison. This does not build or download scanners.

use std::path::Path;
use std::process::Command;

use crate::tooling::sha256_bytes;

const FIXTURES: &str = include_str!("performance_comparison_fixtures.txt");
const COLLECTOR: &str = include_str!("performance_comparison.txt");

fn payload() -> String {
    format!(
        "COMPARISON_COLLECTOR_SHA256 = '{}'\nCOMPARISON_FIXTURE_SHA256 = '{}'\n{FIXTURES}\n{COLLECTOR}",
        sha256_bytes(COLLECTOR.as_bytes()),
        sha256_bytes(FIXTURES.as_bytes())
    )
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    if !cfg!(unix) {
        return Err("external CLI comparison requires Unix wait4 and private permissions; no results were collected".into());
    }
    let status = Command::new("python3")
        .args(["-I", "-c", &payload()])
        .arg("--source-root")
        .arg(root)
        .args(arguments)
        .status()
        .map_err(|error| format!("cannot start Python 3.9+ comparison collector: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("external CLI comparison failed; private evidence records any partial results".into())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn comparison_collector_enforces_complete_results_and_process_boundaries() {
        let output = Command::new("python3")
            .args(["-I", "-c", &payload(), "--self-test"])
            .output()
            .expect("Python collector regression controls must start");
        assert!(
            output.status.success(),
            "comparison collector regression controls failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout,
            b"comparison collector regression controls passed\n"
        );
    }
}
