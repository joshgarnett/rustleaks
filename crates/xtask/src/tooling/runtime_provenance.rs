//! Independently verified Go runtime provenance for historical corpus replay.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

use super::support::{TempDir, command_status_with_output_limits, sha256_bytes};

pub(super) struct GoRuntime {
    version: String,
}

impl GoRuntime {
    pub(super) fn observe(root: &Path) -> Result<Self, String> {
        let temporary = TempDir::new("go-runtime")?;
        let stdout = temporary.path.join("version.stdout");
        let stderr = temporary.path.join("version.stderr");
        let mut command = Command::new("go");
        command
            .current_dir(root.join("crates/rustleaks-compat/oracle"))
            .args(["env", "GOVERSION"])
            .stdout(Stdio::from(
                File::create(&stdout).map_err(|e| e.to_string())?,
            ))
            .stderr(Stdio::from(
                File::create(&stderr).map_err(|e| e.to_string())?,
            ));
        command_status_with_output_limits(
            &mut command,
            Duration::from_secs(120),
            "selected Go runtime",
            &[(&stdout, "stdout", 1024), (&stderr, "stderr", 16 * 1024)],
        )?;
        let version = fs::read_to_string(&stdout).map_err(|e| e.to_string())?;
        verify_selected(root, version.trim())?;
        Ok(Self {
            version: version.trim().to_owned(),
        })
    }

    /// Projects only the verified runtime token for check-only comparison.
    /// The result must never be saved as a fresh oracle observation.
    pub(super) fn comparison_bytes(
        &self,
        committed: &[u8],
        observed: &[u8],
        check: bool,
        label: &str,
    ) -> Result<Vec<u8>, String> {
        let projected = project_runtime(committed, observed, &self.version, label)?;
        if !check && projected != observed {
            return Err(format!(
                "{label}: generating new corpus provenance with {} requires an explicit baseline migration; use --check to replay the historical corpus",
                self.version
            ));
        }
        println!(
            "{label}: fresh oracle runtime {}, raw outcomes SHA-256 {}; historical runtime is projected only for comparison",
            self.version,
            sha256_bytes(observed)
        );
        Ok(projected)
    }
}

pub(super) fn verify_selected(root: &Path, selected: &str) -> Result<(), String> {
    let pin = fs::read_to_string(root.join(".go-version"))
        .map_err(|error| format!("cannot read pinned Go version: {error}"))?;
    verify_version(pin.trim(), selected)
}

fn verify_version(pin: &str, selected: &str) -> Result<(), String> {
    if !valid_version(&format!("go{pin}")) || selected != format!("go{pin}") {
        return Err(format!(
            "selected Go runtime {selected} differs from pinned go{pin}"
        ));
    }
    Ok(())
}

fn valid_version(version: &str) -> bool {
    version
        .strip_prefix("go1.26.")
        .is_some_and(|patch| !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()))
}

fn project_runtime(
    committed: &[u8],
    observed: &[u8],
    selected: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let baseline = records(committed, label)?;
    let fresh = records(observed, label)?;
    if baseline.len() != fresh.len() {
        return Err(format!("{label}: runtime projection outcome count changed"));
    }
    let mut output = Vec::with_capacity(observed.len());
    for (baseline, fresh) in baseline.iter().zip(fresh) {
        let baseline_value: Value = serde_json::from_slice(baseline).map_err(|e| e.to_string())?;
        let fresh_value: Value = serde_json::from_slice(fresh).map_err(|e| e.to_string())?;
        let id = baseline_value["id"]
            .as_str()
            .ok_or_else(|| format!("{label}: baseline outcome has no ID"))?;
        if fresh_value["id"].as_str() != Some(id) {
            return Err(format!("{label}: runtime projection outcome order changed"));
        }
        let historical = baseline_value["go_version"]
            .as_str()
            .filter(|version| valid_version(version))
            .ok_or_else(|| format!("{label}: {id} has invalid historical Go provenance"))?;
        if fresh_value["go_version"].as_str() != Some(selected) {
            return Err(format!(
                "{label}: {id} differs from verified runtime {selected}"
            ));
        }
        let field = b"\"go_version\":";
        let positions = fresh
            .windows(field.len())
            .enumerate()
            .filter_map(|(index, value)| (value == field).then_some(index))
            .collect::<Vec<_>>();
        if positions.len() != 1 {
            return Err(format!("{label}: {id} has ambiguous Go runtime provenance"));
        }
        let token = format!("\"go_version\":\"{selected}\"");
        let start = positions[0];
        if !fresh[start..].starts_with(token.as_bytes()) {
            return Err(format!(
                "{label}: {id} has noncanonical Go runtime provenance"
            ));
        }
        output.extend_from_slice(&fresh[..start]);
        output.extend_from_slice(format!("\"go_version\":\"{historical}\"").as_bytes());
        output.extend_from_slice(&fresh[start + token.len()..]);
    }
    Ok(output)
}

fn records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err(format!("{label}: outcome records lack a final newline"));
    }
    Ok(bytes.split_inclusive(|byte| *byte == b'\n').collect())
}

#[cfg(test)]
mod tests {
    use super::{GoRuntime, project_runtime, verify_version};

    const BASELINE: &[u8] = b"{\"id\":\"case\",\"go_version\":\"go1.26.7\",\"findings\":[{\"line\":3}],\"error\":null}\n";
    const FRESH: &[u8] = b"{\"id\":\"case\",\"go_version\":\"go1.26.10\",\"findings\":[{\"line\":3}],\"error\":null}\n";

    #[test]
    fn selected_runtime_requires_the_exact_pin() {
        assert!(verify_version("1.26.10", "go1.26.10").is_ok());
        for version in ["go1.26.7", "go1.27.0", "go1.26.10rc1"] {
            assert!(verify_version("1.26.10", version).is_err());
        }
    }

    #[test]
    fn projection_preserves_every_semantic_byte() {
        assert_eq!(
            project_runtime(BASELINE, FRESH, "go1.26.10", "test").unwrap(),
            BASELINE
        );
        for changed in [
            String::from_utf8(FRESH.to_vec())
                .unwrap()
                .replace("\"line\":3", "\"line\":4"),
            String::from_utf8(FRESH.to_vec())
                .unwrap()
                .replace("\"error\":null", "\"error\":{}"),
        ] {
            assert_ne!(
                project_runtime(BASELINE, changed.as_bytes(), "go1.26.10", "test").unwrap(),
                BASELINE
            );
        }
    }

    #[test]
    fn provenance_substitution_rejects_invalid_observations() {
        assert!(project_runtime(BASELINE, FRESH, "go1.26.9", "test").is_err());
        for changed in [
            String::from_utf8(FRESH.to_vec())
                .unwrap()
                .replace("\"case\"", "\"wrong\""),
            String::from_utf8(FRESH.to_vec()).unwrap().replace(
                "\"error\":null",
                "\"go_version\":\"go1.26.7\",\"error\":null",
            ),
        ] {
            assert!(project_runtime(BASELINE, changed.as_bytes(), "go1.26.10", "test").is_err());
        }
    }

    #[test]
    fn generation_cannot_mislabel_fresh_runtime() {
        let runtime = GoRuntime {
            version: "go1.26.10".into(),
        };
        assert!(
            runtime
                .comparison_bytes(BASELINE, FRESH, false, "test")
                .is_err()
        );
        assert_eq!(
            runtime
                .comparison_bytes(BASELINE, FRESH, true, "test")
                .unwrap(),
            BASELINE
        );
    }
}
