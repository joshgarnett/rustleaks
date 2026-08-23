//! Construction of pinned private Go observation binaries through overlays.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::json;

use super::runner::Runner;

const MASK_SOURCE: &str = include_str!("mask_oracle_test.go.txt");
const FILTER_SOURCE: &str = include_str!("filter_oracle_test.go.txt");

pub(super) struct Binaries {
    pub(super) composite: PathBuf,
    pub(super) mask: PathBuf,
    pub(super) filter: PathBuf,
}

pub(super) fn build(
    root: &Path,
    upstream: &Path,
    workspace: &Path,
    runner: &Runner,
) -> Result<Binaries, String> {
    let upstream = fs::canonicalize(upstream)
        .map_err(|error| format!("cannot canonicalize pinned upstream checkout: {error}"))?;
    let composite = workspace.join(executable("composite oracle ü"));
    let oracle = root.join("crates/rustleaks-compat/oracle");
    let mut build = Command::new("go");
    runner.go_env(&mut build);
    build
        .current_dir(&oracle)
        .args(["build", "-trimpath", "-o"])
        .arg(&composite)
        .arg(".");
    runner.capture(
        &mut build,
        "composite-go-build",
        Duration::from_secs(180),
        8 * 1024 * 1024,
    )?;

    let mask_source = workspace.join("mask oracle ü_test.go");
    fs::write(&mask_source, MASK_SOURCE)
        .map_err(|error| format!("cannot write {}: {error}", mask_source.display()))?;
    let mask_overlay = workspace.join("mask overlay ü.json");
    write_overlay(
        &mask_overlay,
        &[(upstream.join("report/m7_mask_oracle_test.go"), mask_source)],
    )?;
    let mask = workspace.join(executable("mask oracle ü.test"));
    compile_test(&upstream, runner, &mask_overlay, &mask, "./report", "mask")?;

    let filter_source = workspace.join("filter oracle ü_test.go");
    fs::write(&filter_source, FILTER_SOURCE)
        .map_err(|error| format!("cannot write {}: {error}", filter_source.display()))?;
    let report_source = workspace.join("finding export ü.go");
    let mut finding = fs::read(upstream.join("report/finding.go"))
        .map_err(|error| format!("cannot read pinned finding.go: {error}"))?;
    finding.extend_from_slice(
        b"\nfunc M7RequiredFindings(f Finding) []*RequiredFinding { return f.requiredFindings }\n",
    );
    fs::write(&report_source, finding)
        .map_err(|error| format!("cannot write {}: {error}", report_source.display()))?;
    let filter_overlay = workspace.join("filter overlay ü.json");
    write_overlay(
        &filter_overlay,
        &[
            (
                upstream.join("detect/m7_filter_oracle_test.go"),
                filter_source,
            ),
            (upstream.join("report/finding.go"), report_source),
        ],
    )?;
    let filter = workspace.join(executable("filter oracle ü.test"));
    compile_test(
        &upstream,
        runner,
        &filter_overlay,
        &filter,
        "./detect",
        "filter",
    )?;
    Ok(Binaries {
        composite,
        mask,
        filter,
    })
}

fn compile_test(
    upstream: &Path,
    runner: &Runner,
    overlay: &Path,
    output: &Path,
    package: &str,
    label: &str,
) -> Result<(), String> {
    let mut command = Command::new("go");
    runner.go_env(&mut command);
    command
        .current_dir(upstream)
        .args(["test", "-c", "-overlay"])
        .arg(overlay)
        .arg("-o")
        .arg(output)
        .arg(package);
    runner
        .capture(
            &mut command,
            &format!("{label}-oracle-build"),
            Duration::from_secs(180),
            16 * 1024 * 1024,
        )
        .map(|_| ())
}

fn write_overlay(path: &Path, replacements: &[(PathBuf, PathBuf)]) -> Result<(), String> {
    let replace = replacements
        .iter()
        .map(|(target, source)| {
            (
                target.to_string_lossy().into_owned(),
                serde_json::Value::String(source.to_string_lossy().into_owned()),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let bytes = serde_json::to_vec(&json!({ "Replace": replace }))
        .map_err(|error| format!("cannot serialize Go overlay: {error}"))?;
    fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn executable(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!("{name}.exe"))
    } else {
        PathBuf::from(name)
    }
}
