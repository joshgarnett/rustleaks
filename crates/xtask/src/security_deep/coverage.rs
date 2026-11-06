//! Optional matching-tool source coverage over an explicitly bounded corpus.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use super::{Step, command, require_success};
use crate::fuzzing::{
    private, process,
    profiles::{Deadline, Profile},
};
use crate::tooling::{sha256_bytes, sha256_file};

const MAX_COVERAGE_INPUTS: usize = 128;
const MAX_PRIVATE_BYTES: u64 = 512 * 1024 * 1024;

// Keep the ordered capability checks, bounded run and evidence publication together.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn collect(
    root: &Path,
    directory: &Path,
    campaign: &Path,
    target: &str,
    identity: &Value,
    profile: Profile,
    deadline: Deadline,
    required: bool,
) -> Result<Step, String> {
    let host = identity["host"].as_str().ok_or("missing coverage host")?;
    require_success(command(
        root,
        directory,
        "compiler-location",
        "rustup",
        &[
            "which".into(),
            "--toolchain".into(),
            crate::FUZZ_TOOLCHAIN.into(),
            "rustc".into(),
        ],
        deadline,
        30,
        &[],
    )?)?;
    let compiler = fs::read_to_string(directory.join("compiler-location/stdout.log"))
        .map_err(|error| error.to_string())?;
    let sysroot = Path::new(compiler.trim())
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid compiler location")?;
    let llvm = sysroot.join("lib/rustlib").join(host).join("bin");
    let profdata = llvm.join("llvm-profdata");
    let cov = llvm.join("llvm-cov");
    if !profdata.is_file() || !cov.is_file() {
        return Ok(if required {
            Step::fail(
                "matching-llvm-tools-unavailable",
                json!({"installed_automatically":false}),
            )
        } else {
            Step::skipped("matching-llvm-tools-unavailable")
        });
    }
    let compiler_llvm = identity["rustc"]
        .as_str()
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| line.strip_prefix("LLVM version: "))
        })
        .ok_or("compiler omits LLVM version")?;
    for (name, tool) in [("profdata-version", &profdata), ("coverage-version", &cov)] {
        require_success(command(
            root,
            directory,
            name,
            tool.to_str().ok_or("non-UTF-8 LLVM path")?,
            &["--version".into()],
            deadline,
            30,
            &[],
        )?)?;
        let version = fs::read_to_string(directory.join(name).join("stdout.log"))
            .map_err(|error| error.to_string())?;
        if !version.contains(&format!("LLVM version {compiler_llvm}"))
            && !version.contains(&format!("LLVM version: {compiler_llvm}"))
        {
            return Ok(Step::fail("llvm-compiler-version-mismatch", Value::Null));
        }
    }
    let workspace = workspace(target)?;
    let source = directory.join("source");
    private::directory(&source)?;
    copy_sources(root, directory, &source, identity, deadline)?;
    let original = campaign.join(target).join("final-corpus");
    let maximum = profile.maximum_input(target)?;
    let corpus = directory.join("corpus");
    private::directory(&corpus)?;
    let mut entries = fs::read_dir(&original)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    let original_count = entries.len();
    let record = private::read_json(&campaign.join(target).join("manifest.json"))?;
    for entry in entries.iter().take(MAX_COVERAGE_INPUTS) {
        private::regular_file(entry, maximum)?;
        let bytes = fs::read(entry).map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("invalid corpus filename")?;
        if record["final_corpus"]["files"][name]["sha256"] != sha256_bytes(&bytes) {
            return Err("coverage corpus changed after campaign".into());
        }
        private::write(&corpus.join(name), &bytes)?;
    }
    let fuzz = source.join("crates").join(workspace).join("fuzz");
    let binary_root = root.join("target/private-fuzz-coverage-build");
    let artifacts = directory.join("artifacts");
    private::directory(&artifacts)?;
    let arguments = vec![
        format!("+{}", crate::FUZZ_TOOLCHAIN),
        "fuzz".into(),
        "coverage".into(),
        "--fuzz-dir".into(),
        fuzz.to_string_lossy().into_owned(),
        "--no-trace-compares".into(),
        "--sanitizer".into(),
        "none".into(),
        "--target".into(),
        host.into(),
        "--target-dir".into(),
        binary_root.to_string_lossy().into_owned(),
        "--llvm-path".into(),
        llvm.to_string_lossy().into_owned(),
        "--jobs".into(),
        "1".into(),
        target.into(),
        corpus.to_string_lossy().into_owned(),
        "--".into(),
        "-timeout=5".into(),
        "-rss_limit_mb=2048".into(),
        format!("-max_len={maximum}"),
        format!("-artifact_prefix={}/", artifacts.display()),
    ];
    let logs = directory.join("coverage-run");
    private::directory(&logs)?;
    let timeout = deadline.remaining(Duration::from_mins(10))?;
    private::json(
        &logs.join("command.json"),
        &json!({"program":"cargo","arguments":arguments,"timeout_ms":timeout.as_millis(),"harness_profile":profile.name(),"outcome":"preparing"}),
    )?;
    let mut child = process::command(&source, "cargo", &arguments);
    child.env("RUSTLEAKS_FUZZ_PROFILE", profile.name());
    let outcome = process::run_monitored(&mut child, &logs, timeout, process::LOG_LIMIT, || {
        check_tree_size(directory)
    })?;
    private::json(
        &logs.join("command.json"),
        &json!({"program":"cargo","arguments":arguments,"timeout_ms":timeout.as_millis(),"harness_profile":profile.name(),"outcome":outcome.name()}),
    )?;
    if outcome != process::Outcome::Success {
        return Ok(Step::fail(
            "source-coverage-failed",
            json!({"outcome":outcome.name()}),
        ));
    }
    let data = fuzz.join("coverage").join(target).join("coverage.profdata");
    private::regular_file(&data, MAX_PRIVATE_BYTES)?;
    let binary = binary_root.join(host).join("release").join(target);
    let arguments = vec![
        "export".into(),
        "-summary-only".into(),
        binary.to_string_lossy().into_owned(),
        format!("-instr-profile={}", data.display()),
    ];
    require_success(command(
        root,
        directory,
        "summary",
        cov.to_str().ok_or("non-UTF-8 LLVM tool")?,
        &arguments,
        deadline,
        120,
        &[],
    )?)?;
    let summary = private::read_json(&directory.join("summary/stdout.log"))?;
    let records = summary["data"]
        .as_array()
        .ok_or("LLVM coverage omitted data")?;
    let totals = records
        .iter()
        .map(|record| record["totals"].clone())
        .collect::<Vec<_>>();
    if totals.is_empty() || totals.iter().any(Value::is_null) {
        return Err("LLVM coverage omitted totals".into());
    }
    Ok(Step::pass(
        json!({"scope":"source coverage of deterministic hash-sorted corpus subset; sanitizer none; separate from ASan campaign feedback","corpus_inputs":original_count.min(MAX_COVERAGE_INPUTS),"corpus_inputs_omitted":original_count.saturating_sub(MAX_COVERAGE_INPUTS),"totals":totals,"profdata_sha256":sha256_file(&data)?,"summary_sha256":sha256_file(&directory.join("summary/stdout.log"))?,"binary_sha256":sha256_file(&binary)?,"llvm_cov_sha256":sha256_file(&cov)?,"llvm_profdata_sha256":sha256_file(&profdata)?,"private_output_limit_bytes":MAX_PRIVATE_BYTES,"detailed_file_scope":"per-file and codec source records retained in private LLVM summary; no codec reach inferred from normal tests"}),
    ))
}

fn workspace(target: &str) -> Result<&'static str, String> {
    match target {
        "go_regex" | "config" | "fragment_scan" | "session" => Ok("rustleaks-core"),
        "archive" | "reader_schedule" | "git_patch" => Ok("rustleaks-sources"),
        "template" => Ok("rustleaks-report"),
        _ => Err("unknown coverage target".into()),
    }
}

fn check_tree_size(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_owned()];
    let mut bytes = 0_u64;
    let mut files = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                files += 1;
                bytes = bytes.saturating_add(metadata.len());
            }
            if bytes > MAX_PRIVATE_BYTES || files > 16384 {
                return Err("private coverage output limit exceeded".into());
            }
        }
    }
    Ok(())
}

fn copy_sources(
    root: &Path,
    directory: &Path,
    destination: &Path,
    identity: &Value,
    deadline: Deadline,
) -> Result<(), String> {
    require_success(command(
        root,
        directory,
        "source-list",
        "git",
        &[
            "ls-files".into(),
            "--cached".into(),
            "--others".into(),
            "--exclude-standard".into(),
            "-z".into(),
        ],
        deadline,
        30,
        &[],
    )?)?;
    let paths = fs::read_to_string(directory.join("source-list/stdout.log"))
        .map_err(|error| error.to_string())?;
    let mut inventory = BTreeMap::new();
    let mut bytes = 0_u64;
    for name in paths.split('\0').filter(|name| !name.is_empty()) {
        if deadline.expired() {
            return Err("whole-run deadline exhausted during source snapshot".into());
        }
        let path = Path::new(name);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err("invalid source snapshot path".into());
        }
        let source = root.join(path);
        let target = destination.join(path);
        let metadata = fs::symlink_metadata(&source).map_err(|error| error.to_string())?;
        bytes = bytes.saturating_add(metadata.len());
        if inventory.len() >= 4096 || bytes > 128 * 1024 * 1024 || metadata.len() > 32 * 1024 * 1024
        {
            return Err("coverage source snapshot exceeds bounds".into());
        }
        private_parents(
            destination,
            target.parent().ok_or("source path has no parent")?,
        )?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            metadata.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0;
        let hash = if metadata.file_type().is_symlink() {
            let link = fs::read_link(&source).map_err(|error| error.to_string())?;
            if link.is_absolute()
                || !source
                    .canonicalize()
                    .map_err(|error| error.to_string())?
                    .starts_with(root)
            {
                return Err("source symlink leaves coverage snapshot".into());
            }
            copy_symlink(&link, &target)?;
            sha256_bytes(link.as_os_str().as_encoded_bytes())
        } else if metadata.is_file() {
            let content = fs::read(&source).map_err(|error| error.to_string())?;
            private::write(&target, &content)?;
            sha256_bytes(&content)
        } else {
            return Err("non-file in source snapshot".into());
        };
        inventory.insert(
            name,
            json!({"sha256":hash,"mode":mode,"symlink":metadata.file_type().is_symlink()}),
        );
    }
    let hash = sha256_bytes(&serde_json::to_vec(&inventory).map_err(|error| error.to_string())?);
    if identity["source_tree_sha256"] != hash {
        return Err("source changed while preparing coverage snapshot".into());
    }
    Ok(())
}
fn private_parents(root: &Path, parent: &Path) -> Result<(), String> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| "coverage parent leaves private root")?;
    let mut path = PathBuf::from(root);
    for component in relative.components() {
        path.push(component);
        if !path.exists() {
            private::directory(&path)?;
        }
    }
    Ok(())
}

fn copy_symlink(link: &Path, target: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(link, target).map_err(|error| error.to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = (link, target);
        Err("source symlinks unsupported on this host".into())
    }
}
