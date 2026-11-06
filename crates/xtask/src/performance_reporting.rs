//! Optional local performance collection and an allowlisted public summary.
//!
//! Imported evidence is checked for consistency, never authenticated as an
//! independent execution. Raw build identities and diagnostics stay private.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use super::{
    M1_MAX_PERF_BUDGETS, MEASUREMENT_SCOPE, Prepared, Request as LegacyRequest, prepare,
    sha256_bytes, validate_records, workspace_root,
};
use crate::fuzzing::private;

#[path = "performance_reporting/import.rs"]
mod import;
#[cfg(test)]
#[path = "performance_reporting/tests.rs"]
mod tests;

const INPUT_LIMIT: u64 = 16 * 1024 * 1024;
const DEADLINE_SECONDS: u64 = 900;
const KIND: &str = "periodic-performance-v1";
const REPRESENTATIVE_SCOPE: &str = "representative-v1-operation-only";
const SAMPLE_SCOPE: &str = "investigation-v1-steady-scan-only";
const WINDOW_SCOPE: &str = "investigation-v2-summed-scan-windows";
const PROFILE_SCOPE: &str = "profile-v1-instrumented-steady-loop";

struct Request {
    output: PathBuf,
    input: Option<PathBuf>,
    legacy_budget: bool,
    worker: bool,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut output = None;
        let mut input = None;
        let mut legacy_budget = false;
        let mut worker = false;
        let mut seen = BTreeSet::new();
        let mut args = arguments.iter();
        while let Some(flag) = args.next() {
            if !seen.insert(flag) {
                return Err("duplicate performance report option".into());
            }
            match flag.as_str() {
                "--output" => {
                    output = Some(PathBuf::from(
                        args.next().ok_or("--output requires a path")?,
                    ));
                }
                "--input" => {
                    input = Some(PathBuf::from(args.next().ok_or("--input requires a path")?));
                }
                "--legacy-budget" => legacy_budget = true,
                "--collect-worker" => worker = true,
                _ => return Err("unknown performance report option".into()),
            }
        }
        if input.is_some() && (legacy_budget || worker) {
            return Err("import cannot request native collection".into());
        }
        let output = output.ok_or("performance report requires --output")?;
        if !output.is_absolute() || input.as_ref().is_some_and(|path| !path.is_absolute()) {
            return Err("performance report paths must be absolute".into());
        }
        Ok(Self {
            output,
            input,
            legacy_budget,
            worker,
        })
    }
}

pub(crate) fn run(arguments: &[String]) -> Result<(), String> {
    if let [flag, path] = arguments
        && flag == "--verify-summary"
    {
        let bytes = read_private(Path::new(path), INPUT_LIMIT)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid sanitized summary JSON")?;
        validate_public_summary(&value)?;
        println!("sanitized performance summary satisfies the fixed publication allowlist");
        return Ok(());
    }
    let request = Request::parse(arguments)?;
    let root = fs::canonicalize(workspace_root()?).map_err(|_| "cannot locate source checkout")?;
    if request.output.starts_with(&root) {
        return Err("private performance output must be outside the source checkout".into());
    }
    if request.worker {
        private::checked_path(&request.output).map_err(|_| "invalid private worker directory")?;
        owner_only(&request.output, true)?;
        return collect(&request.output, request.legacy_budget);
    }
    let parent = request.output.parent().ok_or("missing output parent")?;
    private::checked_path(parent)
        .map_err(|_| "output parent must exist without symlinks or traversal")?;
    private::directory(&request.output)
        .map_err(|_| "cannot create new private report directory")?;
    let result = (|| {
        if let Some(input) = request.input {
            let bytes = read_private(&input, INPUT_LIMIT)?;
            private::write(&request.output.join("input.json"), &bytes)?;
            let value = import::parse(&bytes)?;
            let summary = import::summarize(&value, input.parent(), "report-consistency-only")?;
            Ok((summary, bytes))
        } else {
            collect_supervised(&request.output, request.legacy_budget)?;
            let bytes = read_private(&request.output.join("collection.json"), INPUT_LIMIT)?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid private collection JSON")?;
            let summary = import::summarize(&value, None, "local-collector")?;
            Ok((summary, bytes))
        }
    })();
    finish(&request.output, result)
}

fn finish(output: &Path, result: Result<(Value, Vec<u8>), String>) -> Result<(), String> {
    let Ok((mut summary, bytes)) = result else {
        private::json(
            &output.join("failure.json"),
            &json!({"schema_version":1,
            "status":"invalid-or-incomplete-evidence","public_artifact_eligible":false}),
        )?;
        return Err("performance report failed; retained evidence is private".into());
    };
    summary["input_sha256"] = json!(sha256_bytes(&bytes));
    validate_public_summary(&summary)?;
    private::json(&output.join("summary.json"), &summary)?;
    println!(
        "performance report: {}; private evidence retained; summary.json is the only publication candidate",
        summary["status"].as_str().unwrap_or("invalid")
    );
    if matches!(
        summary["status"].as_str(),
        Some("invariant-failure" | "qualified-regression" | "execution-failure")
    ) {
        return Err("performance report recorded a failure; inspect private evidence".into());
    }
    Ok(())
}

fn collect_supervised(output: &Path, legacy_budget: bool) -> Result<(), String> {
    use crate::fuzzing::process::{Outcome, run_with_files};
    let stdout = private::file(&output.join("collector-stdout.txt"))?;
    let stderr = private::file(&output.join("collector-stderr.txt"))?;
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| "cannot locate report collector")?);
    command
        .args(["perf", "report", "--collect-worker", "--output"])
        .arg(output);
    if legacy_budget {
        command.arg("--legacy-budget");
    }
    let monitor = || {
        let mut count = 0;
        for entry in fs::read_dir(output).map_err(|_| "cannot inspect collector files")? {
            let entry = entry.map_err(|_| "cannot inspect collector entry")?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|_| "cannot inspect collector output")?;
            count += 1;
            if !metadata.is_file() || metadata.len() > INPUT_LIMIT || count > 12 {
                return Err("collector exceeded its private file bound".into());
            }
        }
        Ok(())
    };
    let outcome = run_with_files(
        &mut command,
        stdout,
        stderr,
        Duration::from_secs(DEADLINE_SECONDS),
        INPUT_LIMIT,
        monitor,
    )?;
    private::json(
        &output.join("completion.json"),
        &json!({"schema_version":1,
        "outcome":outcome.name(),"cleanup_complete":outcome != Outcome::CleanupFailure}),
    )?;
    if outcome != Outcome::Success {
        return Err("performance collection failed or exceeded its bound".into());
    }
    monitor()
}

fn runner_failure(stderr: &str) -> &'static str {
    if stderr
        .lines()
        .any(|line| line == "rustleaks-perf-status: invariant-failure-v1")
    {
        "invariant-failure"
    } else {
        "execution-failure"
    }
}

fn collect(output: &Path, legacy_budget: bool) -> Result<(), String> {
    // The supervising parent bounds preparation and the entire process tree.
    let prepared = prepare(&workspace_root()?)?;
    let request = LegacyRequest::parse(&[])?;
    let mut record = json!({"schema_version":1,"kind":KIND,"complete":false,
        "source":prepared.source,"build":prepared.build,"host":prepared.host,
        "executable_bytes":prepared.executable_bytes,"executable_fnv1a64":prepared.executable_fnv1a64,
        "measurement_scope":MEASUREMENT_SCOPE,"budget_requested":legacy_budget,
        "calibrated_host":false,"host_qualification":null,"rows":[],"budget_samples":[],"outcome":"execution-failure"});
    let runner_stdout = output.join("runner.jsonl");
    let runner_stderr = output.join("runner-stderr.txt");
    let child = Command::new(&prepared.binary)
        .current_dir(&prepared.root)
        .args(request.arguments("all"))
        .stdout(private::file(&runner_stdout)?)
        .stderr(private::file(&runner_stderr)?)
        .status();
    let result = match child {
        Ok(status) => {
            let stdout = read_private(&runner_stdout, INPUT_LIMIT)?;
            let stderr = read_private(&runner_stderr, INPUT_LIMIT)?;
            if status.success() {
                record["outcome"] = json!("invariant-failure");
                String::from_utf8(stdout)
                    .map_err(|_| "invalid runner encoding".to_owned())
                    .and_then(|raw| prepared.bind(&raw))
                    .and_then(|rows| {
                        validate_records(&rows, &prepared, &request)?;
                        record["rows"] = json!(
                            rows.lines()
                                .map(serde_json::from_str::<Value>)
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(|_| "invalid collected rows")?
                        );
                        Ok(())
                    })
            } else {
                record["outcome"] = json!(runner_failure(&String::from_utf8_lossy(&stderr)));
                Err("performance runner failed".into())
            }
        }
        Err(_) => Err("cannot start performance runner".into()),
    };
    if result.is_ok() {
        record["outcome"] = json!("complete");
        if legacy_budget {
            let hardware = super::legacy_host_hardware()?;
            let calibrated = super::matches_legacy_host(&hardware);
            record["host_qualification"] = hardware;
            record["calibrated_host"] = json!(calibrated);
            if calibrated {
                match collect_budgets(&prepared, output) {
                    Ok(budgets) => record["budget_samples"] = budgets,
                    Err(error) => {
                        private::write(&output.join("budget-failure.txt"), error.as_bytes())?;
                        record["outcome"] = json!(runner_failure(&error));
                    }
                }
            }
        }
    }
    prepared.ensure_unchanged()?;
    record["complete"] = json!(true);
    private::json(&output.join("collection.json"), &record)
}

#[cfg(target_os = "macos")]
fn collect_budgets(prepared: &Prepared, output: &Path) -> Result<Value, String> {
    use std::io::Write as _;
    let mut journal = private::file(&output.join("budget-samples.jsonl"))?;
    let request = LegacyRequest::parse(&[])?;
    let mut budgets = Vec::new();
    for budget in M1_MAX_PERF_BUDGETS {
        let warmup_raw = super::run_perf_sample(prepared, budget.workload)?;
        writeln!(
            journal,
            "{}",
            json!({"kind":"warmup","workload":budget.workload,"raw":warmup_raw})
        )
        .map_err(|_| "cannot retain budget warmup")?;
        let warmup: Value =
            serde_json::from_str(&warmup_raw).map_err(|_| "invalid budget warmup")?;
        super::validate_record(&warmup, prepared, &request)?;
        let mut samples = Vec::new();
        for index in 0..7 {
            let (raw, rss) = if index < 3 {
                let (raw, rss) = super::run_perf_sample_with_rss(prepared, budget.workload)?;
                (raw, Some(rss))
            } else {
                (super::run_perf_sample(prepared, budget.workload)?, None)
            };
            writeln!(journal, "{}", json!({"kind":"sample","workload":budget.workload,"index":index,"peak_rss_bytes":rss,"raw":raw})).map_err(|_| "cannot retain budget sample")?;
            let row: Value = serde_json::from_str(&raw).map_err(|_| "invalid budget sample")?;
            super::validate_record(&row, prepared, &request)?;
            samples.push(json!({"index":index,"row":row,"peak_rss_bytes":rss}));
        }
        budgets.push(json!({"workload":budget.workload,"warmup":warmup,"samples":samples}));
    }
    Ok(json!(budgets))
}

#[cfg(not(target_os = "macos"))]
fn collect_budgets(_prepared: &Prepared, _output: &Path) -> Result<Value, String> {
    Err("legacy budget collection is unavailable on this host".into())
}

fn owner_only(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "missing private evidence")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("performance evidence must have owner-only permissions".into());
        }
    }
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err("unexpected private evidence file type".into());
    }
    Ok(())
}

fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    private::regular_file(path, limit)
        .map_err(|_| "missing, linked or oversized performance evidence")?;
    owner_only(path, false)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "cannot open performance evidence")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read performance evidence")?;
    if bytes.len() as u64 > limit {
        return Err("performance evidence exceeds byte bound".into());
    }
    Ok(bytes)
}

fn inspect_observation(kind: &str, path: &Path) -> Result<Value, String> {
    use crate::fuzzing::process::{Outcome, run_with_files};
    let bundle = private::Bundle::new(None)?;
    let stdout_path = bundle.path.join("stdout.json");
    let stderr_path = bundle.path.join("stderr.txt");
    let result = (|| {
        let mut command = Command::new("python3");
        command
            .args([
                "-c",
                include_str!("performance_investigation.txt"),
                "--inspect-observation",
                kind,
            ])
            .arg(path);
        command.env_clear();
        for name in ["PATH", "TMPDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if run_with_files(
            &mut command,
            private::file(&stdout_path)?,
            private::file(&stderr_path)?,
            Duration::from_secs(15),
            64 * 1024,
            || Ok(()),
        )? != Outcome::Success
        {
            return Err("native observation parser failed or exceeded a bound".into());
        }
        serde_json::from_slice::<Value>(&read_private(&stdout_path, 64 * 1024)?)
            .map_err(|_| "invalid native observation parser result".into())
    })();
    match result {
        Ok(value) => {
            bundle.finish_named(Ok(()), "native observation validation")?;
            Ok(value)
        }
        Err(error) => Err(bundle
            .finish_named(Err(error), "native observation validation")
            .err()
            .unwrap_or_else(|| "native observation validation failed".into())),
    }
}

fn digest(value: &Value, length: usize) -> Result<&str, String> {
    value
        .as_str()
        .filter(|text| {
            text.len() == length
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| "invalid performance identity digest".into())
}

fn exact_keys(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("expected report object")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("unknown or missing report field".into());
    }
    Ok(())
}

fn validate_public_summary(value: &Value) -> Result<(), String> {
    exact_keys(
        value,
        &[
            "schema_version",
            "kind",
            "status",
            "verification",
            "release_gate",
            "retention_days",
            "input_sha256",
            "identity",
            "measurements",
            "profile_artifacts",
            "companion_sha256",
        ],
    )?;
    if value["schema_version"] != 1
        || value["kind"] != "sanitized-performance-summary-v1"
        || value["release_gate"] != false
        || value["retention_days"] != 7
    {
        return Err("invalid public summary contract".into());
    }
    if !matches!(
        value["status"].as_str(),
        Some(
            "invariant-failure"
                | "execution-failure"
                | "qualified-regression"
                | "legacy-budget-passed"
                | "skipped-legacy-host-budget"
                | "informational-timing"
                | "unavailable-profile-tool"
                | "complete-profile"
        )
    ) || !matches!(
        value["verification"].as_str(),
        Some("local-collector" | "report-consistency-only")
    ) {
        return Err("unknown public summary disposition".into());
    }
    digest(&value["input_sha256"], 64)?;
    if !value["companion_sha256"].is_null() {
        digest(&value["companion_sha256"], 64)?;
    }
    import::validate_identity_summary(&value["identity"])?;
    for measurement in value["measurements"]
        .as_array()
        .ok_or("missing public measurements")?
    {
        exact_keys(
            measurement,
            &[
                "workload",
                "phase",
                "sample_count",
                "median_elapsed_ns",
                "peak_rss_bytes",
            ],
        )?;
        if !import::public_workload(measurement["workload"].as_str().unwrap_or_default())
            || !import::public_phase(
                measurement["workload"].as_str().unwrap_or_default(),
                measurement["phase"].as_str().unwrap_or_default(),
            )
            || measurement["sample_count"].as_u64().is_none()
            || measurement["median_elapsed_ns"].as_u64().is_none()
            || (!measurement["peak_rss_bytes"].is_null()
                && measurement["peak_rss_bytes"].as_u64().is_none())
        {
            return Err("invalid public measurement".into());
        }
    }
    for artifact in value["profile_artifacts"]
        .as_array()
        .ok_or("missing public artifact references")?
    {
        exact_keys(artifact, &["role", "sha256"])?;
        if !import::PROFILE_ARTIFACTS.contains(&artifact["role"].as_str().unwrap_or_default()) {
            return Err("unknown public profile artifact role".into());
        }
        digest(&artifact["sha256"], 64)?;
    }
    Ok(())
}
