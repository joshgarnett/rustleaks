//! Opt-in native profiling and an informational, held-out calibration protocol.

use std::fs;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{
    Prepared, codegen_option, command_output, compiler_arguments, prepare, prepare_with_flags,
    sha256_bytes, sha256_file, string_arguments, workspace_root,
};

#[path = "performance_investigation/window_matrix.rs"]
mod window_matrix;

const CONTROLLER: &str = include_str!("performance_investigation.txt");
const PROFILE_SCOPE: &str = "profile-v1-instrumented-steady-loop";
const PROFILE_FLAGS: &[&str] = &[
    "--@rules_rust//rust/settings:extra_rustc_flag=-Cdebuginfo=line-tables-only",
    "--@rules_rust//rust/settings:extra_rustc_flag=-Cforce-frame-pointers=yes",
];
const DEFAULT_WORKLOAD: &str = "core-default-many-keywords-16-kib";
const WORKLOADS: &[&str] = &[
    "core-default-many-keywords-16-kib",
    "core-default-one-keyword-16-kib",
    "core-default-no-hit-16-kib",
    "core-mixed-16-kib",
    "core-dense-16-kib",
    "core-decode-depth-5",
];
const CALIBRATION_DEADLINE: u64 = 900;
const SAMPLE_SCOPE: &str = "investigation-v1-steady-scan-only";
const WINDOW_SCOPE: &str = "investigation-v2-summed-scan-windows";
const WINDOW_POLICY: &str = "empirical-paired-window-band-v2";

struct Request {
    output: PathBuf,
    workload: String,
    seconds: u64,
    pairs: usize,
    iterations: u64,
    window_blocks: Option<u64>,
    first_side: String,
}

impl Request {
    fn parse(arguments: &[String], mode: &str) -> Result<Self, String> {
        let mut output = None;
        let mut request = Self {
            output: PathBuf::new(),
            workload: DEFAULT_WORKLOAD.into(),
            seconds: 15,
            pairs: 9,
            iterations: 5,
            window_blocks: None,
            first_side: "a".into(),
        };
        if !arguments.len().is_multiple_of(2) {
            return Err("investigation options need values".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for pair in arguments.chunks_exact(2) {
            if !seen.insert(&pair[0]) {
                return Err("duplicate investigation option".into());
            }
            match pair[0].as_str() {
                "--output" => output = Some(PathBuf::from(&pair[1])),
                "--workload" if WORKLOADS.contains(&pair[1].as_str()) => {
                    request.workload.clone_from(&pair[1]);
                }
                "--seconds" if mode == "profile" => request.seconds = bounded(&pair[1], 3, 30)?,
                "--pairs" if mode == "calibrate" => {
                    request.pairs = usize::try_from(bounded(&pair[1], 5, 31)?)
                        .map_err(|error| error.to_string())?;
                }
                "--iterations" if mode == "calibrate" => {
                    request.iterations = bounded(&pair[1], 1, 100)?;
                }
                "--window-blocks" if mode == "calibrate" => {
                    request.window_blocks = Some(bounded(&pair[1], 1, 16)?);
                }
                "--first-side" if mode == "calibrate" && matches!(pair[1].as_str(), "a" | "b") => {
                    request.first_side.clone_from(&pair[1]);
                }
                _ => return Err("unknown or unsupported investigation option/workload".into()),
            }
        }
        if request.window_blocks.is_none()
            && seen.iter().any(|option| option.as_str() == "--first-side")
        {
            return Err("--first-side requires --window-blocks".into());
        }
        request.output =
            output.ok_or("profile/calibrate requires --output NEW_PRIVATE_DIRECTORY")?;
        Ok(request)
    }
}

fn bounded(value: &str, low: u64, high: u64) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| (low..=high).contains(value))
        .ok_or_else(|| format!("investigation bound must be in {low}..={high}"))
}

fn directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err("private output must be an absolute path without traversal".into());
        }
        let parent = path.parent().ok_or("missing output parent")?;
        if fs::canonicalize(parent).map_err(|error| error.to_string())? != parent {
            return Err("private output parent must exist without symlink components".into());
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path).map_err(|error| error.to_string())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("private investigation output currently requires Unix permissions".into())
    }
}

fn write(path: &Path, value: &Value) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    file.write_all(&bytes).map_err(|error| error.to_string())
}

fn evidence(prepared: &Prepared, mode: &str) -> Value {
    json!({"schema_version":1,"kind":mode,"source":prepared.source,"build":prepared.build,
        "host":prepared.host,"baseline_eligible":prepared.source["dirty"]==false,
        "controller_sha256":sha256_bytes(CONTROLLER.as_bytes()),"release_gate":false,
        "thermal_and_background_load":"not controlled by runner; operator must record quiet-host conditions",
        "wall_deadline_seconds":if mode=="profile"{180}else{CALIBRATION_DEADLINE}})
}

fn collect(
    prepared: &Prepared,
    mode: &str,
    workload: &str,
    output: &Path,
    limit: u64,
    settings: &[u64],
    deadline: Option<Instant>,
) -> Result<Value, String> {
    let mut command = Command::new("python3");
    command
        .current_dir(&prepared.root)
        .args(["-c", CONTROLLER, mode])
        .arg(&prepared.binary)
        .arg(workload)
        .arg(output)
        .arg(limit.to_string())
        .args(settings.iter().map(u64::to_string));
    command.env_clear();
    for name in ["PATH", "TMPDIR", "TEMP", "TMP", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let raw = if let Some(deadline) = deadline {
        collect_supervised(&mut command, output, deadline)?
    } else {
        command_output(&mut command)?
    };
    let mut result: Value = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    if deadline.is_some() {
        let provenance = &result["ready"]["provenance"];
        if provenance["upstream_revision"] != super::REVISION
            || provenance["default_config_sha256"] != super::CONFIG_SHA256
            || provenance["package_version"] != super::RELEASE_VERSION
            || provenance["target_os"] != prepared.host["os"]
            || provenance["target_arch"] != prepared.host["arch"]
        {
            return Err("window worker provenance differs from the prepared build".into());
        }
    }
    let bound = prepared.bind(&result["ready"].to_string())?;
    result["ready"] = serde_json::from_str(&bound).map_err(|error| error.to_string())?;
    validate_identity(&result["ready"]["identity"], workload)?;
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err("window collector returned after its absolute deadline".into());
    }
    Ok(result)
}

fn calibrate_matrix(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 4 {
        return Err(
            "observation matrix accepts only --matrix observation-window-v2 and --output".into(),
        );
    }
    let mut output = None;
    let mut matrix = false;
    for pair in arguments.chunks_exact(2) {
        match pair[0].as_str() {
            "--output" if output.is_none() => output = Some(PathBuf::from(&pair[1])),
            "--matrix" if !matrix && pair[1] == "observation-window-v2" => matrix = true,
            _ => return Err("unknown, duplicate or incompatible observation matrix option".into()),
        }
    }
    let output = output
        .filter(|_| matrix)
        .ok_or("observation matrix requires output and protocol")?;
    let root = fs::canonicalize(workspace_root()?).map_err(|error| error.to_string())?;
    if output.starts_with(&root) {
        return Err("private calibration output must be outside source checkout".into());
    }
    directory(&output)?;
    write(
        &output.join("request.json"),
        &json!({"operation":"calibrate", "matrix":"observation-window-v2"}),
    )?;
    let result = prepare(&root).and_then(|prepared| window_matrix::run(&prepared, &output));
    finish(&output, result)
}

const COLLECTOR_FILE_LIMIT_ERROR: &str = "observation collector output exceeded its file bound";

fn bounded_collector_files(output: &Path) -> Result<(), String> {
    for entry in fs::read_dir(output).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let metadata = entry
            .path()
            .symlink_metadata()
            .map_err(|error| error.to_string())?;
        let bound = if entry.file_name().to_string_lossy().ends_with("stderr.txt") {
            65_536
        } else {
            16 * 1024 * 1024
        };
        if !metadata.is_file() || metadata.len() > bound {
            return Err(COLLECTOR_FILE_LIMIT_ERROR.into());
        }
    }
    Ok(())
}

fn collect_supervised(
    command: &mut Command,
    output: &Path,
    deadline: Instant,
) -> Result<String, String> {
    use crate::fuzzing::process::{Outcome, run_with_files};
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        write(
            &output.join("parent-completion.json"),
            &json!({"outcome":"deadline-before-spawn",
            "deadline_met":false,"cleanup_complete":true,
            "scope":"collector and inherited worker process group"}),
        )?;
        return Err("observation collector absolute deadline expired before spawn".into());
    }
    let stdout_path = output.join("parent-stdout.json");
    let stdout = crate::fuzzing::private::file(&stdout_path)?;
    let stderr = crate::fuzzing::private::file(&output.join("parent-stderr.txt"))?;
    let mut monitor_failure = None;
    let outcome = run_with_files(command, stdout, stderr, remaining, 4 * 1024 * 1024, || {
        if Instant::now() >= deadline {
            monitor_failure.get_or_insert("absolute-deadline");
            return Err("observation collector absolute deadline expired".into());
        }
        bounded_collector_files(output).inspect_err(|error| {
            monitor_failure.get_or_insert(if error == COLLECTOR_FILE_LIMIT_ERROR {
                "evidence-limit"
            } else {
                "evidence-inspection"
            });
        })
    });
    let deadline_met = Instant::now() < deadline;
    let cleanup_complete = outcome
        .as_ref()
        .is_ok_and(|outcome| *outcome != Outcome::CleanupFailure);
    write(
        &output.join("parent-completion.json"),
        &json!({
        "outcome":outcome.as_ref().map_or("supervisor-error", |outcome| outcome.name()),
        "monitor_failure":monitor_failure,
        "deadline_met":deadline_met,"cleanup_complete":cleanup_complete,
        "scope":"collector and inherited worker process group"}),
    )?;
    if outcome? != Outcome::Success || !deadline_met {
        return Err(
            "observation collector failed, exceeded a bound or returned after its deadline".into(),
        );
    }
    bounded_collector_files(output)?;
    String::from_utf8(fs::read(stdout_path).map_err(|error| error.to_string())?)
        .map_err(|error| format!("invalid collector output: {error}"))
}

pub(super) fn validate_identity(identity: &Value, workload: &str) -> Result<(), String> {
    if identity["workload"] != workload || identity["complete"] != true || identity["errors"] != 0 {
        return Err("investigation workload incomplete or mismatched".into());
    }
    for field in [
        "input_bytes",
        "rules",
        "keywords",
        "findings",
        "decoded_bytes",
        "work_units",
        "finding_records",
    ] {
        if identity[field].as_u64().is_none() {
            return Err(format!("investigation omits {field}"));
        }
    }
    for field in ["input_fnv1a64", "config_fnv1a64", "outcome_fnv1a64"] {
        if !identity[field].as_str().is_some_and(|value| {
            value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err(format!("investigation omits valid {field}"));
        }
    }
    Ok(())
}

pub(super) fn validate_profile_build(graph: &Value) -> Result<(), String> {
    let mut found = false;
    for action in graph["actions"]
        .as_array()
        .ok_or("profile graph omits actions")?
    {
        if action["mnemonic"] != "Rustc" {
            continue;
        }
        let arguments = string_arguments(action)?;
        let (_, arguments) = compiler_arguments(&arguments)?;
        if !arguments.contains(&"--crate-name=rustleaks_perf") {
            continue;
        }
        let arguments = arguments
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        if codegen_option(&arguments, "debuginfo") != Some("line-tables-only")
            || codegen_option(&arguments, "force-frame-pointers") != Some("yes")
        {
            return Err("profile build lacks requested line tables or frame pointers".into());
        }
        found = true;
    }
    if found {
        Ok(())
    } else {
        Err("profile build omitted runner compile action".into())
    }
}

pub(crate) fn profile(arguments: &[String]) -> Result<(), String> {
    let request = Request::parse(arguments, "profile")?;
    let root = workspace_root()?;
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if request.output.starts_with(&root) {
        return Err("private profile output must be outside source checkout".into());
    }
    directory(&request.output)?;
    write(
        &request.output.join("request.json"),
        &json!({"operation":"profile","workload":request.workload,"seconds":request.seconds}),
    )?;
    let result = profile_inner(&root, &request);
    finish(&request.output, result)
}

fn profile_inner(root: &Path, request: &Request) -> Result<Value, String> {
    let prepared = prepare_with_flags(root, PROFILE_FLAGS, PROFILE_SCOPE)?;
    let mut report = evidence(&prepared, "profile");
    let result = collect(
        &prepared,
        "profile",
        &request.workload,
        &request.output,
        180,
        &[request.seconds, 0],
        None,
    )?;
    if let Some(profile) = result.get("profile") {
        if profile["kind"] != "profile-complete"
            || profile["identity"] != result["ready"]["identity"]
            || profile["actual_scan_count"]
                .as_u64()
                .is_none_or(|count| count == 0)
        {
            return Err("profile omitted complete matching work".into());
        }
    } else if result["status"] != "unsupported-host" {
        return Err("profile omitted outcome".into());
    }
    report["result"] = result;
    report["measurement_scope"] = json!(PROFILE_SCOPE);
    report["profile_flags"] = json!(PROFILE_FLAGS);
    report["files"] = artifact_hashes(&request.output)?;
    prepared.ensure_unchanged()?;
    Ok(report)
}

fn artifact_hashes(path: &Path) -> Result<Value, String> {
    let mut hashes = serde_json::Map::new();
    for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            hashes.insert(
                entry.file_name().to_string_lossy().into_owned(),
                json!(sha256_file(&entry.path())?),
            );
        }
    }
    Ok(Value::Object(hashes))
}

fn finish(output: &Path, result: Result<Value, String>) -> Result<(), String> {
    match result {
        Ok(value) => {
            write(&output.join("report.json"), &value)?;
            let disposition = value["result"]["status"]
                .as_str()
                .or_else(|| value["calibration"]["status"].as_str())
                .unwrap_or("complete");
            println!("performance investigation: {disposition}; private report retained");
            Ok(())
        }
        Err(error) => {
            write(
                &output.join("failure.json"),
                &json!({"classification":"investigation-failed","detail":error}),
            )?;
            Err("performance investigation failed; inspect the retained private output".into())
        }
    }
}

pub(crate) fn calibrate(arguments: &[String]) -> Result<(), String> {
    if arguments.iter().any(|argument| argument == "--matrix") {
        return calibrate_matrix(arguments);
    }
    let request = Request::parse(arguments, "calibrate")?;
    let root = fs::canonicalize(workspace_root()?).map_err(|error| error.to_string())?;
    if request.output.starts_with(&root) {
        return Err("private calibration output must be outside source checkout".into());
    }
    directory(&request.output)?;
    let mut details = json!({"operation":"calibrate","workload":request.workload,
        "pairs":request.pairs,"iterations":request.iterations});
    if let Some(blocks) = request.window_blocks {
        details["window_blocks"] = json!(blocks);
        details["first_side"] = json!(request.first_side);
        details["measurement_scope"] = json!(WINDOW_SCOPE);
        details["policy"] = json!(WINDOW_POLICY);
    }
    write(&request.output.join("request.json"), &details)?;
    let result = calibrate_inner(&root, &request);
    finish(&request.output, result)
}

fn calibrate_inner(root: &Path, request: &Request) -> Result<Value, String> {
    let prepared = prepare(root)?;
    let deadline = Instant::now() + Duration::from_secs(CALIBRATION_DEADLINE);
    run_prepared_window(&prepared, request, deadline)
}

fn run_prepared_window(
    prepared: &Prepared,
    request: &Request,
    deadline: Instant,
) -> Result<Value, String> {
    let result = run_prepared_window_inner(prepared, request, deadline);
    if let Err(error) = &result
        && request.window_blocks.is_some()
    {
        write(
            &request.output.join("cell-failure.json"),
            &json!({
            "classification":"incomplete-observation-window-cell", "detail":error}),
        )?;
    }
    result
}

#[allow(clippy::too_many_lines)] // One prepared build serves the ordered calibration stages.
fn run_prepared_window_inner(
    prepared: &Prepared,
    request: &Request,
    deadline: Instant,
) -> Result<Value, String> {
    let mut report = evidence(prepared, "calibration");
    let started = Instant::now();
    let mut rows = Vec::new();
    let mut partial_rows = request
        .window_blocks
        .map(|_| crate::fuzzing::private::file(&request.output.join("rows.jsonl")))
        .transpose()?;
    let mut reference = None;
    for stage in ["training-aa", "validation-aa", "control-ab"] {
        for pair in 0..request.pairs {
            let order = if (pair % 2 == 0) == (request.first_side == "a") {
                ["a", "b"]
            } else {
                ["b", "a"]
            };
            let mut times = [0_u64; 2];
            for side in order {
                let limit = CALIBRATION_DEADLINE
                    .checked_sub(started.elapsed().as_secs())
                    .filter(|limit| *limit > 0)
                    .ok_or("calibration whole-run deadline exceeded")?;
                let extra = u64::from(stage == "control-ab" && side == "b");
                let output = request.output.join(format!("{stage}-{pair:02}-{side}"));
                directory(&output)?;
                let mut settings = vec![request.iterations, extra];
                let mode = if let Some(blocks) = request.window_blocks {
                    settings.push(blocks);
                    "sample-window"
                } else {
                    "sample"
                };
                let result = collect(
                    prepared,
                    mode,
                    &request.workload,
                    &output,
                    limit.min(120),
                    &settings,
                    request
                        .window_blocks
                        .map(|_| deadline.min(Instant::now() + Duration::from_mins(2))),
                )?;
                let identity = &result["ready"]["identity"];
                if reference
                    .as_ref()
                    .is_some_and(|expected| expected != identity)
                {
                    return Err("calibration workload identity changed".into());
                }
                reference = Some(identity.clone());
                let mut row = if let Some(blocks) = request.window_blocks {
                    validate_window(&result, blocks, request.iterations, extra, identity)?
                } else {
                    let sample = &result["sample"];
                    validate_sample(sample, request.iterations, extra, identity)?;
                    json!({"elapsed_ns": sample["elapsed_ns"], "iterations":request.iterations,
                        "extra_passes":extra,"actual_scan_count":request.iterations*(extra+1),
                        "identity":identity})
                };
                times[usize::from(side == "b")] = row["elapsed_ns"]
                    .as_u64()
                    .ok_or("missing calibration elapsed time")?;
                write(&output.join("sample.json"), &result)?;
                row["stage"] = json!(stage);
                row["pair"] = json!(pair);
                row["side"] = json!(side);
                row["order"] = json!(order);
                if let Some(file) = &mut partial_rows {
                    use std::io::Write as _;
                    writeln!(file, "{row}").map_err(|error| error.to_string())?;
                    file.flush().map_err(|error| error.to_string())?;
                }
                rows.push(row);
            }
            if times.contains(&0) {
                return Err("calibration pair incomplete".into());
            }
        }
    }
    let calibration = if request.window_blocks.is_some() {
        classify_windows(&rows, request.pairs, &request.first_side)?
    } else {
        classify(&rows, request.pairs)?
    };
    report["policy"] = json!({"id":"empirical-paired-band-v1",
        "training":"alternating unchanged A/A pairs; band = twice maximum absolute paired ratio deviation plus two clock nanoseconds divided by minimum A elapsed",
        "validation":"every independent held-out unchanged A/A pair must fit the frozen training band",
        "control":"every A/extra-pass pair must exceed the band; candidate performs two complete scans per logical iteration",
        "limits":"empirical observed band, not a statistical confidence bound or universal tolerated regression; no automatic release gate",
        "repeat":"repeat independent full runs before treating this host/workload policy as stable",
        "paired_order":"AB,BA alternating within each stage; stages run training then held-out then control"});
    report["measurement_scope"] = json!(SAMPLE_SCOPE);
    if let Some(blocks) = request.window_blocks {
        report["schema_version"] = json!(2);
        report["measurement_scope"] = json!(WINDOW_SCOPE);
        report["window_blocks"] = json!(blocks);
        report["iterations_per_block"] = json!(request.iterations);
        report["first_side"] = json!(request.first_side);
        report["policy"] = json!({"id":WINDOW_POLICY,
            "training":"twice the maximum exact absolute training (B-A)/A ratio",
            "validation":"every held-out absolute ratio is at most the frozen band",
            "control":"every deliberate extra-work ratio strictly exceeds the band",
            "degeneracy":"a zero training maximum cannot qualify a window",
            "timer_precision_bound_ns":null,"integer_aggregation_rounding_ns":0,
            "timing":"sum of independently timed scans; validation and destruction between scans are untimed",
            "limits":"finite empirical observation, not a confidence bound or release gate",
            "paired_order":"alternate from first_side within each ordered stage"});
    }
    report["workload"] = json!(request.workload);
    report["pairs_per_stage"] = json!(request.pairs);
    report["identity"] = reference.unwrap_or(Value::Null);
    report["rows"] = json!(rows);
    report["calibration"] = calibration;
    report["completed_seconds"] = json!(started.elapsed().as_secs_f64());
    prepared.ensure_unchanged()?;
    if request.window_blocks.is_some() && Instant::now() >= deadline {
        return Err("observation-window cell exceeded its absolute deadline".into());
    }
    Ok(report)
}

pub(super) fn validate_sample(
    sample: &Value,
    iterations: u64,
    extra: u64,
    identity: &Value,
) -> Result<u64, String> {
    if sample["kind"] != "sample"
        || sample["scope"] != SAMPLE_SCOPE
        || sample["identity"] != *identity
        || sample["iterations"].as_u64() != Some(iterations)
        || sample["extra_passes"].as_u64() != Some(extra)
        || sample["actual_scan_count"].as_u64() != iterations.checked_mul(extra + 1)
    {
        return Err("calibration changed outcome, scope or measured work".into());
    }
    sample["elapsed_ns"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "missing positive calibration elapsed time".into())
}

fn window_metadata(
    value: &Value,
    kind: &str,
    blocks: u64,
    iterations: u64,
    extra: u64,
    identity: &Value,
) -> Result<(), String> {
    if value["schema_version"].as_u64() != Some(2)
        || value["kind"] != kind
        || value["scope"] != WINDOW_SCOPE
        || value["window_blocks"].as_u64() != Some(blocks)
        || value["iterations_per_block"].as_u64() != Some(iterations)
        || value["extra_passes"].as_u64() != Some(extra)
        || value["identity"] != *identity
    {
        return Err("window metadata changed".into());
    }
    Ok(())
}

fn window_totals(
    components: &Value,
    blocks: u64,
    iterations: u64,
    extra: u64,
    identity: &Value,
) -> Result<(u64, u64, u64), String> {
    if !(1..=16).contains(&blocks) || !(1..=100).contains(&iterations) || extra > 1 {
        return Err("invalid observation window bounds".into());
    }
    let components = components.as_array().ok_or("missing window components")?;
    if u64::try_from(components.len()).map_err(|error| error.to_string())? != blocks {
        return Err("incomplete observation window".into());
    }
    let mut elapsed = 0_u64;
    let mut scans = 0_u64;
    let mut logical_iterations = 0_u64;
    for (index, component) in components.iter().enumerate() {
        window_metadata(
            component,
            "window-component",
            blocks,
            iterations,
            extra,
            identity,
        )?;
        if component["block_index"].as_u64()
            != Some(u64::try_from(index).map_err(|error| error.to_string())?)
        {
            return Err("window components are missing, duplicated or reordered".into());
        }
        let sample = &component["sample"];
        let measured = validate_sample(sample, iterations, extra, identity)?;
        if sample["ns_per_logical_iteration"].as_u64() != Some(measured / iterations) {
            return Err("window component omitted exact iteration quotient".into());
        }
        elapsed = elapsed
            .checked_add(measured)
            .ok_or("window elapsed overflow")?;
        logical_iterations = logical_iterations
            .checked_add(iterations)
            .ok_or("window iteration overflow")?;
        scans = scans
            .checked_add(
                iterations
                    .checked_mul(extra + 1)
                    .ok_or("window scan count overflow")?,
            )
            .ok_or("window scan count overflow")?;
    }
    Ok((elapsed, logical_iterations, scans))
}

fn validate_window(
    result: &Value,
    blocks: u64,
    iterations: u64,
    extra: u64,
    identity: &Value,
) -> Result<Value, String> {
    let ready = &result["ready"];
    if ready["schema_version"].as_u64() != Some(1)
        || ready["kind"] != "ready"
        || ready["scope"] != SAMPLE_SCOPE
        || ready["identity"] != *identity
        || ready["provenance"]["binding"] != "bazel-action-graph"
        || result["finished"] != json!({"kind":"finished"})
        || result["exit_code"].as_i64() != Some(0)
        || result["stdout_eof"] != true
    {
        return Err("window preparation, binding or process completion incomplete".into());
    }
    let workload = identity["workload"]
        .as_str()
        .ok_or("missing window workload")?;
    validate_identity(identity, workload)?;
    let (elapsed, total_iterations, scans) =
        window_totals(&result["components"], blocks, iterations, extra, identity)?;
    let complete = &result["complete"];
    window_metadata(
        complete,
        "window-complete",
        blocks,
        iterations,
        extra,
        identity,
    )?;
    if complete["elapsed_ns"].as_u64() != Some(elapsed)
        || complete["total_iterations"].as_u64() != Some(total_iterations)
        || complete["actual_scan_count"].as_u64() != Some(scans)
    {
        return Err("window completion totals differ from raw components".into());
    }
    Ok(
        json!({"schema_version":2,"scope":WINDOW_SCOPE,"window_blocks":blocks,
        "iterations_per_block":iterations,"extra_passes":extra,"total_iterations":total_iterations,
        "elapsed_ns":elapsed,"actual_scan_count":scans,"identity":identity,
        "components":result["components"]}),
    )
}

fn exact_product(left: u128, right: u128) -> Result<u128, String> {
    left.checked_mul(right)
        .ok_or_else(|| "exact calibration ratio overflow".into())
}

fn exact_ratio(numerator: u128, denominator: u64) -> Value {
    json!({"numerator":numerator.to_string(),"denominator":denominator.to_string()})
}

#[allow(clippy::too_many_lines)] // Validate the ordered matrix before any exact classification.
pub(super) fn classify_windows(
    rows: &[Value],
    pairs: usize,
    first_side: &str,
) -> Result<Value, String> {
    if !(5..=31).contains(&pairs) || rows.len() != pairs * 6 || !matches!(first_side, "a" | "b") {
        return Err("incomplete observation-window calibration matrix".into());
    }
    let blocks = rows[0]["window_blocks"]
        .as_u64()
        .ok_or("missing window size")?;
    let iterations = rows[0]["iterations_per_block"]
        .as_u64()
        .ok_or("missing window iterations")?;
    let identity = &rows[0]["identity"];
    validate_identity(
        identity,
        identity["workload"]
            .as_str()
            .ok_or("missing window workload")?,
    )?;
    let mut stages = [Vec::new(), Vec::new(), Vec::new()];
    for (stage_index, stage) in ["training-aa", "validation-aa", "control-ab"]
        .iter()
        .enumerate()
    {
        for pair in 0..pairs {
            let order = if (pair % 2 == 0) == (first_side == "a") {
                ["a", "b"]
            } else {
                ["b", "a"]
            };
            let mut times = [0_u64; 2];
            for (position, side) in order.iter().enumerate() {
                let row = &rows[stage_index * pairs * 2 + pair * 2 + position];
                let extra = u64::from(*stage == "control-ab" && *side == "b");
                if row["stage"] != *stage
                    || row["pair"].as_u64() != u64::try_from(pair).ok()
                    || row["side"] != *side
                    || row["order"] != json!(order)
                    || row["schema_version"].as_u64() != Some(2)
                    || row["scope"] != WINDOW_SCOPE
                    || row["window_blocks"].as_u64() != Some(blocks)
                    || row["iterations_per_block"].as_u64() != Some(iterations)
                    || row["extra_passes"].as_u64() != Some(extra)
                    || row["identity"] != *identity
                {
                    return Err("observation-window matrix order or identity changed".into());
                }
                let (elapsed, total_iterations, scans) =
                    window_totals(&row["components"], blocks, iterations, extra, identity)?;
                if row["elapsed_ns"].as_u64() != Some(elapsed)
                    || row["total_iterations"].as_u64() != Some(total_iterations)
                    || row["actual_scan_count"].as_u64() != Some(scans)
                {
                    return Err("observation-window row totals differ".into());
                }
                times[usize::from(*side == "b")] = elapsed;
            }
            stages[stage_index].push(times);
        }
    }
    let mut maximum = (0_u64, 1_u64);
    for [a, b] in &stages[0] {
        let difference = a.abs_diff(*b);
        if exact_product(u128::from(difference), u128::from(maximum.1))?
            > exact_product(u128::from(maximum.0), u128::from(*a))?
        {
            maximum = (difference, *a);
        }
    }
    let band_numerator = exact_product(2, u128::from(maximum.0))?;
    let mut held_out_passed = true;
    for [a, b] in &stages[1] {
        held_out_passed &= exact_product(u128::from(a.abs_diff(*b)), u128::from(maximum.1))?
            <= exact_product(band_numerator, u128::from(*a))?;
    }
    let mut slowdown_detected = true;
    for [a, b] in &stages[2] {
        let left = exact_product(u128::from(a.abs_diff(*b)), u128::from(maximum.1))?;
        let right = exact_product(band_numerator, u128::from(*a))?;
        slowdown_detected &= b > a && left > right;
    }
    #[allow(clippy::cast_precision_loss)]
    let display = |values: &[[u64; 2]]| {
        values
            .iter()
            .map(|[a, b]| *b as f64 / *a as f64 - 1.0)
            .collect::<Vec<_>>()
    };
    #[allow(clippy::cast_precision_loss)]
    let maximum_display = maximum.0 as f64 / maximum.1 as f64;
    let status = if maximum.0 == 0 {
        "degenerate-training-no-gate"
    } else if held_out_passed && slowdown_detected {
        "informational-calibration-validated"
    } else {
        "unstable-or-insensitive-no-gate"
    };
    Ok(
        json!({"training_ratios":display(&stages[0]),"held_out_ratios":display(&stages[1]),
        "control_ratios":display(&stages[2]),"training_maximum_absolute_ratio":maximum_display,
        "training_maximum_absolute_ratio_exact":exact_ratio(u128::from(maximum.0),maximum.1),
        "empirical_relative_band":2.0*maximum_display,"empirical_band_exact":exact_ratio(band_numerator,maximum.1),
        "held_out_aa_within_band":held_out_passed,"every_control_pair_exceeds_band":slowdown_detected,
        "timer_precision_bound_ns":null,"integer_aggregation_rounding_ns":0,
        "status":status,"release_threshold_created":false}),
    )
}

fn ratios(rows: &[Value], stage: &str, pairs: usize) -> Result<(Vec<f64>, u64), String> {
    let mut ratios = Vec::new();
    let mut minimum = u64::MAX;
    for pair in 0..pairs {
        let select = |side: &str| -> Result<u64, String> {
            let matches = rows
                .iter()
                .filter(|row| row["stage"] == stage && row["pair"] == pair && row["side"] == side)
                .collect::<Vec<_>>();
            let [row] = matches.as_slice() else {
                return Err("calibration requires exactly one row per side".into());
            };
            row["elapsed_ns"]
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or("invalid calibration elapsed".into())
        };
        let a = select("a")?;
        let b = select("b")?;
        minimum = minimum.min(a);
        #[allow(clippy::cast_precision_loss)]
        ratios.push(b as f64 / a as f64 - 1.0);
    }
    Ok((ratios, minimum))
}

pub(super) fn classify(rows: &[Value], pairs: usize) -> Result<Value, String> {
    if pairs < 5 || rows.len() != pairs * 6 {
        return Err("incomplete calibration matrix".into());
    }
    let (training, minimum) = ratios(rows, "training-aa", pairs)?;
    let (validation, _) = ratios(rows, "validation-aa", pairs)?;
    let (control, _) = ratios(rows, "control-ab", pairs)?;
    let maximum = training.iter().map(|value| value.abs()).fold(0.0, f64::max);
    #[allow(clippy::cast_precision_loss)]
    let band = 2.0 * maximum + 2.0 / minimum as f64;
    let held_out_passed = validation.iter().all(|value| value.abs() <= band);
    let slowdown_detected = control.iter().all(|value| *value > band);
    Ok(
        json!({"training_ratios":training,"training_maximum_absolute_ratio":maximum,
        "empirical_relative_band":band,"held_out_ratios":validation,"control_ratios":control,
        "held_out_aa_within_band":held_out_passed,"every_control_pair_exceeds_band":slowdown_detected,
        "status":if held_out_passed && slowdown_detected {"informational-calibration-validated"} else {"unstable-or-insensitive-no-gate"},
        "release_threshold_created":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn native_collector_rejects_empty_observations_and_bounds_all_output_files() {
        let output = Command::new("python3")
            .args(["-c", CONTROLLER, "--self-test"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "collector regression controls failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout,
            b"native collector regression controls passed\n"
        );
    }

    fn rows() -> Vec<Value> {
        let mut rows = Vec::new();
        for stage in ["training-aa", "validation-aa", "control-ab"] {
            for pair in 0..5 {
                for side in ["a", "b"] {
                    let elapsed = if side == "a" {
                        1000
                    } else if stage == "control-ab" {
                        2000
                    } else {
                        1000 + pair
                    };
                    rows.push(json!({"stage":stage,"pair":pair,"side":side,"elapsed_ns":elapsed}));
                }
            }
        }
        rows
    }

    #[test]
    fn held_out_noise_and_slowdown_are_independent_requirements() {
        let input = rows();
        let result = classify(&input, 5).unwrap();
        assert_eq!(result["status"], "informational-calibration-validated");
        let mut noisy = input.clone();
        noisy
            .iter_mut()
            .find(|row| row["stage"] == "validation-aa" && row["side"] == "b")
            .unwrap()["elapsed_ns"] = json!(1500);
        assert_eq!(
            classify(&noisy, 5).unwrap()["status"],
            "unstable-or-insensitive-no-gate"
        );
        let mut no_control = input.clone();
        for row in &mut no_control {
            if row["stage"] == "control-ab" {
                row["elapsed_ns"] = json!(1000);
            }
        }
        assert_eq!(
            classify(&no_control, 5).unwrap()["every_control_pair_exceeds_band"],
            false
        );
        let mut duplicate = input;
        duplicate[0] = duplicate[1].clone();
        assert!(classify(&duplicate, 5).is_err());
    }

    #[test]
    fn requests_are_bounded_and_do_not_accept_an_implicit_destination() {
        assert!(Request::parse(&[], "profile").is_err());
        let args = ["--output", "/private/tmp/profile", "--seconds", "31"].map(str::to_owned);
        assert!(Request::parse(&args, "profile").is_err());
        let args = ["--output", "/private/tmp/profile", "--pairs", "4"].map(str::to_owned);
        assert!(Request::parse(&args, "calibrate").is_err());
    }

    #[test]
    fn dense_workload_is_selectable_without_widening_the_workload_family() {
        for mode in ["profile", "calibrate"] {
            for workload in [
                "core-dense-16-kib",
                "core-dense-unknown",
                "serialize-json-10000",
            ] {
                let args =
                    ["--output", "/private/tmp/profile", "--workload", workload].map(str::to_owned);
                let result = Request::parse(&args, mode);
                if workload == "core-dense-16-kib" {
                    assert_eq!(result.unwrap().workload, workload);
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }

    #[test]
    fn dense_identity_requires_complete_typed_counts_and_fingerprints() {
        let workload = "core-dense-16-kib";
        let identity = json!({
            "workload": workload, "input_bytes": 16384,
            "input_fnv1a64": "3e812ba2e5c2f925", "config_fnv1a64": "f8b26dc4f7787416",
            "outcome_fnv1a64": "b80de9ceab6a9984", "rules": 1, "keywords": 0,
            "findings": 256, "decoded_bytes": 0, "work_units": 514,
            "finding_records": 256, "complete": true, "errors": 0,
        });
        assert!(validate_identity(&identity, workload).is_ok());
        for field in [
            "input_bytes",
            "rules",
            "keywords",
            "findings",
            "decoded_bytes",
            "work_units",
            "finding_records",
            "input_fnv1a64",
            "config_fnv1a64",
            "outcome_fnv1a64",
            "complete",
            "errors",
            "workload",
        ] {
            let mut missing = identity.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(validate_identity(&missing, workload).is_err(), "{field}");
        }
        for (field, value) in [
            ("findings", json!("256")),
            ("work_units", json!(-1)),
            ("complete", json!(false)),
            ("errors", json!(1)),
            ("workload", json!("core-mixed-16-kib")),
            ("outcome_fnv1a64", json!("not-a-valid-hash")),
        ] {
            let mut invalid = identity.clone();
            invalid[field] = value;
            assert!(validate_identity(&invalid, workload).is_err(), "{field}");
        }
    }

    #[test]
    fn profile_provenance_requires_effective_line_tables_and_frame_pointers() {
        let graph = json!({"actions":[{"mnemonic":"Rustc","arguments":[
            "wrapper","--","/tool/bin/rustc","--crate-name=rustleaks_perf",
            "-Cdebuginfo=line-tables-only","-Cforce-frame-pointers=yes"
        ]}]});
        assert!(validate_profile_build(&graph).is_ok());
        let mut missing = graph.clone();
        missing["actions"][0]["arguments"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(validate_profile_build(&missing).is_err());
        let mut overridden = graph;
        overridden["actions"][0]["arguments"]
            .as_array_mut()
            .unwrap()
            .push(json!("-Cdebuginfo=0"));
        assert!(validate_profile_build(&overridden).is_err());
    }
}

#[cfg(test)]
#[path = "performance_investigation/window_tests.rs"]
mod window_tests;
