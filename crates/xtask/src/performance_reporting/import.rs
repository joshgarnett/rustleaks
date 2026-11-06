//! Bounded report schema checks and one-way public projection.

use super::{
    INPUT_LIMIT, KIND, LegacyRequest, M1_MAX_PERF_BUDGETS, MEASUREMENT_SCOPE, PROFILE_SCOPE, Path,
    PathBuf, Prepared, REPRESENTATIVE_SCOPE, SAMPLE_SCOPE, Value, WINDOW_SCOPE, digest, exact_keys,
    json, read_private, sha256_bytes,
};

pub(super) const PROFILE_ARTIFACTS: &[&str] = &[
    "cpu-stacks.txt",
    "heap-before.txt",
    "vm-before.txt",
    "heap-after.txt",
    "vm-after.txt",
];
const INVESTIGATION_WORKLOADS: &[&str] = &[
    "core-default-many-keywords-16-kib",
    "core-default-one-keyword-16-kib",
    "core-default-no-hit-16-kib",
    "core-mixed-16-kib",
    "core-dense-16-kib",
    "core-decode-depth-5",
];
const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

#[path = "existing.rs"]
mod existing;

pub(super) fn parse(bytes: &[u8]) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return Ok(value);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid performance report encoding")?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if rows.len() >= 8192 {
            return Err("representative row bound exceeded".into());
        }
        rows.push(
            serde_json::from_str::<Value>(line).map_err(|_| "invalid representative JSON Lines")?,
        );
    }
    if rows.is_empty() {
        return Err("empty performance report".into());
    }
    Ok(json!({"kind":"representative-jsonl","rows":rows}))
}

pub(super) fn public_workload(workload: &str) -> bool {
    super::super::PERF_WORKLOADS.contains(&workload)
        || existing::REPRESENTATIVE_WORKLOADS.contains(&workload)
}

pub(super) fn public_phase(workload: &str, phase: &str) -> bool {
    phase == "legacy-operation" && super::super::PERF_WORKLOADS.contains(&workload)
        || phase == "calibration-summed-scan" && INVESTIGATION_WORKLOADS.contains(&workload)
        || existing::REPRESENTATIVE_WORKLOADS.contains(&workload)
            && super::super::representative_suite::required_phases(workload)
                .is_ok_and(|phases| phases.contains(&phase))
}

pub(super) fn summarize(
    value: &Value,
    artifacts: Option<&Path>,
    verification: &str,
) -> Result<Value, String> {
    if value["kind"] == "representative-jsonl" {
        return existing::representative(value, verification);
    }
    if value["kind"] == "observation-window-matrix" {
        return existing::matrix(value, artifacts, verification);
    }
    let (status, measurements, profiles, workload) = match value["kind"].as_str() {
        Some(KIND) => legacy(value)?,
        Some("profile") => profile(value, artifacts)?,
        Some("calibration") => existing::calibration(value)?,
        _ => return Err("unsupported performance report kind or schema".into()),
    };
    Ok(
        json!({"schema_version":1,"kind":"sanitized-performance-summary-v1",
        "status":status,"verification":verification,"release_gate":false,"retention_days":7,
        "input_sha256":"0".repeat(64),"identity":identity_summary(value, workload)?,
        "measurements":measurements,"profile_artifacts":profiles,"companion_sha256":null}),
    )
}

type Projection = (&'static str, Vec<Value>, Vec<Value>, Option<&'static str>);

fn identity_summary(value: &Value, workload: Option<&str>) -> Result<Value, String> {
    let source = &value["source"];
    let build = &value["build"];
    if build["schema_version"] != 1
        || build["system"] != "bazel"
        || !(build["timing_scope"] == value["measurement_scope"]
            || build["timing_scope"] == MEASUREMENT_SCOPE
                && matches!(
                    value["measurement_scope"].as_str(),
                    Some(SAMPLE_SCOPE | WINDOW_SCOPE)
                ))
        || build["default_config_sha256"] != crate::CONFIG_SHA256
        || source["dirty"].as_bool().is_none()
    {
        return Err("report source or build identity is invalid".into());
    }
    let summary = json!({
        "source_revision":digest(&source["revision"],40)?,
        "source_input_sha256":digest(&source["input_sha256"],64)?,
        "source_dirty":source["dirty"],
        "build_sha256":sha256_bytes(build.to_string().as_bytes()),
        "executable_sha256":digest(&build["executable_sha256"],64)?,
        "compiler_sha256":digest(&build["compiler_sha256"],64)?,
        "workload_definition_sha256":digest(&build["workload_definition_sha256"],64)?,
        "target":build["target"],"scope":value["measurement_scope"],"workload":workload,
        "fixture_sha256":if workload.is_some() { Some(sha256_bytes(value.get("identity").unwrap_or(&value["result"]["ready"]["identity"]).to_string().as_bytes())) } else { None },
    });
    validate_identity_summary(&summary)?;
    Ok(summary)
}

pub(super) fn validate_identity_summary(value: &Value) -> Result<(), String> {
    exact_keys(
        value,
        &[
            "source_revision",
            "source_input_sha256",
            "source_dirty",
            "build_sha256",
            "executable_sha256",
            "compiler_sha256",
            "workload_definition_sha256",
            "target",
            "scope",
            "workload",
            "fixture_sha256",
        ],
    )?;
    digest(&value["source_revision"], 40)?;
    for key in [
        "source_input_sha256",
        "build_sha256",
        "executable_sha256",
        "compiler_sha256",
        "workload_definition_sha256",
    ] {
        digest(&value[key], 64)?;
    }
    if value["source_dirty"].as_bool().is_none()
        || !TARGETS.contains(&value["target"].as_str().unwrap_or_default())
        || !matches!(
            value["scope"].as_str(),
            Some(
                MEASUREMENT_SCOPE
                    | PROFILE_SCOPE
                    | REPRESENTATIVE_SCOPE
                    | SAMPLE_SCOPE
                    | WINDOW_SCOPE
            )
        )
    {
        return Err("unknown public target or measurement scope".into());
    }
    if !value["workload"].is_null() {
        if !INVESTIGATION_WORKLOADS.contains(&value["workload"].as_str().unwrap_or_default()) {
            return Err("unknown public profile workload".into());
        }
        digest(&value["fixture_sha256"], 64)?;
    } else if !value["fixture_sha256"].is_null() {
        return Err("unexpected profile fixture identity".into());
    }
    Ok(())
}

fn prepared(value: &Value) -> Result<Prepared, String> {
    identity_summary(value, None)?;
    let executable_bytes = value["executable_bytes"]
        .as_u64()
        .filter(|bytes| (1..=128 * 1024 * 1024).contains(bytes))
        .ok_or("invalid executable size")?;
    Ok(Prepared {
        root: PathBuf::new(),
        binary: PathBuf::new(),
        source: value["source"].clone(),
        build: value["build"].clone(),
        host: value["host"].clone(),
        executable_bytes,
        executable_fnv1a64: digest(&value["executable_fnv1a64"], 16)?.to_owned(),
    })
}

#[allow(clippy::too_many_lines)] // Validate the complete versioned record in protocol order.
fn legacy(value: &Value) -> Result<Projection, String> {
    exact_keys(
        value,
        &[
            "schema_version",
            "kind",
            "complete",
            "source",
            "build",
            "host",
            "executable_bytes",
            "executable_fnv1a64",
            "measurement_scope",
            "budget_requested",
            "calibrated_host",
            "host_qualification",
            "rows",
            "budget_samples",
            "outcome",
        ],
    )?;
    if value["schema_version"] != 1
        || value["complete"] != true
        || value["measurement_scope"] != MEASUREMENT_SCOPE
        || value["budget_requested"].as_bool().is_none()
        || value["calibrated_host"].as_bool().is_none()
    {
        return Err("incomplete or unsupported collection report".into());
    }
    let prepared = prepared(value)?;
    if value["calibrated_host"] != super::super::matches_legacy_host(&value["host_qualification"])
        || value["budget_requested"] != true && !value["host_qualification"].is_null()
    {
        return Err("legacy host qualification contradicts the retained hardware fields".into());
    }

    let rows = value["rows"].as_array().ok_or("missing invariant rows")?;
    let budgets = value["budget_samples"]
        .as_array()
        .ok_or("missing budget rows")?;
    if matches!(
        value["outcome"].as_str(),
        Some("invariant-failure" | "execution-failure")
    ) {
        if !budgets.is_empty() {
            return Err("failed invariant report contains budget results".into());
        }
        return Ok((
            if value["outcome"] == "invariant-failure" {
                "invariant-failure"
            } else {
                "execution-failure"
            },
            vec![],
            vec![],
            None,
        ));
    }
    if value["outcome"] != "complete" {
        return Err("unknown collection outcome".into());
    }
    super::validate_records(
        &rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
        &prepared,
        &LegacyRequest::parse(&[])?,
    )?;
    let mut measurements = rows
        .iter()
        .map(|row| {
            json!({"workload":row["workload"],"phase":"legacy-operation","sample_count":1,
        "median_elapsed_ns":row["ns_per_iteration"],"peak_rss_bytes":null})
        })
        .collect::<Vec<_>>();
    if value["budget_requested"] != true || value["calibrated_host"] != true {
        if !budgets.is_empty()
            || (value["budget_requested"] != true && value["calibrated_host"] == true)
        {
            return Err("unqualified report contains budget results".into());
        }
        return Ok((
            if value["budget_requested"] == true {
                "skipped-legacy-host-budget"
            } else {
                "informational-timing"
            },
            measurements,
            vec![],
            None,
        ));
    }
    if value["host"]["os"] != "macos"
        || value["host"]["arch"] != "aarch64"
        || value["host"]["cpu"] != "Apple M1 Max"
        || budgets.len() != M1_MAX_PERF_BUDGETS.len()
    {
        return Err("legacy budget matrix or host mismatch".into());
    }
    let mut regressed = false;
    measurements.clear();
    for (record, budget) in budgets.iter().zip(M1_MAX_PERF_BUDGETS) {
        exact_keys(record, &["workload", "warmup", "samples"])?;
        if record["workload"] != budget.workload {
            return Err("legacy budget workload order differs".into());
        }
        let request = LegacyRequest::parse(&[])?;
        if super::super::validate_record(&record["warmup"], &prepared, &request)? != budget.workload
        {
            return Err("legacy warmup workload differs".into());
        }
        let samples = record["samples"]
            .as_array()
            .filter(|samples| samples.len() == 7)
            .ok_or("legacy budget requires seven process samples")?;
        let mut elapsed = Vec::new();
        let mut rss = 0;
        for (index, sample) in samples.iter().enumerate() {
            exact_keys(sample, &["index", "row", "peak_rss_bytes"])?;
            if sample["index"].as_u64() != u64::try_from(index).ok()
                || super::super::validate_record(&sample["row"], &prepared, &request)?
                    != budget.workload
            {
                return Err("legacy sample provenance or order differs".into());
            }
            elapsed.push(
                sample["row"]["ns_per_iteration"]
                    .as_u64()
                    .ok_or("invalid sample timing")?,
            );
            if index < 3 {
                rss = rss.max(
                    sample["peak_rss_bytes"]
                        .as_u64()
                        .filter(|rss| *rss > 0)
                        .ok_or("missing RSS sample")?,
                );
            } else if !sample["peak_rss_bytes"].is_null() {
                return Err("unexpected RSS sample".into());
            }
        }
        elapsed.sort_unstable();
        regressed |= elapsed[3] > budget.median_elapsed_ns || rss > budget.peak_rss_bytes;
        measurements.push(json!({"workload":budget.workload,"phase":"legacy-operation","sample_count":7,"median_elapsed_ns":elapsed[3],"peak_rss_bytes":rss}));
    }
    Ok((
        if regressed {
            "qualified-regression"
        } else {
            "legacy-budget-passed"
        },
        measurements,
        vec![],
        None,
    ))
}

#[allow(clippy::too_many_lines)] // Validate the complete versioned record in protocol order.
fn profile(value: &Value, directory: Option<&Path>) -> Result<Projection, String> {
    if value["schema_version"] != 1
        || value["measurement_scope"] != PROFILE_SCOPE
        || value["release_gate"] != false
    {
        return Err("unsupported profile schema or scope".into());
    }
    let result = &value["result"];
    let identity = &result["ready"]["identity"];
    let ready = &result["ready"];
    let provenance = &ready["provenance"];
    if ready["schema_version"] != 1
        || ready["scope"] != SAMPLE_SCOPE
        || provenance["binding"] != "bazel-action-graph"
        || provenance["source"] != value["source"]
        || provenance["build"] != value["build"]
        || provenance["host"] != value["host"]
        || provenance["baseline_eligible"] != (value["source"]["dirty"] == false)
        || provenance["upstream_revision"] != crate::REVISION
        || provenance["default_config_sha256"] != crate::CONFIG_SHA256
        || provenance["package_version"] != crate::RELEASE_VERSION
        || provenance["target_os"] != value["host"]["os"]
        || provenance["target_arch"] != value["host"]["arch"]
        || provenance["executable_bytes"]
            .as_u64()
            .is_none_or(|bytes| bytes == 0 || bytes > 128 * 1024 * 1024)
    {
        return Err("profile ready provenance differs from report build".into());
    }
    digest(&provenance["executable_fnv1a64"], 16)?;

    let workload = INVESTIGATION_WORKLOADS
        .iter()
        .find(|workload| identity["workload"] == **workload)
        .copied()
        .ok_or("unknown profile workload")?;
    if identity["complete"] != true || identity["errors"] != 0 || result["ready"]["kind"] != "ready"
    {
        return Err("profile workload incomplete".into());
    }
    for key in [
        "input_bytes",
        "rules",
        "keywords",
        "findings",
        "decoded_bytes",
        "work_units",
        "finding_records",
    ] {
        if identity[key].as_u64().is_none() {
            return Err("profile omits exact counts".into());
        }
    }
    for key in ["input_fnv1a64", "config_fnv1a64", "outcome_fnv1a64"] {
        digest(&identity[key], 16)?;
    }
    if result["status"] == "unsupported-host" {
        if result.get("profile").is_some() {
            return Err("unsupported host claims a collected profile".into());
        }
        return Ok(("unavailable-profile-tool", vec![], vec![], Some(workload)));
    }
    if !matches!(
        result["status"].as_str(),
        Some("complete" | "completed-with-unavailable-tools")
    ) || result["profile"]["kind"] != "profile-complete"
        || result["profile"]["identity"] != *identity
        || result["profile"]["actual_scan_count"]
            .as_u64()
            .is_none_or(|count| count == 0)
    {
        return Err("profile omitted a matching completed scan".into());
    }
    let directory = directory.ok_or("profile import requires its private artifacts")?;
    let tools = [
        &result["cpu"],
        &result["memory_before"]["heap"],
        &result["memory_before"]["vm"],
        &result["memory_after"]["heap"],
        &result["memory_after"]["vm"],
    ];
    let mut unavailable = false;
    let mut profiles = Vec::new();
    for (index, (tool, role)) in tools.iter().zip(PROFILE_ARTIFACTS).enumerate() {
        match tool["status"].as_str() {
            Some("unavailable" | "unavailable-or-failed" | "unavailable-or-invalid") => {
                unavailable = true;
                continue;
            }
            Some("complete") => {}
            _ => return Err("missing or unknown native collector status".into()),
        }
        if tool["exit_code"] != 0 {
            return Err("completed native tool has failing exit status".into());
        }
        digest(&tool["tool_sha256"], 64)?;
        let hash = digest(&tool["observation_sha256"], 64)?;
        if value["files"][*role] != hash {
            return Err("profile artifact binding differs".into());
        }
        let bytes = read_private(&directory.join(role), INPUT_LIMIT)?;
        if bytes.is_empty() || sha256_bytes(&bytes) != hash {
            return Err("profile artifact is empty or changed".into());
        }
        let fields: &[&str] = match index {
            0 => &[
                "sampled_thread_sections",
                "thread_sample_total",
                "symbolized_frame_rows",
                "target_symbolized_frame_rows",
            ],
            1 | 3 => &["live_nodes", "live_bytes", "populated_class_rows"],
            _ => &[
                "virtual_bytes",
                "resident_bytes",
                "regions",
                "populated_region_rows",
            ],
        };
        if fields.iter().any(|field| {
            tool["observation"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        }) {
            return Err("profile observation has no usable samples".into());
        }
        let kind = match index {
            0 => "cpu",
            1 | 3 => "heap",
            _ => "vm",
        };
        let inspected = super::inspect_observation(kind, &directory.join(role))?;
        if inspected["sha256"] != hash
            || inspected["observation"].is_null()
            || inspected["observation"] != tool["observation"]
        {
            return Err("retained native observation differs from report counters".into());
        }
        profiles.push(json!({"role":role,"sha256":hash}));
    }
    if (result["status"] == "complete") == unavailable {
        return Err("profile status contradicts tool results".into());
    }
    Ok((
        if unavailable {
            "unavailable-profile-tool"
        } else {
            "complete-profile"
        },
        vec![],
        profiles,
        Some(workload),
    ))
}
