//! Explicit adapters for previously emitted informational protocols.

use std::collections::BTreeMap;

use super::super::super::{investigation, representative_suite};
use super::{
    INPUT_LIMIT, INVESTIGATION_WORKLOADS, Path, Projection, REPRESENTATIVE_SCOPE, SAMPLE_SCOPE,
    Value, WINDOW_SCOPE, digest, identity_summary, json, prepared, read_private, sha256_bytes,
};

pub(super) const REPRESENTATIVE_WORKLOADS: &[&str] = &[
    "core-mixed-1-kib",
    "core-mixed-16-kib",
    "core-mixed-256-kib",
    "core-dense-16-kib",
    "core-minified-16-kib",
    "core-utf8-invalid-16-kib",
    "core-multiline-16-kib",
    "core-many-rules-16-kib",
    "core-default-no-hit-16-kib",
    "core-default-one-keyword-16-kib",
    "core-default-many-keywords-16-kib",
    "core-default-positive",
    "core-decode-depth-0",
    "core-decode-depth-5",
    "session-merge-10000",
    "serialize-json-10000",
    "serialize-sarif-10000",
    "source-many-small-w1",
    "source-many-small-w4",
    "source-few-large-w1",
    "source-few-large-w4",
    "source-skipped-input-control",
    "git-repeated-blobs",
    "cli-startup",
    "cli-dir",
    "cli-stdin",
    "cli-git",
    "archives-all-formats",
];

#[allow(clippy::too_many_lines)] // Keep ordered protocol completeness checks together.
pub(super) fn representative(value: &Value, verification: &str) -> Result<Value, String> {
    let rows = value["rows"]
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 8192)
        .ok_or("missing representative rows")?;
    let completion = rows.last().ok_or("missing run-complete marker")?;
    if completion["kind"] != "run-complete"
        || completion["schema_version"] != 3
        || completion["suite"] != "representative-v1"
    {
        return Err("representative run omitted its final completion marker".into());
    }
    let first = rows.first().ok_or("missing representative sample")?;
    let provenance = &first["provenance"];
    let evidence = json!({"source":provenance["source"],"build":provenance["build"],"host":provenance["host"],
        "executable_bytes":provenance["executable_bytes"],"executable_fnv1a64":provenance["executable_fnv1a64"],"measurement_scope":REPRESENTATIVE_SCOPE});
    let prepared = prepared(&evidence)?;
    if completion["source"] != prepared.source
        || completion["executable_sha256"] != prepared.build["executable_sha256"]
        || completion["baseline_eligible"] != (prepared.source["dirty"] == false)
    {
        return Err("representative completion identity differs".into());
    }
    let mut samples: BTreeMap<String, BTreeMap<u64, Vec<Value>>> = BTreeMap::new();
    let mut summaries = BTreeMap::new();
    let count = first["sample_count"]
        .as_u64()
        .filter(|count| (3..=31).contains(count))
        .ok_or("invalid representative sample count")?;
    for row in &rows[..rows.len() - 1] {
        if row["schema_version"] != 3
            || row["suite"] != "representative-v1"
            || row["measurement_scope"] != REPRESENTATIVE_SCOPE
            || row["threshold_evaluation"] != "none-uncalibrated"
        {
            return Err("unsupported representative schema or timing scope".into());
        }
        let workload = row["workload"]
            .as_str()
            .filter(|workload| REPRESENTATIVE_WORKLOADS.contains(workload))
            .ok_or("unknown representative workload")?;
        if row["kind"] == "summary" {
            let phase = row["phase"].as_str().ok_or("missing summary phase")?;
            if row["source"] != prepared.source
                || row["build"] != prepared.build
                || row["host"] != prepared.host
                || !row["p95"].is_null()
                || summaries
                    .insert((workload.to_owned(), phase.to_owned()), row)
                    .is_some()
            {
                return Err("duplicate or mismatched representative summary".into());
            }
        } else if row.get("kind").is_none() {
            let index = row["sample_index"]
                .as_u64()
                .filter(|index| *index < count)
                .ok_or("invalid representative sample index")?;
            if row["sample_count"] != count || row["provenance"] != *provenance {
                return Err("representative sample provenance differs".into());
            }
            let iterations = row["phase"]["iterations"]
                .as_u64()
                .filter(|count| (1..=1000).contains(count))
                .ok_or("invalid phase iterations")?;
            let elapsed = row["phase"]["elapsed_ns"]
                .as_u64()
                .ok_or("invalid phase duration")?;
            if row["ns_per_iteration"] != elapsed / iterations {
                return Err("representative derived timing differs".into());
            }
            samples
                .entry(workload.to_owned())
                .or_default()
                .entry(index)
                .or_default()
                .push(row.clone());
        } else {
            return Err("unexpected representative record kind".into());
        }
    }
    if samples.is_empty() {
        return Err("representative run has no samples".into());
    }
    let mut measurements = Vec::new();
    for (workload, processes) in samples {
        if u64::try_from(processes.len()).ok() != Some(count) {
            return Err("representative workload omitted a process".into());
        }
        let mut reference = None;
        let mut timings: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for index in 0..count {
            let rows = processes
                .get(&index)
                .ok_or("representative sample index is missing")?;
            let iterations = rows
                .iter()
                .filter_map(|row| row["phase"]["iterations"].as_u64())
                .max()
                .ok_or("missing phase iterations")?;
            let text = rows
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let checked = representative_suite::validate(&text, &prepared, &workload, iterations)?;
            let stable = checked
                .iter()
                .map(representative_suite::stable_identity)
                .collect::<Vec<_>>();
            if reference
                .as_ref()
                .is_some_and(|expected| expected != &stable)
            {
                return Err("representative exact outcomes or work changed".into());
            }
            reference = Some(stable);
            for row in checked {
                timings
                    .entry(
                        row["phase"]["phase"]
                            .as_str()
                            .ok_or("missing phase name")?
                            .to_owned(),
                    )
                    .or_default()
                    .push(
                        row["ns_per_iteration"]
                            .as_u64()
                            .ok_or("invalid derived timing")?,
                    );
            }
        }
        for (phase, timings) in timings {
            let recomputed = representative_suite::statistics(timings)?;
            let reported = summaries
                .remove(&(workload.clone(), phase.clone()))
                .ok_or("representative summary missing")?;
            if reported["statistics"] != recomputed {
                return Err("representative summary differs from raw samples".into());
            }
            measurements.push(
                json!({"workload":workload,"phase":phase,"sample_count":count,
                "median_elapsed_ns":recomputed["median_ns"],"peak_rss_bytes":null}),
            );
        }
    }
    if !summaries.is_empty() {
        return Err("representative summary has no samples".into());
    }
    Ok(
        json!({"schema_version":1,"kind":"sanitized-performance-summary-v1","status":"informational-timing",
        "verification":verification,"release_gate":false,"retention_days":7,"input_sha256":"0".repeat(64),
        "identity":identity_summary(&evidence,None)?,"measurements":measurements,"profile_artifacts":[],"companion_sha256":null}),
    )
}

#[allow(clippy::too_many_lines)] // Keep ordered protocol completeness checks together.
pub(super) fn calibration(value: &Value) -> Result<Projection, String> {
    let workload = INVESTIGATION_WORKLOADS
        .iter()
        .find(|workload| value["workload"] == **workload)
        .copied()
        .ok_or("unknown calibration workload")?;
    if value["release_gate"] != false
        || value["baseline_eligible"] != (value["source"]["dirty"] == false)
    {
        return Err("calibration release or source eligibility differs".into());
    }
    digest(&value["controller_sha256"], 64)?;
    investigation::validate_identity(&value["identity"], workload)?;
    let pairs = usize::try_from(
        value["pairs_per_stage"]
            .as_u64()
            .filter(|pairs| (5..=31).contains(pairs))
            .ok_or("invalid calibration pair count")?,
    )
    .map_err(|_| "calibration pair count exceeds host size")?;
    let rows = value["rows"]
        .as_array()
        .filter(|rows| rows.len() == pairs * 6)
        .ok_or("incomplete calibration matrix")?;
    let classification = match value["schema_version"].as_u64() {
        Some(1)
            if value["measurement_scope"] == SAMPLE_SCOPE
                && value["policy"]["id"] == "empirical-paired-band-v1" =>
        {
            let iterations = rows[0]["iterations"]
                .as_u64()
                .filter(|count| (1..=100).contains(count))
                .ok_or("invalid calibration iterations")?;
            for (stage_index, stage) in ["training-aa", "validation-aa", "control-ab"]
                .iter()
                .enumerate()
            {
                for pair in 0..pairs {
                    let order = if pair % 2 == 0 {
                        ["a", "b"]
                    } else {
                        ["b", "a"]
                    };
                    for (offset, side) in order.iter().enumerate() {
                        let row = &rows[stage_index * pairs * 2 + pair * 2 + offset];
                        let extra = u64::from(*stage == "control-ab" && *side == "b");
                        if row["stage"] != *stage
                            || row["pair"] != pair
                            || row["side"] != *side
                            || row["order"] != json!(order)
                        {
                            return Err("calibration row order differs".into());
                        }
                        let mut sample = row.clone();
                        sample["kind"] = json!("sample");
                        sample["scope"] = json!(SAMPLE_SCOPE);
                        investigation::validate_sample(
                            &sample,
                            iterations,
                            extra,
                            &value["identity"],
                        )?;
                    }
                }
            }
            investigation::classify(rows, pairs)?
        }
        Some(2)
            if value["measurement_scope"] == WINDOW_SCOPE
                && value["policy"]["id"] == "empirical-paired-window-band-v2" =>
        {
            if rows[0]["identity"] != value["identity"]
                || rows[0]["window_blocks"] != value["window_blocks"]
                || rows[0]["iterations_per_block"] != value["iterations_per_block"]
            {
                return Err("window report differs from row identity".into());
            }
            investigation::classify_windows(
                rows,
                pairs,
                value["first_side"].as_str().ok_or("missing first side")?,
            )?
        }
        _ => return Err("unsupported calibration schema, scope or policy".into()),
    };
    // JSON's default float parser may round a display-only ratio on reload.
    // Recreate the producer's serialization boundary; exact window decisions
    // and all recorded booleans remain unchanged.
    let persisted: Value = serde_json::from_slice(
        &serde_json::to_vec(&classification).map_err(|_| "cannot encode recomputed calibration")?,
    )
    .map_err(|_| "cannot decode recomputed calibration")?;
    if classification != value["calibration"] && persisted != value["calibration"] {
        return Err("calibration classification differs from raw rows".into());
    }
    // Deliberate extra-work controls are excluded from displayed scan timing.
    let mut elapsed = rows
        .iter()
        .filter(|row| row["extra_passes"] == 0)
        .map(|row| {
            let count = if value["schema_version"] == 2 {
                &row["total_iterations"]
            } else {
                &row["iterations"]
            }
            .as_u64()
            .filter(|count| *count > 0)
            .ok_or("missing logical calibration iterations")?;
            Ok(row["elapsed_ns"]
                .as_u64()
                .ok_or("missing calibration elapsed")?
                / count)
        })
        .collect::<Result<Vec<u64>, String>>()?;
    elapsed.sort_unstable();
    Ok((
        "informational-timing",
        vec![
            json!({"workload":workload,"phase":"calibration-summed-scan","sample_count":elapsed.len(),"median_elapsed_ns":elapsed[elapsed.len()/2],"peak_rss_bytes":null}),
        ],
        vec![],
        Some(workload),
    ))
}

pub(super) fn matrix(
    value: &Value,
    directory: Option<&Path>,
    verification: &str,
) -> Result<Value, String> {
    if value["schema_version"] != 2
        || value["protocol"] != "observation-window-v2"
        || value["complete"] != true
        || value["completed_cells"] != 16
        || !value["stop"].is_null()
        || value["release_threshold_created"] != false
        || !matches!(
            value["status"].as_str(),
            Some("baseline-qualified-for-later-protocol-review" | "baseline-unqualified-no-gate")
        )
    {
        return Err("incomplete or unsupported observation-window matrix".into());
    }
    let cells = value["schedule"]
        .as_array()
        .filter(|cells| cells.len() == 16)
        .ok_or("matrix omitted cells")?;
    let directory = directory.ok_or("matrix import needs its fixed private companions")?;
    let workloads = [
        "core-dense-16-kib",
        "core-mixed-16-kib",
        "core-default-no-hit-16-kib",
        "core-decode-depth-5",
    ];
    let mut identities = BTreeMap::new();
    let mut hashes = Vec::new();
    let mut measurements = Vec::new();
    let mut eligible = true;
    for (index, cell) in cells.iter().enumerate() {
        let run = if index < 8 { 1 } else { 2 };
        let slot = (index % 8) / 2;
        let workload = workloads[if run == 1 { slot } else { 3 - slot }];
        let blocks = if (index % 2 == 0) == (run == 1) {
            1
        } else {
            10
        };
        let side = if run == 1 { "a" } else { "b" };
        let role = format!("cell-{index:02}");
        if cell["index"] != index
            || cell["run"] != run
            || cell["workload"] != workload
            || cell["window_blocks"] != blocks
            || cell["first_side"] != side
            || cell["directory"] != role
            || cell["status"] != "complete"
            || cell["pairs_per_stage"] != 9
            || cell["iterations_per_block"] != 100
        {
            return Err("matrix schedule is not the fixed protocol".into());
        }
        let bytes = read_private(&directory.join(&role).join("report.json"), INPUT_LIMIT)?;
        let report: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid matrix companion JSON")?;
        if report["source"] != value["provenance"]["source"]
            || report["build"] != value["provenance"]["build"]
            || report["host"] != value["provenance"]["host"]
            || report["workload"] != workload
            || report["window_blocks"] != blocks
            || report["iterations_per_block"] != 100
            || report["pairs_per_stage"] != 9
            || report["first_side"] != side
            || report["calibration"] != cell["calibration"]
        {
            return Err("matrix companion identity, schedule or classification differs".into());
        }
        let (_, mut cell_measurements, _, _) = calibration(&report)?;
        if identities
            .insert(workload, report["identity"].clone())
            .is_some_and(|identity| identity != report["identity"])
        {
            return Err("matrix workload identity changed between cells".into());
        }
        if blocks == 10 {
            eligible &= report["calibration"]["status"] == "informational-calibration-validated";
        }
        measurements.append(&mut cell_measurements);
        hashes.push(json!({"role":format!("{role}/report.json"),"sha256":sha256_bytes(&bytes)}));
    }
    eligible &= value["provenance"]["source"]["dirty"] == false;
    if value["later_trial_eligible"] != eligible
        || value["source_baseline_eligible"] != (value["provenance"]["source"]["dirty"] == false)
        || (value["status"] == "baseline-qualified-for-later-protocol-review") != eligible
    {
        return Err("matrix eligibility differs from its checked cells".into());
    }
    let mut evidence = value["provenance"].clone();
    evidence["measurement_scope"] = json!(WINDOW_SCOPE);
    Ok(
        json!({"schema_version":1,"kind":"sanitized-performance-summary-v1","status":"informational-timing",
        "verification":verification,"release_gate":false,"retention_days":7,"input_sha256":"0".repeat(64),
        "identity":identity_summary(&evidence,None)?,"measurements":measurements,"profile_artifacts":[],
        "companion_sha256":sha256_bytes(json!(hashes).to_string().as_bytes())}),
    )
}
