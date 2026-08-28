//! Fresh outcome validation, provenance rendering, and traceability baselines.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};

use super::spec::{
    BUILD_VERSION, CASE_COUNT, CONFIG_SHA256, DECLARED_TRANSITIONS, LEGACY_BUILD_VERSION, REVISION,
    VARIANT_COUNT,
};
use super::{newline_records, read};
use crate::tooling::support::sha256_bytes;

const DECLARED_OUTCOME_TRANSITION: (&str, &str) = (
    "2d1f1f679ca552f7563e4c3313e4215c0d7e89317304db723a4c6d2321b2a791",
    "525fa0bc43e6603b15cdbc5c6078a3063dfa2c36162ce2e847561ed0eda36df4",
);
const NATIVE_WINDOWS_LEDGER_TRANSITION: (&str, &str) = (
    "38c64dc4d97a59440f3eae5b3593b0ac27545798af8f92fcbaeb52989a52253d",
    "2362611535a41bd04829f95fc8fef4e7b8a7e3340bc4281e05f41931ce03d7c6",
);
const NATIVE_WINDOWS_BASELINE_DISPOSITION: &str = "Windows baseline paths use native logical spelling; canonical findings are exact while paired raw report order may differ.";
const NATIVE_WINDOWS_SYMLINK_DISPOSITION: &str = "Windows cannot create the dangling-symlink fixture; corrupt-archive handling remains natively replayed and pair-exact.";

struct NativeWindowsFacts<'a> {
    baseline_finding_count: usize,
    baseline_findings_sha256: &'a str,
    baseline_report_bytes: u64,
    issue_event_count: usize,
}

pub(super) fn validate_outcomes(
    bytes: &[u8],
    committed: &[u8],
    manifest: &Value,
    native_windows: &Value,
) -> Result<(), String> {
    let lines = newline_records(bytes, "CLI outcomes")?;
    if lines.len() != CASE_COUNT {
        return Err(format!("fresh CLI outcomes contain {} cases", lines.len()));
    }
    let mut variants = 0;
    let mut paired = 0;
    let mut followups = 0;
    for (number, line) in (1..=CASE_COUNT).zip(lines) {
        let row: Value = serde_json::from_slice(line)
            .map_err(|e| format!("invalid CLI outcome {number}: {e}"))?;
        let id = format!("CLI-BB-{number:03}");
        if required_u64(&row, "protocol_version", &id)? != 1 || required_str(&row, "id", &id)? != id
        {
            return Err(format!("{id}: outcome envelope changed"));
        }
        let rows = required_array(&row, "variants", &id)?;
        variants += rows.len();
        for variant in rows {
            if variant.get("status").and_then(Value::as_str) == Some("native-runtime-followup") {
                followups += 1;
                continue;
            }
            paired += 1;
            for implementation in ["go", "rust"] {
                let observation = variant
                    .get(implementation)
                    .ok_or_else(|| format!("{id}: missing {implementation} observation"))?;
                for field in ["stdout_base64", "stdout_sha256"] {
                    required_str(observation, field, &id)?;
                }
                required_array(observation, "stderr_events", &id)?;
                if !(observation["report"].is_null() || observation["report"].is_object())
                    || !(observation["findings"].is_null() || observation["findings"].is_array())
                {
                    return Err(format!("{id}: incomplete {implementation} observation"));
                }
            }
            let comparison = variant
                .get("comparison")
                .ok_or_else(|| format!("{id}: comparison missing"))?;
            let axes = required_object(comparison, "axes", &id)?;
            if axes.keys().map(String::as_str).collect::<BTreeSet<_>>()
                != [
                    "child_cleanup",
                    "exit",
                    "findings",
                    "report",
                    "stderr_events",
                    "stderr_usage",
                    "stdout",
                ]
                .into_iter()
                .collect()
            {
                return Err(format!("{id}: comparison axes changed"));
            }
        }
    }
    if variants != VARIANT_COUNT || paired != 119 || followups != 0 {
        return Err("fresh CLI variant/process accounting changed".into());
    }
    let expected = required_str(manifest, "outcomes_sha256", "manifest")?;
    if expected != sha256_bytes(committed) {
        return Err("committed CLI outcomes differ from manifest".into());
    }
    let actual = sha256_bytes(bytes);
    validate_native_windows_outcomes(committed, bytes, native_windows)?;
    if !cfg!(windows)
        && expected != actual
        && (expected, actual.as_str()) != DECLARED_OUTCOME_TRANSITION
    {
        let differences = outcome_differences(committed, bytes)?;
        return Err(format!(
            "fresh CLI outcomes differ from committed manifest: expected {expected}, got {actual}; first semantic differences: {}",
            differences.join(", ")
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the fail-closed native ledger contract in one reviewable path.
fn validate_native_windows_outcomes(
    committed: &[u8],
    fresh: &[u8],
    ledger: &Value,
) -> Result<(), String> {
    const BASELINE_DIFFERENCE: &str = "CLI-BB-013/outside-baseline";
    const OUTSIDE_I32_DIFFERENCE: &str = "CLI-BB-019/outside-i32";
    const ISSUE_DIFFERENCE: &str = "CLI-BB-030/corrupt-archive-and-broken-symlink";
    const DIFFERENCE_IDS: [&str; 3] = [
        BASELINE_DIFFERENCE,
        OUTSIDE_I32_DIFFERENCE,
        ISSUE_DIFFERENCE,
    ];
    if required_u64(ledger, "schema_version", "native Windows CLI ledger")? != 1
        || required_u64(ledger, "protocol_version", "native Windows CLI ledger")? != 1
        || required_str(ledger, "oracle_mode", "native Windows CLI ledger")? != "cli"
        || required_str(ledger, "upstream_revision", "native Windows CLI ledger")? != REVISION
        || required_str(ledger, "default_config_sha256", "native Windows CLI ledger")?
            != CONFIG_SHA256
    {
        return Err("native Windows CLI ledger provenance changed".into());
    }
    let baseline_hash = sha256_bytes(committed);
    if required_str(
        ledger,
        "baseline_outcomes_sha256",
        "native Windows CLI ledger",
    )? != baseline_hash
        || required_str(
            ledger,
            "portable_outcomes_sha256",
            "native Windows CLI ledger",
        )? != baseline_hash
    {
        return Err("native Windows CLI ledger baseline hash changed".into());
    }
    let platforms = required_object(ledger, "platforms", "native Windows CLI ledger")?;
    let expected_platforms = ["windows/amd64", "windows/arm64"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if platforms
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_platforms
    {
        return Err("native Windows CLI ledger platform set changed".into());
    }
    for platform in &expected_platforms {
        let record = platforms[*platform]
            .as_object()
            .ok_or_else(|| format!("{platform}: native Windows replay record is not an object"))?;
        if record.len() != 1
            || record.get("native_replay").and_then(Value::as_str) != Some("required")
        {
            return Err(format!(
                "{platform}: native Windows replay contract changed"
            ));
        }
    }
    let difference_ids = required_array(ledger, "difference_ids", "native Windows CLI ledger")?;
    if difference_ids != DIFFERENCE_IDS.map(|id| Value::String(id.into())).as_slice() {
        return Err("native Windows CLI difference ids changed".into());
    }
    let counts = required_object(
        ledger,
        "windows_finding_counts",
        "native Windows CLI ledger",
    )?;
    if counts.len() != 1 || counts.get(BASELINE_DIFFERENCE).and_then(Value::as_u64) != Some(2) {
        return Err("native Windows CLI finding counts changed".into());
    }
    let exits = required_object(ledger, "windows_go_exits", "native Windows CLI ledger")?;
    if exits.len() != 1
        || exits.get(OUTSIDE_I32_DIFFERENCE).and_then(Value::as_i64) != Some(i64::from(i32::MIN))
    {
        return Err("native Windows CLI process exits changed".into());
    }
    let finding_hashes = required_object(
        ledger,
        "windows_finding_set_sha256",
        "native Windows CLI ledger",
    )?;
    if finding_hashes.len() != 1 {
        return Err("native Windows CLI finding hash set changed".into());
    }
    let baseline_findings_sha256 = finding_hashes[BASELINE_DIFFERENCE]
        .as_str()
        .ok_or("native Windows CLI finding hash is not a string")?;
    validate_sha256(baseline_findings_sha256, BASELINE_DIFFERENCE)?;
    let report_bytes =
        required_object(ledger, "windows_report_bytes", "native Windows CLI ledger")?;
    let event_counts =
        required_object(ledger, "windows_event_counts", "native Windows CLI ledger")?;
    if report_bytes.len() != 1
        || !report_bytes.contains_key(BASELINE_DIFFERENCE)
        || event_counts.len() != 1
        || !event_counts.contains_key(ISSUE_DIFFERENCE)
    {
        return Err("native Windows CLI bounded fact set changed".into());
    }
    let dispositions = required_object(ledger, "dispositions", "native Windows CLI ledger")?;
    if dispositions.len() != 2
        || dispositions
            .get("CLI-NATIVE-WINDOWS-001")
            .and_then(Value::as_str)
            != Some(NATIVE_WINDOWS_BASELINE_DISPOSITION)
        || dispositions
            .get("CLI-NATIVE-WINDOWS-002")
            .and_then(Value::as_str)
            != Some(NATIVE_WINDOWS_SYMLINK_DISPOSITION)
    {
        return Err("native Windows CLI dispositions changed".into());
    }
    let facts = NativeWindowsFacts {
        baseline_finding_count: usize::try_from(
            counts[BASELINE_DIFFERENCE]
                .as_u64()
                .ok_or("native Windows CLI finding count is not unsigned")?,
        )
        .map_err(|_| "native Windows CLI finding count is out of range")?,
        baseline_findings_sha256,
        baseline_report_bytes: required_u64(
            &report_bytes[BASELINE_DIFFERENCE],
            "bytes",
            BASELINE_DIFFERENCE,
        )?,
        issue_event_count: usize::try_from(required_u64(
            &event_counts[ISSUE_DIFFERENCE],
            "events",
            ISSUE_DIFFERENCE,
        )?)
        .map_err(|_| "native Windows CLI event count is out of range")?,
    };
    if !cfg!(windows) {
        return Ok(());
    }
    native_windows_platform().ok_or("native Windows CLI architecture is unsupported")?;
    reconcile_native_windows_outcomes(committed, fresh, &DIFFERENCE_IDS, &facts)?;
    Ok(())
}

fn reconcile_native_windows_outcomes(
    committed: &[u8],
    fresh: &[u8],
    expected_differences: &[&str],
    facts: &NativeWindowsFacts<'_>,
) -> Result<(), String> {
    let committed_rows = parse_outcome_rows(committed, "committed CLI outcomes")?;
    let fresh_rows = parse_outcome_rows(fresh, "native Windows CLI outcomes")?;
    if committed_rows.len() != fresh_rows.len() {
        return Err("native Windows CLI outcome count changed".into());
    }
    let mut differences = Vec::new();
    let mut unexpected = Vec::new();
    for (committed_row, fresh_row) in committed_rows.iter().zip(&fresh_rows) {
        let case_id = required_str(committed_row, "id", "committed CLI outcome")?;
        if required_str(fresh_row, "id", "native Windows CLI outcome")? != case_id {
            return Err("native Windows CLI outcome order changed".into());
        }
        let committed_variants = required_array(committed_row, "variants", case_id)?;
        let fresh_variants = required_array(fresh_row, "variants", case_id)?;
        if committed_variants.len() != fresh_variants.len() {
            return Err(format!(
                "{case_id}: native Windows CLI variant count changed"
            ));
        }
        for (committed_variant, fresh_variant) in committed_variants.iter().zip(fresh_variants) {
            let variant_id = required_str(committed_variant, "id", case_id)?;
            if required_str(fresh_variant, "id", case_id)? != variant_id {
                return Err(format!(
                    "{case_id}: native Windows CLI variant order changed"
                ));
            }
            if committed_variant == fresh_variant {
                continue;
            }
            let id = format!("{case_id}/{variant_id}");
            differences.push(id.clone());
            match id.as_str() {
                "CLI-BB-013/outside-baseline" => {
                    validate_windows_baseline_variant(
                        committed_variant,
                        fresh_variant,
                        &id,
                        facts,
                    )?;
                }
                "CLI-BB-019/outside-i32" => {
                    validate_windows_outside_i32_variant(committed_variant, fresh_variant, &id)?;
                }
                "CLI-BB-030/corrupt-archive-and-broken-symlink" => {
                    validate_windows_issue_variant(
                        committed_variant,
                        fresh_variant,
                        &id,
                        facts.issue_event_count,
                    )?;
                }
                _ => {
                    if unexpected.len() < 12 {
                        let mut paths = Vec::new();
                        collect_value_differences(
                            committed_variant,
                            fresh_variant,
                            &id,
                            &mut paths,
                        );
                        paths.truncate(4);
                        unexpected.push(format!("{id}: {}", paths.join(", ")));
                    }
                }
            }
        }
    }
    if !unexpected.is_empty() {
        return Err(format!(
            "native Windows CLI outcomes changed outside the ledger: {}",
            unexpected.join("; ")
        ));
    }
    if differences.iter().map(String::as_str).collect::<Vec<_>>() != expected_differences {
        return Err("native Windows CLI difference ledger changed".into());
    }
    Ok(())
}

fn validate_windows_baseline_variant(
    committed: &Value,
    fresh: &Value,
    label: &str,
    facts: &NativeWindowsFacts<'_>,
) -> Result<(), String> {
    let comparison =
        validate_native_windows_disposition(fresh, label, "CLI-NATIVE-WINDOWS-001", true)?;
    if scrub_native_variant(
        committed,
        &["finding_count", "findings", "report", "stderr_events"],
        label,
    )? != scrub_native_variant(
        fresh,
        &["finding_count", "findings", "report", "stderr_events"],
        label,
    )? {
        return Err(format!(
            "{label}: native Windows baseline changed outside bounded fields"
        ));
    }
    for (variant, expected, platform) in [
        (committed, 1_usize, "portable"),
        (fresh, facts.baseline_finding_count, "Windows"),
    ] {
        for implementation in ["go", "rust"] {
            let observation = variant
                .get(implementation)
                .ok_or_else(|| format!("{label}: missing {implementation} observation"))?;
            let finding_count = usize::try_from(required_u64(observation, "finding_count", label)?)
                .map_err(|_| format!("{label}: {platform} finding count is out of range"))?;
            if finding_count != expected
                || required_array(observation, "findings", label)?.len() != expected
            {
                return Err(format!(
                    "{label}: {platform} {implementation} finding count changed"
                ));
            }
            let events = required_array(observation, "stderr_events", label)?;
            if events.len() != 2 {
                return Err(format!(
                    "{label}: {platform} {implementation} event count changed"
                ));
            }
            validate_summary_findings_event(&events[1], expected, label)?;
            let report = required_object(observation, "report", label)?;
            if report.get("state").and_then(Value::as_str) != Some("present") {
                return Err(format!(
                    "{label}: {platform} {implementation} report state changed"
                ));
            }
        }
    }
    for implementation in ["go", "rust"] {
        let findings = &fresh[implementation]["findings"];
        let findings_bytes = serde_json::to_vec(findings)
            .map_err(|error| format!("{label}: cannot hash Windows findings: {error}"))?;
        if sha256_bytes(&findings_bytes) != facts.baseline_findings_sha256
            || fresh[implementation]["report"]["bytes"].as_u64()
                != Some(facts.baseline_report_bytes)
        {
            return Err(format!(
                "{label}: Windows {implementation} canonical payload changed"
            ));
        }
        validate_sha256(
            required_str(&fresh[implementation]["report"], "sha256", label)?,
            label,
        )?;
        if committed[implementation]["stderr_events"][0]
            != fresh[implementation]["stderr_events"][0]
        {
            return Err(format!(
                "{label}: Windows {implementation} scanned summary changed"
            ));
        }
    }
    if fresh["go"]["findings"] != fresh["rust"]["findings"]
        || fresh["go"]["stderr_events"] != fresh["rust"]["stderr_events"]
    {
        return Err(format!(
            "{label}: native Windows paired canonical payloads differ"
        ));
    }
    let reports_equal = fresh["go"]["report"] == fresh["rust"]["report"];
    if (comparison["axes"]["report"].as_str() == Some("equal")) != reports_equal {
        return Err(format!(
            "{label}: native Windows report-order comparison changed"
        ));
    }
    Ok(())
}

fn validate_windows_issue_variant(
    committed: &Value,
    fresh: &Value,
    label: &str,
    expected_event_count: usize,
) -> Result<(), String> {
    validate_native_windows_disposition(fresh, label, "CLI-NATIVE-WINDOWS-002", false)?;
    if scrub_native_variant(committed, &["stderr_events"], label)?
        != scrub_native_variant(fresh, &["stderr_events"], label)?
    {
        return Err(format!(
            "{label}: native Windows issue fixture changed outside stderr events"
        ));
    }
    for implementation in ["go", "rust"] {
        let portable = required_array(&committed[implementation], "stderr_events", label)?;
        let windows = required_array(&fresh[implementation], "stderr_events", label)?;
        if portable.len() != expected_event_count + 1 || windows.len() != expected_event_count {
            return Err(format!(
                "{label}: {implementation} issue event count changed"
            ));
        }
        for event in &portable[..2] {
            validate_source_issue_event(event, label)?;
        }
        validate_source_issue_event(&windows[0], label)?;
        if portable[2..] != windows[1..] {
            return Err(format!(
                "{label}: {implementation} applicable summaries changed"
            ));
        }
    }
    let go_events = required_array(&fresh["go"], "stderr_events", label)?;
    let rust_events = required_array(&fresh["rust"], "stderr_events", label)?;
    if go_events.len() != rust_events.len()
        || go_events
            .iter()
            .zip(rust_events)
            .any(|(go, rust)| !same_event_projection(go, rust))
    {
        return Err(format!(
            "{label}: native Windows paired issue projections differ"
        ));
    }
    Ok(())
}

fn validate_native_windows_disposition<'a>(
    variant: &'a Value,
    label: &str,
    expected_disposition: &str,
    allow_report_order: bool,
) -> Result<&'a Value, String> {
    let comparison = variant
        .get("comparison")
        .ok_or_else(|| format!("{label}: comparison missing"))?;
    if required_str(comparison, "status", label)? != "accepted-versioned-disposition"
        || required_str(comparison, "disposition", label)? != expected_disposition
    {
        return Err(format!("{label}: native Windows disposition changed"));
    }
    let axes = required_object(comparison, "axes", label)?;
    if axes.len() != 7
        || axes.iter().any(|(axis, value)| {
            value.as_str() != Some("equal")
                && !(allow_report_order && axis == "report" && value.as_str() == Some("different"))
        })
    {
        return Err(format!("{label}: native Windows comparison changed"));
    }
    Ok(comparison)
}

fn scrub_native_variant(
    value: &Value,
    observation_fields: &[&str],
    label: &str,
) -> Result<Value, String> {
    let mut scrubbed = value.clone();
    let object = scrubbed
        .as_object_mut()
        .ok_or_else(|| format!("{label}: variant is not an object"))?;
    object
        .remove("comparison")
        .ok_or_else(|| format!("{label}: comparison missing"))?;
    for implementation in ["go", "rust"] {
        let observation = object
            .get_mut(implementation)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("{label}: {implementation} observation missing"))?;
        for field in observation_fields {
            observation
                .remove(*field)
                .ok_or_else(|| format!("{label}: {implementation} {field} missing"))?;
        }
    }
    Ok(scrubbed)
}

fn validate_summary_findings_event(
    event: &Value,
    expected_count: usize,
    label: &str,
) -> Result<(), String> {
    if required_str(event, "severity", label)? != "warn"
        || required_str(event, "class", label)? != "summary.findings"
    {
        return Err(format!("{label}: findings summary event changed"));
    }
    let fields = required_object(event, "fields", label)?;
    if fields.len() != 1
        || fields.get("count").and_then(Value::as_u64)
            != Some(u64::try_from(expected_count).map_err(|_| "finding count is out of range")?)
    {
        return Err(format!("{label}: findings summary count changed"));
    }
    required_str(event, "normalized_message_base64", label)?;
    Ok(())
}

fn validate_source_issue_event(event: &Value, label: &str) -> Result<(), String> {
    if required_str(event, "severity", label)? != "error"
        || required_str(event, "class", label)? != "source.issue"
        || !required_object(event, "fields", label)?.is_empty()
    {
        return Err(format!("{label}: source issue projection changed"));
    }
    required_str(event, "normalized_message_base64", label)?;
    Ok(())
}

fn same_event_projection(left: &Value, right: &Value) -> bool {
    left.get("severity") == right.get("severity")
        && left.get("class") == right.get("class")
        && left.get("fields") == right.get("fields")
}

fn validate_windows_outside_i32_variant(
    committed: &Value,
    fresh: &Value,
    label: &str,
) -> Result<(), String> {
    if committed["go"]["exit"].as_i64() != Some(0)
        || fresh["go"]["exit"].as_i64() != Some(i64::from(i32::MIN))
        || committed["rust"]["exit"].as_i64() != Some(1)
        || fresh["rust"]["exit"].as_i64() != Some(1)
    {
        return Err(format!("{label}: native Windows process exits changed"));
    }
    let mut normalized = fresh.clone();
    normalized["go"]["exit"] = committed["go"]["exit"].clone();
    if &normalized != committed {
        return Err(format!(
            "{label}: native Windows outcome changed outside the Go exit"
        ));
    }
    Ok(())
}

fn parse_outcome_rows(bytes: &[u8], label: &str) -> Result<Vec<Value>, String> {
    newline_records(bytes, label)?
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_slice(line)
                .map_err(|error| format!("invalid {label} row {}: {error}", index + 1))
        })
        .collect()
}

fn native_windows_platform() -> Option<&'static str> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows/amd64")
    } else if cfg!(all(windows, target_arch = "aarch64")) {
        Some("windows/arm64")
    } else {
        None
    }
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} SHA-256 is invalid"));
    }
    Ok(())
}

fn outcome_differences(committed: &[u8], fresh: &[u8]) -> Result<Vec<String>, String> {
    let committed_lines = newline_records(committed, "committed CLI outcomes")?;
    let fresh_lines = newline_records(fresh, "fresh CLI outcomes")?;
    if committed_lines.len() != fresh_lines.len() {
        return Ok(vec![format!(
            "row count differs: committed {}, fresh {}",
            committed_lines.len(),
            fresh_lines.len()
        )]);
    }
    let mut differences = Vec::new();
    for (number, (committed_line, fresh_line)) in
        committed_lines.into_iter().zip(fresh_lines).enumerate()
    {
        let committed_value: Value = serde_json::from_slice(committed_line)
            .map_err(|error| format!("invalid committed CLI outcome {}: {error}", number + 1))?;
        let fresh_value: Value = serde_json::from_slice(fresh_line)
            .map_err(|error| format!("invalid fresh CLI outcome {}: {error}", number + 1))?;
        let label = committed_value
            .get("id")
            .and_then(Value::as_str)
            .map_or_else(|| format!("row[{}]", number + 1), str::to_owned);
        collect_value_differences(&committed_value, &fresh_value, &label, &mut differences);
        if differences.len() >= 12 {
            break;
        }
    }
    if differences.is_empty() {
        differences.push("semantic JSON matches; byte serialization differs".into());
    }
    Ok(differences)
}

fn collect_value_differences(
    committed: &Value,
    fresh: &Value,
    path: &str,
    differences: &mut Vec<String>,
) {
    if committed == fresh || differences.len() >= 12 {
        return;
    }
    match (committed, fresh) {
        (Value::Object(committed), Value::Object(fresh)) => {
            let keys = committed
                .keys()
                .chain(fresh.keys())
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            for key in keys {
                if differences.len() >= 12 {
                    break;
                }
                let next = format!("{path}/{key}");
                match (committed.get(key), fresh.get(key)) {
                    (Some(committed), Some(fresh)) => {
                        collect_value_differences(committed, fresh, &next, differences);
                    }
                    (Some(_), None) => differences.push(format!("{next} (missing fresh field)")),
                    (None, Some(_)) => {
                        differences.push(format!("{next} (unexpected fresh field)"));
                    }
                    (None, None) => unreachable!("key came from at least one object"),
                }
            }
        }
        (Value::Array(committed), Value::Array(fresh)) => {
            for (index, (committed, fresh)) in committed.iter().zip(fresh).enumerate() {
                if differences.len() >= 12 {
                    break;
                }
                let next = committed
                    .get("id")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("{path}[{index}]"), |id| format!("{path}[{id}]"));
                collect_value_differences(committed, fresh, &next, differences);
            }
            if committed.len() != fresh.len() {
                differences.push(format!(
                    "{path}/length (committed {}, fresh {})",
                    committed.len(),
                    fresh.len()
                ));
            }
        }
        _ => differences.push(describe_scalar_difference(path, committed, fresh)),
    }
}

fn describe_scalar_difference(path: &str, committed: &Value, fresh: &Value) -> String {
    let field = path.rsplit('/').next().unwrap_or(path);
    if field == "normalized_message_base64" {
        if let (Some(committed), Some(fresh)) = (committed.as_str(), fresh.as_str()) {
            return format!(
                "{path} (committed sha256 {}, fresh sha256 {})",
                sha256_bytes(committed.as_bytes()),
                sha256_bytes(fresh.as_bytes())
            );
        }
    }
    let safe_value = path.contains("/comparison/axes/")
        || path.contains("/fields/")
        || matches!(
            field,
            "child_reaped"
                | "class"
                | "disposition"
                | "exit"
                | "finding_count"
                | "report"
                | "severity"
                | "state"
                | "status"
                | "stderr_contains_disclosure_marker"
                | "stderr_usage"
                | "stdout_bytes"
        );
    if safe_value
        && !committed.is_array()
        && !committed.is_object()
        && !fresh.is_array()
        && !fresh.is_object()
    {
        format!("{path} (committed {committed}, fresh {fresh})")
    } else {
        path.into()
    }
}

pub(super) fn render_manifest(
    legacy: &[u8],
    manifest: &Value,
    generator_hash: &str,
    native_linux_hash: &str,
    native_windows_hash: &str,
    unix_path_hash: &str,
    unix_logical_name_hash: &str,
) -> Result<Vec<u8>, String> {
    let old = required_str(manifest, "generator_sha256", "manifest")?;
    let mut rendered = legacy.to_vec();
    for field in ["go_runtime_tree_sha256", "rust_runtime_tree_sha256"] {
        rendered = remove_flat_object_field(&rendered, field)?;
    }
    rendered = replace_once(
        &rendered,
        old.as_bytes(),
        generator_hash.as_bytes(),
        "generator provenance",
    )?;
    rendered = replace_declared_transition(
        &rendered,
        LEGACY_BUILD_VERSION.as_bytes(),
        BUILD_VERSION.as_bytes(),
        "CLI build version transition",
    )?;
    for (path, expected, actual) in DECLARED_TRANSITIONS {
        rendered = replace_declared_transition(
            &rendered,
            expected.as_bytes(),
            actual.as_bytes(),
            &format!("{path} transition"),
        )?;
    }
    rendered = replace_declared_transition(
        &rendered,
        DECLARED_OUTCOME_TRANSITION.0.as_bytes(),
        DECLARED_OUTCOME_TRANSITION.1.as_bytes(),
        "CLI outcomes transition",
    )?;
    rendered = render_native_evidence_transitions(rendered)?;
    let field = format!("  \"native_linux_outcome_sha256\": \"{native_linux_hash}\",\n");
    if let Some(current) = manifest
        .get("native_linux_outcome_sha256")
        .and_then(Value::as_str)
    {
        if current != native_linux_hash {
            return Err("native Linux evidence hash differs from manifest".into());
        }
    } else {
        rendered = insert_after_once(
            &rendered,
            b"  \"negative_controls_sha256\": \"fd24952e9e8e28dae4f8a581ae6bbb20bfa720ac75e2028a717850cc9ac6f152\",\n",
            field.as_bytes(),
            "native Linux evidence provenance",
        )?;
    }
    rendered =
        render_native_windows_ledger(rendered, manifest, native_linux_hash, native_windows_hash)?;
    let field = format!("  \"unix_path_outcome_sha256\": \"{unix_path_hash}\",\n");
    if let Some(current) = manifest
        .get("unix_path_outcome_sha256")
        .and_then(Value::as_str)
    {
        if current != unix_path_hash {
            return Err("Unix path evidence hash differs from manifest".into());
        }
    } else {
        rendered = insert_after_once(
            &rendered,
            b"  \"negative_controls_sha256\": \"fd24952e9e8e28dae4f8a581ae6bbb20bfa720ac75e2028a717850cc9ac6f152\",\n",
            field.as_bytes(),
            "Unix path evidence provenance",
        )?;
    }
    let field = format!("  \"unix_logical_name_outcome_sha256\": \"{unix_logical_name_hash}\",\n");
    if let Some(current) = manifest
        .get("unix_logical_name_outcome_sha256")
        .and_then(Value::as_str)
    {
        if current != unix_logical_name_hash {
            return Err("Unix logical-name evidence hash differs from manifest".into());
        }
    } else {
        let anchor = format!("  \"unix_path_outcome_sha256\": \"{unix_path_hash}\",\n");
        rendered = insert_after_once(
            &rendered,
            anchor.as_bytes(),
            field.as_bytes(),
            "Unix logical-name evidence provenance",
        )?;
    }
    Ok(rendered)
}

fn render_native_windows_ledger(
    mut rendered: Vec<u8>,
    manifest: &Value,
    native_linux_hash: &str,
    native_windows_hash: &str,
) -> Result<Vec<u8>, String> {
    let field = format!("  \"native_windows_ledger_sha256\": \"{native_windows_hash}\",\n");
    if let Some(current) = manifest
        .get("native_windows_ledger_sha256")
        .and_then(Value::as_str)
    {
        if current != native_windows_hash {
            if (current, native_windows_hash) != NATIVE_WINDOWS_LEDGER_TRANSITION {
                return Err("native Windows CLI ledger hash differs from manifest".into());
            }
            rendered = replace_declared_transition(
                &rendered,
                current.as_bytes(),
                native_windows_hash.as_bytes(),
                "native Windows CLI ledger transition",
            )?;
        }
    } else {
        let anchor = format!("  \"native_linux_outcome_sha256\": \"{native_linux_hash}\",\n");
        rendered = insert_after_once(
            &rendered,
            anchor.as_bytes(),
            field.as_bytes(),
            "native Windows CLI ledger provenance",
        )?;
    }
    Ok(rendered)
}

fn render_native_evidence_transitions(mut rendered: Vec<u8>) -> Result<Vec<u8>, String> {
    for (old, new, label) in [
        (
            "  \"paired_observation_pair_count\": 118,\n",
            "  \"paired_observation_pair_count\": 119,\n",
            "paired observation count",
        ),
        (
            "  \"paired_observation_process_count\": 236,\n",
            "  \"paired_observation_process_count\": 238,\n",
            "observation process count",
        ),
        (
            "  \"fresh_cli_process_count\": 240,\n",
            "  \"fresh_cli_process_count\": 242,\n",
            "fresh process count",
        ),
        (
            "  \"exact_variant_count\": 100,\n",
            "  \"exact_variant_count\": 101,\n",
            "exact variant count",
        ),
        (
            "  \"versioned_disposition_variant_count\": 19,\n",
            "  \"versioned_disposition_variant_count\": 18,\n",
            "disposition variant count",
        ),
        (
            "  \"complete_duplicate_preserving_finding_count_both_implementations\": 100,\n",
            "  \"complete_duplicate_preserving_finding_count_both_implementations\": 102,\n",
            "finding count",
        ),
        (
            "  \"raw_report_byte_count_both_implementations\": 48732,\n",
            "  \"raw_report_byte_count_both_implementations\": 49540,\n",
            "report byte count",
        ),
        (
            "  \"stderr_event_count_both_implementations\": 884,\n",
            "  \"stderr_event_count_both_implementations\": 888,\n",
            "stderr event count",
        ),
    ] {
        rendered = replace_text_transition(&rendered, old, new, label)?;
    }
    rendered = replace_text_transition(
        &rendered,
        "    \"FOLLOWUP-NATIVE-M11-001\": 1,\n",
        "",
        "native follow-up disposition count",
    )?;
    rendered = replace_text_transition(
        &rendered,
        "    \"REPORT-SAFE-001\": \"Rust uses the reviewed deterministic capability-free safe-template profile; Go helpers outside that profile are not reproduced.\",\n    \"FOLLOWUP-NATIVE-M11-001\": \"Native Linux and Windows runtime replay is unavailable and nonblocking; cross-compilation is not runtime evidence.\"\n",
        "    \"REPORT-SAFE-001\": \"Rust uses the reviewed deterministic capability-free safe-template profile; Go helpers outside that profile are not reproduced.\"\n",
        "native follow-up disposition description",
    )?;
    rendered = replace_text_transition(
        &rendered,
        "  \"runtime_provenance_policy\": \"independently-validated-then-omitted\",\n",
        "  \"runtime_provenance_policy\": \"independently-validated-with-native-linux-record\",\n",
        "runtime provenance policy",
    )?;
    replace_text_transition(
        &rendered,
        "  \"native_runtime_evidence\": {\n    \"generation_host\": \"validated-but-omitted\",\n    \"linux\": \"FOLLOWUP-NATIVE-M11-001\",\n    \"windows\": \"FOLLOWUP-NATIVE-M11-001\"\n  }\n",
        "  \"native_runtime_evidence\": {\n    \"generation_host\": \"validated-and-recorded\",\n    \"linux\": \"native-linux-v1.json exact replay plus native Bazel tests\",\n    \"windows\": \"pinned oracle replay plus native Bazel tests\"\n  }\n",
        "native runtime evidence",
    )
}

fn replace_text_transition(
    bytes: &[u8],
    old: &str,
    new: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let old_count = bytes
        .windows(old.len())
        .filter(|value| *value == old.as_bytes())
        .count();
    let new_count = if new.is_empty() {
        usize::from(old_count == 0)
    } else {
        bytes
            .windows(new.len())
            .filter(|value| *value == new.as_bytes())
            .count()
    };
    match (old_count, new_count) {
        (1, 0) => {
            let start = bytes
                .windows(old.len())
                .position(|value| value == old.as_bytes())
                .unwrap();
            let mut result = Vec::with_capacity(bytes.len() - old.len() + new.len());
            result.extend_from_slice(&bytes[..start]);
            result.extend_from_slice(new.as_bytes());
            result.extend_from_slice(&bytes[start + old.len()..]);
            Ok(result)
        }
        (0, 1) => Ok(bytes.to_vec()),
        _ => Err(format!(
            "expected exactly one old or current {label}, found {old_count}/{new_count}"
        )),
    }
}

fn insert_after_once(
    bytes: &[u8],
    marker: &[u8],
    insertion: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let positions = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, value)| (value == marker).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(format!(
            "expected one {label} marker, found {}",
            positions.len()
        ));
    }
    let end = positions[0] + marker.len();
    let mut result = Vec::with_capacity(bytes.len() + insertion.len());
    result.extend_from_slice(&bytes[..end]);
    result.extend_from_slice(insertion);
    result.extend_from_slice(&bytes[end..]);
    Ok(result)
}

fn remove_flat_object_field(bytes: &[u8], field: &str) -> Result<Vec<u8>, String> {
    let prefix = format!("  \"{field}\": {{\n");
    let positions = bytes
        .windows(prefix.len())
        .enumerate()
        .filter_map(|(index, window)| (window == prefix.as_bytes()).then_some(index))
        .collect::<Vec<_>>();
    if positions.is_empty() {
        return Ok(bytes.to_vec());
    }
    if positions.len() != 1 {
        return Err(format!(
            "expected at most one {field} object, found {}",
            positions.len()
        ));
    }
    let start = positions[0];
    let body = &bytes[start + prefix.len()..];
    let suffix = b"\n  },\n";
    let relative_end = body
        .windows(suffix.len())
        .position(|window| window == suffix)
        .ok_or_else(|| format!("{field} object is not a flat generated object"))?;
    let end = start + prefix.len() + relative_end + suffix.len();
    let mut rendered = Vec::with_capacity(bytes.len() - (end - start));
    rendered.extend_from_slice(&bytes[..start]);
    rendered.extend_from_slice(&bytes[end..]);
    Ok(rendered)
}

fn replace_declared_transition(
    bytes: &[u8],
    old: &[u8],
    new: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let old_count = bytes
        .windows(old.len())
        .filter(|value| *value == old)
        .count();
    let new_count = bytes
        .windows(new.len())
        .filter(|value| *value == new)
        .count();
    match (old_count, new_count) {
        (1, 0) => replace_once(bytes, old, new, label),
        (0, 1) => Ok(bytes.to_vec()),
        _ => Err(format!(
            "expected exactly one old or current {label}, found {old_count}/{new_count}"
        )),
    }
}

fn replace_once(bytes: &[u8], old: &[u8], new: &[u8], label: &str) -> Result<Vec<u8>, String> {
    if old.len() != new.len() {
        return Err(format!("{label} digest length changed"));
    }
    let positions = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(i, w)| (w == old).then_some(i))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(format!("expected one {label}, found {}", positions.len()));
    }
    let mut result = bytes.to_vec();
    result[positions[0]..positions[0] + old.len()].copy_from_slice(new);
    Ok(result)
}

pub(crate) fn validate_cli_manifest_baselines(root: &Path, text: &str) -> Result<(), String> {
    let corpus = root.join("compat/cli-corpus");
    let manifest_bytes = read(&corpus.join("manifest-v1.json"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("invalid CLI manifest: {e}"))?;
    let required = [
        format!(
            "cli_generator_sha256 = \"{}\"",
            required_str(&manifest, "generator_sha256", "manifest")?
        ),
        format!(
            "cli_requests_sha256 = \"{}\"",
            required_str(&manifest, "requests_sha256", "manifest")?
        ),
        format!(
            "cli_outcomes_sha256 = \"{}\"",
            required_str(&manifest, "outcomes_sha256", "manifest")?
        ),
        format!(
            "cli_negative_controls_sha256 = \"{}\"",
            required_str(&manifest, "negative_controls_sha256", "manifest")?
        ),
        format!(
            "cli_manifest_sha256 = \"{}\"",
            sha256_bytes(&manifest_bytes)
        ),
        format!(
            "cli_readme_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("README.md"))?)
        ),
        format!(
            "cli_native_linux_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("native-linux-v1.json"))?)
        ),
        format!(
            "cli_native_windows_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("native-windows-v1.json"))?)
        ),
        format!(
            "cli_unix_path_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("unix-path-v1.json"))?)
        ),
        format!(
            "cli_unix_logical_name_sha256 = \"{}\"",
            sha256_bytes(&read(&corpus.join("unix-logical-name-v1.json"))?)
        ),
        "cli_cases = 34".into(),
        "cli_variants = 119".into(),
        "cli_fresh_processes = 242".into(),
        "cli_exact_variants = 101".into(),
        "cli_disposition_variants = 18".into(),
        "cli_findings_both = 102".into(),
        "cli_report_bytes_both = 49540".into(),
        "cli_parser_usage_bytes_both = 19508".into(),
        "cli_stderr_events_both = 888".into(),
        "cli_mutation_controls = 20".into(),
    ];
    for baseline in required {
        if !text.contains(&baseline) {
            return Err(format!("test manifest is missing CLI baseline {baseline}"));
        }
    }
    Ok(())
}

pub(super) fn required_array<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Vec<Value>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: {field} is not an array"))
}
pub(super) fn required_object<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}: {field} is not an object"))
}
pub(super) fn required_str<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} is not a string"))
}
pub(super) fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label}: {field} is not unsigned"))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::tooling::support::sha256_bytes;

    use super::{
        NativeWindowsFacts, collect_value_differences, reconcile_native_windows_outcomes,
        remove_flat_object_field, replace_declared_transition, replace_once,
    };

    fn baseline_variant(count: u64) -> serde_json::Value {
        let findings = (0..count)
            .map(|index| json!({"index": index}))
            .collect::<Vec<_>>();
        let observation = json!({
            "finding_count": count,
            "findings": findings,
            "report": {
                "state": "present",
                "bytes": count * 10,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "stderr_events": [
                {
                    "severity": "info",
                    "class": "summary.scanned",
                    "fields": {"bytes": 1, "human": "1 byte"},
                    "normalized_message_base64": "c2Nhbm5lZA=="
                },
                {
                    "severity": "warn",
                    "class": "summary.findings",
                    "fields": {"count": count},
                    "normalized_message_base64": "ZmluZGluZ3M="
                }
            ]
        });
        let native = count == 2;
        json!({
            "id": "outside-baseline",
            "go": observation,
            "rust": observation,
            "comparison": {
                "axes": {
                    "child_cleanup": "equal",
                    "exit": "equal",
                    "findings": "equal",
                    "report": "equal",
                    "stderr_events": "equal",
                    "stderr_usage": "equal",
                    "stdout": "equal"
                },
                "status": if native { "accepted-versioned-disposition" } else { "exact" },
                "disposition": if native { json!("CLI-NATIVE-WINDOWS-001") } else { Value::Null }
            }
        })
    }

    fn issue_variant(native: bool) -> serde_json::Value {
        let issue = |message| {
            json!({
                "severity": "error",
                "class": "source.issue",
                "fields": {},
                "normalized_message_base64": message
            })
        };
        let summary = json!({
            "severity": "info",
            "class": "summary.scanned",
            "fields": {"bytes": 1, "human": "1 byte"},
            "normalized_message_base64": "c2Nhbm5lZA=="
        });
        let findings = json!({
            "severity": "warn",
            "class": "summary.findings",
            "fields": {"count": 1},
            "normalized_message_base64": "ZmluZGluZ3M="
        });
        let events = if native {
            vec![issue("bmF0aXZl"), summary, findings]
        } else {
            vec![
                issue("YXJjaGl2ZQ=="),
                issue("c3ltbGluaw=="),
                summary,
                findings,
            ]
        };
        let observation = json!({
            "exit": 1,
            "report": {"state": "present", "bytes": 10},
            "findings": [{"index": 0}],
            "finding_count": 1,
            "stderr_events": events
        });
        json!({
            "id": "corrupt-archive-and-broken-symlink",
            "go": observation,
            "rust": observation,
            "comparison": {
                "axes": {
                    "child_cleanup": "equal",
                    "exit": "equal",
                    "findings": "equal",
                    "report": "equal",
                    "stderr_events": "equal",
                    "stderr_usage": "equal",
                    "stdout": "equal"
                },
                "status": if native { "accepted-versioned-disposition" } else { "exact" },
                "disposition": if native { json!("CLI-NATIVE-WINDOWS-002") } else { Value::Null }
            }
        })
    }

    #[test]
    fn native_windows_reconciliation_accepts_only_the_baseline_branch() {
        let committed = json!({
            "id": "CLI-BB-013",
            "variants": [baseline_variant(1), {"id": "portable"}, {"id": "second"}]
        });
        let fresh = json!({
            "id": "CLI-BB-013",
            "variants": [baseline_variant(2), {"id": "portable"}, {"id": "second"}]
        });
        let render = |value: &serde_json::Value| {
            let mut bytes = serde_json::to_vec(value).unwrap();
            bytes.push(b'\n');
            bytes
        };
        let findings = serde_json::to_vec(&fresh["variants"][0]["go"]["findings"]).unwrap();
        let finding_hash = sha256_bytes(&findings);
        let facts = NativeWindowsFacts {
            baseline_finding_count: 2,
            baseline_findings_sha256: &finding_hash,
            baseline_report_bytes: 20,
            issue_event_count: 3,
        };
        assert!(
            reconcile_native_windows_outcomes(
                &render(&committed),
                &render(&fresh),
                &["CLI-BB-013/outside-baseline"],
                &facts,
            )
            .is_ok()
        );

        let mut unexpected = fresh;
        unexpected["variants"][1]["changed"] = json!(true);
        unexpected["variants"][2]["changed"] = json!(true);
        let error = reconcile_native_windows_outcomes(
            &render(&committed),
            &render(&unexpected),
            &["CLI-BB-013/outside-baseline"],
            &facts,
        );
        let error = error.unwrap_err();
        assert!(error.contains("CLI-BB-013/portable"));
        assert!(error.contains("CLI-BB-013/second"));
    }

    #[test]
    fn native_windows_reconciliation_accepts_only_the_signed_go_exit() {
        let committed = json!({
            "id": "CLI-BB-019",
            "variants": [{
                "id": "outside-i32",
                "go": {"exit": 0},
                "rust": {"exit": 1}
            }]
        });
        let mut fresh = committed.clone();
        fresh["variants"][0]["go"]["exit"] = json!(i32::MIN);
        let render = |value: &serde_json::Value| {
            let mut bytes = serde_json::to_vec(value).unwrap();
            bytes.push(b'\n');
            bytes
        };
        let facts = NativeWindowsFacts {
            baseline_finding_count: 2,
            baseline_findings_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            baseline_report_bytes: 20,
            issue_event_count: 3,
        };
        assert!(
            reconcile_native_windows_outcomes(
                &render(&committed),
                &render(&fresh),
                &["CLI-BB-019/outside-i32"],
                &facts,
            )
            .is_ok()
        );

        fresh["variants"][0]["rust"]["exit"] = json!(2);
        assert!(
            reconcile_native_windows_outcomes(
                &render(&committed),
                &render(&fresh),
                &["CLI-BB-019/outside-i32"],
                &facts,
            )
            .is_err()
        );
    }

    #[test]
    fn native_windows_reconciliation_bounds_the_symlink_capability_gap() {
        let committed = json!({
            "id": "CLI-BB-030",
            "variants": [issue_variant(false)]
        });
        let mut fresh = json!({
            "id": "CLI-BB-030",
            "variants": [issue_variant(true)]
        });
        let render = |value: &serde_json::Value| {
            let mut bytes = serde_json::to_vec(value).unwrap();
            bytes.push(b'\n');
            bytes
        };
        let facts = NativeWindowsFacts {
            baseline_finding_count: 2,
            baseline_findings_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            baseline_report_bytes: 20,
            issue_event_count: 3,
        };
        assert!(
            reconcile_native_windows_outcomes(
                &render(&committed),
                &render(&fresh),
                &["CLI-BB-030/corrupt-archive-and-broken-symlink"],
                &facts,
            )
            .is_ok()
        );

        fresh["variants"][0]["go"]["finding_count"] = json!(2);
        assert!(
            reconcile_native_windows_outcomes(
                &render(&committed),
                &render(&fresh),
                &["CLI-BB-030/corrupt-archive-and-broken-symlink"],
                &facts,
            )
            .is_err()
        );
    }

    #[test]
    fn outcome_differences_report_safe_values_without_finding_contents() {
        let committed = json!({"variants": [{"id": "portable", "comparison": {"axes": {"stderr_events": "equal"}}, "go": {"stderr_events": [{"class": "expected", "normalized_message_base64": "secret-a"}]}, "findings": [{"file": "sensitive-a"}]}]});
        let fresh = json!({"variants": [{"id": "portable", "comparison": {"axes": {"stderr_events": "different"}}, "go": {"stderr_events": [{"class": "actual", "normalized_message_base64": "secret-b"}]}, "findings": [{"file": "sensitive-b"}]}]});
        let mut differences = Vec::new();
        collect_value_differences(&committed, &fresh, "CLI-BB-001", &mut differences);
        assert_eq!(
            differences,
            [
                "CLI-BB-001/variants[portable]/comparison/axes/stderr_events (committed \"equal\", fresh \"different\")",
                "CLI-BB-001/variants[portable]/findings[0]/file",
                "CLI-BB-001/variants[portable]/go/stderr_events[0]/class (committed \"expected\", fresh \"actual\")",
                "CLI-BB-001/variants[portable]/go/stderr_events[0]/normalized_message_base64 (committed sha256 8766b9cb08e6040b704f1e3ee1e186efccf2635b1d2634d6525333007e6aeae1, fresh sha256 ff492ef788c89b555e6f738b33d2422f57dbb6656af2402155672c5f123a90af)",
            ]
        );
    }

    #[test]
    fn flat_generated_object_removal_is_idempotent_and_fails_closed() {
        let input =
            b"{\n  \"keep\": 1,\n  \"tree\": {\n    \"path\": \"hash\"\n  },\n  \"tail\": 2\n}\n";
        let expected = b"{\n  \"keep\": 1,\n  \"tail\": 2\n}\n";
        assert_eq!(remove_flat_object_field(input, "tree").unwrap(), expected);
        assert_eq!(
            remove_flat_object_field(expected, "tree").unwrap(),
            expected
        );
        assert!(remove_flat_object_field(b"  \"tree\": {\n  \"tree\": {\n", "tree").is_err());
    }

    #[test]
    fn provenance_replacement_fails_closed() {
        assert_eq!(
            replace_once(b"old", b"old", b"new", "test").unwrap(),
            b"new"
        );
        assert!(replace_once(b"old old", b"old", b"new", "test").is_err());
        assert_eq!(
            replace_declared_transition(b"new", b"old", b"new", "test").unwrap(),
            b"new"
        );
        assert!(replace_declared_transition(b"old new", b"old", b"new", "test").is_err());
    }
}
