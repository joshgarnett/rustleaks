//! Response-envelope, fixture, count, and manifest validation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value};

use super::controls;
use super::read;
use super::spec::{CASE_COUNT, DEFAULT_CONFIG_SHA256, PROTOCOL_VERSION, REVISION};
use crate::tooling::artifacts::{OutcomeBaseline, first_json_difference};
use crate::tooling::support::sha256_bytes;

pub(super) fn validate_envelope(
    request: &Value,
    outcome: &Value,
    go_version: &str,
    platform: &str,
) -> Result<(), String> {
    let id = required_str(request, "id", "request")?;
    if required_str(outcome, "id", id)? != id
        || required_u64(outcome, "protocol_version", id)? != PROTOCOL_VERSION
        || required_str(outcome, "oracle_mode", id)? != "report"
        || required_str(outcome, "upstream_revision", id)? != REVISION
        || required_str(outcome, "default_config_sha256", id)? != DEFAULT_CONFIG_SHA256
    {
        return Err(format!("{id}: oracle response envelope changed"));
    }
    if !runtime_matches(outcome, go_version, platform) {
        return Err(format!(
            "{id}: runtime provenance differs from selected Go toolchain"
        ));
    }
    for field in ["behavior_ids", "test_case_ids"] {
        if outcome.get(field) != request.get(field) {
            return Err(format!("{id}: {field} changed in oracle response"));
        }
    }
    if outcome.get("format") != request.get("format") {
        return Err(format!("{id}: format changed in oracle response"));
    }
    let output = decoded_output(outcome)?;
    if required_u64(outcome, "output_bytes", id)? != output.len() as u64
        || required_str(outcome, "output_sha256", id)? != sha256_bytes(&output)
    {
        return Err(format!("{id}: output length or hash mismatch"));
    }
    if !outcome
        .get("redacted_findings")
        .is_some_and(Value::is_array)
    {
        return Err(format!("{id}: redacted projection is missing"));
    }
    Ok(())
}

pub(super) fn runtime_negative_control(
    outcome: &Value,
    go_version: &str,
    platform: &str,
) -> Result<(), String> {
    for field in ["go_version", "platform"] {
        let mut mutated = outcome.clone();
        mutated
            .as_object_mut()
            .ok_or("oracle outcome is not an object")?
            .insert(field.into(), Value::String("invalid-provenance".into()));
        if runtime_matches(&mutated, go_version, platform) {
            return Err(format!(
                "runtime provenance negative control accepted mutated {field}"
            ));
        }
    }
    Ok(())
}

fn runtime_matches(outcome: &Value, go_version: &str, platform: &str) -> bool {
    outcome.get("go_version").and_then(Value::as_str) == Some(go_version)
        && outcome.get("platform").and_then(Value::as_str) == Some(platform)
}

pub(super) fn validate_native_windows_ledger(
    committed: OutcomeBaseline<'_>,
    observed: OutcomeBaseline<'_>,
    observed_platform: &str,
    ledger: &Value,
) -> Result<(), String> {
    const DIFFERENCE_ID: &str = "template-missing-path";
    const DIFFERENCE_PATH: &str = "/error/message";

    if required_u64(ledger, "schema_version", "native Windows report ledger")? != 1
        || required_u64(ledger, "protocol_version", "native Windows report ledger")?
            != PROTOCOL_VERSION
        || required_str(ledger, "oracle_mode", "native Windows report ledger")? != "report"
        || required_str(ledger, "upstream_revision", "native Windows report ledger")? != REVISION
        || required_str(
            ledger,
            "default_config_sha256",
            "native Windows report ledger",
        )? != DEFAULT_CONFIG_SHA256
    {
        return Err("native Windows report ledger provenance changed".into());
    }
    let baseline_hash = sha256_bytes(committed.bytes);
    if required_str(
        ledger,
        "baseline_outcomes_sha256",
        "native Windows report ledger",
    )? != baseline_hash
        || required_str(
            ledger,
            "portable_outcomes_sha256",
            "native Windows report ledger",
        )? != baseline_hash
    {
        return Err("native Windows report ledger baseline hash changed".into());
    }

    let platforms = required_object(ledger, "platforms", "native Windows report ledger")?;
    let expected_platforms = ["windows/amd64", "windows/arm64"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if platforms
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_platforms
    {
        return Err("native Windows report ledger platform set changed".into());
    }
    for platform in &expected_platforms {
        validate_sha256(
            required_str(&platforms[*platform], "outcomes_sha256", platform)?,
            platform,
        )?;
    }
    if string_array(ledger, "difference_ids", "native Windows report ledger")? != [DIFFERENCE_ID] {
        return Err("native Windows report difference ids changed".into());
    }
    let paths = required_object(ledger, "difference_paths", "native Windows report ledger")?;
    if paths.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != [DIFFERENCE_ID].into_iter().collect()
        || paths[DIFFERENCE_ID]
            .as_array()
            .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
            .as_deref()
            != Some(&[DIFFERENCE_PATH])
    {
        return Err("native Windows report difference paths changed".into());
    }

    if !cfg!(windows) {
        return Ok(());
    }
    let platform = platforms.get(observed_platform).ok_or_else(|| {
        format!("native Windows report platform is unsupported: {observed_platform}")
    })?;
    if sha256_bytes(observed.bytes) != required_str(platform, "outcomes_sha256", observed_platform)?
    {
        return Err(format!(
            "native Windows report outcomes changed for {observed_platform}"
        ));
    }
    reconcile_native_windows_outcomes(committed.values, observed.values)
}

fn reconcile_native_windows_outcomes(
    committed: &[Value],
    observed: &[Value],
) -> Result<(), String> {
    const DIFFERENCE_ID: &str = "template-missing-path";
    const DIFFERENCE_PATH: &str = "/error/message";

    if committed.len() != observed.len() {
        return Err("native Windows report outcome count changed".into());
    }
    let mut difference_ids = Vec::new();
    for (baseline, windows) in committed.iter().zip(observed) {
        let id = required_str(baseline, "id", "committed report outcome")?;
        if required_str(windows, "id", "native Windows report outcome")? != id {
            return Err("native Windows report outcome order changed".into());
        }
        if baseline == windows {
            continue;
        }
        difference_ids.push(id);
        if id != DIFFERENCE_ID
            || first_json_difference(baseline, windows, "").as_deref() != Some(DIFFERENCE_PATH)
        {
            return Err(format!(
                "native Windows report outcome {id} changed outside its recorded path"
            ));
        }
        let baseline_message = baseline
            .pointer(DIFFERENCE_PATH)
            .and_then(Value::as_str)
            .ok_or("committed missing-template report error has no message")?;
        let windows_message = windows
            .pointer(DIFFERENCE_PATH)
            .and_then(Value::as_str)
            .ok_or("native Windows missing-template report error has no message")?;
        if baseline_message == windows_message {
            return Err("native Windows missing-template report message did not differ".into());
        }
        let mut portable = windows.clone();
        *portable
            .pointer_mut(DIFFERENCE_PATH)
            .ok_or("native Windows missing-template report message disappeared")? =
            Value::String(baseline_message.to_owned());
        if &portable != baseline {
            return Err(
                "native Windows report portable outcome differs from committed corpus".into(),
            );
        }
    }
    if difference_ids != [DIFFERENCE_ID] {
        return Err("native Windows report difference ledger changed".into());
    }
    Ok(())
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

pub(super) fn validate_all(
    upstream: &Path,
    requests: &[Value],
    outcomes: &[Value],
    outcome_bytes: &[u8],
    coverage: &Value,
) -> Result<(), String> {
    if requests.len() != outcomes.len() || outcomes.len() != CASE_COUNT {
        return Err("report request/outcome count mismatch".into());
    }
    let by_id = outcomes
        .iter()
        .map(|outcome| required_str(outcome, "id", "outcome").map(|id| (id, outcome)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if by_id.len() != CASE_COUNT {
        return Err("report outcomes contain duplicate ids".into());
    }
    for (request, outcome) in requests.iter().zip(outcomes) {
        let id = required_str(request, "id", "request")?;
        if required_str(outcome, "id", "outcome")? != id {
            return Err(format!("{id}: outcome order changed"));
        }
    }
    validate_fixture_relations(upstream, &by_id)?;
    controls::validate(&by_id)?;
    if outcome_bytes
        .windows(b"rustleaks-report-template-".len())
        .any(|window| window == b"rustleaks-report-template-")
    {
        return Err("temporary template path leaked into report outcomes".into());
    }
    if !cfg!(windows)
        && required_str(coverage, "outcomes_sha256", "coverage")? != sha256_bytes(outcome_bytes)
    {
        return Err("fresh report outcomes differ from coverage outcomes_sha256".into());
    }
    let output_count = outcomes
        .iter()
        .map(|outcome| required_u64(outcome, "output_bytes", "outcome"))
        .sum::<Result<u64, _>>()?;
    if output_count != required_u64(coverage, "output_byte_count", "coverage")? {
        return Err("report output byte count differs from coverage".into());
    }
    let error_count = outcomes
        .iter()
        .filter(|outcome| outcome.get("error").is_some_and(|value| !value.is_null()))
        .count() as u64;
    if error_count != required_u64(coverage, "error_case_count", "coverage")? {
        return Err("report error count differs from coverage".into());
    }
    Ok(())
}

fn validate_fixture_relations(
    upstream: &Path,
    outcomes: &BTreeMap<&str, &Value>,
) -> Result<(), String> {
    for (id, fixture) in [
        ("json-empty", "testdata/expected/report/empty.json"),
        (
            "json-upstream-simple",
            "testdata/expected/report/json_simple.json",
        ),
        (
            "csv-upstream-simple",
            "testdata/expected/report/csv_simple.csv",
        ),
        ("junit-empty", "testdata/expected/report/junit_empty.xml"),
        (
            "junit-upstream-simple",
            "testdata/expected/report/junit_simple.xml",
        ),
        (
            "sarif-upstream-simple",
            "testdata/expected/report/sarif_simple.sarif",
        ),
        (
            "template-markdown",
            "testdata/expected/report/template_markdown.md",
        ),
        (
            "template-jsonextra",
            "testdata/expected/report/template_jsonextra.json",
        ),
    ] {
        if output_for(outcomes, id)? != read(&upstream.join(fixture))? {
            return Err(format!("{id}: exact upstream fixture bytes changed"));
        }
    }
    Ok(())
}

pub(super) fn decoded_output(outcome: &Value) -> Result<Vec<u8>, String> {
    let id = outcome
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("outcome");
    BASE64
        .decode(required_str(outcome, "output_base64", id)?)
        .map_err(|error| format!("{id}: invalid output_base64: {error}"))
}

pub(super) fn output_for(outcomes: &BTreeMap<&str, &Value>, id: &str) -> Result<Vec<u8>, String> {
    decoded_output(outcome_for(outcomes, id)?)
}

pub(super) fn outcome_for<'a>(
    outcomes: &'a BTreeMap<&str, &Value>,
    id: &str,
) -> Result<&'a Value, String> {
    outcomes
        .get(id)
        .copied()
        .ok_or_else(|| format!("missing report outcome {id}"))
}

pub(super) fn error_class(outcome: &Value) -> Option<&str> {
    outcome.pointer("/error/class").and_then(Value::as_str)
}

pub(super) fn required_object<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{label}: {field} must be an object"))
}

pub(super) fn required_str<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: {field} must be a string"))
}

pub(super) fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{label}: {field} must be a nonnegative integer"))
}

pub(super) fn string_array<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<Vec<&'a str>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: {field} must be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("{label}: {field} contains a non-string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{reconcile_native_windows_outcomes, required_str, runtime_negative_control};

    #[test]
    fn missing_fields_and_mutated_provenance_fail() {
        assert!(required_str(&json!({}), "id", "test").is_err());
        let outcome = json!({"go_version":"go1.26", "platform":"linux/amd64"});
        runtime_negative_control(&outcome, "go1.26", "linux/amd64").unwrap();
    }

    #[test]
    fn native_windows_reconciliation_changes_only_the_recorded_message() {
        let committed = vec![
            json!({"id":"same", "error":null}),
            json!({"id":"template-missing-path", "error":{"class":"template", "message":"portable"}}),
        ];
        let windows = vec![
            committed[0].clone(),
            json!({"id":"template-missing-path", "error":{"class":"template", "message":"windows"}}),
        ];
        reconcile_native_windows_outcomes(&committed, &windows).unwrap();

        let mut changed_class = windows.clone();
        changed_class[1]["error"]["class"] = json!("changed");
        assert!(reconcile_native_windows_outcomes(&committed, &changed_class).is_err());

        let unexpected = vec![
            json!({"id":"same", "error":{"message":"unexpected"}}),
            windows[1].clone(),
        ];
        assert!(reconcile_native_windows_outcomes(&committed, &unexpected).is_err());
    }
}
