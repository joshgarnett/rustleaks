//! Exact Rust observation checks against immutable historical expectations.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Map, Value, json};

use super::observe::Observed;
use super::{newline_records, spec};
use crate::tooling::presentation::{self, Disposition, Field};
use crate::tooling::support::sha256_bytes;

pub(super) struct Variant {
    pub(super) case_id: String,
    pub(super) id: String,
    pub(super) request: Value,
    pub(super) expected: Value,
}

pub(super) fn bind_expected(requests: &[Value], bytes: &[u8]) -> Result<Vec<Variant>, String> {
    let outcomes = newline_records(bytes, "CLI outcomes")?
        .into_iter()
        .map(|line| serde_json::from_slice::<Value>(line).map_err(|_| "invalid CLI outcome JSON"))
        .collect::<Result<Vec<_>, _>>()?;
    if outcomes.len() != requests.len() {
        return Err("CLI request/outcome case counts differ".into());
    }
    let mut result = Vec::new();
    let mut identities = BTreeSet::new();
    for (request, outcome) in requests.iter().zip(&outcomes) {
        let case_id = required_str(request, "id", "CLI request")?;
        if outcome["id"] != request["id"] || outcome["title"] != request["title"] {
            return Err(format!("{case_id}: outcome identity or title changed"));
        }
        let variants = required_array(request, "variants", case_id)?;
        let expected = required_array(outcome, "variants", case_id)?;
        if variants.len() != expected.len() {
            return Err(format!("{case_id}: outcome variant count changed"));
        }
        for (variant, frozen) in variants.iter().zip(expected) {
            let id = required_str(variant, "id", case_id)?;
            let label = format!("{case_id}/{id}");
            if frozen["id"] != variant["id"] || !identities.insert(label.clone()) {
                return Err(format!("{label}: missing, duplicate or reordered outcome"));
            }
            let observation = frozen
                .get("rust")
                .ok_or_else(|| format!("{label}: missing Rust observation"))?;
            if required_str(observation, "implementation", &label)? != "rust" {
                return Err(format!("{label}: expected implementation changed"));
            }
            result.push(Variant {
                case_id: case_id.into(),
                id: label,
                request: variant.clone(),
                expected: observation.clone(),
            });
        }
    }
    if result.len() != spec::VARIANT_COUNT {
        return Err("CLI observation identity total changed".into());
    }
    Ok(result)
}

pub(super) fn inapplicable(request: &Value, windows: bool, linux: bool) -> Option<&'static str> {
    if request
        .pointer("/expectation/linux_only")
        .and_then(Value::as_bool)
        == Some(true)
        && !linux
    {
        Some("requires native Linux byte paths")
    } else if windows
        && (request
            .pointer("/expectation/unix_only")
            .and_then(Value::as_bool)
            == Some(true)
            || request["id"] == "windows-logical-name")
    {
        Some("requires a Unix filename unavailable on Windows")
    } else {
        None
    }
}

pub(super) fn native_disposition(id: &str, windows: bool) -> Option<&'static str> {
    if !windows {
        return None;
    }
    match id {
        "CLI-BB-013/outside-baseline" => Some("CLI-NATIVE-WINDOWS-001"),
        "CLI-BB-030/corrupt-archive-and-broken-symlink" => Some("CLI-NATIVE-WINDOWS-002"),
        _ => None,
    }
}

// Keep historical build metadata frozen; derive only these release-specific
// expectations and the Rustleaks report tool identity from trusted build
// metadata or the frozen corpus, never from the observed binary output.
pub(super) fn current_build_expectation(
    id: &str,
    frozen: &Value,
    build_version: &str,
) -> Result<(Value, Option<&'static str>), String> {
    let mut expected = frozen.clone();
    let marker = match id {
        "CLI-BB-001/version-command"
        | "CLI-BB-001/version-flag"
        | "CLI-BB-001/version-persistent-flag" => {
            let prefix = if id == "CLI-BB-001/version-flag" {
                "gitleaks version "
            } else {
                ""
            };
            let historical = format!("{prefix}{}\n", spec::BUILD_VERSION);
            if frozen["stdout_base64"] != BASE64.encode(&historical)
                || frozen["stdout_bytes"] != json!(historical.len())
                || frozen["stdout_sha256"] != sha256_bytes(historical.as_bytes())
            {
                return Err(format!("{id}: historical CLI version output changed"));
            }
            let current = format!("{prefix}{build_version}\n");
            expected["stdout_base64"] = json!(BASE64.encode(&current));
            expected["stdout_bytes"] = json!(current.len());
            expected["stdout_sha256"] = json!(sha256_bytes(current.as_bytes()));
            Some("stdout-current-build-version")
        }
        id if presentation::REMOVED_FIRST_EVENT_VARIANTS.contains(&id) => {
            let historical = json!({
                "severity": "warn", "class": "config.error", "fields": {},
                "normalized_message_base64": BASE64.encode(historical_build_version_warning())
            });
            if frozen
                .get("stderr_events")
                .and_then(Value::as_array)
                .and_then(|events| events.first())
                != Some(&historical)
            {
                return Err(format!("{id}: historical CLI build warning changed"));
            }
            // The historical build compared the embedded config's minVersion
            // with its own crate version. The current build compares it with
            // the implemented Gitleaks version, which satisfies it, so the
            // warning is not printed.
            expected["stderr_events"]
                .as_array_mut()
                .ok_or_else(|| format!("{id}: stderr_events is not an array"))?
                .remove(0);
            Some("embedded-config-min-version-satisfied")
        }
        id if REPORT_TOOL_IDENTITY_VARIANTS.contains(&id) => {
            let sarif = id.ends_with("sarif");
            // The replay spells Rustleaks names in stdout as `gitleaks`, as it
            // does for every other stdout comparison. Report files keep the
            // spelling that Rustleaks writes.
            let (base64_key, bytes_key, sha_key, holder, legacy) = if frozen["report"].is_object() {
                (
                    "bytes_base64",
                    "bytes",
                    "sha256",
                    &mut expected["report"],
                    false,
                )
            } else {
                (
                    "stdout_base64",
                    "stdout_bytes",
                    "stdout_sha256",
                    &mut expected,
                    true,
                )
            };
            let historical = holder[base64_key]
                .as_str()
                .and_then(|text| BASE64.decode(text).ok())
                .ok_or_else(|| format!("{id}: frozen report bytes are missing"))?;
            let current =
                with_rustleaks_tool_identity(id, &historical, sarif, build_version, legacy)?;
            holder[base64_key] = json!(BASE64.encode(&current));
            holder[bytes_key] = json!(current.len());
            holder[sha_key] = json!(sha256_bytes(&current));
            Some("report-rustleaks-tool-identity")
        }
        _ => None,
    };
    Ok((expected, marker))
}

/// Variants whose frozen SARIF or `JUnit` report names the tool `gitleaks`.
/// `CLI-BB-021/junit` is not listed: its report is on stdout, where the
/// replay spells the `rustleaks` suite name as `gitleaks`.
const REPORT_TOOL_IDENTITY_VARIANTS: &[&str] = &[
    "CLI-BB-021/sarif",
    "CLI-BB-022/result.sarif",
    "CLI-BB-034/junit",
    "CLI-BB-034/sarif",
];

/// Replaces the one historical tool identity in a frozen report with the
/// Rustleaks name, version and repository. Every other byte stays frozen.
/// With `legacy`, the name is spelled `gitleaks` as in other stdout
/// comparisons.
fn with_rustleaks_tool_identity(
    id: &str,
    historical: &[u8],
    sarif: bool,
    build_version: &str,
    legacy: bool,
) -> Result<Vec<u8>, String> {
    let name = if legacy { "gitleaks" } else { "rustleaks" };
    let (old, new) = if sarif {
        (
            concat!(
                "     \"name\": \"gitleaks\",\n",
                "     \"semanticVersion\": \"v8.0.0\",\n",
                "     \"informationUri\": \"https://github.com/gitleaks/gitleaks\",\n",
            )
            .to_owned(),
            format!(
                concat!(
                    "     \"name\": \"{name}\",\n",
                    "     \"semanticVersion\": \"{version}\",\n",
                    "     \"informationUri\": \"https://github.com/joshgarnett/{name}\",\n",
                ),
                name = name,
                version = build_version
            ),
        )
    } else {
        (
            " name=\"gitleaks\" ".to_owned(),
            format!(" name=\"{name}\" "),
        )
    };
    let old = old.as_bytes();
    let mut starts = historical
        .windows(old.len())
        .enumerate()
        .filter(|(_, window)| *window == old)
        .map(|(start, _)| start);
    let (Some(start), None) = (starts.next(), starts.next()) else {
        return Err(format!("{id}: frozen report tool identity changed"));
    };
    let mut current = historical[..start].to_vec();
    current.extend_from_slice(new.as_bytes());
    current.extend_from_slice(&historical[start + old.len()..]);
    Ok(current)
}

fn historical_build_version_warning() -> String {
    format!(
        "config requires a newer Gitleaks version... required=v8.25.0 current={} config path=<embedded-default>",
        spec::BUILD_VERSION
    )
}

/// Compares one observation with its frozen expectation and returns the IDs of
/// the presentation dispositions it used.
///
/// Each disposition requires the native text of its field to equal the
/// reviewed text exactly and the legacy projection of that field to differ
/// from the frozen corpus, so a disposition is never a no-op. Only that field
/// is then removed from the legacy projection on both sides, and every
/// remaining field must match exactly. The ledger check rejects dispositions
/// for variants with native platform expectations before replay.
pub(super) fn compare(
    id: &str,
    actual: &Observed,
    frozen: &Value,
    windows: bool,
    dispositions: &[&Disposition],
) -> Result<Vec<String>, String> {
    let mut expected = expected_observations(id, frozen, windows)?;
    if dispositions.is_empty() {
        exact(id, &actual.value, &expected)?;
        return Ok(Vec::new());
    }
    let mut observed = actual.value.clone();
    let mut messages = actual.native.messages.clone();
    // Remove the usage block first so event indices refer to frozen events
    // outside it, whatever the length of the new usage text.
    let mut frozen_usage = None;
    if let Some(disposition) = dispositions
        .iter()
        .find(|disposition| disposition.field == Field::StderrUsage)
    {
        require_native(id, disposition, actual.native.usage.as_deref())?;
        require_changed(id, disposition, &observed, &expected, "/stderr_usage")?;
        let range = actual
            .native
            .usage_events
            .clone()
            .ok_or_else(|| format!("{id}: Rust usage block has no stderr events"))?;
        if messages.len() < range.end {
            return Err(format!("{id}: Rust usage events are out of range"));
        }
        messages.drain(range.clone());
        remove_usage(&mut observed, range)?;
        for value in &mut expected {
            let range = presentation::usage_event_range(value, id)?
                .ok_or_else(|| format!("{id}: frozen observation has no usage block"))?;
            remove_usage(value, range.clone())?;
            frozen_usage = Some(range);
        }
    }
    let mut used = Vec::new();
    for disposition in dispositions {
        if disposition.variant != id {
            return Err(format!(
                "{id}: disposition {} is for another variant",
                disposition.id
            ));
        }
        match disposition.field {
            Field::Stdout => {
                require_native(id, disposition, Some(actual.native.stdout.as_slice()))?;
                require_changed(id, disposition, &observed, &expected, "/stdout_base64")?;
                for value in std::iter::once(&mut observed).chain(&mut expected) {
                    for key in ["stdout_base64", "stdout_bytes", "stdout_sha256"] {
                        value[key] = Value::Null;
                    }
                }
            }
            Field::StderrUsage => {}
            Field::StderrEventMessage(frozen_index) => {
                // Event indices name frozen events. The replay removes the
                // first frozen event of some variants before comparison.
                let frozen_index = if presentation::REMOVED_FIRST_EVENT_VARIANTS.contains(&id) {
                    frozen_index.checked_sub(1).ok_or_else(|| {
                        format!(
                            "{id}: disposition {} targets a removed event",
                            disposition.id
                        )
                    })?
                } else {
                    frozen_index
                };
                let index = match &frozen_usage {
                    Some(range) if range.contains(&frozen_index) => {
                        return Err(format!(
                            "{id}: disposition {} targets a usage event",
                            disposition.id
                        ));
                    }
                    Some(range) if frozen_index >= range.end => frozen_index - range.len(),
                    _ => frozen_index,
                };
                require_native(id, disposition, messages.get(index).map(Vec::as_slice))?;
                let pointer = format!("/stderr_events/{index}/normalized_message_base64");
                require_changed(id, disposition, &observed, &expected, &pointer)?;
                for value in std::iter::once(&mut observed).chain(&mut expected) {
                    mask_message(value, index);
                }
            }
        }
        used.push(disposition.id.clone());
    }
    exact(id, &observed, &expected)?;
    Ok(used)
}

fn require_changed(
    id: &str,
    disposition: &Disposition,
    observed: &Value,
    expected: &[Value],
    pointer: &str,
) -> Result<(), String> {
    let actual = observed.pointer(pointer);
    if expected
        .iter()
        .any(|value| value.pointer(pointer) == actual)
    {
        Err(format!(
            "{id}: disposition {} is stale because the Rust output still matches the frozen corpus",
            disposition.id
        ))
    } else {
        Ok(())
    }
}

fn require_native(
    id: &str,
    disposition: &Disposition,
    native: Option<&[u8]>,
) -> Result<(), String> {
    if native == Some(disposition.expected.as_bytes()) {
        Ok(())
    } else {
        // Report the disposition, never captured output.
        Err(format!(
            "{id}: Rust presentation differs from reviewed disposition {}",
            disposition.id
        ))
    }
}

fn remove_usage(value: &mut Value, range: std::ops::Range<usize>) -> Result<(), String> {
    value["stderr_usage"] = Value::Null;
    let events = value["stderr_events"]
        .as_array_mut()
        .ok_or("CLI observation stderr_events is not an array")?;
    if events.len() < range.end {
        return Err("CLI usage events are out of range".into());
    }
    events.drain(range);
    Ok(())
}

/// Removes one event message, and the message digest that only the
/// unclassified diagnostic class records. Severity, class and every other
/// event field stay compared.
fn mask_message(value: &mut Value, index: usize) {
    if let Some(event) = value
        .get_mut("stderr_events")
        .and_then(|events| events.get_mut(index))
    {
        if event["class"] == "diagnostic.other"
            && let Some(fields) = event.get_mut("fields").and_then(Value::as_object_mut)
        {
            fields.remove("message_sha256");
        }
        event["normalized_message_base64"] = Value::Null;
    }
}

fn exact(id: &str, actual: &Value, expected: &[Value]) -> Result<(), String> {
    if expected.contains(actual) {
        return Ok(());
    }
    // Report field names, never finding values, paths or captured output.
    let fields = actual
        .as_object()
        .ok_or("CLI observation is not an object")?
        .keys()
        .chain(
            expected[0]
                .as_object()
                .ok_or("CLI expectation is not an object")?
                .keys(),
        )
        .filter(|key| actual.get(*key) != expected[0].get(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    Err(format!(
        "{id}: Rust observation differs in {}",
        fields.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

fn expected_observations(id: &str, frozen: &Value, windows: bool) -> Result<Vec<Value>, String> {
    match native_disposition(id, windows) {
        Some("CLI-NATIVE-WINDOWS-001") => windows_baseline(frozen),
        Some("CLI-NATIVE-WINDOWS-002") => {
            let mut expected = frozen.clone();
            let events = expected["stderr_events"]
                .as_array_mut()
                .ok_or("missing issue events")?;
            if events.len() != 4
                || events[0]["normalized_message_base64"] != BASE64.encode(b"source Decode/Decode scan/bad.gz: invalid gzip header")
                || events[1]["normalized_message_base64"] != BASE64.encode(b"source Symlink/DanglingSymlink scan/broken-link: <os:not-found> (os error 2)") {
                return Err("historical CLI issue fixture changed".into());
            }
            // The Windows fixture cannot create the dangling symlink. Its
            // remaining physical file path is rendered with the native separator.
            events.remove(1);
            events[0]["normalized_message_base64"] =
                json!(BASE64.encode(b"source Decode/Decode scan\\bad.gz: invalid gzip header"));
            Ok(vec![expected])
        }
        None => Ok(vec![frozen.clone()]),
        Some(other) => Err(format!("unknown CLI native disposition {other}")),
    }
}

fn windows_baseline(frozen: &Value) -> Result<Vec<Value>, String> {
    let mut expected = frozen.clone();
    let findings = expected["findings"]
        .as_array_mut()
        .ok_or("missing baseline findings")?;
    if findings.len() != 1 || findings[0]["File"] != "secret.txt" {
        return Err("historical CLI baseline fixture changed".into());
    }
    // The Windows source spelling prevents excluding other/baseline.json.
    // Its synthetic contents are [{"Extra":"token=AB12"}] followed by LF.
    // The second token begins at byte 11, hence columns 12 through 21.
    let mut extra = findings[0].clone();
    extra["File"] = json!("other/baseline.json");
    extra["Fingerprint"] = json!("other/baseline.json:fixture-token:1");
    extra["StartColumn"] = json!(12);
    extra["EndColumn"] = json!(21);
    findings.push(extra);
    let findings_bytes =
        serde_json::to_vec(findings).map_err(|_| "cannot encode baseline expectation")?;
    if sha256_bytes(&findings_bytes)
        != "5c47e6a449ce6e905ae112eef094907de2e1af89e1409e2d86fb6e7cf367c90d"
    {
        return Err(
            "independent Windows finding expectation disagrees with historical ledger".into(),
        );
    }
    expected["finding_count"] = json!(2);
    expected["stderr_events"][1] = json!({
        "severity": "warn", "class": "summary.findings", "fields": {"count": 2},
        "normalized_message_base64": BASE64.encode(b"leaks found: 2")
    });
    let report = BASE64
        .decode(required_str(
            &frozen["report"],
            "bytes_base64",
            "baseline report",
        )?)
        .map_err(|_| "invalid historical report bytes")?;
    let text =
        std::str::from_utf8(&report).map_err(|_| "historical baseline report is not UTF-8")?;
    let first = text
        .strip_prefix("[\n")
        .and_then(|body| body.strip_suffix("\n]\n"))
        .ok_or("historical baseline report framing changed")?;
    let mut second = first.to_owned();
    for (from, to) in [
        ("\"StartColumn\": 1,", "\"StartColumn\": 12,"),
        ("\"EndColumn\": 10,", "\"EndColumn\": 21,"),
        (
            "\"File\": \"secret.txt\"",
            "\"File\": \"other/baseline.json\"",
        ),
        (
            "\"Fingerprint\": \"secret.txt:fixture-token:1\"",
            "\"Fingerprint\": \"other/baseline.json:fixture-token:1\"",
        ),
    ] {
        if second.matches(from).count() != 1 {
            return Err("historical baseline report field changed".into());
        }
        second = second.replacen(from, to, 1);
    }
    // Only the two complete finding orders are permitted. Every byte in each
    // object, report framing and all remaining observation fields stay exact.
    [
        format!("[\n{first},\n{second}\n]\n"),
        format!("[\n{second},\n{first}\n]\n"),
    ]
    .into_iter()
    .map(|report| {
        if report.len() != 796 {
            return Err("Windows report extent changed".into());
        }
        let mut alternative = expected.clone();
        alternative["report"] = json!({
            "state": "present", "bytes_base64": BASE64.encode(report.as_bytes()),
            "bytes": report.len(), "sha256": sha256_bytes(report.as_bytes())
        });
        Ok(alternative)
    })
    .collect()
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
    use super::super::observe::NativePresentation;
    use super::*;
    use crate::tooling::presentation::FrozenVariant;
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    fn fixture() -> (Vec<Value>, Vec<Variant>, Vec<u8>) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let requests = std::fs::read(root.join("requests-v1.jsonl")).unwrap();
        let rows = newline_records(&requests, "requests")
            .unwrap()
            .into_iter()
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect::<Vec<Value>>();
        let bytes = std::fs::read(root.join("outcomes-v1.jsonl")).unwrap();
        let variants = bind_expected(&rows, &bytes).unwrap();
        (rows, variants, bytes)
    }

    fn observed(value: &Value) -> Observed {
        Observed {
            value: value.clone(),
            native: NativePresentation::default(),
        }
    }

    fn compare_frozen(
        id: &str,
        actual: &Value,
        frozen: &Value,
        windows: bool,
    ) -> Result<(), String> {
        let used = compare(id, &observed(actual), frozen, windows, &[])?;
        assert!(used.is_empty());
        Ok(())
    }

    fn set_stdout(observation: &mut Value, bytes: &[u8]) {
        observation["stdout_base64"] = json!(BASE64.encode(bytes));
        observation["stdout_bytes"] = json!(bytes.len());
        observation["stdout_sha256"] = json!(sha256_bytes(bytes));
    }

    #[test]
    fn version_stdout_requires_the_current_build_and_exact_framing() {
        let (_, variants, _) = fixture();
        for (build_version, plain, qualified) in [
            (
                "0.1.0-alpha.6",
                "0.1.0-alpha.6\n",
                "gitleaks version 0.1.0-alpha.6\n",
            ),
            (
                "12.34.56-rc.789+review",
                "12.34.56-rc.789+review\n",
                "gitleaks version 12.34.56-rc.789+review\n",
            ),
        ] {
            for id in [
                "CLI-BB-001/version-command",
                "CLI-BB-001/version-flag",
                "CLI-BB-001/version-persistent-flag",
            ] {
                let frozen = &variants
                    .iter()
                    .find(|variant| variant.id == id)
                    .unwrap()
                    .expected;
                let original = frozen.clone();
                let (expected, marker) =
                    current_build_expectation(id, frozen, build_version).unwrap();
                assert_eq!(marker, Some("stdout-current-build-version"));
                let stdout = if id.ends_with("/version-flag") {
                    qualified
                } else {
                    plain
                };
                let mut actual = frozen.clone();
                set_stdout(&mut actual, stdout.as_bytes());
                assert_eq!(actual, expected);
                compare_frozen(id, &actual, &expected, false).unwrap();
                assert!(
                    compare_frozen(id, frozen, &expected, false).is_err(),
                    "stale build: {id}"
                );
                for invalid in [
                    stdout.trim_end_matches('\n').to_owned(),
                    format!(" {stdout}"),
                    format!("{stdout}\n"),
                    format!("{stdout}unexpected output\n"),
                    stdout.replace(build_version, "99.0.0-wrong"),
                ] {
                    set_stdout(&mut actual, invalid.as_bytes());
                    assert!(
                        compare_frozen(id, &actual, &expected, false).is_err(),
                        "{id}"
                    );
                }
                for field in ["stdout_base64", "stdout_bytes", "stdout_sha256"] {
                    let mut changed = frozen.clone();
                    changed[field] = Value::Null;
                    assert!(current_build_expectation(id, &changed, build_version).is_err());
                }
                assert_eq!(*frozen, original);
            }
        }
    }

    #[test]
    fn satisfied_embedded_min_version_removes_only_the_historical_warning() {
        let (_, variants, _) = fixture();
        let index = frozen_index(&variants);
        let historical = "config requires a newer Gitleaks version... required=v8.25.0 current=0.1.0-alpha.5 config path=<embedded-default>";
        let current = "config minVersion v8.25.0 is newer than Gitleaks 8.30.0, the newest configuration version that Rustleaks supports, so some settings may not be supported; config path=<embedded-default>";
        for id in [
            "CLI-BB-007/file-embedded",
            "CLI-BB-007/directory-embedded-empty",
        ] {
            let variant = variants.iter().find(|variant| variant.id == id).unwrap();
            let frozen = &variant.expected;
            let frozen_events = frozen["stderr_events"].as_array().unwrap();
            assert_eq!(
                frozen_events[0],
                json!({"severity": "warn", "class": "config.error", "fields": {},
                    "normalized_message_base64": BASE64.encode(historical)})
            );
            let (expected, marker) =
                current_build_expectation(id, frozen, "12.34.56-rc.789+review").unwrap();
            assert_eq!(marker, Some("embedded-config-min-version-satisfied"));
            // The projection does not depend on the current build version.
            assert_eq!(
                current_build_expectation(id, frozen, "0.1.0-alpha.9").unwrap(),
                (expected.clone(), marker)
            );
            let mut actual = frozen.clone();
            actual["stderr_events"] = json!(frozen_events[1..].to_vec());
            assert_eq!(actual, expected);
            compare_frozen(id, &actual, &expected, false).unwrap();
            // The historical warning, or any reworded warning, is a regression.
            assert!(compare_frozen(id, frozen, &expected, false).is_err());
            for message in [historical, current] {
                let mut warned = actual.clone();
                warned["stderr_events"].as_array_mut().unwrap().insert(
                    0,
                    json!({"severity": "warn", "class": "config.error", "fields": {},
                        "normalized_message_base64": BASE64.encode(message)}),
                );
                assert!(compare_frozen(id, &warned, &expected, false).is_err());
            }
            for field in ["severity", "class", "fields", "normalized_message_base64"] {
                let mut changed = frozen.clone();
                changed["stderr_events"][0][field] = Value::Null;
                assert!(current_build_expectation(id, &changed, "12.34.56-rc.789+review").is_err());
            }
            for malformed in [
                Value::Null,
                json!({"0": frozen["stderr_events"][0]}),
                json!([]),
            ] {
                let mut changed = frozen.clone();
                changed["stderr_events"] = malformed;
                assert!(current_build_expectation(id, &changed, "12.34.56-rc.789+review").is_err());
            }
            for field in [
                "exit",
                "report",
                "findings",
                "finding_count",
                "child_reaped",
            ] {
                let mut changed = expected.clone();
                changed[field] = json!({"mutation": true});
                assert!(compare_frozen(id, &changed, &expected, false).is_err());
            }

            // A message disposition names a later event by its frozen index.
            let later = synthetic("SYN-LATER", variant, Field::StderrEventMessage(1));
            presentation::validate_dispositions(std::slice::from_ref(&later), &index).unwrap();
            let mut shifted = presented(frozen, std::slice::from_ref(&later));
            shifted.value["stderr_events"]
                .as_array_mut()
                .unwrap()
                .remove(0);
            shifted.native.messages.remove(0);
            let used = compare(id, &shifted, &expected, false, &[&later]).unwrap();
            assert_eq!(used, ["SYN-LATER"]);
            assert!(compare(id, &shifted, &expected, false, &[]).is_err());
            let removed = synthetic("SYN-REMOVED", variant, Field::StderrEventMessage(0));
            assert!(
                presentation::validate_dispositions(std::slice::from_ref(&removed), &index)
                    .is_err()
            );
            assert!(compare(id, &observed(&actual), &expected, false, &[&removed]).is_err());
        }
    }

    #[test]
    fn report_tool_identity_changes_only_the_tool_identity() {
        let (_, variants, _) = fixture();
        for id in REPORT_TOOL_IDENTITY_VARIANTS {
            let frozen = &variants
                .iter()
                .find(|variant| variant.id == *id)
                .unwrap()
                .expected;
            let (expected, marker) =
                current_build_expectation(id, frozen, "12.34.56-rc.789+review").unwrap();
            assert_eq!(marker, Some("report-rustleaks-tool-identity"));
            let (holder, key) = if frozen["report"].is_object() {
                ("/report", "bytes_base64")
            } else {
                ("", "stdout_base64")
            };
            let decode = |value: &Value| {
                let text = value.pointer(holder).unwrap()[key].as_str().unwrap();
                String::from_utf8(BASE64.decode(text).unwrap()).unwrap()
            };
            let (before, after) = (decode(frozen), decode(&expected));
            let name = if holder.is_empty() {
                "gitleaks"
            } else {
                "rustleaks"
            };
            if id.ends_with("sarif") {
                assert!(before.contains("\"semanticVersion\": \"v8.0.0\""), "{id}");
                assert!(
                    after.contains(&format!(
                        "     \"name\": \"{name}\",\n     \"semanticVersion\": \"12.34.56-rc.789+review\",\n     \"informationUri\": \"https://github.com/joshgarnett/{name}\",\n"
                    )),
                    "{id}: {after}"
                );
            } else {
                assert!(after.contains(" name=\"rustleaks\" "), "{id}: {after}");
            }
            if !holder.is_empty() {
                assert!(!after.contains("gitleaks"), "{id}: {after}");
            }
            // Everything outside the tool identity is unchanged.
            let prefix = before
                .bytes()
                .zip(after.bytes())
                .take_while(|(old, new)| old == new)
                .count();
            let suffix = before
                .bytes()
                .rev()
                .zip(after.bytes().rev())
                .take_while(|(old, new)| old == new)
                .count();
            let identity = if id.ends_with("sarif") {
                "     \"name\": \"gitleaks\",\n     \"semanticVersion\": \"v8.0.0\",\n     \"informationUri\": \"https://github.com/gitleaks/gitleaks\",\n"
            } else {
                " name=\"gitleaks\" "
            };
            let start = before.find(identity).unwrap();
            assert!(prefix >= start, "{id}");
            assert!(before.len() - suffix <= start + identity.len(), "{id}");
            let mut tampered = frozen.clone();
            tampered.pointer_mut(holder).unwrap()[key] = json!(BASE64.encode("{}"));
            assert!(
                current_build_expectation(id, &tampered, "1.0.0").is_err(),
                "{id}"
            );
        }
    }

    #[test]
    fn unrelated_observations_are_not_projected_for_release_versions() {
        let (_, variants, _) = fixture();
        let mut projected = 0;
        for variant in variants {
            let (expected, marker) =
                current_build_expectation(&variant.id, &variant.expected, "12.34.56-rc.789+review")
                    .unwrap();
            if marker.is_some() {
                projected += 1;
                continue;
            }
            assert_eq!(expected, variant.expected);
            compare_frozen(&variant.id, &variant.expected, &expected, false).unwrap();
            let mut changed = variant.expected.clone();
            set_stdout(&mut changed, b"12.34.56-rc.789+review\n");
            assert!(compare_frozen(&variant.id, &changed, &expected, false).is_err());
        }
        assert_eq!(projected, 5 + REPORT_TOOL_IDENTITY_VARIANTS.len());
    }

    #[test]
    fn missing_swapped_and_duplicate_identities_are_rejected() {
        use std::fmt::Write as _;

        let (rows, _, bytes) = fixture();
        let mut outcomes = newline_records(&bytes, "outcomes")
            .unwrap()
            .into_iter()
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        outcomes[0]["variants"].as_array_mut().unwrap().swap(0, 1);
        let encode = |rows: &[Value]| {
            rows.iter().fold(String::new(), |mut output, row| {
                writeln!(output, "{row}").unwrap();
                output
            })
        };
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes()).is_err());
        outcomes.swap(0, 1);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes()).is_err());
        outcomes.remove(0);
        assert!(bind_expected(&rows, encode(&outcomes).as_bytes()).is_err());
        let mut duplicated = rows.clone();
        duplicated[0]["variants"][1] = duplicated[0]["variants"][0].clone();
        assert!(bind_expected(&duplicated, &bytes).is_err());
    }

    #[test]
    fn all_declared_material_mutations_fail_exact_comparison() {
        let (_, variants, _) = fixture();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let controls: Value =
            serde_json::from_slice(&std::fs::read(root.join("negative-controls-v1.json")).unwrap())
                .unwrap();
        for control in controls["controls"].as_array().unwrap() {
            let id = format!(
                "{}/{}",
                control["case_id"].as_str().unwrap(),
                control["variant_id"].as_str().unwrap()
            );
            let frozen = &variants
                .iter()
                .find(|variant| variant.id == id)
                .unwrap()
                .expected;
            compare_frozen(&id, frozen, frozen, false).unwrap();
            let mut changed = frozen.clone();
            mutate_for_control(
                control["expected_failure_class"].as_str().unwrap(),
                &mut changed,
                &variants,
            );
            assert!(
                &changed != frozen,
                "{id}: mutation did not change its observation"
            );
            assert!(
                compare_frozen(&id, &changed, frozen, false).is_err(),
                "{id}"
            );
        }
    }

    fn mutate_for_control(class: &str, changed: &mut Value, variants: &[Variant]) {
        match class {
            "selected-findings" => {
                // Selecting the matching environment config instead of the
                // explicit no-match config introduces this fixture finding.
                changed["findings"] = variants
                    .iter()
                    .find(|variant| variant.id == "CLI-BB-002/dir")
                    .unwrap()
                    .expected["findings"]
                    .clone();
            }
            "complete-findings" => {
                let removed = changed["findings"].as_array_mut().unwrap().pop();
                assert!(removed.is_some(), "no finding available to remove");
            }
            "safe-arity"
            | "stdout-format"
            | "terminal-exit"
            | "report-open-failure"
            | "persistent-grammar"
            | "shorthand-grammar"
            | "raw-template-grammar"
            | "exit" => changed["exit"] = json!(99),
            "dormant-report" | "report-before-exit" | "safe-preflight" | "report-bytes" => {
                changed["report"] = json!({"state": "mutated"});
            }
            "non-disclosure" => changed["stderr_contains_disclosure_marker"] = json!(true),
            "help-golden" => changed["stdout_base64"] = json!(BASE64.encode(b"changed help")),
            "stderr-severity" => changed["stderr_events"][0]["severity"] = json!("fatal"),
            "process-cleanup" => changed["child_reaped"] = json!(false),
            unknown => panic!("unmapped control {unknown}"),
        }
    }

    fn frozen_index(variants: &[Variant]) -> BTreeMap<String, FrozenVariant> {
        variants
            .iter()
            .map(|variant| {
                (
                    variant.id.clone(),
                    FrozenVariant {
                        help_stdout: presentation::help_stdout(&variant.request),
                        observation: variant.expected.clone(),
                    },
                )
            })
            .collect()
    }

    fn decode(value: &Value, pointer: &str) -> Vec<u8> {
        BASE64
            .decode(value.pointer(pointer).unwrap().as_str().unwrap())
            .unwrap()
    }

    fn legacy(text: &str) -> String {
        text.replace("rustleaks", "gitleaks")
            .replace("Rustleaks", "Gitleaks")
    }

    fn synthetic(id: &str, variant: &Variant, field: Field) -> Disposition {
        let frozen = &variant.expected;
        let (frozen, expected) = match field {
            Field::Stdout => (
                decode(frozen, "/stdout_base64"),
                "synthetic Rustleaks help for rustleaks\n".to_owned(),
            ),
            Field::StderrUsage => (
                decode(frozen, "/stderr_usage/bytes_base64"),
                "Usage:\n  rustleaks synthetic [flags]\n\nFlags:\n  -h, --help   show help\n"
                    .to_owned(),
            ),
            Field::StderrEventMessage(index) => (
                decode(
                    frozen,
                    &format!("/stderr_events/{index}/normalized_message_base64"),
                ),
                format!("synthetic rustleaks message {index}"),
            ),
        };
        Disposition {
            id: id.into(),
            variant: variant.id.clone(),
            field,
            frozen_sha256: sha256_bytes(&frozen),
            expected,
            reason: "Synthetic review.".into(),
        }
    }

    /// Builds what a CLI printing the reviewed text for each disposition
    /// observes, with every functional field left at its frozen value.
    fn presented(frozen: &Value, dispositions: &[Disposition]) -> Observed {
        let events = frozen["stderr_events"].as_array().unwrap();
        let mut native = NativePresentation {
            stdout: decode(frozen, "/stdout_base64"),
            usage: frozen["stderr_usage"]
                .is_object()
                .then(|| decode(frozen, "/stderr_usage/bytes_base64")),
            messages: (0..events.len())
                .map(|index| {
                    decode(
                        frozen,
                        &format!("/stderr_events/{index}/normalized_message_base64"),
                    )
                })
                .collect(),
            usage_events: presentation::usage_event_range(frozen, "frozen").unwrap(),
        };
        let mut value = frozen.clone();
        for disposition in dispositions {
            let text = legacy(&disposition.expected);
            match disposition.field {
                Field::Stdout => {
                    set_stdout(&mut value, text.as_bytes());
                    native.stdout = disposition.expected.clone().into_bytes();
                }
                Field::StderrEventMessage(index) => {
                    let event = &mut value["stderr_events"][index];
                    event["normalized_message_base64"] = json!(BASE64.encode(&text));
                    if event["class"] == "diagnostic.other" {
                        event["fields"]["message_sha256"] = json!(sha256_bytes(text.as_bytes()));
                    }
                    native.messages[index] = disposition.expected.clone().into_bytes();
                }
                Field::StderrUsage => {}
            }
        }
        if let Some(disposition) = dispositions.iter().find(|d| d.field == Field::StderrUsage) {
            let range = native.usage_events.clone().unwrap();
            let lines = disposition
                .expected
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            let replacement = lines.iter().map(|line| {
                let line = legacy(line);
                json!({"severity": "error", "class": "diagnostic.other",
                    "fields": {"message_sha256": sha256_bytes(line.as_bytes())},
                    "normalized_message_base64": BASE64.encode(&line)})
            });
            value["stderr_events"]
                .as_array_mut()
                .unwrap()
                .splice(range.clone(), replacement);
            native.messages.splice(
                range.clone(),
                lines.iter().map(|line| line.as_bytes().to_vec()),
            );
            native.usage_events = Some(range.start..range.start + lines.len());
            native.usage = Some(disposition.expected.clone().into_bytes());
            let usage = legacy(&disposition.expected).replace("Gitleaks", "gitleaks");
            value["stderr_usage"] = json!({
                "bytes_base64": BASE64.encode(&usage), "bytes": usage.len(),
                "sha256": sha256_bytes(usage.as_bytes())
            });
        }
        Observed { value, native }
    }

    #[test]
    fn presentation_disposition_pins_replacement_and_nothing_else() {
        let (_, variants, _) = fixture();
        let index = frozen_index(&variants);
        for (id, fields) in [
            ("CLI-BB-001/help", vec![Field::Stdout]),
            (
                "CLI-BB-018/following-positional",
                vec![
                    Field::StderrUsage,
                    Field::StderrEventMessage(0),
                    Field::StderrEventMessage(22),
                ],
            ),
        ] {
            let variant = variants.iter().find(|variant| variant.id == id).unwrap();
            let frozen = &variant.expected;
            let dispositions = fields
                .iter()
                .enumerate()
                .map(|(n, field)| synthetic(&format!("SYN-{n}"), variant, *field))
                .collect::<Vec<_>>();
            presentation::validate_dispositions(&dispositions, &index).unwrap();
            let refs = dispositions.iter().collect::<Vec<_>>();
            let actual = presented(frozen, &dispositions);
            assert_ne!(actual.value, *frozen);
            let used = compare(id, &actual, frozen, false, &refs).unwrap();
            assert_eq!(used.len(), dispositions.len(), "{id}");
            // Without the dispositions the new text is a regression.
            assert!(compare(id, &actual, frozen, false, &[]).is_err(), "{id}");
            // A disposition whose legacy field still matches the frozen corpus
            // is a no-op, even when the native text equals the reviewed text.
            for disposition in &dispositions {
                let mut noop = presented(frozen, std::slice::from_ref(disposition));
                noop.value = frozen.clone();
                let error = compare(id, &noop, frozen, false, &[disposition]).unwrap_err();
                assert!(error.contains("stale"), "{id}: {error}");
            }

            for (n, disposition) in dispositions.iter().enumerate() {
                // Stale: the CLI still prints the frozen text.
                let mut stale = presented(frozen, &dispositions);
                let frozen_text = synthetic("stale", variant, disposition.field);
                let native = match disposition.field {
                    Field::Stdout => decode(frozen, "/stdout_base64"),
                    Field::StderrUsage => decode(frozen, "/stderr_usage/bytes_base64"),
                    Field::StderrEventMessage(index) => decode(
                        frozen,
                        &format!("/stderr_events/{index}/normalized_message_base64"),
                    ),
                };
                assert_eq!(sha256_bytes(&native), frozen_text.frozen_sha256);
                set_native(&mut stale, frozen, disposition.field, native);
                assert!(
                    compare(id, &stale, frozen, false, &refs).is_err(),
                    "{id}: stale {n}"
                );
                // Wrong: the CLI prints text other than the reviewed text.
                let mut wrong = presented(frozen, &dispositions);
                set_native(
                    &mut wrong,
                    frozen,
                    disposition.field,
                    b"other text\n".to_vec(),
                );
                assert!(
                    compare(id, &wrong, frozen, false, &refs).is_err(),
                    "{id}: wrong {n}"
                );
            }

            assert_unrelated_fields_stay_pinned(id, &actual, frozen, &dispositions);
        }
    }

    /// Asserts that presentation dispositions do not excuse a change to any
    /// field other than the presentation text they replace.
    fn assert_unrelated_fields_stay_pinned(
        id: &str,
        actual: &Observed,
        frozen: &Value,
        dispositions: &[Disposition],
    ) {
        let refs = dispositions.iter().collect::<Vec<_>>();
        for field in [
            "implementation",
            "exit",
            "stderr_contains_disclosure_marker",
            "report",
            "findings",
            "finding_count",
            "child_reaped",
        ] {
            let mut changed = presented(frozen, dispositions);
            changed.value[field] = json!({"mutation": true});
            assert!(
                compare(id, &changed, frozen, false, &refs).is_err(),
                "{id}: {field}"
            );
        }
        let count = actual.value["stderr_events"].as_array().unwrap().len();
        for event in 0..count {
            for field in ["severity", "class", "fields"] {
                let mut changed = presented(frozen, dispositions);
                let in_usage = changed
                    .native
                    .usage_events
                    .as_ref()
                    .is_some_and(|range| range.contains(&event))
                    && refs.iter().any(|d| d.field == Field::StderrUsage);
                if in_usage {
                    continue;
                }
                changed.value["stderr_events"][event][field] = json!("mutation");
                assert!(
                    compare(id, &changed, frozen, false, &refs).is_err(),
                    "{id}: event {event} {field}"
                );
            }
        }
        let mut extra = presented(frozen, dispositions);
        extra.value["stderr_events"]
            .as_array_mut()
            .unwrap()
            .push(frozen["stderr_events"].get(0).cloned().unwrap_or(json!({})));
        assert!(
            compare(id, &extra, frozen, false, &refs).is_err(),
            "{id}: extra event"
        );
    }

    #[test]
    fn usage_disposition_replaces_the_block_as_one_unit() {
        let (_, variants, _) = fixture();
        let index = frozen_index(&variants);
        let id = "CLI-BB-003/surplus";
        let variant = variants.iter().find(|variant| variant.id == id).unwrap();
        let frozen = &variant.expected;
        let frozen_events = frozen["stderr_events"].as_array().unwrap().len();
        let frozen_usage = presentation::usage_event_range(frozen, id)
            .unwrap()
            .unwrap();
        assert_eq!(
            (frozen_usage.start, frozen_usage.end),
            (1, frozen_events - 1)
        );
        // The new usage text adds flags, so it has more lines than the frozen one.
        let mut disposition = synthetic("SYN-USAGE", variant, Field::StderrUsage);
        let added = (0..40).fold(String::new(), |mut added, n| {
            let _ = writeln!(
                added,
                "      --synthetic-{n} string   synthetic rustleaks flag {n}"
            );
            added
        });
        disposition.expected = format!("{}{added}", disposition.expected);
        presentation::validate_dispositions(std::slice::from_ref(&disposition), &index).unwrap();
        let refs = [&disposition];
        let actual = presented(frozen, std::slice::from_ref(&disposition));
        let count = actual.value["stderr_events"].as_array().unwrap().len();
        assert!(count > frozen_events);
        assert_eq!(
            compare(id, &actual, frozen, false, &refs).unwrap(),
            ["SYN-USAGE"]
        );
        // The leading Error event and the trailing fatal event stay pinned.
        for event in [0, count - 1] {
            for (field, value) in [
                ("severity", json!("warn")),
                ("class", json!("diagnostic.other")),
                ("normalized_message_base64", json!(BASE64.encode("changed"))),
            ] {
                let mut changed = presented(frozen, std::slice::from_ref(&disposition));
                changed.value["stderr_events"][event][field] = value;
                assert!(
                    compare(id, &changed, frozen, false, &refs).is_err(),
                    "event {event} {field}"
                );
            }
        }
        // An extra or missing event outside the block still fails.
        let mut extra = presented(frozen, std::slice::from_ref(&disposition));
        let events = extra.value["stderr_events"].as_array_mut().unwrap();
        events.push(events[0].clone());
        assert!(compare(id, &extra, frozen, false, &refs).is_err());
        let mut missing = presented(frozen, std::slice::from_ref(&disposition));
        missing.value["stderr_events"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert!(compare(id, &missing, frozen, false, &refs).is_err());
        // The new usage text is pinned exactly.
        let mut wrong = presented(frozen, std::slice::from_ref(&disposition));
        wrong.native.usage = Some(b"Usage:\n  rustleaks other\n".to_vec());
        assert!(compare(id, &wrong, frozen, false, &refs).is_err());
    }

    fn set_native(observed: &mut Observed, frozen: &Value, field: Field, text: Vec<u8>) {
        match field {
            Field::Stdout => observed.native.stdout = text,
            Field::StderrUsage => observed.native.usage = Some(text),
            Field::StderrEventMessage(frozen_index) => {
                // A replaced usage block before this event moves its index.
                let frozen_usage = presentation::usage_event_range(frozen, "frozen").unwrap();
                let index = match (frozen_usage, &observed.native.usage_events) {
                    (Some(old), Some(new)) if frozen_index >= old.end => {
                        frozen_index - old.len() + new.len()
                    }
                    _ => frozen_index,
                };
                observed.native.messages[index] = text;
            }
        }
    }

    #[test]
    fn negative_controls_fail_under_synthetic_dispositions() {
        let (_, variants, _) = fixture();
        let index = frozen_index(&variants);
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/cli-corpus");
        let controls: Value =
            serde_json::from_slice(&std::fs::read(root.join("negative-controls-v1.json")).unwrap())
                .unwrap();
        let mut presented_controls = 0;
        for control in controls["controls"].as_array().unwrap() {
            let id = format!(
                "{}/{}",
                control["case_id"].as_str().unwrap(),
                control["variant_id"].as_str().unwrap()
            );
            assert!(native_disposition(&id, true).is_none(), "{id}");
            let variant = variants.iter().find(|variant| variant.id == id).unwrap();
            let frozen = &variant.expected;
            let events = frozen["stderr_events"].as_array().unwrap().len();
            // Every presentation field that the ledger rules allow for this variant.
            let dispositions = [Field::Stdout, Field::StderrUsage]
                .into_iter()
                .chain((0..events).map(Field::StderrEventMessage))
                .enumerate()
                .filter_map(|(n, field)| {
                    if field == Field::StderrUsage && frozen["stderr_usage"].is_null() {
                        return None;
                    }
                    let disposition = synthetic(&format!("SYN-{n}"), variant, field);
                    presentation::validate_dispositions(std::slice::from_ref(&disposition), &index)
                        .is_ok()
                        .then_some(disposition)
                })
                .collect::<Vec<_>>();
            presentation::validate_dispositions(&dispositions, &index).unwrap();
            presented_controls += usize::from(!dispositions.is_empty());
            let refs = dispositions.iter().collect::<Vec<_>>();
            let mut actual = presented(frozen, &dispositions);
            assert_eq!(
                compare(&id, &actual, frozen, false, &refs).unwrap().len(),
                dispositions.len()
            );
            let class = control["expected_failure_class"].as_str().unwrap();
            mutate_for_control(class, &mut actual.value, &variants);
            if class == "help-golden" {
                // A changed help text changes the native text too.
                actual.native.stdout = b"changed help".to_vec();
            }
            assert!(
                compare(&id, &actual, frozen, false, &refs).is_err(),
                "{id}: {class}"
            );
        }
        assert!(presented_controls >= 19, "{presented_controls}");
    }

    #[test]
    fn ledger_lists_every_native_expectation_variant() {
        let (_, variants, _) = fixture();
        let native = variants
            .iter()
            .filter(|variant| native_disposition(&variant.id, true).is_some())
            .map(|variant| variant.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(native, presentation::NATIVE_EXPECTATION_VARIANTS);
    }

    #[test]
    fn native_expectations_preserve_every_unaffected_field() {
        let (_, variants, _) = fixture();
        for id in [
            "CLI-BB-013/outside-baseline",
            "CLI-BB-030/corrupt-archive-and-broken-symlink",
        ] {
            let frozen = &variants
                .iter()
                .find(|variant| variant.id == id)
                .unwrap()
                .expected;
            for expected in expected_observations(id, frozen, true).unwrap() {
                compare_frozen(id, &expected, frozen, true).unwrap();
                for field in expected.as_object().unwrap().keys() {
                    let mut changed = expected.clone();
                    changed[field] = json!({"mutation": true});
                    assert!(
                        compare_frozen(id, &changed, frozen, true).is_err(),
                        "{id}: {field}"
                    );
                }
            }
        }
        let outside_i32 = variants
            .iter()
            .find(|v| v.id == "CLI-BB-019/outside-i32")
            .unwrap();
        assert_eq!(outside_i32.expected["exit"], 1);
        compare_frozen(
            &outside_i32.id,
            &outside_i32.expected,
            &outside_i32.expected,
            true,
        )
        .unwrap();
        let mut changed = outside_i32.expected.clone();
        changed["exit"] = json!(-2_147_483_648_i64);
        assert!(compare_frozen(&outside_i32.id, &changed, &outside_i32.expected, true).is_err());
    }

    #[test]
    fn platform_accounting_never_calls_archived_rows_executed() {
        let (_, variants, _) = fixture();
        for (windows, linux, expected) in [(false, true, 0), (false, false, 1), (true, false, 3)] {
            assert_eq!(
                variants
                    .iter()
                    .filter(|v| inapplicable(&v.request, windows, linux).is_some())
                    .count(),
                expected
            );
        }
    }
}
