//! Material behavior and negative controls retained from the legacy generator.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

use super::validation::{outcome_for, required_array, required_str};

const COMPARED: &[&str] = &[
    "rule-id",
    "description",
    "start-line",
    "end-line",
    "start-column",
    "end-column",
    "match",
    "secret",
    "file",
    "commit",
    "author",
    "email",
    "date",
    "message",
    "entropy",
];
const IGNORED: &[&str] = &[
    "line",
    "symlink",
    "link",
    "tags",
    "fingerprint",
    "fragment",
    "required-findings",
];

pub(super) fn validate(
    outcomes: &BTreeMap<&str, &Value>,
    coverage: &Value,
    _negative: &Value,
) -> Result<(), String> {
    validate_ignore(outcomes)?;
    validate_baseline(outcomes)?;
    validate_collection(outcomes)?;
    validate_assertion_metadata(coverage)
}

fn validate_ignore(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let fingerprints = required_array(
        outcome_for(outcomes, "fingerprints-global-and-commit")?,
        "collected_findings",
        "fingerprints",
    )?
    .iter()
    .map(|finding| decoded(finding, "fingerprint_base64", "fingerprint"))
    .collect::<Result<Vec<_>, _>>()?;
    if fingerprints
        != [
            b"commit-a:dir/file.txt:rule:7".as_slice(),
            b"dir/file.txt:rule:7".as_slice(),
            b"commit-b:dir/file.txt:rule:7".as_slice(),
        ]
    {
        return Err("exact global and commit fingerprints changed".into());
    }
    let windows = ignore_entries(outcomes, "upstream-normalize-window-paths")?;
    if windows
        != [
            b"b55d88dc151f7022901cda41a03d43e0e508f2b7:test_data/test_local_repo_three_leaks.json:aws-access-token:73".as_slice(),
            b"foo/bar/gitleaks-false-positive.yaml:aws-access-token:4".as_slice(),
            b"foo/bar/gitleaks-false-positive.yaml:aws-access-token:5".as_slice(),
        ]
    {
        return Err("upstream Windows-path normalization changed".into());
    }
    let malformed = ignore_entries(outcomes, "ignore-comments-invalid-duplicates")?;
    if malformed
        != [
            b"foo/bar.txt:rule:7".as_slice(),
            b"invalid".as_slice(),
            b"too:many:colon:fields:here".as_slice(),
        ]
    {
        return Err("ignore comments, invalid entries, or duplicate collapse changed".into());
    }
    assert_decisions(outcomes, "ignore-global-before-commit", &["ignored-global"])?;
    assert_baseline_is_new(outcomes, "ignore-global-before-commit", 0, false)?;
    assert_decisions(
        outcomes,
        "ignore-commit-exact-and-near-misses",
        &["ignored-commit", "accepted", "accepted"],
    )?;
    assert_baseline_is_new(outcomes, "ignore-commit-exact-and-near-misses", 0, false)?;
    assert_decisions(
        outcomes,
        "ignore-slash-positive-backslash-negative",
        &["ignored-global", "accepted"],
    )?;
    assert_decisions(
        outcomes,
        "ignore-explicit-drive-colon-bytes",
        &["ignored-global"],
    )
}

fn validate_baseline(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    for id in ["baseline-valid-empty", "baseline-valid-null"] {
        if outcome_for(outcomes, id)?
            .pointer("/baseline/loaded")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(format!("{id}: valid baseline did not load"));
        }
    }
    for (id, count) in [
        ("baseline-upstream-json-fixture", 2),
        ("baseline-preserves-duplicates-order", 2),
    ] {
        if outcome_for(outcomes, id)?
            .pointer("/baseline/findings")
            .and_then(Value::as_array)
            .map(Vec::len)
            != Some(count)
        {
            return Err(format!("{id}: baseline finding count changed"));
        }
    }
    let folded = outcome_for(outcomes, "baseline-unicode-folded-keys")?
        .pointer("/baseline/findings/0")
        .ok_or("folded baseline finding is missing")?;
    if decoded(folded, "description_base64", "folded description")? != b"folded"
        || decoded(folded, "link_base64", "folded link")? != b"kelvin"
    {
        return Err("baseline Unicode simple-fold keys changed".into());
    }
    assert_decisions(outcomes, "baseline-equal", &["ignored-baseline"])?;
    for field in COMPARED {
        assert_decisions(
            outcomes,
            &format!("baseline-compared-{field}"),
            &["accepted"],
        )?;
    }
    for field in IGNORED {
        assert_decisions(
            outcomes,
            &format!("baseline-ignored-{field}"),
            &["ignored-baseline"],
        )?;
    }
    assert_decisions(
        outcomes,
        "baseline-redaction-disabled-near-negative",
        &["accepted"],
    )?;
    assert_decisions(
        outcomes,
        "baseline-redaction-enabled",
        &["ignored-baseline"],
    )?;
    assert_decisions(
        outcomes,
        "upstream-redacted-different-baseline",
        &["accepted"],
    )
}

fn validate_collection(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let ordered = outcome_for(outcomes, "collection-order-duplicates-canonical")?;
    let collected = required_array(ordered, "collected_findings", "collection order")?;
    let collected_rules = collected
        .iter()
        .map(|finding| required_str(finding, "rule_id", "finding"))
        .collect::<Result<Vec<_>, _>>()?;
    if collected_rules != ["z-rule", "a-rule", "a-rule", "m-rule"]
        || collected.get(1) != collected.get(2)
    {
        return Err("collection order or duplicate preservation changed".into());
    }
    let canonical_rules = required_array(ordered, "canonical_findings", "canonical order")?
        .iter()
        .map(|finding| required_str(finding, "rule_id", "finding"))
        .collect::<Result<Vec<_>, _>>()?;
    if canonical_rules != ["a-rule", "a-rule", "m-rule", "z-rule"]
        || decoded(
            &required_array(ordered, "input_findings", "input findings")?[0],
            "fingerprint_base64",
            "input fingerprint",
        )? != b"caller-stale"
        || decoded(
            &required_array(ordered, "collected_findings", "collected findings")?[0],
            "fingerprint_base64",
            "collected fingerprint",
        )? != b"z.txt:z-rule:9"
    {
        return Err("canonical order or fingerprint mutation changed".into());
    }
    let sort = outcome_for(outcomes, "canonical-sort-full-projection-inputs")?;
    let files = required_array(sort, "canonical_findings", "canonical sort")?
        .iter()
        .map(|finding| decoded(finding, "file_base64", "canonical file"))
        .collect::<Result<Vec<_>, _>>()?;
    if files != [b"a.txt".as_slice(), b"z.txt".as_slice()] {
        return Err("complete-projection canonical sort changed".into());
    }
    Ok(())
}

fn validate_assertion_metadata(coverage: &Value) -> Result<(), String> {
    let expected = expected_assertions();
    let rows = required_array(coverage, "material_assertions", "coverage")?;
    if rows.len() != expected.len() {
        return Err("material assertion group inventory changed".into());
    }
    for (row, (number, names)) in rows.iter().zip(expected) {
        let actual = required_array(row, "assertions", "material assertions")?
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>();
        if row.get("number").and_then(Value::as_u64) != Some(number) || actual != Some(names) {
            return Err(format!("material assertion group {number} changed"));
        }
    }
    Ok(())
}

fn expected_assertions() -> Vec<(u64, Vec<String>)> {
    let mut compared = COMPARED
        .iter()
        .map(|field| format!("compared-field-{field}"))
        .collect::<Vec<_>>();
    compared.push("exact-equality-suppresses".into());
    let ignored = IGNORED
        .iter()
        .map(|field| format!("ignored-field-{field}"))
        .collect::<Vec<_>>();
    vec![
        (1, vec!["exact-global-and-commit-fingerprints".into()]),
        (2, vec!["exact-upstream-windows-normalization".into()]),
        (3, vec!["comments-blanks-invalid-and-duplicates".into()]),
        (4, vec!["ignore-precedence-and-near-misses".into()]),
        (
            5,
            vec![
                "baseline-load-and-error-classes".into(),
                "baseline-unicode-simple-fold-keys".into(),
                "baseline-float32-overflow-rejected".into(),
            ],
        ),
        (6, compared),
        (7, ignored),
        (8, vec!["redaction-match-secret-only".into()]),
        (9, vec!["collection-order-and-duplicates".into()]),
        (10, vec!["canonical-sort-and-fingerprint-mutation".into()]),
    ]
}

fn ignore_entries(outcomes: &BTreeMap<&str, &Value>, id: &str) -> Result<Vec<Vec<u8>>, String> {
    outcome_for(outcomes, id)?
        .pointer("/ignore/entries_base64")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{id}: ignore entries are missing"))?
        .iter()
        .map(|value| {
            BASE64
                .decode(
                    value
                        .as_str()
                        .ok_or_else(|| format!("{id}: non-string ignore entry"))?,
                )
                .map_err(|error| format!("{id}: invalid ignore entry base64: {error}"))
        })
        .collect()
}

fn assert_decisions(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    expected: &[&str],
) -> Result<(), String> {
    let actual = required_array(outcome_for(outcomes, id)?, "decisions", id)?
        .iter()
        .map(|decision| required_str(decision, "disposition", id))
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        return Err(format!("{id}: decisions changed"));
    }
    Ok(())
}

fn assert_baseline_is_new(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    index: usize,
    expected: bool,
) -> Result<(), String> {
    if outcome_for(outcomes, id)?
        .pointer(&format!("/decisions/{index}/baseline_is_new"))
        .and_then(Value::as_bool)
        != Some(expected)
    {
        return Err(format!("{id}: baseline decision changed"));
    }
    Ok(())
}

fn decoded(value: &Value, field: &str, label: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(required_str(value, field, label)?)
        .map_err(|error| format!("{label}: invalid {field}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::expected_assertions;

    #[test]
    fn material_assertion_inventory_remains_complete() {
        let groups = expected_assertions();
        assert_eq!(groups.len(), 10);
        assert_eq!(
            groups.iter().map(|(_, names)| names.len()).sum::<usize>(),
            33
        );
    }
}
