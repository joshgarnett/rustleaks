use std::collections::BTreeSet;

use super::model::{FixturePayload, Inventory};
use super::records::{json_string, json_strings, required, section_records};

pub(super) fn verify(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    verify_packages(inventory, manifest)?;
    verify_test_files(inventory, manifest)?;
    verify_cases(inventory, manifest)?;
    verify_benchmarks(inventory, manifest)?;
    verify_constructors(inventory, manifest)?;
    verify_fixtures(inventory, manifest)?;
    Ok(())
}

fn verify_packages(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    let actual = section_records(manifest, "api_package")
        .into_iter()
        .map(|row| {
            Ok((
                json_string(required(&row, "name", "api_package")?, "api_package name")?,
                json_string(
                    required(&row, "mapping_id", "api_package")?,
                    "api_package mapping_id",
                )?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expected = inventory
        .packages
        .iter()
        .map(|name| (name.clone(), "API-ALL-001".into()))
        .collect::<Vec<_>>();
    exact("api_package", &expected, &actual)
}

fn verify_test_files(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    let actual = section_records(manifest, "test_file")
        .into_iter()
        .map(|row| {
            let path = json_string(required(&row, "path", "test_file")?, "test_file path")?;
            let count = required(&row, "active_top_level", &path)?
                .parse::<usize>()
                .map_err(|error| format!("invalid active_top_level for {path}: {error}"))?;
            let tests = json_strings(
                required(&row, "top_level_names", &path)?,
                &format!("{path} top_level_names"),
            )?;
            let benchmarks = json_strings(
                required(&row, "benchmark_names", &path)?,
                &format!("{path} benchmark_names"),
            )?;
            Ok((path, count, tests, benchmarks))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let expected = inventory
        .test_files
        .iter()
        .map(|file| {
            (
                file.path.clone(),
                file.tests.len(),
                file.tests.clone(),
                file.benchmarks.clone(),
            )
        })
        .collect::<Vec<_>>();
    exact("test_file", &expected, &actual)
}

fn verify_cases(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    let actual = section_records(manifest, "case");
    if actual.len() != inventory.events.len() {
        return Err(format!(
            "case identity count mismatch: expected {}, got {}",
            inventory.events.len(),
            actual.len()
        ));
    }
    for (index, (event, row)) in inventory.events.iter().zip(actual).enumerate() {
        let id = format!("TM-{:04}", index + 1);
        let root = event
            .name
            .split('/')
            .next()
            .expect("split always yields one item");
        let location = inventory
            .tests
            .get(root)
            .ok_or_else(|| format!("test event {} has no top-level source", event.name))?;
        let platform = if matches!(root, "TestFromGit" | "TestDetectWithSymlinks") {
            "not-windows"
        } else {
            "all"
        };
        for (key, expected) in [
            ("id", id.as_str()),
            ("package", event.package.as_str()),
            ("go_name", event.name.as_str()),
            ("source", location.path.as_str()),
            ("platform", platform),
        ] {
            let found = json_string(required(&row, key, &id)?, &format!("{id} {key}"))?;
            if found != expected {
                return Err(format!(
                    "case {id} {key} mismatch: expected {expected:?}, got {found:?}"
                ));
            }
        }
        let line = required(&row, "source_line", &id)?
            .parse::<usize>()
            .map_err(|error| format!("invalid {id} source_line: {error}"))?;
        if line != location.line {
            return Err(format!(
                "case {id} source_line mismatch: expected {}, got {line}",
                location.line
            ));
        }
        let top_level = required(&row, "top_level", &id)?;
        if top_level != if event.name == root { "true" } else { "false" } {
            return Err(format!("case {id} top_level mismatch"));
        }
        if json_strings(
            required(&row, "behavior_ids", &id)?,
            &format!("{id} behavior_ids"),
        )?
        .is_empty()
        {
            return Err(format!("case {id} has no behavior_ids"));
        }
        let expected_skip = match (event.name.as_str(), root) {
            ("TestFromGit", "TestFromGit") => Some(
                "TODO: this fails on Windows: [git] fatal: bad object refs/remotes/origin/main?",
            ),
            ("TestDetectWithSymlinks", "TestDetectWithSymlinks") => {
                Some("TODO: this returns no results on windows, I'm not sure why.")
            }
            _ => None,
        };
        let found_skip = row
            .get("platform_skip_reason")
            .map(|raw| json_string(raw, &format!("{id} platform_skip_reason")))
            .transpose()?;
        if found_skip.as_deref() != expected_skip {
            return Err(format!("case {id} platform_skip_reason mismatch"));
        }
    }
    Ok(())
}

fn verify_benchmarks(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    let actual = section_records(manifest, "benchmark");
    if actual.len() != inventory.benchmarks.len() {
        return Err(format!(
            "benchmark count mismatch: expected {}, got {}",
            inventory.benchmarks.len(),
            actual.len()
        ));
    }
    for (index, ((name, location), row)) in inventory.benchmarks.iter().zip(actual).enumerate() {
        let id = format!("BM-{:04}", index + 1);
        for (key, expected) in [
            ("id", id.as_str()),
            ("go_name", name.as_str()),
            ("source", location.path.as_str()),
            ("disposition", "port-workload-record-separate-go-baseline"),
        ] {
            let found = json_string(required(&row, key, &id)?, &format!("{id} {key}"))?;
            if found != expected {
                return Err(format!("benchmark {id} {key} mismatch"));
            }
        }
        if required(&row, "source_line", &id)?.parse::<usize>().ok() != Some(location.line) {
            return Err(format!("benchmark {id} source_line mismatch"));
        }
    }
    Ok(())
}

fn verify_constructors(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    let actual = section_records(manifest, "generator_constructor");
    if actual.len() != inventory.constructors.len() {
        return Err(format!(
            "generator_constructor count mismatch: expected {}, got {}",
            inventory.constructors.len(),
            actual.len()
        ));
    }
    for (index, (expected, row)) in inventory.constructors.iter().zip(actual).enumerate() {
        let id = format!("GEN-{:04}", index + 1);
        let disposition = if expected.selected {
            "selected-default"
        } else {
            "excluded-by-upstream-default"
        };
        for (key, value) in [
            ("id", id.as_str()),
            ("name", expected.name.as_str()),
            ("source", expected.source.path.as_str()),
            ("disposition", disposition),
            ("helper", expected.helper.as_str()),
            ("rule_id", expected.rule_id.as_str()),
            (
                "sample_inventory",
                "compat/generator-corpus/constructors-v1.jsonl",
            ),
        ] {
            let found = json_string(required(&row, key, &id)?, &format!("{id} {key}"))?;
            if found != value {
                return Err(format!(
                    "generator_constructor {id} {key} mismatch: expected {value:?}, got {found:?}"
                ));
            }
        }
        if required(&row, "source_line", &id)?.parse::<usize>().ok() != Some(expected.source.line) {
            return Err(format!("generator_constructor {id} source_line mismatch"));
        }
    }
    Ok(())
}

fn verify_fixtures(inventory: &Inventory, manifest: &str) -> Result<(), String> {
    let actual = section_records(manifest, "fixture");
    if actual.len() != inventory.fixtures.len() {
        return Err(format!(
            "fixture count mismatch: expected {}, got {}",
            inventory.fixtures.len(),
            actual.len()
        ));
    }
    for (index, (expected, row)) in inventory.fixtures.iter().zip(actual).enumerate() {
        let id = format!("FIX-{:04}", index + 1);
        let kind = if matches!(expected.payload, FixturePayload::Regular { .. }) {
            "regular"
        } else {
            "symlink"
        };
        for (key, value) in [
            ("id", id.as_str()),
            ("source", expected.path.as_str()),
            ("kind", kind),
            ("mode", expected.mode.as_str()),
            (
                "rust_location",
                format!("compat/fixtures/upstream/{}", expected.path).as_str(),
            ),
            ("provenance", "Gitleaks MIT; pinned upstream testdata"),
            ("asset_status", "copied-verified"),
            ("verification", "cargo xtask fixture-check"),
        ] {
            let found = json_string(required(&row, key, &id)?, &format!("{id} {key}"))?;
            if found != value {
                return Err(format!(
                    "fixture {id} {key} mismatch: expected {value:?}, got {found:?}"
                ));
            }
        }
        let consumers = json_strings(
            required(&row, "consumers", &id)?,
            &format!("{id} consumers"),
        )?;
        if consumers != fixture_consumers(&expected.path) {
            return Err(format!("fixture {id} consumers mismatch"));
        }
        match &expected.payload {
            FixturePayload::Regular { size, sha256 } => {
                if required(&row, "size", &id)?.parse::<u64>().ok() != Some(*size) {
                    return Err(format!("fixture {id} size mismatch"));
                }
                if json_string(required(&row, "sha256", &id)?, &format!("{id} sha256"))? != *sha256
                {
                    return Err(format!("fixture {id} sha256 mismatch"));
                }
                if row.contains_key("symlink_target") {
                    return Err(format!("regular fixture {id} has symlink_target"));
                }
            }
            FixturePayload::Symlink { target } => {
                if json_string(
                    required(&row, "symlink_target", &id)?,
                    &format!("{id} symlink_target"),
                )? != *target
                {
                    return Err(format!("fixture {id} symlink target mismatch"));
                }
                if row.contains_key("size") || row.contains_key("sha256") {
                    return Err(format!("symlink fixture {id} has regular payload fields"));
                }
            }
        }
    }
    Ok(())
}

fn fixture_consumers(path: &str) -> Vec<String> {
    let values: &[&str] = if path.starts_with("testdata/archives/") {
        &["detect/TestDetectWithArchives", "source/archive"]
    } else if path.starts_with("testdata/baseline/") {
        &[
            "detect/TestFileLoadBaseline",
            "detect/TestIgnoreIssuesInBaseline",
        ]
    } else if path.starts_with("testdata/config/") {
        &["config tests", "detect custom-config tests", "regex corpus"]
    } else if path.starts_with("testdata/expected/git/") {
        &["detect/TestFromGit", "sources disabled Git intentions"]
    } else if path.starts_with("testdata/expected/report/") {
        &["report golden tests"]
    } else if path.starts_with("testdata/gitleaksignore/") {
        &["detect/TestNormalizeGitleaksIgnorePaths"]
    } else if path.starts_with("testdata/report/") {
        &["report/TestWriteTemplate"]
    } else if path.starts_with("testdata/repos/archives/") {
        &["detect/TestFromGit archives"]
    } else if path.starts_with("testdata/repos/nogit/") {
        &["detect/TestFromFiles"]
    } else if path.starts_with("testdata/repos/small/") {
        &["detect/TestFromGit", "sources disabled Git intentions"]
    } else if path.starts_with("testdata/repos/staged/") {
        &["detect/TestFromGitStaged"]
    } else if path.starts_with("testdata/repos/symlinks/") {
        &["detect/TestDetectWithSymlinks"]
    } else {
        &["inventory review required"]
    };
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn exact<T: std::fmt::Debug + PartialEq>(
    label: &str,
    expected: &[T],
    actual: &[T],
) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    let expected_set = expected
        .iter()
        .map(|value| format!("{value:?}"))
        .collect::<BTreeSet<_>>();
    let actual_set = actual
        .iter()
        .map(|value| format!("{value:?}"))
        .collect::<BTreeSet<_>>();
    Err(format!(
        "{label} identity mismatch\nmissing: {}\nunexpected: {}",
        expected_set
            .difference(&actual_set)
            .next()
            .map_or("<none>", String::as_str),
        actual_set
            .difference(&expected_set)
            .next()
            .map_or("<none>", String::as_str)
    ))
}
