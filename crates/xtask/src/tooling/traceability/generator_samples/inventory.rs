//! Pinned checkout verification and constructor-source inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use super::{CONFIG_SHA256, REVISION, process};

const EXCLUSIONS: [(&str, &str); 3] = [
    (
        "GCPServiceAccount",
        "excluded-default; helper fails: escaped keyword does not occur in positive sample",
    ),
    (
        "SquareSecret",
        "excluded-default; helper passes when invoked independently",
    ),
    (
        "TrelloAccessToken",
        "excluded-default; helper passes when invoked independently",
    ),
];
const GAPS: [(&str, &str); 2] = [
    (
        "DropBoxLongLivedAPIToken",
        "selected-default; validate TODO returns rule without helper",
    ),
    (
        "DropBoxShortLivedAPIToken",
        "selected-default; validate TODO returns rule without helper",
    ),
];

pub(super) fn verify_upstream(upstream: &Path) -> Result<(), String> {
    if !upstream.is_dir() {
        return Err(format!("missing upstream checkout: {}", upstream.display()));
    }
    let revision = process::capture(
        Command::new("git")
            .current_dir(upstream)
            .args(["rev-parse", "HEAD"]),
        "git revision",
        Duration::from_secs(30),
    )?;
    if revision != REVISION {
        return Err(format!(
            "upstream revision mismatch: expected {REVISION}, got {revision}"
        ));
    }
    let config = upstream.join("config/gitleaks.toml");
    let digest = crate::tooling::support::sha256_file(&config)?;
    if digest != CONFIG_SHA256 {
        return Err(format!(
            "upstream config hash mismatch: expected {CONFIG_SHA256}, got {digest}"
        ));
    }
    let status = process::capture(
        Command::new("git").current_dir(upstream).args([
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            "cmd/generate",
            "config/gitleaks.toml",
        ]),
        "git status",
        Duration::from_secs(30),
    )?;
    if !status.is_empty() {
        return Err("tracked generator/config changes exist in read-only upstream checkout".into());
    }
    Ok(())
}

pub(super) fn build(upstream: &Path) -> Result<Vec<Value>, String> {
    let mut records = source_records(upstream)?;
    let selected = selected_names(upstream)?;
    if selected.len() != 222 {
        return Err(format!(
            "expected 222 selected constructors, got {}",
            selected.len()
        ));
    }
    if selected.iter().collect::<BTreeSet<_>>().len() != selected.len() {
        return Err("selected constructor names are not unique".into());
    }
    let by_name: BTreeMap<_, _> = records
        .iter()
        .enumerate()
        .map(|(index, row)| Ok((super::json::string(row, "constructor")?.to_owned(), index)))
        .collect::<Result<_, String>>()?;
    let missing: Vec<_> = selected
        .iter()
        .filter(|name| !by_name.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "selected constructors missing from source inventory: {}",
            missing
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    verify_config_ids(upstream, &selected, &records, &by_name)?;
    let selected_set: BTreeSet<_> = selected.into_iter().collect();
    for row in &mut records {
        decorate(row, &selected_set)?;
    }
    records.sort_by(|left, right| {
        super::json::string(left, "constructor")
            .unwrap_or_default()
            .cmp(super::json::string(right, "constructor").unwrap_or_default())
    });
    Ok(records)
}

fn source_records(upstream: &Path) -> Result<Vec<Value>, String> {
    let directory = upstream.join("cmd/generate/config/rules");
    let mut paths: Vec<PathBuf> = fs::read_dir(&directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .map(|entry| {
            entry
                .map(|value| value.path())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<_, _>>()?;
    paths.retain(|path| path.extension().is_some_and(|extension| extension == "go"));
    paths.sort();
    let mut output = Vec::new();
    for path in paths {
        output.extend(records_from_file(upstream, &path)?);
    }
    Ok(output)
}

fn records_from_file(upstream: &Path, path: &Path) -> Result<Vec<Value>, String> {
    let source =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let text = std::str::from_utf8(&source)
        .map_err(|error| format!("{} is not UTF-8: {error}", path.display()))?;
    let starts = constructor_starts(text);
    let relative = path
        .strip_prefix(upstream)
        .map_err(|error| error.to_string())?
        .to_string_lossy()
        .replace('\\', "/");
    let mut records = Vec::new();
    for (index, (start, name)) in starts.iter().enumerate() {
        let end = starts.get(index + 1).map_or(source.len(), |next| next.0);
        let body = &source[*start..end];
        let body_text = &text[*start..end];
        let (helper, helper_offset) = find_helper(body_text);
        let rule_id =
            literal_rule_id(body_text).ok_or_else(|| format!("{name} has no literal RuleID"))?;
        let constructor_line = line_at(&source, *start);
        let helper_line =
            helper_offset.map(|offset| constructor_line + newline_count(&body[..offset]));
        records.push(json!({
            "schema_version": 1, "record_type": "generator_constructor",
            "upstream_revision": REVISION, "constructor": name, "rule_id": rule_id,
            "source_file": relative, "constructor_line": constructor_line,
            "helper_line": helper_line, "helper": helper,
            "constructor_source_sha256": crate::tooling::support::sha256_bytes(body)
        }));
    }
    Ok(records)
}

fn constructor_starts(source: &str) -> Vec<(usize, String)> {
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("func ") {
            if let Some(name) = rest
                .strip_suffix("() *config.Rule {\n")
                .or_else(|| rest.strip_suffix("() *config.Rule {"))
            {
                if name.starts_with(|character: char| character.is_ascii_uppercase())
                    && name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    starts.push((offset, name.to_owned()));
                }
            }
        }
        offset += line.len();
    }
    starts
}

fn find_helper(body: &str) -> (&'static str, Option<usize>) {
    for (needle, helper) in [
        ("return utils.ValidateWithPaths(", "validate_with_paths"),
        ("return utils.Validate(", "validate"),
    ] {
        if let Some(index) = body.find(needle) {
            return (helper, Some(index));
        }
    }
    ("none", None)
}

fn literal_rule_id(body: &str) -> Option<&str> {
    let tail = body.split_once("RuleID:")?.1.trim_start();
    let quoted = tail.strip_prefix('"')?;
    Some(quoted.split_once('"')?.0)
}

fn line_at(source: &[u8], offset: usize) -> usize {
    newline_count(&source[..offset]) + 1
}

fn newline_count(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut remaining = bytes;
    while let Some(index) = remaining.iter().position(|byte| *byte == b'\n') {
        count += 1;
        remaining = &remaining[index + 1..];
    }
    count
}

fn selected_names(upstream: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(upstream.join("cmd/generate/config/main.go"))
        .map_err(|error| format!("cannot read generator main: {error}"))?;
    Ok(text
        .lines()
        .filter_map(|line| {
            if line.trim_start().starts_with("//") {
                return None;
            }
            let trimmed = line.trim_start().strip_prefix("rules.")?;
            let name = trimmed.strip_suffix("(),")?;
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| name.to_owned())
        })
        .collect())
}

fn verify_config_ids(
    upstream: &Path,
    selected: &[String],
    records: &[Value],
    by_name: &BTreeMap<String, usize>,
) -> Result<(), String> {
    let config = fs::read_to_string(upstream.join("config/gitleaks.toml"))
        .map_err(|e| format!("cannot read config: {e}"))?;
    let mut config_ids: Vec<_> = config
        .lines()
        .filter_map(|line| {
            line.strip_prefix("id = \"")?
                .strip_suffix('"')
                .map(str::to_owned)
        })
        .collect();
    if config_ids.len() != 222 {
        return Err(format!(
            "expected 222 generated config RuleIDs, got {}",
            config_ids.len()
        ));
    }
    let mut selected_ids = selected
        .iter()
        .map(|name| super::json::string(&records[by_name[name]], "rule_id").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    selected_ids.sort();
    config_ids.sort();
    if selected_ids != config_ids {
        return Err("selected constructor RuleIDs differ from generated config".into());
    }
    Ok(())
}

fn decorate(row: &mut Value, selected: &BTreeSet<String>) -> Result<(), String> {
    let name = super::json::string(row, "constructor")?.to_owned();
    let is_selected = selected.contains(&name);
    let helper_covered = is_selected && super::json::string(row, "helper")? != "none";
    let (disposition, exception): (&str, Option<&str>) =
        if let Some((_, reason)) = EXCLUSIONS.iter().find(|(value, _)| *value == name) {
            ("excluded_default", Some(*reason))
        } else if let Some((_, reason)) = GAPS.iter().find(|(value, _)| *value == name) {
            ("selected_gap", Some(*reason))
        } else if is_selected {
            ("selected_helper", None)
        } else {
            ("unexpected_exclusion", None)
        };
    let object = row
        .as_object_mut()
        .ok_or("constructor row is not an object")?;
    object.insert("selected_default".into(), Value::Bool(is_selected));
    object.insert("helper_covered".into(), Value::Bool(helper_covered));
    object.insert("disposition".into(), Value::String(disposition.into()));
    object.insert(
        "exception".into(),
        exception.map_or(Value::Null, |value| Value::String(value.into())),
    );
    Ok(())
}
