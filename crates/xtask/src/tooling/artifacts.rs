//! Exact generated-artifact tree writing and check-only comparison.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

#[derive(Default)]
pub(crate) struct GeneratedTree {
    files: BTreeMap<PathBuf, Vec<u8>>,
}

#[derive(Clone, Copy)]
pub(crate) struct OutcomeBaseline<'a> {
    pub(crate) values: &'a [Value],
    pub(crate) bytes: &'a [u8],
}

impl GeneratedTree {
    pub(crate) fn insert(
        &mut self,
        relative: impl Into<PathBuf>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<(), String> {
        let relative = relative.into();
        validate_relative(&relative)?;
        if self.files.insert(relative.clone(), bytes.into()).is_some() {
            return Err(format!(
                "generated artifact was inserted twice: {}",
                relative.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn write_or_check(&self, root: &Path, check: bool) -> Result<(), String> {
        if check {
            return self.check(root);
        }
        fs::create_dir_all(root).map_err(|error| {
            format!(
                "cannot create generated artifact root {}: {error}",
                root.display()
            )
        })?;
        self.validate_file_set(root, false)?;
        for (relative, bytes) in &self.files {
            let destination = root.join(relative);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "cannot create artifact directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            fs::write(&destination, bytes).map_err(|error| {
                format!(
                    "cannot write generated artifact {}: {error}",
                    destination.display()
                )
            })?;
        }
        Ok(())
    }

    fn check(&self, root: &Path) -> Result<(), String> {
        self.validate_file_set(root, true)?;
        for (relative, expected) in &self.files {
            let path = root.join(relative);
            let actual = fs::read(&path).map_err(|error| {
                format!("cannot read generated artifact {}: {error}", path.display())
            })?;
            if actual != *expected {
                let offset = expected
                    .iter()
                    .zip(&actual)
                    .position(|(left, right)| left != right)
                    .unwrap_or(expected.len().min(actual.len()));
                return Err(format!(
                    "generated artifact {} differs at byte {offset}: expected {} bytes, got {}",
                    path.display(),
                    expected.len(),
                    actual.len()
                ));
            }
        }
        Ok(())
    }

    fn validate_file_set(&self, root: &Path, require_all: bool) -> Result<(), String> {
        let expected = self.files.keys().cloned().collect::<BTreeSet<_>>();
        let actual = if root.exists() {
            artifact_paths(root)?
        } else {
            BTreeSet::new()
        };
        if let Some(extra) = actual.difference(&expected).next() {
            return Err(format!(
                "unexpected generated artifact: {}",
                root.join(extra).display()
            ));
        }
        if require_all {
            if let Some(missing) = expected.difference(&actual).next() {
                if root.exists() {
                    return Err(format!(
                        "missing generated artifact: {}",
                        root.join(missing).display()
                    ));
                }
                if !self.files.is_empty() {
                    return Err(format!(
                        "missing generated artifact root: {}",
                        root.display()
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn compare_json_outcomes(
    committed: &[Value],
    observed: &[Value],
    ignored_provenance: &[&str],
    label: &str,
) -> Result<(), String> {
    if committed.len() != observed.len() {
        return Err(format!(
            "{label} outcome count changed: expected {}, got {}",
            committed.len(),
            observed.len()
        ));
    }
    for (index, (committed, observed)) in committed.iter().zip(observed).enumerate() {
        let committed_id = outcome_id(committed, label, index)?;
        let observed_id = outcome_id(observed, label, index)?;
        if committed_id != observed_id {
            return Err(format!(
                "{label} outcome order changed at record {}: expected {committed_id}, got {observed_id}",
                index + 1
            ));
        }
        let mut committed = committed.clone();
        let mut observed = observed.clone();
        for field in ignored_provenance {
            remove_provenance(&mut committed, field, label, committed_id)?;
            remove_provenance(&mut observed, field, label, observed_id)?;
        }
        if committed != observed {
            let path = first_json_difference(&committed, &observed, "")
                .unwrap_or_else(|| "<unknown>".to_owned());
            return Err(format!(
                "fresh {label} outcome {observed_id} differs from the committed semantic outcome at {path}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn first_json_difference(
    expected: &Value,
    actual: &Value,
    path: &str,
) -> Option<String> {
    match (expected, actual) {
        (Value::Array(expected), Value::Array(actual)) => {
            for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                let child = format!("{path}/{index}");
                if let Some(difference) = first_json_difference(expected, actual, &child) {
                    return Some(difference);
                }
            }
            (expected.len() != actual.len()).then(|| format!("{path}/length"))
        }
        (Value::Object(expected), Value::Object(actual)) => {
            let keys = expected
                .keys()
                .chain(actual.keys())
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            for key in keys {
                let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (expected.get(key), actual.get(key)) {
                    (Some(expected), Some(actual)) => {
                        if let Some(difference) = first_json_difference(expected, actual, &child) {
                            return Some(difference);
                        }
                    }
                    _ => return Some(child),
                }
            }
            None
        }
        _ => (expected != actual).then(|| {
            if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            }
        }),
    }
}

fn outcome_id<'a>(value: &'a Value, label: &str, index: usize) -> Result<&'a str, String> {
    value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} outcome record {} has no string id", index + 1))
}

fn remove_provenance(value: &mut Value, field: &str, label: &str, id: &str) -> Result<(), String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| format!("{label} outcome {id} is not an object"))?;
    if !object.remove(field).is_some_and(|value| value.is_string()) {
        return Err(format!(
            "{label} outcome {id} has no string {field} provenance"
        ));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "generated artifact path must be a nonempty relative path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn artifact_paths(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    fn visit(root: &Path, directory: &Path, output: &mut BTreeSet<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(directory).map_err(|error| {
            format!(
                "cannot read artifact directory {}: {error}",
                directory.display()
            )
        })? {
            let entry = entry.map_err(|error| {
                format!(
                    "cannot read artifact entry in {}: {error}",
                    directory.display()
                )
            })?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            if kind.is_dir() {
                visit(root, &entry.path(), output)?;
            } else if kind.is_file() || kind.is_symlink() {
                output.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|error| format!("cannot relativize artifact path: {error}"))?
                        .to_owned(),
                );
            } else {
                return Err(format!(
                    "unsupported generated artifact type: {}",
                    entry.path().display()
                ));
            }
        }
        Ok(())
    }

    let mut output = BTreeSet::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::{GeneratedTree, compare_json_outcomes};
    use crate::tooling::support::TempDir;

    #[test]
    fn exact_tree_handles_spaces_unicode_and_binary_bytes() {
        let temporary = TempDir::new("artifacts ü").unwrap();
        let root = temporary.path.join("output dir ü");
        let mut tree = GeneratedTree::default();
        tree.insert("nested dir ü/data.bin", [0, 255, 10]).unwrap();
        tree.insert("README.md", b"exact\n".to_vec()).unwrap();
        tree.write_or_check(&root, false).unwrap();
        tree.write_or_check(&root, true).unwrap();
        assert_eq!(
            fs::read(root.join("nested dir ü/data.bin")).unwrap(),
            [0, 255, 10]
        );
    }

    #[test]
    fn exact_tree_rejects_stale_missing_extra_and_unsafe_paths() {
        let temporary = TempDir::new("artifact-negative").unwrap();
        let root = temporary.path.join("output");
        let mut tree = GeneratedTree::default();
        tree.insert("expected", b"value".to_vec()).unwrap();
        assert!(tree.write_or_check(&root, true).is_err());
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("expected"), b"stale").unwrap();
        assert!(tree.write_or_check(&root, true).is_err());
        fs::write(root.join("expected"), b"value").unwrap();
        fs::write(root.join("extra"), b"extra").unwrap();
        assert!(tree.write_or_check(&root, true).is_err());
        assert!(tree.insert("../escape", b"bad".to_vec()).is_err());
        assert!(tree.insert("/absolute", b"bad".to_vec()).is_err());
    }

    #[test]
    fn semantic_outcomes_ignore_only_named_provenance() {
        let committed = [json!({
            "id": "case",
            "platform": "darwin/arm64",
            "ordered": ["first", "second"],
            "result": {"value": 1}
        })];
        let observed = [json!({
            "result": {"value": 1},
            "ordered": ["first", "second"],
            "platform": "linux/amd64",
            "id": "case"
        })];
        compare_json_outcomes(&committed, &observed, &["platform"], "test").unwrap();

        let reordered = [json!({
            "id": "case",
            "platform": "linux/amd64",
            "ordered": ["second", "first"],
            "result": {"value": 1}
        })];
        let error =
            compare_json_outcomes(&committed, &reordered, &["platform"], "test").unwrap_err();
        assert!(error.ends_with("at /ordered/0"));

        let changed = [json!({
            "id": "case",
            "platform": "linux/amd64",
            "ordered": ["first", "second"],
            "result": {"value": 2}
        })];
        assert!(compare_json_outcomes(&committed, &changed, &["platform"], "test").is_err());
        assert!(compare_json_outcomes(&committed, &observed, &["missing"], "test").is_err());
    }
}
