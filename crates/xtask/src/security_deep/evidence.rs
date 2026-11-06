//! Comparison evidence is not a dependency audit or an approval receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::{command, require_success};
use crate::fuzzing::{private, profiles::Deadline};
use crate::tooling::{sha256_bytes, sha256_file};

const LOCKS: &[&str] = &[
    "Cargo.lock",
    "cargo-bazel-lock.json",
    "MODULE.bazel.lock",
    "crates/rustleaks-core/fuzz/Cargo.lock",
    "crates/rustleaks-sources/fuzz/Cargo.lock",
    "crates/rustleaks-report/fuzz/Cargo.lock",
];
const POLICY: &[&str] = &[
    "deny.toml",
    "supply-chain-exceptions.toml",
    "supply-chain/config.toml",
    "supply-chain/audits.toml",
    "supply-chain/imports.lock",
    "supply-chain/inventory-v1.json",
    "docs/DEPENDENCY_SAFETY.md",
    "MODULE.bazel",
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

#[allow(clippy::too_many_lines)] // Keep each evidence source beside its validation and final record.
pub(super) fn snapshot(
    root: &Path,
    directory: &Path,
    identity: &Value,
    deadline: Deadline,
) -> Result<Value, String> {
    let locks = hashes(root, LOCKS)?;
    let policy = hashes(root, POLICY)?;
    let source = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    let lock: toml::Value = toml::from_str(&source).map_err(|_| "invalid Cargo lockfile")?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("lockfile omits packages")?;
    let mut locked_packages = BTreeMap::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or("lock package omits name")?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or("lock package omits version")?;
        let source = package
            .get("source")
            .and_then(toml::Value::as_str)
            .unwrap_or("workspace");
        let package = serde_json::to_value(package).map_err(|error| error.to_string())?;
        if locked_packages
            .insert(format!("{name}@{version} ({source})"), package)
            .is_some()
        {
            return Err("duplicate lock package identity".into());
        }
    }
    let host = identity["host"].as_str().ok_or("missing native host")?;
    let mut evidence_tools = BTreeMap::new();
    for (label, arguments) in [
        ("cargo-version", vec!["-vV".into()]),
        ("geiger-version", vec!["geiger".into(), "--version".into()]),
    ] {
        require_success(command(
            root,
            directory,
            label,
            "cargo",
            &arguments,
            deadline,
            30,
            &[],
        )?)?;
        let version = fs::read_to_string(directory.join(label).join("stdout.log"))
            .map_err(|error| error.to_string())?;
        if label == "geiger-version" && version.trim() != crate::CARGO_GEIGER_VERSION {
            return Err("unsafe inventory tool version drift".into());
        }
        evidence_tools.insert(label, version.trim().to_owned());
    }
    let arguments = [
        "metadata".into(),
        "--locked".into(),
        "--offline".into(),
        "--format-version".into(),
        "1".into(),
        "--all-features".into(),
        "--filter-platform".into(),
        host.into(),
    ];
    require_success(command(
        root,
        directory,
        "graph",
        "cargo",
        &arguments,
        deadline,
        180,
        &[],
    )?)?;
    let metadata = private::read_json(&directory.join("graph/stdout.log"))?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("Cargo metadata omits resolved graph")?;
    let identities = metadata["packages"]
        .as_array()
        .ok_or("Cargo metadata omits packages")?
        .iter()
        .map(|package| {
            let id = package["id"].as_str().ok_or("Cargo package omits id")?;
            let name = package["name"].as_str().ok_or("Cargo package omits name")?;
            let version = package["version"]
                .as_str()
                .ok_or("Cargo package omits version")?;
            Ok((
                id,
                format!(
                    "{name}@{version} ({})",
                    package["source"].as_str().unwrap_or("workspace")
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let mut graph = BTreeMap::new();
    for node in nodes {
        let id = node["id"].as_str().ok_or("Cargo node omits id")?;
        let name = identities.get(id).ok_or("unresolved Cargo node")?;
        let mut deps = Vec::new();
        for dep in node["deps"]
            .as_array()
            .ok_or("Cargo node omits dependencies")?
        {
            let target = identities
                .get(dep["pkg"].as_str().ok_or("dependency omits package id")?)
                .ok_or("unresolved Cargo dependency")?;
            deps.push(json!({"name":dep["name"],"package":target,"dep_kinds":dep["dep_kinds"]}));
        }
        graph.insert(name, json!({"features":node["features"],"deps":deps}));
    }
    let vet = private::read_json(&root.join("supply-chain/inventory-v1.json"))?;
    if vet["cargo_lock_sha256"]
        != locks
            .get("Cargo.lock")
            .ok_or("missing Cargo lock identity")?
            .as_str()
    {
        return Err("vet inventory does not identify the current lockfile".into());
    }
    let target = root.join("target/private-deep-geiger");
    let arguments = geiger_arguments(root)?;
    require_success(command(
        root,
        directory,
        "unsafe",
        "cargo",
        &arguments,
        deadline,
        600,
        &[("CARGO_TARGET_DIR", target.to_string_lossy().into_owned())],
    )?)?;
    let output = fs::read_to_string(directory.join("unsafe/stdout.log"))
        .map_err(|error| error.to_string())?;
    let report = output
        .lines()
        .rev()
        .find(|line| line.starts_with("{\"packages\":"))
        .ok_or("unsafe tool omitted its JSON inventory")?;
    let report: Value = serde_json::from_str(report).map_err(|_| "invalid unsafe inventory")?;
    if report["packages_without_metrics"]
        .as_array()
        .is_none_or(|rows| !rows.is_empty())
    {
        return Err("unsafe inventory has missing metrics".into());
    }
    let mut unsafe_packages = BTreeMap::new();
    for row in report["packages"]
        .as_array()
        .ok_or("unsafe inventory omits packages")?
    {
        let id = &row["package"]["id"];
        let name = id["name"].as_str().ok_or("unsafe package omits name")?;
        let version = id["version"]
            .as_str()
            .ok_or("unsafe package omits version")?;
        unsafe_packages.insert(format!("{name}@{version}"),json!({"used_unsafe":crate::unsafe_count(&row["unsafety"]["used"]),"forbids_unsafe":row["unsafety"]["forbids_unsafe"],"source":if id["source"].is_null() || id["source"].get("Path").is_some() {json!("workspace")} else {id["source"].clone()}}));
    }
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
        })
        .ok_or("Cargo home unavailable")?;
    let database = cargo_home.join("advisory-db");
    let arguments = [
        "-C".into(),
        database.to_string_lossy().into_owned(),
        "rev-parse".into(),
        "HEAD".into(),
    ];
    require_success(command(
        root,
        directory,
        "advisory-revision",
        "git",
        &arguments,
        deadline,
        30,
        &[],
    )?)?;
    let revision = fs::read_to_string(directory.join("advisory-revision/stdout.log"))
        .map_err(|error| error.to_string())?;
    let revision = revision.trim();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid advisory database revision".into());
    }
    Ok(
        json!({"schema_version":1,"kind":"dependency-comparison-evidence","source_identity":identity,"locks":locks,"policy":policy,"locked_packages":locked_packages,"cargo_graph":graph,"cargo_graph_scope":{"features":"all workspace features","filter_platform":host,"runtime_support_claim":false},"metadata_sha256":sha256_file(&directory.join("graph/stdout.log"))?,"declared_compile_targets":TARGETS,"vet_inventory":vet,"unsafe_packages":unsafe_packages,"unsafe_scope":"selected rustleaks-sources all-features Cargo graph; change signal, not safety proof","advisory_database":{"revision":revision,"observed":"default Cargo advisory database after the existing security gate"},"review_status":"unreviewed-comparison-evidence","evidence_tools":evidence_tools}),
    )
}

fn geiger_arguments(root: &Path) -> Result<Vec<String>, String> {
    if !root.is_absolute() {
        return Err("cargo-geiger requires an absolute workspace root".into());
    }
    let manifest = root.join("crates/rustleaks-sources/Cargo.toml");
    let manifest = manifest
        .to_str()
        .ok_or("non-UTF-8 cargo-geiger manifest path")?;
    Ok(vec![
        "geiger".into(),
        "--manifest-path".into(),
        manifest.into(),
        "--all-features".into(),
        "--locked".into(),
        "--offline".into(),
        "--output-format".into(),
        "Json".into(),
        "--quiet".into(),
    ])
}

fn hashes(root: &Path, paths: &[&str]) -> Result<BTreeMap<String, String>, String> {
    paths
        .iter()
        .map(|path| Ok(((*path).into(), sha256_file(&root.join(path))?)))
        .collect()
}

pub(super) fn compare(current: &Value, baseline: Option<&Path>) -> Result<Value, String> {
    let Some(path) = baseline else {
        return Ok(
            json!({"review_status":"unreviewed-initial","baseline":null,"reason":"no operator-selected prior snapshot; no delta audit claimed"}),
        );
    };
    let before = private::read_json(path)?;
    validate_snapshot(&before)?;
    validate_snapshot(current)?;
    let components = [
        "locks",
        "policy",
        "locked_packages",
        "cargo_graph",
        "cargo_graph_scope",
        "declared_compile_targets",
        "vet_inventory",
        "unsafe_packages",
        "advisory_database",
        "evidence_tools",
    ];
    let changed = components
        .iter()
        .filter(|name| before[**name] != current[**name])
        .copied()
        .collect::<Vec<_>>();
    let mut package_changes = BTreeMap::new();
    for component in ["locked_packages", "cargo_graph", "unsafe_packages"] {
        package_changes.insert(
            component,
            object_delta(&before[component], &current[component])?,
        );
    }
    Ok(
        json!({"review_status":if changed.is_empty(){"unchanged-comparison-only"}else{"unreviewed-delta"},"baseline_sha256":sha256_file(path)?,"baseline_source_identity":before["source_identity"],"changed_components":changed,"package_changes":package_changes,"current_snapshot_sha256":sha256_bytes(&serde_json::to_vec(current).map_err(|error|error.to_string())?),"meaning":"operator-selected comparison; neither a new audit nor approval of changed dependencies"}),
    )
}
fn validate_snapshot(value: &Value) -> Result<(), String> {
    if value["schema_version"] != 1 || value["kind"] != "dependency-comparison-evidence" {
        return Err("incompatible dependency snapshot".into());
    }
    for name in [
        "source_identity",
        "locks",
        "policy",
        "locked_packages",
        "cargo_graph",
        "cargo_graph_scope",
        "vet_inventory",
        "unsafe_packages",
        "advisory_database",
        "evidence_tools",
    ] {
        if !value[name].is_object() {
            return Err("dependency snapshot omits a required component".into());
        }
    }
    if !value["declared_compile_targets"].is_array() {
        return Err("dependency snapshot omits target scope".into());
    }
    Ok(())
}
fn object_delta(before: &Value, after: &Value) -> Result<Value, String> {
    let before = before
        .as_object()
        .ok_or("baseline component is not an object")?;
    let after = after
        .as_object()
        .ok_or("current component is not an object")?;
    let names = before.keys().chain(after.keys()).collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for name in names {
        match (before.get(name), after.get(name)) {
            (None, Some(_)) => added.push(name),
            (Some(_), None) => removed.push(name),
            (Some(left), Some(right)) if left != right => changed.push(name),
            _ => {}
        }
    }
    Ok(json!({"added":added,"removed":removed,"changed":changed}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geiger_receives_one_absolute_manifest_argument_in_checkouts_with_spaces() {
        let root = std::env::current_dir().unwrap().join("review with spaces");
        let arguments = geiger_arguments(&root).unwrap();
        assert_eq!(arguments.len(), 9);
        assert_eq!(&arguments[..2], ["geiger", "--manifest-path"]);
        assert_eq!(
            Path::new(&arguments[2]),
            root.join("crates/rustleaks-sources/Cargo.toml")
        );
        assert!(Path::new(&arguments[2]).is_absolute());
        assert_eq!(
            &arguments[3..],
            [
                "--all-features",
                "--locked",
                "--offline",
                "--output-format",
                "Json",
                "--quiet"
            ]
        );
        assert!(geiger_arguments(Path::new("relative-checkout")).is_err());
    }

    #[test]
    fn delta_reports_added_removed_and_changed_without_approving_them() {
        let delta = object_delta(
            &json!({"old@1":{},"same@1":{"features":[]},"changed@1":{"count":1}}),
            &json!({"new@1":{},"same@1":{"features":[]},"changed@1":{"count":2}}),
        )
        .unwrap();
        assert_eq!(
            delta,
            json!({"added":["new@1"],"removed":["old@1"],"changed":["changed@1"]})
        );
        assert_eq!(
            compare(&json!({}), None).unwrap()["review_status"],
            "unreviewed-initial"
        );
        assert!(
            validate_snapshot(&json!({"schema_version":1,"kind":"dependency-comparison-evidence"}))
                .is_err()
        );
    }
}
