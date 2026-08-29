//! Deterministic locked dependency and cargo-vet coverage inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use super::{command_output, sha256_file};

const CORE_PACKAGE: &str = "rustleaks-core";
type PackageStringSets = BTreeMap<String, BTreeSet<String>>;
type IncomingEdgeProperties = (PackageStringSets, PackageStringSets);

#[derive(Debug, Default, Eq, PartialEq)]
struct VetCoverage {
    exemptions: BTreeSet<(String, String)>,
    exemption_crate_names: BTreeSet<String>,
    local_audits: BTreeSet<(String, String)>,
    peer_audits: BTreeSet<(String, String)>,
    peer_imports: BTreeSet<String>,
}

pub(crate) fn write_vet_inventory(root: &Path, output: &Path) -> Result<(), String> {
    let generated = generate_vet_inventory(root)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::write(output, &generated)
        .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
    println!(
        "wrote locked cargo-vet dependency inventory to {}",
        output.display()
    );
    Ok(())
}

pub(crate) fn check_vet_inventory(root: &Path, candidate: &Path) -> Result<(), String> {
    let generated = generate_vet_inventory(root)?;
    let actual = fs::read(candidate)
        .map_err(|error| format!("cannot read {}: {error}", candidate.display()))?;
    if actual != generated {
        let offset = actual
            .iter()
            .zip(&generated)
            .position(|(left, right)| left != right)
            .unwrap_or(actual.len().min(generated.len()));
        return Err(format!(
            "cargo-vet inventory {} differs at byte {offset}: expected {} bytes, got {}",
            candidate.display(),
            generated.len(),
            actual.len()
        ));
    }
    let inventory: Value = serde_json::from_slice(&actual)
        .map_err(|error| format!("cannot decode {}: {error}", candidate.display()))?;
    println!(
        "verified {} locked third-party packages: {} local audits, {} peer-imported audits, and {} exemptions across {} crate names",
        inventory["summary"]["third_party_package_count"],
        inventory["summary"]["local_full_audit_record_count"],
        inventory["summary"]["peer_imported_audit_package_count"],
        inventory["summary"]["exemption_record_count"],
        inventory["summary"]["exemption_crate_name_count"]
    );
    Ok(())
}

fn generate_vet_inventory(root: &Path) -> Result<Vec<u8>, String> {
    let coverage = read_vet_coverage(root)?;
    if !coverage.peer_imports.is_empty() {
        command_output(Command::new("cargo").current_dir(root).args([
            "vet",
            "--locked",
            "--no-registry-suggestions",
        ]))?;
    }
    let metadata = command_output(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--format-version",
        "1",
        "--offline",
        "--locked",
    ]))?;
    let metadata: Value = serde_json::from_str(&metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let lock_source = fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|error| format!("cannot read Cargo.lock: {error}"))?;
    let lock: toml::Value = toml::from_str(&lock_source)
        .map_err(|error| format!("cannot parse Cargo.lock: {error}"))?;
    let consumers = cargo_tree_consumers(root, &metadata)?;
    let core_graph = cargo_tree_identities(root, CORE_PACKAGE, "normal,build")?;
    let inventory = build_inventory(
        &metadata,
        &lock,
        &coverage,
        &consumers,
        &core_graph,
        &sha256_file(&root.join("Cargo.lock"))?,
    )?;
    let mut generated = serde_json::to_vec_pretty(&inventory)
        .map_err(|error| format!("cannot serialize cargo-vet inventory: {error}"))?;
    generated.push(b'\n');
    Ok(generated)
}

fn build_inventory(
    metadata: &Value,
    lock: &toml::Value,
    coverage: &VetCoverage,
    consumers: &BTreeMap<(String, String), BTreeSet<String>>,
    core_graph: &BTreeSet<(String, String)>,
    cargo_lock_sha256: &str,
) -> Result<Value, String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omits packages")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("cargo metadata omits resolve nodes")?;
    let nodes_by_id = nodes
        .iter()
        .map(|node| {
            let id = required_json_str(node, "id", "cargo metadata node")?;
            Ok((id.to_owned(), node.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let lock_checksums = lock_checksums(lock)?;
    let (dependency_kinds, applicable_targets) = incoming_edge_properties(nodes)?;

    let locked_identities = packages
        .iter()
        .filter(|package| !package["source"].is_null())
        .map(|package| {
            Ok((
                required_json_str(package, "name", "cargo metadata package")?.to_owned(),
                required_json_str(package, "version", "cargo metadata package")?.to_owned(),
            ))
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    let peer_audits = validate_coverage_against_locked(&locked_identities, coverage)?;

    let mut third_party = packages
        .iter()
        .filter(|package| !package["source"].is_null())
        .map(|package| {
            package_record(
                package,
                &nodes_by_id,
                &lock_checksums,
                coverage,
                consumers,
                core_graph,
                &dependency_kinds,
                &applicable_targets,
                &peer_audits,
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    third_party.sort_by(|left, right| {
        left["name"]
            .as_str()
            .cmp(&right["name"].as_str())
            .then_with(|| left["version"].as_str().cmp(&right["version"].as_str()))
    });

    Ok(json!({
        "format_version": 1,
        "generated_by": "cargo xtask generate vet-inventory",
        "cargo_lock_sha256": cargo_lock_sha256,
        "feature_resolution": "locked default workspace metadata across declared target edges",
        "summary": {
            "third_party_package_count": third_party.len(),
            "local_full_audit_record_count": coverage.local_audits.len(),
            "peer_import_source_count": coverage.peer_imports.len(),
            "peer_imported_audit_package_count": peer_audits.len(),
            "exemption_record_count": coverage.exemptions.len(),
            "exemption_crate_name_count": coverage.exemption_crate_names.len(),
        },
        "packages": third_party,
    }))
}

fn validate_coverage_against_locked(
    locked_identities: &BTreeSet<(String, String)>,
    coverage: &VetCoverage,
) -> Result<BTreeSet<(String, String)>, String> {
    let policy_identities = coverage
        .exemptions
        .union(&coverage.local_audits)
        .chain(coverage.peer_audits.intersection(locked_identities))
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing = locked_identities
        .difference(&policy_identities)
        .cloned()
        .collect::<BTreeSet<_>>();
    let orphaned = policy_identities
        .difference(locked_identities)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !missing.is_empty() || !orphaned.is_empty() {
        return Err(format!(
            "cargo-vet coverage does not match the locked third-party graph: missing {missing:?}, orphaned {orphaned:?}"
        ));
    }
    Ok(coverage
        .peer_audits
        .intersection(locked_identities)
        .cloned()
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn package_record(
    package: &Value,
    nodes_by_id: &BTreeMap<String, Value>,
    lock_checksums: &BTreeMap<(String, String, String), String>,
    coverage: &VetCoverage,
    consumers: &BTreeMap<(String, String), BTreeSet<String>>,
    core_graph: &BTreeSet<(String, String)>,
    dependency_kinds: &BTreeMap<String, BTreeSet<String>>,
    applicable_targets: &BTreeMap<String, BTreeSet<String>>,
    peer_audits: &BTreeSet<(String, String)>,
) -> Result<Value, String> {
    let id = required_json_str(package, "id", "cargo metadata package")?;
    let name = required_json_str(package, "name", "cargo metadata package")?;
    let version = required_json_str(package, "version", "cargo metadata package")?;
    let source = required_json_str(package, "source", "third-party cargo metadata package")?;
    let identity = (name.to_owned(), version.to_owned());
    let checksum = lock_checksums
        .get(&(name.to_owned(), version.to_owned(), source.to_owned()))
        .ok_or_else(|| format!("Cargo.lock omits checksum for {name}@{version} from {source}"))?;
    let node = nodes_by_id
        .get(id)
        .ok_or_else(|| format!("cargo metadata omits resolve node for {id}"))?;
    let features = string_array(&node["features"], "cargo metadata node features")?;
    let targets = package["targets"]
        .as_array()
        .ok_or_else(|| format!("cargo metadata package {name}@{version} omits targets"))?;
    let build_script = targets.iter().any(|target| {
        target["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
    });
    let coverage_name = if coverage.local_audits.contains(&identity) {
        "local-full-audit"
    } else if peer_audits.contains(&identity) {
        "peer-imported-audit"
    } else if coverage.exemptions.contains(&identity) {
        "exemption"
    } else {
        "missing"
    };
    Ok(json!({
        "name": name,
        "version": version,
        "source": source,
        "checksum": checksum,
        "dependency_kinds": set_values(dependency_kinds.get(id)),
        "workspace_consumers": set_values(consumers.get(&identity)),
        "enabled_features": features,
        "applicable_targets": set_values(applicable_targets.get(id)),
        "build_script": build_script,
        "links": package["links"],
        "core_normal_or_build_graph": core_graph.contains(&identity),
        "cargo_vet": {
            "criteria": "safe-to-deploy",
            "coverage": coverage_name,
        },
    }))
}

fn lock_checksums(
    lock: &toml::Value,
) -> Result<BTreeMap<(String, String, String), String>, String> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("Cargo.lock omits package records")?;
    let mut checksums = BTreeMap::new();
    for package in packages {
        let Some(source) = package.get("source").and_then(toml::Value::as_str) else {
            continue;
        };
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or("Cargo.lock package omits name")?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("Cargo.lock package {name} omits version"))?;
        let checksum = package
            .get("checksum")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("Cargo.lock package {name}@{version} omits checksum"))?;
        checksums.insert(
            (name.to_owned(), version.to_owned(), source.to_owned()),
            checksum.to_owned(),
        );
    }
    Ok(checksums)
}

fn read_vet_coverage(root: &Path) -> Result<VetCoverage, String> {
    let config = read_toml(&root.join("supply-chain/config.toml"))?;
    let audits = read_toml(&root.join("supply-chain/audits.toml"))?;
    let imports = read_toml(&root.join("supply-chain/imports.lock"))?;
    reject_broad_trust(&config, "cargo-vet config")?;
    reject_broad_trust(&audits, "local cargo-vet audits")?;
    reject_broad_trust(&imports, "cargo-vet import lock")?;
    let mut coverage = vet_coverage(&config, &audits)?;
    coverage.peer_audits = imported_audit_coverage(&imports)?;
    Ok(coverage)
}

fn reject_broad_trust(value: &toml::Value, context: &str) -> Result<(), String> {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                if matches!(key.as_str(), "trusted" | "wildcard-audits") {
                    return Err(format!(
                        "{context} contains unsupported publisher-wide or wildcard trust table {key}"
                    ));
                }
                reject_broad_trust(child, context)?;
            }
        }
        toml::Value::Array(values) => {
            for child in values {
                reject_broad_trust(child, context)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn imported_audit_coverage(imports: &toml::Value) -> Result<BTreeSet<(String, String)>, String> {
    let Some(peers) = imports.get("audits") else {
        return Ok(BTreeSet::new());
    };
    let peers = peers
        .as_table()
        .ok_or("cargo-vet imported audits are not a table")?;
    let mut covered = BTreeSet::<(String, String)>::new();
    let mut deltas = BTreeMap::<String, Vec<(String, String)>>::new();
    for (peer, peer_value) in peers {
        let peer_audits = peer_value
            .get("audits")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("cargo-vet import {peer} omits its audits table"))?;
        for (name, entries) in peer_audits {
            let entries = entries.as_array().ok_or_else(|| {
                format!("cargo-vet imported audits for {name} from {peer} are not an array")
            })?;
            for entry in entries {
                require_safe_to_deploy(entry, name, "imported audit")?;
                match (entry.get("version"), entry.get("delta")) {
                    (Some(version), None) => {
                        let version = version.as_str().ok_or_else(|| {
                            format!("cargo-vet imported audit for {name} has invalid version")
                        })?;
                        covered.insert((name.clone(), version.to_owned()));
                    }
                    (None, Some(delta)) => {
                        let delta = delta.as_str().ok_or_else(|| {
                            format!("cargo-vet imported audit for {name} has invalid delta")
                        })?;
                        let (from, to) = delta.split_once("->").ok_or_else(|| {
                            format!("cargo-vet imported audit for {name} has invalid delta {delta}")
                        })?;
                        deltas
                            .entry(name.clone())
                            .or_default()
                            .push((from.trim().to_owned(), to.trim().to_owned()));
                    }
                    _ => {
                        return Err(format!(
                            "cargo-vet imported audit for {name} must contain exactly one of version or delta"
                        ));
                    }
                }
            }
        }
    }

    loop {
        let mut changed = false;
        for (name, edges) in &deltas {
            for (from, to) in edges {
                if covered.contains(&(name.clone(), from.clone())) {
                    changed |= covered.insert((name.clone(), to.clone()));
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(covered)
}

fn read_toml(path: &Path) -> Result<toml::Value, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    toml::from_str(&source).map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn vet_coverage(config: &toml::Value, audits: &toml::Value) -> Result<VetCoverage, String> {
    let mut coverage = VetCoverage::default();
    if let Some(imports) = config.get("imports") {
        let imports = imports
            .as_table()
            .ok_or("cargo-vet imports are not a table")?;
        for (name, entry) in imports {
            required_toml_str(entry, "url", name, "peer import")?;
            coverage.peer_imports.insert(name.clone());
        }
    }
    if let Some(exemptions) = config.get("exemptions") {
        let exemptions = exemptions
            .as_table()
            .ok_or("cargo-vet exemptions are not a table")?;
        for (name, entries) in exemptions {
            let entries = entries
                .as_array()
                .ok_or_else(|| format!("cargo-vet exemptions for {name} are not an array"))?;
            for entry in entries {
                require_safe_to_deploy(entry, name, "exemption")?;
                let version = required_toml_str(entry, "version", name, "exemption")?;
                if !coverage
                    .exemptions
                    .insert((name.clone(), version.to_owned()))
                {
                    return Err(format!(
                        "cargo-vet contains duplicate exemption {name}@{version}"
                    ));
                }
                coverage.exemption_crate_names.insert(name.clone());
            }
        }
    }
    if let Some(audits) = audits.get("audits") {
        let audits = audits
            .as_table()
            .ok_or("cargo-vet audits are not a table")?;
        for (name, entries) in audits {
            let entries = entries
                .as_array()
                .ok_or_else(|| format!("cargo-vet audits for {name} are not an array"))?;
            for entry in entries {
                require_safe_to_deploy(entry, name, "audit")?;
                let version = required_toml_str(entry, "version", name, "audit")?;
                if !coverage
                    .local_audits
                    .insert((name.clone(), version.to_owned()))
                {
                    return Err(format!(
                        "cargo-vet contains duplicate local audit {name}@{version}"
                    ));
                }
            }
        }
    }
    let duplicates = coverage
        .exemptions
        .intersection(&coverage.local_audits)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !duplicates.is_empty() {
        return Err(format!(
            "cargo-vet identities have both local audits and exemptions: {duplicates:?}"
        ));
    }
    Ok(coverage)
}

fn require_safe_to_deploy(
    entry: &toml::Value,
    name: &str,
    record_kind: &str,
) -> Result<(), String> {
    let criteria = entry
        .get("criteria")
        .ok_or_else(|| format!("cargo-vet {record_kind} for {name} omits criteria"))?;
    let includes_safe_to_deploy = criteria.as_str() == Some("safe-to-deploy")
        || criteria.as_array().is_some_and(|criteria| {
            criteria
                .iter()
                .any(|criterion| criterion.as_str() == Some("safe-to-deploy"))
        });
    if !includes_safe_to_deploy {
        return Err(format!(
            "cargo-vet {record_kind} for {name} does not include safe-to-deploy criteria"
        ));
    }
    Ok(())
}

fn required_toml_str<'a>(
    value: &'a toml::Value,
    field: &str,
    name: &str,
    record_kind: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("cargo-vet {record_kind} for {name} omits {field}"))
}

fn cargo_tree_consumers(
    root: &Path,
    metadata: &Value,
) -> Result<BTreeMap<(String, String), BTreeSet<String>>, String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omits packages")?;
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .ok_or("cargo metadata omits workspace members")?;
    let workspace_ids = workspace_members
        .iter()
        .map(|member| {
            member
                .as_str()
                .ok_or_else(|| "cargo metadata workspace member is not a string".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let workspace_names = packages
        .iter()
        .filter(|package| {
            package["id"]
                .as_str()
                .is_some_and(|id| workspace_ids.contains(id))
        })
        .map(|package| required_json_str(package, "name", "workspace package").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut consumers = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for workspace_name in workspace_names {
        for identity in cargo_tree_identities(root, &workspace_name, "normal,build,dev")? {
            consumers
                .entry(identity)
                .or_default()
                .insert(workspace_name.clone());
        }
    }
    Ok(consumers)
}

fn cargo_tree_identities(
    root: &Path,
    package: &str,
    edges: &str,
) -> Result<BTreeSet<(String, String)>, String> {
    let output = command_output(
        Command::new("cargo")
            .current_dir(root)
            .args(["tree", "--color", "never", "--locked", "--offline"])
            .args(["--edges", edges, "--target", "all", "--prefix", "none"])
            .args(["--format", "{p}", "-p", package]),
    )?;
    output.lines().map(parse_cargo_tree_identity).collect()
}

fn parse_cargo_tree_identity(line: &str) -> Result<(String, String), String> {
    let mut fields = line.split_whitespace();
    let name = fields
        .next()
        .ok_or_else(|| "cargo tree contains an empty package entry".to_owned())?;
    let version = fields
        .next()
        .and_then(|version| version.strip_prefix('v'))
        .ok_or_else(|| format!("cargo tree package entry omits version: {line}"))?;
    Ok((name.to_owned(), version.to_owned()))
}

fn incoming_edge_properties(nodes: &[Value]) -> Result<IncomingEdgeProperties, String> {
    let mut kinds = BTreeMap::<String, BTreeSet<String>>::new();
    let mut targets = BTreeMap::<String, BTreeSet<String>>::new();
    for node in nodes {
        let deps = node["deps"]
            .as_array()
            .ok_or("cargo metadata resolve node omits deps")?;
        for dep in deps {
            let package = required_json_str(dep, "pkg", "cargo metadata dependency")?;
            let dep_kinds = dep["dep_kinds"]
                .as_array()
                .ok_or("cargo metadata dependency omits dep_kinds")?;
            for dep_kind in dep_kinds {
                let kind = match dep_kind["kind"].as_str() {
                    None => "normal",
                    Some("dev") => "development",
                    Some(kind) => kind,
                };
                kinds
                    .entry(package.to_owned())
                    .or_default()
                    .insert(kind.to_owned());
                let target = dep_kind["target"].as_str().unwrap_or("all");
                targets
                    .entry(package.to_owned())
                    .or_default()
                    .insert(target.to_owned());
            }
        }
    }
    Ok((kinds, targets))
}

fn required_json_str<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{context} omits {field}"))
}

fn string_array(value: &Value, context: &str) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} is not an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{context} contains a non-string"))
        })
        .collect()
}

fn set_values(values: Option<&BTreeSet<String>>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(BTreeSet::iter)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_distinguishes_records_from_crate_names() {
        let config: toml::Value = toml::from_str(
            r#"
                [[exemptions.multi]]
                version = "1.0.0"
                criteria = "safe-to-deploy"

                [[exemptions.multi]]
                version = "2.0.0"
                criteria = "safe-to-deploy"
            "#,
        )
        .expect("config");
        let audits: toml::Value = toml::from_str(
            r#"
                [[audits.reviewed]]
                version = "3.0.0"
                criteria = "safe-to-deploy"
            "#,
        )
        .expect("audits");
        let coverage = vet_coverage(&config, &audits).expect("coverage");
        assert_eq!(coverage.exemptions.len(), 2);
        assert_eq!(coverage.exemption_crate_names.len(), 1);
        assert_eq!(coverage.local_audits.len(), 1);
        assert!(coverage.peer_audits.is_empty());
        assert!(coverage.peer_imports.is_empty());
    }

    #[test]
    fn coverage_rejects_audit_and_exemption_for_one_identity() {
        let config: toml::Value = toml::from_str(
            r#"
                [[exemptions.same]]
                version = "1.0.0"
                criteria = "safe-to-deploy"
            "#,
        )
        .expect("config");
        let audits: toml::Value = toml::from_str(
            r#"
                [[audits.same]]
                version = "1.0.0"
                criteria = "safe-to-deploy"
            "#,
        )
        .expect("audits");
        let error = vet_coverage(&config, &audits).expect_err("duplicate coverage");
        assert!(error.contains("both local audits and exemptions"));
    }

    #[test]
    fn coverage_rejects_duplicate_records() {
        let config: toml::Value = toml::from_str(
            r#"
                [[exemptions.same]]
                version = "1.0.0"
                criteria = "safe-to-deploy"

                [[exemptions.same]]
                version = "1.0.0"
                criteria = "safe-to-deploy"
            "#,
        )
        .expect("config");
        let audits: toml::Value = toml::from_str("[audits]").expect("audits");
        let error = vet_coverage(&config, &audits).expect_err("duplicate exemption");
        assert!(error.contains("duplicate exemption same@1.0.0"));
    }

    #[test]
    fn locked_coverage_rejects_missing_and_orphaned_identities() {
        let locked = BTreeSet::from([("locked".to_owned(), "1.0.0".to_owned())]);
        let coverage = VetCoverage {
            exemptions: BTreeSet::from([("orphaned".to_owned(), "2.0.0".to_owned())]),
            exemption_crate_names: BTreeSet::from(["orphaned".to_owned()]),
            local_audits: BTreeSet::new(),
            peer_audits: BTreeSet::new(),
            peer_imports: BTreeSet::new(),
        };
        let error =
            validate_coverage_against_locked(&locked, &coverage).expect_err("coverage mismatch");
        assert!(error.contains("missing {(\"locked\", \"1.0.0\")}"));
        assert!(error.contains("orphaned {(\"orphaned\", \"2.0.0\")}"));
    }

    #[test]
    fn locked_coverage_classifies_unrecorded_identities_as_peer_imports() {
        let locked = BTreeSet::from([("peer-covered".to_owned(), "1.0.0".to_owned())]);
        let coverage = VetCoverage {
            peer_audits: locked.clone(),
            peer_imports: BTreeSet::from(["peer".to_owned()]),
            ..VetCoverage::default()
        };
        assert_eq!(
            validate_coverage_against_locked(&locked, &coverage).expect("peer coverage"),
            locked
        );
    }

    #[test]
    fn coverage_records_explicit_peer_imports() {
        let config: toml::Value = toml::from_str(
            r#"
                [imports.peer]
                url = "https://example.invalid/audits.toml"
            "#,
        )
        .expect("config");
        let audits: toml::Value = toml::from_str("[audits]").expect("audits");
        let coverage = vet_coverage(&config, &audits).expect("coverage");
        assert_eq!(coverage.peer_imports, BTreeSet::from(["peer".to_owned()]));
    }

    #[test]
    fn broad_publisher_and_wildcard_trust_are_rejected() {
        for source in ["[trusted.crate]", "[audits.peer.wildcard-audits.crate]"] {
            let value: toml::Value = toml::from_str(source).expect("trust table");
            let error = reject_broad_trust(&value, "test policy").expect_err("broad trust");
            assert!(error.contains("publisher-wide or wildcard trust"));
        }
    }

    #[test]
    fn imported_audit_coverage_follows_cross_peer_delta_chains() {
        let imports: toml::Value = toml::from_str(
            r#"
                [[audits.first.audits.crate]]
                criteria = "safe-to-deploy"
                version = "1.0.0"

                [[audits.second.audits.crate]]
                criteria = ["safe-to-run", "safe-to-deploy"]
                delta = "1.0.0 -> 2.0.0"
            "#,
        )
        .expect("imports");
        assert_eq!(
            imported_audit_coverage(&imports).expect("coverage"),
            BTreeSet::from([
                ("crate".to_owned(), "1.0.0".to_owned()),
                ("crate".to_owned(), "2.0.0".to_owned()),
            ])
        );
    }

    #[test]
    fn edge_properties_preserve_kinds_and_targets() {
        let nodes = serde_json::from_value::<Vec<Value>>(json!([
            {
                "id": "root",
                "deps": [
                    {
                        "pkg": "dep",
                        "dep_kinds": [
                            {"kind": null, "target": null},
                            {"kind": "dev", "target": "cfg(unix)"}
                        ]
                    }
                ]
            }
        ]))
        .expect("nodes");
        let (kinds, targets) = incoming_edge_properties(&nodes).expect("properties");
        assert_eq!(
            kinds["dep"],
            BTreeSet::from(["development".to_owned(), "normal".to_owned()])
        );
        assert_eq!(
            targets["dep"],
            BTreeSet::from(["all".to_owned(), "cfg(unix)".to_owned()])
        );
    }

    #[test]
    fn cargo_tree_identity_ignores_annotations() {
        assert_eq!(
            parse_cargo_tree_identity("serde_derive v1.0.229 (proc-macro) (*)").expect("identity"),
            ("serde_derive".to_owned(), "1.0.229".to_owned())
        );
    }
}
