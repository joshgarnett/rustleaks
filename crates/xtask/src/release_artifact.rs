//! Deterministic release bundles, target SBOMs, and dry-run provenance.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::Compression;
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::tooling::{command_output, sha256_file};

const RELEASE_VERSION: &str = "0.1.0-alpha.2";
const REPOSITORY: &str = "https://github.com/joshgarnett/rustleaks";
const BAZEL_VERSION: &str = "9.2.0";
const RULES_RUST_VERSION: &str = "0.72.0";
const BAZEL_RUST_VERSION: &str = "1.85.0";

const TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-gnu", "release-linux-x86_64-gnu"),
    ("aarch64-unknown-linux-gnu", "release-linux-aarch64-gnu"),
    ("x86_64-unknown-linux-musl", "release-linux-x86_64-musl"),
    ("aarch64-unknown-linux-musl", "release-linux-aarch64-musl"),
    ("x86_64-apple-darwin", "release-macos-x86_64"),
    ("aarch64-apple-darwin", "release-macos-aarch64"),
    ("x86_64-pc-windows-msvc", "release-windows-x86_64-msvc"),
    ("aarch64-pc-windows-msvc", "release-windows-aarch64-msvc"),
];

struct ReleaseEvidence<'a> {
    target: &'a str,
    bazel_config: &'a str,
    commit: &'a str,
    artifact_name: &'a str,
    artifact_sha256: &'a str,
    binary_sha256: &'a str,
    lock_digests: &'a Value,
}

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [command, left, right, proof] if command == "compare" => {
            compare(Path::new(left), Path::new(right), Path::new(proof))
        }
        [command, left, right] if command == "compare-bundles" => {
            compare_bundles(Path::new(left), Path::new(right))
        }
        [command, binary, bazel_output_root, target, commit, proof, output, glibc]
            if command == "prepare" =>
        {
            prepare(
                root,
                Path::new(binary),
                Path::new(bazel_output_root),
                target,
                commit,
                Path::new(proof),
                Path::new(output),
                glibc,
            )
        }
        [command, output] if command == "verify" => verify(root, Path::new(output)),
        _ => Err("usage: cargo xtask release-artifact <compare LEFT RIGHT PROOF|compare-bundles LEFT RIGHT|prepare BINARY BAZEL_OUTPUT_ROOT TARGET COMMIT PROOF OUTPUT GLIBC_BASELINE|verify OUTPUT>".into()),
    }
}

fn compare_bundles(left: &Path, right: &Path) -> Result<(), String> {
    let left_files = read_bundle_files(left)?;
    let right_files = read_bundle_files(right)?;
    compare_bundle_maps(&left_files, &right_files)?;
    println!(
        "isolated release bundles are byte-identical: {} files",
        left_files.len()
    );
    Ok(())
}

fn compare_bundle_maps(
    left_files: &BTreeMap<String, Vec<u8>>,
    right_files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    if left_files.keys().ne(right_files.keys()) {
        return Err(format!(
            "isolated release bundle paths differ: first has {:?}, second has {:?}",
            left_files.keys().collect::<Vec<_>>(),
            right_files.keys().collect::<Vec<_>>()
        ));
    }
    for (name, left_bytes) in left_files {
        let right_bytes = right_files
            .get(name)
            .ok_or("second bundle lost a path after comparison")?;
        if left_bytes != right_bytes {
            let offset = left_bytes
                .iter()
                .zip(right_bytes)
                .position(|(left, right)| left != right)
                .unwrap_or(left_bytes.len().min(right_bytes.len()));
            return Err(format!(
                "isolated release bundle file {name} differs at byte {offset}: first has {} bytes, second has {} bytes",
                left_bytes.len(),
                right_bytes.len()
            ));
        }
    }
    Ok(())
}

fn read_bundle_files(directory: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot read release bundle {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "cannot inspect release bundle {}: {error}",
                directory.display()
            )
        })?;
        if !entry
            .file_type()
            .map_err(|error| format!("cannot inspect release bundle entry: {error}"))?
            .is_file()
        {
            return Err(format!(
                "release bundle contains a non-file entry: {}",
                entry.path().display()
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "release bundle contains a non-UTF-8 file name".to_owned())?;
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("cannot read release bundle file {name}: {error}"))?;
        if files.insert(name.clone(), bytes).is_some() {
            return Err(format!("release bundle repeats file {name}"));
        }
    }
    Ok(files)
}

fn compare(left: &Path, right: &Path, proof: &Path) -> Result<(), String> {
    let left_bytes = fs::read(left).map_err(|error| {
        format!(
            "cannot read first release binary {}: {error}",
            left.display()
        )
    })?;
    let right_bytes = fs::read(right).map_err(|error| {
        format!(
            "cannot read second release binary {}: {error}",
            right.display()
        )
    })?;
    if left_bytes != right_bytes {
        let offset = left_bytes
            .iter()
            .zip(&right_bytes)
            .position(|(left, right)| left != right)
            .unwrap_or(left_bytes.len().min(right_bytes.len()));
        return Err(format!(
            "isolated release binaries differ at byte {offset}: first has {} bytes, second has {} bytes",
            left_bytes.len(),
            right_bytes.len()
        ));
    }
    let digest = sha256_bytes(&left_bytes);
    write_json(
        proof,
        &json!({
            "schemaVersion": 1,
            "identical": true,
            "sha256": digest,
            "size": left_bytes.len(),
        }),
    )?;
    println!("isolated release binaries are byte-identical: {digest}");
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Keep bundle generation as one fail-closed transaction.
fn prepare(
    root: &Path,
    binary: &Path,
    bazel_output_root: &Path,
    target: &str,
    commit: &str,
    proof: &Path,
    output: &Path,
    glibc: &str,
) -> Result<(), String> {
    let bazel_config = target_config(target)?;
    validate_commit(commit)?;
    validate_glibc(target, glibc)?;
    let binary_bytes = fs::read(binary)
        .map_err(|error| format!("cannot read release binary {}: {error}", binary.display()))?;
    let binary_sha256 = sha256_bytes(&binary_bytes);
    validate_reproducibility_proof(proof, &binary_sha256, binary_bytes.len())?;
    let graph_text = bazel_graph(root, bazel_output_root, bazel_config)?;
    let metadata = cargo_metadata(root, target)?;
    let graph = CargoGraph::from_metadata(&metadata)?;
    graph.reconcile_bazel(&graph_text)?;
    validate_workspace_versions(root)?;

    prepare_output_directory(output)?;

    let stem = format!("rustleaks-{RELEASE_VERSION}-{target}");
    let archive_name = format!("{stem}.tar.gz");
    let binary_name = if target.contains("windows") {
        "rustleaks.exe"
    } else {
        "rustleaks"
    };
    let archive = output.join(&archive_name);
    write_archive(
        &archive,
        &stem,
        binary_name,
        &binary_bytes,
        root,
        target.contains("windows"),
    )?;
    let archive_sha256 = sha256_file(&archive)?;
    let sbom_name = format!("{stem}.cdx.json");
    let sbom_path = output.join(&sbom_name);
    let lock_digests = lock_digests(root, commit)?;
    let package_checksums = cargo_lock_checksums(root)?;
    let evidence = ReleaseEvidence {
        target,
        bazel_config,
        commit,
        artifact_name: &archive_name,
        artifact_sha256: &archive_sha256,
        binary_sha256: &binary_sha256,
        lock_digests: &lock_digests,
    };
    let sbom = graph.cyclonedx(&evidence, &package_checksums)?;
    write_json(&sbom_path, &sbom)?;
    let sbom_sha256 = sha256_file(&sbom_path)?;

    let provenance_name = format!("{stem}.provenance.json");
    let provenance_path = output.join(&provenance_name);
    let provenance = provenance(&evidence, &sbom_name, &sbom_sha256);
    write_json(&provenance_path, &provenance)?;
    let provenance_sha256 = sha256_file(&provenance_path)?;

    fs::copy(proof, output.join("reproducibility.json")).map_err(|error| {
        format!(
            "cannot copy reproducibility proof {}: {error}",
            proof.display()
        )
    })?;
    fs::write(
        output.join("SHA256SUMS"),
        format!("{archive_sha256}  {archive_name}\n{sbom_sha256}  {sbom_name}\n{provenance_sha256}  {provenance_name}\n"),
    )
    .map_err(|error| format!("cannot write release checksums: {error}"))?;

    let manifest = json!({
        "schemaVersion": 1,
        "release": {
            "name": "rustleaks",
            "version": RELEASE_VERSION,
            "sourceCommit": commit,
            "repository": REPOSITORY,
        },
        "build": {
            "target": target,
            "bazelConfig": bazel_config,
            "bazelVersion": read_trimmed(&root.join(".bazelversion"))?,
            "rustVersion": BAZEL_RUST_VERSION,
            "rulesRustVersion": RULES_RUST_VERSION,
            "features": ["archives"],
            "lockfiles": lock_digests,
        },
        "artifact": {
            "file": archive_name,
            "sha256": archive_sha256,
            "binarySha256": binary_sha256,
            "reproducible": true,
            "glibcMinimum": if glibc == "none" { Value::Null } else { Value::String(glibc.to_owned()) },
        },
        "sbom": {
            "file": sbom_name,
            "format": "CycloneDX",
            "specVersion": "1.6",
            "sha256": sbom_sha256,
            "bazelReconciled": true,
        },
        "provenance": {
            "file": provenance_name,
            "predicateType": "https://slsa.dev/provenance/v1",
            "sha256": provenance_sha256,
            "signed": false,
        },
    });
    write_json(&output.join("manifest.json"), &manifest)?;
    verify(root, output)?;
    println!("prepared and verified non-publishing release bundle {archive_name}");
    Ok(())
}

fn prepare_output_directory(output: &Path) -> Result<(), String> {
    if !output.exists() {
        return fs::create_dir_all(output).map_err(|error| {
            format!(
                "cannot create release output directory {}: {error}",
                output.display()
            )
        });
    }
    let mut entries = fs::read_dir(output).map_err(|error| {
        format!(
            "cannot inspect release output {}: {error}",
            output.display()
        )
    })?;
    if entries.next().is_some() {
        return Err(format!(
            "release output directory is not empty: {}",
            output.display()
        ));
    }
    Ok(())
}

fn verify(root: &Path, output: &Path) -> Result<(), String> {
    let manifest = read_json(&output.join("manifest.json"))?;
    let commit = required_pointer(&manifest, "/release/sourceCommit")?;
    validate_commit(commit)?;
    let committed_lock_digests = lock_digests(root, commit)?;
    if manifest.pointer("/build/lockfiles") != Some(&committed_lock_digests) {
        return Err("release manifest lockfile digests do not match the committed sources".into());
    }
    let artifact_name = required_pointer(&manifest, "/artifact/file")?;
    let artifact_sha256 = required_pointer(&manifest, "/artifact/sha256")?;
    let sbom_name = required_pointer(&manifest, "/sbom/file")?;
    let sbom_sha256 = required_pointer(&manifest, "/sbom/sha256")?;
    let provenance_name = required_pointer(&manifest, "/provenance/file")?;
    let provenance_sha256 = required_pointer(&manifest, "/provenance/sha256")?;
    validate_output_directory(output, artifact_name, sbom_name, provenance_name)?;
    for (name, expected) in [
        (artifact_name, artifact_sha256),
        (sbom_name, sbom_sha256),
        (provenance_name, provenance_sha256),
    ] {
        let actual = sha256_file(&output.join(name))?;
        if actual != expected {
            return Err(format!(
                "release file {name} has SHA-256 {actual}, expected {expected}"
            ));
        }
    }
    let sums = fs::read_to_string(output.join("SHA256SUMS"))
        .map_err(|error| format!("cannot read SHA256SUMS: {error}"))?;
    for (name, digest) in [
        (artifact_name, artifact_sha256),
        (sbom_name, sbom_sha256),
        (provenance_name, provenance_sha256),
    ] {
        let expected = format!("{digest}  {name}");
        if !sums.lines().any(|line| line == expected) {
            return Err(format!("SHA256SUMS omits exact entry {expected}"));
        }
    }
    if sums.lines().count() != 3 {
        return Err("SHA256SUMS must contain exactly three entries".into());
    }
    let sbom = read_json(&output.join(sbom_name))?;
    if sbom["bomFormat"] != "CycloneDX" || sbom["specVersion"] != "1.6" {
        return Err("release SBOM is not CycloneDX 1.6".into());
    }
    let sbom_artifact = sbom
        .pointer("/metadata/properties")
        .and_then(Value::as_array)
        .and_then(|properties| {
            properties
                .iter()
                .find(|property| property["name"] == "rustleaks:artifact:sha256")
        })
        .and_then(|property| property["value"].as_str());
    if sbom_artifact != Some(artifact_sha256) {
        return Err("release SBOM is not bound to the artifact checksum".into());
    }
    let provenance = read_json(&output.join(provenance_name))?;
    if provenance["predicateType"] != "https://slsa.dev/provenance/v1"
        || provenance
            .pointer("/subject/0/digest/sha256")
            .and_then(Value::as_str)
            != Some(artifact_sha256)
    {
        return Err("release provenance is not bound to the artifact checksum".into());
    }
    validate_archive(&output.join(artifact_name), artifact_name)?;
    let proof = read_json(&output.join("reproducibility.json"))?;
    if proof["identical"] != true
        || proof["sha256"].as_str()
            != manifest
                .pointer("/artifact/binarySha256")
                .and_then(Value::as_str)
    {
        return Err("release reproducibility proof is invalid".into());
    }
    println!("verified release bundle checksums, SBOM, provenance, and archive contents");
    Ok(())
}

fn validate_output_directory(
    output: &Path,
    artifact_name: &str,
    sbom_name: &str,
    provenance_name: &str,
) -> Result<(), String> {
    let stem = artifact_name
        .strip_suffix(".tar.gz")
        .ok_or("release archive name must end in .tar.gz")?;
    let attestation_name = format!("{stem}.attestation.jsonl");
    let files = read_bundle_files(output)?;
    let mut expected = [
        artifact_name,
        sbom_name,
        provenance_name,
        "manifest.json",
        "reproducibility.json",
        "SHA256SUMS",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if files.contains_key(&attestation_name) {
        expected.insert(attestation_name);
    }
    let actual = files.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "release bundle paths differ: expected {expected:?}, got {actual:?}"
        ));
    }
    if files.values().any(Vec::is_empty) {
        return Err("release bundle contains an empty file".into());
    }
    Ok(())
}

fn cargo_metadata(root: &Path, target: &str) -> Result<Value, String> {
    let output = command_output(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        "--filter-platform",
        target,
    ]))?;
    serde_json::from_str(&output).map_err(|error| format!("cannot decode Cargo metadata: {error}"))
}

fn bazel_graph(root: &Path, output_root: &Path, config: &str) -> Result<String, String> {
    let mut command = Command::new("bazelisk");
    command
        .current_dir(root)
        .arg(format!("--output_user_root={}", output_root.display()));
    if cfg!(windows) {
        command.arg("--windows_enable_symlinks");
    }
    command.arg("cquery").args([
        &format!("--config={config}"),
        "deps(//crates/rustleaks-cli:rustleaks)",
        "--output=label",
        "--ui_event_filters=-info,-warning",
        "--noshow_progress",
    ]);
    if cfg!(windows) {
        command.args([
            "--repo_env=BAZEL_DO_NOT_DETECT_CPP_TOOLCHAIN=0",
            "--extra_toolchains=@@rules_cc++cc_configure_extension+local_config_cc_toolchains//:all",
        ]);
    }
    command_output(&mut command)
}

struct CargoGraph<'a> {
    packages: BTreeMap<&'a str, &'a Value>,
    nodes: BTreeMap<&'a str, &'a Value>,
    reached: BTreeSet<&'a str>,
}

impl<'a> CargoGraph<'a> {
    fn from_metadata(metadata: &'a Value) -> Result<Self, String> {
        let packages = metadata["packages"]
            .as_array()
            .ok_or("Cargo metadata omits packages")?
            .iter()
            .map(|package| {
                Ok((
                    package["id"].as_str().ok_or("Cargo package omits id")?,
                    package,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let nodes = metadata
            .pointer("/resolve/nodes")
            .and_then(Value::as_array)
            .ok_or("Cargo metadata omits resolve nodes")?
            .iter()
            .map(|node| Ok((node["id"].as_str().ok_or("Cargo node omits id")?, node)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let roots = packages
            .iter()
            .filter(|(_, package)| package["name"] == "rustleaks-cli")
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let [root] = roots.as_slice() else {
            return Err(format!(
                "Cargo metadata must contain one rustleaks-cli package, got {}",
                roots.len()
            ));
        };
        let mut reached = BTreeSet::new();
        let mut pending = VecDeque::from([*root]);
        while let Some(id) = pending.pop_front() {
            if !reached.insert(id) {
                continue;
            }
            let node = nodes
                .get(id)
                .ok_or_else(|| format!("Cargo resolve omits node {id}"))?;
            for dependency in node["deps"]
                .as_array()
                .ok_or("Cargo node omits dependencies")?
            {
                if dependency_is_selected(
                    packages.get(id).ok_or("Cargo package is unknown")?,
                    node,
                    dependency,
                )? {
                    pending.push_back(
                        dependency["pkg"]
                            .as_str()
                            .ok_or("Cargo dependency omits package id")?,
                    );
                }
            }
        }
        Ok(Self {
            packages,
            nodes,
            reached,
        })
    }

    fn reconcile_bazel(&self, labels: &str) -> Result<(), String> {
        let all_registry = self
            .packages
            .iter()
            .filter(|(_, package)| is_registry(package))
            .map(|(id, package)| Ok::<_, String>((*id, identity(package)?)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut observed = BTreeSet::new();
        for (id, identity) in &all_registry {
            if bazel_mentions(labels, identity) {
                observed.insert(*id);
            }
        }
        let expected = self
            .reached
            .iter()
            .filter(|id| {
                self.packages
                    .get(**id)
                    .is_some_and(|package| is_registry(package))
            })
            .copied()
            .collect::<BTreeSet<_>>();
        if observed != expected {
            let missing = expected.difference(&observed).copied().collect::<Vec<_>>();
            let extra = observed.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "Cargo and Bazel registry graphs differ; missing {missing:?}, extra {extra:?}"
            ));
        }
        for id in &self.reached {
            let package = self.packages.get(id).ok_or("reached package is unknown")?;
            if is_registry(package) {
                continue;
            }
            let name = package["name"].as_str().ok_or("package omits name")?;
            let label = format!("//crates/{name}:");
            if !labels.contains(&label) {
                return Err(format!(
                    "Bazel release graph omits first-party package {name}"
                ));
            }
        }
        Ok(())
    }

    fn cyclonedx(
        &self,
        evidence: &ReleaseEvidence<'_>,
        package_checksums: &BTreeMap<(String, String), String>,
    ) -> Result<Value, String> {
        let mut components = Vec::new();
        let mut dependencies = Vec::new();
        let root_id = self
            .reached
            .iter()
            .find(|id| {
                self.packages
                    .get(**id)
                    .is_some_and(|package| package["name"] == "rustleaks-cli")
            })
            .copied()
            .ok_or("release Cargo graph omits rustleaks-cli")?;
        for id in &self.reached {
            let package = self.packages.get(id).ok_or("reached package is unknown")?;
            let reference = purl(package)?;
            if *id != root_id {
                components.push(component(package, &reference, package_checksums)?);
            }
            let node = self.nodes.get(id).ok_or("reached Cargo node is unknown")?;
            let mut depends_on = Vec::new();
            for dependency in node["deps"]
                .as_array()
                .ok_or("Cargo node omits dependencies")?
            {
                let dependency_id = dependency["pkg"]
                    .as_str()
                    .ok_or("dependency omits package id")?;
                if self.reached.contains(dependency_id)
                    && dependency_is_selected(package, node, dependency)?
                {
                    depends_on.push(purl(
                        self.packages
                            .get(dependency_id)
                            .ok_or("dependency package is unknown")?,
                    )?);
                }
            }
            depends_on.sort();
            depends_on.dedup();
            dependencies.push(json!({"ref": reference, "dependsOn": depends_on}));
        }
        components.sort_by(|left, right| left["bom-ref"].as_str().cmp(&right["bom-ref"].as_str()));
        dependencies.sort_by(|left, right| left["ref"].as_str().cmp(&right["ref"].as_str()));
        let root_package = self
            .packages
            .get(root_id)
            .ok_or("root package is unknown")?;
        Ok(json!({
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": purl(root_package)?,
                    "name": "rustleaks",
                    "version": RELEASE_VERSION,
                    "purl": purl(root_package)?,
                },
                "properties": [
                    {"name": "rustleaks:artifact:file", "value": evidence.artifact_name},
                    {"name": "rustleaks:artifact:sha256", "value": evidence.artifact_sha256},
                    {"name": "rustleaks:binary:sha256", "value": evidence.binary_sha256},
                    {"name": "rustleaks:build:bazel", "value": BAZEL_VERSION},
                    {"name": "rustleaks:build:rules-rust", "value": RULES_RUST_VERSION},
                    {"name": "rustleaks:build:rust", "value": BAZEL_RUST_VERSION},
                    {"name": "rustleaks:source:commit", "value": evidence.commit},
                    {"name": "rustleaks:target", "value": evidence.target},
                    {"name": "rustleaks:lockfiles", "value": serde_json::to_string(evidence.lock_digests).map_err(|error| format!("cannot serialize lock digests: {error}"))?},
                ],
            },
            "components": components,
            "dependencies": dependencies,
        }))
    }
}

fn component(
    package: &Value,
    reference: &str,
    package_checksums: &BTreeMap<(String, String), String>,
) -> Result<Value, String> {
    let name = package["name"].as_str().ok_or("Cargo package omits name")?;
    let version = package["version"]
        .as_str()
        .ok_or("Cargo package omits version")?;
    let mut value = json!({
        "type": "library",
        "bom-ref": reference,
        "name": name,
        "version": version,
        "purl": reference,
    });
    if let Some(license) = package["license"].as_str() {
        value["licenses"] = json!([{"expression": license}]);
    } else if let Some(file) = package["license_file"].as_str() {
        let file = Path::new(file)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Cargo license file has no portable name")?;
        value["licenses"] = json!([{"license": {"name": format!("License file: {file}")}}]);
    }
    if is_registry(package) {
        let checksum = package_checksums
            .get(&(name.to_owned(), version.to_owned()))
            .ok_or_else(|| format!("Cargo.lock omits checksum for {name} {version}"))?;
        value["hashes"] = json!([{"alg": "SHA-256", "content": checksum}]);
    }
    Ok(value)
}

fn provenance(evidence: &ReleaseEvidence<'_>, sbom_name: &str, sbom_sha256: &str) -> Value {
    let workflow = format!(
        "{REPOSITORY}/.github/workflows/release-dry-run.yml@{}",
        evidence.commit
    );
    let mut resolved = vec![json!({
        "uri": format!("git+{REPOSITORY}@{}", evidence.commit),
        "digest": {"gitCommit": evidence.commit},
    })];
    for name in ["Cargo.lock", "cargo-bazel-lock.json", "MODULE.bazel.lock"] {
        resolved.push(json!({
            "name": name,
            "uri": format!("{REPOSITORY}/blob/{}/{name}", evidence.commit),
            "digest": {"sha256": evidence.lock_digests[name]},
        }));
    }
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": evidence.artifact_name, "digest": {"sha256": evidence.artifact_sha256}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": format!("{REPOSITORY}/blob/{}/docs/RELEASING.md#non-publishing-release-candidate", evidence.commit),
                "externalParameters": {
                    "bazelConfig": evidence.bazel_config,
                    "features": ["archives"],
                    "target": evidence.target,
                },
                "internalParameters": {
                    "bazelVersion": BAZEL_VERSION,
                    "rulesRustVersion": RULES_RUST_VERSION,
                    "rustVersion": BAZEL_RUST_VERSION,
                },
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {"id": workflow},
                "metadata": {"invocationId": format!("dry-run:{}:{}", evidence.commit, evidence.target)},
                "byproducts": [{"name": sbom_name, "digest": {"sha256": sbom_sha256}}],
            },
        },
    })
}

fn write_archive(
    destination: &Path,
    stem: &str,
    binary_name: &str,
    binary: &[u8],
    root: &Path,
    windows: bool,
) -> Result<(), String> {
    let mut entries = vec![
        (
            "LICENSE",
            fs::read(root.join("LICENSE"))
                .map_err(|error| format!("cannot read LICENSE: {error}"))?,
            0o644,
        ),
        (
            "NOTICE",
            fs::read(root.join("NOTICE"))
                .map_err(|error| format!("cannot read NOTICE: {error}"))?,
            0o644,
        ),
        (
            "README.md",
            fs::read(root.join("README.md"))
                .map_err(|error| format!("cannot read README.md: {error}"))?,
            0o644,
        ),
        (
            binary_name,
            binary.to_vec(),
            if windows { 0o644 } else { 0o755 },
        ),
    ];
    entries.sort_by_key(|(name, _, _)| *name);
    let file = fs::File::create(destination).map_err(|error| {
        format!(
            "cannot create release archive {}: {error}",
            destination.display()
        )
    })?;
    let encoder = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(file, Compression::best());
    let mut archive = tar::Builder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    for (name, bytes, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive
            .append_data(&mut header, format!("{stem}/{name}"), bytes.as_slice())
            .map_err(|error| format!("cannot append {name} to release archive: {error}"))?;
    }
    archive
        .into_inner()
        .map_err(|error| format!("cannot finalize release archive: {error}"))?
        .finish()
        .map_err(|error| format!("cannot finalize release gzip stream: {error}"))?;
    Ok(())
}

fn validate_archive(path: &Path, archive_name: &str) -> Result<(), String> {
    let stem = archive_name
        .strip_suffix(".tar.gz")
        .ok_or("release archive name must end in .tar.gz")?;
    let file = fs::File::open(path)
        .map_err(|error| format!("cannot open release archive {}: {error}", path.display()))?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let mut paths = BTreeSet::new();
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot read release archive: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("cannot read release entry: {error}"))?;
        if !entry.header().entry_type().is_file() {
            return Err("release archive contains a non-file entry".into());
        }
        let path = entry
            .path()
            .map_err(|error| format!("cannot read release entry path: {error}"))?
            .into_owned();
        if !paths.insert(path.clone()) {
            return Err(format!("release archive repeats {}", path.display()));
        }
        let mut sink = Vec::new();
        entry
            .read_to_end(&mut sink)
            .map_err(|error| format!("cannot read release entry {}: {error}", path.display()))?;
        if sink.is_empty() {
            return Err(format!("release archive entry {} is empty", path.display()));
        }
    }
    let mut expected = ["LICENSE", "NOTICE", "README.md"]
        .into_iter()
        .map(|name| PathBuf::from(format!("{stem}/{name}")))
        .collect::<BTreeSet<_>>();
    expected.insert(PathBuf::from(format!(
        "{stem}/{}",
        if stem.contains("windows") {
            "rustleaks.exe"
        } else {
            "rustleaks"
        }
    )));
    if paths != expected {
        return Err(format!(
            "release archive paths differ: expected {expected:?}, got {paths:?}"
        ));
    }
    Ok(())
}

fn lock_digests(root: &Path, commit: &str) -> Result<Value, String> {
    Ok(json!({
        "Cargo.lock": committed_file_sha256(root, commit, "Cargo.lock")?,
        "cargo-bazel-lock.json": committed_file_sha256(root, commit, "cargo-bazel-lock.json")?,
        "MODULE.bazel.lock": committed_file_sha256(root, commit, "MODULE.bazel.lock")?,
    }))
}

fn committed_file_sha256(root: &Path, commit: &str, path: &str) -> Result<String, String> {
    let object = format!("{commit}:{path}");
    let output = Command::new("git")
        .current_dir(root)
        .args(["cat-file", "blob", &object])
        .output()
        .map_err(|error| format!("failed to read committed release input {object}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git cat-file failed for committed release input {object}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(sha256_bytes(&output.stdout))
}

fn cargo_lock_checksums(root: &Path) -> Result<BTreeMap<(String, String), String>, String> {
    let source = fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|error| format!("cannot read Cargo.lock: {error}"))?;
    let lock: toml::Value =
        toml::from_str(&source).map_err(|error| format!("cannot decode Cargo.lock: {error}"))?;
    let mut checksums = BTreeMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or("Cargo.lock omits packages")?
    {
        let Some(checksum) = package.get("checksum").and_then(toml::Value::as_str) else {
            continue;
        };
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or("Cargo.lock package omits name")?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or("Cargo.lock package omits version")?;
        if checksums
            .insert((name.to_owned(), version.to_owned()), checksum.to_owned())
            .is_some()
        {
            return Err(format!(
                "Cargo.lock repeats checksummed package {name} {version}"
            ));
        }
    }
    Ok(checksums)
}

fn validate_workspace_versions(root: &Path) -> Result<(), String> {
    let module = fs::read_to_string(root.join("MODULE.bazel"))
        .map_err(|error| format!("cannot read MODULE.bazel: {error}"))?;
    for expected in [
        format!("version = \"{RELEASE_VERSION}\""),
        format!("bazel_dep(name = \"rules_rust\", version = \"{RULES_RUST_VERSION}\")"),
        format!("versions = [\"{BAZEL_RUST_VERSION}\"]"),
    ] {
        if !module.contains(&expected) {
            return Err(format!(
                "MODULE.bazel omits exact release setting {expected}"
            ));
        }
    }
    if read_trimmed(&root.join(".bazelversion"))? != BAZEL_VERSION {
        return Err(format!("release Bazel version must be {BAZEL_VERSION}"));
    }
    Ok(())
}

fn validate_reproducibility_proof(
    proof: &Path,
    binary_sha256: &str,
    size: usize,
) -> Result<(), String> {
    let proof = read_json(proof)?;
    if proof["schemaVersion"] != 1
        || proof["identical"] != true
        || proof["sha256"] != binary_sha256
        || proof["size"].as_u64() != Some(size as u64)
    {
        return Err("reproducibility proof does not match the selected binary".into());
    }
    Ok(())
}

fn validate_commit(commit: &str) -> Result<(), String> {
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("release commit must be a full lowercase Git object ID".into());
    }
    Ok(())
}

fn validate_glibc(target: &str, glibc: &str) -> Result<(), String> {
    let is_gnu = target.ends_with("linux-gnu");
    if is_gnu == (glibc == "none") {
        return Err(if is_gnu {
            "GNU release artifacts require a measured glibc baseline".into()
        } else {
            "non-GNU release artifacts must use glibc baseline `none`".into()
        });
    }
    if is_gnu
        && (!glibc.starts_with("GLIBC_")
            || glibc[6..].is_empty()
            || !glibc[6..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'))
    {
        return Err("glibc baseline must use the form GLIBC_X.Y".into());
    }
    Ok(())
}

fn target_config(target: &str) -> Result<&'static str, String> {
    TARGETS
        .iter()
        .find_map(|(candidate, config)| (*candidate == target).then_some(*config))
        .ok_or_else(|| format!("unsupported release target {target}"))
}

fn identity(package: &Value) -> Result<String, String> {
    Ok(format!(
        "{}-{}",
        package["name"].as_str().ok_or("package omits name")?,
        package["version"].as_str().ok_or("package omits version")?
    ))
}

fn is_registry(package: &Value) -> bool {
    package["source"]
        .as_str()
        .is_some_and(|source| source.starts_with("registry+"))
}

fn bazel_mentions(labels: &str, identity: &str) -> bool {
    labels.contains(&format!("@crates//{identity}:"))
        || labels.contains(&format!("crates__{}//:", identity.replace('+', "-")))
}

fn dependency_is_selected(
    package: &Value,
    node: &Value,
    dependency: &Value,
) -> Result<bool, String> {
    let relevant_kind = dependency["dep_kinds"]
        .as_array()
        .ok_or("Cargo dependency omits kinds")?
        .iter()
        .any(|kind| kind["kind"].is_null() || kind["kind"] == "build");
    if !relevant_kind {
        return Ok(false);
    }
    let dependency_name = dependency["name"]
        .as_str()
        .ok_or("Cargo dependency omits name")?;
    let declarations = package["dependencies"]
        .as_array()
        .ok_or("Cargo package omits dependency declarations")?
        .iter()
        .filter(|declaration| {
            declaration["rename"]
                .as_str()
                .or_else(|| declaration["name"].as_str())
                .is_some_and(|name| normalize_dependency_name(name) == dependency_name)
        })
        .collect::<Vec<_>>();
    if declarations.is_empty() {
        return Err(format!(
            "Cargo package omits declaration for resolved dependency {dependency_name}"
        ));
    }
    if declarations
        .iter()
        .any(|declaration| declaration["optional"] == false)
    {
        return Ok(true);
    }
    Ok(active_optional_dependencies(package, node)?.contains(dependency_name))
}

fn active_optional_dependencies(package: &Value, node: &Value) -> Result<BTreeSet<String>, String> {
    let features = package["features"]
        .as_object()
        .ok_or("Cargo package omits features")?;
    let mut pending = node["features"]
        .as_array()
        .ok_or("Cargo node omits active features")?
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "Cargo feature name is not a string".to_owned())
        })
        .collect::<Result<VecDeque<_>, _>>()?;
    let mut expanded = BTreeSet::new();
    let mut active = BTreeSet::new();
    while let Some(feature) = pending.pop_front() {
        if !expanded.insert(feature.clone()) {
            continue;
        }
        let Some(values) = features.get(&feature).and_then(Value::as_array) else {
            active.insert(feature);
            continue;
        };
        for value in values {
            let value = value
                .as_str()
                .ok_or("Cargo feature value is not a string")?;
            if let Some(dependency) = value.strip_prefix("dep:") {
                active.insert(normalize_dependency_name(dependency));
            } else if let Some((dependency, _)) = value.split_once('/') {
                if dependency.strip_suffix('?').is_none() {
                    active.insert(normalize_dependency_name(dependency));
                }
            } else if features.contains_key(value) {
                pending.push_back(value.to_owned());
            } else {
                active.insert(normalize_dependency_name(value));
            }
        }
    }
    Ok(active)
}

fn normalize_dependency_name(name: &str) -> String {
    name.replace('-', "_")
}

fn purl(package: &Value) -> Result<String, String> {
    Ok(format!(
        "pkg:cargo/{}@{}",
        percent_encode(package["name"].as_str().ok_or("package omits name")?),
        percent_encode(package["version"].as_str().ok_or("package omits version")?)
    ))
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            encoded.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read JSON file {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot decode JSON file {}: {error}", path.display()))
}

fn read_trimmed(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn required_pointer<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("release manifest omits {pointer}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::process::Command;

    use serde_json::json;

    use super::{
        active_optional_dependencies, bazel_mentions, compare_bundle_maps, dependency_is_selected,
        lock_digests, percent_encode, sha256_bytes, sha256_file, target_config, validate_commit,
        validate_glibc,
    };

    #[test]
    fn accepts_only_the_release_matrix() {
        assert_eq!(
            target_config("aarch64-unknown-linux-musl").unwrap(),
            "release-linux-aarch64-musl"
        );
        assert!(target_config("wasm32-unknown-unknown").is_err());
    }

    #[test]
    fn validates_candidate_identity_and_libc_evidence() {
        assert!(validate_commit(&"a".repeat(40)).is_ok());
        assert!(validate_commit("main").is_err());
        assert!(validate_glibc("x86_64-unknown-linux-gnu", "GLIBC_2.17").is_ok());
        assert!(validate_glibc("x86_64-unknown-linux-gnu", "none").is_err());
        assert!(validate_glibc("x86_64-apple-darwin", "none").is_ok());
    }

    #[test]
    fn matches_both_crate_universe_label_forms() {
        assert!(bazel_mentions(
            "@crates//serde-1.0.229:serde-1.0.229",
            "serde-1.0.229"
        ));
        assert!(bazel_mentions(
            "@@rules_rust++crate+crates__serde-1.0.229//:serde",
            "serde-1.0.229"
        ));
        assert!(!bazel_mentions("@other//serde", "serde-1.0.229"));
    }

    #[test]
    fn encodes_package_url_segments() {
        assert_eq!(percent_encode("1.1.4+spec-1.1.0"), "1.1.4%2Bspec-1.1.0");
    }

    #[test]
    fn complete_bundle_comparison_rejects_path_and_byte_differences() {
        let first = BTreeMap::from([
            ("manifest.json".to_owned(), b"same".to_vec()),
            ("rustleaks.tar.gz".to_owned(), b"archive".to_vec()),
        ]);
        assert!(compare_bundle_maps(&first, &first).is_ok());

        let missing = BTreeMap::from([("manifest.json".to_owned(), b"same".to_vec())]);
        assert!(compare_bundle_maps(&first, &missing).is_err());

        let changed = BTreeMap::from([
            ("manifest.json".to_owned(), b"same".to_vec()),
            ("rustleaks.tar.gz".to_owned(), b"changed".to_vec()),
        ]);
        assert!(compare_bundle_maps(&first, &changed).is_err());
    }

    #[test]
    fn committed_lock_digests_ignore_worktree_line_endings() {
        let root = std::env::temp_dir().join(format!(
            "rustleaks-release-lock-digests-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir(&root).unwrap();
        let git = |arguments: &[&str]| {
            let output = Command::new("git")
                .current_dir(&root)
                .args(arguments)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {arguments:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        git(&["init", "--quiet"]);
        git(&["config", "core.autocrlf", "false"]);
        git(&["config", "user.name", "Rustleaks test"]);
        git(&["config", "user.email", "rustleaks-test@example.invalid"]);

        let committed = [
            ("Cargo.lock", b"cargo\nlock\n".as_slice()),
            (
                "cargo-bazel-lock.json",
                b"{\n  \"lock\": true\n}\n".as_slice(),
            ),
            (
                "MODULE.bazel.lock",
                b"{\n  \"module\": true\n}\n".as_slice(),
            ),
        ];
        for (path, bytes) in committed {
            fs::write(root.join(path), bytes).unwrap();
        }
        git(&[
            "add",
            "Cargo.lock",
            "cargo-bazel-lock.json",
            "MODULE.bazel.lock",
        ]);
        git(&["commit", "--quiet", "-m", "test committed inputs"]);
        let commit = String::from_utf8(git(&["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();

        for (path, bytes) in committed {
            let crlf = String::from_utf8_lossy(bytes).replace('\n', "\r\n");
            fs::write(root.join(path), crlf).unwrap();
        }

        let digests = lock_digests(&root, &commit).unwrap();
        for (path, bytes) in committed {
            let expected = sha256_bytes(bytes);
            assert_eq!(digests[path].as_str(), Some(expected.as_str()));
            assert_ne!(sha256_file(&root.join(path)).unwrap(), expected);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn optional_dependencies_follow_the_active_feature_expansion() {
        let package = json!({
            "features": {
                "default": ["parse", "display"],
                "parse": ["dep:parser"],
                "display": ["dep:writer"],
                "preserve_order": ["dep:index-map"]
            },
            "dependencies": [
                {"name": "parser", "rename": null, "optional": true},
                {"name": "writer", "rename": null, "optional": true},
                {"name": "index-map", "rename": null, "optional": true}
            ]
        });
        let node = json!({"features": ["default"]});
        let active = active_optional_dependencies(&package, &node).unwrap();
        assert_eq!(active.into_iter().collect::<Vec<_>>(), ["parser", "writer"]);
        let parser = json!({
            "name": "parser",
            "dep_kinds": [{"kind": null, "target": null}]
        });
        let index_map = json!({
            "name": "index_map",
            "dep_kinds": [{"kind": null, "target": null}]
        });
        assert!(dependency_is_selected(&package, &node, &parser).unwrap());
        assert!(!dependency_is_selected(&package, &node, &index_map).unwrap());
    }
}
