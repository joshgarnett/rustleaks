//! Deterministic release bundles, target SBOMs, and dry-run provenance.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use std::process::Command;

use flate2::Compression;
use flate2::bufread::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::tooling::{command_output, sha256_file};

mod corresponding_source;
mod notices;
mod runtime_inputs;

const RELEASE_VERSION: &str = "0.1.0-alpha.9";
const REPOSITORY: &str = "https://github.com/joshgarnett/rustleaks";
const BAZEL_VERSION: &str = "9.2.0";
const RULES_RUST_VERSION: &str = "0.72.0";
const BAZEL_RUST_VERSION: &str = "1.95.0";
const MAX_NATIVE_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NATIVE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RELEASE_METADATA_BYTES: u64 = 8 * 1024 * 1024;

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
        [command] if command == "notices" => notices::generate(root, false),
        [command, flag] if command == "notices" && flag == "--check" => notices::generate(root, true),
        [command, cache, commit, output] if command == "prepare-source" => {
            corresponding_source::prepare(root, Path::new(cache), commit, Path::new(output))?;
            Ok(())
        }
        [command, cache] if command == "fetch-source" => corresponding_source::fetch_inputs(Path::new(cache)),
        [command, archive, commit, target, work, proof] if command == "relink-source" => {
            corresponding_source::relink(root, Path::new(archive), commit, target, Path::new(work), Path::new(proof))
        }
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
                None,
                None,
            )
        }
        [command, binary, bazel_output_root, target, commit, proof, output, glibc, source_proof] if command == "prepare" => prepare(root, Path::new(binary), Path::new(bazel_output_root), target, commit, Path::new(proof), Path::new(output), glibc, Some(Path::new(source_proof)), None),
        [command, binary, bazel_output_root, target, commit, proof, output, map, trace] if command == "prepare-windows" => prepare(root, Path::new(binary), Path::new(bazel_output_root), target, commit, Path::new(proof), Path::new(output), "none", None, Some((Path::new(map), Path::new(trace)))),
        [command, output] if command == "verify" => verify(root, Path::new(output)),
        _ => Err("usage: cargo xtask release-artifact <notices [--check]|fetch-source REPOSITORY_CACHE|prepare-source REPOSITORY_CACHE COMMIT OUTPUT|relink-source ARCHIVE COMMIT TARGET WORK PROOF|compare LEFT RIGHT PROOF|compare-bundles LEFT RIGHT|prepare BINARY BAZEL_OUTPUT_ROOT TARGET COMMIT PROOF OUTPUT GLIBC_BASELINE [SOURCE_PROOF]|prepare-windows BINARY BAZEL_OUTPUT_ROOT TARGET COMMIT PROOF OUTPUT MAP TRACE|verify OUTPUT>".into()),
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
    source_proof: Option<&Path>,
    windows_evidence: Option<(&Path, &Path)>,
) -> Result<(), String> {
    let bazel_config = target_config(target)?;
    validate_commit(commit)?;
    validate_glibc(target, glibc)?;
    validate_binary_size(
        fs::metadata(binary)
            .map_err(|error| format!("cannot inspect release binary: {error}"))?
            .len(),
    )?;
    let binary_bytes = fs::read(binary)
        .map_err(|error| format!("cannot read release binary {}: {error}", binary.display()))?;
    let binary_sha256 = sha256_bytes(&binary_bytes);
    validate_reproducibility_proof(proof, &binary_sha256, binary_bytes.len())?;
    let graph_text = bazel_graph(root, bazel_output_root, bazel_config)?;
    let metadata = cargo_metadata(root, target)?;
    let graph = CargoGraph::from_metadata(&metadata)?;
    graph.reconcile_bazel(&graph_text)?;
    validate_workspace_versions(root)?;
    let mut notices = notices::load(root, target, Some(commit))?;
    notices::reconcile_graph(&notices, &graph)?;
    notices::reconcile_package_documents(root, commit, &notices, &graph)?;
    let runtime_evidence = match (target.ends_with("windows-msvc"), windows_evidence) {
        (true, Some((map, trace))) => Some(runtime_inputs::collect(root, bazel_output_root, target, commit, &binary_sha256, &notices, map, trace)?),
        (false, None) => None,
        _ => return Err("Windows preparation requires the actual configured action and native linker map/trace evidence".into()),
    };
    bind_runtime_evidence(&mut notices, runtime_evidence.as_ref())?;

    prepare_output_directory(output)?;
    let source = if target.ends_with("linux-gnu") {
        let cache = bazel_repository_cache(root, bazel_output_root, bazel_config)?;
        Some(corresponding_source::prepare(root, &cache, commit, output)?)
    } else {
        None
    };
    let source_relink = match (&source, source_proof) {
        (Some(source), Some(proof)) => {
            corresponding_source::validate_relink_proof(
                proof,
                source,
                target,
                commit,
                &binary_sha256,
            )?;
            fs::copy(proof, output.join("source-relink.json"))
                .map_err(|error| format!("cannot retain source relink proof: {error}"))?;
            Some(json!({"file":"source-relink.json","sha256":sha256_file(proof)?}))
        }
        (None, None) => None,
        _ => return Err(
            "GNU releases require a corresponding-source relink proof; other targets must omit it"
                .into(),
        ),
    };
    bind_corresponding_source(&mut notices, source.as_ref(), source_relink.as_ref())?;

    let stem = format!("rustleaks-{RELEASE_VERSION}-{target}");
    let archive_name = format!("{stem}.tar.gz");
    let binary_name = if target.contains("windows") {
        "rustleaks.exe"
    } else {
        "rustleaks"
    };
    let archive = output.join(&archive_name);
    let mut archive_files = archive_documents(root, commit, &notices)?;
    archive_files.insert(
        binary_name.into(),
        (
            binary_bytes.clone(),
            if target.contains("windows") {
                0o644
            } else {
                0o755
            },
        ),
    );
    write_archive(&archive, &stem, &archive_files)?;
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
    let mut provenance = provenance(&evidence, &sbom_name, &sbom_sha256);
    if let Some(source) = &source {
        provenance["predicate"]["runDetails"]["byproducts"]
            .as_array_mut()
            .ok_or("provenance byproducts are missing")?
            .push(json!({"name": source["file"], "digest":{"sha256":source["sha256"]}}));
    }
    if let Some(proof) = &source_relink {
        provenance["predicate"]["runDetails"]["byproducts"]
            .as_array_mut()
            .ok_or("provenance byproducts are missing")?
            .push(json!({"name": proof["file"], "digest":{"sha256":proof["sha256"]}}));
    }
    write_json(&provenance_path, &provenance)?;
    let provenance_sha256 = sha256_file(&provenance_path)?;

    fs::copy(proof, output.join("reproducibility.json")).map_err(|error| {
        format!(
            "cannot copy reproducibility proof {}: {error}",
            proof.display()
        )
    })?;
    let mut sums = format!(
        "{archive_sha256}  {archive_name}\n{sbom_sha256}  {sbom_name}\n{provenance_sha256}  {provenance_name}\n"
    );
    if let Some(source) = &source {
        writeln!(
            sums,
            "{}  {}",
            required_pointer(source, "/sha256")?,
            required_pointer(source, "/file")?
        )
        .expect("writing to a String cannot fail");
    }
    if let Some(proof) = &source_relink {
        writeln!(
            sums,
            "{}  {}",
            required_pointer(proof, "/sha256")?,
            required_pointer(proof, "/file")?
        )
        .expect("writing to a String cannot fail");
    }
    fs::write(output.join("SHA256SUMS"), sums)
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
            "binarySize": binary_bytes.len(),
            "reproducible": true,
            "glibcMinimum": if glibc == "none" { Value::Null } else { Value::String(glibc.to_owned()) },
        },
        "notices": notice_manifest(&notices)?,
        "correspondingSource": source,
        "sourceRelink": source_relink,
        "runtimeInputEvidence": runtime_evidence,
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

#[allow(clippy::too_many_lines)] // Verify the complete bound bundle before extraction or native execution.
fn verify(root: &Path, output: &Path) -> Result<(), String> {
    let manifest = read_json(&output.join("manifest.json"))?;
    let commit = required_pointer(&manifest, "/release/sourceCommit")?;
    validate_commit(commit)?;
    let target = required_pointer(&manifest, "/build/target")?;
    target_config(target)?;
    let binary_size = manifest["artifact"]["binarySize"]
        .as_u64()
        .ok_or("release manifest omits exact binary size")?;
    validate_binary_size(binary_size)?;
    if manifest["release"]["version"] != RELEASE_VERSION {
        return Err("release manifest version differs from this verifier".into());
    }
    let mut notices = notices::load(root, target, Some(commit))?;
    if target.ends_with("windows-msvc") {
        runtime_inputs::validate(
            &notices,
            &manifest["runtimeInputEvidence"],
            target,
            commit,
            required_pointer(&manifest, "/artifact/binarySha256")?,
        )?;
        bind_runtime_evidence(&mut notices, Some(&manifest["runtimeInputEvidence"]))?;
    } else if !manifest["runtimeInputEvidence"].is_null() {
        return Err(
            "non-Windows archive contains unexpected mutable runtime input evidence".into(),
        );
    }
    let source = if target.ends_with("linux-gnu") {
        let source = corresponding_source::verify(
            root,
            &output.join(corresponding_source::source_name()),
            commit,
        )?;
        if manifest["correspondingSource"] != source {
            return Err(
                "release corresponding-source binding differs from verified materials".into(),
            );
        }
        Some(source)
    } else {
        if !manifest["correspondingSource"].is_null() {
            return Err("non-GNU artifact has an unexpected corresponding-source binding".into());
        }
        None
    };
    let source_relink = if let Some(source) = &source {
        let proof = output.join("source-relink.json");
        corresponding_source::validate_relink_proof(
            &proof,
            source,
            target,
            commit,
            required_pointer(&manifest, "/artifact/binarySha256")?,
        )?;
        let binding = json!({"file":"source-relink.json","sha256":sha256_file(&proof)?});
        if manifest["sourceRelink"] != binding {
            return Err("source relink proof binding differs from the verified proof".into());
        }
        Some(binding)
    } else {
        if !manifest["sourceRelink"].is_null() {
            return Err("non-GNU artifact has an unexpected source relink proof".into());
        }
        None
    };
    bind_corresponding_source(&mut notices, source.as_ref(), source_relink.as_ref())?;
    if manifest["notices"] != notice_manifest(&notices)? {
        return Err("release manifest notice index binding differs from committed inputs".into());
    }
    let committed_lock_digests = lock_digests(root, commit)?;
    if manifest.pointer("/build/lockfiles") != Some(&committed_lock_digests) {
        return Err("release manifest lockfile digests do not match the committed sources".into());
    }
    let artifact_name = required_pointer(&manifest, "/artifact/file")?;
    if artifact_name != format!("rustleaks-{RELEASE_VERSION}-{target}.tar.gz") {
        return Err("release archive identity differs from the target and version".into());
    }
    let artifact_sha256 = required_pointer(&manifest, "/artifact/sha256")?;
    let sbom_name = required_pointer(&manifest, "/sbom/file")?;
    let sbom_sha256 = required_pointer(&manifest, "/sbom/sha256")?;
    let provenance_name = required_pointer(&manifest, "/provenance/file")?;
    let provenance_sha256 = required_pointer(&manifest, "/provenance/sha256")?;
    validate_output_directory(
        output,
        artifact_name,
        sbom_name,
        provenance_name,
        source.as_ref(),
    )?;
    if fs::metadata(output.join(artifact_name))
        .map_err(|error| error.to_string())?
        .len()
        > MAX_NATIVE_ARCHIVE_BYTES + 4 * 1024 * 1024
    {
        return Err("release archive exceeds its compressed file limit".into());
    }
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
    if fs::metadata(output.join("SHA256SUMS"))
        .map_err(|error| error.to_string())?
        .len()
        > 4096
    {
        return Err("release checksum list exceeds its size limit".into());
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
    if let Some(source) = &source {
        let expected = format!(
            "{}  {}",
            required_pointer(source, "/sha256")?,
            required_pointer(source, "/file")?
        );
        if !sums.lines().any(|line| line == expected) {
            return Err("SHA256SUMS omits exact corresponding-source entry".into());
        }
    }
    if let Some(proof) = &source_relink {
        let expected = format!(
            "{}  {}",
            required_pointer(proof, "/sha256")?,
            required_pointer(proof, "/file")?
        );
        if !sums.lines().any(|line| line == expected) {
            return Err("SHA256SUMS omits exact source relink proof entry".into());
        }
    }
    if sums.lines().count() != 3 + 2 * usize::from(source.is_some()) {
        return Err("SHA256SUMS has an unexpected number of release entries".into());
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
    for (name, expected) in [
        ("rustleaks:target", target),
        ("rustleaks:source:commit", commit),
    ] {
        if !sbom["metadata"]["properties"]
            .as_array()
            .is_some_and(|properties| {
                properties
                    .iter()
                    .any(|property| property["name"] == name && property["value"] == expected)
            })
        {
            return Err(format!("release SBOM omits exact identity property {name}"));
        }
    }
    notices::reconcile_sbom(&notices, &sbom)?;
    let provenance = read_json(&output.join(provenance_name))?;
    if provenance["predicateType"] != "https://slsa.dev/provenance/v1"
        || provenance
            .pointer("/subject/0/digest/sha256")
            .and_then(Value::as_str)
            != Some(artifact_sha256)
    {
        return Err("release provenance is not bound to the artifact checksum".into());
    }
    if let Some(source) = &source {
        let expected = json!({"name":source["file"],"digest":{"sha256":source["sha256"]}});
        if !provenance["predicate"]["runDetails"]["byproducts"]
            .as_array()
            .is_some_and(|entries| entries.contains(&expected))
        {
            return Err("release provenance omits the corresponding-source digest".into());
        }
    }
    if let Some(proof) = &source_relink {
        let expected = json!({"name":proof["file"],"digest":{"sha256":proof["sha256"]}});
        if !provenance["predicate"]["runDetails"]["byproducts"]
            .as_array()
            .is_some_and(|entries| entries.contains(&expected))
        {
            return Err("release provenance omits the source relink proof digest".into());
        }
    }
    let proof = read_json(&output.join("reproducibility.json"))?;
    if proof["identical"] != true
        || proof["size"].as_u64() != Some(binary_size)
        || proof["sha256"].as_str()
            != manifest
                .pointer("/artifact/binarySha256")
                .and_then(Value::as_str)
    {
        return Err("release reproducibility proof is invalid".into());
    }
    let documents = archive_documents(root, commit, &notices)?;
    validate_archive(
        &output.join(artifact_name),
        artifact_name,
        &documents,
        required_pointer(&manifest, "/artifact/binarySha256")?,
        binary_size,
    )?;
    println!("verified release bundle checksums, SBOM, provenance, and archive contents");
    Ok(())
}

fn validate_output_directory(
    output: &Path,
    artifact_name: &str,
    sbom_name: &str,
    provenance_name: &str,
    source: Option<&Value>,
) -> Result<(), String> {
    let stem = artifact_name
        .strip_suffix(".tar.gz")
        .ok_or("release archive name must end in .tar.gz")?;
    let attestation_name = format!("{stem}.attestation.jsonl");
    let mut actual = BTreeSet::new();
    for entry in
        fs::read_dir(output).map_err(|error| format!("cannot inspect release bundle: {error}"))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
            || entry.metadata().map_err(|error| error.to_string())?.len() == 0
        {
            return Err("release bundle contains a non-file or empty entry".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "release bundle path is not UTF-8")?;
        actual.insert(name);
        if actual.len() > 9 {
            return Err("release bundle exceeds its file inventory limit".into());
        }
    }
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
    if let Some(source) = source {
        expected.insert(required_pointer(source, "/file")?.to_owned());
        expected.insert("source-relink.json".into());
    }
    if actual.contains(&attestation_name) {
        expected.insert(attestation_name);
    }
    if actual != expected {
        return Err(format!(
            "release bundle paths differ: expected {expected:?}, got {actual:?}"
        ));
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

fn bazel_repository_cache(
    root: &Path,
    output_root: &Path,
    config: &str,
) -> Result<std::path::PathBuf, String> {
    let output = command_output(
        Command::new("bazelisk")
            .current_dir(root)
            .arg(format!("--output_user_root={}", output_root.display()))
            .args(["info", &format!("--config={config}"), "repository_cache"]),
    )?;
    let path = std::path::PathBuf::from(output.trim());
    if !path.is_absolute() {
        return Err("Bazel repository cache path is not absolute".into());
    }
    Ok(path)
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

fn bind_runtime_evidence(
    notices: &mut notices::Bundle,
    evidence: Option<&Value>,
) -> Result<(), String> {
    if let Some(evidence) = evidence {
        notices.index["runtime_input_evidence"] = evidence.clone();
        notices.files.insert(
            "licenses/index.json".into(),
            notices::json_bytes(&notices.index)?,
        );
    }
    Ok(())
}

fn notice_manifest(notices: &notices::Bundle) -> Result<Value, String> {
    Ok(json!({
        "index": "licenses/index.json",
        "sha256": sha256_bytes(notices.files.get("licenses/index.json").ok_or("notice index is missing")?),
        "components": notices.index["components"].as_array().ok_or("notice components are missing")?.len(),
        "documents": notices.files.len() - 1,
    }))
}

fn bind_corresponding_source(
    notices: &mut notices::Bundle,
    source: Option<&Value>,
    proof: Option<&Value>,
) -> Result<(), String> {
    match (source, proof) {
        (Some(source), Some(proof)) => {
            notices.index["corresponding_source"] = json!({"archive":source,"relink_proof":proof});
            notices.files.insert(
                "licenses/index.json".into(),
                notices::json_bytes(&notices.index)?,
            );
        }
        (None, None) => {}
        _ => return Err("corresponding source and relink proof must be bound together".into()),
    }
    Ok(())
}

fn archive_documents(
    root: &Path,
    commit: &str,
    notices: &notices::Bundle,
) -> Result<BTreeMap<String, (Vec<u8>, u32)>, String> {
    let mut files = notices
        .files
        .iter()
        .map(|(path, bytes)| (path.clone(), (bytes.clone(), 0o644)))
        .collect::<BTreeMap<_, _>>();
    for path in ["LICENSE", "NOTICE", "README.md"] {
        files.insert(
            path.to_owned(),
            (committed_file_bytes(root, commit, path)?, 0o644),
        );
    }
    Ok(files)
}

fn write_archive(
    destination: &Path,
    stem: &str,
    files: &BTreeMap<String, (Vec<u8>, u32)>,
) -> Result<(), String> {
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
    for (name, (bytes, mode)) in files {
        notices::portable_path(name)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(*mode);
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

struct ExpectedArchiveMember {
    size: u64,
    mode: u32,
    sha256: String,
}

#[allow(clippy::too_many_lines)] // Check each raw header against the trusted inventory before reading its bounded payload.
fn validate_archive(
    path: &Path,
    archive_name: &str,
    documents: &BTreeMap<String, (Vec<u8>, u32)>,
    binary_sha256: &str,
    binary_size: u64,
) -> Result<(), String> {
    validate_binary_size(binary_size)?;
    let stem = archive_name
        .strip_suffix(".tar.gz")
        .ok_or("release archive name must end in .tar.gz")?;
    let binary_name = if stem.contains("windows") {
        "rustleaks.exe"
    } else {
        "rustleaks"
    };
    let binary_mode = if stem.contains("windows") {
        0o644
    } else {
        0o755
    };
    let mut expected = documents
        .iter()
        .map(|(name, (bytes, mode))| {
            (
                format!("{stem}/{name}"),
                ExpectedArchiveMember {
                    size: bytes.len() as u64,
                    mode: *mode,
                    sha256: sha256_bytes(bytes),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    expected.insert(
        format!("{stem}/{binary_name}"),
        ExpectedArchiveMember {
            size: binary_size,
            mode: binary_mode,
            sha256: binary_sha256.into(),
        },
    );
    if expected.len() > 4096 {
        return Err("native archive inventory exceeds its member limit".into());
    }
    let max_path = expected
        .keys()
        .map(String::len)
        .max()
        .ok_or("native archive inventory is empty")?;
    if max_path > 4096 {
        return Err("native archive path exceeds its byte limit".into());
    }
    let mut stream_size = 1024_u64;
    for (path, member) in &expected {
        notices::portable_path(path)?;
        stream_size = add_tar_member_size(stream_size, member.size)?;
        if path.len() > 100 {
            stream_size = add_tar_member_size(stream_size, path.len() as u64 + 1)?;
        }
    }
    let file = canonical_gzip_file(path, stream_size)?;
    let mut archive = tar::Archive::new(GzDecoder::new(BufReader::new(file)).take(stream_size + 1));
    let mut paths = BTreeSet::new();
    let mut previous = String::new();
    let mut long_name: Option<String> = None;
    for (raw_count, entry) in archive
        .entries()
        .map_err(|error| format!("cannot read release archive: {error}"))?
        .raw(true)
        .enumerate()
    {
        if raw_count >= expected.len() * 2 {
            return Err("release archive exceeds its raw member limit".into());
        }
        let mut entry = entry.map_err(|error| format!("cannot read release entry: {error}"))?;
        let header = entry.header();
        if header.as_gnu().is_none()
            || header.uid().map_err(|error| error.to_string())? != 0
            || header.gid().map_err(|error| error.to_string())? != 0
            || header.mtime().map_err(|error| error.to_string())? != 0
        {
            return Err("release entry has unsupported or nondeterministic header metadata".into());
        }
        if header.entry_type().is_gnu_longname() {
            if long_name.is_some()
                || header.path_bytes().as_ref() != b"././@LongLink"
                || header.mode().map_err(|error| error.to_string())? != 0o644
                || entry.size() <= 101
                || entry.size() > max_path as u64 + 1
            {
                return Err(
                    "release archive contains invalid or oversized GNU path metadata".into(),
                );
            }
            let size = entry.size();
            let mut bytes =
                Vec::with_capacity(usize::try_from(size).map_err(|error| error.to_string())?);
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() as u64 != size || bytes.pop() != Some(0) || bytes.contains(&0) {
                return Err(
                    "release GNU path metadata is not one bounded NUL-terminated path".into(),
                );
            }
            let path = String::from_utf8(bytes).map_err(|_| "release GNU path is not UTF-8")?;
            if !expected.contains_key(&path) {
                return Err(format!("unexpected release GNU path {path}"));
            }
            long_name = Some(path);
            continue;
        }
        if !header.entry_type().is_file() {
            return Err(
                "release archive contains unsupported non-file or extended metadata".into(),
            );
        }
        let raw_path = header.path_bytes();
        let path = if let Some(path) = long_name.take() {
            let mut truncated = 100;
            while !path.is_char_boundary(truncated) {
                truncated -= 1;
            }
            if raw_path.as_ref() != &path.as_bytes()[..truncated] {
                return Err("release GNU path header does not match its bounded extension".into());
            }
            path
        } else {
            std::str::from_utf8(raw_path.as_ref())
                .map_err(|_| "release entry path is not UTF-8")?
                .to_owned()
        };
        let member = expected
            .get(&path)
            .ok_or_else(|| format!("unexpected release archive entry {path}"))?;
        if path <= previous || !paths.insert(path.clone()) {
            return Err(format!(
                "release archive entries are duplicated or unordered at {path}"
            ));
        }
        if entry.size() != member.size || member.size == 0 {
            return Err(format!(
                "release entry {path} size differs from the exact expected size"
            ));
        }
        if header.mode().map_err(|error| error.to_string())? != member.mode {
            return Err(format!(
                "release entry {path} mode differs from its expected mode"
            ));
        }
        previous = path.clone();
        let mut digest = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = entry
                .read(&mut buffer)
                .map_err(|error| format!("cannot read release entry {path}: {error}"))?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > member.size {
                return Err("release entry exceeded its exact byte limit".into());
            }
            digest.update(&buffer[..read]);
        }
        let digest = digest.finalize();
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        if count != member.size || encoded != member.sha256 {
            return Err(format!(
                "release entry {path} differs from its committed bytes or selected binary"
            ));
        }
    }
    if long_name.is_some() || paths.len() != expected.len() {
        return Err(
            "release archive omits expected entries or ends with orphaned GNU path metadata".into(),
        );
    }
    let mut reader = archive.into_inner();
    let mut trailer = [0_u8; 512];
    reader
        .read_exact(&mut trailer)
        .map_err(|error| format!("release archive omits its complete tar trailer: {error}"))?;
    let mut extra = [0_u8; 1];
    if trailer != [0; 512] || reader.read(&mut extra).map_err(|error| error.to_string())? != 0 {
        return Err("release archive has noncanonical or excessive tar trailing data".into());
    }
    let mut compressed = reader.into_inner().into_inner();
    if compressed
        .read(&mut extra)
        .map_err(|error| error.to_string())?
        != 0
    {
        return Err("release archive has trailing compressed data or multiple gzip streams".into());
    }
    Ok(())
}

fn add_tar_member_size(total: u64, payload: u64) -> Result<u64, String> {
    let padded = payload
        .checked_add(511)
        .map(|size| size / 512 * 512)
        .ok_or("release archive member size overflow")?;
    total
        .checked_add(512)
        .and_then(|size| size.checked_add(padded))
        .filter(|size| *size <= MAX_NATIVE_ARCHIVE_BYTES)
        .ok_or_else(|| "native archive exceeds its decompressed size limit".into())
}

fn canonical_gzip_file(path: &Path, stream_size: u64) -> Result<fs::File, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("cannot open release archive {}: {error}", path.display()))?;
    if file.metadata().map_err(|error| error.to_string())?.len()
        > stream_size + stream_size / 100 + 65536
    {
        return Err("release archive exceeds its compressed size limit".into());
    }
    let mut header = [0_u8; 10];
    file.read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if header != [31, 139, 8, 0, 0, 0, 0, 0, 2, 255] {
        return Err("release archive has noncanonical or extensible gzip metadata".into());
    }
    file.rewind().map_err(|error| error.to_string())?;
    Ok(file)
}

fn validate_binary_size(size: u64) -> Result<(), String> {
    if size == 0 || size > MAX_NATIVE_BINARY_BYTES {
        return Err("release binary size exceeds the supported artifact range".into());
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
    Ok(sha256_bytes(&committed_file_bytes(root, commit, path)?))
}

fn committed_file_bytes(root: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
    notices::portable_path(path)?;
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
    Ok(output.stdout)
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
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect JSON file {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RELEASE_METADATA_BYTES {
        return Err(format!(
            "release JSON file {} is not a regular file or exceeds its metadata size limit",
            path.display()
        ));
    }
    let file = fs::File::open(path)
        .map_err(|error| format!("cannot open JSON file {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_RELEASE_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read JSON file {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_RELEASE_METADATA_BYTES {
        return Err("release JSON exceeded its metadata size limit while reading".into());
    }
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
    use std::io::{Read as _, Write as _};
    use std::process::Command;

    use serde_json::json;

    use super::{
        active_optional_dependencies, bazel_mentions, bind_corresponding_source,
        compare_bundle_maps, dependency_is_selected, lock_digests, notice_manifest, percent_encode,
        sha256_bytes, sha256_file, target_config, validate_archive, validate_commit,
        validate_glibc, validate_output_directory, write_archive,
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
    fn native_archive_checks_exact_notices_binary_modes_and_inventory() {
        let root = crate::ScopedTempDir::new("notice-archive-validation").unwrap();
        let stem = "rustleaks-1.0-x86_64-unknown-linux-gnu";
        let path = root.path.join(format!("{stem}.tar.gz"));
        let document_names = [
            "LICENSE",
            "NOTICE",
            "README.md",
            "licenses/index.json",
            "licenses/packages/example/LICENSE-MIT",
            "licenses/packages/example/LICENSE-APACHE",
            "licenses/packages/example/src/unicode_tables/LICENSE-UNICODE",
            "licenses/packages/example/nested/NOTICE",
            "licenses/packages/custom/COPYING",
        ];
        let documents = document_names
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    (
                        format!("independent synthetic bytes for {name}\r\n").into_bytes(),
                        0o644,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut files = documents.clone();
        files.insert("rustleaks".into(), (b"synthetic binary".to_vec(), 0o755));
        let digest = sha256_bytes(b"synthetic binary");
        let archive_name = format!("{stem}.tar.gz");
        write_archive(&path, stem, &files).unwrap();
        validate_archive(
            &path,
            &archive_name,
            &documents,
            &digest,
            b"synthetic binary".len() as u64,
        )
        .unwrap();
        let first = fs::read(&path).unwrap();
        write_archive(&path, stem, &files).unwrap();
        assert_eq!(fs::read(&path).unwrap(), first);
        for name in document_names {
            let mut missing = files.clone();
            missing.remove(name);
            write_archive(&path, stem, &missing).unwrap();
            assert!(
                validate_archive(
                    &path,
                    &archive_name,
                    &documents,
                    &digest,
                    b"synthetic binary".len() as u64
                )
                .is_err(),
                "accepted missing {name}"
            );
            let mut changed = files.clone();
            changed.get_mut(name).unwrap().0.push(b'x');
            write_archive(&path, stem, &changed).unwrap();
            assert!(
                validate_archive(
                    &path,
                    &archive_name,
                    &documents,
                    &digest,
                    b"synthetic binary".len() as u64
                )
                .is_err(),
                "accepted changed {name}"
            );
        }
        files.get_mut("rustleaks").unwrap().1 = 0o644;
        write_archive(&path, stem, &files).unwrap();
        assert!(
            validate_archive(
                &path,
                &archive_name,
                &documents,
                &digest,
                b"synthetic binary".len() as u64
            )
            .is_err()
        );
        files.get_mut("rustleaks").unwrap().1 = 0o755;
        files.insert("licenses/unindexed".into(), (b"unindexed".to_vec(), 0o644));
        write_archive(&path, stem, &files).unwrap();
        assert!(
            validate_archive(
                &path,
                &archive_name,
                &documents,
                &digest,
                b"synthetic binary".len() as u64
            )
            .is_err()
        );
    }

    fn write_raw_native_tar(path: &std::path::Path, bytes: &[u8]) {
        let file = fs::File::create(path).unwrap();
        let mut gzip = flate2::GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(file, flate2::Compression::best());
        gzip.write_all(bytes).unwrap();
        gzip.finish().unwrap();
    }

    fn raw_native_header(name: &[u8], kind: u8, size: u64) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        assert!(name.len() <= 100);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::new(kind));
        header.set_size(size);
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    #[test]
    fn native_archive_rejects_unknown_huge_or_extended_members_before_payload_reads() {
        let root = crate::ScopedTempDir::new("native-archive-early-limits").unwrap();
        let path = root.path.join("native.tar.gz");
        let digest = sha256_bytes(b"native binary");
        for (name, kind, size, message) in [
            (
                b"native/unexpected".as_slice(),
                b'0',
                1_u64 << 40,
                "unexpected release archive entry",
            ),
            (
                b"native/rustleaks".as_slice(),
                b'0',
                1_u64 << 40,
                "size differs",
            ),
            (b"native/rustleaks".as_slice(), b'0', 0, "size differs"),
            (
                b"././@LongLink".as_slice(),
                b'L',
                1_u64 << 40,
                "oversized GNU path metadata",
            ),
            (
                b"pax".as_slice(),
                b'x',
                1_u64 << 40,
                "unsupported non-file or extended metadata",
            ),
            (
                b"native/../escape".as_slice(),
                b'0',
                1_u64 << 40,
                "unexpected release archive entry",
            ),
        ] {
            let mut raw = raw_native_header(name, kind, size);
            raw.extend_from_slice(&[0; 1024]);
            write_raw_native_tar(&path, &raw);
            let error = validate_archive(&path, "native.tar.gz", &BTreeMap::new(), &digest, 13)
                .unwrap_err();
            assert!(
                error.contains(message),
                "expected early {message}, got {error}"
            );
        }
        assert!(super::validate_binary_size(0).is_err());
        assert!(super::validate_binary_size(128 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    fn native_archive_accepts_bounded_unicode_long_paths_and_rejects_trailer_changes() {
        let root = crate::ScopedTempDir::new("native-archive-long-path").unwrap();
        let path = root.path.join("native.tar.gz");
        let name = format!("licenses/{}/LICENSE", "unicode-é-".repeat(14));
        let documents =
            BTreeMap::from([(name, (b"synthetic Unicode attribution".to_vec(), 0o644))]);
        let mut files = documents.clone();
        files.insert("rustleaks".into(), (b"native binary".to_vec(), 0o755));
        let digest = sha256_bytes(b"native binary");
        write_archive(&path, "native", &files).unwrap();
        validate_archive(&path, "native.tar.gz", &documents, &digest, 13).unwrap();
        let gzip = fs::read(&path).unwrap();
        let mut raw = Vec::new();
        flate2::read::GzDecoder::new(gzip.as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        write_raw_native_tar(&path, &raw[..raw.len() - 512]);
        assert!(
            validate_archive(&path, "native.tar.gz", &documents, &digest, 13)
                .unwrap_err()
                .contains("complete tar trailer")
        );
        raw.push(b'x');
        write_raw_native_tar(&path, &raw);
        assert!(
            validate_archive(&path, "native.tar.gz", &documents, &digest, 13)
                .unwrap_err()
                .contains("trailing data")
        );
        let mut trailing_gzip = gzip.clone();
        trailing_gzip.push(b'x');
        fs::write(&path, trailing_gzip).unwrap();
        assert!(
            validate_archive(&path, "native.tar.gz", &documents, &digest, 13)
                .unwrap_err()
                .contains("trailing compressed data")
        );
        let mut extra_metadata = gzip;
        extra_metadata[3] = 8;
        fs::write(&path, extra_metadata).unwrap();
        assert!(
            validate_archive(&path, "native.tar.gz", &documents, &digest, 13)
                .unwrap_err()
                .contains("gzip metadata")
        );
    }

    #[test]
    fn native_signed_index_binds_both_source_archive_and_relink_proof() {
        let mut bundle = super::notices::Bundle {
            index: json!({"schema_version":1,"components":[]}),
            files: BTreeMap::from([(
                "licenses/index.json".into(),
                b"independent initial index\n".to_vec(),
            )]),
        };
        let initial = notice_manifest(&bundle).unwrap();
        let source = json!({"file":"source.tar.gz","sha256":"a".repeat(64)});
        let proof = json!({"file":"source-relink.json","sha256":"b".repeat(64)});
        assert!(bind_corresponding_source(&mut bundle, Some(&source), None).is_err());
        bind_corresponding_source(&mut bundle, Some(&source), Some(&proof)).unwrap();
        assert_eq!(
            bundle.index["corresponding_source"],
            json!({"archive":source,"relink_proof":proof})
        );
        let bound = notice_manifest(&bundle).unwrap();
        assert_ne!(initial["sha256"], bound["sha256"]);
        let altered = json!({"file":"source-relink.json","sha256":"c".repeat(64)});
        bind_corresponding_source(&mut bundle, Some(&source), Some(&altered)).unwrap();
        assert_ne!(bound["sha256"], notice_manifest(&bundle).unwrap()["sha256"]);
    }

    #[test]
    fn gnu_bundle_inventory_requires_source_materials_and_proof_together() {
        let root = crate::ScopedTempDir::new("source-bundle-inventory").unwrap();
        for name in [
            "native.tar.gz",
            "native.cdx.json",
            "native.provenance.json",
            "manifest.json",
            "reproducibility.json",
            "SHA256SUMS",
        ] {
            fs::write(root.path.join(name), b"synthetic contents").unwrap();
        }
        let check = |source| {
            validate_output_directory(
                &root.path,
                "native.tar.gz",
                "native.cdx.json",
                "native.provenance.json",
                source,
            )
        };
        check(None).unwrap();
        let source = json!({"file":"source.tar.gz"});
        assert!(check(Some(&source)).is_err());
        fs::write(root.path.join("source.tar.gz"), b"synthetic source archive").unwrap();
        assert!(check(Some(&source)).is_err());
        fs::write(
            root.path.join("source-relink.json"),
            b"synthetic relink proof",
        )
        .unwrap();
        check(Some(&source)).unwrap();
        assert!(check(None).is_err());
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
