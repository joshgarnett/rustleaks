//! Reviewed source inputs and reproducible, offline native notice bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use flate2::read::GzDecoder;
use serde_json::{Value, json};

use super::{
    CargoGraph, TARGETS, cargo_lock_checksums, cargo_metadata, identity, is_registry, purl,
    sha256_bytes,
};

const CATALOG: &str = "release/licenses/index.json";
const PACKAGE_INPUT: &str = "release/notice-inputs/packages/catalog.json";
const RUNTIME_INPUT: &str = "release/notice-inputs/runtime/catalog.json";
const SOURCE_INPUTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "cargo-bazel-lock.json",
    "MODULE.bazel",
    "MODULE.bazel.lock",
    ".bazelrc",
    ".bazelversion",
    "rust-toolchain.toml",
    "bazel/BUILD.bazel",
    "platforms/BUILD.bazel",
    PACKAGE_INPUT,
    RUNTIME_INPUT,
];
const COVERAGE: &str = "Selected release build graph, including build and proc-macro inputs, plus explicitly mapped native runtime notices; this is not a runtime reachability claim.";

pub(super) struct Bundle {
    pub(super) index: Value,
    pub(super) files: BTreeMap<String, Vec<u8>>,
}

#[allow(clippy::too_many_lines)] // Keep collection and generation in one fail-closed transaction.
pub(super) fn generate(root: &Path, check: bool) -> Result<(), String> {
    validate_generated_root(root)?;
    let supplements = read_json(root, PACKAGE_INPUT)?;
    let runtime = read_json(root, RUNTIME_INPUT)?;
    let checksums = cargo_lock_checksums(root)?;
    let mut records = BTreeMap::<String, Value>::new();
    let mut files = BTreeMap::new();
    let mut used_supplements = BTreeSet::new();
    let mut bindings = BTreeMap::new();
    for &path in SOURCE_INPUTS {
        let bytes = if path.starts_with("release/") {
            read_regular(root, path)?
        } else {
            canonical_workspace_file(root, path)?
        };
        bindings.insert(path.to_owned(), sha256_bytes(&bytes));
    }
    for (target, _) in TARGETS {
        let metadata = cargo_metadata(root, target)?;
        let graph = CargoGraph::from_metadata(&metadata)?;
        for id in &graph.reached {
            let package = graph.packages[id];
            let reference = purl(package)?;
            if let Some(record) = records.get_mut(&reference) {
                record["targets"]
                    .as_array_mut()
                    .ok_or("notice targets are not an array")?
                    .push(json!(target));
                continue;
            }
            let (source, documents) = if is_registry(package) {
                registry_documents(
                    package,
                    &checksums,
                    &supplements,
                    &|path| read_regular(root, path),
                    &mut used_supplements,
                )?
            } else {
                workspace_documents(
                    package,
                    &|path| canonical_workspace_file(root, path),
                    &mut bindings,
                )?
            };
            let namespace = format!("packages/{}", identity(package)?);
            let docs = add_documents(&namespace, documents, &mut files)?;
            records.insert(reference.clone(), json!({
                "id": reference, "name": package["name"], "version": package["version"],
                "license_expression": package["license"], "license_file": license_file(package)?,
                "coverage": "selected-release-build-graph", "source": source,
                "targets": [target], "documents": docs,
            }));
        }
    }
    let expected_supplements = components(&supplements)?
        .iter()
        .map(supplement_id)
        .collect::<Result<BTreeSet<_>, _>>()?;
    if used_supplements != expected_supplements {
        return Err(
            "package notice supplements contain stale or unselected package versions".into(),
        );
    }
    for record in runtime_records(&runtime, &|path| read_regular(root, path), &mut files)? {
        let id = string(&record, "id")?.to_owned();
        if records.insert(id.clone(), record).is_some() {
            return Err(format!("duplicate notice component {id}"));
        }
    }
    let mut components = records.into_values().collect::<Vec<_>>();
    for record in &mut components {
        record["targets"]
            .as_array_mut()
            .ok_or("notice targets are not an array")?
            .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    let index = json!({"schema_version":1,"coverage":COVERAGE,"input_sha256":bindings,"runtime_target_coverage":runtime["target_coverage"],"components":components});
    files.insert("index.json".into(), json_bytes(&index)?);
    let destination = root.join("release/licenses");
    if check {
        let actual = read_tree(&destination)?;
        super::compare_bundle_maps(&files, &actual).map_err(|error| format!("native notice catalog is stale; regenerate with cargo xtask release-artifact notices: {error}"))?;
    } else {
        validate_generated_root(root)?;
        // Remove only previously generated files, after rejecting unexpected entries.
        if destination.exists() {
            let previous = read_tree(&destination)?;
            validate_generated_inventory(&previous)?;
            for path in previous.keys() {
                fs::remove_file(destination.join(path))
                    .map_err(|error| format!("cannot replace generated notice {path}: {error}"))?;
            }
        }
        for (path, bytes) in &files {
            let path = destination.join(path);
            fs::create_dir_all(path.parent().ok_or("notice path has no parent")?)
                .map_err(|error| error.to_string())?;
            fs::write(&path, bytes)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        }
    }
    println!(
        "{} deterministic native notice catalog ({} components, {} files)",
        if check { "checked" } else { "generated" },
        index["components"].as_array().map_or(0, Vec::len),
        files.len()
    );
    Ok(())
}

fn validate_generated_inventory(files: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    if files.is_empty() {
        return Ok(());
    }
    let index: Value = serde_json::from_slice(
        files
            .get("index.json")
            .ok_or("refusing to replace a notice tree without its generated index")?,
    )
    .map_err(|error| format!("cannot read previous generated notice index: {error}"))?;
    let mut expected = BTreeSet::from(["index.json".to_owned()]);
    for component in components(&index)? {
        for document in array(component, "documents")? {
            let path = string(document, "archive_path")?
                .strip_prefix("licenses/")
                .ok_or("previous generated notice path escapes its tree")?;
            portable_path(path)?;
            expected.insert(path.to_owned());
        }
    }
    if let Some(unexpected) = files.keys().find(|path| !expected.contains(*path)) {
        return Err(format!(
            "refusing to delete unindexed file from generated notice tree: {unexpected}"
        ));
    }
    Ok(())
}

type Documents = BTreeMap<String, (Vec<u8>, Value)>;

fn workspace_documents(
    package: &Value,
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
    bindings: &mut BTreeMap<String, String>,
) -> Result<(Value, Documents), String> {
    let name = string(package, "name")?;
    let paths = workspace_paths(name)?;
    let manifest = format!("crates/{name}/Cargo.toml");
    bindings.insert(manifest.clone(), sha256_bytes(&read(&manifest)?));
    let mut documents = BTreeMap::new();
    for path in paths {
        let bytes = read(path)?;
        bindings.insert((*path).to_owned(), sha256_bytes(&bytes));
        documents.insert(
            (*path).to_owned(),
            (bytes, json!({"kind":"workspace","path":path})),
        );
    }
    Ok((json!({"kind":"workspace","manifest":manifest}), documents))
}

fn workspace_paths(name: &str) -> Result<&'static [&'static str], String> {
    Ok(match name {
        "rustleaks-cli" | "rustleaks-report" | "rustleaks-sources" => &["LICENSE"],
        "rustleaks-core" => &[
            "crates/rustleaks-core/LICENSE",
            "crates/rustleaks-core/NOTICE",
        ],
        "rustleaks-bzip2" => &[
            "crates/rustleaks-bzip2/LICENSE-MIT",
            "crates/rustleaks-bzip2/LICENSE-APACHE",
        ],
        "rustleaks-sevenz" => &["crates/rustleaks-sevenz/LICENSE"],
        "rustleaks-rar-codec" => &["crates/rustleaks-rar-codec/COPYING"],
        _ => {
            return Err(format!(
                "workspace package {name} has no reviewed notice mapping"
            ));
        }
    })
}

fn canonical_workspace_file(root: &Path, path: &str) -> Result<Vec<u8>, String> {
    let bytes = read_regular(root, path)?;
    // Compare against Git's clean-filter identity without writing objects or
    // the index. This supports uncommitted edits while preserving opaque
    // upstream bytes and the exact canonical bytes on CRLF checkouts.
    let canonical = git_blob_identity(root, Some(path), &bytes)?;
    if git_blob_identity(root, None, &bytes)? == canonical {
        return Ok(bytes);
    }
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut position = 0;
    while position < bytes.len() {
        if bytes.get(position..position + 2) == Some(b"\r\n") {
            position += 1;
        }
        normalized.push(bytes[position]);
        position += 1;
    }
    if git_blob_identity(root, None, &normalized)? != canonical {
        return Err(format!(
            "workspace notice input {path} uses a clean filter that the exact-byte generator cannot reproduce"
        ));
    }
    Ok(normalized)
}

fn git_blob_identity(root: &Path, path: Option<&str>, bytes: &[u8]) -> Result<String, String> {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = path {
        command.arg(format!("--path={path}"));
    } else {
        command.arg("--no-filters");
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot compute canonical workspace blob identity: {error}"))?;
    child
        .stdin
        .take()
        .ok_or("Git blob identity input is unavailable")?
        .write_all(bytes)
        .map_err(|error| format!("cannot send workspace bytes to Git: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "Git could not identify canonical workspace bytes: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| error.to_string())
}

fn registry_documents(
    package: &Value,
    checksums: &BTreeMap<(String, String), String>,
    supplements: &Value,
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
    used: &mut BTreeSet<String>,
) -> Result<(Value, Documents), String> {
    let name = string(package, "name")?;
    let version = string(package, "version")?;
    let checksum = checksums
        .get(&(name.to_owned(), version.to_owned()))
        .ok_or_else(|| format!("no locked archive checksum for {name} {version}"))?;
    let archive = cached_archive(&format!("{name}-{version}.crate"), checksum)?;
    let members = read_crate_archive(&archive, &format!("{name}-{version}"), checksum)?;
    let declared = license_file(package)?;
    let mut documents = select_archive_documents(&members, declared.as_deref(), checksum)?;
    let matching = components(supplements)?
        .iter()
        .filter(|entry| entry["name"] == name && entry["version"] == version)
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(format!("duplicate notice supplements for {name} {version}"));
    }
    if let Some(supplement) = matching.first() {
        validate_supplement(package, checksum, &members, supplement)?;
        used.insert(supplement_id(supplement)?);
        for document in array(supplement, "documents")? {
            let path = string(document, "original_path")?;
            let input = string(document, "input_path")?;
            if !input.starts_with("release/notice-inputs/packages/") {
                return Err("package notice supplement has an unexpected input root".into());
            }
            let bytes = read(input)?;
            verify_digest(&bytes, string(document, "sha256")?, input)?;
            if documents.insert(path.to_owned(), (bytes, json!({"kind":"source-supplement","repository":supplement["repository"],"revision":supplement["revision"],"vcs_path":supplement["vcs_path"],"archive_sha256":checksum,"url":document["url"]}))).is_some() {
                return Err(format!("supplement duplicates archive notice {path}"));
            }
        }
    }
    if documents.is_empty() {
        return Err(format!(
            "{name} {version} has no license text; add an exact-source reviewed supplement"
        ));
    }
    Ok((
        json!({"kind":"registry","registry":package["source"],"archive_sha256":checksum}),
        documents,
    ))
}

fn select_archive_documents(
    members: &BTreeMap<String, Vec<u8>>,
    declared: Option<&str>,
    checksum: &str,
) -> Result<Documents, String> {
    if let Some(path) = declared
        && !members.contains_key(path)
    {
        return Err(format!("archive omits declared license-file {path}"));
    }
    Ok(members
        .iter()
        .filter(|(path, _)| notice_name(path) || declared == Some(path.as_str()))
        .map(|(path, bytes)| {
            (
                path.clone(),
                (
                    bytes.clone(),
                    json!({"kind":"registry-archive","archive_sha256":checksum}),
                ),
            )
        })
        .collect())
}

fn validate_supplement(
    package: &Value,
    checksum: &str,
    members: &BTreeMap<String, Vec<u8>>,
    supplement: &Value,
) -> Result<(), String> {
    let vcs: Value = serde_json::from_slice(
        members
            .get(".cargo_vcs_info.json")
            .ok_or("supplemented archive omits VCS identity")?,
    )
    .map_err(|error| error.to_string())?;
    if supplement["name"] != package["name"]
        || supplement["version"] != package["version"]
        || supplement["archive_sha256"] != checksum
        || supplement["revision"] != vcs["git"]["sha1"]
        || supplement["vcs_path"] != vcs["path_in_vcs"]
        || supplement["repository"] != package["repository"]
    {
        return Err("notice supplement source checksum, repository, or VCS pin does not match the locked crate".into());
    }
    super::validate_commit(string(supplement, "revision")?)?;
    portable_path(string(supplement, "vcs_path")?)?;
    for document in array(supplement, "documents")? {
        portable_path(string(document, "original_path")?)?;
        let repository = string(supplement, "repository")?
            .strip_prefix("https://github.com/")
            .ok_or("notice supplement repository has no reviewed raw-file route")?;
        let expected = format!(
            "https://raw.githubusercontent.com/{repository}/{}/{}",
            string(supplement, "revision")?,
            string(document, "original_path")?
        );
        if string(document, "url")? != expected {
            return Err(
                "notice supplement URL is not bound to its exact source pin and path".into(),
            );
        }
    }
    Ok(())
}

fn supplement_id(entry: &Value) -> Result<String, String> {
    Ok(format!(
        "{}@{}",
        string(entry, "name")?,
        string(entry, "version")?
    ))
}

fn license_file(package: &Value) -> Result<Option<String>, String> {
    let Some(path) = package["license_file"].as_str() else {
        return Ok(None);
    };
    let path = Path::new(path);
    let relative = if path.is_absolute() {
        path.strip_prefix(
            Path::new(string(package, "manifest_path")?)
                .parent()
                .ok_or("package manifest has no parent")?,
        )
        .map_err(|_| "license-file escapes its package")?
    } else {
        path
    };
    let path = relative
        .to_str()
        .ok_or("license-file is not UTF-8")?
        .replace('\\', "/");
    portable_path(&path)?;
    Ok(Some(path))
}

fn cached_archive(name: &str, checksum: &str) -> Result<Vec<u8>, String> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|home| PathBuf::from(home).join(".cargo"))
        })
        .ok_or("cannot locate Cargo archive cache")?;
    let cache = cargo_home.join("registry/cache");
    let mut found = Vec::new();
    for directory in
        fs::read_dir(&cache).map_err(|error| format!("cannot read Cargo archive cache: {error}"))?
    {
        let path = directory
            .map_err(|error| error.to_string())?
            .path()
            .join(name);
        if path.is_file() {
            let bytes = fs::read(&path).map_err(|error| error.to_string())?;
            if sha256_bytes(&bytes) != checksum {
                return Err(format!("cached archive {name} does not match Cargo.lock"));
            }
            found.push(bytes);
        }
    }
    found.pop().ok_or_else(|| format!("locked archive {name} is unavailable; populate the Cargo cache before regenerating notices"))
}

fn read_crate_archive(
    bytes: &[u8],
    identity: &str,
    checksum: &str,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    if sha256_bytes(bytes) != checksum {
        return Err("crate archive checksum mismatch".into());
    }
    let prefix = format!("{identity}/");
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut files = BTreeMap::new();
    let mut cases = BTreeSet::new();
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        let path = entry
            .path()
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or("crate archive path is not UTF-8")?
            .to_owned();
        let relative = path
            .strip_prefix(&prefix)
            .ok_or("crate archive path escapes package root")?;
        portable_path(relative)?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(format!(
                "crate archive contains unsupported non-file {path}"
            ));
        }
        if !cases.insert(relative.to_lowercase()) {
            return Err(format!(
                "crate archive has duplicate or case-conflicting path {relative}"
            ));
        }
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|error| error.to_string())?;
        files.insert(relative.to_owned(), contents);
    }
    Ok(files)
}

fn notice_name(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_uppercase();
    [
        "LICENSE",
        "LICENCE",
        "NOTICE",
        "COPYING",
        "COPYRIGHT",
        "UNLICENSE",
    ]
    .iter()
    .any(|prefix| {
        name == *prefix
            || name
                .strip_prefix(*prefix)
                .is_some_and(|suffix| suffix.starts_with(['-', '_', '.']))
    })
}

#[allow(clippy::too_many_lines)] // Preserve each reviewed component's complete source and document provenance together.
fn runtime_records(
    runtime: &Value,
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Vec<Value>, String> {
    validate_target_coverage(runtime, None)?;
    let mut records = Vec::new();
    let mut covered = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for component in components(runtime)? {
        let id = string(component, "id")?;
        portable_path(id)?;
        if id.contains('/') || !ids.insert(id.to_lowercase()) || component["status"] != "complete" {
            return Err(format!(
                "runtime component {id} is duplicated, unsafe, or incomplete"
            ));
        }
        for field in ["name", "version"] {
            string(component, field)?;
        }
        if !component["source"].is_object()
            || component["source"]
                .as_object()
                .is_none_or(serde_json::Map::is_empty)
            || component["coverage"].is_null()
        {
            return Err(format!(
                "runtime component {id} omits source or coverage evidence"
            ));
        }
        let mut targets = BTreeSet::new();
        for target in array(component, "targets")? {
            let target = target.as_str().ok_or("runtime target is not a string")?;
            super::target_config(target)?;
            if !targets.insert(target) {
                return Err(format!("runtime component {id} repeats target {target}"));
            }
            covered.insert(target);
        }
        if targets.is_empty() {
            return Err(format!("runtime component {id} has no targets"));
        }
        let mut documents = BTreeMap::new();
        for document in array(component, "documents")? {
            let path = string(document, "original_path")?;
            portable_path(path)?;
            let input = string(document, "input_path")?;
            let stored_path = input
                .strip_prefix(&format!("release/notice-inputs/runtime/{id}/"))
                .ok_or("runtime notice input escapes its component input root")?;
            portable_path(stored_path)?;
            let bytes = read(input)?;
            verify_digest(&bytes, string(document, "sha256")?, input)?;
            if documents
                .insert(stored_path.to_owned(), (bytes, document.clone()))
                .is_some()
            {
                return Err(format!(
                    "runtime component {id} repeats document {stored_path}"
                ));
            }
        }
        let mut record = component.clone();
        record["id"] = json!(format!("runtime:{id}"));
        record["targets"] = json!(targets);
        record["documents"] = json!(add_documents(&format!("runtime/{id}"), documents, files)?);
        records.push(record);
    }
    if covered != TARGETS.iter().map(|(target, _)| *target).collect() {
        return Err("runtime notice catalog does not cover all eight release targets".into());
    }
    Ok(records)
}

fn validate_target_coverage(runtime: &Value, selected: Option<&str>) -> Result<(), String> {
    let mut targets = BTreeSet::new();
    for record in array(runtime, "target_coverage")? {
        let target = string(record, "target")?;
        super::target_config(target)?;
        if !targets.insert(target) || record["evidence"].is_null() {
            return Err(format!(
                "runtime target {target} repeats or omits coverage evidence"
            ));
        }
        let status = string(record, "status")?;
        if selected == Some(target) && status != "complete" {
            return Err(format!(
                "runtime coverage for {target} is {status}; resolve the reviewed target coverage before packaging"
            ));
        }
    }
    if targets != TARGETS.iter().map(|(target, _)| *target).collect() {
        return Err("runtime target coverage must describe all eight release targets".into());
    }
    Ok(())
}

fn add_documents(
    namespace: &str,
    documents: Documents,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<Vec<Value>, String> {
    if documents.is_empty() {
        return Err(format!("notice component {namespace} has no documents"));
    }
    let mut result = Vec::new();
    let mut cases = files
        .keys()
        .map(|path| path.to_lowercase())
        .collect::<BTreeSet<_>>();
    for (original, (bytes, origin)) in documents {
        portable_path(&original)?;
        let path = format!("{namespace}/{original}");
        portable_path(&path)?;
        if bytes.is_empty() || !cases.insert(path.to_lowercase()) {
            return Err(format!(
                "empty, duplicate, or case-conflicting notice {path}"
            ));
        }
        result.push(json!({"original_path":origin.get("original_path").cloned().unwrap_or_else(|| json!(original)),"archive_path":format!("licenses/{path}"),"sha256":sha256_bytes(&bytes),"origin":origin}));
        files.insert(path, bytes);
    }
    Ok(result)
}

#[allow(clippy::too_many_lines)] // Validate committed source identities before selecting a target's exact notice bytes.
pub(super) fn load(root: &Path, target: &str, commit: Option<&str>) -> Result<Bundle, String> {
    super::target_config(target)?;
    let read = |path: &str| match commit {
        Some(commit) => super::committed_file_bytes(root, commit, path),
        None => read_regular(root, path),
    };
    let index: Value = serde_json::from_slice(&read(CATALOG)?)
        .map_err(|error| format!("cannot decode native notice catalog: {error}"))?;
    validate_bindings(&index, &read)?;
    let runtime: Value =
        serde_json::from_slice(&read(RUNTIME_INPUT)?).map_err(|error| error.to_string())?;
    validate_target_coverage(&runtime, Some(target))?;
    if index["runtime_target_coverage"] != runtime["target_coverage"] {
        return Err("generated runtime target coverage differs from reviewed inputs".into());
    }
    let expected_runtime = runtime_records(&runtime, &read, &mut BTreeMap::new())?
        .into_iter()
        .map(|record| Ok((string(&record, "id")?.to_owned(), record)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let actual_runtime = components(&index)?
        .iter()
        .filter(|record| {
            record["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("runtime:"))
        })
        .map(|record| Ok((string(record, "id")?.to_owned(), record.clone())))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if actual_runtime != expected_runtime {
        return Err("generated runtime notices differ from reviewed source inputs".into());
    }
    validate_locked_sources(&index, &read("Cargo.lock")?)?;
    let mut selected = Vec::new();
    let mut files = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let mut cases = BTreeSet::new();
    for component in components(&index)? {
        let id = string(component, "id")?;
        if !ids.insert(id) {
            return Err(format!("notice catalog repeats component {id}"));
        }
        let targets = array(component, "targets")?;
        for target in targets {
            super::target_config(target.as_str().ok_or("notice target is not a string")?)?;
        }
        if !targets.iter().any(|candidate| candidate == target) {
            continue;
        }
        for document in array(component, "documents")? {
            let path = string(document, "archive_path")?;
            portable_path(path)?;
            if !path.starts_with("licenses/")
                || path == "licenses/index.json"
                || !cases.insert(path.to_lowercase())
            {
                return Err(format!(
                    "notice catalog contains invalid or conflicting archive path {path}"
                ));
            }
            let bytes = read(&format!("release/{path}"))?;
            verify_digest(&bytes, string(document, "sha256")?, path)?;
            files.insert(path.to_owned(), bytes);
        }
        if array(component, "documents")?.is_empty() {
            return Err(format!("notice component {id} has no documents"));
        }
        selected.push(component.clone());
    }
    if !selected.iter().any(|record| {
        record["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("runtime:"))
    }) {
        return Err(format!("no reviewed runtime notice coverage for {target}"));
    }
    selected.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let runtime_coverage = array(&runtime, "target_coverage")?
        .iter()
        .find(|record| record["target"] == target)
        .ok_or("runtime target coverage disappeared")?;
    let target_index = json!({"schema_version":1,"target":target,"coverage":COVERAGE,"runtime_target_coverage":runtime_coverage,"components":selected});
    files.insert("licenses/index.json".into(), json_bytes(&target_index)?);
    Ok(Bundle {
        index: target_index,
        files,
    })
}

fn validate_locked_sources(index: &Value, lock: &[u8]) -> Result<(), String> {
    let lock: toml::Value =
        toml::from_str(std::str::from_utf8(lock).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let locked = lock["package"]
        .as_array()
        .ok_or("Cargo.lock omits packages")?;
    for component in components(index)? {
        if component["source"]["kind"] != "registry" {
            continue;
        }
        let name = string(component, "name")?;
        let version = string(component, "version")?;
        let package = locked
            .iter()
            .find(|entry| {
                entry.get("name").and_then(toml::Value::as_str) == Some(name)
                    && entry.get("version").and_then(toml::Value::as_str) == Some(version)
            })
            .ok_or_else(|| {
                format!("notice component {name} {version} is absent from Cargo.lock")
            })?;
        if package.get("checksum").and_then(toml::Value::as_str)
            != component["source"]["archive_sha256"].as_str()
            || package.get("source").and_then(toml::Value::as_str)
                != component["source"]["registry"].as_str()
        {
            return Err(format!(
                "notice component {name} {version} has a stale source pin"
            ));
        }
    }
    Ok(())
}

fn validate_bindings(
    index: &Value,
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    let bindings = index["input_sha256"]
        .as_object()
        .ok_or("notice catalog omits input bindings")?;
    for &required in SOURCE_INPUTS {
        if !bindings.contains_key(required) {
            return Err(format!("notice catalog omits binding {required}"));
        }
    }
    for (path, expected) in bindings {
        portable_path(path)?;
        verify_digest(
            &read(path)?,
            expected.as_str().ok_or("notice binding is not a digest")?,
            path,
        )?;
    }
    Ok(())
}

pub(super) fn reconcile_graph(bundle: &Bundle, graph: &CargoGraph<'_>) -> Result<(), String> {
    let expected = graph
        .reached
        .iter()
        .map(|id| purl(graph.packages[id]))
        .collect::<Result<BTreeSet<_>, _>>()?;
    reconcile_identities(bundle, &expected)?;
    for id in &graph.reached {
        let package = graph.packages[id];
        let reference = purl(package)?;
        let record = components(&bundle.index)?
            .iter()
            .find(|record| record["id"] == reference)
            .ok_or("notice component disappeared")?;
        if record["license_expression"] != package["license"]
            || record["license_file"] != json!(license_file(package)?)
        {
            return Err(format!(
                "notice metadata differs from selected package {reference}"
            ));
        }
    }
    Ok(())
}

pub(super) fn reconcile_package_documents(
    root: &Path,
    commit: &str,
    bundle: &Bundle,
    graph: &CargoGraph<'_>,
) -> Result<(), String> {
    let read = |path: &str| super::committed_file_bytes(root, commit, path);
    let supplements: Value =
        serde_json::from_slice(&read(PACKAGE_INPUT)?).map_err(|error| error.to_string())?;
    let checksums = cargo_lock_checksums(root)?;
    let mut used_supplements = BTreeSet::new();
    for id in &graph.reached {
        let package = graph.packages[id];
        let (source, documents) = if is_registry(package) {
            registry_documents(
                package,
                &checksums,
                &supplements,
                &read,
                &mut used_supplements,
            )?
        } else {
            workspace_documents(package, &read, &mut BTreeMap::new())?
        };
        reconcile_package_record(bundle, package, &source, documents)?;
    }
    Ok(())
}

fn reconcile_package_record(
    bundle: &Bundle,
    package: &Value,
    source: &Value,
    documents: Documents,
) -> Result<(), String> {
    let reference = purl(package)?;
    let record = components(&bundle.index)?
        .iter()
        .find(|record| record["id"] == reference)
        .ok_or_else(|| format!("selected package {reference} has no notice catalog record"))?;
    let mut expected_files = BTreeMap::new();
    let expected_documents = add_documents(
        &format!("packages/{}", identity(package)?),
        documents,
        &mut expected_files,
    )?;
    if record["source"] != *source || record["documents"] != json!(expected_documents) {
        return Err(format!(
            "notice catalog omits or changes source documents for {reference}; regenerate from the locked archive and reviewed inputs"
        ));
    }
    for (path, bytes) in expected_files {
        if bundle.files.get(&format!("licenses/{path}")) != Some(&bytes) {
            return Err(format!(
                "notice bytes for {reference} document {path} differ from their owning source"
            ));
        }
    }
    Ok(())
}

pub(super) fn reconcile_sbom(bundle: &Bundle, sbom: &Value) -> Result<(), String> {
    let mut expected = BTreeSet::new();
    for component in array(sbom, "components")?
        .iter()
        .chain(std::iter::once(&sbom["metadata"]["component"]))
    {
        let id = string(component, "purl")?;
        if !expected.insert(id.to_owned()) {
            return Err(format!("SBOM repeats notice component {id}"));
        }
        let record = components(&bundle.index)?
            .iter()
            .find(|record| record["id"] == id)
            .ok_or_else(|| format!("SBOM component {id} has no committed notice coverage"))?;
        if record["source"]["kind"] == "registry" {
            let matches = array(component, "hashes")?.iter().any(|hash| {
                hash["alg"] == "SHA-256" && hash["content"] == record["source"]["archive_sha256"]
            });
            if !matches {
                return Err(format!(
                    "SBOM component {id} differs from the locked notice source checksum"
                ));
            }
        }
        if component != &sbom["metadata"]["component"] {
            if let Some(expression) = record["license_expression"].as_str() {
                if component["licenses"] != json!([{"expression":expression}]) {
                    return Err(format!(
                        "SBOM component {id} has different declared license metadata"
                    ));
                }
            } else if let Some(path) = record["license_file"].as_str() {
                let basename = path
                    .rsplit('/')
                    .next()
                    .ok_or("license file has no basename")?;
                if component["licenses"]
                    != json!([{"license":{"name":format!("License file: {basename}")}}])
                {
                    return Err(format!(
                        "SBOM component {id} has different custom license metadata"
                    ));
                }
            }
        }
    }
    reconcile_identities(bundle, &expected)
}

fn reconcile_identities(bundle: &Bundle, expected: &BTreeSet<String>) -> Result<(), String> {
    let actual = components(&bundle.index)?
        .iter()
        .map(|component| string(component, "id"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|id| id.starts_with("pkg:cargo/"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if &actual != expected {
        return Err(format!(
            "native notice package coverage differs: missing {:?}, extra {:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(expected).collect::<Vec<_>>()
        ));
    }
    Ok(())
}

pub(super) fn json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn components(value: &Value) -> Result<&Vec<Value>, String> {
    if value["schema_version"] != 1 {
        return Err("unsupported native notice catalog schema".into());
    }
    array(value, "components")
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("notice record omits array {key}"))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("notice record omits string {key}"))
}

pub(super) fn portable_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains(['\\', ':', '\0', '<', '>', '"', '|', '?', '*'])
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || windows_device_name(part)
                || part.bytes().any(|byte| byte < 0x20)
        })
    {
        return Err(format!("unsafe native notice path {path:?}"));
    }
    Ok(())
}

fn windows_device_name(part: &str) -> bool {
    let base = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(*prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        })
}

fn read_regular(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    portable_path(relative)?;
    let mut current = root.to_path_buf();
    for part in relative.split('/') {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("cannot inspect notice input {relative}: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("notice input {relative} contains a symlink"));
        }
    }
    if !current.is_file() {
        return Err(format!("notice input {relative} is not a regular file"));
    }
    fs::read(&current).map_err(|error| format!("cannot read notice input {relative}: {error}"))
}

#[cfg(test)]
fn read_verified(root: &Path, path: &str, expected: &str) -> Result<Vec<u8>, String> {
    let bytes = read_regular(root, path)?;
    verify_digest(&bytes, expected, path)?;
    Ok(bytes)
}

fn verify_digest(bytes: &[u8], expected: &str, path: &str) -> Result<(), String> {
    if bytes.is_empty() || sha256_bytes(bytes) != expected {
        return Err(format!(
            "notice input {path} is empty or has changed; regenerate only after reviewing its source identity"
        ));
    }
    Ok(())
}

fn read_json(root: &Path, path: &str) -> Result<Value, String> {
    serde_json::from_slice(&read_regular(root, path)?)
        .map_err(|error| format!("cannot decode {path}: {error}"))
}

fn read_tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    fn visit(
        root: &Path,
        relative: &Path,
        files: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(root.join(relative)).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = relative.join(entry.file_name());
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() {
                visit(root, &path, files)?;
            } else if kind.is_file() {
                let path = path
                    .to_str()
                    .ok_or("non-UTF-8 notice path")?
                    .replace('\\', "/");
                files.insert(path.clone(), read_regular(root, &path)?);
            } else {
                return Err("generated notice tree contains a non-file entry".into());
            }
        }
        Ok(())
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect generated notice directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("generated notice root must be a real directory, not a symlink or file".into());
    }
    let mut files = BTreeMap::new();
    visit(root, Path::new(""), &mut files)?;
    Ok(files)
}

fn validate_generated_root(root: &Path) -> Result<(), String> {
    let mut path = root.to_path_buf();
    for part in ["release", "licenses"] {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(format!(
                    "generated notice output must use real directories; refusing symlink or file {}",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "cannot inspect generated notice output {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crate_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, format!("example-1.0.0/{name}"), *bytes)
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn archive_selection_preserves_dual_custom_and_nested_unicode_notices() {
        let bytes = crate_bytes(&[
            ("LICENSE-MIT", b"synthetic contributor MIT notice\r\n"),
            ("LICENSE-APACHE", b"synthetic Apache terms\n"),
            (
                "src/unicode_tables/LICENSE-UNICODE",
                b"synthetic Unicode terms\n",
            ),
            ("nested/NOTICE", b"synthetic nested attribution\n"),
            ("terms.txt", b"synthetic custom declared terms\n"),
            ("src/lib.rs", b"ignored source"),
        ]);
        let checksum = sha256_bytes(&bytes);
        let members = read_crate_archive(&bytes, "example-1.0.0", &checksum).unwrap();
        let docs = select_archive_documents(&members, Some("terms.txt"), &checksum).unwrap();
        let expected = [
            "LICENSE-APACHE",
            "LICENSE-MIT",
            "nested/NOTICE",
            "src/unicode_tables/LICENSE-UNICODE",
            "terms.txt",
        ];
        assert_eq!(
            docs.keys().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            docs["LICENSE-MIT"].0,
            b"synthetic contributor MIT notice\r\n"
        );
        assert_eq!(
            docs["src/unicode_tables/LICENSE-UNICODE"].0,
            b"synthetic Unicode terms\n"
        );
        assert!(select_archive_documents(&members, Some("absent-terms.txt"), &checksum).is_err());
        assert!(read_crate_archive(&bytes, "example-1.0.0", &"0".repeat(64)).is_err());
        assert!(read_crate_archive(&bytes, "other-1.0.0", &checksum).is_err());
    }

    #[test]
    fn archive_source_order_does_not_change_notice_bytes_or_index() {
        let first = crate_bytes(&[("LICENSE", b"MIT"), ("COPYING", b"custom")]);
        let second = crate_bytes(&[("COPYING", b"custom"), ("LICENSE", b"MIT")]);
        let collect = |bytes: &[u8]| {
            let members = read_crate_archive(bytes, "example-1.0.0", &sha256_bytes(bytes)).unwrap();
            // The original archive checksum is independently recorded in source identity.
            let docs = select_archive_documents(&members, None, "same-source-identity").unwrap();
            let mut files = BTreeMap::new();
            let index = add_documents("packages/example-1.0.0", docs, &mut files).unwrap();
            (index, files)
        };
        assert_eq!(collect(&first), collect(&second));
    }

    #[test]
    fn preparation_rejects_self_consistent_omissions_and_edits_against_source_documents() {
        let inputs: &[(&str, &[u8])] = &[
            ("LICENSE-APACHE", b"synthetic Apache terms"),
            ("LICENSE-MIT", b"synthetic MIT terms"),
            ("nested/NOTICE", b"synthetic attribution"),
            (
                "src/unicode_tables/LICENSE-UNICODE",
                b"synthetic Unicode terms",
            ),
        ];
        let archive = crate_bytes(inputs);
        let checksum = sha256_bytes(&archive);
        let members = read_crate_archive(&archive, "example-1.0.0", &checksum).unwrap();
        let package = json!({"name":"example","version":"1.0.0"});
        let source = json!({"kind":"registry","registry":"registry+https://example.invalid/index","archive_sha256":checksum});
        let documents = inputs.iter().map(|(path, bytes)| json!({"original_path":path,"archive_path":format!("licenses/packages/example-1.0.0/{path}"),"sha256":sha256_bytes(bytes),"origin":{"kind":"registry-archive","archive_sha256":checksum}})).collect::<Vec<_>>();
        let bundle = Bundle {
            index: json!({"schema_version":1,"components":[{"id":"pkg:cargo/example@1.0.0","source":source,"documents":documents}]}),
            files: inputs
                .iter()
                .map(|(path, bytes)| {
                    (
                        format!("licenses/packages/example-1.0.0/{path}"),
                        bytes.to_vec(),
                    )
                })
                .collect(),
        };
        let source_documents = || select_archive_documents(&members, None, &checksum).unwrap();
        reconcile_package_record(&bundle, &package, &source, source_documents()).unwrap();
        for (position, (path, _)) in inputs.iter().enumerate() {
            let mut missing = Bundle {
                index: bundle.index.clone(),
                files: bundle.files.clone(),
            };
            missing.index["components"][0]["documents"]
                .as_array_mut()
                .unwrap()
                .remove(position);
            missing
                .files
                .remove(&format!("licenses/packages/example-1.0.0/{path}"));
            assert!(
                reconcile_package_record(&missing, &package, &source, source_documents()).is_err(),
                "accepted omission of {path}"
            );
            let mut changed = Bundle {
                index: bundle.index.clone(),
                files: bundle.files.clone(),
            };
            let replacement = b"altered terms".to_vec();
            changed.index["components"][0]["documents"][position]["sha256"] =
                json!(sha256_bytes(&replacement));
            changed.files.insert(
                format!("licenses/packages/example-1.0.0/{path}"),
                replacement,
            );
            assert!(
                reconcile_package_record(&changed, &package, &source, source_documents()).is_err(),
                "accepted changed bytes and index for {path}"
            );
        }
    }

    #[test]
    fn rejects_missing_empty_and_case_conflicting_license_texts() {
        assert!(add_documents("packages/example", BTreeMap::new(), &mut BTreeMap::new()).is_err());
        for entries in [
            vec![("LICENSE", b"".as_slice())],
            vec![
                ("LICENSE", b"MIT".as_slice()),
                ("license", b"other".as_slice()),
            ],
        ] {
            let docs = entries
                .into_iter()
                .map(|(path, bytes)| (path.to_owned(), (bytes.to_vec(), json!({}))))
                .collect();
            assert!(add_documents("packages/example", docs, &mut BTreeMap::new()).is_err());
        }
        let archive = crate_bytes(&[("LICENSE", b"one"), ("license", b"two")]);
        assert!(read_crate_archive(&archive, "example-1.0.0", &sha256_bytes(&archive)).is_err());
    }

    #[test]
    fn rejects_unsafe_portable_paths() {
        for path in [
            "../LICENSE",
            "/LICENSE",
            "a/../LICENSE",
            "a//LICENSE",
            "a/./LICENSE",
            "C:/LICENSE",
            "a\\LICENSE",
            "LICENSE.",
            "LICENSE ",
            "a/\0b",
            "a\nb",
            "CON",
            "nested/nul.txt",
            "COM1.txt",
            "name?.txt",
        ] {
            assert!(portable_path(path).is_err(), "accepted {path:?}");
        }
        assert!(portable_path("src/ユニコード/LICENSE-UNICODE").is_ok());
    }

    #[test]
    fn exact_vcs_supplements_reject_stale_pins_and_wrong_sources() {
        let revision = "a".repeat(40);
        let checksum = "b".repeat(64);
        let package = json!({"name":"example","version":"1.0.0","repository":"https://github.com/example/synthetic-notice-fixture"});
        let members = BTreeMap::from([(
            ".cargo_vcs_info.json".into(),
            json_bytes(&json!({"git":{"sha1":revision},"path_in_vcs":"nested-crate"})).unwrap(),
        )]);
        let supplement = json!({"name":"example","version":"1.0.0","archive_sha256":checksum,"repository":"https://github.com/example/synthetic-notice-fixture","revision":revision,"vcs_path":"nested-crate","documents":[{"original_path":"LICENSE","url":format!("https://raw.githubusercontent.com/example/synthetic-notice-fixture/{revision}/LICENSE")} ]});
        validate_supplement(&package, &checksum, &members, &supplement).unwrap();
        for field in [
            "name",
            "version",
            "archive_sha256",
            "repository",
            "revision",
            "vcs_path",
        ] {
            let mut changed = supplement.clone();
            changed[field] = json!("wrong");
            assert!(
                validate_supplement(&package, &checksum, &members, &changed).is_err(),
                "accepted stale {field}"
            );
        }
        let mut stale_url = supplement;
        stale_url["documents"][0]["url"] = json!("https://example.invalid/main/LICENSE");
        assert!(validate_supplement(&package, &checksum, &members, &stale_url).is_err());
    }

    #[test]
    fn workspace_mapping_preserves_inherited_dual_apache_and_custom_terms() {
        assert_eq!(workspace_paths("rustleaks-cli").unwrap(), ["LICENSE"]);
        assert_eq!(
            workspace_paths("rustleaks-core").unwrap(),
            [
                "crates/rustleaks-core/LICENSE",
                "crates/rustleaks-core/NOTICE"
            ]
        );
        assert_eq!(
            workspace_paths("rustleaks-bzip2").unwrap(),
            [
                "crates/rustleaks-bzip2/LICENSE-MIT",
                "crates/rustleaks-bzip2/LICENSE-APACHE"
            ]
        );
        assert_eq!(
            workspace_paths("rustleaks-sevenz").unwrap(),
            ["crates/rustleaks-sevenz/LICENSE"]
        );
        assert_eq!(
            workspace_paths("rustleaks-rar-codec").unwrap(),
            ["crates/rustleaks-rar-codec/COPYING"]
        );
        assert!(workspace_paths("unreviewed-workspace-member").is_err());
        assert_eq!(
            license_file(&json!({"license_file":"COPYING"})).unwrap(),
            Some("COPYING".into())
        );
        assert!(license_file(&json!({"license_file":"../COPYING"})).is_err());
    }

    fn runtime_fixture() -> (Value, BTreeMap<String, Vec<u8>>) {
        let input = "release/notice-inputs/runtime/example-runtime/LICENSE";
        let bytes = b"synthetic runtime attribution\n".to_vec();
        let runtime = json!({"schema_version":1,"target_coverage": TARGETS.iter().map(|(target, _)| json!({"target":target,"status":"complete","evidence":"synthetic evidence"})).collect::<Vec<_>>(),"components":[{
            "id":"example-runtime", "name":"example", "version":"1.0", "license_expression":null,
            "source":{"revision":"exact-source"},"coverage":"synthetic all-target fixture","status":"complete",
            "targets": TARGETS.iter().map(|(target, _)| *target).collect::<Vec<_>>(),
            "documents":[{"original_path":"LICENSE","input_path":input,"sha256":sha256_bytes(&bytes),"source_byte_range":[0,bytes.len()]}]
        }]});
        (runtime, BTreeMap::from([(input.to_owned(), bytes)]))
    }

    #[test]
    fn runtime_selection_preserves_provenance_and_rejects_incomplete_mapping() {
        let (runtime, inputs) = runtime_fixture();
        let read = |path: &str| {
            inputs
                .get(path)
                .cloned()
                .ok_or_else(|| "missing source".into())
        };
        let mut files = BTreeMap::new();
        let records = runtime_records(&runtime, &read, &mut files).unwrap();
        assert_eq!(records[0]["id"], "runtime:example-runtime");
        assert_eq!(
            records[0]["documents"][0]["origin"]["source_byte_range"],
            json!([0, 30])
        );
        assert_eq!(
            files["runtime/example-runtime/LICENSE"],
            b"synthetic runtime attribution\n"
        );
        for mutation in [
            "unknown-target",
            "missing-target",
            "incomplete",
            "changed-bytes",
            "no-documents",
        ] {
            let mut bad = runtime.clone();
            match mutation {
                "unknown-target" => {
                    bad["components"][0]["targets"][0] = json!("wasm32-unknown-unknown");
                }
                "missing-target" => {
                    bad["components"][0]["targets"]
                        .as_array_mut()
                        .unwrap()
                        .pop();
                }
                "incomplete" => bad["components"][0]["status"] = json!("unresolved"),
                "changed-bytes" => {
                    bad["components"][0]["documents"][0]["sha256"] = json!("0".repeat(64));
                }
                _ => bad["components"][0]["documents"] = json!([]),
            }
            assert!(
                runtime_records(&bad, &read, &mut BTreeMap::new()).is_err(),
                "accepted {mutation}"
            );
        }
        let mut pending = runtime;
        pending["target_coverage"][0]["status"] = json!("pending-native-evidence");
        validate_target_coverage(&pending, None).unwrap();
        assert!(validate_target_coverage(&pending, Some(TARGETS[0].0)).is_err());
    }

    #[test]
    fn split_source_notices_keep_distinct_archive_paths_and_original_provenance() {
        let (mut runtime, mut inputs) = runtime_fixture();
        let path = "release/notice-inputs/runtime/example-runtime/LICENSE.part-2.notice";
        let bytes = b"synthetic second source notice".to_vec();
        runtime["components"][0]["documents"].as_array_mut().unwrap().push(json!({"original_path":"LICENSE","input_path":path,"sha256":sha256_bytes(&bytes),"source_byte_range":{"start":100,"end":130}}));
        inputs.insert(path.into(), bytes);
        let read = |path: &str| {
            inputs
                .get(path)
                .cloned()
                .ok_or_else(|| "missing source".into())
        };
        let records = runtime_records(&runtime, &read, &mut BTreeMap::new()).unwrap();
        assert_eq!(records[0]["documents"][0]["original_path"], "LICENSE");
        assert_eq!(records[0]["documents"][1]["original_path"], "LICENSE");
        assert_eq!(
            records[0]["documents"][1]["archive_path"],
            "licenses/runtime/example-runtime/LICENSE.part-2.notice"
        );
        assert_eq!(
            records[0]["documents"][1]["origin"]["source_byte_range"],
            json!({"start":100,"end":130})
        );
    }

    #[test]
    fn regeneration_preserves_unindexed_files_by_refusing_replacement() {
        let index = json_bytes(&json!({"schema_version":1,"components":[{"documents":[{"archive_path":"licenses/packages/example/LICENSE"}]}]})).unwrap();
        let mut files = BTreeMap::from([
            ("index.json".to_owned(), index),
            (
                "packages/example/LICENSE".to_owned(),
                b"synthetic MIT".to_vec(),
            ),
        ]);
        validate_generated_inventory(&files).unwrap();
        files.insert("unrelated.txt".into(), b"preserve this file".to_vec());
        assert!(
            validate_generated_inventory(&files)
                .unwrap_err()
                .contains("refusing to delete")
        );
    }

    #[test]
    fn sbom_coverage_requires_every_selected_package_and_the_cli_root() {
        let bundle = Bundle {
            index: json!({"schema_version":1,"components":[{"id":"pkg:cargo/rustleaks-cli@1.0"},{"id":"pkg:cargo/example@2.0"},{"id":"runtime:example"}]}),
            files: BTreeMap::new(),
        };
        let sbom = json!({"metadata":{"component":{"purl":"pkg:cargo/rustleaks-cli@1.0"}},"components":[{"purl":"pkg:cargo/example@2.0"}]});
        reconcile_sbom(&bundle, &sbom).unwrap();
        let mut missing = sbom.clone();
        missing["components"] = json!([]);
        assert!(reconcile_sbom(&bundle, &missing).is_err());
        let mut extra = sbom;
        extra["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({"purl":"pkg:cargo/extra@1.0"}));
        assert!(reconcile_sbom(&bundle, &extra).is_err());
    }

    #[test]
    fn file_sources_are_root_independent_and_reject_changed_or_missing_bytes() {
        let first = crate::ScopedTempDir::new("notice-first-root").unwrap();
        let second = crate::ScopedTempDir::new("notice-second-root").unwrap();
        for root in [&first.path, &second.path] {
            fs::create_dir_all(root.join("nested")).unwrap();
            fs::write(root.join("nested/LICENSE"), b"synthetic MIT\r\n").unwrap();
        }
        let checksum = sha256_bytes(b"synthetic MIT\r\n");
        assert_eq!(
            read_verified(&first.path, "nested/LICENSE", &checksum).unwrap(),
            read_verified(&second.path, "nested/LICENSE", &checksum).unwrap()
        );
        fs::write(second.path.join("nested/LICENSE"), b"synthetic MIT\n").unwrap();
        assert!(read_verified(&second.path, "nested/LICENSE", &checksum).is_err());
        assert!(read_verified(&second.path, "nested/NOTICE", &checksum).is_err());
    }

    #[test]
    fn generation_uses_current_git_canonical_bytes_without_requiring_a_commit() {
        let root = crate::ScopedTempDir::new("notice-canonical-worktree").unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .current_dir(&root.path)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "--quiet"]);
        git(&["config", "core.autocrlf", "true"]);
        git(&["config", "core.safecrlf", "false"]);
        fs::write(root.path.join(".gitattributes"), b"opaque -text\n").unwrap();
        fs::write(root.path.join("LICENSE"), b"old workspace terms\r\n").unwrap();
        git(&["add", "LICENSE"]);
        fs::write(root.path.join("LICENSE"), b"updated workspace terms\r\n").unwrap();
        fs::write(root.path.join("opaque"), b"exact upstream terms\r\n").unwrap();
        assert_eq!(
            canonical_workspace_file(&root.path, "LICENSE").unwrap(),
            b"updated workspace terms\n"
        );
        assert_eq!(
            canonical_workspace_file(&root.path, "opaque").unwrap(),
            b"exact upstream terms\r\n"
        );
        git(&["config", "core.autocrlf", "false"]);
        assert_eq!(
            canonical_workspace_file(&root.path, "LICENSE").unwrap(),
            b"updated workspace terms\r\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn notice_sources_reject_symlink_escapes() {
        let root = crate::ScopedTempDir::new("notice-symlink").unwrap();
        std::os::unix::fs::symlink("/", root.path.join("escape")).unwrap();
        assert!(
            read_regular(&root.path, "escape/LICENSE")
                .unwrap_err()
                .contains("symlink")
        );
    }

    #[cfg(unix)]
    #[test]
    fn generation_rejects_output_and_parent_symlinks_without_touching_external_files() {
        for link_parent in [false, true] {
            let root = crate::ScopedTempDir::new("notice-output-symlink").unwrap();
            let external = crate::ScopedTempDir::new("notice-external-preserve").unwrap();
            fs::create_dir(external.path.join("licenses")).unwrap();
            let external_file = external.path.join("licenses/preserve.txt");
            fs::write(&external_file, b"unrelated external contents\n").unwrap();
            if link_parent {
                std::os::unix::fs::symlink(&external.path, root.path.join("release")).unwrap();
            } else {
                fs::create_dir(root.path.join("release")).unwrap();
                std::os::unix::fs::symlink(
                    external.path.join("licenses"),
                    root.path.join("release/licenses"),
                )
                .unwrap();
            }
            let error = generate(&root.path, false).unwrap_err();
            assert!(
                error.contains("refusing symlink"),
                "unexpected failure: {error}"
            );
            assert_eq!(
                fs::read(&external_file).unwrap(),
                b"unrelated external contents\n"
            );
            assert!(read_tree(&root.path.join("release/licenses")).is_err() || link_parent);
        }
    }
}
