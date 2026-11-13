//! Offline corresponding-source bundles and native GNU startup relink evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::read::GzDecoder;
use serde_json::{Value, json};

use crate::tooling::{command_output, sha256_file};

use super::{
    RELEASE_VERSION, committed_file_bytes, notices, sha256_bytes, validate_commit, write_archive,
    write_json,
};

const README: &str = "release/corresponding-source/README.md";
const GLIBC_COMMIT: &str = "92d25389c255b0da9b56bc05694f0702cd22921a";
const LLVM_PREFIX: &str = "hermetic-llvm-0.8.11/";
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const SOURCE_MEMBER_COUNT: usize = 8;
const MAX_SOURCE_PATH_BYTES: usize = 100;
// Eight headers, at most eight partial blocks, and the two-block end marker.
const MAX_TAR_STREAM_BYTES: u64 = MAX_BUNDLE_BYTES + 8 * 1024 + 1024;
const MAX_COMPRESSED_BYTES: u64 = MAX_TAR_STREAM_BYTES + 1024 * 1024;

struct Input {
    file: &'static str,
    size: u64,
    sha256: &'static str,
    url: &'static str,
}

// These identities come from the locked LLVM 0.8.11 module and its BCR source
// record. Changing them is a reviewed build-input change, never discovery.
const INPUTS: &[Input] = &[
    Input {
        file: "92d25389c255b0da9b56bc05694f0702cd22921a.tar.gz",
        size: 33_264_381,
        sha256: "f4cf37f12e0c3a81485ea8743dc41dbcec31ae326b22d6265e724c7ee753529e",
        url: "https://github.com/bminor/glibc/archive/92d25389c255b0da9b56bc05694f0702cd22921a.tar.gz",
    },
    Input {
        file: "hermetic-llvm-v0.8.11.tar.gz",
        size: 514_739,
        sha256: "781670efedbcffe9e6bedd086a8037a3fe467baec16d24124534062e36e727a4",
        url: "https://github.com/hermeticbuild/hermetic-llvm/releases/download/v0.8.11/hermetic-llvm-v0.8.11.tar.gz",
    },
    Input {
        file: "module_dot_bazel_version.patch",
        size: 295,
        sha256: "066fb1fc462cc605d940b289e9538de3eae5e43804ff96d5b6a509b97d56fd23",
        url: "https://bcr.bazel.build/modules/llvm/0.8.11/patches/module_dot_bazel_version.patch",
    },
    Input {
        file: "x86_64-linux-gnu.2.28.tar.zst",
        size: 350_783,
        sha256: "8015f4a710987439dfdcde7539b62cc5db52d2cd9456af5e2e297494f13c56f3",
        url: "https://github.com/cerisier/glibc-headers/releases/download/2.28-20250512/x86_64-linux-gnu.2.28.tar.zst",
    },
    Input {
        file: "aarch64-linux-gnu.2.28.tar.zst",
        size: 342_808,
        sha256: "a0f8d45193c814d4b77452ee921cbba49cdd60b9d2e41af28d555b03a4522857",
        url: "https://github.com/cerisier/glibc-headers/releases/download/2.28-20250512/aarch64-linux-gnu.2.28.tar.zst",
    },
];

const PATCHES: &[(&str, &str)] = &[
    (
        "0001-Add-empty-config.h.patch",
        "576b0a0f2d13ab03c3b9c99dd43e6470dabe82244ee4ea476e571610e2df9610",
    ),
    (
        "0002-Add-abi-tag.h.patch",
        "2d69c6475d819d33711e30f2c59d319d42fa1ee770a7ca867d3e75cd0c5c259d",
    ),
    (
        "0003-Adding-libc-modules.h.patch",
        "2c8d58e3418051bbab6b07de88c10b6939d1fd0d919e8afb7479ab052c4027aa",
    ),
];

const RECIPES: &[&str] = &[
    "LICENSE",
    "MODULE.bazel",
    "3rd_party/libc/glibc/COPYING.LIB",
    "3rd_party/libc/glibc/LICENSE",
    "3rd_party/libc/glibc/NOTICE",
    "3rd_party/libc/glibc/glibc.BUILD.bazel",
    "3rd_party/libc/glibc/helpers.bzl",
    "3rd_party/libc/glibc/csu/abi-note-2.31.S",
    "3rd_party/libc/glibc/csu/elf-init-2.31.c",
    "runtimes/glibc/extension/glibc.bzl",
    "runtimes/glibc/extension/glibc_headers_index.json",
    "runtimes/glibc/BUILD.bazel",
    "runtimes/BUILD.bazel",
    "toolchain/runtimes/cc_stage0_object.bzl",
    "toolchain/runtimes/cc_runtime_library.bzl",
    "toolchain/runtimes/cc_runtime_static_library.bzl",
];

pub(super) fn source_name() -> String {
    format!("rustleaks-{RELEASE_VERSION}-corresponding-source.tar.gz")
}

/// Acquisition is deliberately separate from the offline packaging transaction.
pub(super) fn fetch_inputs(repository_cache: &Path) -> Result<(), String> {
    for input in INPUTS {
        let path = cache_file(repository_cache, input);
        if path.exists() {
            read_input(&path, input)?;
            continue;
        }
        let parent = path.parent().ok_or("source cache path has no parent")?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let temporary = path.with_extension("download");
        if temporary.exists() {
            return Err(format!(
                "source download staging path already exists: {}",
                temporary.display()
            ));
        }
        command_output(
            Command::new("curl")
                .args([
                    "--fail",
                    "--location",
                    "--proto",
                    "=https",
                    "--tlsv1.2",
                    "--output",
                ])
                .arg(&temporary)
                .arg(input.url),
        )?;
        read_input(&temporary, input)?;
        fs::rename(&temporary, &path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub(super) fn prepare(
    root: &Path,
    repository_cache: &Path,
    commit: &str,
    output: &Path,
) -> Result<Value, String> {
    validate_candidate(root, commit)?;
    let mut files = BTreeMap::new();
    files.insert(
        "application.tar".into(),
        (application_archive(root, commit)?, 0o644),
    );
    files.insert(
        "README.md".into(),
        (committed_file_bytes(root, commit, README)?, 0o644),
    );
    for input in INPUTS {
        let path = cache_file(repository_cache, input);
        let bytes = read_input(&path, input).map_err(|error| format!("invalid corresponding-source input {}: {error}; acquire the pinned inputs before offline preparation", path.display()))?;
        files.insert(format!("inputs/{}", input.file), (bytes, 0o644));
    }
    let manifest = manifest(commit, &files)?;
    files.insert("manifest.json".into(), (json_bytes(&manifest)?, 0o644));
    fs::create_dir_all(output).map_err(|error| error.to_string())?;
    let path = output.join(source_name());
    let stem = source_name().trim_end_matches(".tar.gz").to_owned();
    write_archive(&path, &stem, &files)?;
    verify(root, &path, commit)
}

pub(super) fn verify(root: &Path, archive: &Path, expected_commit: &str) -> Result<Value, String> {
    validate_candidate(root, expected_commit)?;
    let files = read_bundle(archive, &expected_members(root, expected_commit)?)?;
    validate_files(root, expected_commit, &files)?;
    Ok(json!({
        "schemaVersion": 1, "file": source_name(), "sha256": sha256_file(archive)?,
        "candidate": expected_commit, "glibcCommit": GLIBC_COMMIT,
        "targets": ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"],
    }))
}

fn cache_file(repository_cache: &Path, input: &Input) -> PathBuf {
    repository_cache
        .join("content_addressable/sha256")
        .join(input.sha256)
        .join("file")
}

fn read_input(path: &Path, input: &Input) -> Result<Vec<u8>, String> {
    let bytes = read_limited_regular(path, input.size)?;
    if u64::try_from(bytes.len()).map_err(|error| error.to_string())? != input.size {
        return Err(format!(
            "corresponding-source input size differs: {}",
            input.file
        ));
    }
    check_digest(&bytes, input.sha256, input.file)?;
    Ok(bytes)
}

fn read_limited_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!(
            "source material is not a regular file within its size limit: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(
            limit
                .checked_add(1)
                .ok_or("source material limit overflow")?,
        )
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).map_err(|error| error.to_string())? > limit {
        return Err("source material grew beyond its size limit".into());
    }
    Ok(bytes)
}

fn check_digest(bytes: &[u8], expected: &str, path: &str) -> Result<(), String> {
    if sha256_bytes(bytes) != expected {
        return Err(format!("corresponding-source input digest differs: {path}"));
    }
    Ok(())
}

fn validate_candidate(root: &Path, commit: &str) -> Result<(), String> {
    validate_commit(commit)?;
    let module = committed_file_bytes(root, commit, "MODULE.bazel")?;
    let lock = committed_file_bytes(root, commit, "MODULE.bazel.lock")?;
    let module = std::str::from_utf8(&module).map_err(|error| error.to_string())?;
    let lock = std::str::from_utf8(&lock).map_err(|error| error.to_string())?;
    if !module.contains("bazel_dep(name = \"llvm\", version = \"0.8.11\")")
        || !lock.contains("b40edb2bb2ed271bf613b396d245cb473c42fb057a2b26a3bc7d7e8bfcf6aa71")
    {
        return Err("corresponding-source pins do not match the candidate LLVM module".into());
    }
    Ok(())
}

fn application_archive(root: &Path, commit: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "core.autocrlf=false",
            "archive",
            "--format=tar",
            commit,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "cannot archive candidate application source: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

type Files = BTreeMap<String, (Vec<u8>, u32)>;

fn validate_files(root: &Path, commit: &str, files: &Files) -> Result<(), String> {
    let expected = INPUTS
        .iter()
        .map(|input| format!("inputs/{}", input.file))
        .chain([
            "application.tar".into(),
            "README.md".into(),
            "manifest.json".into(),
        ])
        .collect::<BTreeSet<_>>();
    if files.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err("corresponding-source material inventory differs".into());
    }
    let recorded_manifest: Value = serde_json::from_slice(file_bytes(files, "manifest.json")?)
        .map_err(|error| error.to_string())?;
    validate_manifest_header(commit, &recorded_manifest)?;
    for input in INPUTS {
        check_digest(
            file_bytes(files, &format!("inputs/{}", input.file))?,
            input.sha256,
            input.file,
        )?;
    }
    if file_bytes(files, "application.tar")? != application_archive(root, commit)? {
        return Err(
            "corresponding-source application archive differs from the exact candidate".into(),
        );
    }
    if file_bytes(files, "README.md")? != committed_file_bytes(root, commit, README)? {
        return Err(
            "corresponding-source reconstruction instructions differ from the candidate".into(),
        );
    }
    let expected_manifest = json_bytes(&manifest(commit, files)?)?;
    if file_bytes(files, "manifest.json")? != expected_manifest {
        return Err(
            "corresponding-source manifest, patch order, or material checksums differ".into(),
        );
    }
    Ok(())
}

fn validate_manifest_header(commit: &str, manifest: &Value) -> Result<(), String> {
    let patches = PATCHES.iter().map(|(name,digest)| json!({"path":format!("3rd_party/libc/glibc/{name}"),"sha256":digest,"strip":1})).collect::<Vec<_>>();
    if manifest["schemaVersion"] != 1
        || manifest["candidate"] != commit
        || manifest["version"] != RELEASE_VERSION
        || manifest["glibc"]["commit"] != GLIBC_COMMIT
        || manifest["glibc"]["patches"] != json!(patches)
    {
        return Err(
            "corresponding-source manifest candidate, pin, or ordered patches differ".into(),
        );
    }
    Ok(())
}

fn file_bytes<'a>(files: &'a Files, path: &str) -> Result<&'a [u8], String> {
    files
        .get(path)
        .map(|(bytes, _)| bytes.as_slice())
        .ok_or_else(|| format!("missing corresponding-source material {path}"))
}

fn manifest(commit: &str, files: &Files) -> Result<Value, String> {
    let llvm = gzip_files(
        file_bytes(files, "inputs/hermetic-llvm-v0.8.11.tar.gz")?,
        LLVM_PREFIX,
    )?;
    let mut recipes = BTreeMap::new();
    for path in RECIPES {
        recipes.insert(*path, sha256_bytes(file_bytes(&llvm, path)?));
    }
    let mut patches = Vec::new();
    for (name, digest) in PATCHES {
        let path = format!("3rd_party/libc/glibc/{name}");
        check_digest(file_bytes(&llvm, &path)?, digest, &path)?;
        patches.push(json!({"path":path,"sha256":digest,"strip":1}));
    }
    let materials = files.iter().filter(|(path, _)| path.as_str() != "manifest.json")
        .map(|(path, (bytes, mode))| json!({"path":path,"sha256":sha256_bytes(bytes),"size":bytes.len(),"mode":mode})).collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion":1, "candidate":commit, "version":RELEASE_VERSION,
        "application":{"path":"application.tar","format":"git archive --format=tar","commit":commit},
        "glibc":{"version":"2.28","commit":GLIBC_COMMIT,"stripPrefix":format!("glibc-{GLIBC_COMMIT}"),"patches":patches},
        "llvm":{"version":"0.8.11","stripPrefix":"hermetic-llvm-0.8.11","registryPatch":"inputs/module_dot_bazel_version.patch","recipes":recipes},
        "generatedHeaders":["inputs/x86_64-linux-gnu.2.28.tar.zst","inputs/aarch64-linux-gnu.2.28.tar.zst"],
        "inputs":INPUTS.iter().map(|input| json!({"path":format!("inputs/{}",input.file),"sha256":input.sha256,"url":input.url})).collect::<Vec<_>>(),
        "files":materials,
    }))
}

fn json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

struct ExpectedMember {
    size: Option<u64>,
    limit: u64,
    sha256: Option<String>,
}

fn expected_members(root: &Path, commit: &str) -> Result<BTreeMap<String, ExpectedMember>, String> {
    let mut members = BTreeMap::new();
    for input in INPUTS {
        members.insert(
            format!("inputs/{}", input.file),
            ExpectedMember {
                size: Some(input.size),
                limit: input.size,
                sha256: Some(input.sha256.into()),
            },
        );
    }
    for (name, bytes) in [
        ("application.tar", application_archive(root, commit)?),
        ("README.md", committed_file_bytes(root, commit, README)?),
    ] {
        let size = u64::try_from(bytes.len()).map_err(|error| error.to_string())?;
        members.insert(
            name.into(),
            ExpectedMember {
                size: Some(size),
                limit: size,
                sha256: Some(sha256_bytes(&bytes)),
            },
        );
    }
    members.insert(
        "manifest.json".into(),
        ExpectedMember {
            size: None,
            limit: MAX_MANIFEST_BYTES,
            sha256: None,
        },
    );
    if members.len() != SOURCE_MEMBER_COUNT
        || members
            .values()
            .try_fold(0_u64, |total, member| total.checked_add(member.limit))
            .is_none_or(|size| size > MAX_BUNDLE_BYTES)
    {
        return Err("expected corresponding-source materials exceed the bundle limits".into());
    }
    Ok(members)
}

fn read_bundle(path: &Path, expected: &BTreeMap<String, ExpectedMember>) -> Result<Files, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_COMPRESSED_BYTES {
        return Err("source bundle is not a regular file within the compressed size limit".into());
    }
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    read_source_gzip(
        file.take(MAX_COMPRESSED_BYTES + 1),
        expected,
        MAX_TAR_STREAM_BYTES,
    )
}

fn read_source_gzip(
    mut compressed: impl Read,
    expected: &BTreeMap<String, ExpectedMember>,
    stream_limit: u64,
) -> Result<Files, String> {
    // The maintained writer emits this fixed header, with no filename/comment
    // extensions. Check it before constructing a decoder that could retain them.
    let mut header = [0_u8; 10];
    compressed
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if header != [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255] {
        return Err("source bundle has a noncanonical or extended gzip header".into());
    }
    let mut decoder = flate2::bufread::GzDecoder::new(std::io::BufReader::new(
        Cursor::new(header).chain(compressed),
    ));
    let files = read_source_tar(&mut decoder, expected, stream_limit)?;
    let mut extra = [0_u8; 1];
    if decoder
        .into_inner()
        .read(&mut extra)
        .map_err(|error| error.to_string())?
        != 0
    {
        return Err("source bundle has trailing compressed data or multiple gzip streams".into());
    }
    Ok(files)
}

#[allow(clippy::too_many_lines)] // Keep the parser's count, payload, and trailer accounting together.
fn read_source_tar(
    reader: impl Read,
    expected: &BTreeMap<String, ExpectedMember>,
    stream_limit: u64,
) -> Result<Files, String> {
    let stem = source_name().trim_end_matches(".tar.gz").to_owned();
    let mut bounded = reader.take(
        stream_limit
            .checked_add(1)
            .ok_or("source stream limit overflow")?,
    );
    let mut archive = tar::Archive::new(&mut bounded);
    let mut files = BTreeMap::new();
    let mut size = 0_u64;
    let mut previous = String::new();
    // Raw iteration exposes extension headers before tar allocates their bodies.
    // All eight maintained outer names fit the GNU header itself. Inner original
    // source archives remain opaque bytes and retain their own metadata.
    for (index, entry) in archive
        .entries()
        .map_err(|error| error.to_string())?
        .raw(true)
        .enumerate()
    {
        let mut entry = entry.map_err(|error| error.to_string())?;
        if index >= expected.len() || index >= SOURCE_MEMBER_COUNT {
            return Err("source bundle exceeds its exact member count".into());
        }
        if !entry.header().entry_type().is_file() || entry.header().as_gnu().is_none() {
            return Err(
                "source bundle contains extension metadata or a noncanonical file header".into(),
            );
        }
        let raw_path = entry.header().path_bytes();
        if raw_path.len() > MAX_SOURCE_PATH_BYTES {
            return Err("source bundle path exceeds its header bound".into());
        }
        let path = std::str::from_utf8(&raw_path).map_err(|error| error.to_string())?;
        notices::portable_path(path)?;
        let name = path
            .strip_prefix(&format!("{stem}/"))
            .ok_or("source bundle path escapes root")?;
        let member = expected
            .get(name)
            .ok_or_else(|| format!("unexpected source bundle member {name}"))?;
        if name <= previous.as_str()
            || entry.header().mode().map_err(|error| error.to_string())? != 0o644
            || entry.header().mtime().map_err(|error| error.to_string())? != 0
            || entry.header().uid().map_err(|error| error.to_string())? != 0
            || entry.header().gid().map_err(|error| error.to_string())? != 0
        {
            return Err(
                "source bundle contains unordered, duplicate, non-file, or noncanonical entries"
                    .into(),
            );
        }
        if entry.size() > member.limit || member.size.is_some_and(|size| entry.size() != size) {
            return Err(format!(
                "source bundle member size differs from its expected size or limit: {name}"
            ));
        }
        size = size
            .checked_add(entry.size())
            .filter(|size| *size <= MAX_BUNDLE_BYTES)
            .ok_or("source bundle exceeds material size limit")?;
        let name = name.to_owned();
        previous.clone_from(&name);
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if let Some(digest) = &member.sha256 {
            check_digest(&bytes, digest, &name)?;
        }
        files.insert(name, (bytes, 0o644));
    }
    if files.len() != expected.len() {
        return Err("source bundle is missing required members".into());
    }
    // The iterator consumes the first zero block. Require exactly the second
    // zero block and EOF, bounding trailing padding and concatenated tar data.
    let mut trailer = Vec::new();
    bounded
        .by_ref()
        .take(513)
        .read_to_end(&mut trailer)
        .map_err(|error| error.to_string())?;
    let consumed = stream_limit + 1 - bounded.limit();
    if consumed > stream_limit || trailer.len() != 512 || trailer.iter().any(|byte| *byte != 0) {
        return Err(
            "source bundle exceeds its decompressed stream limit or has a noncanonical trailer"
                .into(),
        );
    }
    Ok(files)
}

fn gzip_files(bytes: &[u8], prefix: &str) -> Result<Files, String> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut files = BTreeMap::new();
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|error| error.to_string())?
            .to_str()
            .ok_or("module path is not UTF-8")?
            .to_owned();
        let path = path
            .strip_prefix(prefix)
            .ok_or("module archive path escapes prefix")?;
        notices::portable_path(path)?;
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        let mode = entry.header().mode().map_err(|error| error.to_string())?;
        if files.insert(path.to_owned(), (bytes, mode)).is_some() {
            return Err("duplicate module archive path".into());
        }
    }
    Ok(files)
}

/// Rebuild from the offered application source, then replace the offered glibc
/// startup routine with an ABI-neutral modification and relink the same source.
#[allow(clippy::too_many_lines)] // Keep source substitution and its evidence in one transaction.
pub(super) fn relink(
    root: &Path,
    archive: &Path,
    commit: &str,
    target: &str,
    work: &Path,
    proof: &Path,
) -> Result<(), String> {
    let (architecture, config) = gnu_target(target)?;
    if std::env::consts::OS != "linux" || std::env::consts::ARCH != architecture {
        return Err(
            "corresponding-source relink proof requires the exact native GNU Linux target".into(),
        );
    }
    let binding = verify(root, archive, commit)?;
    if work.exists() {
        return Err("corresponding-source relink workspace must not already exist".into());
    }
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let work = fs::canonicalize(work).map_err(|error| error.to_string())?;
    let files = read_bundle(archive, &expected_members(root, commit)?)?;
    let application = work.join("application");
    fs::create_dir(&application).map_err(|error| error.to_string())?;
    tar::Archive::new(Cursor::new(file_bytes(&files, "application.tar")?))
        .unpack(&application)
        .map_err(|error| error.to_string())?;
    let inputs = work.join("inputs");
    fs::create_dir(&inputs).map_err(|error| error.to_string())?;
    for input in INPUTS {
        fs::write(
            inputs.join(input.file),
            file_bytes(&files, &format!("inputs/{}", input.file))?,
        )
        .map_err(|error| error.to_string())?;
    }
    tar::Archive::new(GzDecoder::new(file_bytes(
        &files,
        &format!("inputs/{}", INPUTS[0].file),
    )?))
    .unpack(&work)
    .map_err(|error| error.to_string())?;
    tar::Archive::new(GzDecoder::new(file_bytes(
        &files,
        &format!("inputs/{}", INPUTS[1].file),
    )?))
    .unpack(&work)
    .map_err(|error| error.to_string())?;
    let glibc = work.join(format!("glibc-{GLIBC_COMMIT}"));
    let llvm = work.join("hermetic-llvm-0.8.11");
    command_output(
        Command::new("git")
            .current_dir(&llvm)
            .args(["apply", "--no-index", "-p1"])
            .arg(inputs.join("module_dot_bazel_version.patch")),
    )?;
    for (patch, _) in PATCHES {
        command_output(
            Command::new("git")
                .current_dir(&glibc)
                .args(["apply", "--no-index", "-p1"])
                .arg(llvm.join("3rd_party/libc/glibc").join(patch)),
        )?;
    }
    fs::copy(
        llvm.join("3rd_party/libc/glibc/glibc.BUILD.bazel"),
        glibc.join("BUILD.bazel"),
    )
    .map_err(|error| error.to_string())?;
    let startup_path = format!("sysdeps/{architecture}/start.S");
    let startup = glibc.join(&startup_path);
    let original = fs::read(&startup).map_err(|error| error.to_string())?;
    let baseline = build_from_source(&application, &work, &inputs, &glibc, architecture, config)?;
    let baseline_sha256 = sha256_file(&baseline)?;
    let baseline_bytes = fs::read(&baseline).map_err(|error| error.to_string())?;
    smoke(&baseline)?;
    let modified = modified_startup(&original, architecture)?;
    fs::write(&startup, &modified).map_err(|error| error.to_string())?;
    let binary = build_from_source(&application, &work, &inputs, &glibc, architecture, config)?;
    let modified_bytes = fs::read(&binary).map_err(|error| error.to_string())?;
    let marker = entry_marker(architecture);
    if entry_has_marker(&baseline_bytes, &marker)?
        || !entry_has_marker(&modified_bytes, &marker)?
        || baseline_bytes == modified_bytes
    {
        return Err(
            "relinked executable does not prove replacement of the glibc startup routine".into(),
        );
    }
    smoke(&binary)?;
    write_json(
        proof,
        &json!({
            "schemaVersion":1,"candidate":commit,"target":target,
            "sourceArchive":{"file":binding["file"],"sha256":binding["sha256"]},
            "baselineBinarySha256":baseline_sha256,"modifiedBinarySha256":sha256_bytes(&modified_bytes),
            "startup":{"path":startup_path,"originalSha256":sha256_bytes(&original),"modifiedSha256":sha256_bytes(&modified),"entryMarkerHex":hex(&marker)},
            "nativeSmoke":{"help":true,"version":true},"modifiedEntryVerified":true,
        }),
    )
}

fn gnu_target(target: &str) -> Result<(&'static str, &'static str), String> {
    match target {
        "x86_64-unknown-linux-gnu" => Ok(("x86_64", "release-linux-x86_64-gnu")),
        "aarch64-unknown-linux-gnu" => Ok(("aarch64", "release-linux-aarch64-gnu")),
        _ => Err("corresponding-source relink target must be a supported GNU Linux target".into()),
    }
}

fn build_from_source(
    application: &Path,
    work: &Path,
    inputs: &Path,
    glibc: &Path,
    architecture: &str,
    config: &str,
) -> Result<PathBuf, String> {
    let output_root = format!("--output_user_root={}", work.join("bazel").display());
    let config = format!("--config={config}");
    let distdir = format!("--distdir={}", inputs.display());
    let replacement = format!(
        "--override_repository=llvm++glibc+glibc_{architecture}-linux-gnu.2.28={}",
        glibc.display()
    );
    let module = format!(
        "--override_repository=llvm+={}",
        work.join("hermetic-llvm-0.8.11").display()
    );
    command_output(Command::new("bazelisk").current_dir(application).args([
        &output_root,
        "build",
        &config,
        &distdir,
        &replacement,
        &module,
        "//crates/rustleaks-cli:rustleaks",
    ]))?;
    let bin = command_output(Command::new("bazelisk").current_dir(application).args([
        &output_root,
        "info",
        &config,
        &distdir,
        &replacement,
        &module,
        "bazel-bin",
    ]))?;
    Ok(PathBuf::from(bin.trim()).join("crates/rustleaks-cli/rustleaks"))
}

fn smoke(binary: &Path) -> Result<(), String> {
    for argument in ["--help", "--version"] {
        let text = command_output(Command::new(binary).arg(argument))?;
        if !text.to_ascii_lowercase().contains("rustleaks")
            || (argument == "--version" && !text.contains(RELEASE_VERSION))
        {
            return Err(format!(
                "relinked executable failed {argument} smoke output"
            ));
        }
    }
    Ok(())
}

fn modified_startup(original: &[u8], architecture: &str) -> Result<Vec<u8>, String> {
    let source = std::str::from_utf8(original).map_err(|error| error.to_string())?;
    let label = if architecture == "aarch64" {
        "_start:\n"
    } else {
        "ENTRY (_start)\n"
    };
    if source.matches(label).count() != 1 {
        return Err("glibc startup entry label is absent or ambiguous".into());
    }
    Ok(source
        .replacen(label, &format!("{label}{}", "\tnop\n".repeat(16)), 1)
        .into_bytes())
}

fn entry_marker(architecture: &str) -> Vec<u8> {
    if architecture == "aarch64" {
        [0x1f, 0x20, 0x03, 0xd5].repeat(16)
    } else {
        vec![0x90; 16]
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::new();
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn elf_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let data: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or("truncated ELF header")?
        .try_into()
        .map_err(|error: std::array::TryFromSliceError| error.to_string())?;
    Ok(u64::from_le_bytes(data))
}

fn entry_has_marker(bytes: &[u8], marker: &[u8]) -> Result<bool, String> {
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01") {
        return Err("relink executable is not ELF64 little endian".into());
    }
    let entry = elf_u64(bytes, 24)?;
    let table = usize::try_from(elf_u64(bytes, 32)?).map_err(|error| error.to_string())?;
    let size = usize::from(u16::from_le_bytes(
        bytes
            .get(54..56)
            .ok_or("truncated ELF header")?
            .try_into()
            .map_err(|error: std::array::TryFromSliceError| error.to_string())?,
    ));
    let count = usize::from(u16::from_le_bytes(
        bytes
            .get(56..58)
            .ok_or("truncated ELF header")?
            .try_into()
            .map_err(|error: std::array::TryFromSliceError| error.to_string())?,
    ));
    if size < 56 {
        return Err("invalid ELF program header size".into());
    }
    for index in 0..count {
        let header = table
            .checked_add(index.checked_mul(size).ok_or("ELF header overflow")?)
            .ok_or("ELF header overflow")?;
        if bytes.get(header..header.saturating_add(4)) != Some(&[1, 0, 0, 0]) {
            continue;
        }
        let address = elf_u64(bytes, header + 16)?;
        let length = elf_u64(bytes, header + 32)?;
        if let Some(relative) = entry.checked_sub(address).filter(|offset| *offset < length) {
            let offset = elf_u64(bytes, header + 8)?
                .checked_add(relative)
                .ok_or("ELF entry overflow")?;
            let offset = usize::try_from(offset).map_err(|error| error.to_string())?;
            let start =
                if bytes.get(offset..offset.saturating_add(4)) == Some(&[0xf3, 0x0f, 0x1e, 0xfa]) {
                    offset.saturating_add(4)
                } else {
                    offset
                };
            return Ok(bytes.get(start..start.saturating_add(marker.len())) == Some(marker));
        }
    }
    Err("ELF entry point is outside file-backed load segments".into())
}

pub(super) fn validate_relink_proof(
    proof: &Path,
    binding: &Value,
    target: &str,
    commit: &str,
    binary_sha256: &str,
) -> Result<Value, String> {
    let (architecture, _) = gnu_target(target)?;
    let bytes = read_limited_regular(proof, MAX_MANIFEST_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let expected_shape = json!({
        "schemaVersion":value["schemaVersion"],"candidate":value["candidate"],"target":value["target"],
        "sourceArchive":{"file":value["sourceArchive"]["file"],"sha256":value["sourceArchive"]["sha256"]},
        "baselineBinarySha256":value["baselineBinarySha256"],"modifiedBinarySha256":value["modifiedBinarySha256"],
        "startup":{"path":value["startup"]["path"],"originalSha256":value["startup"]["originalSha256"],"modifiedSha256":value["startup"]["modifiedSha256"],"entryMarkerHex":value["startup"]["entryMarkerHex"]},
        "nativeSmoke":{"help":value["nativeSmoke"]["help"],"version":value["nativeSmoke"]["version"]},
        "modifiedEntryVerified":value["modifiedEntryVerified"],
    });
    if value != expected_shape || bytes != json_bytes(&value)? {
        return Err("source relink proof has unknown fields or noncanonical serialization".into());
    }
    if value["schemaVersion"] != 1
        || value["candidate"] != commit
        || value["target"] != target
        || value["sourceArchive"] != json!({"file":binding["file"],"sha256":binding["sha256"]})
        || value["baselineBinarySha256"] != binary_sha256
        || value["modifiedEntryVerified"] != true
        || value["nativeSmoke"] != json!({"help":true,"version":true})
        || value["startup"]["path"] != format!("sysdeps/{architecture}/start.S")
        || value["startup"]["originalSha256"]
            != if architecture == "aarch64" {
                "5e26fab3490c25240bbf806146860ea3d6596988e16a27da52bd428e116a5cc3"
            } else {
                "95293b62857d9b4d3d1b0c9fefc7f0676ed69d65d8dbc35f3a125624e878bfc7"
            }
        || value["startup"]["entryMarkerHex"] != hex(&entry_marker(architecture))
    {
        return Err("source relink proof does not bind the candidate, target, native binary, source archive, and startup replacement".into());
    }
    for field in [
        &value["baselineBinarySha256"],
        &value["modifiedBinarySha256"],
        &value["startup"]["originalSha256"],
        &value["startup"]["modifiedSha256"],
    ] {
        let digest = field
            .as_str()
            .ok_or("source relink proof digest is missing")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("source relink proof digest is invalid".into());
        }
    }
    if value["baselineBinarySha256"] == value["modifiedBinarySha256"]
        || value["startup"]["originalSha256"] == value["startup"]["modifiedSha256"]
    {
        return Err("source relink proof did not change both startup source and executable".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser_members() -> BTreeMap<String, ExpectedMember> {
        [
            "README.md",
            "application.tar",
            "inputs/92d25389c255b0da9b56bc05694f0702cd22921a.tar.gz",
            "inputs/aarch64-linux-gnu.2.28.tar.zst",
            "inputs/hermetic-llvm-v0.8.11.tar.gz",
            "inputs/module_dot_bazel_version.patch",
            "inputs/x86_64-linux-gnu.2.28.tar.zst",
            "manifest.json",
        ]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                ExpectedMember {
                    size: Some(3),
                    limit: 3,
                    sha256: Some(
                        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
                    ),
                },
            )
        })
        .collect()
    }

    fn parser_header(name: &str, size: u64, kind: u8) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        let stem = source_name().trim_end_matches(".tar.gz").to_owned();
        header.set_path(format!("{stem}/{name}")).unwrap();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::new(kind));
        header.set_cksum();
        header
    }

    fn parser_tar(names: impl IntoIterator<Item = String>, body: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();
        for name in names {
            archive.extend_from_slice(
                parser_header(&name, u64::try_from(body.len()).unwrap(), b'0').as_bytes(),
            );
            archive.extend_from_slice(body);
            archive.resize(archive.len().next_multiple_of(512), 0);
        }
        archive.extend_from_slice(&[0; 1024]);
        archive
    }

    #[test]
    fn source_reader_accepts_exact_stream_limit_and_rejects_one_byte_less() {
        let expected = parser_members();
        let archive = parser_tar(expected.keys().cloned(), b"abc");
        let exact = u64::try_from(archive.len()).unwrap();
        assert_eq!(
            read_source_tar(archive.as_slice(), &expected, exact)
                .unwrap()
                .len(),
            8
        );
        assert!(
            read_source_tar(archive.as_slice(), &expected, exact - 1)
                .unwrap_err()
                .contains("stream limit")
        );
        let mut padding = archive;
        padding.push(0);
        assert!(
            read_source_tar(padding.as_slice(), &expected, exact + 1)
                .unwrap_err()
                .contains("trailer")
        );
    }

    #[test]
    fn source_reader_rejects_trailing_bytes_and_additional_gzip_members() {
        use std::io::Write as _;

        fn gzip(bytes: &[u8]) -> Vec<u8> {
            let mut encoder = flate2::GzBuilder::new()
                .mtime(0)
                .operating_system(255)
                .write(Vec::new(), flate2::Compression::best());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        }

        let expected = parser_members();
        let tar = parser_tar(expected.keys().cloned(), b"abc");
        let archive = gzip(&tar);
        assert_eq!(
            read_source_gzip(archive.as_slice(), &expected, MAX_TAR_STREAM_BYTES)
                .unwrap()
                .len(),
            8
        );
        for suffix in [vec![0], gzip(&tar), gzip(b"")] {
            let mut changed = archive.clone();
            changed.extend_from_slice(&suffix);
            assert!(
                read_source_gzip(changed.as_slice(), &expected, MAX_TAR_STREAM_BYTES)
                    .unwrap_err()
                    .contains("trailing compressed data")
            );
        }
    }

    #[test]
    fn source_reader_rejects_excess_zero_members_without_reading_their_bodies() {
        let mut expected = parser_members();
        for member in expected.values_mut() {
            member.size = Some(0);
            member.limit = 0;
            member.sha256 =
                Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into());
        }
        let names = expected
            .keys()
            .cloned()
            .chain((0..100).map(|index| format!("zzz-{index:03}")));
        let archive = parser_tar(names, b"");
        let mut reader = Cursor::new(archive);
        let error = read_source_tar(&mut reader, &expected, MAX_TAR_STREAM_BYTES).unwrap_err();
        assert!(error.contains("member count"));
        assert_eq!(reader.position(), 9 * 512);
    }

    #[test]
    fn source_reader_rejects_unexpected_name_and_known_size_before_payload() {
        let expected = parser_members();
        let unexpected = parser_header("AAA-unexpected", MAX_BUNDLE_BYTES, b'0');
        let mut reader = Cursor::new(unexpected.as_bytes());
        assert!(
            read_source_tar(&mut reader, &expected, MAX_TAR_STREAM_BYTES)
                .unwrap_err()
                .contains("unexpected")
        );
        assert_eq!(reader.position(), 512);
        let oversized = parser_header("README.md", 4, b'0');
        let mut reader = Cursor::new(oversized.as_bytes());
        assert!(
            read_source_tar(&mut reader, &expected, MAX_TAR_STREAM_BYTES)
                .unwrap_err()
                .contains("member size")
        );
        assert_eq!(reader.position(), 512);
        let corrupt = parser_tar(expected.keys().cloned(), b"abd");
        let mut reader = Cursor::new(corrupt);
        assert!(
            read_source_tar(&mut reader, &expected, MAX_TAR_STREAM_BYTES)
                .unwrap_err()
                .contains("digest differs")
        );
        assert_eq!(reader.position(), 515);
    }

    #[test]
    fn source_reader_rejects_oversized_extension_metadata_before_payload() {
        let expected = parser_members();
        for kind in [b'L', b'K', b'x', b'g'] {
            let header = parser_header("metadata", MAX_TAR_STREAM_BYTES + 1, kind);
            let mut reader = Cursor::new(header.as_bytes());
            assert!(
                read_source_tar(&mut reader, &expected, MAX_TAR_STREAM_BYTES)
                    .unwrap_err()
                    .contains("extension metadata")
            );
            assert_eq!(reader.position(), 512);
        }
    }

    #[test]
    fn source_reader_rejects_long_paths_and_gzip_metadata_before_payload() {
        let expected = parser_members();
        let mut header = tar::Header::new_ustar();
        header
            .set_path(format!("{}/README.md", "x".repeat(120)))
            .unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        let mut reader = Cursor::new(header.as_bytes());
        assert!(read_source_tar(&mut reader, &expected, MAX_TAR_STREAM_BYTES).is_err());
        assert_eq!(reader.position(), 512);
        for flag in [4, 8, 16] {
            let header = [0x1f, 0x8b, 8, flag, 0, 0, 0, 0, 2, 255];
            let mut reader = Cursor::new(header);
            assert!(
                read_source_gzip(&mut reader, &expected, MAX_TAR_STREAM_BYTES)
                    .unwrap_err()
                    .contains("gzip header")
            );
            assert_eq!(reader.position(), 10);
        }
    }

    #[test]
    fn source_reader_enforces_manifest_member_limit_exactly() {
        let expected = BTreeMap::from([(
            "manifest.json".into(),
            ExpectedMember {
                size: None,
                limit: 3,
                sha256: None,
            },
        )]);
        let exact = parser_tar(["manifest.json".into()], b"abc");
        assert!(read_source_tar(exact.as_slice(), &expected, 2048).is_ok());
        let oversized = parser_header("manifest.json", 4, b'0');
        assert!(
            read_source_tar(oversized.as_bytes().as_slice(), &expected, 2048)
                .unwrap_err()
                .contains("member size")
        );
    }

    #[test]
    fn input_hash_is_independently_pinned() {
        assert!(
            check_digest(
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "source"
            )
            .is_ok()
        );
        assert!(
            check_digest(
                b"abd",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "source"
            )
            .is_err()
        );
    }

    fn known_manifest() -> Value {
        json!({"schemaVersion":1,"candidate":"a".repeat(40),"version":RELEASE_VERSION,
        "glibc":{"commit":"92d25389c255b0da9b56bc05694f0702cd22921a","patches":[
            {"path":"3rd_party/libc/glibc/0001-Add-empty-config.h.patch","sha256":"576b0a0f2d13ab03c3b9c99dd43e6470dabe82244ee4ea476e571610e2df9610","strip":1},
            {"path":"3rd_party/libc/glibc/0002-Add-abi-tag.h.patch","sha256":"2d69c6475d819d33711e30f2c59d319d42fa1ee770a7ca867d3e75cd0c5c259d","strip":1},
            {"path":"3rd_party/libc/glibc/0003-Adding-libc-modules.h.patch","sha256":"2c8d58e3418051bbab6b07de88c10b6939d1fd0d919e8afb7479ab052c4027aa","strip":1}
        ]}})
    }

    #[test]
    fn manifest_rejects_wrong_candidate_patch_order_hash_and_path() {
        let commit = "a".repeat(40);
        assert!(validate_manifest_header(&commit, &known_manifest()).is_ok());
        assert!(validate_manifest_header(&"b".repeat(40), &known_manifest()).is_err());
        let mut wrong_order = known_manifest();
        wrong_order["glibc"]["patches"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(validate_manifest_header(&commit, &wrong_order).is_err());
        let mut wrong_hash = known_manifest();
        wrong_hash["glibc"]["patches"][0]["sha256"] = json!("0".repeat(64));
        assert!(validate_manifest_header(&commit, &wrong_hash).is_err());
        let mut wrong_path = known_manifest();
        wrong_path["glibc"]["patches"][0]["path"] = json!("../config.h");
        assert!(validate_manifest_header(&commit, &wrong_path).is_err());
    }

    #[test]
    fn missing_header_archive_is_a_material_failure_before_git_access() {
        let mut files = Files::new();
        for path in [
            "application.tar",
            "README.md",
            "manifest.json",
            "inputs/92d25389c255b0da9b56bc05694f0702cd22921a.tar.gz",
            "inputs/hermetic-llvm-v0.8.11.tar.gz",
            "inputs/module_dot_bazel_version.patch",
            "inputs/x86_64-linux-gnu.2.28.tar.zst",
        ] {
            files.insert(path.into(), (Vec::new(), 0o644));
        }
        let failure =
            validate_files(Path::new("absent-repository"), &"a".repeat(40), &files).unwrap_err();
        assert!(failure.contains("material inventory"));
    }

    fn elf_with_entry(code: &[u8]) -> Vec<u8> {
        let mut elf = vec![0_u8; 512];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[24..32].copy_from_slice(&0x400100_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[96..104].copy_from_slice(&512_u64.to_le_bytes());
        elf[256..256 + code.len()].copy_from_slice(code);
        elf
    }

    #[test]
    fn relink_marker_must_be_at_the_executable_entry() {
        let aarch64 = [0x1f, 0x20, 0x03, 0xd5].repeat(16);
        let x86 = vec![0x90; 16];
        for marker in [&aarch64, &x86] {
            assert!(entry_has_marker(&elf_with_entry(marker), marker).unwrap());
            let mut decoy = elf_with_entry(&[0xcc; 64]);
            decoy[320..320 + marker.len()].copy_from_slice(marker);
            assert!(!entry_has_marker(&decoy, marker).unwrap());
        }
        assert!(entry_has_marker(b"not an executable", &x86).is_err());
    }

    #[test]
    fn startup_edit_preserves_code_and_requires_unique_label() {
        let source = b"/* Original copyright. */\n_start:\n\tmov x29, #0\n";
        let modified = modified_startup(source, "aarch64").unwrap();
        let text = String::from_utf8(modified).unwrap();
        assert!(text.starts_with("/* Original copyright. */\n_start:\n\tnop\n"));
        assert!(text.ends_with("\tmov x29, #0\n"));
        assert_eq!(text.matches("\tnop\n").count(), 16);
        assert!(modified_startup(b"_start:\n_start:\n", "aarch64").is_err());
        assert!(modified_startup(b"missing label", "x86_64").is_err());
    }
}
