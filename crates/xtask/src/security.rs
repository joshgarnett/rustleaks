//! Dependency policy, vetting, unsafe inventory, Miri and panic policy checks.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::tooling::{ScopedTempDir, command_output, command_status_with_timeout};
use crate::{require_exact_tool_version, tooling, workspace_root};

const CARGO_DENY_VERSION: &str = "cargo-deny 0.19.9";
const CARGO_AUDIT_VERSION: &str = "cargo-audit-audit 0.22.2";
pub(crate) const CARGO_GEIGER_VERSION: &str = "cargo-geiger 0.13.0";
const CARGO_VET_VERSION: &str = "cargo-vet 0.10.2";
const COMPCOL_EXEMPTION_VERSION: &str = "0.8.0";
const COMPCOL_EXEMPTION_SHA256: &str =
    "f4be160df80e77bdf4902bb026c6a0f6c700ec7793379c26305d45e293e17b8c";
/// Targets the compcol exemption was reviewed for. This is a separate list from
/// [`REQUIRED_TARGETS`] so that a target change requires a new review.
const COMPCOL_EXEMPTION_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
];
pub(crate) const MIRI_TOOLCHAIN: &str = "nightly-2026-08-21";

fn validate_supply_chain_exceptions(source: &str) -> Result<(), String> {
    let active = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    if active.first().copied() != Some("schema = 1") {
        return Err("supply-chain exception file must start with `schema = 1`".into());
    }
    if active.len() != 1 {
        return Err(
            "active supply-chain exceptions require an explicit validator and release review"
                .into(),
        );
    }
    Ok(())
}

fn supply_chain_check() -> Result<(), String> {
    let root = workspace_root()?;
    require_exact_tool_version(
        Command::new("cargo").args(["deny", "--version"]),
        CARGO_DENY_VERSION,
        "cargo-deny",
    )?;
    let exceptions = std::fs::read_to_string(root.join("supply-chain-exceptions.toml"))
        .map_err(|error| format!("cannot read supply-chain exception policy: {error}"))?;
    validate_supply_chain_exceptions(&exceptions)?;
    command_output(
        Command::new("cargo")
            .args(["deny", "check"])
            .current_dir(&root),
    )?;
    println!("dependency advisories, bans, licenses, and sources satisfy policy");
    Ok(())
}

fn rustsec_check() -> Result<(), String> {
    let root = workspace_root()?;
    require_exact_tool_version(
        Command::new("cargo").args(["audit", "--version"]),
        CARGO_AUDIT_VERSION,
        "cargo-audit",
    )?;
    command_output(
        Command::new("cargo")
            .current_dir(&root)
            .args(["audit", "--deny", "warnings", "--color", "never"]),
    )?;
    println!(
        "fresh RustSec audit found no vulnerability, unmaintained, unsound, or yanked warning"
    );
    Ok(())
}

fn vet_check() -> Result<(), String> {
    let root = workspace_root()?;
    require_exact_tool_version(
        Command::new("cargo").args(["vet", "--version"]),
        CARGO_VET_VERSION,
        "cargo-vet",
    )?;
    for required in [
        "supply-chain/config.toml",
        "supply-chain/audits.toml",
        "supply-chain/imports.lock",
    ] {
        if !root.join(required).is_file() {
            return Err(format!("cargo-vet policy is missing {required}"));
        }
    }
    if validate_vet_exemptions(&root.join("supply-chain/config.toml"))? {
        check_compcol_exemption_scope(&root)?;
    }
    tooling::check_vet_inventory(&root, &root.join("supply-chain/inventory-v1.json"))?;
    command_output(Command::new("cargo").current_dir(&root).args([
        "vet",
        "--locked",
        "--no-registry-suggestions",
    ]))?;
    println!("locked cargo-vet graph satisfies the checked-in review policy");
    Ok(())
}

fn validate_vet_exemptions(path: &Path) -> Result<bool, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read cargo-vet policy {}: {error}", path.display()))?;
    let config: toml::Value = toml::from_str(&source)
        .map_err(|error| format!("cannot parse cargo-vet policy {}: {error}", path.display()))?;
    let exemptions = match config.get("exemptions") {
        Some(exemptions) => Some(
            exemptions
                .as_table()
                .ok_or("cargo-vet exemptions are not a table")?,
        ),
        None => None,
    };
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock predates the Unix epoch: {error}"))?
        .as_secs()
        / 86_400;
    let mut record_count = 0_usize;
    let mut compcol_standing_exemption = false;
    for (package, entries) in exemptions.into_iter().flatten() {
        let entries = entries
            .as_array()
            .ok_or_else(|| format!("cargo-vet exemptions for {package} are not an array"))?;
        record_count += entries.len();
        for entry in entries {
            compcol_standing_exemption |= validate_vet_exemption(package, entry, today)?;
        }
    }
    let crate_name_count = exemptions.map_or(0, toml::map::Map::len);
    println!(
        "all {record_count} cargo-vet exemption records across {crate_name_count} crate names have required metadata and valid review conditions"
    );
    Ok(compcol_standing_exemption)
}

fn validate_vet_exemption(package: &str, entry: &toml::Value, today: u64) -> Result<bool, String> {
    let version = entry
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("cargo-vet exemption for {package} omits version"))?;
    let context = format!("cargo-vet exemption {package}@{version}");
    let notes = entry
        .get("notes")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("{context} omits notes"))?;
    let field = |name: &str| -> Result<Option<&str>, String> {
        let values = notes
            .split(';')
            .filter_map(|field| field.trim().split_once('='))
            .filter_map(|(key, value)| (key == name).then_some(value.trim()))
            .collect::<Vec<_>>();
        match values.as_slice() {
            [] => Ok(None),
            [value] if !value.is_empty() => Ok(Some(*value)),
            _ => Err(format!("{context} has empty or duplicate {name} metadata")),
        }
    };
    for name in ["owner", "scope", "rationale"] {
        field(name)?.ok_or_else(|| format!("{context} omits {name} metadata"))?;
    }
    let review_by = field("review-by")?;
    if let Some(review_on) = field("review-on")? {
        let criterion = entry.get("criteria").is_some_and(|criteria| {
            criteria.as_str() == Some("safe-to-deploy")
                || criteria.as_array().is_some_and(|values| {
                    values.len() == 1 && values[0].as_str() == Some("safe-to-deploy")
                })
        });
        if package != "compcol"
            || version != COMPCOL_EXEMPTION_VERSION
            || !criterion
            || review_on != "boundary-change"
            || review_by.is_some()
        {
            return Err(format!("{context} is not the approved standing exemption"));
        }
        field("resolution")?.ok_or_else(|| format!("{context} omits resolution metadata"))?;
        return Ok(true);
    }
    let review = review_by.ok_or_else(|| format!("{context} has no review date"))?;
    let review_day = parse_civil_day(review)
        .ok_or_else(|| format!("{context} has invalid review date {review}"))?;
    if review_day < today {
        return Err(format!("{context} expired on {review}"));
    }
    Ok(false)
}

fn check_compcol_exemption_scope(root: &Path) -> Result<(), String> {
    let core = normal_dependency_packages(root, "rustleaks-core", true)?;
    let metadata = command_output(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--format-version",
        "1",
        "--offline",
        "--locked",
        "--all-features",
    ]))?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let bazel = std::fs::read_to_string(root.join("cargo-bazel-lock.json"))
        .map_err(|error| format!("cannot read cargo-bazel-lock.json: {error}"))?;
    let bazel: serde_json::Value = serde_json::from_str(&bazel)
        .map_err(|error| format!("cannot decode cargo-bazel-lock.json: {error}"))?;
    validate_compcol_exemption_scope(&core, &metadata, &bazel)?;
    println!(
        "compcol standing exemption retains its reviewed source, features, targets, and core boundary"
    );
    Ok(())
}

fn validate_compcol_exemption_scope(
    core: &BTreeSet<String>,
    metadata: &serde_json::Value,
    bazel: &serde_json::Value,
) -> Result<(), String> {
    let outside_scope = "compcol standing exemption requires re-review after a source, version, feature, target, or core boundary change";
    if core.contains("compcol") {
        return Err(outside_scope.into());
    }
    let packages = metadata["packages"].as_array().ok_or(outside_scope)?;
    let compcol = packages
        .iter()
        .filter(|package| package["name"].as_str() == Some("compcol"))
        .collect::<Vec<_>>();
    let [compcol] = compcol.as_slice() else {
        return Err(outside_scope.into());
    };
    if compcol["version"].as_str() != Some(COMPCOL_EXEMPTION_VERSION)
        || compcol["source"].as_str()
            != Some("registry+https://github.com/rust-lang/crates.io-index")
    {
        return Err(outside_scope.into());
    }
    let id = compcol["id"].as_str().ok_or(outside_scope)?;
    let node = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or(outside_scope)?
        .iter()
        .find(|node| node["id"].as_str() == Some(id))
        .ok_or(outside_scope)?;
    let expected_features = BTreeSet::from(["alloc", "rar2"]);
    if json_string_set(&node["features"])? != expected_features {
        return Err(outside_scope.into());
    }

    let crates = bazel["crates"].as_object().ok_or(outside_scope)?;
    let compcol = crates
        .values()
        .filter(|package| package["name"].as_str() == Some("compcol"))
        .collect::<Vec<_>>();
    let [compcol] = compcol.as_slice() else {
        return Err(outside_scope.into());
    };
    let features = &compcol["common_attrs"]["crate_features"];
    if compcol["version"].as_str() != Some(COMPCOL_EXEMPTION_VERSION)
        || compcol["repository"]["Http"]["sha256"].as_str() != Some(COMPCOL_EXEMPTION_SHA256)
        || json_string_set(&features["common"])? != expected_features
        || !features["selects"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    {
        return Err(outside_scope.into());
    }
    let mut targets = BTreeSet::new();
    for condition in bazel["conditions"]
        .as_object()
        .ok_or(outside_scope)?
        .values()
    {
        targets.extend(json_string_set(condition)?);
    }
    if targets != COMPCOL_EXEMPTION_TARGETS.iter().copied().collect() {
        return Err(outside_scope.into());
    }
    Ok(())
}

fn json_string_set(value: &serde_json::Value) -> Result<BTreeSet<&str>, String> {
    value
        .as_array()
        .ok_or_else(|| "expected an array of strings in dependency resolution".to_owned())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "expected a string in dependency resolution".to_owned())
        })
        .collect()
}

fn parse_civil_day(value: &str) -> Option<u64> {
    let mut fields = value.split('-');
    let mut year = fields.next()?.parse::<i64>().ok()?;
    let month = fields.next()?.parse::<i64>().ok()?;
    let day = fields.next()?.parse::<i64>().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=days_in_month).contains(&day) {
        return None;
    }
    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468).try_into().ok()
}

pub(crate) fn unsafe_count(value: &serde_json::Value) -> u64 {
    match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            .map(|(name, value)| {
                if name == "unsafe_" {
                    value.as_u64().unwrap_or_default()
                } else {
                    unsafe_count(value)
                }
            })
            .sum(),
        serde_json::Value::Array(values) => values.iter().map(unsafe_count).sum(),
        _ => 0,
    }
}

fn reviewed_unsafe_packages() -> (BTreeSet<String>, BTreeSet<String>) {
    let common = [
        "aho-corasick@1.1.5",
        "alloc-no-stdlib@3.0.0",
        "alloc-stdlib@0.3.0",
        "block-buffer@0.12.1",
        "brotli-decompressor@6.3.2",
        "const-oid@0.10.2",
        "hybrid-array@0.4.15",
        "itoa@1.0.18",
        "lz4_flex@0.14.2",
        "lzma-rust2@0.25.0",
        "memchr@2.8.3",
        "proc-macro2@1.0.107",
        "regex-automata@0.4.19",
        "semver@1.0.28",
        "serde_core@1.0.229",
        "serde_json@1.0.154",
        "sha2@0.11.1",
        "syn@3.0.9",
        "toml_parser@1.1.5+spec-1.1.0",
        "twox-hash@2.1.5",
        "unicode-ident@1.0.27",
        "winnow@1.0.5",
        "zmij@1.0.23",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let target_specific = ["cpufeatures@0.3.1", "libc@0.2.191"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    (common, target_specific)
}

fn validate_unsafe_package_set(
    unsafe_packages: &BTreeSet<String>,
) -> Result<(usize, usize), String> {
    let (common, target_specific) = reviewed_unsafe_packages();
    let missing = common
        .difference(unsafe_packages)
        .cloned()
        .collect::<BTreeSet<_>>();
    let unexpected = unsafe_packages
        .difference(&common)
        .filter(|package| !target_specific.contains(*package))
        .cloned()
        .collect::<BTreeSet<_>>();
    if !missing.is_empty() || !unexpected.is_empty() {
        return Err(format!(
            "cargo-geiger unsafe-bearing package set changed: missing common {missing:?}, unexpected {unexpected:?}, got {unsafe_packages:?}"
        ));
    }
    Ok((
        common.len(),
        unsafe_packages.intersection(&target_specific).count(),
    ))
}

fn unsafe_inventory_check() -> Result<(), String> {
    let root = workspace_root()?;
    require_exact_tool_version(
        Command::new("cargo").args(["geiger", "--version"]),
        CARGO_GEIGER_VERSION,
        "cargo-geiger",
    )?;
    let target = ScopedTempDir::new("geiger")?;
    let manifest = root.join("crates/rustleaks-sources/Cargo.toml");
    let output = command_output(
        Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target.path)
            .args(["geiger", "--manifest-path"])
            .arg(&manifest)
            .args([
                "--all-features",
                "--locked",
                "--offline",
                "--output-format",
                "Json",
                "--quiet",
            ]),
    )?;
    let report = output
        .lines()
        .rev()
        .find(|line| line.starts_with("{\"packages\":"))
        .ok_or("cargo-geiger output omitted its JSON inventory")?;
    let report: serde_json::Value = serde_json::from_str(report)
        .map_err(|error| format!("cannot decode cargo-geiger inventory: {error}"))?;
    if report["packages_without_metrics"]
        .as_array()
        .is_none_or(|packages| !packages.is_empty())
    {
        return Err("cargo-geiger omitted metrics for one or more selected packages".into());
    }
    let packages = report["packages"]
        .as_array()
        .ok_or("cargo-geiger inventory omits packages")?;
    let mut unsafe_packages = BTreeSet::new();
    for package in packages {
        let id = &package["package"]["id"];
        let name = id["name"]
            .as_str()
            .ok_or("cargo-geiger package omits name")?;
        let version = id["version"]
            .as_str()
            .ok_or("cargo-geiger package omits version")?;
        let used_unsafe = unsafe_count(&package["unsafety"]["used"]);
        validate_owned_unsafe_package(
            id,
            used_unsafe,
            package["unsafety"]["forbids_unsafe"] == true,
        )?;
        if used_unsafe != 0 {
            unsafe_packages.insert(format!("{name}@{version}"));
        }
    }
    let (common_count, selected_target_specific) = validate_unsafe_package_set(&unsafe_packages)?;
    println!(
        "cargo-geiger matched the reviewed {common_count}-package common unsafe-bearing inventory plus {selected_target_specific} target-specific packages; owned packages remain zero-unsafe"
    );
    Ok(())
}

fn validate_owned_unsafe_package(
    id: &serde_json::Value,
    used_unsafe: u64,
    forbids_unsafe: bool,
) -> Result<(), String> {
    let source = &id["source"];
    let owned = source.is_null() || source.get("Path").is_some();
    if owned && id["name"].as_str() == Some(UNSAFE_CRATE) {
        return Ok(());
    }
    if owned && (used_unsafe != 0 || !forbids_unsafe) {
        return Err(format!(
            "owned package {}@{} does not have a zero-unsafe forbid inventory",
            id["name"].as_str().unwrap_or("unknown"),
            id["version"].as_str().unwrap_or("unknown"),
        ));
    }
    Ok(())
}

fn normal_dependency_packages(
    root: &Path,
    package: &str,
    all_features: bool,
) -> Result<BTreeSet<String>, String> {
    let mut command = Command::new("cargo");
    command.current_dir(root).args([
        "tree", "--color", "never", "--locked", "--edges", "normal", "--prefix", "none", "-p",
        package, "--target", "all",
    ]);
    if all_features {
        command.arg("--all-features");
    }
    let output = command_output(&mut command)?;
    output
        .lines()
        .map(|line| {
            line.split_whitespace()
                .next()
                .map(str::to_owned)
                .ok_or_else(|| format!("{package} dependency tree contains an empty entry"))
        })
        .collect()
}

fn validate_dependency_boundaries(
    core: &BTreeSet<String>,
    sources: &BTreeSet<String>,
    metadata: &str,
) -> Result<(), String> {
    let coupled = core
        .iter()
        .filter(|package| {
            (package.starts_with("rustleaks-") && package.as_str() != "rustleaks-core")
                || package.as_str() == "xtask"
        })
        .collect::<Vec<_>>();
    if !coupled.is_empty() {
        return Err(format!(
            "rustleaks-core depends on higher-layer or codec packages: {coupled:?}"
        ));
    }

    let native_helpers = ["bindgen", "cc", "cmake", "pkg-config", "vcpkg"];
    let native = sources
        .iter()
        .filter(|package| native_helpers.contains(&package.as_str()) || package.ends_with("-sys"))
        .collect::<Vec<_>>();
    if !native.is_empty() {
        return Err(format!(
            "normal all-feature source graph contains native build dependencies: {native:?}"
        ));
    }

    let metadata: serde_json::Value = serde_json::from_str(metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omits packages")?;
    let linked = packages
        .iter()
        .filter_map(|package| {
            package["links"].as_str().map(|links| {
                format!(
                    "{}@{} ({links})",
                    package["name"].as_str().unwrap_or("<unnamed>"),
                    package["version"].as_str().unwrap_or("<unknown>")
                )
            })
        })
        .collect::<Vec<_>>();
    if !linked.is_empty() {
        return Err(format!(
            "locked workspace resolution contains native links packages: {linked:?}"
        ));
    }
    Ok(())
}

fn dependency_safety_check() -> Result<(), String> {
    let root = workspace_root()?;
    let core = normal_dependency_packages(&root, "rustleaks-core", false)?;
    let sources = normal_dependency_packages(&root, "rustleaks-sources", true)?;
    let metadata = command_output(Command::new("cargo").current_dir(&root).args([
        "metadata",
        "--format-version",
        "1",
        "--offline",
        "--locked",
    ]))?;
    validate_dependency_boundaries(&core, &sources, &metadata)?;
    println!(
        "dependency boundaries exclude core layer coupling, native build helpers, and links packages"
    );
    Ok(())
}

/// Lists every owned crate root: `src/lib.rs`, `src/main.rs`, `src/bin/*.rs`,
/// `examples/*.rs` and `fuzz/fuzz_targets/*.rs` of each directory under
/// `crates/`. Scanning means a new binary, example or fuzz target is checked
/// without a list to update.
fn owned_crate_roots(root: &Path) -> Result<Vec<String>, String> {
    let rust_files = |directory: &Path| -> Result<Vec<String>, String> {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("cannot list {}: {error}", directory.display())),
        };
        let mut names = Vec::new();
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.extension().is_some_and(|extension| extension == "rs") {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| format!("non-UTF-8 file name in {}", directory.display()))?;
                names.push(name.to_owned());
            }
        }
        Ok(names)
    };
    let mut roots = Vec::new();
    for entry in std::fs::read_dir(root.join("crates"))
        .map_err(|error| format!("cannot list crates: {error}"))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if !path.join("Cargo.toml").is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("non-UTF-8 crate directory name")?
            .to_owned();
        for file in ["src/lib.rs", "src/main.rs"] {
            if path.join(file).is_file() {
                roots.push(format!("crates/{name}/{file}"));
            }
        }
        for directory in ["src/bin", "examples", "fuzz/fuzz_targets", "tests"] {
            for file in rust_files(&path.join(directory))? {
                roots.push(format!("crates/{name}/{directory}/{file}"));
            }
        }
    }
    roots.sort();
    if roots.is_empty() {
        return Err("no owned crate roots found under crates/".into());
    }
    Ok(roots)
}

/// The only owned crate that may use unsafe Rust: the C ABI of the Go and
/// Python bindings. See `docs/dev/dependencies.md`.
const UNSAFE_CRATE: &str = "rustleaks-ffi";
/// The crate root of [`UNSAFE_CRATE`]. Its other roots, such as fuzz
/// targets, still forbid unsafe code.
const UNSAFE_CRATE_ROOT: &str = "crates/rustleaks-ffi/src/lib.rs";
/// Lints that [`UNSAFE_CRATE`] must deny, in its root and its manifest.
const UNSAFE_CRATE_LINTS: [&str; 3] = [
    "unsafe_op_in_unsafe_fn",
    "clippy::undocumented_unsafe_blocks",
    "clippy::missing_safety_doc",
];

/// Checks the root of the one crate that may use unsafe code: it denies the
/// unsafe lints and refuses to build without unwinding, which its
/// `catch_unwind` boundary needs.
fn validate_unsafe_crate_root(source: &str) -> Result<(), String> {
    let deny = source
        .split("#![deny(")
        .nth(1)
        .and_then(|tail| tail.split(")]").next())
        .ok_or_else(|| format!("{UNSAFE_CRATE_ROOT} has no #![deny(...)] lint list"))?;
    for lint in UNSAFE_CRATE_LINTS {
        if !deny.split(',').any(|entry| entry.trim() == lint) {
            return Err(format!("{UNSAFE_CRATE_ROOT} does not deny {lint}"));
        }
    }
    if !source.contains("#[cfg(not(panic = \"unwind\"))]\ncompile_error!(") {
        return Err(format!(
            "{UNSAFE_CRATE_ROOT} must fail to compile without panic=unwind"
        ));
    }
    Ok(())
}

/// Checks that the manifest of [`UNSAFE_CRATE`] denies the unsafe lints
/// for Cargo builds.
fn validate_unsafe_crate_manifest(manifest: &str) -> Result<(), String> {
    if manifest.contains("[lints]\nworkspace = true") {
        return Err(format!(
            "{UNSAFE_CRATE} cannot inherit the workspace forbid"
        ));
    }
    for line in [
        "unsafe_op_in_unsafe_fn = \"deny\"",
        "undocumented_unsafe_blocks = \"deny\"",
        "missing_safety_doc = \"deny\"",
    ] {
        if !manifest.lines().any(|entry| entry == line) {
            return Err(format!("{UNSAFE_CRATE} manifest lacks `{line}`"));
        }
    }
    Ok(())
}

fn owned_safety_check() -> Result<(), String> {
    let root = workspace_root()?;
    let workspace = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("cannot read workspace manifest: {error}"))?;
    if !workspace.contains("[workspace.lints.rust]\nunsafe_code = \"forbid\"") {
        return Err("workspace must forbid unsafe code for inheriting owned crates".into());
    }
    let crate_roots = owned_crate_roots(&root)?;
    if !crate_roots
        .iter()
        .any(|relative| relative == UNSAFE_CRATE_ROOT)
    {
        return Err(format!("{UNSAFE_CRATE_ROOT} is missing"));
    }
    for relative in &crate_roots {
        let source = std::fs::read_to_string(root.join(relative))
            .map_err(|error| format!("cannot read owned crate root {relative}: {error}"))?;
        if relative == UNSAFE_CRATE_ROOT {
            validate_unsafe_crate_root(&source)?;
            continue;
        }
        if !source
            .lines()
            .take(50)
            .any(|line| line == "#![forbid(unsafe_code)]")
        {
            return Err(format!(
                "owned crate root {relative} does not forbid unsafe code"
            ));
        }
    }
    let manifest = std::fs::read_to_string(root.join("crates/rustleaks-ffi/Cargo.toml"))
        .map_err(|error| format!("cannot read the {UNSAFE_CRATE} manifest: {error}"))?;
    validate_unsafe_crate_manifest(&manifest)?;
    // Test crate roots forbid unsafe code like other roots. Test modules in
    // subfolders inherit their root's forbid, and the link test library is
    // the one named exception.
    for relative in test_folder_rust_files(&root)? {
        if crate_roots.contains(&relative) {
            continue;
        }
        let source = std::fs::read_to_string(root.join(&relative))
            .map_err(|error| format!("cannot read {relative}: {error}"))?;
        if relative == LINKTEST_ROOT {
            validate_linktest_root(&source)?;
        } else if mentions_unsafe(&source) {
            return Err(format!("{relative} uses unsafe Rust in a test"));
        }
    }
    // A crate root forbids unsafe code only for the files that the compiler
    // reaches from it, and a Bazel target can name a root that the list
    // above does not know. So every Rust file outside the FFI crate is also
    // searched for unsafe code and for includes the search cannot follow.
    let searched = rust_files_outside_unsafe_crate(&root)?;
    for relative in &searched {
        let source = std::fs::read_to_string(root.join(relative))
            .map_err(|error| format!("cannot read {relative}: {error}"))?;
        if mentions_unsafe(&source) || mentions_unsafe_attribute(&source) {
            return Err(format!(
                "{relative} uses unsafe Rust outside {UNSAFE_CRATE}; move it into crates/rustleaks-ffi"
            ));
        }
        if let Some(include) = non_rust_include(&source) {
            return Err(format!(
                "{relative} includes {include:?}, which the unsafe search does not read; include only .rs files"
            ));
        }
    }
    println!(
        "every owned crate root forbids unsafe code except {UNSAFE_CRATE_ROOT}, which denies undocumented unsafe code; {} Rust files outside crates/{UNSAFE_CRATE}, under crates/ and {}, use no unsafe Rust",
        searched.len(),
        RUST_OUTSIDE_CRATES.join(", ")
    );
    Ok(())
}

/// Folders outside `crates/` that Bazel builds Rust from. Rust there is
/// never in the unsafe inventory, so it must not use unsafe Rust at all.
const RUST_OUTSIDE_CRATES: &[&str] = &["bazel", "bindings", "release"];

/// Lists the Rust files under `crates/`, except those of [`UNSAFE_CRATE`],
/// and under [`RUST_OUTSIDE_CRATES`], relative to `root`.
fn rust_files_outside_unsafe_crate(root: &Path) -> Result<Vec<String>, String> {
    fn walk(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return Ok(());
        };
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, files)?;
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
                files.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    for directory in RUST_OUTSIDE_CRATES {
        walk(root, &root.join(directory), &mut files)?;
    }
    let crates = std::fs::read_dir(root.join("crates"))
        .map_err(|error| format!("cannot list crates/: {error}"))?;
    for entry in crates {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() && !path.ends_with(UNSAFE_CRATE) {
            walk(root, &path, &mut files)?;
        }
    }
    files.sort();
    Ok(files)
}

/// Attributes that are unsafe without the `unsafe` keyword before edition
/// 2024.
const UNSAFE_ATTRIBUTES: [&str; 3] = ["no_mangle", "export_name", "link_section"];

/// Macros that run assembly. `global_asm!` needs no `unsafe` keyword.
const ASSEMBLY_MACROS: [&str; 3] = ["asm", "global_asm", "naked_asm"];

/// Reports whether Rust source uses, in code, an attribute in
/// [`UNSAFE_ATTRIBUTES`] or a macro in [`ASSEMBLY_MACROS`].
fn mentions_unsafe_attribute(source: &str) -> bool {
    let code = code_only(source).chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < code.len() {
        if !is_identifier(code[index]) {
            index += 1;
            continue;
        }
        let end = identifier_end(&code, index);
        let word = code[index..end].iter().collect::<String>();
        if UNSAFE_ATTRIBUTES.contains(&word.as_str())
            || (ASSEMBLY_MACROS.contains(&word.as_str())
                && next_code(&code, end).is_some_and(|next| code[next] == '!'))
        {
            return true;
        }
        index = end;
    }
    false
}

/// Returns the first `include!` or path attribute target in Rust source that
/// is not a literal `.rs` path, since the unsafe search reads only `.rs`
/// files. It finds `include!` with any delimiter, `#[path = ...]` and
/// `path = ...` inside any attribute, such as `cfg_attr`, with comments or
/// whitespace between the tokens.
fn non_rust_include(source: &str) -> Option<String> {
    let tokens = literal_marked(source);
    let code = |index: usize| {
        tokens
            .get(index)
            .filter(|(_, literal)| !literal)
            .map(|(c, _)| *c)
    };
    let next = |mut index: usize| {
        while let Some(&(character, literal)) = tokens.get(index) {
            if literal || !is_rust_whitespace(character) {
                return Some(index);
            }
            index += 1;
        }
        None
    };
    let word_at = |index: usize| {
        let mut end = index;
        while code(end).is_some_and(is_identifier) {
            end += 1;
        }
        let starts = index == 0 || !code(index - 1).is_some_and(is_identifier);
        (starts && end > index).then(|| {
            (
                tokens[index..end]
                    .iter()
                    .map(|(c, _)| c)
                    .collect::<String>(),
                end,
            )
        })
    };
    // The target after `at`: a literal path, or the start of whatever else
    // is there.
    let target = |at: Option<usize>| -> Result<(), String> {
        let Some(at) = at.filter(|&at| tokens[at].1) else {
            let rest = at.map_or(String::new(), |at| {
                tokens[at..].iter().take(40).map(|(c, _)| c).collect()
            });
            return Err(rest);
        };
        let mut end = at;
        while tokens.get(end).is_some_and(|(_, literal)| *literal) {
            end += 1;
        }
        let literal = tokens[at..end].iter().map(|(c, _)| c).collect::<String>();
        let path = literal
            .split_once('"')
            .and_then(|(_, rest)| rest.rsplit_once('"'))
            .map_or(literal.as_str(), |(path, _)| path);
        if path.ends_with(".rs") {
            Ok(())
        } else {
            Err(path.to_owned())
        }
    };
    let mut attribute_depth = 0_usize;
    let mut index = 0;
    while index < tokens.len() {
        let Some(character) = code(index) else {
            index += 1;
            continue;
        };
        if character == '#' {
            let mut open = next(index + 1);
            if open.and_then(code) == Some('!') {
                open = open.and_then(|open| next(open + 1));
            }
            if let Some(open) = open.filter(|&open| code(open) == Some('[')) {
                attribute_depth = 1;
                index = open + 1;
                continue;
            }
        }
        if attribute_depth > 0 {
            match character {
                '[' | '(' => attribute_depth += 1,
                ']' | ')' => attribute_depth -= 1,
                _ => {}
            }
        }
        if let Some((word, end)) = word_at(index) {
            let after = next(end);
            if word == "include" && after.and_then(code) == Some('!') {
                let open = after.and_then(|after| next(after + 1));
                if open
                    .and_then(code)
                    .is_some_and(|open| matches!(open, '(' | '[' | '{'))
                    && let Err(found) = target(open.and_then(|open| next(open + 1)))
                {
                    return Some(found);
                }
            }
            if word == "path"
                && attribute_depth > 0
                && after.and_then(code) == Some('=')
                && let Err(found) = target(after.and_then(|after| next(after + 1)))
            {
                return Some(found);
            }
            index = end;
            continue;
        }
        index += 1;
    }
    None
}

/// Returns the next index at or after `index` in `code` that is not
/// whitespace.
fn next_code(code: &[char], index: usize) -> Option<usize> {
    (index..code.len()).find(|&index| !is_rust_whitespace(code[index]))
}

/// Whether Rust's lexer treats `character` as whitespace. Rust uses the
/// Unicode `Pattern_White_Space` set, which also holds the left-to-right and
/// right-to-left marks that `char::is_whitespace` does not.
fn is_rust_whitespace(character: char) -> bool {
    character.is_whitespace() || matches!(character, '\u{200E}' | '\u{200F}')
}

/// Returns the characters of Rust source without comments, each marked as
/// part of a string or character literal or not. Comments become one space.
fn literal_marked(source: &str) -> Vec<(char, bool)> {
    let mut tokens = Vec::with_capacity(source.len());
    scan_rust(source, &mut |piece: &[char], literal: bool| {
        tokens.extend(piece.iter().map(|&character| (character, literal)));
    });
    tokens
}

/// Returns the code of Rust source with comments (nested block comments
/// included), string literals (raw, byte and C strings included) and
/// character literals blanked, so that a search for a keyword sees only
/// code. Identifiers, raw identifiers, lifetimes and labels are read as whole
/// tokens and stay code, so that the `r` at the end of `'r` or `r#r` never
/// starts a raw string.
fn code_only(source: &str) -> String {
    let mut code = String::with_capacity(source.len());
    scan_rust(source, &mut |piece: &[char], literal: bool| {
        if literal {
            code.push(' ');
        } else {
            code.extend(piece);
        }
    });
    code
}

/// Splits Rust source into code and literals, without comments, and passes
/// each piece to `emit` with whether it is a literal. A comment is passed as
/// one space of code.
fn scan_rust(source: &str, emit: &mut dyn FnMut(&[char], bool)) {
    let characters = source.chars().collect::<Vec<_>>();
    let space = [' '];
    let mut index = 0;
    while let Some(&character) = characters.get(index) {
        let next = characters.get(index + 1).copied();
        if character == '/' && next == Some('/') {
            while index < characters.len() && characters[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if character == '/' && next == Some('*') {
            let mut depth = 0_usize;
            while index < characters.len() {
                match (characters[index], characters.get(index + 1)) {
                    ('/', Some('*')) => {
                        depth += 1;
                        index += 2;
                    }
                    ('*', Some('/')) => {
                        depth -= 1;
                        index += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => index += 1,
                }
            }
            emit(&space, false);
            continue;
        }
        if is_identifier(character) {
            let end = identifier_end(&characters, index);
            let word = characters[index..end].iter().collect::<String>();
            if matches!(word.as_str(), "r" | "br" | "cr")
                && let Some(end) = raw_string_end(&characters, end)
            {
                emit(&characters[index..end], true);
                index = end;
                continue;
            }
            // A raw identifier, such as `r#r`, is one token.
            let end = raw_identifier_end(&characters, &word, end).unwrap_or(end);
            emit(&characters[index..end], false);
            index = end;
            continue;
        }
        if character == '"' {
            let start = index;
            index += 1;
            while let Some(&next) = characters.get(index) {
                index += if next == '\\' { 2 } else { 1 };
                if next == '"' {
                    break;
                }
            }
            index = index.min(characters.len());
            emit(&characters[start..index], true);
            continue;
        }
        if character == '\'' {
            // A character literal is an escape, or one character and a
            // closing quote. Anything else starts a lifetime or a label.
            let end = if next == Some('\\') {
                // The escaped character itself may be a quote.
                characters
                    .get(index + 3..)
                    .and_then(|rest| rest.iter().position(|&next| next == '\''))
                    .map(|offset| index + 4 + offset)
            } else if characters.get(index + 2) == Some(&'\'') {
                Some(index + 3)
            } else {
                None
            };
            if let Some(end) = end.map(|end: usize| end.min(characters.len())) {
                emit(&characters[index..end], true);
                index = end;
                continue;
            }
            // A lifetime or a label, such as `'r` or `'r#r`, is one token.
            let start = index + 1;
            let mut end = identifier_end(&characters, start);
            let word = characters[start..end].iter().collect::<String>();
            end = raw_identifier_end(&characters, &word, end).unwrap_or(end);
            emit(&characters[index..end], false);
            index = end;
            continue;
        }
        emit(&characters[index..=index], false);
        index += 1;
    }
}

fn is_identifier(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Returns the index just past the identifier characters from `start`.
fn identifier_end(characters: &[char], start: usize) -> usize {
    characters.get(start..).map_or(start, |rest| {
        start + rest.iter().take_while(|&&next| is_identifier(next)).count()
    })
}

/// If `word`, which ends at `end`, is the `r` of a raw identifier such as
/// `r#r`, returns the index just past the identifier.
fn raw_identifier_end(characters: &[char], word: &str, end: usize) -> Option<usize> {
    (word == "r"
        && characters.get(end) == Some(&'#')
        && characters
            .get(end + 1)
            .is_some_and(|&next| is_identifier(next)))
    .then(|| identifier_end(characters, end + 1))
}

/// If the `r`, `br` or `cr` prefix that ends just before `open` starts a raw
/// string literal (`r"…"`, `r#"…"#`, `br#"…"#` or `cr"…"`), returns the index
/// just past the literal.
fn raw_string_end(characters: &[char], open: usize) -> Option<usize> {
    let hashes = characters
        .get(open..)?
        .iter()
        .take_while(|&&next| next == '#')
        .count();
    let quote = open + hashes;
    if characters.get(quote) != Some(&'"') {
        return None;
    }
    let mut cursor = quote + 1;
    while cursor < characters.len() {
        if characters[cursor] == '"'
            && characters[cursor + 1..]
                .iter()
                .take(hashes)
                .filter(|&&next| next == '#')
                .count()
                == hashes
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(characters.len())
}

/// Reports whether Rust source uses the `unsafe` keyword in code: an unsafe
/// block, function, impl or attribute such as `#[unsafe(no_mangle)]`.
fn mentions_unsafe(source: &str) -> bool {
    code_only(source)
        .split(|character: char| !(character.is_alphanumeric() || character == '_'))
        .any(|word| word == "unsafe")
}

/// The one Rust file outside `crates/rustleaks-ffi/src` that uses unsafe Rust:
/// the second static library of the cgo link test. It is its own crate root
/// with the same unsafe lint denials as the FFI crate, and its only unsafe
/// Rust is `#[unsafe(no_mangle)]` on its C exports.
const LINKTEST_ROOT: &str = "crates/rustleaks-ffi/tests/linktest/other.rs";

/// Checks the link test library: the FFI crate's deny lints, and no unsafe
/// Rust but `#[unsafe(no_mangle)]` attributes, each under a `SAFETY:`
/// comment.
fn validate_linktest_root(source: &str) -> Result<(), String> {
    let denials = "#![deny(\n    unsafe_op_in_unsafe_fn,\n    clippy::undocumented_unsafe_blocks,\n    clippy::missing_safety_doc\n)]";
    if !source.contains(denials) {
        return Err(format!(
            "{LINKTEST_ROOT} must deny the unsafe lints that crates/rustleaks-ffi denies"
        ));
    }
    let without_attributes = source.replace("#[unsafe(no_mangle)]", "");
    if mentions_unsafe(&without_attributes) {
        return Err(format!(
            "{LINKTEST_ROOT} may use unsafe Rust only as #[unsafe(no_mangle)]"
        ));
    }
    let lines = source.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "#[unsafe(no_mangle)]"
            && !lines[..index]
                .iter()
                .rev()
                .take_while(|previous| previous.trim_start().starts_with("//"))
                .any(|previous| previous.trim_start().starts_with("// SAFETY:"))
        {
            return Err(format!(
                "{LINKTEST_ROOT}:{} has #[unsafe(no_mangle)] without a SAFETY comment",
                index + 1
            ));
        }
    }
    Ok(())
}

/// Lists the Rust files under `crates/*/tests/` folders, relative to `root`.
fn test_folder_rust_files(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    let entries = std::fs::read_dir(root.join("crates"))
        .map_err(|error| format!("cannot list crates: {error}"))?;
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        let tests = path.join("tests");
        if tests.is_dir() {
            collect_rust_files(root, &tests, &mut files)?;
        }
    }
    files.sort();
    Ok(files)
}

fn collect_rust_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?;
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            collect_rust_files(root, &path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            files.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

pub(crate) fn security_check() -> Result<(), String> {
    supply_chain_check()?;
    rustsec_check()?;
    vet_check()?;
    dependency_safety_check()?;
    owned_safety_check()?;
    unsafe_inventory_check()?;
    miri_check()?;
    panic_abort_check()?;
    println!("dependency policy, vetting, Miri, panic policy, and owned-code safety checks passed");
    Ok(())
}

fn miri_check() -> Result<(), String> {
    let root = workspace_root()?;
    let target = ScopedTempDir::new("miri")?;
    let toolchain = format!("+{MIRI_TOOLCHAIN}");
    let cases = [
        (
            "rustleaks-core",
            "decoder::tests::maps_every_overlap_geometry_with_signed_overflow",
        ),
        (
            "rustleaks-core",
            "config::loader::tests::virtual_paths_are_host_independent_and_preserve_parents",
        ),
        (
            "rustleaks-core",
            "session::tests::batches_merge_only_under_the_same_policy",
        ),
        (
            "rustleaks-sources",
            "runner::tests::partial_fragment_findings_are_not_merged_into_a_source_batch",
        ),
        (
            "rustleaks-report",
            "go_json::tests::float32_format_uses_go_json_cutoffs_and_sign",
        ),
        // The C ABI: null and misaligned pointer checks, rule views made
        // before their owner moves, finding views read after a scan on a
        // scan thread, and a panic that crosses that thread.
        (
            "rustleaks-ffi",
            "tests::null_handles_and_out_pointers_are_invalid_arguments",
        ),
        (
            "rustleaks-ffi",
            "tests::findings_carry_every_field_and_the_given_path",
        ),
        (
            "rustleaks-ffi",
            "tests::views_have_null_pointers_for_empty_lists",
        ),
        (
            "rustleaks-ffi",
            "tests::a_panicking_scan_drops_its_scratch_and_returns_an_internal_error",
        ),
        (
            "rustleaks-ffi",
            "tests::misaligned_out_handle_argument_and_free_pointers_are_invalid",
        ),
        (
            "rustleaks-ffi",
            "tests::error_message_checks_both_out_pointers_before_writing",
        ),
        (
            "rustleaks-ffi",
            "tests::rules_list_every_reporting_rule_in_report_order",
        ),
        (
            "rustleaks-ffi",
            "tests::an_engine_from_another_process_is_closed_and_free_releases_nothing",
        ),
    ];
    for (package, case) in cases {
        command_status_with_timeout(
            Command::new("cargo")
                .current_dir(&root)
                .env("CARGO_TARGET_DIR", &target.path)
                .args([
                    toolchain.as_str(),
                    "miri",
                    "test",
                    "-p",
                    package,
                    "--lib",
                    "--locked",
                    "--offline",
                    case,
                    "--",
                    "--exact",
                ]),
            Duration::from_mins(20),
            &format!("Miri case {package}::{case}"),
        )?;
    }
    println!("selected core, source, report and C ABI state transitions passed pinned Miri");
    Ok(())
}

fn panic_abort_check() -> Result<(), String> {
    let root = workspace_root()?;
    let target = ScopedTempDir::new("panic-abort")?;
    command_status_with_timeout(
        Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target.path)
            .env("RUSTFLAGS", "-D warnings -C panic=abort")
            .args([
                "run",
                "--locked",
                "--offline",
                "-p",
                "rustleaks-sources",
                "--example",
                "panic_abort_policy",
                "--all-features",
            ]),
        Duration::from_mins(4),
        "panic=abort archive policy",
    )?;
    println!("panic=abort archive policy rejected 7z as unsupported before dependency entry");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        COMPCOL_EXEMPTION_SHA256, COMPCOL_EXEMPTION_TARGETS, mentions_unsafe, owned_crate_roots,
        parse_civil_day, reviewed_unsafe_packages, validate_compcol_exemption_scope,
        validate_dependency_boundaries, validate_owned_unsafe_package,
        validate_supply_chain_exceptions, validate_unsafe_crate_manifest,
        validate_unsafe_crate_root, validate_unsafe_package_set, validate_vet_exemption,
    };

    #[test]
    fn unsafe_rust_is_found_in_code_but_not_in_comments_or_lint_names() {
        assert!(mentions_unsafe(
            "#[unsafe(no_mangle)]\npub extern \"C\" fn f() {}\n"
        ));
        assert!(mentions_unsafe("fn f() { unsafe { g() } }\n"));
        // A quote inside a character literal does not open a string.
        assert!(mentions_unsafe("const Q: char = '\"'; unsafe fn f() {}\n"));
        assert!(mentions_unsafe("const Q: u8 = b'\"'; unsafe fn f() {}\n"));
        assert!(mentions_unsafe("const Q: char = '\\''; unsafe fn f() {}\n"));
        // A quote inside a raw string does not end it early.
        assert!(mentions_unsafe(
            "const S: &str = r#\"a \" b\"#; unsafe fn f() {}\n"
        ));
        assert!(!mentions_unsafe("const S: &str = r#\"a \" unsafe\"#;\n"));
        assert!(!mentions_unsafe("const S: &[u8] = br\"unsafe\";\n"));
        assert!(!mentions_unsafe(
            "const C: char = 'u'; /* /* unsafe */ unsafe */\n"
        ));
        // Lifetimes and labels are code, not character literals.
        assert!(mentions_unsafe(
            "fn f<'a>(x: &'a u8) { 'outer: loop { unsafe { g() } } }\n"
        ));
        // A lifetime or a raw identifier that ends in r is not a raw
        // string prefix.
        let lifetime_macro =
            "macro_rules! m { ($l:lifetime $a:literal, $e:expr, $b:literal) => { $e } }\n";
        assert!(mentions_unsafe(&format!(
            "{lifetime_macro}let x = m!('r\"\\\"\", unsafe {{ std::ptr::read(&7u8) }}, \"\\\"\");\n"
        )));
        assert!(mentions_unsafe(&format!(
            "{lifetime_macro}let x = m!('br\"\\\"\", unsafe {{ std::ptr::read(&7u8) }}, \"\\\"\");\n"
        )));
        assert!(mentions_unsafe(
            "macro_rules! m { ($l:ident $a:literal, $e:expr, $b:literal) => { $e } }\n\
             let x = m!(r#r\"\\\"\", unsafe { std::ptr::read(&7u8) }, \"\\\"\");\n"
        ));
        assert!(mentions_unsafe(
            "fn f<'a>() { let _: &'a u8; unsafe { g() } }\n"
        ));
        assert!(!mentions_unsafe("const S: &str = cr#\"unsafe\"#;\n"));
        // Unsafe attributes from before edition 2024 count, in code only.
        assert!(super::mentions_unsafe_attribute(
            "#[no_mangle]\npub extern \"C\" fn f() {}\n"
        ));
        assert!(super::mentions_unsafe_attribute(
            "#[link_section = \".x\"]\nstatic X: u8 = 0;\n"
        ));
        assert!(!super::mentions_unsafe_attribute(
            "// #[no_mangle]\nconst S: &str = \"export_name\";\n"
        ));
        // Includes must name .rs files, which the search reads too.
        assert_eq!(super::non_rust_include("include!(\"tables.rs\");\n"), None);
        assert_eq!(
            super::non_rust_include("const S: &str = include_str!(\"x.txt\");\n"),
            None
        );
        assert_eq!(
            super::non_rust_include("include!(\"x.inc\");\n").as_deref(),
            Some("x.inc")
        );
        // Rust also treats the left-to-right and right-to-left marks as
        // whitespace between tokens.
        assert_eq!(
            super::non_rust_include("include\u{200E}!(\"x.inc\");\n").as_deref(),
            Some("x.inc")
        );
        assert_eq!(
            super::non_rust_include("#[path\u{200E}= \"x.txt\"]\nmod x;\n").as_deref(),
            Some("x.txt")
        );
        assert_eq!(
            super::non_rust_include("#\u{200F}[path = \"x.txt\"]\nmod x;\n").as_deref(),
            Some("x.txt")
        );
        assert_eq!(
            super::non_rust_include("#[path = \"x.txt\"]\nmod x;\n").as_deref(),
            Some("x.txt")
        );
        assert!(
            super::non_rust_include("include!(concat!(env!(\"OUT_DIR\"), \"/x.rs\"));\n").is_some()
        );
        // Any delimiter, comments between tokens, and path in any attribute.
        for (source, found) in [
            ("include!{\"x.inc\"}\n", "x.inc"),
            ("include![\"x.inc\"]\n", "x.inc"),
            ("include /* x */ ! /* y */ (\"x.inc\");\n", "x.inc"),
            ("include // x\n!(\"x.inc\");\n", "x.inc"),
            ("#[path /* x */ = \"x.txt\"]\nmod x;\n", "x.txt"),
            ("#[cfg_attr(all(), path = \"x.txt\")]\nmod x;\n", "x.txt"),
            ("#![cfg_attr(unix, path = \"x.txt\")]\n", "x.txt"),
            ("#[path = r\"x.txt\"]\nmod x;\n", "x.txt"),
        ] {
            assert_eq!(
                super::non_rust_include(source).as_deref(),
                Some(found),
                "{source}"
            );
        }
        for source in [
            "#[cfg_attr(unix, path = \"unix.rs\")]\nmod x;\n",
            "fn f(path: &str) { let path = 1; }\n",
            "#[derive(Debug)]\nstruct S { path: u8 }\nconst T: &str = \"include!(x)\";\n",
            "// include!(\"x.inc\")\nfn f() {}\n",
            "let x = my_include!(\"x.inc\");\n",
        ] {
            assert_eq!(super::non_rust_include(source), None, "{source}");
        }
        // Assembly macros, which need no unsafe keyword in global_asm!.
        assert!(super::mentions_unsafe_attribute("global_asm!(\"nop\");\n"));
        assert!(super::mentions_unsafe_attribute(
            "global_asm\u{200F}!(\"nop\");\n"
        ));
        assert!(super::mentions_unsafe_attribute(
            "core::arch::global_asm /* x */ !(\"nop\");\n"
        ));
        assert!(super::mentions_unsafe_attribute(
            "fn f() { asm!(\"nop\") }\n"
        ));
        assert!(!super::mentions_unsafe_attribute(
            "let asm = 1; // global_asm!\n"
        ));
        // An identifier that ends in r is not a raw string prefix.
        assert!(mentions_unsafe(
            "fn f() { let r = 1; let br = \"x\"; unsafe { g() } }\n"
        ));
        assert!(mentions_unsafe("pub unsafe extern \"C\" fn f() {}\n"));
        assert!(!mentions_unsafe(
            "#![forbid(unsafe_code)]\n// unsafe in a comment\n"
        ));
        assert!(!mentions_unsafe(
            "let url = \"https://example.com/unsafe\"; /* unsafe */\n"
        ));
        assert!(mentions_unsafe(
            "let url = \"https://example.com/\"; unsafe { f() }\n"
        ));
    }

    #[test]
    fn the_link_test_library_keeps_its_unsafe_boundary() {
        let root = crate::workspace_root().unwrap();
        let source = std::fs::read_to_string(root.join(super::LINKTEST_ROOT)).unwrap();
        super::validate_linktest_root(&source).unwrap();
        let block = source.replacen("text.len() as u64", "unsafe { text.len() as u64 }", 1);
        assert!(super::validate_linktest_root(&block).is_err());
        let undocumented = source.replacen("// SAFETY:", "// Note:", 1);
        assert!(super::validate_linktest_root(&undocumented).is_err());
    }

    #[test]
    fn owned_crate_roots_include_every_binary_example_and_fuzz_target() {
        let roots = owned_crate_roots(&crate::workspace_root().unwrap()).unwrap();
        for expected in [
            "crates/rustleaks-cli/src/main.rs",
            "crates/rustleaks-eval/src/bin/rustleaks-cli-fixture.rs",
            "crates/rustleaks-eval/src/bin/rustleaks-perf.rs",
            "crates/rustleaks-core/src/lib.rs",
            "crates/rustleaks-sources/examples/panic_abort_policy.rs",
            "crates/rustleaks-sources/fuzz/fuzz_targets/archive.rs",
            "crates/xtask/src/main.rs",
        ] {
            assert!(roots.iter().any(|root| root == expected), "{expected}");
        }
        let fuzz_roots = roots
            .iter()
            .filter(|root| root.contains("/fuzz/fuzz_targets/"))
            .count();
        assert_eq!(fuzz_roots, crate::fuzzing::TARGETS.len());
    }

    #[test]
    fn unsafe_inventory_accepts_only_reviewed_target_variance() {
        let (common, target_specific) = reviewed_unsafe_packages();
        assert_eq!(validate_unsafe_package_set(&common).unwrap(), (23, 0));

        let union = common.union(&target_specific).cloned().collect();
        assert_eq!(validate_unsafe_package_set(&union).unwrap(), (23, 2));

        let missing = common.iter().skip(1).cloned().collect::<BTreeSet<_>>();
        assert!(validate_unsafe_package_set(&missing).is_err());

        let mut unexpected = common;
        unexpected.insert("unreviewed@1.0.0".into());
        assert!(validate_unsafe_package_set(&unexpected).is_err());
    }

    #[test]
    fn unsafe_inventory_enforces_path_package_policy() {
        let mut id = serde_json::json!({
            "name": "rustleaks-core",
            "version": "0.1.0",
            "source": { "Path": "file:///workspace/crates/rustleaks-core" },
        });
        assert!(validate_owned_unsafe_package(&id, 0, true).is_ok());
        assert!(validate_owned_unsafe_package(&id, 1, true).is_err());
        assert!(validate_owned_unsafe_package(&id, 0, false).is_err());

        id["source"] = serde_json::Value::Null;
        assert!(validate_owned_unsafe_package(&id, 0, true).is_ok());
        assert!(validate_owned_unsafe_package(&id, 1, true).is_err());
        assert!(validate_owned_unsafe_package(&id, 0, false).is_err());

        id["source"] = serde_json::json!({ "Registry": { "name": "crates.io" } });
        assert!(validate_owned_unsafe_package(&id, 1, false).is_ok());
    }

    #[test]
    fn only_the_ffi_crate_may_use_unsafe_code() {
        let ffi = serde_json::json!({
            "name": "rustleaks-ffi",
            "version": "0.2.0",
            "source": { "Path": "file:///workspace/crates/rustleaks-ffi" },
        });
        assert!(validate_owned_unsafe_package(&ffi, 12, false).is_ok());
        let other = serde_json::json!({
            "name": "rustleaks-ffi-extra",
            "version": "0.2.0",
            "source": { "Path": "file:///workspace/crates/rustleaks-ffi-extra" },
        });
        assert!(validate_owned_unsafe_package(&other, 1, false).is_err());

        let root = crate::workspace_root().unwrap();
        let source = std::fs::read_to_string(root.join("crates/rustleaks-ffi/src/lib.rs")).unwrap();
        assert!(validate_unsafe_crate_root(&source).is_ok());
        assert!(validate_unsafe_crate_root("#![forbid(unsafe_code)]\n").is_err());
        let weaker = source.replace("    clippy::undocumented_unsafe_blocks,\n", "");
        assert!(validate_unsafe_crate_root(&weaker).is_err());
        let abort = source.replace("#[cfg(not(panic = \"unwind\"))]", "");
        assert!(validate_unsafe_crate_root(&abort).is_err());

        let manifest =
            std::fs::read_to_string(root.join("crates/rustleaks-ffi/Cargo.toml")).unwrap();
        assert!(validate_unsafe_crate_manifest(&manifest).is_ok());
        assert!(validate_unsafe_crate_manifest("[lints]\nworkspace = true\n").is_err());
        let weaker = manifest.replace(
            "missing_safety_doc = \"deny\"",
            "missing_safety_doc = \"warn\"",
        );
        assert!(validate_unsafe_crate_manifest(&weaker).is_err());
    }

    #[test]
    fn civil_dates_reject_impossible_exemption_deadlines() {
        assert_eq!(parse_civil_day("1970-01-01"), Some(0));
        assert!(parse_civil_day("2024-02-29").is_some());
        assert!(parse_civil_day("2023-02-29").is_none());
        assert!(parse_civil_day("2026-04-31").is_none());
        assert!(parse_civil_day("2026-13-01").is_none());
        assert!(parse_civil_day("2026-01-01-extra").is_none());
    }

    #[test]
    fn vet_exemptions_retain_ordinary_expiry_and_require_valid_metadata() {
        let today = parse_civil_day("2026-11-05").unwrap();
        let entry = |notes: &str| {
            toml::Value::Table(toml::map::Map::from_iter([
                ("version".into(), toml::Value::String("1.0.0".into())),
                (
                    "criteria".into(),
                    toml::Value::String("safe-to-deploy".into()),
                ),
                ("notes".into(), toml::Value::String(notes.into())),
            ]))
        };
        let metadata = "owner=maintainers; scope=runtime; rationale=review gap";
        for date in ["2026-11-05", "2026-11-06"] {
            assert!(
                !validate_vet_exemption(
                    "other",
                    &entry(&format!("{metadata}; review-by={date}")),
                    today,
                )
                .unwrap()
            );
        }
        for suffix in [
            "",
            "; review-by=2026-11-04",
            "; review-by=never",
            "; review-by=2026-11-31",
            "; review-by=2026-11-06; review-by=2026-11-07",
            "; owner=; review-by=2026-11-06",
            "; review-on=boundary-change",
        ] {
            assert!(
                validate_vet_exemption("other", &entry(&format!("{metadata}{suffix}")), today)
                    .is_err(),
                "{suffix}"
            );
        }
    }

    #[test]
    fn standing_vet_exemption_accepts_only_the_approved_package_and_criterion() {
        let entry: toml::Value = toml::from_str(
            r#"version = "0.8.0"
criteria = "safe-to-deploy"
notes = "owner=maintainers; scope=reviewed graph; rationale=unselected concern; resolution=fixed audited release; review-on=boundary-change"
"#,
        ).unwrap();
        let future = parse_civil_day("2100-01-01").unwrap();
        assert!(validate_vet_exemption("compcol", &entry, future).unwrap());
        assert!(validate_vet_exemption("other", &entry, future).is_err());
        for (field, value) in [
            ("version", "0.8.1"),
            ("criteria", "safe-to-run"),
            ("criteria", "unreviewed"),
            (
                "notes",
                "owner=maintainers; scope=runtime; rationale=gap; resolution=fix; review-on=never",
            ),
            (
                "notes",
                "owner=; scope=runtime; rationale=gap; resolution=fix; review-on=boundary-change",
            ),
            (
                "notes",
                "owner=maintainers; scope=runtime; rationale=gap; resolution=fix; review-on=boundary-change; review-on=boundary-change",
            ),
            (
                "notes",
                "owner=maintainers; scope=runtime; rationale=gap; review-on=boundary-change",
            ),
            (
                "notes",
                "owner=maintainers; scope=runtime; rationale=gap; resolution=fix; review-on=boundary-change; review-by=2100-01-01",
            ),
        ] {
            let mut invalid = entry.clone();
            invalid[field] = toml::Value::String(value.into());
            assert!(
                validate_vet_exemption("compcol", &invalid, future).is_err(),
                "{field}={value}"
            );
        }
        let mut criteria_array = entry.clone();
        criteria_array["criteria"] =
            toml::Value::Array(vec![toml::Value::String("safe-to-deploy".into())]);
        assert!(validate_vet_exemption("compcol", &criteria_array, future).unwrap());
        criteria_array["criteria"]
            .as_array_mut()
            .unwrap()
            .push(toml::Value::String("safe-to-run".into()));
        assert!(validate_vet_exemption("compcol", &criteria_array, future).is_err());
    }

    #[test]
    fn standing_compcol_scope_rejects_resolved_graph_expansion() {
        let core = BTreeSet::from(["rustleaks-core".to_owned()]);
        let metadata = serde_json::json!({
            "packages": [{"name":"compcol", "version":"0.8.0", "id":"compcol-id",
                "source":"registry+https://github.com/rust-lang/crates.io-index"}],
            "resolve":{"nodes":[{"id":"compcol-id", "features":["alloc","rar2"]}]},
        });
        let bazel = serde_json::json!({
            "crates":{"compcol 0.8.0":{
                "name":"compcol", "version":"0.8.0",
                "repository":{"Http":{"sha256":COMPCOL_EXEMPTION_SHA256}},
                "common_attrs":{"crate_features":{"common":["alloc","rar2"],"selects":{}}},
            }},
            "conditions":{"cfg(reviewed)":COMPCOL_EXEMPTION_TARGETS},
        });
        validate_compcol_exemption_scope(&core, &metadata, &bazel).unwrap();
        let mut coupled = core.clone();
        coupled.insert("compcol".into());
        assert!(validate_compcol_exemption_scope(&coupled, &metadata, &bazel).is_err());
        for (path, value) in [
            ("/packages/0/version", serde_json::json!("0.8.1")),
            ("/packages/0/source", serde_json::Value::Null),
            (
                "/resolve/nodes/0/features",
                serde_json::json!(["alloc", "rar2", "lzfse"]),
            ),
            ("/resolve/nodes/0/features", serde_json::json!(["rar2"])),
            (
                "/resolve/nodes/0/features",
                serde_json::json!(["alloc", "rar2", false]),
            ),
        ] {
            let mut changed = metadata.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                validate_compcol_exemption_scope(&core, &changed, &bazel).is_err(),
                "{path}"
            );
        }
        for (path, value) in [
            ("/crates/compcol 0.8.0/version", serde_json::json!("0.8.1")),
            (
                "/crates/compcol 0.8.0/repository/Http/sha256",
                serde_json::json!("changed"),
            ),
            (
                "/crates/compcol 0.8.0/common_attrs/crate_features/common",
                serde_json::json!(["alloc", "rar2", "default"]),
            ),
            (
                "/crates/compcol 0.8.0/common_attrs/crate_features/selects",
                serde_json::json!({"cfg(unix)":["std"]}),
            ),
            (
                "/conditions",
                serde_json::json!({"cfg(target_pointer_width=32)":["i686-unknown-linux-gnu"]}),
            ),
        ] {
            let mut changed = bazel.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                validate_compcol_exemption_scope(&core, &metadata, &changed).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn supply_chain_exceptions_fail_closed_when_activated() {
        validate_supply_chain_exceptions("# policy\nschema = 1\n").unwrap();
        assert!(validate_supply_chain_exceptions("schema = 2\n").is_err());
        assert!(
            validate_supply_chain_exceptions("schema = 1\n[[exception]]\nid = \"SC-1\"\n").is_err()
        );
    }

    #[test]
    fn dependency_boundaries_reject_only_security_relevant_structure() {
        let core = BTreeSet::from(["rustleaks-core".to_owned(), "serde".to_owned()]);
        let sources = BTreeSet::from([
            "rustleaks-core".to_owned(),
            "rustleaks-sources".to_owned(),
            "serde".to_owned(),
        ]);
        let metadata = r#"{"packages":[{"name":"serde","version":"1.0.0","links":null}]}"#;
        validate_dependency_boundaries(&core, &sources, metadata).unwrap();

        let coupled = BTreeSet::from([
            "rustleaks-core".to_owned(),
            "rustleaks-rar-codec".to_owned(),
        ]);
        assert!(validate_dependency_boundaries(&coupled, &sources, metadata).is_err());

        let native = BTreeSet::from(["rustleaks-sources".to_owned(), "openssl-sys".to_owned()]);
        assert!(validate_dependency_boundaries(&core, &native, metadata).is_err());

        let linked = r#"{"packages":[{"name":"native","version":"1.0.0","links":"native"}]}"#;
        assert!(validate_dependency_boundaries(&core, &sources, linked).is_err());
    }
}
