//! Cargo-to-Bazel build contract validation.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

use crate::REQUIRED_TARGETS;

pub(crate) fn check(root: &Path) -> Result<(), String> {
    crate::tooling::generate_native_pack_identity(root, true)?;
    let bazel_ignore = fs::read_to_string(root.join(".bazelignore"))
        .map_err(|error| format!("cannot read .bazelignore: {error}"))?;
    check_bazel_ignore(&bazel_ignore)?;

    let workspace = parse_toml(&root.join("Cargo.toml"))?;
    let members = string_array(&workspace, &["workspace", "members"])?;
    let discovered = discover_crates(root)?;
    if members != discovered {
        return Err(format!(
            "Cargo workspace members {members:?} differ from Bazel crate packages {discovered:?}"
        ));
    }

    check_version(root, &workspace)?;
    let root_targets = root_rust_targets(root)?;
    let mut publishable = Vec::new();
    for member in &members {
        check_crate(root, member, &root_targets, &mut publishable)?;
    }
    if publishable != ["rustleaks-core"] {
        return Err(format!(
            "only rustleaks-core may be publishable, got {publishable:?}"
        ));
    }

    check_profiles(root)?;
    check_module(root)?;
    check_interface(root)?;
    check_locks(root, &members)?;
    println!(
        "Cargo and Bazel sources, features, dependencies, assets, tests, packages, and locks match"
    );
    Ok(())
}

fn check_bazel_ignore(source: &str) -> Result<(), String> {
    // Standalone fuzz workspaces own separate Cargo outputs. Excluding only
    // these exact directories keeps changing artifacts out of Bazel globs
    // without allowing source directories to disappear from contract checks.
    let expected = [
        "target",
        "crates/rustleaks-core/fuzz/target",
        "crates/rustleaks-report/fuzz/target",
        "crates/rustleaks-sources/fuzz/target",
    ];
    if !source.lines().eq(expected) {
        return Err(
            ".bazelignore must exclude exactly the workspace and three standalone fuzz Cargo target directories"
                .into(),
        );
    }
    Ok(())
}

fn parse_toml(path: &Path) -> Result<Value, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    toml::from_str(&source).map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn string_array(value: &Value, path: &[&str]) -> Result<BTreeSet<String>, String> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .ok_or_else(|| format!("missing TOML key {}", path.join(".")))?;
    }
    current
        .as_array()
        .ok_or_else(|| format!("TOML key {} is not an array", path.join(".")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("TOML key {} contains a non-string", path.join(".")))
        })
        .collect()
}

fn discover_crates(root: &Path) -> Result<BTreeSet<String>, String> {
    let crates = root.join("crates");
    let mut discovered = BTreeSet::new();
    for entry in fs::read_dir(&crates)
        .map_err(|error| format!("cannot read {}: {error}", crates.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect crates directory: {error}"))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let has_manifest = path.join("Cargo.toml").is_file();
        let has_build = path.join("BUILD.bazel").is_file();
        if has_manifest != has_build {
            return Err(format!(
                "{} must contain both Cargo.toml and BUILD.bazel",
                path.display()
            ));
        }
        if has_manifest {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "crate directory name is not UTF-8".to_owned())?;
            discovered.insert(format!("crates/{name}"));
        }
    }
    Ok(discovered)
}

fn check_crate(
    root: &Path,
    member: &str,
    root_targets: &str,
    publishable: &mut Vec<&'static str>,
) -> Result<(), String> {
    let crate_root = root.join(member);
    let manifest = parse_toml(&crate_root.join("Cargo.toml"))?;
    let build = fs::read_to_string(crate_root.join("BUILD.bazel"))
        .map_err(|error| format!("cannot read {member}/BUILD.bazel: {error}"))?;
    let package = manifest
        .get("package")
        .and_then(Value::as_table)
        .ok_or_else(|| format!("{member}/Cargo.toml has no package table"))?;
    let package_name = package
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{member}/Cargo.toml has no package name"))?;
    let crate_name = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(Value::as_str)
        .map_or_else(|| package_name.replace('-', "_"), str::to_owned);
    require_contains(
        &build,
        &format!("crate_name = \"{crate_name}\""),
        &format!("{member}/BUILD.bazel library identity"),
    )?;

    match package.get("publish") {
        None => {
            if package_name == "rustleaks-core" {
                publishable.push("rustleaks-core");
            } else {
                return Err(format!("{package_name} must set publish = false"));
            }
        }
        Some(Value::Boolean(false)) => {}
        value => {
            return Err(format!(
                "{package_name} has unsupported publish policy {value:?}"
            ));
        }
    }

    if let Some(features) = manifest.get("features").and_then(Value::as_table) {
        for feature in features.keys() {
            if feature == "default"
                && (build.contains("_DEFAULT_FEATURES") || build.contains("profile_minimal"))
            {
                continue;
            }
            require_contains(
                &build,
                &format!("\"{feature}\""),
                &format!("{package_name} feature {feature}"),
            )?;
        }
    }

    check_dependencies(root, member, &manifest, &build)?;
    check_test_membership(&crate_root, member, &build, root_targets)?;
    check_compile_assets(&crate_root, &build)?;
    Ok(())
}

fn dependency_tables(manifest: &Value) -> Vec<&toml::map::Map<String, Value>> {
    let mut tables = Vec::new();
    for name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = manifest.get(name).and_then(Value::as_table) {
            tables.push(table);
        }
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for target in targets.values().filter_map(Value::as_table) {
            for name in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = target.get(name).and_then(Value::as_table) {
                    tables.push(table);
                }
            }
        }
    }
    tables
}

fn check_dependencies(
    root: &Path,
    member: &str,
    manifest: &Value,
    build: &str,
) -> Result<(), String> {
    let mut has_external = false;
    for table in dependency_tables(manifest) {
        for (alias, dependency) in table {
            if let Some(details) = dependency.as_table() {
                if details.contains_key("git") || details.contains_key("registry") {
                    return Err(format!(
                        "{member} dependency {alias} uses a forbidden Git or alternate registry source"
                    ));
                }
                if let Some(path) = details.get("path").and_then(Value::as_str) {
                    let target = normalize_path(&root.join(member).join(path));
                    if !target.starts_with(normalize_path(&root.join("crates"))) {
                        return Err(format!(
                            "{member} dependency {alias} escapes the workspace: {path}"
                        ));
                    }
                    let directory = Path::new(path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| format!("invalid path dependency {path}"))?;
                    require_contains(
                        build,
                        &format!("//crates/{directory}:"),
                        &format!("{member} path dependency {alias}"),
                    )?;
                    continue;
                }
            }
            has_external = true;
        }
    }
    if has_external && !build.contains("all_crate_deps") && !build.contains("rustleaks_library") {
        return Err(format!(
            "{member} external dependencies are not connected to crate-universe"
        ));
    }
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Requires every integration test file `tests/<stem>.rs` to build as the
/// Bazel target `<stem>_test`, to be listed in the crate's `all_tests` suite,
/// which `//:test` runs, and in the root `_RUST_TARGETS` list, which
/// `//:clippy` and `//:format` check.
fn check_test_membership(
    crate_root: &Path,
    member: &str,
    build: &str,
    root_targets: &str,
) -> Result<(), String> {
    let tests = crate_root.join("tests");
    if !tests.is_dir() {
        return Ok(());
    }
    for entry in
        fs::read_dir(&tests).map_err(|error| format!("cannot read {}: {error}", tests.display()))?
    {
        let path = entry
            .map_err(|error| format!("cannot inspect {}: {error}", tests.display()))?
            .path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| format!("test name is not UTF-8: {}", path.display()))?;
        if !build.contains(&format!("\"{stem}\"")) && !build.contains(&format!("tests/{stem}.rs")) {
            return Err(format!(
                "test {} is not represented in BUILD.bazel",
                path.display()
            ));
        }
        let suite = named_call(build, "test_suite", "all_tests")
            .map_err(|error| format!("{member}: {error}"))?;
        if !suite.contains(&format!("\":{stem}_test\""))
            && !suite_groups_contain(build, suite, stem)
        {
            return Err(format!(
                "{member} all_tests suite is missing '\":{stem}_test\"'"
            ));
        }
        require_contains(
            root_targets,
            &format!("\"//{member}:{stem}_test\""),
            "root _RUST_TARGETS list",
        )?;
    }
    Ok(())
}

/// Reports whether an `all_tests` suite built from grouped name lists, such
/// as `for test in _PLAIN_TESTS + _CORPUS_TESTS`, includes `stem` in one of
/// those lists.
fn suite_groups_contain(build: &str, suite: &str, stem: &str) -> bool {
    let quoted = format!("\"{stem}\"");
    suite
        .split(|character: char| !(character.is_ascii_uppercase() || character == '_'))
        .filter(|word| word.starts_with('_') && word.ends_with("_TESTS"))
        .any(|group| {
            build
                .split(&format!("\n{group} = "))
                .nth(1)
                .and_then(|tail| tail.split("\n]").next())
                .and_then(|tail| tail.split("\n}").next())
                .is_some_and(|list| {
                    list.lines()
                        .any(|line| line.trim_start().starts_with(&quoted))
                })
        })
}

/// Returns the root `_RUST_TARGETS` list, which `//:clippy` and `//:format`
/// check.
fn root_rust_targets(root: &Path) -> Result<String, String> {
    let build = fs::read_to_string(root.join("BUILD.bazel"))
        .map_err(|error| format!("cannot read BUILD.bazel: {error}"))?;
    build
        .split("_RUST_TARGETS = [")
        .nth(1)
        .and_then(|tail| tail.split("\n]").next())
        .map(str::to_owned)
        .ok_or_else(|| "BUILD.bazel omits the _RUST_TARGETS list".to_owned())
}

/// Requires the `RUSTLEAKS_VERSION` that Bazel targets use to equal the Cargo
/// workspace package version.
fn check_version(root: &Path, workspace: &Value) -> Result<(), String> {
    let cargo = workspace
        .get("workspace")
        .and_then(|value| value.get("package"))
        .and_then(|value| value.get("version"))
        .and_then(Value::as_str)
        .ok_or("Cargo.toml has no workspace package version")?;
    let rules = fs::read_to_string(root.join("bazel/rust_crate.bzl"))
        .map_err(|error| format!("cannot read bazel/rust_crate.bzl: {error}"))?;
    require_contains(
        &rules,
        &format!("\nRUSTLEAKS_VERSION = \"{cargo}\"\n"),
        "bazel/rust_crate.bzl workspace version",
    )
}

fn check_compile_assets(crate_root: &Path, build: &str) -> Result<(), String> {
    let mut sources = Vec::new();
    collect_rs_files(&crate_root.join("src"), &mut sources)?;
    collect_rs_files(&crate_root.join("tests"), &mut sources)?;
    collect_rs_files(&crate_root.join("examples"), &mut sources)?;
    let mut needs_compat = false;
    let mut needs_default = false;
    for source in sources {
        let text = fs::read_to_string(&source)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        needs_compat |= text.contains("compat/") || text.contains("../compat");
        needs_default |= text.contains("default/gitleaks.toml");
    }
    if needs_compat && !build.contains("//compat:") && !build.contains("//:build_contract_files") {
        return Err(format!(
            "{} compatibility assets are not declared",
            crate_root.display()
        ));
    }
    if needs_default && !build.contains("default/**") && !build.contains("//:build_contract_files")
    {
        return Err(format!(
            "{} default configuration is not declared",
            crate_root.display()
        ));
    }
    if contains_non_rust_source_asset(&crate_root.join("src"))? {
        require_contains(
            build,
            "compile_data",
            &format!("{} compile-time assets", crate_root.display()),
        )?;
    }
    Ok(())
}

fn collect_rs_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let path = entry
            .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?
            .path();
        if path.is_dir() {
            collect_rs_files(&path, output)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            output.push(path);
        }
    }
    Ok(())
}

fn contains_non_rust_source_asset(directory: &Path) -> Result<bool, String> {
    if !directory.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let path = entry
            .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?
            .path();
        if path.is_dir() {
            if contains_non_rust_source_asset(&path)? {
                return Ok(true);
            }
        } else if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_profiles(root: &Path) -> Result<(), String> {
    let sources = fs::read_to_string(root.join("crates/rustleaks-sources/BUILD.bazel"))
        .map_err(|error| format!("cannot read rustleaks-sources BUILD file: {error}"))?;
    require_contains(
        &sources,
        "feature_profiles",
        "rustleaks-sources feature profiles",
    )?;
    for profile in ["fuzzing", "minimal"] {
        require_contains(
            &sources,
            &format!("profile_{profile}"),
            &format!("rustleaks-sources {profile} profile"),
        )?;
    }
    require_not_contains(
        named_call(&sources, "rustleaks_library", "rustleaks_sources")?,
        "crate_features",
        "rustleaks-sources default target",
    )?;
    let archives = named_call(&sources, "rustleaks_library", "rustleaks_sources_archives")?;
    require_contains(
        archives,
        "crate_features = _ARCHIVE_FEATURES",
        "rustleaks-sources archives target",
    )?;
    require_contains(
        archives,
        "deps = _ARCHIVE_DEPS",
        "rustleaks-sources archives dependencies",
    )?;
    let cli = fs::read_to_string(root.join("crates/rustleaks-cli/BUILD.bazel"))
        .map_err(|error| format!("cannot read rustleaks-cli BUILD file: {error}"))?;
    require_contains(
        &cli,
        "//crates/rustleaks-sources:rustleaks_sources_archives",
        "rustleaks-cli archives feature",
    )?;
    let compatibility = fs::read_to_string(root.join("crates/rustleaks-compat/BUILD.bazel"))
        .map_err(|error| format!("cannot read rustleaks-compat BUILD file: {error}"))?;
    require_contains(
        &compatibility,
        "//crates/rustleaks-sources:rustleaks_sources",
        "rustleaks-compat default source feature",
    )?;
    require_not_contains(
        &compatibility,
        "rustleaks_sources_archives",
        "rustleaks-compat default source feature",
    )?;
    Ok(())
}

fn named_call<'a>(source: &'a str, function: &str, target: &str) -> Result<&'a str, String> {
    let start = format!("{function}(");
    let name = format!("name = \"{target}\"");
    source
        .split(&start)
        .skip(1)
        .filter_map(|tail| tail.split("\n)").next())
        .find(|call| call.contains(&name))
        .ok_or_else(|| format!("BUILD file omits {function} target {target}"))
}

fn calls<'a>(source: &'a str, function: &str) -> Vec<&'a str> {
    source
        .split(&format!("{function}("))
        .skip(1)
        .filter_map(|tail| tail.split("\n)").next())
        .collect()
}

fn check_module(root: &Path) -> Result<(), String> {
    let module = fs::read_to_string(root.join("MODULE.bazel"))
        .map_err(|error| format!("cannot read MODULE.bazel: {error}"))?;
    for required in [
        "bazel_dep(name = \"git\", version = \"2.55.0\")",
        "bazel_dep(name = \"llvm\", version = \"0.8.11\")",
        "bazel_dep(name = \"rules_rust\", version = \"0.72.0\")",
        "cargo_lockfile = \"//:Cargo.lock\"",
        "isolated = True",
        "lockfile = \"//:cargo-bazel-lock.json\"",
        "manifests = [\"//:Cargo.toml\"]",
        "patches = [\"//bazel:git_macos_no_fsmonitor.patch\"]",
        "regen_command = \"just deps-repin\"",
        "versions = [\"1.95.0\"]",
    ] {
        require_contains(&module, required, "crate-universe module contract")?;
    }
    let rust_toolchain = calls(&module, "rust.toolchain")
        .into_iter()
        .next()
        .ok_or_else(|| "MODULE.bazel omits the default Rust toolchain".to_owned())?;
    let crate_universe = calls(&module, "crate.from_cargo")
        .into_iter()
        .next()
        .ok_or_else(|| "MODULE.bazel omits crate-universe".to_owned())?;
    for target in REQUIRED_TARGETS {
        require_contains(
            crate_universe,
            &format!("\"{target}\""),
            "crate-universe target set",
        )?;
        if target.ends_with("-musl") {
            require_not_contains(
                rust_toolchain,
                &format!("\"{target}\""),
                "unconstrained default Rust toolchain",
            )?;
        } else {
            require_contains(
                rust_toolchain,
                &format!("\"{target}\""),
                "default Rust toolchain target set",
            )?;
        }
    }
    let repository_sets = calls(&module, "rust.repository_set");
    for (name, exec_triple) in [
        ("rust_musl_macos_aarch64", "aarch64-apple-darwin"),
        ("rust_musl_macos_x86_64", "x86_64-apple-darwin"),
        ("rust_musl_linux_aarch64", "aarch64-unknown-linux-gnu"),
        ("rust_musl_linux_x86_64", "x86_64-unknown-linux-gnu"),
        ("rust_musl_windows_aarch64", "aarch64-pc-windows-msvc"),
        ("rust_musl_windows_x86_64", "x86_64-pc-windows-msvc"),
    ] {
        let declarations = repository_sets
            .iter()
            .copied()
            .filter(|call| call.contains(&format!("name = \"{name}\"")))
            .collect::<Vec<_>>();
        if declarations.len() != 2
            || !declarations
                .iter()
                .any(|call| call.contains("target_triple = \"aarch64-unknown-linux-musl\""))
            || !declarations
                .iter()
                .any(|call| call.contains("target_triple = \"x86_64-unknown-linux-musl\""))
            || !declarations
                .iter()
                .all(|call| call.contains("\"//platforms:musl\""))
            || !declarations
                .iter()
                .any(|call| call.contains(&format!("exec_triple = \"{exec_triple}\"")))
        {
            return Err(format!(
                "MODULE.bazel does not define the complete constrained repository set {name}"
            ));
        }
    }
    if module.contains("git_override") || module.contains("git_repository") {
        return Err("MODULE.bazel contains a forbidden Git dependency".into());
    }
    Ok(())
}

fn check_interface(root: &Path) -> Result<(), String> {
    let version = fs::read_to_string(root.join(".bazelversion"))
        .map_err(|error| format!("cannot read .bazelversion: {error}"))?;
    if version.trim() != "9.2.0" {
        return Err(format!("Bazelisk version must be 9.2.0, got {version:?}"));
    }

    let bazelrc = fs::read_to_string(root.join(".bazelrc"))
        .map_err(|error| format!("cannot read .bazelrc: {error}"))?;
    for required in [
        "common --lockfile_mode=error",
        "common --incompatible_strict_action_env",
        "build:clippy --@rules_rust//rust/settings:clippy_flag=-Dwarnings",
        "build:linux-x86_64-gnu --platforms=//platforms:linux_x86_64_gnu",
        "build:linux-aarch64-gnu --platforms=//platforms:linux_aarch64_gnu",
        "build:linux-x86_64-musl --platforms=//platforms:linux_x86_64_musl",
        "build:linux-aarch64-musl --platforms=//platforms:linux_aarch64_musl",
        "build:linux-x86_64-musl --extra_toolchains=@rust_musl_linux_aarch64__x86_64-unknown-linux-musl__stable//:toolchain",
        "build:linux-x86_64-musl --extra_toolchains=@rust_musl_linux_x86_64__x86_64-unknown-linux-musl__stable//:toolchain",
        "build:linux-x86_64-musl --extra_toolchains=@rust_musl_macos_aarch64__x86_64-unknown-linux-musl__stable//:toolchain",
        "build:linux-x86_64-musl --extra_toolchains=@rust_musl_macos_x86_64__x86_64-unknown-linux-musl__stable//:toolchain",
        "build:linux-x86_64-musl --extra_toolchains=@rust_musl_windows_aarch64_x86_64//:toolchain",
        "build:linux-x86_64-musl --extra_toolchains=@rust_musl_windows_x86_64_x86_64//:toolchain",
        "build:linux-aarch64-musl --extra_toolchains=@rust_musl_linux_aarch64__aarch64-unknown-linux-musl__stable//:toolchain",
        "build:linux-aarch64-musl --extra_toolchains=@rust_musl_linux_x86_64__aarch64-unknown-linux-musl__stable//:toolchain",
        "build:linux-aarch64-musl --extra_toolchains=@rust_musl_macos_aarch64__aarch64-unknown-linux-musl__stable//:toolchain",
        "build:linux-aarch64-musl --extra_toolchains=@rust_musl_macos_x86_64__aarch64-unknown-linux-musl__stable//:toolchain",
        "build:linux-aarch64-musl --extra_toolchains=@rust_musl_windows_aarch64_aarch64//:toolchain",
        "build:linux-aarch64-musl --extra_toolchains=@rust_musl_windows_x86_64_aarch64//:toolchain",
        "build:macos-x86_64 --platforms=//platforms:macos_x86_64",
        "build:macos-aarch64 --platforms=//platforms:macos_aarch64",
        "build:windows-x86_64-msvc --platforms=//platforms:windows_x86_64_msvc",
        "build:windows-aarch64-msvc --platforms=//platforms:windows_aarch64_msvc",
    ] {
        require_contains(&bazelrc, required, ".bazelrc build contract")?;
    }

    let platforms = fs::read_to_string(root.join("platforms/BUILD.bazel"))
        .map_err(|error| format!("cannot read platforms/BUILD.bazel: {error}"))?;
    for target in REQUIRED_TARGETS {
        require_contains(
            &platforms,
            &format!("name = \"{target}\""),
            "crate-universe platform mapping",
        )?;
    }
    for platform in [
        "linux_x86_64_gnu",
        "linux_aarch64_gnu",
        "linux_x86_64_musl",
        "linux_aarch64_musl",
        "macos_x86_64",
        "macos_aarch64",
        "windows_x86_64_msvc",
        "windows_aarch64_msvc",
    ] {
        require_contains(
            &platforms,
            &format!("name = \"{platform}\""),
            "explicit target platform",
        )?;
    }

    check_just_interface(root)
}

#[allow(clippy::too_many_lines)] // Keep the public recipe names and command contract together.
fn check_just_interface(root: &Path) -> Result<(), String> {
    let justfile = fs::read_to_string(root.join("justfile"))
        .map_err(|error| format!("cannot read justfile: {error}"))?;
    require_contains(&justfile, "set default-list", "read-only default recipe")?;
    let recipes = crate::docs_check::justfile_recipes(&justfile);
    let expected = [
        "build",
        "check",
        "ci",
        "compare",
        "compare-quality",
        "compare-workloads",
        "deps-repin",
        "docs",
        "docs-check",
        "doctor",
        "flake-check",
        "format",
        "fuzz",
        "fuzz-build",
        "fuzz-smoke",
        "package-check",
        "parity",
        "perf-calibrate",
        "perf-check",
        "perf-fixtures",
        "perf-profile",
        "perf-report",
        "perf-representative",
        "perf-run",
        "quality-eval",
        "release-dry-run",
        "security",
        "security-deep",
        "test",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if recipes != expected {
        return Err(format!(
            "public just recipes differ: expected {expected:?}, got {recipes:?}"
        ));
    }
    for (recipe, command) in [
        ("build", "bazelisk build //:build"),
        ("test", "bazelisk test //:test"),
        (
            "flake-check",
            "bazelisk test --nocache_test_results --runs_per_test=10 //:test",
        ),
        ("docs", "bazelisk build //:docs"),
        (
            "docs-check",
            "bazelisk run //crates/xtask:xtask -- docs-check",
        ),
        ("parity", "bazelisk test //:parity"),
        (
            "quality-eval",
            "bazelisk run //crates/rustleaks-compat:rustleaks_quality -- evaluate",
        ),
        ("perf-run", "bazelisk run //crates/xtask:xtask -- perf run"),
        (
            "perf-fixtures",
            "bazelisk run //crates/xtask:xtask -- perf fixtures \"$@\"",
        ),
        (
            "perf-representative",
            "bazelisk run //crates/xtask:xtask -- perf representative",
        ),
        ("fuzz", "bazelisk run //crates/xtask:xtask -- fuzz \"$@\""),
        (
            "perf-profile",
            "bazelisk run //crates/xtask:xtask -- perf profile \"$@\"",
        ),
        (
            "perf-report",
            "bazelisk run //crates/xtask:xtask -- perf report \"$@\"",
        ),
        (
            "perf-calibrate",
            "bazelisk run //crates/xtask:xtask -- perf calibrate \"$@\"",
        ),
        (
            "security-deep",
            "bazelisk run //crates/xtask:xtask -- security-deep \"$@\"",
        ),
        (
            "perf-check",
            "bazelisk run //crates/xtask:xtask -- perf check",
        ),
        (
            "compare",
            "bazelisk run //crates/xtask:xtask -- compare \"$@\"",
        ),
        (
            "compare-quality",
            "bazelisk run //crates/xtask:xtask -- compare-quality \"$@\"",
        ),
        (
            "compare-workloads",
            "bazelisk run //crates/xtask:xtask -- compare-workloads \"$@\"",
        ),
        ("check", "bazelisk test //:check"),
        ("ci", "bazelisk test --jobs=1 //:ci"),
    ] {
        require_contains(&justfile, command, &format!("just {recipe}"))?;
    }
    require_contains(
        &justfile,
        "bazelisk build --build_tests_only //:test",
        "just ci test prebuild",
    )?;
    for recipe in [
        "compare",
        "compare-quality",
        "compare-workloads",
        "fuzz",
        "perf-profile",
        "perf-calibrate",
        "security-deep",
    ] {
        require_contains(
            &justfile,
            &format!("[unix]\n[positional-arguments]\n{recipe} *arguments:"),
            &format!("private Unix {recipe} argument forwarding"),
        )?;
    }
    for forbidden in ["cargo build", "cargo clippy", "cargo doc", "cargo test"] {
        require_not_contains(&justfile, forbidden, "normal just recipe")?;
    }
    Ok(())
}

fn check_locks(root: &Path, members: &BTreeSet<String>) -> Result<(), String> {
    let cargo = parse_toml(&root.join("Cargo.lock"))?;
    let cargo_packages = cargo
        .get("package")
        .and_then(Value::as_array)
        .ok_or("Cargo.lock has no package array")?;
    let cargo_ids = cargo_packages
        .iter()
        .map(|package| {
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .ok_or("locked package has no name")?;
            let version = package
                .get("version")
                .and_then(Value::as_str)
                .ok_or("locked package has no version")?;
            if package
                .get("source")
                .and_then(Value::as_str)
                .is_some_and(|source| {
                    !source.starts_with("registry+https://github.com/rust-lang/crates.io-index")
                })
            {
                return Err(format!(
                    "Cargo.lock package {name} uses an unreviewed source"
                ));
            }
            Ok(format!("{name} {version}"))
        })
        .collect::<Result<BTreeSet<_>, String>>()?;

    let rendered: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("cargo-bazel-lock.json"))
            .map_err(|error| format!("cannot read cargo-bazel-lock.json: {error}"))?,
    )
    .map_err(|error| format!("cannot parse cargo-bazel-lock.json: {error}"))?;
    let rendered_crates = rendered
        .get("crates")
        .and_then(serde_json::Value::as_object)
        .ok_or("cargo-bazel-lock.json has no crates object")?;
    let rendered_ids = rendered_crates
        .values()
        .map(|package| {
            let name = package
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or("rendered crate has no name")?;
            let version = package
                .get("version")
                .and_then(serde_json::Value::as_str)
                .ok_or("rendered crate has no version")?;
            Ok(format!("{name} {version}"))
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    if cargo_ids != rendered_ids {
        return Err(
            "Cargo.lock and cargo-bazel-lock.json resolve different package versions".into(),
        );
    }

    for member in members {
        let manifest = parse_toml(&root.join(member).join("Cargo.toml"))?;
        let package = manifest
            .get("package")
            .and_then(Value::as_table)
            .ok_or("workspace manifest has no package")?;
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or("workspace package has no name")?;
        let locked = rendered_crates
            .values()
            .find(|candidate| {
                candidate.get("name").and_then(serde_json::Value::as_str) == Some(name)
            })
            .ok_or_else(|| format!("crate-universe lock omits workspace package {name}"))?;
        if let Some(features) = locked
            .pointer("/common_attrs/crate_features/common")
            .and_then(serde_json::Value::as_array)
        {
            let declared = manifest.get("features").and_then(Value::as_table);
            for feature in features.iter().filter_map(serde_json::Value::as_str) {
                if feature != "default" && declared.is_none_or(|table| !table.contains_key(feature))
                {
                    return Err(format!(
                        "crate-universe enables undeclared {name} feature {feature}"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_contains(haystack: &str, needle: &str, context: &str) -> Result<(), String> {
    if haystack.contains(needle) {
        Ok(())
    } else {
        Err(format!("{context} is missing '{needle}'"))
    }
}

fn require_not_contains(haystack: &str, needle: &str, context: &str) -> Result<(), String> {
    if haystack.contains(needle) {
        Err(format!("{context} unexpectedly contains '{needle}'"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{check_bazel_ignore, check_test_membership};

    #[test]
    fn test_membership_requires_the_suite_and_root_lists() {
        let crate_root =
            std::env::temp_dir().join(format!("rustleaks-build-system-{}", std::process::id()));
        std::fs::create_dir_all(crate_root.join("tests")).unwrap();
        std::fs::write(crate_root.join("tests/sample.rs"), "").unwrap();
        let declared = "[\n    rustleaks_integration_test(\n        name = test + \"_test\",\n    )\n    for test in [\"sample\"]\n]\n";
        let suite = "test_suite(\n    name = \"all_tests\",\n    tests = [\":sample_test\"],\n)\n";
        let root = "\n    \"//crates/demo:sample_test\",";
        let check = |build: &str, root: &str| {
            check_test_membership(&crate_root, "crates/demo", build, root)
        };
        assert!(check(&format!("{declared}{suite}"), root).is_ok());
        let without_suite = suite.replace("\":sample_test\"", "");
        assert!(check(&format!("{declared}{without_suite}"), root).is_err());
        assert!(check(&format!("{declared}{suite}"), "").is_err());
        let grouped = "\n_PLAIN_TESTS = [\n    \"sample\",\n]\n\ntest_suite(\n    name = \"all_tests\",\n    tests = [\":\" + test + \"_test\" for test in _PLAIN_TESTS],\n)\n";
        assert!(check(&format!("{declared}{grouped}"), root).is_ok());
        let other_group = grouped.replace("\"sample\",", "\"other\",");
        assert!(check(&format!("{declared}{other_group}"), root).is_err());
        assert!(check(suite, root).is_err());
        std::fs::remove_dir_all(&crate_root).unwrap();
    }

    #[test]
    fn bazel_ignore_rejects_missing_outputs_and_source_exclusions() {
        let expected = "target\ncrates/rustleaks-core/fuzz/target\ncrates/rustleaks-report/fuzz/target\ncrates/rustleaks-sources/fuzz/target\n";
        assert!(check_bazel_ignore(expected).is_ok());
        let directories = expected.lines().collect::<Vec<_>>();
        for missing in 0..directories.len() {
            let incomplete = directories
                .iter()
                .enumerate()
                .filter_map(|(index, directory)| (index != missing).then_some(*directory))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(check_bazel_ignore(&incomplete).is_err());
        }
        for forbidden in [
            "crates",
            "crates/rustleaks-sources/fuzz",
            "crates/rustleaks-sources/src",
            "crates/rustleaks-sources/fuzz/**",
            "target",
        ] {
            assert!(check_bazel_ignore(&format!("{expected}{forbidden}\n")).is_err());
        }
    }
}
