//! Cargo-to-Bazel build contract validation.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use toml::Value;

const REQUIRED_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let bazel_ignore = fs::read_to_string(root.join(".bazelignore"))
        .map_err(|error| format!("cannot read .bazelignore: {error}"))?;
    if bazel_ignore.lines().collect::<Vec<_>>() != ["target"] {
        return Err(".bazelignore must exclude exactly Cargo's target directory".into());
    }

    let workspace = parse_toml(&root.join("Cargo.toml"))?;
    let members = string_array(&workspace, &["workspace", "members"])?;
    let discovered = discover_crates(root)?;
    if members != discovered {
        return Err(format!(
            "Cargo workspace members {members:?} differ from Bazel crate packages {discovered:?}"
        ));
    }

    let mut publishable = Vec::new();
    for member in &members {
        check_crate(root, member, &mut publishable)?;
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
    check_test_membership(&crate_root, &build)?;
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

fn check_test_membership(crate_root: &Path, build: &str) -> Result<(), String> {
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
    }
    Ok(())
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
    let profiles = [
        (
            "rustleaks-bzip2",
            &[
                "default",
                "nightly",
                "rustc_1_37",
                "rustc_1_40",
                "rustc_1_51",
            ][..],
        ),
        (
            "rustleaks-compcol",
            &["default", "alloc", "rar2", "rar3", "rar5"][..],
        ),
        ("rustleaks-sevenz", &["minimal"][..]),
        ("rustleaks-sources", &["fuzzing", "minimal"][..]),
    ];
    for (package, required) in profiles {
        let build = fs::read_to_string(root.join("crates").join(package).join("BUILD.bazel"))
            .map_err(|error| format!("cannot read {package} BUILD file: {error}"))?;
        require_contains(
            &build,
            "feature_profiles",
            &format!("{package} feature profiles"),
        )?;
        for profile in required {
            require_contains(
                &build,
                &format!("profile_{profile}"),
                &format!("{package} {profile} profile"),
            )?;
        }
    }

    let bzip2 = fs::read_to_string(root.join("crates/rustleaks-bzip2/BUILD.bazel"))
        .map_err(|error| format!("cannot read rustleaks-bzip2 BUILD file: {error}"))?;
    require_not_contains(
        named_call(&bzip2, "rustleaks_library", "rustleaks_bzip2")?,
        "crate_features",
        "rustleaks-bzip2 default target",
    )?;
    for closure in [
        r#""nightly": ["nightly", "rustc_1_37", "rustc_1_40"]"#,
        r#""rustc_1_40": ["rustc_1_37", "rustc_1_40"]"#,
    ] {
        require_contains(&bzip2, closure, "rustleaks-bzip2 feature closure")?;
    }

    let compcol = fs::read_to_string(root.join("crates/rustleaks-compcol/BUILD.bazel"))
        .map_err(|error| format!("cannot read rustleaks-compcol BUILD file: {error}"))?;
    require_not_contains(
        named_call(&compcol, "rustleaks_library", "compcol")?,
        "crate_features",
        "rustleaks-compcol default target",
    )?;
    require_contains(
        &compcol,
        r#""rar2": ["alloc", "rar2"]"#,
        "rustleaks-compcol rar2 feature closure",
    )?;

    let sources = fs::read_to_string(root.join("crates/rustleaks-sources/BUILD.bazel"))
        .map_err(|error| format!("cannot read rustleaks-sources BUILD file: {error}"))?;
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
    require_contains(
        &sources,
        "//crates/rustleaks-compcol:profile_rar2",
        "rustleaks-sources archives dependency feature",
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
        "versions = [\"1.85.0\"]",
    ] {
        require_contains(&module, required, "crate-universe module contract")?;
    }
    for target in REQUIRED_TARGETS {
        if module.matches(&format!("\"{target}\"")).count() != 2 {
            return Err(format!(
                "MODULE.bazel must declare {target} once for Rust and once for crate-universe"
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

    let justfile = fs::read_to_string(root.join("justfile"))
        .map_err(|error| format!("cannot read justfile: {error}"))?;
    require_contains(&justfile, "set default-list", "read-only default recipe")?;
    let recipes = justfile
        .lines()
        .filter(|line| line.chars().next().is_some_and(|ch| !ch.is_whitespace()))
        .filter_map(|line| line.strip_suffix(':'))
        .filter(|line| !line.starts_with('['))
        .collect::<BTreeSet<_>>();
    let expected = [
        "build",
        "check",
        "ci",
        "deps-repin",
        "docs",
        "doctor",
        "format",
        "fuzz-build",
        "fuzz-smoke",
        "package-check",
        "parity",
        "release-dry-run",
        "security",
        "test",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if recipes != expected {
        return Err(format!(
            "public just recipes differ: expected {expected:?}, got {recipes:?}"
        ));
    }
    for (recipe, command) in [
        ("build", "bazelisk build //:build"),
        ("test", "bazelisk test //:test"),
        ("docs", "bazelisk build //:docs"),
        ("parity", "bazelisk test //:parity"),
        ("check", "bazelisk test //:check"),
        ("ci", "bazelisk test //:ci"),
    ] {
        require_contains(&justfile, command, &format!("just {recipe}"))?;
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
