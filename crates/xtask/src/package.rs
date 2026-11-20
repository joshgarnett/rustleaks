//! Core crate packaging, external consumer and publish dry-run checks.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::tooling::{ScopedTempDir, command_output, hex_lower};
use crate::{RELEASE_VERSION, REVISION, workspace_root};

fn package_attribution_check(root: &Path) -> Result<(), String> {
    for name in ["LICENSE", "NOTICE"] {
        let workspace_copy = std::fs::read(root.join(name))
            .map_err(|error| format!("cannot read workspace {name}: {error}"))?;
        let package_copy = std::fs::read(root.join("crates/rustleaks-core").join(name))
            .map_err(|error| format!("cannot read packaged core {name}: {error}"))?;
        if workspace_copy != package_copy {
            return Err(format!(
                "packaged rustleaks-core {name} differs from the workspace copy"
            ));
        }
    }
    let notice = std::fs::read_to_string(root.join("NOTICE"))
        .map_err(|error| format!("cannot read workspace NOTICE: {error}"))?;
    let pinned_commit = format!("pinned commit {REVISION}");
    for required in [
        pinned_commit.as_str(),
        "MIT License\n\nCopyright (c) 2019 Zachary Rice",
        "Copyright 2009 The Go Authors.",
    ] {
        if !notice.contains(required) {
            return Err(format!("NOTICE omits required attribution `{required}`"));
        }
    }
    let rustc_version = command_output(Command::new("rustc").arg("-vV"))?;
    let host = rustc_version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("rustc -vV omitted its host target")?;
    let metadata = command_output(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--format-version",
        "1",
        "--offline",
        "--filter-platform",
        host,
    ]))?;
    validate_core_repository_metadata(&metadata)?;
    validate_regex_backend_metadata(&metadata)?;
    let package_files = command_output(Command::new("cargo").current_dir(root).args([
        "package",
        "-p",
        "rustleaks-core",
        "--list",
        "--allow-dirty",
        "--offline",
    ]))?;
    for required in [
        "LICENSE",
        "NOTICE",
        "README.md",
        "src/config/eisel_lemire.rs",
        "src/go_lowercase_tables.rs",
        "default/rustleaks-extra-v1.toml",
        "default/rustleaks-extra-v1.md",
        "default/rustleaks-extra-v1.sha256",
        "default/rustleaks-providers-v1.toml",
        "default/rustleaks-providers-v1.md",
        "default/rustleaks-providers-v1.sha256",
        "default/rustleaks-providers-v1.provenance.json",
        "default/LICENSE.betterleaks",
        "default/NOTICE",
        "default/rustleaks-connections-v1.toml",
        "default/rustleaks-connections-v1.md",
        "default/rustleaks-connections-v1.sha256",
        "default/rustleaks-connections-v1.provenance.json",
        "default/LICENSE.kingfisher",
        "default/LICENSE.veles",
        "data/README.md",
        "data/cl100k-vercel60-v1.bin",
        "data/LICENSE.tiktoken",
        "data/LICENSE.tiktoken-rs",
    ] {
        if !package_files.lines().any(|path| path == required) {
            return Err(format!(
                "rustleaks-core source package omits required `{required}`"
            ));
        }
    }
    let allowed_roots = [
        ".cargo_vcs_info.json",
        "Cargo.lock",
        "Cargo.toml",
        "Cargo.toml.orig",
        "LICENSE",
        "NOTICE",
        "README.md",
    ];
    for path in package_files.lines() {
        if !allowed_roots.contains(&path)
            && !["data/", "default/", "src/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            return Err(format!(
                "rustleaks-core source package contains unexpected `{path}`"
            ));
        }
    }
    Ok(())
}

fn validate_core_repository_metadata(metadata: &str) -> Result<(), String> {
    let metadata: serde_json::Value = serde_json::from_str(metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let package = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package["name"] == "rustleaks-core")
        })
        .ok_or("cargo metadata omits rustleaks-core")?;
    for (field, expected) in [
        ("version", RELEASE_VERSION),
        (
            "description",
            "Synchronous, byte-first secret detection engine for Rustleaks",
        ),
        ("license", "MIT AND BSD-3-Clause AND Apache-2.0"),
        ("repository", "https://github.com/joshgarnett/rustleaks"),
        ("homepage", "https://github.com/joshgarnett/rustleaks"),
        ("documentation", "https://docs.rs/rustleaks-core"),
        ("readme", "README.md"),
        ("rust_version", "1.95"),
    ] {
        if package[field].as_str() != Some(expected) {
            return Err(format!(
                "rustleaks-core package metadata {field} must be {expected:?}"
            ));
        }
    }
    if package["keywords"] != json_array(&["gitleaks", "secret-detection", "security", "scanner"])
        || package["categories"] != json_array(&["development-tools"])
    {
        return Err("rustleaks-core package keywords or categories changed".into());
    }
    let docs = &package["metadata"]["docs"]["rs"];
    if docs["all-features"] != true
        || docs["rustdoc-args"] != json_array(&["--cfg", "docsrs", "-D", "warnings"])
    {
        return Err("rustleaks-core docs.rs metadata changed".into());
    }
    Ok(())
}

fn json_array(values: &[&str]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|value| serde_json::Value::String((*value).to_owned()))
            .collect(),
    )
}

fn validate_regex_backend_metadata(metadata: &str) -> Result<(), String> {
    let metadata: serde_json::Value = serde_json::from_str(metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omits packages")?;
    let core = packages
        .iter()
        .find(|package| package["name"] == "rustleaks-core")
        .ok_or("cargo metadata omits rustleaks-core")?;
    let dependencies = core["dependencies"]
        .as_array()
        .ok_or("cargo metadata omits rustleaks-core dependencies")?;
    for (name, requirement) in [("regex-automata", "^0.4.12"), ("regex-syntax", "^0.8.5")] {
        let dependency = dependencies
            .iter()
            .find(|dependency| dependency["name"] == name)
            .ok_or_else(|| format!("rustleaks-core omits compatible {name} backend dependency"))?;
        if dependency["req"].as_str() != Some(requirement) {
            return Err(format!(
                "rustleaks-core {name} requirement must be {requirement}"
            ));
        }
        let requirement = semver::VersionReq::parse(requirement)
            .map_err(|error| format!("invalid maintained {name} requirement: {error}"))?;
        let resolved = packages.iter().any(|package| {
            package["name"] == name
                && package["version"]
                    .as_str()
                    .and_then(|version| semver::Version::parse(version).ok())
                    .is_some_and(|version| requirement.matches(&version))
        });
        if !resolved {
            return Err(format!("resolved Cargo graph omits compatible {name}"));
        }
    }
    if dependencies
        .iter()
        .any(|dependency| dependency["name"] == "regex")
    {
        return Err("rustleaks-core must use the direct PikeVM, not the regex facade".into());
    }
    Ok(())
}

fn validate_publish_policy(metadata: &str) -> Result<(), String> {
    let metadata: serde_json::Value = serde_json::from_str(metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omits packages")?;
    let mut publishable = Vec::new();
    for package in packages {
        let name = package["name"].as_str().ok_or("package omits name")?;
        let version = package["version"].as_str().ok_or("package omits version")?;
        let alpha_package = matches!(
            name,
            "rustleaks-core"
                | "rustleaks-sources"
                | "rustleaks-report"
                | "rustleaks-cli"
                | "rustleaks-compat"
                | "xtask"
        );
        if alpha_package && version != RELEASE_VERSION {
            return Err(format!(
                "workspace package {name} has version {version}, expected {RELEASE_VERSION}"
            ));
        }
        match &package["publish"] {
            serde_json::Value::Null => publishable.push(name),
            serde_json::Value::Array(registries) if registries.is_empty() => {}
            value => {
                return Err(format!(
                    "workspace package {name} has unsupported publish policy {value}"
                ));
            }
        }
    }
    if publishable != ["rustleaks-core"] {
        return Err(format!(
            "only rustleaks-core may be publishable, got {publishable:?}"
        ));
    }
    Ok(())
}

pub(crate) fn package_check() -> Result<(), String> {
    let root = workspace_root()?;
    command_output(Command::new("cargo").current_dir(&root).args([
        "fetch",
        "--locked",
        "--offline",
    ]))
    .map_err(|error| {
        format!(
            "locked dependency cache is incomplete; run `cargo fetch --locked` before the offline package check: {error}"
        )
    })?;
    let metadata = command_output(Command::new("cargo").current_dir(&root).args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--offline",
    ]))?;
    validate_publish_policy(&metadata)?;
    package_attribution_check(&root)?;
    let staging = ScopedTempDir::new("package-check")?;
    command_output(
        Command::new("cargo")
            .current_dir(&root)
            .args([
                "package",
                "--locked",
                "--offline",
                "--allow-dirty",
                "-p",
                "rustleaks-core",
                "--target-dir",
            ])
            .arg(staging.path.join("target")),
    )?;
    let package_dir = extract_core_package(&staging.path)?;
    run_external_cargo_consumer(&staging.path, &package_dir)?;
    run_external_bazel_consumer(&staging.path, &package_dir)?;
    println!("rustleaks-core packaged and ran from clean external Cargo and Bazel consumers");
    Ok(())
}

fn extract_core_package(staging: &Path) -> Result<PathBuf, String> {
    let archive_dir = staging.join("target/package");
    let archive = std::fs::read_dir(&archive_dir)
        .map_err(|error| {
            format!(
                "cannot read package directory {}: {error}",
                archive_dir.display()
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rustleaks-core-"))
                && path
                    .extension()
                    .is_some_and(|extension| extension == "crate")
        })
        .ok_or_else(|| {
            format!(
                "cargo did not create a rustleaks-core archive in {}",
                archive_dir.display()
            )
        })?;
    let output = staging.join("extracted");
    std::fs::create_dir(&output)
        .map_err(|error| format!("cannot create package extraction directory: {error}"))?;
    let file = std::fs::File::open(&archive)
        .map_err(|error| format!("cannot open package archive {}: {error}", archive.display()))?;
    let decoder = flate2::read::GzDecoder::new(file);
    tar::Archive::new(decoder)
        .unpack(&output)
        .map_err(|error| {
            format!(
                "cannot extract package archive {}: {error}",
                archive.display()
            )
        })?;
    let package = output.join(format!("rustleaks-core-{RELEASE_VERSION}"));
    if !package.join("Cargo.toml").is_file() {
        return Err(format!(
            "extracted package is missing {}",
            package.join("Cargo.toml").display()
        ));
    }
    Ok(package)
}

fn consumer_source() -> &'static str {
    r#"use rustleaks_core::config::{ConfigError, ConfigLoader};
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::native::{CONNECTION_RULES_V1, EXTRA_RULES_V1, NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::triage::{ReviewPolicy, ReviewSource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ConfigLoader::new().load_toml(
        "[[allowlists]]\nregexes = ['(?P<x>a){0}', '\\b\\pL\\b']\n",
    )?;
    for (path, field, pattern, message) in [
        ("(", "path", "(", "regexp compile error: error parsing regex"),
        ("valid", "regex", "\\", "regexp syntax error at byte 0: trailing backslash"),
    ] {
        let source = format!("[[allowlists]]\npaths = ['{path}']\nregexes = ['\\']\n");
        let error = ConfigLoader::new().load_toml(&source).unwrap_err();
        let ConfigError::InvalidPattern {
            scope, field: actual_field, pattern: actual_pattern, message: actual_message,
        } = error else {
            panic!("unexpected allowlist error: {error}");
        };
        assert_eq!(scope, "[[allowlists]]");
        assert_eq!(actual_field, field);
        assert_eq!(actual_pattern, pattern);
        assert_eq!(actual_message, message);
    }
    let config = ConfigLoader::new().load_default()?;
    let engine = Engine::builder(config).build()?;
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(10_000)
            .max_finding_records(100),
    );
    let outcome = engine.scan_fragment_controlled(
        &Fragment::new(concat!("string AWSToken = \"AKIA", "LALEMEL33243OLIB\";").as_bytes()),
        &ScanOptions::default(),
        &control,
    );
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings()[0].rule_id().as_str()?, "aws-access-token");
    let native = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)?.build()?;
    let scan = native.scan_fragment_controlled(
        &Fragment::new(b"mongodb://synthetic:password123@db.example.invalid/"),
        &ScanOptions::default(), &control, ExplanationOptions::bounded(32),
    );
    assert!(scan.scan().is_complete());
    assert!(scan.scan().findings().iter().any(|finding|
        finding.rule_id().as_bytes() == b"rustleaks.mongodb-password"));
    let policy = ReviewPolicy::for_builtin(native.identity())?;
    let source = ReviewSource::caller_bound("synthetic-snapshot-v1")?;
    let review = policy.review(&scan, &source, &[], 1_700_000_000)?;
    assert!(review.is_complete());
    assert_eq!(review.occurrences().len(), scan.scan().findings().len());
    let partial = native.scan_fragment_controlled(
        &Fragment::new(b"synthetic input"), &ScanOptions::default(),
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
        ExplanationOptions::disabled(),
    );
    assert!(!policy.review(&partial, &source, &[], 1_700_000_000)?.is_complete());
    let providers = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)?.build()?;
    let provider_secret = format!("r8_{}", "Q7m2Z9v4L1c8R5s0N6b3X".chars().cycle().take(37).collect::<String>());
    let provider_scan = providers.engine().scan_fragment(
        &Fragment::new(provider_secret.as_bytes()), &ScanOptions::default(),
    );
    assert!(provider_scan.is_complete());
    assert_eq!(provider_scan.findings().len(), 1);
    assert_eq!(provider_scan.findings()[0].rule_id().as_bytes(), b"rustleaks.replicate-api-token");
    assert_eq!(provider_scan.findings()[0].secret().as_bytes(), provider_secret.as_bytes());
    assert!(providers.identity().builtin_review_reference().is_some());
    let connections = NativePolicy::builder()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)?.build()?;
    let connection_secret = "Q7m2Z9v4L1c8R5s0N6b3X"; // gitleaks:allow
    let connection_input = format!("Server=localhost;PWD={connection_secret};");
    let connection_scan = connections.engine().scan_fragment(
        &Fragment::new(connection_input.as_bytes()), &ScanOptions::default(),
    );
    assert!(connection_scan.is_complete());
    assert_eq!(connection_scan.findings().len(), 1);
    assert_eq!(connection_scan.findings()[0].rule_id().as_bytes(), b"rustleaks.connection-string.password.unquoted");
    assert_eq!(connection_scan.findings()[0].secret().as_bytes(), connection_secret.as_bytes());
    assert!(connections.identity().builtin_review_reference().is_some());
    Ok(())
}
"#
}

fn write_external_consumer(root: &Path, package: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root.join("src"))
        .map_err(|error| format!("cannot create external consumer: {error}"))?;
    let path = package.to_string_lossy().replace('\\', "/");
    let manifest = format!(
        "[package]\nname = \"rustleaks-external-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\nregex-automata = \"^0.4.12\"\nregex-syntax = \"^0.8.5\"\nrustleaks-core = {{ path = {} }}\n",
        serde_json::to_string(&path)
            .map_err(|error| format!("cannot quote package path: {error}"))?
    );
    std::fs::write(root.join("Cargo.toml"), manifest)
        .map_err(|error| format!("cannot write external Cargo manifest: {error}"))?;
    std::fs::write(root.join("src/main.rs"), consumer_source())
        .map_err(|error| format!("cannot write external consumer source: {error}"))?;
    Ok(())
}

fn validate_external_regex_resolution(root: &Path) -> Result<(), String> {
    let metadata = command_output(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--offline",
    ]))?;
    let document: serde_json::Value = serde_json::from_str(&metadata)
        .map_err(|error| format!("cannot parse external consumer cargo metadata: {error}"))?;
    let packages = document["packages"]
        .as_array()
        .ok_or("external consumer cargo metadata has no packages array")?;

    for (name, requirement) in [("regex-automata", "^0.4.12"), ("regex-syntax", "^0.8.5")] {
        let versions = packages
            .iter()
            .filter(|package| package["name"].as_str() == Some(name))
            .filter_map(|package| package["version"].as_str())
            .collect::<Vec<_>>();
        if versions.len() != 1 {
            return Err(format!(
                "external consumer must resolve one shared {name} version satisfying {requirement}, got {versions:?}"
            ));
        }
        let version = semver::Version::parse(versions[0])
            .map_err(|error| format!("invalid {name} version {}: {error}", versions[0]))?;
        let requirement = semver::VersionReq::parse(requirement)
            .map_err(|error| format!("invalid {name} requirement {requirement}: {error}"))?;
        if !requirement.matches(&version) {
            return Err(format!(
                "external consumer resolved {name} {version}, which does not satisfy {requirement}"
            ));
        }
    }
    Ok(())
}

fn run_external_cargo_consumer(staging: &Path, package: &Path) -> Result<(), String> {
    let root = staging.join("cargo-consumer");
    write_external_consumer(&root, package)?;
    command_output(
        Command::new("cargo")
            .current_dir(&root)
            .args(["generate-lockfile", "--offline"]),
    )?;
    validate_external_regex_resolution(&root)?;
    command_output(Command::new("cargo").current_dir(&root).args([
        "run",
        "--locked",
        "--offline",
    ]))?;
    Ok(())
}

fn run_external_bazel_consumer(staging: &Path, package: &Path) -> Result<(), String> {
    let root = staging.join("bazel-consumer");
    write_external_consumer(&root, package)?;
    command_output(
        Command::new("cargo")
            .current_dir(&root)
            .args(["generate-lockfile", "--offline"]),
    )?;
    validate_external_regex_resolution(&root)?;
    std::fs::write(
        root.join("MODULE.bazel"),
        r#"module(name = "rustleaks_external_consumer")
bazel_dep(name = "rules_rust", version = "0.72.0")

rust = use_extension("@rules_rust//rust:extensions.bzl", "rust")
rust.toolchain(edition = "2024", versions = ["1.95.0"])
use_repo(rust, "rust_toolchains")
register_toolchains("@rust_toolchains//:all")

crate = use_extension("@rules_rust//crate_universe:extensions.bzl", "crate")
crate.from_cargo(
    name = "crates",
    cargo_lockfile = "//:Cargo.lock",
    isolated = True,
    manifests = ["//:Cargo.toml"],
)
use_repo(crate, "crates")
"#,
    )
    .map_err(|error| format!("cannot write external Bazel module: {error}"))?;
    std::fs::write(
        root.join("BUILD.bazel"),
        r#"load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_binary")

rust_binary(
    name = "consumer",
    aliases = aliases(),
    crate_root = "src/main.rs",
    deps = all_crate_deps(normal = True),
    edition = "2024",
    srcs = ["src/main.rs"],
)
"#,
    )
    .map_err(|error| format!("cannot write external Bazel build: {error}"))?;
    for locked in [false, true] {
        command_output(Command::new("bazelisk").current_dir(&root).args(
            external_bazel_consumer_args(cfg!(target_os = "macos"), locked),
        ))?;
    }
    Ok(())
}

fn external_bazel_consumer_args(macos: bool, locked: bool) -> Vec<&'static str> {
    let mut args = vec![
        "--ignore_all_rc_files",
        "run",
        "//:consumer",
        if locked {
            "--lockfile_mode=error"
        } else {
            "--lockfile_mode=update"
        },
    ];
    if macos {
        // Apple-linked proc macros can have a misaligned LINKEDIT string pool
        // when debug stripping is enabled. Keep exec artifacts unstripped so
        // rustc can load them; target code and toolchain versions are unchanged.
        args.push("--@rules_rust//rust/settings:extra_exec_rustc_flag=-Cstrip=none");
    }
    if locked {
        args.push("--nofetch");
    }
    args
}

pub(crate) fn release_dry_run() -> Result<(), String> {
    package_check()?;
    let root = workspace_root()?;
    let staging = ScopedTempDir::new("release-registry")?;
    let index = staging.path.join("index");
    let bare_index = staging.path.join("index.git");
    std::fs::create_dir(&index)
        .map_err(|error| format!("cannot create local release registry: {error}"))?;
    std::fs::write(
        index.join("config.json"),
        r#"{"dl":"https://static.crates.io/crates","api":"http://127.0.0.1:9"}"#,
    )
    .map_err(|error| format!("cannot write local release registry: {error}"))?;
    command_output(
        Command::new("git")
            .current_dir(&index)
            .args(["init", "--quiet"]),
    )?;
    command_output(
        Command::new("git")
            .current_dir(&index)
            .args(["add", "config.json"]),
    )?;
    command_output(Command::new("git").current_dir(&index).args([
        "-c",
        "user.name=Rustleaks",
        "-c",
        "user.email=local@invalid",
        "commit",
        "--quiet",
        "-m",
        "initialize local registry",
    ]))?;
    command_output(
        Command::new("git")
            .args(["clone", "--quiet", "--bare"])
            .arg(&index)
            .arg(&bare_index),
    )?;
    let index_url = local_file_url(&bare_index)?;
    command_output(
        Command::new("cargo")
            .current_dir(&root)
            .args([
                "publish",
                "--dry-run",
                "--locked",
                "--allow-dirty",
                "-p",
                "rustleaks-core",
                "--index",
            ])
            .arg(index_url),
    )?;
    println!("rustleaks-core locked publish dry run passed against a local no-upload registry");
    Ok(())
}

fn local_file_url(path: &Path) -> Result<String, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve local registry path: {error}"))?;
    let path = path.to_string_lossy().replace('\\', "/");
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&hex_lower(&[byte]));
        }
    }
    if cfg!(windows) {
        Ok(format!("file:///{encoded}"))
    } else {
        Ok(format!("file://{encoded}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RELEASE_VERSION, validate_core_repository_metadata, validate_publish_policy,
        validate_regex_backend_metadata,
    };

    #[test]
    fn external_bazel_consumer_scopes_strip_override_to_macos_in_both_passes() {
        let strip = "--@rules_rust//rust/settings:extra_exec_rustc_flag=-Cstrip=none";
        for macos in [false, true] {
            let mut update = super::external_bazel_consumer_args(macos, false);
            let locked = super::external_bazel_consumer_args(macos, true);
            assert_eq!(update.contains(&strip), macos);
            assert_eq!(locked.contains(&strip), macos);
            assert_eq!(
                &update[..3],
                ["--ignore_all_rc_files", "run", "//:consumer"]
            );
            assert_eq!(update[3], "--lockfile_mode=update");
            update[3] = "--lockfile_mode=error";
            update.push("--nofetch");
            assert_eq!(locked, update);
        }
    }

    #[test]
    fn publish_policy_allows_only_the_versioned_core_crate() {
        let valid = serde_json::json!({
            "packages": [
                {"name": "rustleaks-core", "version": RELEASE_VERSION, "publish": null},
                {"name": "rustleaks-cli", "version": RELEASE_VERSION, "publish": []},
                {"name": "rustleaks-bzip2", "version": "0.1.2-rustleaks.1", "publish": []}
            ]
        });
        validate_publish_policy(&valid.to_string()).unwrap();
        let extra = valid.to_string().replace(
            r#""name":"rustleaks-cli","publish":[]"#,
            r#""name":"rustleaks-cli","publish":null"#,
        );
        assert!(validate_publish_policy(&extra).is_err());
        let wrong_version = valid.to_string().replace(RELEASE_VERSION, "9.9.9");
        assert!(validate_publish_policy(&wrong_version).is_err());
    }

    #[test]
    fn resolved_metadata_rejects_inherited_upstream_repository() {
        let inherited = r#"{
            "packages": [{
                "name": "rustleaks-core",
                "repository": "https://github.com/gitleaks/gitleaks"
            }]
        }"#;
        assert!(validate_core_repository_metadata(inherited).is_err());

        let independent = serde_json::json!({
            "packages": [{
                "name": "rustleaks-core",
                "version": RELEASE_VERSION,
                "description": "Synchronous, byte-first secret detection engine for Rustleaks",
                "license": "MIT AND BSD-3-Clause AND Apache-2.0",
                "repository": "https://github.com/joshgarnett/rustleaks",
                "homepage": "https://github.com/joshgarnett/rustleaks",
                "documentation": "https://docs.rs/rustleaks-core",
                "readme": "README.md",
                "rust_version": "1.95",
                "keywords": ["gitleaks", "secret-detection", "security", "scanner"],
                "categories": ["development-tools"],
                "metadata": {"docs": {"rs": {
                    "all-features": true,
                    "rustdoc-args": ["--cfg", "docsrs", "-D", "warnings"]
                }}}
            }]
        })
        .to_string();
        assert!(validate_core_repository_metadata(&independent).is_ok());
    }

    #[test]
    fn resolved_metadata_requires_compatible_regex_backend_ranges() {
        let compatible = r#"{
            "packages": [
                {"name":"rustleaks-core","dependencies":[
                    {"name":"regex-automata","req":"^0.4.12"},
                    {"name":"regex-syntax","req":"^0.8.5"}
                ]},
                {"name":"regex-automata","version":"0.4.18"},
                {"name":"regex-syntax","version":"0.8.11"}
            ]
        }"#;
        assert!(validate_regex_backend_metadata(compatible).is_ok());

        let mut current = compatible.replace("^0.4.12", "=0.4.12");
        assert!(validate_regex_backend_metadata(&current).is_err());
        current = compatible.replace("^0.8.5", "^0.8.4");
        assert!(validate_regex_backend_metadata(&current).is_err());
        current = compatible.replace(
            r#"{"name":"regex-syntax","req":"^0.8.5"}"#,
            r#"{"name":"regex-syntax","req":"^0.8.5"},{"name":"regex","req":"^1"}"#,
        );
        assert!(validate_regex_backend_metadata(&current).is_err());
    }

    #[test]
    fn resolved_workspace_inheritance_negative_control_fails_closed() {
        // This is the resolved shape Cargo emits for `repository.workspace =
        // true`; test the metadata boundary without relying on a host Cargo.
        let inherited = r#"{
            "packages": [{
                "name": "rustleaks-core",
                "repository": "https://github.com/gitleaks/gitleaks"
            }]
        }"#;
        assert!(validate_core_repository_metadata(inherited).is_err());
    }
}
