#![forbid(unsafe_code)]
//! Stable repository validation commands.

use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

mod build_system;
mod fuzzing;
mod performance;
mod performance_comparison;
mod release_artifact;
mod security_deep;
mod tooling;
mod workflows;

use tooling::{command_output, command_status_with_timeout};

const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
const CONFIG_SHA256: &str = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
const RELEASE_VERSION: &str = "0.1.0-alpha.8";
const CARGO_DENY_VERSION: &str = "cargo-deny 0.19.9";
const CARGO_AUDIT_VERSION: &str = "cargo-audit-audit 0.22.2";
const CARGO_GEIGER_VERSION: &str = "cargo-geiger 0.13.0";
const CARGO_PUBLIC_API_VERSION: &str = "cargo-public-api 0.52.0";
const PUBLIC_API_TOOLCHAIN: &str = "nightly-2026-08-21";
const CARGO_FUZZ_VERSION: &str = "cargo-fuzz 0.13.2";
const CARGO_VET_VERSION: &str = "cargo-vet 0.10.2";
const COMPCOL_EXEMPTION_VERSION: &str = "0.7.8";
const COMPCOL_EXEMPTION_SHA256: &str =
    "7a9657f9d47c2bc36be681f158d208f40bafdd1c8c32003dac8e7dfe0cb68a97";
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
const FUZZ_TOOLCHAIN: &str = "nightly-2026-08-21";
const MIRI_TOOLCHAIN: &str = "nightly-2026-08-21";
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const PUBLIC_API_SNAPSHOT: &str = "compat/public-api/rustleaks-core-0.1.0-alpha.1.txt";

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command] if command == "manifest-check" || command == "frozen-evidence-check" => {
            tooling::check_frozen_evidence(&workspace_root()?)
        }
        [command] if command == "regression-check" => regression_check(),
        [command] if command == "qualify" => qualify(),
        [command, arguments @ ..] if command == "generate" => {
            tooling::run_generate(&workspace_root()?, arguments)
        }
        [command] if command == "public-api-check" => public_api_check(),
        [command] if command == "build-system-check" => build_system::check(&workspace_root()?),
        [command] if command == "package-check" => package_check(),
        [command] if command == "release-dry-run" => release_dry_run(),
        [command, arguments @ ..] if command == "release-artifact" => {
            release_artifact::run(&workspace_root()?, arguments)
        }
        [command] if command == "security-check" => security_check(),
        [command, arguments @ ..] if command == "security-deep" => {
            security_deep::run(&workspace_root()?, arguments)
        }
        [command] if command == "rustsec-check" => rustsec_check(),
        [command] if command == "vet-check" => vet_check(),
        [command] if command == "unsafe-inventory-check" => unsafe_inventory_check(),
        [command] if command == "supply-chain-check" => supply_chain_check(),
        [command] if command == "dependency-safety-check" => dependency_safety_check(),
        [command] if command == "owned-safety-check" => owned_safety_check(),
        [command] if command == "docs-check" => docs_check(),
        [command] if command == "quality-check" => quality_check(),
        [command] if command == "miri-check" => miri_check(),
        [command] if command == "panic-abort-check" => panic_abort_check(),
        [command, arguments @ ..] if command == "fuzz" => {
            fuzzing::run(&workspace_root()?, arguments)
        }
        [command] if command == "fuzz-check" => fuzz_check(),
        [command] if command == "fuzz-build" => fuzz_build(),
        [command] if command == "fuzz-smoke" => fuzz_smoke(),
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "run" => {
            performance::run(arguments)
        }
        [command, subcommand] if command == "perf" && subcommand == "check" => performance::check(),
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "report" => {
            performance::report(arguments)
        }
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "profile" => {
            performance::profile(arguments)
        }
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "calibrate" => {
            performance::calibrate(arguments)
        }
        [command, subcommand, arguments @ ..]
            if command == "perf" && subcommand == "representative" =>
        {
            performance::representative(arguments)
        }
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "compare" => {
            performance_comparison::run(&workspace_root()?, arguments)
        }
        _ => Err("usage: cargo xtask {manifest-check|frozen-evidence-check|regression-check|qualify|public-api-check|build-system-check|package-check|release-dry-run|release-artifact [ARGS]|security-check|security-deep [ARGS]|rustsec-check|vet-check|unsafe-inventory-check|supply-chain-check|dependency-safety-check|owned-safety-check|docs-check|quality-check|miri-check|panic-abort-check|fuzz-check|fuzz-build|fuzz-smoke|fuzz [ARGS]|generate [ARGS]|perf <run|check|representative|compare|profile|calibrate|report> [ARGS]}".into()),
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    if let Some(root) = env::var_os("BUILD_WORKSPACE_DIRECTORY").filter(|root| !root.is_empty()) {
        return Ok(PathBuf::from(root));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot locate workspace root".to_owned())?;
    if root.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(root)
    }
}

fn composite_test_executable_from_messages(messages: &str) -> Result<PathBuf, String> {
    let mut executables = Vec::new();
    for (index, line) in messages.lines().enumerate() {
        let message: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "cargo emitted invalid JSON on line {} while locating the composite test: {error}",
                index + 1
            )
        })?;
        let is_composite_test = message.get("reason").and_then(serde_json::Value::as_str)
            == Some("compiler-artifact")
            && message
                .pointer("/target/name")
                .and_then(serde_json::Value::as_str)
                == Some("composite_corpus")
            && message
                .pointer("/target/kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("test")));
        if !is_composite_test {
            continue;
        }
        let executable = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "composite_corpus compiler artifact did not include an executable".to_owned()
            })?;
        executables.push(PathBuf::from(executable));
    }
    executables.sort();
    executables.dedup();
    match executables.as_slice() {
        [executable] => Ok(executable.clone()),
        [] => Err("cargo did not report a composite_corpus test executable".into()),
        _ => Err(format!(
            "cargo reported multiple composite_corpus test executables: {executables:?}"
        )),
    }
}

fn composite_test_executable(root: &Path) -> Result<PathBuf, String> {
    let messages = command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--test",
                "composite_corpus",
                "--no-run",
                "--message-format=json",
            ])
            .current_dir(root),
    )?;
    composite_test_executable_from_messages(&messages)
}

fn resource_test_command(executable: &Path, test: &str, root: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .args([test, "--exact"])
        .env("RUSTLEAKS_BOUNDED_RESOURCE_TEST", test)
        .current_dir(root);
    command
}

fn run_resource_test(
    executable: &Path,
    test: &str,
    root: &Path,
    timeout: Duration,
) -> Result<(), String> {
    command_status_with_timeout(
        &mut resource_test_command(executable, test, root),
        timeout,
        test,
    )
}

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
    for required in [
        "pinned commit b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b",
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
            && !["default/", "src/", "tests/"]
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
            "Byte-first synchronous engine for the independent Rustleaks port",
        ),
        ("license", "MIT AND BSD-3-Clause"),
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

fn require_exact_tool_version(
    command: &mut Command,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let actual = command_output(command)?;
    if actual != expected {
        return Err(format!(
            "{label} version mismatch: expected `{expected}`, got `{actual}`"
        ));
    }
    Ok(())
}

fn public_api_check() -> Result<(), String> {
    let root = workspace_root()?;
    let mut version_command = public_api_command();
    version_command.arg("--version");
    require_exact_tool_version(
        &mut version_command,
        CARGO_PUBLIC_API_VERSION,
        "cargo-public-api",
    )?;
    let mut command = public_api_command();
    command
        .args(["-p", "rustleaks-core", "-sss", "--color", "never"])
        .current_dir(&root);
    let actual = command_output(&mut command)?;
    let expected = std::fs::read_to_string(root.join(PUBLIC_API_SNAPSHOT))
        .map_err(|error| format!("cannot read public API snapshot: {error}"))?;
    if actual.trim_end() != expected.trim_end() {
        return Err(format!(
            "rustleaks-core public API differs from {PUBLIC_API_SNAPSHOT}"
        ));
    }
    println!("rustleaks-core public API matches the supported alpha snapshot");
    Ok(())
}

fn public_api_command() -> Command {
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{PUBLIC_API_TOOLCHAIN}"))
        .arg("public-api");
    command
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

fn package_check() -> Result<(), String> {
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
    r#"use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::native::{EXTRA_RULES_V1, NativePolicy};
use rustleaks_core::triage::{ReviewPolicy, ReviewSource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    command_output(Command::new("bazelisk").current_dir(&root).args([
        "--ignore_all_rc_files",
        "run",
        "//:consumer",
        "--lockfile_mode=update",
    ]))?;
    command_output(Command::new("bazelisk").current_dir(&root).args([
        "--ignore_all_rc_files",
        "run",
        "//:consumer",
        "--lockfile_mode=error",
        "--nofetch",
    ]))?;
    Ok(())
}

fn release_dry_run() -> Result<(), String> {
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
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    if cfg!(windows) {
        Ok(format!("file:///{encoded}"))
    } else {
        Ok(format!("file://{encoded}"))
    }
}

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

fn unsafe_count(value: &serde_json::Value) -> u64 {
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
        "brotli-decompressor@6.2.0",
        "const-oid@0.10.2",
        "hybrid-array@0.4.15",
        "itoa@1.0.18",
        "lz4_flex@0.14.0",
        "lzma-rust2@0.25.0",
        "memchr@2.8.3",
        "proc-macro2@1.0.107",
        "regex-automata@0.4.18",
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
    if (source.is_null() || source.get("Path").is_some()) && (used_unsafe != 0 || !forbids_unsafe) {
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

fn owned_safety_check() -> Result<(), String> {
    let root = workspace_root()?;
    let workspace = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|error| format!("cannot read workspace manifest: {error}"))?;
    if !workspace.contains("[workspace.lints.rust]\nunsafe_code = \"forbid\"") {
        return Err("workspace must forbid unsafe code for inheriting owned crates".into());
    }
    let crate_roots = [
        "crates/rustleaks-bzip2/src/lib.rs",
        "crates/rustleaks-cli/src/lib.rs",
        "crates/rustleaks-cli/src/main.rs",
        "crates/rustleaks-compat/src/lib.rs",
        "crates/rustleaks-compat/src/bin/rustleaks-perf.rs",
        "crates/rustleaks-compat/src/bin/rustleaks-quality.rs",
        "crates/rustleaks-core/src/lib.rs",
        "crates/rustleaks-rar-codec/src/lib.rs",
        "crates/rustleaks-report/src/lib.rs",
        "crates/rustleaks-sevenz/src/lib.rs",
        "crates/rustleaks-sources/src/lib.rs",
        "crates/rustleaks-sources/examples/panic_abort_policy.rs",
        "crates/xtask/src/main.rs",
        "crates/rustleaks-core/fuzz/fuzz_targets/config.rs",
        "crates/rustleaks-core/fuzz/fuzz_targets/fragment_scan.rs",
        "crates/rustleaks-core/fuzz/fuzz_targets/go_regex.rs",
        "crates/rustleaks-core/fuzz/fuzz_targets/session.rs",
        "crates/rustleaks-report/fuzz/fuzz_targets/template.rs",
        "crates/rustleaks-sources/fuzz/fuzz_targets/archive.rs",
        "crates/rustleaks-sources/fuzz/fuzz_targets/git_patch.rs",
        "crates/rustleaks-sources/fuzz/fuzz_targets/reader_schedule.rs",
    ];
    for relative in crate_roots {
        let source = std::fs::read_to_string(root.join(relative))
            .map_err(|error| format!("cannot read owned crate root {relative}: {error}"))?;
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
    println!("workspace, fork, executable, example, and standalone fuzz roots forbid unsafe code");
    Ok(())
}

fn security_check() -> Result<(), String> {
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

fn run_quality_command(
    root: &Path,
    target: &ScopedTempDir,
    args: &[&str],
    label: &str,
) -> Result<(), String> {
    command_status_with_timeout(
        Command::new("cargo")
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &target.path)
            .args(args),
        Duration::from_mins(20),
        label,
    )
}

fn run_quality_tests(
    root: &Path,
    target: &ScopedTempDir,
    tools: &performance::QualityTestTools,
    args: &[&str],
    label: &str,
) -> Result<(), String> {
    tools.unchanged()?;
    let mut command = Command::new("cargo");
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", &target.path)
        .args(args);
    tools.bind(&mut command);
    command_status_with_timeout(&mut command, Duration::from_mins(20), label)?;
    tools.unchanged()
}

fn collect_documentation(
    directory: &Path,
    root: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot read documentation directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("cannot read documentation entry: {error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("cannot relativize documentation path: {error}"))?;
        let verbatim_upstream_fixture = [
            "compat/fixtures/upstream/testdata/expected/report/template_markdown.md",
            "compat/fixtures/upstream/testdata/repos/archives/README.md",
            "compat/fixtures/upstream/testdata/repos/small/README.md",
            "compat/fixtures/upstream/testdata/repos/staged/README.md",
        ]
        .iter()
        .any(|fixture| relative == Path::new(fixture));
        if relative.starts_with("target")
            || relative.starts_with(".git")
            || verbatim_upstream_fixture
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_documentation(&path, root, files)?;
        } else if file_type.is_file()
            && path
                .extension()
                .is_some_and(|value| matches!(value.to_str(), Some("md" | "rs" | "yml" | "yaml")))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn markdown_local_links(contents: &str) -> impl Iterator<Item = &str> {
    contents
        .split("](")
        .skip(1)
        .filter_map(|tail| tail.split_once(')').map(|(target, _)| target.trim()))
}

fn rust_documentation(contents: &str) -> String {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            line.strip_prefix("//!")
                .or_else(|| line.strip_prefix("///"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn docs_check() -> Result<(), String> {
    let root = workspace_root()?;
    workflows::check(&root)?;
    let mut files = Vec::new();
    collect_documentation(&root, &root, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err("documentation check found no maintained prose surfaces".into());
    }
    let mut prose_files = 0_usize;
    let mut rust_doc_surfaces = 0_usize;
    for path in &files {
        let contents = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read documentation {}: {error}", path.display()))?;
        let is_rust = path.extension().is_some_and(|value| value == "rs");
        let prose = if is_rust {
            rust_documentation(&contents)
        } else {
            contents.clone()
        };
        if prose.is_empty() {
            continue;
        }
        if is_rust {
            rust_doc_surfaces += 1;
        } else {
            prose_files += 1;
        }
        if prose.contains('\u{2014}') {
            return Err(format!(
                "documentation contains an em dash: {}",
                path.display()
            ));
        }
        if prose.chars().any(|character| {
            ('\u{1f000}'..='\u{1faff}').contains(&character)
                || ('\u{2600}'..='\u{27bf}').contains(&character)
        }) {
            return Err(format!(
                "documentation contains an emoji: {}",
                path.display()
            ));
        }
        let lowercase = prose.to_ascii_lowercase();
        for phrase in [
            "100% safe",
            "blazing fast",
            "best-in-class",
            "production-quality",
            "world-class",
            "ultra-fast",
        ] {
            if lowercase.contains(phrase) {
                return Err(format!(
                    "documentation contains disallowed marketing phrase {phrase:?}: {}",
                    path.display()
                ));
            }
        }
        if path.extension().is_some_and(|value| value == "md") {
            let parent = path
                .parent()
                .ok_or_else(|| format!("{} has no parent", path.display()))?;
            for target in markdown_local_links(&contents) {
                let target = target.trim_matches(['<', '>']);
                if target.is_empty()
                    || target.starts_with('#')
                    || target.starts_with("http://")
                    || target.starts_with("https://")
                    || target.starts_with("mailto:")
                {
                    continue;
                }
                let target = target.split('#').next().unwrap_or(target);
                if !parent.join(target).exists() {
                    return Err(format!(
                        "broken local documentation link {target:?} in {}",
                        path.display()
                    ));
                }
            }
        }
    }
    println!(
        "checked {prose_files} maintained prose files and {rust_doc_surfaces} Rust documentation surfaces for links and style"
    );
    Ok(())
}

fn quality_check() -> Result<(), String> {
    let root = workspace_root()?;
    let target = ScopedTempDir::new("release-quality")?;
    run_quality_command(&root, &target, &["fmt", "--all", "--check"], "format check")?;
    run_quality_command(
        &root,
        &target,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
            "--",
            "-D",
            "warnings",
        ],
        "warning-denied Clippy",
    )?;
    let tools = performance::QualityTestTools::prepare(&root)?;
    run_quality_tests(
        &root,
        &target,
        &tools,
        &["test", "--workspace", "--locked", "--offline"],
        "default-feature workspace tests",
    )?;
    run_quality_tests(
        &root,
        &target,
        &tools,
        &[
            "test",
            "--workspace",
            "--all-features",
            "--locked",
            "--offline",
        ],
        "all-feature workspace tests",
    )?;
    command_status_with_timeout(
        Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target.path)
            .env("RUSTDOCFLAGS", "-D warnings")
            .args([
                "doc",
                "--workspace",
                "--all-features",
                "--no-deps",
                "--locked",
                "--offline",
            ]),
        Duration::from_mins(20),
        "warning-denied rustdoc",
    )?;
    run_quality_command(
        &root,
        &target,
        &[
            "+1.95.0",
            "check",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
        ],
        "Rust 1.95 MSRV check",
    )?;
    println!("local quality and MSRV checks passed; Bazel owns the supported target matrix");
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
    println!("selected core, source, and report state transitions passed pinned Miri");
    Ok(())
}

fn clean_worktree_check() -> Result<(), String> {
    let root = workspace_root()?;
    let status = command_output(Command::new("git").current_dir(&root).args([
        "status",
        "--porcelain",
        "--untracked-files=all",
    ]))?;
    if !status.is_empty() {
        return Err(format!(
            "release proof requires a clean worktree:\n{status}"
        ));
    }
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

struct ScopedTempDir {
    path: PathBuf,
}

impl ScopedTempDir {
    fn new(label: &str) -> Result<Self, String> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rustleaks-{label}-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path).map_err(|error| {
            format!(
                "cannot create temporary directory {}: {error}",
                path.display()
            )
        })?;
        Ok(Self { path })
    }
}

impl Drop for ScopedTempDir {
    fn drop(&mut self) {
        let safe = self.path.parent() == Some(std::env::temp_dir().as_path())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rustleaks-"));
        if safe {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn fuzz_build() -> Result<(), String> {
    let root = workspace_root()?;
    let toolchain = format!("+{FUZZ_TOOLCHAIN}");
    require_exact_tool_version(
        Command::new("cargo").args(["fuzz", "--version"]),
        CARGO_FUZZ_VERSION,
        "cargo-fuzz",
    )?;
    for manifest in [
        "crates/rustleaks-core/fuzz/Cargo.toml",
        "crates/rustleaks-sources/fuzz/Cargo.toml",
        "crates/rustleaks-report/fuzz/Cargo.toml",
    ] {
        command_output(Command::new("cargo").current_dir(&root).args([
            toolchain.as_str(),
            "check",
            "--locked",
            "--offline",
            "--all-targets",
            "--manifest-path",
            manifest,
        ]))?;
    }
    println!("all eight fuzz targets compile with their locked standalone manifests");
    Ok(())
}

fn fuzz_smoke() -> Result<(), String> {
    fuzzing::smoke(&workspace_root()?)
}

fn fuzz_campaign_bound(name: &str, default: u64, maximum: u64) -> Result<u64, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(default);
    };
    let value = value
        .to_str()
        .ok_or_else(|| format!("{name} is not UTF-8"))?
        .parse::<u64>()
        .map_err(|error| format!("{name} is not an unsigned integer: {error}"))?;
    if value == 0 || value > maximum {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(value)
}

fn fuzz_check() -> Result<(), String> {
    fuzz_smoke()
}

fn validate_git_adversarial_matrix(root: &Path) -> Result<(), String> {
    let paths = [
        "crates/rustleaks-sources/src/git.rs",
        "crates/rustleaks-sources/tests/git_sources.rs",
        "crates/rustleaks-sources/tests/git_scm.rs",
        "crates/rustleaks-sources/tests/git_corpus.rs",
    ];
    let mut evidence = String::new();
    for path in paths {
        let source = std::fs::read_to_string(root.join(path))
            .map_err(|error| format!("cannot read {path}: {error}"))?;
        evidence.push_str(&source);
    }
    for letter in 'a'..='n' {
        let marker = format!("fn matrix_{letter}_");
        if !evidence.contains(&marker) {
            return Err(format!(
                "mandatory Git adversarial matrix entry {letter} is missing ({marker})"
            ));
        }
    }
    let negative_controls = [
        "preserves_literal_space_splitting",
        "preserve_added_bytes_and_no_newline",
        "invalid UTF-8 path",
        "ineffective-commit-allowlist",
        "SourceControl::Stop",
        "rustleaks-deliberately-missing-git-executable",
        "cancelled_git_child_is_not_left_waitable_or_zombie",
        "FailingReader",
        "std::process::exit(code)",
    ];
    for marker in negative_controls {
        if !evidence.contains(marker) {
            return Err(format!(
                "mandatory Git negative control is missing ({marker})"
            ));
        }
    }
    let core_manifest = std::fs::read_to_string(root.join("crates/rustleaks-core/Cargo.toml"))
        .map_err(|error| format!("cannot read core manifest: {error}"))?;
    if core_manifest.contains("rustleaks-sources") || core_manifest.contains("git2") {
        return Err("Git/source dependencies entered rustleaks-core".to_owned());
    }
    let workflow = std::fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .map_err(|error| format!("cannot read CI workflow: {error}"))?;
    for (runner, target) in [
        ("ubuntu-24.04", "x86_64-unknown-linux-gnu"),
        ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
        ("ubuntu-24.04", "x86_64-unknown-linux-musl"),
        ("ubuntu-24.04-arm", "aarch64-unknown-linux-musl"),
        ("macos-15-intel", "x86_64-apple-darwin"),
        ("macos-15", "aarch64-apple-darwin"),
        ("windows-2025", "x86_64-pc-windows-msvc"),
        ("windows-11-arm", "aarch64-pc-windows-msvc"),
    ] {
        if !workflow.contains(runner) || !workflow.contains(target) {
            return Err(format!(
                "native Git CI matrix is missing {target} on {runner}"
            ));
        }
    }
    let dispositions = std::fs::read_to_string(root.join("compat/api-dispositions-v1.jsonl"))
        .map_err(|error| format!("cannot read API dispositions: {error}"))?;
    if dispositions.contains("rustleaks_sources::git::internal") {
        return Err("Git API dispositions name a nonexistent private path".to_owned());
    }
    Ok(())
}

fn regression_check() -> Result<(), String> {
    let root = workspace_root()?;
    tooling::check_frozen_evidence(&root)?;
    validate_git_adversarial_matrix(&root)?;
    command_status_with_timeout(
        Command::new("bazelisk")
            .current_dir(&root)
            .args(["test", "//:parity"]),
        Duration::from_mins(30),
        "Rust frozen regression replay",
    )?;
    println!("frozen evidence integrity and Rust regression replay passed");
    Ok(())
}

fn bounded_composite_resources() -> Result<(), String> {
    let root = workspace_root()?;
    let test_executable = composite_test_executable(&root)?;
    for test in [
        "resource_primary_aux_duplicate_cartesian_is_bounded",
        "resource_many_generics_is_bounded",
        "resource_empty_full_long_malformed_is_bounded",
        "resource_deep_required_graph_is_bounded",
    ] {
        run_resource_test(&test_executable, test, &root, Duration::from_secs(30))?;
    }
    println!("bounded composite resource controls passed");
    Ok(())
}

fn qualify() -> Result<(), String> {
    clean_worktree_check()?;
    docs_check()?;
    quality_check()?;
    owned_safety_check()?;
    dependency_safety_check()?;
    miri_check()?;
    regression_check()?;
    bounded_composite_resources()?;
    public_api_check()?;
    package_check()?;
    supply_chain_check()?;
    panic_abort_check()?;
    fuzz_check()?;
    performance::check()?;
    clean_worktree_check()?;
    println!("complete Rust regression and local release hardening passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        COMPCOL_EXEMPTION_SHA256, COMPCOL_EXEMPTION_TARGETS, PUBLIC_API_TOOLCHAIN, RELEASE_VERSION,
        build_system, composite_test_executable_from_messages, parse_civil_day, public_api_command,
        resource_test_command, reviewed_unsafe_packages, run_resource_test,
        validate_compcol_exemption_scope, validate_core_repository_metadata,
        validate_dependency_boundaries, validate_owned_unsafe_package, validate_publish_policy,
        validate_regex_backend_metadata, validate_supply_chain_exceptions,
        validate_unsafe_package_set, validate_vet_exemption, workspace_root,
    };
    use crate::tooling::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};

    const TIMEOUT_PROBE_TEST: &str = "tests::resource_launcher_timeout_probe_child";
    const RESOURCE_SELECTOR: &str = "RUSTLEAKS_BOUNDED_RESOURCE_TEST";

    #[test]
    fn public_api_uses_the_pinned_nightly_toolchain() {
        let command = public_api_command();
        assert_eq!(command.get_program(), "cargo");
        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [format!("+{PUBLIC_API_TOOLCHAIN}"), "public-api".to_owned()]
        );
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
            r#"version = "0.7.8"
criteria = "safe-to-deploy"
notes = "owner=maintainers; scope=reviewed graph; rationale=unselected concern; resolution=fixed audited release; review-on=boundary-change"
"#,
        ).unwrap();
        let future = parse_civil_day("2100-01-01").unwrap();
        assert!(validate_vet_exemption("compcol", &entry, future).unwrap());
        assert!(validate_vet_exemption("other", &entry, future).is_err());
        for (field, value) in [
            ("version", "0.7.9"),
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
            "packages": [{"name":"compcol", "version":"0.7.8", "id":"compcol-id",
                "source":"registry+https://github.com/rust-lang/crates.io-index"}],
            "resolve":{"nodes":[{"id":"compcol-id", "features":["alloc","rar2"]}]},
        });
        let bazel = serde_json::json!({
            "crates":{"compcol 0.7.8":{
                "name":"compcol", "version":"0.7.8",
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
            ("/packages/0/version", serde_json::json!("0.7.9")),
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
            ("/crates/compcol 0.7.8/version", serde_json::json!("0.7.9")),
            (
                "/crates/compcol 0.7.8/repository/Http/sha256",
                serde_json::json!("changed"),
            ),
            (
                "/crates/compcol 0.7.8/common_attrs/crate_features/common",
                serde_json::json!(["alloc", "rar2", "default"]),
            ),
            (
                "/crates/compcol 0.7.8/common_attrs/crate_features/selects",
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
    fn subprocess_diagnostics_preserve_bounded_output_tails() {
        assert_eq!(diagnostic_tail(b"", 4), "<empty>");
        assert_eq!(diagnostic_tail(b" full output \n", 32), "full output");
        assert_eq!(
            diagnostic_tail(b"prefix-failure detail\n", 15),
            "... 7 bytes omitted ...\nfailure detail"
        );
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

    #[derive(Default)]
    struct TimeoutLifecycleProbe {
        killed: bool,
        reaped: bool,
        fail_reap: bool,
    }

    impl TimeoutChild for TimeoutLifecycleProbe {
        fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
            Ok(None)
        }

        fn kill(&mut self) -> std::io::Result<()> {
            self.killed = true;
            Ok(())
        }

        fn reap(&mut self) -> std::io::Result<()> {
            assert!(self.killed, "child must be killed before it is reaped");
            self.reaped = true;
            if self.fail_reap {
                Err(std::io::Error::other("injected reap failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn timeout_lifecycle_requires_kill_and_reap() {
        let mut child = TimeoutLifecycleProbe::default();
        let error = wait_for_child_with_timeout(
            &mut child,
            Duration::ZERO,
            "lifecycle probe",
            "injected child",
        )
        .unwrap_err();
        assert!(error.contains("exceeded its external 0 second deadline"));
        assert!(child.killed, "timeout did not terminate the child");
        assert!(child.reaped, "timeout did not reap the terminated child");
    }

    #[test]
    fn timeout_lifecycle_fails_closed_when_reap_fails() {
        let mut child = TimeoutLifecycleProbe {
            fail_reap: true,
            ..TimeoutLifecycleProbe::default()
        };
        let error = wait_for_child_with_timeout(
            &mut child,
            Duration::ZERO,
            "lifecycle probe",
            "injected child",
        )
        .unwrap_err();
        assert!(error.contains("failed to reap timed-out lifecycle probe"));
        assert!(child.killed);
        assert!(child.reaped);
    }

    #[test]
    fn resource_launcher_timeout_probe_child() {
        if std::env::var(RESOURCE_SELECTOR).as_deref() != Ok(TIMEOUT_PROBE_TEST) {
            return;
        }
        let root = std::env::current_dir().unwrap();
        fs::write(root.join("pid"), std::process::id().to_string()).unwrap();
        let path = root.join("heartbeat");
        let mut heartbeat = 0_u64;
        loop {
            fs::write(&path, format!("{heartbeat}\n")).unwrap();
            heartbeat = heartbeat.wrapping_add(1);
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    fn assert_process_was_reaped(pid: &[u8]) {
        let raw_pid = std::str::from_utf8(pid)
            .expect("probe PID was not UTF-8")
            .parse()
            .expect("probe PID was not an integer");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("probe PID was zero");
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
            Err(error) if error == rustix::io::Errno::CHILD => {}
            Ok(Some((unreaped, status))) => panic!(
                "timed-out direct child PID {unreaped} remained waitable after launcher return: {status:?}"
            ),
            Ok(None) => {
                panic!("timed-out direct child PID {pid} was still running after launcher return")
            }
            Err(error) => panic!("failed to verify timed-out child PID {pid}: {error}"),
        }
    }

    #[test]
    fn resource_launcher_kills_and_reaps_its_selected_test_body() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rustleaks-xtask-timeout-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let heartbeat = root.join("heartbeat");
        let result = run_resource_test(
            &std::env::current_exe().unwrap(),
            TIMEOUT_PROBE_TEST,
            &root,
            Duration::from_secs(5),
        );
        assert!(
            result
                .unwrap_err()
                .contains("exceeded its external 5 second deadline")
        );
        let stopped = fs::read(&heartbeat).expect("probe body did not start before its deadline");
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            fs::read(&heartbeat).unwrap(),
            stopped,
            "timed-out direct test body continued writing after kill and reap"
        );
        #[cfg(unix)]
        assert_process_was_reaped(&fs::read(root.join("pid")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resource_launcher_command_contract_is_exact() {
        let executable = std::path::Path::new("/tmp/composite-corpus-test");
        let root = std::path::Path::new("/tmp/composite-root");
        let command = resource_test_command(executable, "resource-case", root);
        assert_eq!(command.get_program(), executable.as_os_str());
        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["resource-case", "--exact"]
        );
        assert_eq!(command.get_current_dir(), Some(root));
        assert!(command.get_envs().any(|(key, value)| {
            key == RESOURCE_SELECTOR
                && value.and_then(std::ffi::OsStr::to_str) == Some("resource-case")
        }));
    }

    #[test]
    fn composite_test_executable_is_selected_from_cargo_json() {
        let messages = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"dependency","kind":["lib"]},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"composite_corpus","kind":["test"]},"executable":"/tmp/composite-corpus-test"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        assert_eq!(
            composite_test_executable_from_messages(messages).unwrap(),
            std::path::PathBuf::from("/tmp/composite-corpus-test")
        );
        let missing = r#"{"reason":"build-finished","success":true}"#;
        assert!(composite_test_executable_from_messages(missing).is_err());
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

        let independent = r#"{
            "packages": [{
                "name": "rustleaks-core",
                "version": "0.1.0-alpha.8",
                "description": "Byte-first synchronous engine for the independent Rustleaks port",
                "license": "MIT AND BSD-3-Clause",
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
        }"#;
        assert!(validate_core_repository_metadata(independent).is_ok());
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

    #[test]
    fn cargo_and_bazel_build_contracts_match() {
        build_system::check(&workspace_root().unwrap()).unwrap();
    }
}
