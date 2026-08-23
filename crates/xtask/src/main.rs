#![forbid(unsafe_code)]
//! Stable repository validation commands.

use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use sha2::{Digest, Sha256};

mod build_system;
mod tooling;
mod workflows;

use tooling::{command_output, command_status_with_timeout, sha256_file};

const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
const CONFIG_SHA256: &str = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
const API_INVENTORY_SHA256: &str =
    "958ddaa92c5cce6afb21ef8209ce5689ff907cb2d9f152951bb75c795362125a";
const RELEASE_VERSION: &str = "0.1.0-alpha.1";
const CARGO_DENY_VERSION: &str = "cargo-deny 0.19.9";
const CARGO_AUDIT_VERSION: &str = "cargo-audit-audit 0.22.2";
const CARGO_GEIGER_VERSION: &str = "cargo-geiger 0.13.0";
const CARGO_PUBLIC_API_VERSION: &str = "cargo-public-api 0.52.0";
const CARGO_FUZZ_VERSION: &str = "cargo-fuzz 0.13.2";
const CARGO_VET_VERSION: &str = "cargo-vet 0.10.2";
const FUZZ_TOOLCHAIN: &str = "nightly-2026-08-21";
const MIRI_TOOLCHAIN: &str = "nightly-2026-08-21";
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const PUBLIC_API_SNAPSHOT: &str = "compat/public-api/rustleaks-core-0.1.0-alpha.1.txt";
const PERF_WORKLOADS: &[&str] = &[
    "default-compile",
    "default-no-keyword",
    "default-one-keyword",
    "default-many-keywords",
    "default-positive",
    "regex-hostile-miss",
    "regex-capture-entropy",
    "decode-five-level",
    "decode-large-base64-like",
    "source-directory-1",
    "source-directory-4",
    "report-json",
    "report-sarif",
    "bm-0001",
    "bm-0002",
    "bm-0003",
    "bm-0004",
    "bm-0005",
    "bm-0006",
    "bm-0007",
    "bm-0008",
];

#[derive(Clone, Copy)]
struct PerfInvariant {
    workload: &'static str,
    logical_bytes: u64,
    result_count: u64,
    output_bytes: u64,
    outcome_fnv1a64: &'static str,
}

const PERF_INVARIANTS: &[PerfInvariant] = &[
    PerfInvariant {
        workload: "default-compile",
        logical_bytes: 97_731,
        result_count: 222,
        output_bytes: 0,
        outcome_fnv1a64: "bba0f636d5a02d49",
    },
    PerfInvariant {
        workload: "default-no-keyword",
        logical_bytes: 1_048_576,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
    },
    PerfInvariant {
        workload: "default-one-keyword",
        logical_bytes: 1_048_576,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
    },
    PerfInvariant {
        workload: "default-many-keywords",
        logical_bytes: 1_048_576,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
    },
    PerfInvariant {
        workload: "default-positive",
        logical_bytes: 143,
        result_count: 1,
        output_bytes: 0,
        outcome_fnv1a64: "58e4f5aab1da7b3f",
    },
    PerfInvariant {
        workload: "regex-hostile-miss",
        logical_bytes: 262_144,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
    },
    PerfInvariant {
        workload: "regex-capture-entropy",
        logical_bytes: 65_536,
        result_count: 1,
        output_bytes: 0,
        outcome_fnv1a64: "038649fafe732c81",
    },
    PerfInvariant {
        workload: "decode-five-level",
        logical_bytes: 12_428,
        result_count: 128,
        output_bytes: 0,
        outcome_fnv1a64: "0d9076d695194702",
    },
    PerfInvariant {
        workload: "decode-large-base64-like",
        logical_bytes: 1_048_576,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
    },
    PerfInvariant {
        workload: "source-directory-1",
        logical_bytes: 8_388_608,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "3cee0642681c47e5",
    },
    PerfInvariant {
        workload: "source-directory-4",
        logical_bytes: 8_388_608,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "3cee0642681c47e5",
    },
    PerfInvariant {
        workload: "report-json",
        logical_bytes: 10_000,
        result_count: 10_000,
        output_bytes: 4_406_685,
        outcome_fnv1a64: "13362a3d26854efc",
    },
    PerfInvariant {
        workload: "report-sarif",
        logical_bytes: 10_000,
        result_count: 10_000,
        output_bytes: 7_308_202,
        outcome_fnv1a64: "8293a2e439c3f929",
    },
    PerfInvariant {
        workload: "bm-0001",
        logical_bytes: 40,
        result_count: 1,
        output_bytes: 0,
        outcome_fnv1a64: "af63bc4c8601b62c",
    },
    PerfInvariant {
        workload: "bm-0002",
        logical_bytes: 40,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "af63bd4c8601b7df",
    },
    PerfInvariant {
        workload: "bm-0003",
        logical_bytes: 1_153,
        result_count: 24,
        output_bytes: 0,
        outcome_fnv1a64: "43b103a307f3ee9d",
    },
    PerfInvariant {
        workload: "bm-0004",
        logical_bytes: 874,
        result_count: 68,
        output_bytes: 0,
        outcome_fnv1a64: "188c1f945093510b",
    },
    PerfInvariant {
        workload: "bm-0005",
        logical_bytes: 52,
        result_count: 1,
        output_bytes: 0,
        outcome_fnv1a64: "af63bc4c8601b62c",
    },
    PerfInvariant {
        workload: "bm-0006",
        logical_bytes: 77,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "af63bd4c8601b7df",
    },
    PerfInvariant {
        workload: "bm-0007",
        logical_bytes: 44,
        result_count: 1,
        output_bytes: 0,
        outcome_fnv1a64: "af63bc4c8601b62c",
    },
    PerfInvariant {
        workload: "bm-0008",
        logical_bytes: 82,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "af63bd4c8601b7df",
    },
];

#[derive(Clone, Copy)]
#[cfg(any(target_os = "macos", test))]
struct PerfBudget {
    workload: &'static str,
    median_elapsed_ns: u64,
    peak_rss_bytes: u64,
}

#[cfg(target_os = "macos")]
const M1_MAX_PERF_BUDGETS: &[PerfBudget] = &[
    PerfBudget {
        workload: "default-compile",
        median_elapsed_ns: 100_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
    PerfBudget {
        workload: "default-one-keyword",
        median_elapsed_ns: 600_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
    PerfBudget {
        workload: "regex-hostile-miss",
        median_elapsed_ns: 30_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
    PerfBudget {
        workload: "decode-five-level",
        median_elapsed_ns: 10_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
    PerfBudget {
        workload: "source-directory-1",
        median_elapsed_ns: 150_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
    PerfBudget {
        workload: "source-directory-4",
        median_elapsed_ns: 75_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
    PerfBudget {
        workload: "report-json",
        median_elapsed_ns: 30_000_000,
        peak_rss_bytes: 48 * 1024 * 1024,
    },
];

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
        [command] if command == "verify-upstream" => verify_upstream(),
        [command] if command == "manifest-check" => manifest_check(),
        [command] if command == "assertion-check" => assertion_check(),
        [command] if command == "generator-check" => generator_check(),
        [command] if command == "api-check" => api_check(),
        [command] if command == "fixture-check" => fixture_check(),
        [command, arguments @ ..] if command == "generate" => {
            tooling::run_generate(&workspace_root()?, arguments)
        }
        [command] if command == "config-check" => config_check(),
        [command] if command == "regex-check" => regex_check(),
        [command] if command == "detect-check" => detect_check(),
        [command] if command == "allowlist-check" => allowlist_check(),
        [command] if command == "decoder-check" => decoder_check(),
        [command] if command == "composite-check" => composite_check(),
        [command] if command == "session-check" => session_check(),
        [command] if command == "source-check" => source_check(),
        [command] if command == "git-check" => git_check(),
        [command] if command == "report-check" => report_check(),
        [command] if command == "cli-check" => cli_check(),
        [command] if command == "public-api-check" => public_api_check(),
        [command] if command == "build-system-check" => build_system::check(&workspace_root()?),
        [command] if command == "package-check" => package_check(),
        [command] if command == "release-dry-run" => release_dry_run(),
        [command] if command == "security-check" => security_check(),
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
        [command] if command == "fuzz-check" => fuzz_check(),
        [command] if command == "fuzz-build" => fuzz_build(),
        [command] if command == "fuzz-smoke" => fuzz_smoke(),
        [command, subcommand] if command == "perf" && subcommand == "run" => perf_run(),
        [command, subcommand] if command == "perf" && subcommand == "check" => perf_check(),
        [command, subcommand, flag] if command == "oracle" && subcommand == "generate" && flag == "--check" => oracle_check(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "bootstrap" => bootstrap_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "config" => config_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "regex" => regex_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "detect" => detect_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "allowlist" => allowlist_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "decoder" => decoder_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "composite" => composite_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "session" => session_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "source" => source_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "git" => git_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "report" => report_parity(),
        [command, flag, scope] if command == "parity" && flag == "--scope" && scope == "cli" => cli_parity(),
        [command, flag] if command == "parity" && flag == "--all" => full_parity(),
        _ => Err("usage: cargo xtask {verify-upstream|manifest-check|assertion-check|generator-check|api-check|fixture-check|config-check|regex-check|detect-check|allowlist-check|decoder-check|composite-check|session-check|source-check|git-check|report-check|cli-check|public-api-check|build-system-check|package-check|release-dry-run|security-check|rustsec-check|vet-check|unsafe-inventory-check|supply-chain-check|dependency-safety-check|owned-safety-check|docs-check|quality-check|miri-check|panic-abort-check|fuzz-check|fuzz-build|fuzz-smoke|generate <go-lowercase [--check]|api-dispositions [--check|--self-test|--summary|--output PATH]|assertions|generator-samples [--check|--output PATH|--check-output PATH]|config|composite|regex|detect|allowlist|decoder|session|source|git|report|cli [--check|--output PATH]|inventory [--check [CANDIDATE]|--output PATH]|regex-fuzz-seeds REQUESTS OUTPUT>|perf <run|check>|oracle generate --check|parity --scope <bootstrap|config|regex|detect|allowlist|decoder|composite|session|source|git|report|cli>|parity --all}".into()),
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

fn oracle_root() -> Result<PathBuf, String> {
    Ok(workspace_root()?
        .parent()
        .ok_or("workspace has no parent")?
        .join("gitleaks"))
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

fn verify_upstream() -> Result<(), String> {
    let root = oracle_root()?;
    let actual_revision = command_output(
        Command::new("git")
            .args(["-C"])
            .arg(&root)
            .args(["rev-parse", "HEAD"]),
    )?;
    if actual_revision != REVISION {
        return Err(format!(
            "upstream revision mismatch: expected {REVISION}, got {actual_revision}"
        ));
    }
    let actual_hash = sha256_file(&root.join("config/gitleaks.toml"))?;
    if actual_hash != CONFIG_SHA256 {
        return Err(format!(
            "default config hash mismatch: expected {CONFIG_SHA256}, got {actual_hash}"
        ));
    }
    println!("verified upstream revision {REVISION} and default config sha256 {CONFIG_SHA256}");
    Ok(())
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
    ] {
        if !package_files.lines().any(|path| path == required) {
            return Err(format!(
                "rustleaks-core source package omits required `{required}`"
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
    if package["repository"].as_str() == Some("https://github.com/gitleaks/gitleaks") {
        return Err("independent rustleaks-core package claims the upstream repository".into());
    }
    Ok(())
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
    for (name, requirement) in [("regex-automata", "=0.4.7"), ("regex-syntax", "=0.8.4")] {
        let dependency = dependencies
            .iter()
            .find(|dependency| dependency["name"] == name)
            .ok_or_else(|| format!("rustleaks-core omits exact {name} backend dependency"))?;
        if dependency["req"].as_str() != Some(requirement) {
            return Err(format!(
                "rustleaks-core {name} requirement must be {requirement}"
            ));
        }
        let resolved = packages.iter().any(|package| {
            package["name"] == name
                && package["version"].as_str() == Some(requirement.trim_start_matches('='))
        });
        if !resolved {
            return Err(format!(
                "resolved Cargo graph omits exact {name} {}",
                requirement.trim_start_matches('=')
            ));
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
    require_exact_tool_version(
        Command::new("cargo").args(["public-api", "--version"]),
        CARGO_PUBLIC_API_VERSION,
        "cargo-public-api",
    )?;
    let actual = command_output(
        Command::new("cargo")
            .args([
                "public-api",
                "-p",
                "rustleaks-core",
                "-sss",
                "--color",
                "never",
            ])
            .current_dir(&root),
    )?;
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
                .is_some_and(|name| name.starts_with("rustleaks-core-") && name.ends_with(".crate"))
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
use rustleaks_core::Engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigLoader::new().load_default()?;
    let engine = Engine::builder(config).build()?;
    let outcome = engine.scan_fragment(
        &Fragment::new(b"string AWSToken = \"AKIALALEMEL33243OLIB\";"),
        &ScanOptions::default(),
    );
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings()[0].rule_id().as_str()?, "aws-access-token");
    Ok(())
}
"#
}

fn write_external_consumer(root: &Path, package: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root.join("src"))
        .map_err(|error| format!("cannot create external consumer: {error}"))?;
    let path = package.to_string_lossy().replace('\\', "/");
    let manifest = format!(
        "[package]\nname = \"rustleaks-external-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\nrustleaks-core = {{ path = {} }}\n",
        serde_json::to_string(&path)
            .map_err(|error| format!("cannot quote package path: {error}"))?
    );
    std::fs::write(root.join("Cargo.toml"), manifest)
        .map_err(|error| format!("cannot write external Cargo manifest: {error}"))?;
    std::fs::write(root.join("src/main.rs"), consumer_source())
        .map_err(|error| format!("cannot write external consumer source: {error}"))?;
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
    std::fs::write(
        root.join("MODULE.bazel"),
        r#"module(name = "rustleaks_external_consumer")
bazel_dep(name = "rules_rust", version = "0.72.0")

rust = use_extension("@rules_rust//rust:extensions.bzl", "rust")
rust.toolchain(edition = "2024", versions = ["1.85.0"])
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
        "run",
        "//:consumer",
        "--lockfile_mode=update",
    ]))?;
    command_output(Command::new("bazelisk").current_dir(&root).args([
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
    validate_vet_exemptions(&root.join("supply-chain/config.toml"))?;
    command_output(Command::new("cargo").current_dir(&root).args([
        "vet",
        "--locked",
        "--no-registry-suggestions",
    ]))?;
    println!("locked cargo-vet graph satisfies the checked-in review policy");
    Ok(())
}

fn validate_vet_exemptions(path: &Path) -> Result<(), String> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read cargo-vet policy {}: {error}", path.display()))?;
    let config: toml::Value = toml::from_str(&source)
        .map_err(|error| format!("cannot parse cargo-vet policy {}: {error}", path.display()))?;
    let exemptions = config
        .get("exemptions")
        .and_then(toml::Value::as_table)
        .ok_or("cargo-vet policy contains no reviewed exemptions")?;
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock predates the Unix epoch: {error}"))?
        .as_secs()
        / 86_400;
    for (package, entries) in exemptions {
        let entries = entries
            .as_array()
            .ok_or_else(|| format!("cargo-vet exemptions for {package} are not an array"))?;
        for entry in entries {
            let version = entry
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("cargo-vet exemption for {package} omits version"))?;
            let notes = entry
                .get("notes")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("cargo-vet exemption {package}@{version} omits notes"))?;
            for marker in ["owner=", "scope=", "rationale=", "review-by="] {
                if !notes.contains(marker) {
                    return Err(format!(
                        "cargo-vet exemption {package}@{version} omits {marker} metadata"
                    ));
                }
            }
            let review = notes
                .split(';')
                .map(str::trim)
                .find_map(|field| field.strip_prefix("review-by="))
                .ok_or_else(|| {
                    format!("cargo-vet exemption {package}@{version} has no review date")
                })?;
            let review_day = parse_civil_day(review).ok_or_else(|| {
                format!("cargo-vet exemption {package}@{version} has invalid review date {review}")
            })?;
            if review_day < today {
                return Err(format!(
                    "cargo-vet exemption {package}@{version} expired on {review}"
                ));
            }
        }
    }
    println!(
        "all {} cargo-vet bootstrap package groups have owner, scope, rationale, and active review dates",
        exemptions.len()
    );
    Ok(())
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
        if id["source"].is_null()
            && (used_unsafe != 0 || package["unsafety"]["forbids_unsafe"] != true)
        {
            return Err(format!(
                "owned package {name}@{version} does not have a zero-unsafe forbid inventory"
            ));
        }
        if used_unsafe != 0 {
            unsafe_packages.insert(format!("{name}@{version}"));
        }
    }
    let expected = [
        "aho-corasick@1.1.5",
        "alloc-no-stdlib@2.0.4",
        "alloc-stdlib@0.2.4",
        "block-buffer@0.12.1",
        "brotli-decompressor@5.0.3",
        "const-oid@0.10.2",
        "cpufeatures@0.3.0",
        "hybrid-array@0.4.14",
        "itoa@1.0.18",
        "libc@0.2.189",
        "lz4_flex@0.14.0",
        "lzma-rust2@0.16.5",
        "lzma-rust2@0.19.0",
        "memchr@2.8.3",
        "proc-macro2@1.0.107",
        "regex-automata@0.4.7",
        "semver@1.0.28",
        "serde_core@1.0.229",
        "serde_json@1.0.151",
        "sha2@0.11.0",
        "syn@3.0.3",
        "toml_parser@1.1.3+spec-1.1.0",
        "twox-hash@2.1.3",
        "unicode-ident@1.0.24",
        "winnow@0.7.15",
        "winnow@1.0.4",
        "zmij@1.0.23",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if unsafe_packages != expected {
        return Err(format!(
            "cargo-geiger unsafe-bearing package set changed: expected {expected:?}, got {unsafe_packages:?}"
        ));
    }
    println!(
        "cargo-geiger matched the reviewed {}-package unsafe-bearing inventory; owned packages remain zero-unsafe",
        expected.len()
    );
    Ok(())
}

fn normalize_workspace_dependency_tree(root: &Path, tree: &str) -> String {
    tree.lines()
        .map(|line| {
            let (entry, repeat) = line
                .strip_suffix(" (*)")
                .map_or((line, ""), |entry| (entry, " (*)"));
            let Some((package, location)) = entry.rsplit_once(" (") else {
                return line.to_owned();
            };
            let Some(location) = location.strip_suffix(')') else {
                return line.to_owned();
            };
            if Path::new(location).starts_with(root) {
                format!("{package}{repeat}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn dependency_safety_check() -> Result<(), String> {
    let root = workspace_root()?;
    let graphs = [
        (
            "rustleaks-core",
            false,
            "d58ae3874c4c31586e859cab2ac5659608b55c07e7c771991b37700d56faadc1",
        ),
        (
            "rustleaks-report",
            false,
            "31d643c37aef98750509103e02a81c8a54c36593899db6f237ce8b4aa21c6b88",
        ),
        (
            "rustleaks-sources",
            false,
            "8bb90a9651d9f074b2362f23efbfb0dde8edfd12f82a76a606e5048d102232d9",
        ),
        (
            "rustleaks-sources",
            true,
            "507c513d16c3667a362f7f1f62b43c81e0b6bd6bf27d73fe38f85bc961f44b32",
        ),
        (
            "rustleaks-cli",
            true,
            "abf38e45586827bbc0320814a8dcb7a5a5bafdea44f65f5bf7772b2426116877",
        ),
    ];
    for (package, all_features, expected) in graphs {
        let mut command = Command::new("cargo");
        command.current_dir(&root).args([
            "tree", "--locked", "--edges", "normal", "--prefix", "none", "-p", package, "--target",
            "all",
        ]);
        if all_features {
            command.arg("--all-features");
        }
        let tree = normalize_workspace_dependency_tree(&root, &command_output(&mut command)?);
        let digest = Sha256::digest(format!("{tree}\n").as_bytes());
        let mut actual = String::with_capacity(64);
        for byte in digest {
            actual.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            actual.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        if actual != expected {
            let feature_set = if all_features {
                "all-feature"
            } else {
                "default-feature"
            };
            return Err(format!(
                "{package} {feature_set} all-target normal dependency graph changed: expected {expected}, got {actual}"
            ));
        }
    }
    println!(
        "reviewed default/all-feature normal dependency graphs match their exact all-target safety boundaries"
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
        "crates/rustleaks-compcol/src/lib.rs",
        "crates/rustleaks-compat/src/lib.rs",
        "crates/rustleaks-compat/src/bin/rustleaks-perf.rs",
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
        Duration::from_secs(1_200),
        label,
    )
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
    run_quality_command(
        &root,
        &target,
        &["test", "--workspace", "--locked", "--offline"],
        "default-feature workspace tests",
    )?;
    run_quality_command(
        &root,
        &target,
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
        Duration::from_secs(1_200),
        "warning-denied rustdoc",
    )?;
    run_quality_command(
        &root,
        &target,
        &[
            "+1.85.0",
            "check",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--offline",
        ],
        "Rust 1.85 MSRV check",
    )?;
    for cross_target in [
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        command_status_with_timeout(
            Command::new("cargo")
                .current_dir(&root)
                .env("CARGO_TARGET_DIR", &target.path)
                .env("RUSTFLAGS", "-D warnings")
                .args([
                    "+1.98.0",
                    "check",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--offline",
                    "--target",
                    cross_target,
                ]),
            Duration::from_secs(1_200),
            &format!("warning-denied compile-only {cross_target} check"),
        )?;
    }
    println!(
        "local quality, MSRV, and compile-only Linux/Windows target checks passed; native runtime remains follow-up"
    );
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
            Duration::from_secs(1_200),
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
        Duration::from_secs(240),
        "panic=abort archive policy",
    )?;
    println!("panic=abort archive policy rejected 7z as unsupported before dependency entry");
    Ok(())
}

fn validate_perf_record<'a>(
    record: &'a serde_json::Value,
    index: usize,
    expected_rust_revision: &str,
) -> Result<&'a str, String> {
    if record["schema_version"] != 1 || record["iterations"] != 1 {
        return Err(format!(
            "performance row {index} has an unsupported schema or iteration count"
        ));
    }
    let workload = record["workload"]
        .as_str()
        .ok_or_else(|| format!("performance row {index} omits workload"))?;
    let expected = PERF_INVARIANTS
        .iter()
        .find(|candidate| candidate.workload == workload)
        .ok_or_else(|| format!("unknown performance workload `{workload}`"))?;
    let exact = record["logical_bytes"].as_u64() == Some(expected.logical_bytes)
        && record["result_count"].as_u64() == Some(expected.result_count)
        && record["output_bytes"].as_u64() == Some(expected.output_bytes)
        && record["outcome_fnv1a64"].as_str() == Some(expected.outcome_fnv1a64);
    if !exact {
        return Err(format!(
            "performance workload `{workload}` differs from its exact outcome invariant"
        ));
    }
    let elapsed = record["elapsed_ns"]
        .as_u64()
        .ok_or_else(|| format!("performance workload `{workload}` has invalid elapsed_ns"))?;
    if record["ns_per_iteration"].as_u64() != Some(elapsed)
        || record["invariant"].as_str().is_none_or(str::is_empty)
    {
        return Err(format!(
            "performance workload `{workload}` omits its checked timing or invariant"
        ));
    }
    let provenance = &record["provenance"];
    if provenance["upstream_revision"].as_str() != Some(REVISION)
        || provenance["default_config_sha256"].as_str() != Some(CONFIG_SHA256)
        || provenance["package_version"].as_str() != Some(RELEASE_VERSION)
        || provenance["rust_revision"].as_str() != Some(expected_rust_revision)
        || provenance["rustc"].as_str().is_none_or(str::is_empty)
        || provenance["target_os"].as_str().is_none_or(str::is_empty)
        || provenance["target_arch"].as_str().is_none_or(str::is_empty)
        || provenance["executable_bytes"]
            .as_u64()
            .is_none_or(|bytes| bytes == 0)
        || !provenance["executable_fnv1a64"]
            .as_str()
            .is_some_and(|hash| {
                hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(format!(
            "performance workload `{workload}` has mismatched provenance"
        ));
    }
    Ok(workload)
}

fn validate_perf_records(output: &str, expected_rust_revision: &str) -> Result<(), String> {
    let expected = PERF_WORKLOADS
        .iter()
        .map(|workload| (*workload).to_owned())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for (index, line) in output.lines().enumerate() {
        let record: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("invalid performance JSON row {}: {error}", index + 1))?;
        let workload = validate_perf_record(&record, index + 1, expected_rust_revision)?;
        if !actual.insert(workload.to_owned()) {
            return Err(format!("duplicate performance workload `{workload}`"));
        }
    }
    if actual != expected {
        return Err(format!(
            "performance workload set mismatch: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn current_revision(root: &Path) -> Result<String, String> {
    command_output(
        Command::new("git")
            .current_dir(root)
            .args(["rev-parse", "HEAD"]),
    )
}

fn run_perf_matrix() -> Result<String, String> {
    command_output(
        Command::new("cargo")
            .args([
                "run",
                "-p",
                "rustleaks-compat",
                "--bin",
                "rustleaks-perf",
                "--release",
                "--offline",
                "--",
                "--workload",
                "all",
                "--iterations",
                "1",
            ])
            .current_dir(workspace_root()?),
    )
}

fn perf_run() -> Result<(), String> {
    let output = run_perf_matrix()?;
    println!("{output}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn perf_binary(root: &Path) -> Result<PathBuf, String> {
    command_output(Command::new("cargo").current_dir(root).args([
        "build",
        "-p",
        "rustleaks-compat",
        "--bin",
        "rustleaks-perf",
        "--release",
        "--locked",
        "--offline",
    ]))?;
    let metadata = command_output(Command::new("cargo").current_dir(root).args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--offline",
    ]))?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)
        .map_err(|error| format!("cannot decode cargo metadata: {error}"))?;
    let target = metadata["target_directory"]
        .as_str()
        .ok_or("cargo metadata omits target_directory")?;
    Ok(Path::new(target)
        .join("release")
        .join(format!("rustleaks-perf{}", std::env::consts::EXE_SUFFIX)))
}

#[cfg(target_os = "macos")]
fn run_perf_sample(binary: &Path, workload: &str) -> Result<String, String> {
    command_output(Command::new(binary).args(["--workload", workload, "--iterations", "1"]))
}

#[cfg(target_os = "macos")]
fn calibrated_m1_max_host() -> Result<bool, String> {
    let output =
        command_output(Command::new("system_profiler").args(["SPHardwareDataType", "-json"]))?;
    let profile: serde_json::Value = serde_json::from_str(&output)
        .map_err(|error| format!("cannot decode macOS hardware profile: {error}"))?;
    let hardware = profile["SPHardwareDataType"]
        .as_array()
        .and_then(|rows| rows.first())
        .ok_or("macOS hardware profile omits its overview")?;
    Ok(hardware["machine_model"] == "MacBookPro18,2"
        && hardware["chip_type"] == "Apple M1 Max"
        && hardware["physical_memory"] == "32 GB"
        && hardware["number_processors"] == "proc 10:8:2:0")
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)] // Keep the platform implementations type-identical.
fn calibrated_m1_max_host() -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn run_perf_sample_with_rss(binary: &Path, workload: &str) -> Result<(String, u64), String> {
    const SCRIPT: &str = r#"import resource, subprocess, sys
p = subprocess.run(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sys.stderr.buffer.write(p.stderr)
sys.stdout.buffer.write(p.stdout)
print("__RUSTLEAKSS_BYTES__=" + str(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss))
raise SystemExit(p.returncode)
"#;
    let display = format!("Python RSS collector for {workload}");
    let output = Command::new("python3")
        .arg("-c")
        .arg(SCRIPT)
        .arg(binary)
        .args(["--workload", workload, "--iterations", "1"])
        .output()
        .map_err(|error| format!("failed to run {display}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{display} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|error| format!("{display} returned non-UTF-8 output: {error}"))?;
    let (record, rss) = output
        .trim_end()
        .rsplit_once('\n')
        .ok_or_else(|| format!("{display} omitted its RSS record"))?;
    let rss = rss
        .strip_prefix("__RUSTLEAKSS_BYTES__=")
        .ok_or_else(|| format!("{display} returned an invalid RSS record"))?
        .parse::<u64>()
        .map_err(|error| format!("{display} returned invalid RSS bytes: {error}"))?;
    Ok((record.to_owned(), rss))
}

#[cfg(any(target_os = "macos", test))]
fn validate_perf_budget(
    budget: PerfBudget,
    elapsed: &mut [u64],
    peak_rss: u64,
) -> Result<(u64, u64), String> {
    if elapsed.len() != 7 {
        return Err(format!(
            "{} performance budget requires seven fresh elapsed samples",
            budget.workload
        ));
    }
    elapsed.sort_unstable();
    let median = elapsed[3];
    if median > budget.median_elapsed_ns {
        return Err(format!(
            "{} median elapsed {median} ns exceeds {} ns",
            budget.workload, budget.median_elapsed_ns
        ));
    }
    if peak_rss > budget.peak_rss_bytes {
        return Err(format!(
            "{} peak RSS {peak_rss} bytes exceeds {} bytes",
            budget.workload, budget.peak_rss_bytes
        ));
    }
    Ok((median, peak_rss))
}

#[cfg(target_os = "macos")]
fn perf_budget_check(root: &Path, expected_revision: &str) -> Result<(), String> {
    let binary = perf_binary(root)?;
    for budget in M1_MAX_PERF_BUDGETS {
        let warmup = run_perf_sample(&binary, budget.workload)?;
        let warmup: serde_json::Value = serde_json::from_str(&warmup)
            .map_err(|error| format!("invalid performance warmup JSON: {error}"))?;
        validate_perf_record(&warmup, 1, expected_revision)?;

        let mut elapsed = Vec::with_capacity(7);
        let mut peak_rss = 0_u64;
        for sample in 0..7 {
            let (record, rss) = if sample < 3 {
                let (record, rss) = run_perf_sample_with_rss(&binary, budget.workload)?;
                (record, Some(rss))
            } else {
                (run_perf_sample(&binary, budget.workload)?, None)
            };
            let record: serde_json::Value = serde_json::from_str(&record)
                .map_err(|error| format!("invalid performance sample JSON: {error}"))?;
            validate_perf_record(&record, sample + 1, expected_revision)?;
            elapsed.push(
                record["ns_per_iteration"]
                    .as_u64()
                    .expect("validated timing"),
            );
            if let Some(rss) = rss {
                peak_rss = peak_rss.max(rss);
            }
        }
        let (median, rss) = validate_perf_budget(*budget, &mut elapsed, peak_rss)?;
        println!(
            "{}: median {median} ns, peak RSS {rss} bytes",
            budget.workload
        );
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)] // Keep the platform implementations type-identical.
fn perf_budget_check(_root: &Path, _expected_revision: &str) -> Result<(), String> {
    Ok(())
}

fn perf_check() -> Result<(), String> {
    let root = workspace_root()?;
    let revision = current_revision(&root)?;
    let output = run_perf_matrix()?;
    validate_perf_records(&output, &revision)?;
    println!(
        "all {} performance workloads satisfy exact outcome and provenance invariants",
        PERF_WORKLOADS.len()
    );
    if calibrated_m1_max_host()? {
        perf_budget_check(&root, &revision)?;
        println!("calibrated Apple M1 Max elapsed and RSS budgets passed");
    } else {
        println!("elapsed and RSS budgets skipped on this uncalibrated host class");
    }
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

fn copy_seed_files(source: &Path, destination: &Path) -> Result<(), String> {
    std::fs::create_dir(destination).map_err(|error| {
        format!(
            "cannot create fuzz corpus {}: {error}",
            destination.display()
        )
    })?;
    for entry in std::fs::read_dir(source)
        .map_err(|error| format!("cannot read fuzz seeds {}: {error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot read fuzz seed entry: {error}"))?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "cannot inspect fuzz seed {}: {error}",
                entry.path().display()
            )
        })?;
        if !file_type.is_file() {
            return Err(format!(
                "fuzz seed directory contains a non-file entry: {}",
                entry.path().display()
            ));
        }
        std::fs::copy(entry.path(), destination.join(entry.file_name())).map_err(|error| {
            format!("cannot copy fuzz seed {}: {error}", entry.path().display())
        })?;
    }
    Ok(())
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

#[allow(clippy::too_many_lines)] // The explicit eight-target matrix is easier to audit in one gate.
fn fuzz_smoke() -> Result<(), String> {
    fuzz_build()?;
    let root = workspace_root()?;
    let toolchain = format!("+{FUZZ_TOOLCHAIN}");
    let smoke = ScopedTempDir::new("fuzz-smoke")?;
    let runs = fuzz_campaign_bound("RUSTLEAKS_FUZZ_RUNS", 16, 1_000_000)?;
    let max_total_time = fuzz_campaign_bound("RUSTLEAKS_FUZZ_MAX_TOTAL_TIME", 20, 600)?;
    let campaign_timeout = Duration::from_secs(max_total_time.saturating_add(120));
    let targets = [
        (
            "crates/rustleaks-core/fuzz",
            "go_regex",
            "corpus/go_regex",
            4096_u32,
            "dictionaries/go_regex.dict",
        ),
        (
            "crates/rustleaks-core/fuzz",
            "config",
            "seeds/config",
            8192,
            "dictionaries/config.dict",
        ),
        (
            "crates/rustleaks-core/fuzz",
            "fragment_scan",
            "seeds/fragment_scan",
            8192,
            "dictionaries/fragment_scan.dict",
        ),
        (
            "crates/rustleaks-core/fuzz",
            "session",
            "seeds/session",
            16_384,
            "dictionaries/session.dict",
        ),
        (
            "crates/rustleaks-sources/fuzz",
            "archive",
            "seeds/archive",
            8192,
            "dictionaries/archive.dict",
        ),
        (
            "crates/rustleaks-sources/fuzz",
            "reader_schedule",
            "seeds/reader_schedule",
            4096,
            "dictionaries/reader_schedule.dict",
        ),
        (
            "crates/rustleaks-sources/fuzz",
            "git_patch",
            "seeds/git_patch",
            16_384,
            "dictionaries/git_patch.dict",
        ),
        (
            "crates/rustleaks-report/fuzz",
            "template",
            "seeds/template",
            8192,
            "dictionaries/template.dict",
        ),
    ];
    for (fuzz_dir, target, seeds, max_len, dictionary) in targets {
        let target_root = smoke.path.join(target);
        let corpus = target_root.join("corpus");
        let artifacts = target_root.join("artifacts");
        std::fs::create_dir_all(&artifacts)
            .map_err(|error| format!("cannot create fuzz artifact directory: {error}"))?;
        if target == "go_regex" {
            tooling::generate_regex_fuzz_seeds(
                &root.join("compat/regex-corpus/requests-v1.jsonl"),
                &corpus,
            )?;
        } else {
            copy_seed_files(&root.join(fuzz_dir).join(seeds), &corpus)?;
        }
        let artifact_prefix = format!("{}/", artifacts.display());
        let dictionary = root.join(fuzz_dir).join(dictionary);
        let runs = format!("-runs={runs}");
        let max_total_time = format!("-max_total_time={max_total_time}");
        command_status_with_timeout(
            Command::new("cargo")
                .current_dir(&root)
                .args([
                    toolchain.as_str(),
                    "fuzz",
                    "run",
                    "--fuzz-dir",
                    fuzz_dir,
                    "--no-trace-compares",
                    target,
                ])
                .arg(&corpus)
                .arg("--")
                .args([
                    runs.as_str(),
                    max_total_time.as_str(),
                    "-timeout=5",
                    "-rss_limit_mb=2048",
                ])
                .arg(format!("-max_len={max_len}"))
                .arg(format!("-dict={}", dictionary.display()))
                .arg(format!("-artifact_prefix={artifact_prefix}")),
            campaign_timeout,
            target,
        )?;
    }
    println!("all eight bounded fuzz targets compiled and replayed seed campaigns");
    Ok(())
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

fn manifest_check() -> Result<(), String> {
    let root = workspace_root()?;
    package_attribution_check(&root)?;
    tooling::check_inventory(&root, &root.join("compat/test-manifest.toml"))?;
    assertion_check()?;
    generator_check()?;
    api_check()?;
    println!("manifest exact mechanical identities and dispositions are consistent");
    Ok(())
}

fn generator_check() -> Result<(), String> {
    let root = workspace_root()?;
    tooling::check_generator_samples(&oracle_root()?, &root.join("compat/generator-corpus"))?;
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--test",
                "default_rule_corpus",
                "--offline",
            ])
            .current_dir(&root),
    )?;
    println!("generator sample identities and all 6,770 Rust default-rule outcomes are consistent");
    Ok(())
}

fn api_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    command_output(
        Command::new("go")
            .args(["run", "compat/inventory_api.go", "-mode", "self-test"])
            .env("GOCACHE", env::temp_dir().join("rustleaks-api-gocache"))
            .current_dir(&root),
    )?;
    let actual_hash = sha256_file(&root.join("compat/api-inventory-v1.json"))?;
    if actual_hash != API_INVENTORY_SHA256 {
        return Err(format!(
            "API inventory hash mismatch: expected {API_INVENTORY_SHA256}, got {actual_hash}"
        ));
    }
    tooling::check_api_dispositions(&root, &root.join("compat/api-dispositions-v1.jsonl"))?;
    println!("API inventory contains the exact pinned 607-identity surface");
    Ok(())
}

fn assertion_check() -> Result<(), String> {
    let root = workspace_root()?;
    let upstream = oracle_root()?;
    tooling::check_assertions(&root, &upstream, &root.join("compat/assertion-corpus"))?;
    let assertions = std::fs::read_to_string(root.join("compat/assertion-corpus/assertions.jsonl"))
        .map_err(|error| format!("cannot read semantic assertions: {error}"))?;
    let benchmarks =
        std::fs::read_to_string(root.join("compat/assertion-corpus/benchmark-links.jsonl"))
            .map_err(|error| format!("cannot read benchmark assertion links: {error}"))?;
    let platform_skips =
        std::fs::read_to_string(root.join("compat/assertion-corpus/platform-skips.jsonl"))
            .map_err(|error| format!("cannot read platform branches: {error}"))?;
    tooling::validate_final_traceability(&assertions, &benchmarks, &platform_skips)?;
    println!(
        "semantic assertions, benchmark links, and platform branches have final Rust evidence"
    );
    Ok(())
}

fn fixture_check() -> Result<(), String> {
    verify_upstream()?;
    tooling::verify_fixtures(&workspace_root()?, &oracle_root()?)?;
    println!("independent fixture copy matches the pinned upstream testdata");
    Ok(())
}

fn oracle_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    let corpus = root.join("compat/oracle-corpus");
    for required in [
        "README.md",
        "bootstrap-input.jsonl",
        "bootstrap-golden.jsonl",
    ] {
        let path = corpus.join(required);
        if !path.is_file() {
            return Err(format!(
                "missing oracle corpus artifact: {}",
                path.display()
            ));
        }
    }
    let oracle_dir = root.join("crates/rustleaks-compat/oracle");
    command_output(
        Command::new("go")
            .args(["test", "./..."])
            .current_dir(&oracle_dir),
    )?;
    command_output(
        Command::new("go")
            .args(["run", ".", "-input"])
            .arg(corpus.join("bootstrap-input.jsonl"))
            .arg("-check")
            .arg(corpus.join("bootstrap-golden.jsonl"))
            .current_dir(oracle_dir),
    )?;
    tooling::check_config_corpus(&root)?;
    tooling::replay_corpus(&root, tooling::Corpus::Regex)?;
    tooling::replay_corpus(&root, tooling::Corpus::Detect)?;
    tooling::generate_go_lowercase(&root, true)?;
    tooling::replay_corpus(&root, tooling::Corpus::Allowlist)?;
    tooling::replay_corpus(&root, tooling::Corpus::Decoder)?;
    tooling::check_composite_corpus(&root)?;
    tooling::check_session_corpus(&root)?;
    tooling::check_source_corpus(&root)?;
    tooling::check_git_corpus(&root)?;
    println!("oracle corpus matches fresh Go outcomes");
    Ok(())
}

fn config_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_config_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--test", "config"])
            .current_dir(&root),
    )?;
    println!("configuration corpus and Rust outcomes are consistent");
    Ok(())
}

fn regex_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::replay_corpus(&root, tooling::Corpus::Regex)?;
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--lib",
                "regex::tests::canonical_go_regex_corpus_matches_all_manifest_outcomes",
            ])
            .current_dir(&root),
    )?;
    println!("GoRegex corpus and all Rust match/capture/span outcomes are consistent");
    Ok(())
}

fn detect_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::replay_corpus(&root, tooling::Corpus::Detect)?;
    tooling::generate_go_lowercase(&root, true)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--test", "detect_corpus"])
            .current_dir(&root),
    )?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--lib", "engine::tests::"])
            .current_dir(&root),
    )?;
    println!("raw detector corpus and all Rust finding outcomes are consistent");
    Ok(())
}

fn allowlist_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::replay_corpus(&root, tooling::Corpus::Allowlist)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--test", "allowlist"])
            .current_dir(&root),
    )?;
    println!("allowlist corpus and all validated Rust outcomes are consistent");
    Ok(())
}

fn decoder_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::replay_corpus(&root, tooling::Corpus::Decoder)?;
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--lib",
                "decoder::tests::canonical_decoder_pass_corpus_matches_go",
            ])
            .current_dir(&root),
    )?;
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--test",
                "detect_corpus",
                "frozen_decoder_detector_corpus_matches_go",
            ])
            .current_dir(&root),
    )?;
    println!("decoder/pass corpus and complete decoded finding outcomes are consistent");
    Ok(())
}

fn composite_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_composite_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--test", "composite_corpus"])
            .current_dir(&root),
    )?;
    let test_executable = composite_test_executable(&root)?;
    for test in [
        "resource_primary_aux_duplicate_cartesian_is_bounded",
        "resource_many_generics_is_bounded",
        "resource_empty_full_long_malformed_is_bounded",
        "resource_deep_required_graph_is_bounded",
    ] {
        run_resource_test(&test_executable, test, &root, Duration::from_secs(30))?;
    }
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--lib",
                "engine::tests::private_filter_replays_the_frozen_oracle_adapter",
            ])
            .current_dir(&root),
    )?;
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--lib",
                "model::redaction_tests::private_mask_helper_replays_every_frozen_oracle_row",
            ])
            .current_dir(&root),
    )?;
    println!("composite, suppression, and redaction corpus outcomes are consistent");
    Ok(())
}

fn session_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_session_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--test", "session_corpus"])
            .current_dir(&root),
    )?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-core", "--lib", "session::tests::"])
            .current_dir(&root),
    )?;
    println!("scan-session corpus and portable Rust filtering outcomes are consistent");
    Ok(())
}

fn source_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_inventory(&root, &root.join("compat/test-manifest.toml"))?;
    tooling::check_source_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-sources", "--all-features"])
            .current_dir(&root),
    )?;
    println!("reader, filesystem, and archive source outcomes are consistent");
    Ok(())
}

fn git_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_inventory(&root, &root.join("compat/test-manifest.toml"))?;
    validate_git_adversarial_matrix(&root)?;
    tooling::check_git_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-sources",
                "--all-features",
                "--lib",
                "--test",
                "git_corpus",
                "--test",
                "git_sources",
                "--test",
                "git_scm",
            ])
            .current_dir(&root),
    )?;
    println!("Git source, detector findings, and SCM outcomes are consistent");
    Ok(())
}

fn report_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_inventory(&root, &root.join("compat/test-manifest.toml"))?;
    tooling::check_report_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-report", "--offline"])
            .current_dir(&root),
    )?;
    println!("built-in and safe-template report outcomes are consistent");
    Ok(())
}

fn cli_check() -> Result<(), String> {
    verify_upstream()?;
    let root = workspace_root()?;
    tooling::check_cli_corpus(&root)?;
    command_output(
        Command::new("cargo")
            .args(["test", "-p", "rustleaks-cli", "--all-features", "--offline"])
            .current_dir(&root),
    )?;
    println!("portable command-line outcomes are consistent");
    Ok(())
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

fn bootstrap_parity() -> Result<(), String> {
    verify_upstream()?;
    manifest_check()?;
    fixture_check()?;
    println!("bootstrap parity scope passed");
    Ok(())
}

fn config_parity() -> Result<(), String> {
    bootstrap_parity()?;
    config_check()?;
    println!("configuration parity scope passed");
    Ok(())
}

fn regex_parity() -> Result<(), String> {
    config_parity()?;
    regex_check()?;
    println!("GoRegex feasibility parity scope passed");
    Ok(())
}

fn detect_parity() -> Result<(), String> {
    regex_parity()?;
    detect_check()?;
    println!("raw detector parity scope passed");
    Ok(())
}

fn allowlist_parity() -> Result<(), String> {
    detect_parity()?;
    allowlist_check()?;
    println!("allowlist parity scope passed");
    Ok(())
}

fn decoder_parity() -> Result<(), String> {
    allowlist_parity()?;
    decoder_check()?;
    println!("decoder and original-offset parity scope passed");
    Ok(())
}

fn composite_parity() -> Result<(), String> {
    decoder_parity()?;
    composite_check()?;
    println!("required/composite and final-filtering parity scope passed");
    Ok(())
}

fn session_parity() -> Result<(), String> {
    composite_parity()?;
    session_check()?;
    println!("scan-session, baseline, ignore, and collection parity scope passed");
    Ok(())
}

fn source_parity() -> Result<(), String> {
    session_parity()?;
    source_check()?;
    println!("portable filesystem and archive source parity scope passed");
    Ok(())
}

fn git_parity() -> Result<(), String> {
    source_parity()?;
    git_check()?;
    println!("portable Git repository source parity scope passed");
    Ok(())
}

fn report_parity() -> Result<(), String> {
    git_parity()?;
    report_check()?;
    println!("reusable report writer parity scope passed");
    Ok(())
}

fn cli_parity() -> Result<(), String> {
    report_parity()?;
    cli_check()?;
    println!("portable command-line parity scope passed");
    Ok(())
}

fn full_parity() -> Result<(), String> {
    clean_worktree_check()?;
    docs_check()?;
    quality_check()?;
    owned_safety_check()?;
    dependency_safety_check()?;
    miri_check()?;
    cli_parity()?;
    public_api_check()?;
    package_check()?;
    supply_chain_check()?;
    panic_abort_check()?;
    fuzz_check()?;
    perf_check()?;
    clean_worktree_check()?;
    println!("complete compatibility and local release hardening passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        CONFIG_SHA256, PERF_INVARIANTS, PerfBudget, RELEASE_VERSION, REVISION, build_system,
        composite_test_executable_from_messages, normalize_workspace_dependency_tree,
        parse_civil_day, resource_test_command, run_resource_test,
        validate_core_repository_metadata, validate_perf_budget, validate_perf_records,
        validate_publish_policy, validate_regex_backend_metadata, validate_supply_chain_exceptions,
        workspace_root,
    };
    use crate::tooling::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};

    const TIMEOUT_PROBE_TEST: &str = "tests::resource_launcher_timeout_probe_child";
    const RESOURCE_SELECTOR: &str = "RUSTLEAKS_BOUNDED_RESOURCE_TEST";

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
    fn dependency_graph_digest_ignores_only_the_workspace_checkout_path() {
        let first = "rustleaks-core v0.1.0 (/tmp/first/crates/rustleaks-core)\n\
rustleaks-core v0.1.0 (/tmp/first/crates/rustleaks-core) (*)\n\
serde_derive v1.0.0 (proc-macro)\n\
outside v1.0.0 (/opt/external/outside)";
        let second = "rustleaks-core v0.1.0 (/tmp/second/crates/rustleaks-core)\n\
rustleaks-core v0.1.0 (/tmp/second/crates/rustleaks-core) (*)\n\
serde_derive v1.0.0 (proc-macro)\n\
outside v1.0.0 (/opt/external/outside)";
        assert_eq!(
            normalize_workspace_dependency_tree(Path::new("/tmp/first"), first),
            normalize_workspace_dependency_tree(Path::new("/tmp/second"), second)
        );
        assert!(
            normalize_workspace_dependency_tree(Path::new("/tmp/first"), first)
                .contains("outside v1.0.0 (/opt/external/outside)")
        );
    }

    #[test]
    fn performance_record_gate_requires_the_exact_matrix_and_provenance() {
        let output = PERF_INVARIANTS
            .iter()
            .map(|expected| {
                serde_json::json!({
                    "schema_version": 1,
                    "workload": expected.workload,
                    "iterations": 1,
                    "elapsed_ns": 1,
                    "ns_per_iteration": 1,
                    "logical_bytes": expected.logical_bytes,
                    "result_count": expected.result_count,
                    "output_bytes": expected.output_bytes,
                    "outcome_fnv1a64": expected.outcome_fnv1a64,
                    "invariant": "exact",
                    "provenance": {
                        "upstream_revision": REVISION,
                        "default_config_sha256": CONFIG_SHA256,
                        "package_version": RELEASE_VERSION,
                        "rust_revision": "rust-head",
                        "rustc": "rustc test",
                        "target_os": "test",
                        "target_arch": "test",
                        "executable_bytes": 1,
                        "executable_fnv1a64": "0123456789abcdef"
                    }
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        validate_perf_records(&output, "rust-head").unwrap();
        assert!(
            validate_perf_records(&output.replacen(REVISION, "wrong", 1), "rust-head").is_err()
        );
        assert!(
            validate_perf_records(
                &output.replacen("\"result_count\":222", "\"result_count\":221", 1),
                "rust-head"
            )
            .is_err()
        );
        assert!(validate_perf_records(&output, "stale-head").is_err());
        assert!(
            validate_perf_records(
                output
                    .lines()
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join("\n")
                    .as_str(),
                "rust-head"
            )
            .is_err()
        );
    }

    #[test]
    fn performance_budgets_reject_elapsed_and_rss_regressions() {
        let budget = PerfBudget {
            workload: "probe",
            median_elapsed_ns: 10,
            peak_rss_bytes: 20,
        };
        let mut passing = vec![7, 8, 9, 10, 11, 12, 13];
        assert_eq!(validate_perf_budget(budget, &mut passing, 20), Ok((10, 20)));
        let mut slow = vec![11; 7];
        assert!(validate_perf_budget(budget, &mut slow, 20).is_err());
        let mut memory = vec![10; 7];
        assert!(validate_perf_budget(budget, &mut memory, 21).is_err());
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
            Duration::from_secs(2),
        );
        assert!(
            result
                .unwrap_err()
                .contains("exceeded its external 2 second deadline")
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
            "packages": [{"name": "rustleaks-core", "repository": null}]
        }"#;
        assert!(validate_core_repository_metadata(independent).is_ok());
    }

    #[test]
    fn resolved_metadata_requires_the_exact_unicode_15_backend() {
        let exact = r#"{
            "packages": [
                {"name":"rustleaks-core","dependencies":[
                    {"name":"regex-automata","req":"=0.4.7"},
                    {"name":"regex-syntax","req":"=0.8.4"}
                ]},
                {"name":"regex-automata","version":"0.4.7"},
                {"name":"regex-syntax","version":"0.8.4"}
            ]
        }"#;
        assert!(validate_regex_backend_metadata(exact).is_ok());

        let mut current = exact.replace("=0.4.7", "^0.4.7");
        assert!(validate_regex_backend_metadata(&current).is_err());
        current = exact.replace("0.8.4", "0.8.11");
        assert!(validate_regex_backend_metadata(&current).is_err());
        current = exact.replace(
            r#"{"name":"regex-syntax","req":"=0.8.4"}"#,
            r#"{"name":"regex-syntax","req":"=0.8.4"},{"name":"regex","req":"^1"}"#,
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
