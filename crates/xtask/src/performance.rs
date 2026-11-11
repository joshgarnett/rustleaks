//! Bazel performance orchestration and checked build provenance.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::tooling::{command_output, sha256_file};
use crate::{CONFIG_SHA256, RELEASE_VERSION, REVISION, workspace_root};

#[path = "performance_representative.rs"]
mod representative_suite;

pub(crate) use representative_suite::{QualityTestTools, run as representative};

#[path = "performance_investigation.rs"]
mod investigation;
pub(crate) use investigation::{calibrate, profile};

#[path = "performance_reporting.rs"]
mod reporting;
pub(crate) use reporting::run as report;

const TARGET: &str = "//crates/rustleaks-compat:rustleaks_perf";
const BUILD_FLAGS: &[&str] = &["--compilation_mode=opt", "--stamp=no"];
const MEASUREMENT_SCOPE: &str = "legacy-v1-includes-verification";
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

const PERF_WORKLOADS: &[&str] = &[
    "default-compile",
    "default-no-keyword-1-kib",
    "default-no-keyword-16-kib",
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
        workload: "default-no-keyword-1-kib",
        logical_bytes: 1_024,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
    },
    PerfInvariant {
        workload: "default-no-keyword-16-kib",
        logical_bytes: 16 * 1_024,
        result_count: 0,
        output_bytes: 0,
        outcome_fnv1a64: "a8c7f832281a39c5",
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
// Reports may validate retained Mac budgets on any supported host.
struct PerfBudget {
    workload: &'static str,
    median_elapsed_ns: u64,
    peak_rss_bytes: u64,
}

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

#[derive(Clone, Debug)]
struct Request {
    workloads: Vec<String>,
    iterations: u64,
    warmup: u64,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut workload = "all";
        let mut iterations = 1;
        let mut warmup = 0;
        let mut arguments = arguments.iter();
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| format!("{argument} requires a value"))?;
            match argument.as_str() {
                "--workload" => workload = value,
                "--iterations" => iterations = parse_count(value, 1, "iterations")?,
                "--warmup" => warmup = parse_count(value, 0, "warmup")?,
                _ => return Err(format!("unknown performance argument {argument}")),
            }
        }
        let workloads = if workload == "all" {
            PERF_WORKLOADS
                .iter()
                .map(|value| (*value).to_owned())
                .collect()
        } else if PERF_WORKLOADS.contains(&workload) {
            vec![workload.to_owned()]
        } else {
            return Err(format!("unknown performance workload {workload}"));
        };
        Ok(Self {
            workloads,
            iterations,
            warmup,
        })
    }

    fn arguments(&self, workload: &str) -> Vec<String> {
        vec![
            "--workload".into(),
            workload.into(),
            "--iterations".into(),
            self.iterations.to_string(),
            "--warmup".into(),
            self.warmup.to_string(),
        ]
    }
}

fn parse_count(value: &str, minimum: u64, name: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("invalid {name}"))?;
    if !(minimum..=10).contains(&value) {
        return Err(format!("{name} must be in {minimum}..=10"));
    }
    Ok(value)
}

struct Prepared {
    root: PathBuf,
    binary: PathBuf,
    source: Value,
    build: Value,
    host: Value,
    executable_bytes: u64,
    executable_fnv1a64: String,
}

pub(crate) fn run(arguments: &[String]) -> Result<(), String> {
    let request = Request::parse(arguments)?;
    let prepared = prepare(&workspace_root()?)?;
    let output = run_matrix(&prepared, &request)?;
    prepared.ensure_unchanged()?;
    println!("{output}");
    Ok(())
}

pub(crate) fn check() -> Result<(), String> {
    let request = Request::parse(&[])?;
    let mut prepared = prepare(&workspace_root()?)?;
    let output = run_matrix(&prepared, &request)?;
    validate_records(&output, &prepared, &request)?;
    println!(
        "all {} performance workloads satisfy exact outcome and Bazel build provenance invariants",
        PERF_WORKLOADS.len()
    );
    let calibrated_host = calibrated_m1_max_host()?;
    if calibrated_host {
        perf_budget_check(&prepared)?;
        println!(
            "unchanged inherited M1 Max elapsed and RSS limits passed on the Bazel build; timing scope is {MEASUREMENT_SCOPE}"
        );
    } else {
        println!("inherited M1 Max elapsed and RSS limits not evaluated on this host class");
    }
    prepared.build["timing_scope"] = json!("representative-v1-operation-only");
    representative_suite::fragment_budget_check(&prepared, calibrated_host)?;
    prepared.ensure_unchanged()?;
    println!(
        "performance evidence: executable_sha256={} input_sha256={} dirty={}",
        prepared.build["executable_sha256"],
        prepared.source["input_sha256"],
        prepared.source["dirty"]
    );
    Ok(())
}

fn bazel(root: &Path, operation: &str) -> Command {
    let mut command = Command::new("bazelisk");
    command.current_dir(root).arg(operation).args(BUILD_FLAGS);
    command
}

fn prepare(root: &Path) -> Result<Prepared, String> {
    prepare_with_flags(root, &[], MEASUREMENT_SCOPE)
}

#[allow(clippy::too_many_lines)] // Keep build and executable provenance bound in one preparation path.
fn prepare_with_flags(root: &Path, extra_flags: &[&str], scope: &str) -> Result<Prepared, String> {
    let selected_bazel = |operation: &str| {
        let mut command = bazel(root, operation);
        command.args(extra_flags);
        command
    };
    let source = source_snapshot(root)?;
    let default_config = fs::read(root.join("crates/rustleaks-core/default/gitleaks.toml"))
        .map_err(|error| format!("cannot read benchmark default configuration: {error}"))?;
    let default_config_sha256 = verify_default_config(&default_config)?;
    command_output(selected_bazel("build").arg(TARGET))?;
    let execution_root = PathBuf::from(command_output(
        Command::new("bazelisk")
            .current_dir(root)
            .args(["info", "execution_root"]),
    )?);
    let outputs = command_output(selected_bazel("cquery").args([TARGET, "--output=files"]))?;
    let binary = select_binary(&execution_root, &outputs)?;
    let graph = command_output(selected_bazel("aquery").args([
        &format!("mnemonic(\"Rustc\", deps({TARGET}))"),
        "--output=jsonproto",
    ]))?;
    let graph: Value = serde_json::from_str(&graph)
        .map_err(|error| format!("invalid Bazel action graph: {error}"))?;
    let mut build = action_identity(&graph)?;
    build["requested_flags"] = json!(
        BUILD_FLAGS
            .iter()
            .chain(extra_flags)
            .copied()
            .collect::<Vec<_>>()
    );
    build["timing_scope"] = json!(scope);
    if !extra_flags.is_empty() {
        investigation::validate_profile_build(&graph)?;
    }
    let compiler = build["compiler_path"]
        .as_str()
        .ok_or("action omits compiler path")?;
    let compiler_path = execution_root.join(compiler);
    let compiler_version = command_output(Command::new(&compiler_path).arg("-Vv"))?;
    if !compiler_version.starts_with("rustc ") || !compiler_version.contains("commit-hash:") {
        return Err("selected Bazel compiler did not identify its build".into());
    }
    build
        .as_object_mut()
        .expect("action identity is an object")
        .remove("compiler_path");
    build["compiler_version"] = json!(compiler_version);
    build["default_config_sha256"] = json!(default_config_sha256);
    build["compiler_sha256"] = json!(sha256_file(&compiler_path)?);
    build["argument_files"] = argument_file_identity(&graph, &execution_root)?;
    build["executable_sha256"] = json!(sha256_file(&binary)?);
    build["lockfiles"] = file_identity(
        root,
        &[
            "Cargo.lock",
            "cargo-bazel-lock.json",
            "MODULE.bazel.lock",
            "MODULE.bazel",
            "rust-toolchain.toml",
        ],
    )?;
    build["workload_definition_sha256"] = json!(hash_paths(
        root,
        &[
            "crates/rustleaks-compat/src/bin/rustleaks-perf.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/benchmark_data.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/representative.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/fragment_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/edge_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/normalization_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/worker_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/decode_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/report_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/default_rule_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/default_rule_realistic.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/default_rule_custom.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/default_rule_contention.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/default_rule_tests.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/representative_io.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/source_scale_workloads.rs".to_owned(),
            "crates/rustleaks-compat/src/perf/investigation.rs".to_owned(),
            "crates/rustleaks-sources/tests/perf_archives.rs".to_owned(),
            "crates/rustleaks-sources/fuzz/support/archive_seeds.rs".to_owned(),
            "crates/rustleaks-sources/fuzz/support/archive_scale.rs".to_owned(),
            "crates/rustleaks-sources/fuzz/support/archive_frame.rs".to_owned(),
            "crates/xtask/src/performance.rs".to_owned(),
            "crates/xtask/src/performance_reporting.rs".to_owned(),
            "crates/xtask/src/performance_reporting/import.rs".to_owned(),
            "crates/xtask/src/performance_reporting/existing.rs".to_owned(),
            "crates/xtask/src/performance_reporting/tests.rs".to_owned(),
            "crates/xtask/src/performance_representative.rs".to_owned(),
            "crates/xtask/src/performance_source_scale.rs".to_owned(),
            "crates/xtask/src/performance_investigation.rs".to_owned(),
            "crates/xtask/src/performance_investigation.txt".to_owned(),
            "crates/xtask/src/performance_investigation/window_matrix.rs".to_owned(),
            "crates/xtask/src/performance_investigation/window_tests.rs".to_owned(),
        ]
    )?);
    if fs::metadata(&binary)
        .map_err(|error| error.to_string())?
        .len()
        > 128 * 1024 * 1024
    {
        return Err("benchmark executable exceeds 128 MiB provenance limit".into());
    }
    let bytes =
        fs::read(&binary).map_err(|error| format!("cannot fingerprint benchmark: {error}"))?;
    let prepared = Prepared {
        root: root.to_owned(),
        binary,
        source,
        build,
        host: host_identity()?,
        executable_bytes: u64::try_from(bytes.len()).map_err(|error| error.to_string())?,
        executable_fnv1a64: format!("{:016x}", fnv1a64(&bytes)),
    };
    prepared.ensure_unchanged()?;
    Ok(prepared)
}

fn verify_default_config(bytes: &[u8]) -> Result<String, String> {
    let actual = sha256_bytes(bytes);
    if actual != CONFIG_SHA256 {
        return Err("benchmark default configuration differs from its pinned SHA-256".into());
    }
    Ok(actual)
}

fn select_binary(execution_root: &Path, outputs: &str) -> Result<PathBuf, String> {
    let name = format!("rustleaks_perf{}", std::env::consts::EXE_SUFFIX);
    let binaries = outputs
        .lines()
        .filter(|line| {
            Path::new(line)
                .file_name()
                .is_some_and(|file| file == name.as_str())
        })
        .collect::<Vec<_>>();
    match binaries.as_slice() {
        [binary] => Ok(execution_root.join(binary)),
        _ => Err("Bazel must identify exactly one performance executable".into()),
    }
}

fn string_arguments(action: &Value) -> Result<Vec<&str>, String> {
    action["arguments"]
        .as_array()
        .ok_or("Rust action omits arguments")?
        .iter()
        .map(|argument| {
            argument
                .as_str()
                .ok_or_else(|| "non-string Rust argument".into())
        })
        .collect()
}

fn compiler_arguments<'a>(arguments: &'a [&'a str]) -> Result<(&'a str, &'a [&'a str]), String> {
    let separator = arguments
        .iter()
        .position(|argument| *argument == "--")
        .ok_or("Rust action omits process-wrapper compiler separator")?;
    let compiler = arguments
        .get(separator + 1)
        .ok_or("Rust action omits compiler")?;
    if !Path::new(compiler)
        .file_name()
        .is_some_and(|name| name == "rustc" || name == "rustc.exe")
    {
        return Err("Rust action compiler is not rustc".into());
    }
    Ok((compiler, &arguments[separator + 2..]))
}

fn action_identity(graph: &Value) -> Result<Value, String> {
    action_identity_for(graph, TARGET, "rustleaks_perf", MEASUREMENT_SCOPE)
}

fn action_identity_for(
    graph: &Value,
    label: &str,
    crate_name: &str,
    timing_scope: &str,
) -> Result<Value, String> {
    let actions = graph["actions"]
        .as_array()
        .ok_or("Bazel graph omits actions")?;
    let mut selected = Vec::new();
    let mut identities = Vec::new();
    for action in actions {
        if action["mnemonic"] != "Rustc" {
            continue;
        }
        let arguments = string_arguments(action)?;
        let (compiler, rustc_arguments) = compiler_arguments(&arguments)?;
        let action_key = action["actionKey"]
            .as_str()
            .filter(|key| !key.is_empty())
            .ok_or("Rust action omits its action key")?;
        let identity = json!({
            "action_key": action_key,
            "compiler": compiler,
            "arguments": rustc_arguments,
            "environment": selected_environment(action),
            "execution_platform": action["executionPlatform"],
        });
        identities.push(identity.to_string());
        if rustc_arguments.contains(&format!("--crate-name={crate_name}").as_str()) {
            selected.push((
                compiler.to_owned(),
                rustc_arguments
                    .iter()
                    .map(|arg| (*arg).to_owned())
                    .collect::<Vec<_>>(),
                action_key.to_owned(),
            ));
        }
    }
    let [(compiler, arguments, action_key)] = selected.as_slice() else {
        return Err("Bazel graph must contain exactly one performance compile action".into());
    };
    if codegen_option(arguments, "opt-level") != Some("3") {
        return Err("performance compile action is not opt-level=3".into());
    }
    let target = arguments
        .iter()
        .find_map(|argument| argument.strip_prefix("--target="))
        .ok_or("performance compile action omits target triple")?;
    identities.sort();
    Ok(json!({
        "schema_version": 1,
        "system": "bazel",
        "label": label,
        "requested_flags": BUILD_FLAGS,
        "compiler_path": compiler,
        "compiler_options": selected_compiler_options(arguments),
        "rustc_arguments_sha256": sha256_bytes(arguments.join("\0").as_bytes()),
        "compile_action_key": action_key,
        "rust_action_count": identities.len(),
        "rust_action_graph_sha256": sha256_bytes(identities.join("\n").as_bytes()),
        "target": target,
        "timing_scope": timing_scope,
    }))
}

fn codegen_option<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    let mut selected = None;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let option = if argument == "-C" || argument == "--codegen" {
            arguments.next().map(String::as_str)
        } else {
            argument
                .strip_prefix("--codegen=")
                .or_else(|| argument.strip_prefix("-C"))
        };
        if let Some((key, value)) = option.and_then(|option| option.split_once('='))
            && key == name
        {
            selected = Some(value);
        }
    }
    selected
}

fn selected_environment(action: &Value) -> Value {
    let mut environment = serde_json::Map::new();
    for entry in action["environmentVariables"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(key) = entry["key"].as_str() else {
            continue;
        };
        if [
            "CARGO_CFG_TARGET_ARCH",
            "CARGO_CFG_TARGET_OS",
            "CARGO_CRATE_NAME",
            "CARGO_PKG_VERSION",
            "ZERO_AR_DATE",
        ]
        .contains(&key)
        {
            environment.insert(key.into(), entry["value"].clone());
        }
    }
    Value::Object(environment)
}

fn selected_compiler_options(arguments: &[String]) -> Vec<&str> {
    arguments
        .iter()
        .filter_map(|argument| {
            let option = argument
                .strip_prefix("--codegen=")
                .or_else(|| argument.strip_prefix("-C"));
            let selected = option.is_some_and(|option| {
                option.split_once('=').is_some_and(|(name, _)| {
                    [
                        "opt-level",
                        "debuginfo",
                        "strip",
                        "codegen-units",
                        "lto",
                        "panic",
                        "embed-bitcode",
                        "target-cpu",
                        "target-feature",
                        "force-frame-pointers",
                    ]
                    .contains(&name)
                })
            }) || argument.starts_with("--target=")
                || argument.starts_with("--edition=");
            selected.then_some(argument.as_str())
        })
        .collect()
}

fn argument_file_identity(graph: &Value, execution_root: &Path) -> Result<Value, String> {
    let mut files = BTreeSet::new();
    for action in graph["actions"]
        .as_array()
        .ok_or("Bazel graph omits actions")?
    {
        let arguments = string_arguments(action)?;
        for pair in arguments.windows(2) {
            if pair[0] == "--arg-file" {
                files.insert(pair[1]);
            }
        }
    }
    let mut identities = serde_json::Map::new();
    for file in files {
        identities.insert(
            sha256_bytes(file.as_bytes()),
            json!(sha256_file(&execution_root.join(file))?),
        );
    }
    Ok(Value::Object(identities))
}

fn file_identity(root: &Path, files: &[&str]) -> Result<Value, String> {
    let mut result = serde_json::Map::new();
    for file in files {
        result.insert((*file).into(), json!(sha256_file(&root.join(file))?));
    }
    Ok(Value::Object(result))
}

fn source_snapshot(root: &Path) -> Result<Value, String> {
    let revision = command_output(
        Command::new("git")
            .current_dir(root)
            .args(["rev-parse", "HEAD"]),
    )?;
    let status = command_output(Command::new("git").current_dir(root).args([
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ]))?;
    let files = command_output(Command::new("git").current_dir(root).args([
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    ]))?;
    let files = files
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    Ok(json!({
        "revision": revision,
        "dirty": !status.is_empty(),
        "status_sha256": sha256_bytes(status.as_bytes()),
        "input_sha256": hash_paths(root, &files.into_iter().collect::<Vec<_>>())?,
    }))
}

fn hash_paths(root: &Path, files: &[String]) -> Result<String, String> {
    let mut records = Vec::new();
    for name in files {
        let path = Path::new(name);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("benchmark source path escapes the repository".into());
        }
        let path = root.join(path);
        records.extend_from_slice(name.as_bytes());
        records.push(0);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = fs::read_link(&path).map_err(|error| error.to_string())?;
                records.extend_from_slice(b"symlink:");
                records.extend_from_slice(target.as_os_str().as_encoded_bytes());
            }
            Ok(metadata) if metadata.is_file() => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    records
                        .extend_from_slice(&(metadata.permissions().mode() & 0o111).to_le_bytes());
                }
                records.extend_from_slice(sha256_file(&path)?.as_bytes());
            }
            Ok(_) => return Err(format!("benchmark source is not a file: {name}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                records.extend_from_slice(b"deleted");
            }
            Err(error) => return Err(format!("cannot inspect benchmark input: {error}")),
        }
        records.push(b'\n');
    }
    Ok(sha256_bytes(&records))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |value, byte| {
        (value ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}

fn host_identity() -> Result<Value, String> {
    let mut identity = json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "available_parallelism": std::thread::available_parallelism().map_err(|error| error.to_string())?.get(),
    });
    #[cfg(target_os = "macos")]
    {
        identity["cpu"] = json!(command_output(
            Command::new("sysctl").args(["-n", "machdep.cpu.brand_string"])
        )?);
        identity["os_version"] = json!(command_output(
            Command::new("sw_vers").arg("-productVersion")
        )?);
    }
    #[cfg(target_os = "linux")]
    {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo")
            .map_err(|error| format!("cannot read CPU identity: {error}"))?;
        identity["cpu"] = json!(
            cpuinfo
                .lines()
                .find(|line| line.starts_with("model name") || line.starts_with("Hardware"))
                .unwrap_or("unavailable")
        );
        identity["os_version"] = json!(command_output(Command::new("uname").arg("-r"))?);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        identity["cpu"] =
            json!(std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unavailable".into()));
        identity["os_version"] = json!("unavailable");
    }
    Ok(identity)
}

impl Prepared {
    fn ensure_unchanged(&self) -> Result<(), String> {
        if source_snapshot(&self.root)? != self.source {
            return Err(
                "source tree changed during performance build or measurement; discard this run"
                    .into(),
            );
        }
        if json!(sha256_file(&self.binary)?) != self.build["executable_sha256"] {
            return Err(
                "performance executable changed during measurement; discard this run".into(),
            );
        }
        Ok(())
    }

    fn bind(&self, output: &str) -> Result<String, String> {
        let mut records = Vec::new();
        for line in output.lines() {
            let mut record: Value = serde_json::from_str(line)
                .map_err(|error| format!("invalid performance JSON: {error}"))?;
            if record["provenance"]["binding"] != "unbound-runner"
                || record["provenance"]["executable_bytes"] != self.executable_bytes
                || record["provenance"]["executable_fnv1a64"] != self.executable_fnv1a64
            {
                return Err("runner identity does not match the Bazel-built executable".into());
            }
            record["provenance"]["binding"] = json!("bazel-action-graph");
            record["provenance"]["build"] = self.build.clone();
            record["provenance"]["source"] = self.source.clone();
            record["provenance"]["host"] = self.host.clone();
            record["provenance"]["baseline_eligible"] = json!(self.source["dirty"] == false);
            records.push(record.to_string());
        }
        Ok(records.join("\n"))
    }
}

fn run_matrix(prepared: &Prepared, request: &Request) -> Result<String, String> {
    let workload = if request.workloads.len() == 1 {
        request.workloads[0].as_str()
    } else {
        "all"
    };
    let output = command_output(
        Command::new(&prepared.binary)
            .current_dir(&prepared.root)
            .args(request.arguments(workload)),
    )?;
    let output = prepared.bind(&output)?;
    validate_records(&output, prepared, request)?;
    Ok(output)
}

fn validate_record<'a>(
    record: &'a Value,
    prepared: &Prepared,
    request: &Request,
) -> Result<&'a str, String> {
    if record["schema_version"] != 2
        || record["iterations"] != request.iterations
        || record["warmup_iterations"] != request.warmup
        || record["measurement_scope"] != MEASUREMENT_SCOPE
    {
        return Err(
            "performance record has unsupported schema, iteration count, or timing scope".into(),
        );
    }
    let workload = record["workload"]
        .as_str()
        .ok_or("performance record omits workload")?;
    let expected = PERF_INVARIANTS
        .iter()
        .find(|candidate| candidate.workload == workload)
        .ok_or_else(|| format!("unknown performance workload {workload}"))?;
    let unit = if workload.starts_with("report-") {
        "findings"
    } else {
        "input-bytes"
    };
    if record["logical_bytes"].as_u64() != Some(expected.logical_bytes)
        || record["result_count"].as_u64() != Some(expected.result_count)
        || record["output_bytes"].as_u64() != Some(expected.output_bytes)
        || record["outcome_fnv1a64"].as_str() != Some(expected.outcome_fnv1a64)
        || record["logical_unit"] != unit
    {
        return Err(format!(
            "performance workload {workload} differs from its exact outcome invariant"
        ));
    }
    let elapsed = record["elapsed_ns"]
        .as_u64()
        .ok_or("invalid performance elapsed_ns")?;
    if record["ns_per_iteration"].as_u64() != Some(elapsed / request.iterations)
        || record["invariant"].as_str().is_none_or(str::is_empty)
    {
        return Err("performance record omits checked timing or invariant".into());
    }
    let provenance = &record["provenance"];
    if provenance["upstream_revision"] != REVISION
        || provenance["default_config_sha256"] != CONFIG_SHA256
        || provenance["package_version"] != RELEASE_VERSION
        || provenance["binding"] != "bazel-action-graph"
        || provenance["executable_bytes"] != prepared.executable_bytes
        || provenance["executable_fnv1a64"] != prepared.executable_fnv1a64
        || provenance["build"] != prepared.build
        || provenance["source"] != prepared.source
        || provenance["host"] != prepared.host
        || provenance["baseline_eligible"] != (prepared.source["dirty"] == false)
        || provenance["target_os"] != prepared.host["os"]
        || provenance["target_arch"] != prepared.host["arch"]
    {
        return Err(format!(
            "performance workload {workload} has mismatched provenance"
        ));
    }
    Ok(workload)
}

fn validate_records(output: &str, prepared: &Prepared, request: &Request) -> Result<(), String> {
    let mut actual = BTreeSet::new();
    for line in output.lines() {
        let record: Value = serde_json::from_str(line)
            .map_err(|error| format!("invalid performance JSON: {error}"))?;
        let workload = validate_record(&record, prepared, request)?;
        if !actual.insert(workload.to_owned()) {
            return Err(format!("duplicate performance workload {workload}"));
        }
    }
    let expected = request.workloads.iter().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("performance workload set mismatch".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_perf_sample(prepared: &Prepared, workload: &str) -> Result<String, String> {
    let output = command_output(
        Command::new(&prepared.binary)
            .current_dir(&prepared.root)
            .args(["--workload", workload, "--iterations", "1"]),
    )?;
    prepared.bind(&output)
}

fn matches_legacy_host(hardware: &Value) -> bool {
    hardware["machine_model"] == "MacBookPro18,2"
        && hardware["chip_type"] == "Apple M1 Max"
        && hardware["physical_memory"] == "32 GB"
        && hardware["number_processors"] == "proc 10:8:2:0"
}

#[cfg(target_os = "macos")]
fn legacy_host_hardware() -> Result<Value, String> {
    let output =
        command_output(Command::new("system_profiler").args(["SPHardwareDataType", "-json"]))?;
    let profile: Value = serde_json::from_str(&output)
        .map_err(|error| format!("cannot decode macOS hardware profile: {error}"))?;
    let hardware = profile["SPHardwareDataType"]
        .as_array()
        .and_then(|rows| rows.first())
        .ok_or("macOS hardware profile omits its overview")?;
    // Retain only fields used by the unchanged calibration predicate.
    Ok(
        json!({"machine_model":hardware["machine_model"],"chip_type":hardware["chip_type"],
        "physical_memory":hardware["physical_memory"],"number_processors":hardware["number_processors"]}),
    )
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
fn legacy_host_hardware() -> Result<Value, String> {
    Ok(Value::Null)
}

fn calibrated_m1_max_host() -> Result<bool, String> {
    legacy_host_hardware().map(|hardware| matches_legacy_host(&hardware))
}

#[cfg(target_os = "macos")]
fn run_perf_sample_with_rss(prepared: &Prepared, workload: &str) -> Result<(String, u64), String> {
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
        .arg(&prepared.binary)
        .current_dir(&prepared.root)
        .args(["--workload", workload, "--iterations", "1"])
        .output()
        .map_err(|error| format!("failed to run {display}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{display} exited {}:\n{}",
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
    Ok((prepared.bind(record)?, rss))
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
fn perf_budget_check(prepared: &Prepared) -> Result<(), String> {
    let request = Request::parse(&[])?;
    for budget in M1_MAX_PERF_BUDGETS {
        let warmup = run_perf_sample(prepared, budget.workload)?;
        let warmup: serde_json::Value = serde_json::from_str(&warmup)
            .map_err(|error| format!("invalid performance warmup JSON: {error}"))?;
        validate_record(&warmup, prepared, &request)?;

        let mut elapsed = Vec::with_capacity(7);
        let mut peak_rss = 0_u64;
        for sample in 0..7 {
            let (record, rss) = if sample < 3 {
                let (record, rss) = run_perf_sample_with_rss(prepared, budget.workload)?;
                (record, Some(rss))
            } else {
                (run_perf_sample(prepared, budget.workload)?, None)
            };
            let record: serde_json::Value = serde_json::from_str(&record)
                .map_err(|error| format!("invalid performance sample JSON: {error}"))?;
            validate_record(&record, prepared, &request)?;
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
fn perf_budget_check(_prepared: &Prepared) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_identity_rejects_same_length_content_changes() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustleaks-core/default/gitleaks.toml");
        let mut bytes = fs::read(path).unwrap();
        assert_eq!(verify_default_config(&bytes).unwrap(), CONFIG_SHA256);
        let length = bytes.len();
        bytes[0] ^= 1;
        assert_eq!(bytes.len(), length);
        assert!(verify_default_config(&bytes).is_err());
    }

    fn prepared() -> Prepared {
        Prepared {
            root: PathBuf::new(),
            binary: PathBuf::new(),
            source: json!({"revision": "test-head", "dirty": false, "input_sha256": "input"}),
            build: json!({"system": "bazel", "compiler_version": "actual compiler", "rust_action_graph_sha256": "graph", "workload_definition_sha256": "corpus"}),
            host: json!({"os": "test", "arch": "test", "cpu": "test cpu"}),
            executable_bytes: 1,
            executable_fnv1a64: "0123456789abcdef".into(),
        }
    }

    fn raw_matrix() -> String {
        PERF_INVARIANTS.iter().map(|expected| json!({
            "schema_version": 2,
            "workload": expected.workload,
            "iterations": 1,
            "warmup_iterations": 0,
            "measurement_scope": MEASUREMENT_SCOPE,
            "logical_unit": if expected.workload.starts_with("report-") { "findings" } else { "input-bytes" },
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
                "binding": "unbound-runner",
                "target_os": "test",
                "target_arch": "test",
                "executable_bytes": 1,
                "executable_fnv1a64": "0123456789abcdef"
            }
        }).to_string()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn record_gate_requires_exact_matrix_outcomes_and_build_binding() {
        let prepared = prepared();
        let request = Request::parse(&[]).unwrap();
        let raw = raw_matrix();
        assert!(validate_records(&raw, &prepared, &request).is_err());
        let output = prepared.bind(&raw).unwrap();
        validate_records(&output, &prepared, &request).unwrap();
        for (before, after) in [
            (REVISION, "wrong"),
            ("\"result_count\":222", "\"result_count\":221"),
            ("actual compiler", "unavailable"),
            ("test-head", "stale-head"),
            ("\"dirty\":false", "\"dirty\":true"),
            ("\"corpus\"", "\"wrong-corpus\""),
            ("\"graph\"", "\"wrong-graph\""),
            (MEASUREMENT_SCOPE, "new-unreviewed-timer"),
        ] {
            assert!(
                validate_records(&output.replacen(before, after, 1), &prepared, &request).is_err(),
                "accepted mutation {before}"
            );
        }
        let missing = output.lines().skip(1).collect::<Vec<_>>().join("\n");
        assert!(validate_records(&missing, &prepared, &request).is_err());
        let duplicate = format!("{output}\n{}", output.lines().next().unwrap());
        assert!(validate_records(&duplicate, &prepared, &request).is_err());
        assert!(
            prepared
                .bind(&raw.replacen("0123456789abcdef", "ffffffffffffffff", 1))
                .is_err()
        );
    }

    #[test]
    fn dirty_experiments_are_bound_but_not_baseline_eligible() {
        let mut prepared = prepared();
        prepared.source["dirty"] = json!(true);
        let output = prepared.bind(&raw_matrix()).unwrap();
        validate_records(&output, &prepared, &Request::parse(&[]).unwrap()).unwrap();
        for line in output.lines() {
            let record: Value = serde_json::from_str(line).unwrap();
            assert_eq!(record["provenance"]["baseline_eligible"], false);
        }
    }

    fn graph() -> Value {
        json!({"actions": [{
            "mnemonic": "Rustc", "actionKey": "key", "executionPlatform": "native",
            "arguments": ["wrapper", "--", "toolchain/bin/rustc", "src.rs", "--crate-name=rustleaks_perf", "--crate-type=bin", "--codegen=opt-level=3", "--target=test-target"],
            "environmentVariables": []
        }]})
    }

    #[test]
    fn action_identity_requires_actual_optimized_compiler_action() {
        let graph = graph();
        let identity = action_identity(&graph).unwrap();
        assert_eq!(identity["compiler_path"], "toolchain/bin/rustc");
        assert_eq!(identity["target"], "test-target");
        for (before, after) in [
            ("toolchain/bin/rustc", "other/tool"),
            ("--codegen=opt-level=3", "--codegen=opt-level=0"),
            ("--target=test-target", "--not-target=test-target"),
            ("--crate-name=rustleaks_perf", "--crate-name=other"),
        ] {
            let modified = serde_json::from_str(&graph.to_string().replace(before, after)).unwrap();
            assert!(
                action_identity(&modified).is_err(),
                "accepted action mutation {before}"
            );
        }
        let mut duplicate = graph.clone();
        duplicate["actions"]
            .as_array_mut()
            .unwrap()
            .push(graph["actions"][0].clone());
        assert!(action_identity(&duplicate).is_err());
        let mut changed = graph;
        changed["actions"][0]["arguments"]
            .as_array_mut()
            .unwrap()
            .push(json!("--cfg=feature=changed"));
        assert_ne!(
            identity["rust_action_graph_sha256"],
            action_identity(&changed).unwrap()["rust_action_graph_sha256"]
        );
    }

    #[test]
    fn metadata_allowlists_omit_arbitrary_environment_and_paths() {
        let action = json!({"environmentVariables": [
            {"key": "CARGO_CFG_TARGET_ARCH", "value": "aarch64"},
            {"key": "PRIVATE_TOKEN", "value": "synthetic-do-not-retain"},
            {"key": "PATH", "value": "/private/user/path"},
        ]});
        let selected = selected_environment(&action).to_string();
        assert!(selected.contains("aarch64"));
        assert!(!selected.contains("synthetic-do-not-retain"));
        assert!(!selected.contains("/private/user/path"));
        let arguments = vec![
            "--codegen=opt-level=3".into(),
            "--extern=x=/private/user/path".into(),
        ];
        assert_eq!(
            selected_compiler_options(&arguments),
            ["--codegen=opt-level=3"]
        );
        let mut overridden = graph();
        overridden["actions"][0]["arguments"]
            .as_array_mut()
            .unwrap()
            .extend([json!("-C"), json!("opt-level=0")]);
        assert!(action_identity(&overridden).is_err());
    }

    #[test]
    fn source_hash_observes_new_modified_and_deleted_inputs() {
        let temporary = crate::ScopedTempDir::new("perf-input-test").unwrap();
        let files = vec!["first.rs".into(), "new.rs".into()];
        fs::write(temporary.path.join("first.rs"), "before").unwrap();
        let initial = hash_paths(&temporary.path, &files).unwrap();
        fs::write(temporary.path.join("new.rs"), "new source").unwrap();
        let added = hash_paths(&temporary.path, &files).unwrap();
        assert_ne!(initial, added);
        fs::write(temporary.path.join("first.rs"), "after").unwrap();
        let modified = hash_paths(&temporary.path, &files).unwrap();
        assert_ne!(added, modified);
        fs::remove_file(temporary.path.join("first.rs")).unwrap();
        assert_ne!(modified, hash_paths(&temporary.path, &files).unwrap());
        assert!(hash_paths(&temporary.path, &["../escape".into()]).is_err());
    }

    #[test]
    fn requests_are_bounded_and_selection_is_exact() {
        assert_eq!(Request::parse(&[]).unwrap().workloads.len(), 23);
        assert!(Request::parse(&["--iterations".into(), "0".into()]).is_err());
        assert!(Request::parse(&["--iterations".into(), "11".into()]).is_err());
        assert!(Request::parse(&["--warmup".into(), "11".into()]).is_err());
        assert!(Request::parse(&["--workload".into(), "unknown".into()]).is_err());
        let selected = Request::parse(&[
            "--workload".into(),
            "report-json".into(),
            "--warmup".into(),
            "2".into(),
        ])
        .unwrap();
        assert_eq!(selected.workloads, ["report-json"]);
        assert_eq!(selected.warmup, 2);
    }

    #[test]
    fn inherited_budgets_reject_elapsed_and_rss_regressions() {
        let budget = PerfBudget {
            workload: "probe",
            median_elapsed_ns: 10,
            peak_rss_bytes: 20,
        };
        let mut passing = vec![7, 8, 9, 10, 11, 12, 13];
        assert_eq!(validate_perf_budget(budget, &mut passing, 20), Ok((10, 20)));
        assert!(validate_perf_budget(budget, &mut [11; 7], 20).is_err());
        assert!(validate_perf_budget(budget, &mut [10; 7], 21).is_err());
        assert!(validate_perf_budget(budget, &mut [10; 6], 20).is_err());
    }
}
