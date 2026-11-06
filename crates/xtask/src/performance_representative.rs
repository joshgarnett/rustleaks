//! On-demand representative phase collection. Never applies legacy budgets.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use super::{
    Prepared, action_identity_for, argument_file_identity, bazel, command_output, prepare,
    sha256_bytes, sha256_file, workspace_root,
};

const SCOPE: &str = "representative-v1-operation-only";
const CLI: &str = "//crates/rustleaks-cli:rustleaks";
const ARCHIVES: &str = "//crates/rustleaks-sources:perf_archives_test";
const MAX_ITERATIONS: u64 = 1_000;
const MAX_SAMPLES: u64 = 31;
const PROCESS_DEADLINE_SECONDS: u64 = 600;

struct Request {
    workload: Option<String>,
    samples: u64,
    iterations: u64,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut request = Self {
            workload: None,
            samples: 7,
            iterations: 25,
        };
        let mut arguments = arguments.iter();
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| format!("{argument} needs a value"))?;
            match argument.as_str() {
                "--workload" => request.workload = Some(value.clone()),
                "--samples" => request.samples = bounded(value, 3, MAX_SAMPLES, "samples")?,
                "--iterations" => {
                    request.iterations = bounded(value, 1, MAX_ITERATIONS, "iterations")?;
                }
                _ => return Err(format!("unknown representative option {argument}")),
            }
        }
        Ok(request)
    }
}

fn bounded(value: &str, minimum: u64, maximum: u64, name: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("invalid {name}"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be in {minimum}..={maximum}"));
    }
    Ok(value)
}

struct Executable {
    path: PathBuf,
    identity: Value,
}

impl Executable {
    fn unchanged(&self) -> Result<(), String> {
        if self.identity["executable_sha256"] != sha256_file(&self.path)? {
            return Err("representative auxiliary executable changed; discard this run".into());
        }
        Ok(())
    }
}

fn build_executable(root: &Path, label: &str, basename: &str) -> Result<Executable, String> {
    command_output(bazel(root, "build").arg(label))?;
    let execution_root = PathBuf::from(command_output(
        Command::new("bazelisk")
            .current_dir(root)
            .args(["info", "execution_root"]),
    )?);
    let outputs = command_output(bazel(root, "cquery").args([label, "--output=files"]))?;
    let filename = format!("{basename}{}", std::env::consts::EXE_SUFFIX);
    let candidates = outputs
        .lines()
        .filter(|line| {
            Path::new(line)
                .file_name()
                .is_some_and(|name| name == filename.as_str())
        })
        .collect::<Vec<_>>();
    let [relative] = candidates.as_slice() else {
        return Err(format!("{label} must identify exactly one executable"));
    };
    let path = execution_root.join(relative);
    let graph = command_output(bazel(root, "aquery").args([
        &format!("mnemonic(\"Rustc\", deps({label}))"),
        "--output=jsonproto",
    ]))?;
    let graph: Value = serde_json::from_str(&graph).map_err(|error| error.to_string())?;
    let mut identity = action_identity_for(&graph, label, basename, SCOPE)?;
    let compiler_path = execution_root.join(
        identity["compiler_path"]
            .as_str()
            .ok_or("missing compiler")?,
    );
    identity
        .as_object_mut()
        .ok_or("invalid action identity")?
        .remove("compiler_path");
    identity["compiler_sha256"] = json!(sha256_file(&compiler_path)?);
    identity["compiler_version"] = json!(command_output(Command::new(&compiler_path).arg("-Vv"))?);
    identity["argument_files"] = argument_file_identity(&graph, &execution_root)?;
    identity["executable_sha256"] = json!(sha256_file(&path)?);
    Ok(Executable { path, identity })
}

fn git_executable(root: &Path) -> Result<Executable, String> {
    if cfg!(windows) {
        // Match the installed-Git policy of the Windows compatibility test target.
        let search_path = std::env::var_os("PATH").ok_or("PATH unavailable for Windows Git")?;
        let path = installed_windows_git(&search_path)?;
        let version = command_output(Command::new(&path).arg("--version"))?;
        if !version.starts_with("git version ") || version.lines().count() != 1 {
            return Err("installed Windows Git returned an invalid version".into());
        }
        let identity = json!({"label":"installed-windows-git", "executable_sha256":sha256_file(&path)?, "version":version});
        return Ok(Executable { path, identity });
    }
    command_output(bazel(root, "build").arg("//bazel:git"))?;
    let execution_root = PathBuf::from(command_output(
        Command::new("bazelisk")
            .current_dir(root)
            .args(["info", "execution_root"]),
    )?);
    let outputs = command_output(bazel(root, "cquery").args(["//bazel:git", "--output=files"]))?;
    let paths = outputs.lines().collect::<Vec<_>>();
    let [path] = paths.as_slice() else {
        return Err("Bazel Git target must identify one executable".into());
    };
    let path = execution_root.join(path);
    let identity = json!({"label":"//bazel:git", "executable_sha256":sha256_file(&path)?, "version":command_output(Command::new(&path).arg("--version"))?});
    Ok(Executable { path, identity })
}

fn installed_windows_git(search_path: &std::ffi::OsStr) -> Result<PathBuf, String> {
    for directory in std::env::split_paths(search_path) {
        let path = directory.join("git.exe");
        if path.is_file() {
            return path.canonicalize().map_err(|error| error.to_string());
        }
    }
    Err("PATH does not contain an installed git.exe".into())
}

struct Tools {
    cli: Option<Executable>,
    archives: Option<Executable>,
    git: Option<Executable>,
}

impl Tools {
    fn prepare(root: &Path, workloads: &[String]) -> Result<Self, String> {
        let needs_cli = workloads.iter().any(|id| id.starts_with("cli-"));
        let needs_git = workloads
            .iter()
            .any(|id| id.starts_with("git-") || id == "cli-git");
        let needs_archives = workloads.iter().any(|id| id == "archives-all-formats");
        Ok(Self {
            cli: needs_cli
                .then(|| build_executable(root, CLI, "rustleaks"))
                .transpose()?,
            archives: needs_archives
                .then(|| build_executable(root, ARCHIVES, "perf_archives_test"))
                .transpose()?,
            git: needs_git.then(|| git_executable(root)).transpose()?,
        })
    }

    fn identities(&self) -> Value {
        json!({"cli": self.cli.as_ref().map(|tool| &tool.identity), "archives": self.archives.as_ref().map(|tool| &tool.identity), "git": self.git.as_ref().map(|tool| &tool.identity)})
    }

    fn unchanged(&self) -> Result<(), String> {
        for tool in [&self.cli, &self.archives, &self.git].into_iter().flatten() {
            tool.unchanged()?;
        }
        Ok(())
    }
}

pub(crate) struct QualityTestTools {
    cli: Executable,
    git: Executable,
}

impl QualityTestTools {
    pub(crate) fn prepare(root: &Path) -> Result<Self, String> {
        let tools = Tools::prepare(root, &["cli-git".into()])?;
        Ok(Self {
            cli: tools.cli.ok_or("quality tests require the Bazel CLI")?,
            git: tools
                .git
                .ok_or("quality tests require the declared Git tool")?,
        })
    }

    pub(crate) fn bind(&self, command: &mut Command) {
        let git_variables = std::env::vars_os()
            .map(|(name, _)| name)
            .chain(command.get_envs().map(|(name, _)| name.to_owned()))
            .filter(|name| {
                name.to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("GIT_")
            })
            .collect::<BTreeSet<_>>();
        for name in git_variables {
            command.env_remove(name);
        }
        command
            .env("RUSTLEAKS_PERF_CLI", &self.cli.path)
            .env("RUSTLEAKS_PERF_GIT", &self.git.path);
    }

    pub(crate) fn unchanged(&self) -> Result<(), String> {
        self.cli.unchanged()?;
        self.git.unchanged()
    }
}

// The wrapper observes the entire child process and waited descendants. It does
// not pretend CPU/RSS are phase-local. stdout is bounded by the runner's matrix.
const COLLECTOR: &str = r"import json, os, signal, subprocess, sys, time
try:
 import resource
except ImportError:
 resource = None
before = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
start = time.perf_counter_ns()
p = subprocess.Popen(sys.argv[2:], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=(os.name == 'posix'))
try:
 out, err = p.communicate(timeout=int(sys.argv[1]))
except subprocess.TimeoutExpired:
 if os.name == 'posix': os.killpg(p.pid, signal.SIGKILL)
 else: p.kill()
 p.communicate()
 raise SystemExit('representative child exceeded its wall deadline')
wall = time.perf_counter_ns() - start
if len(out) > 4194304 or len(err) > 65536: raise SystemExit('representative output exceeds collector bounds')
if p.returncode:
 sys.stderr.buffer.write(err)
 raise SystemExit(p.returncode)
after = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
print(json.dumps({'stdout':out.decode('utf-8'), 'process':{'wall_ns':wall, 'user_cpu_ns':round((after.ru_utime-before.ru_utime)*1e9) if resource else None, 'system_cpu_ns':round((after.ru_stime-before.ru_stime)*1e9) if resource else None, 'peak_rss_bytes':round(after.ru_maxrss*(1 if sys.platform == 'darwin' else 1024)) if resource else None, 'scope':'whole-child-process-and-waited-descendants-includes-fixtures-verification-and-destruction', 'collector':'python-resource-v1', 'deadline_seconds':int(sys.argv[1]), 'allocation_counts':None}}))
";

fn collect(
    prepared: &Prepared,
    tools: &Tools,
    arguments: &[String],
) -> Result<(String, Value), String> {
    let mut command = Command::new("python3");
    command
        .current_dir(&prepared.root)
        .arg("-c")
        .arg(COLLECTOR)
        .arg(PROCESS_DEADLINE_SECONDS.to_string())
        .arg(&prepared.binary)
        .args(arguments);
    // No ambient Git configuration can change the synthetic corpus or Git scans.
    let path = std::env::var_os("PATH").ok_or("PATH unavailable for collector")?;
    let path = if let Some(git) = &tools.git {
        let parent = git.path.parent().ok_or("Git executable has no parent")?;
        std::env::join_paths(std::iter::once(parent.to_owned()).chain(std::env::split_paths(&path)))
            .map_err(|error| error.to_string())?
    } else {
        path
    };
    command
        .env_clear()
        .env("PATH", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        );
    for name in ["SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for (name, tool) in [
        ("RUSTLEAKS_PERF_CLI", &tools.cli),
        ("RUSTLEAKS_PERF_GIT", &tools.git),
        ("RUSTLEAKS_PERF_ARCHIVE_DRIVER", &tools.archives),
    ] {
        if let Some(tool) = tool {
            command.env(name, &tool.path);
        }
    }
    command.env("RUSTLEAKS_PERF_ROOT", &prepared.root);
    let collected = command_output(&mut command)?;
    let value: Value = serde_json::from_str(&collected)
        .map_err(|error| format!("invalid collector JSON: {error}"))?;
    let output = value["stdout"]
        .as_str()
        .ok_or("collector omitted stdout")?
        .to_owned();
    if value["process"]["wall_ns"].as_u64().is_none() {
        return Err("collector omitted process wall time".into());
    }
    Ok((output, value["process"].clone()))
}

#[allow(clippy::too_many_lines)] // Keep sample validation and final stability checks in one flow.
pub(crate) fn run(arguments: &[String]) -> Result<(), String> {
    let request = Request::parse(arguments)?;
    let mut prepared = prepare(&workspace_root()?)?;
    prepared.build["timing_scope"] = json!(SCOPE);
    let listed = command_output(Command::new(&prepared.binary).arg("--representative-list"))?;
    let available = listed.lines().map(str::to_owned).collect::<Vec<_>>();
    if available.len() != available.iter().collect::<BTreeSet<_>>().len() || available.is_empty() {
        return Err("representative workload list is empty or duplicated".into());
    }
    let workloads = match request.workload {
        Some(ref id) if available.contains(id) => vec![id.clone()],
        Some(ref id) => return Err(format!("unknown representative workload {id}")),
        None => available,
    };
    let tools = Tools::prepare(&prepared.root, &workloads)?;
    prepared.ensure_unchanged()?;
    // No build work occurs after this point.
    for workload in workloads {
        let mut reference = None;
        let mut elapsed_by_phase: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for sample in 0..request.samples {
            let (startup, startup_process) =
                collect(&prepared, &tools, &["--representative-startup".into()])?;
            if startup.trim() != "rustleaks-representative-startup-v1" {
                return Err("startup control returned wrong marker".into());
            }
            let (output, process) = collect(
                &prepared,
                &tools,
                &[
                    "--representative".into(),
                    "--workload".into(),
                    workload.clone(),
                    "--iterations".into(),
                    request.iterations.to_string(),
                ],
            )?;
            let bound = prepared.bind(&output)?;
            let records = validate(&bound, &prepared, &workload, request.iterations)?;
            let invariants = records.iter().map(stable_identity).collect::<Vec<_>>();
            if reference
                .as_ref()
                .is_some_and(|expected| expected != &invariants)
            {
                return Err(format!(
                    "{workload} corpus, exact outcome or counts changed between processes"
                ));
            }
            reference = Some(invariants);
            for mut record in records {
                let phase = record["phase"]["phase"]
                    .as_str()
                    .ok_or("phase omitted name")?
                    .to_owned();
                let elapsed = record["phase"]["elapsed_ns"]
                    .as_u64()
                    .ok_or("phase omitted elapsed time")?;
                let iterations = record["phase"]["iterations"]
                    .as_u64()
                    .ok_or("phase omitted iterations")?;
                let units = record["phase"]["logical_units_per_iteration"]
                    .as_u64()
                    .ok_or("phase omitted units")?;
                elapsed_by_phase
                    .entry(phase)
                    .or_default()
                    .push(elapsed / iterations);
                record["sample_index"] = json!(sample);
                record["sample_count"] = json!(request.samples);
                record["ns_per_iteration"] = json!(elapsed / iterations);
                record["logical_units_per_second"] = throughput(units, iterations, elapsed);
                record["process"] = process.clone();
                record["startup_control_process"] = startup_process.clone();
                record["provenance"]["auxiliary_executables"] = tools.identities();
                record["provenance"]["collector_sha256"] =
                    json!(sha256_bytes(COLLECTOR.as_bytes()));
                record["threshold_evaluation"] = json!("none-uncalibrated");
                println!("{record}");
            }
        }
        for (phase, samples) in elapsed_by_phase {
            println!(
                "{}",
                json!({"schema_version":3,"suite":"representative-v1","kind":"summary","workload":workload,"phase":phase,"measurement_scope":SCOPE,"statistics":statistics(samples)?,"p95":null,"threshold_evaluation":"none-uncalibrated","source":prepared.source,"build":prepared.build,"host":prepared.host})
            );
        }
    }
    prepared.ensure_unchanged()?;
    tools.unchanged()?;
    println!(
        "{}",
        json!({"schema_version":3,"suite":"representative-v1","kind":"run-complete","source":prepared.source,"executable_sha256":prepared.build["executable_sha256"],"baseline_eligible":prepared.source["dirty"] == false})
    );
    Ok(())
}

pub(super) fn required_phases(workload: &str) -> Result<Vec<&'static str>, String> {
    if workload.starts_with("core-") {
        return Ok(vec![
            "config-parse-and-compile",
            "engine-construction",
            "first-scan",
            "steady-scan",
        ]);
    }
    if workload.starts_with("source-") {
        return Ok(vec![
            "traversal-and-read",
            "runner-detection-and-session",
            "traversal-and-detection",
        ]);
    }
    match workload {
        "session-merge-10000" => Ok(vec!["session-merge"]),
        "serialize-json-10000" | "serialize-sarif-10000" => Ok(vec!["report-serialization"]),
        "git-repeated-blobs" => Ok(vec!["git-history-and-parse", "git-history-and-detection"]),
        "cli-startup" => Ok(vec!["cold-process-version"]),
        "cli-dir" | "cli-stdin" | "cli-git" => Ok(vec!["cold-cli-startup-config-scan-report"]),
        "archives-all-formats" => Ok(vec![
            "archive-expand/tar-two-members",
            "archive-expand/zip",
            "archive-expand/7z-stored",
            "archive-expand/rar5-stored",
            "archive-expand/tar-gzip-two-members",
            "archive-expand/gzip",
            "archive-expand/tar-xz-two-members",
            "archive-expand/xz",
            "archive-expand/bzip2",
            "archive-expand/brotli",
            "archive-expand/lz4",
            "archive-expand/snappy",
            "archive-expand/minlz",
            "archive-expand/zstd",
            "archive-expand/zlib",
            "archive-expand/lzip",
            "archive-expand/s2",
            "archive-expand/rar5-compressed",
            "archive-expand/rar2-compressed",
            "archive-expand/rar3-compressed",
            "archive-expand/7z-compressed",
            "archive-expand/gzip-compressed",
            "archive-expand/zlib-compressed",
        ]),
        _ => Err(format!("unrecognized representative workload {workload}")),
    }
}

fn valid_fingerprint(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() == 16
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub(super) fn validate(
    output: &str,
    prepared: &Prepared,
    workload: &str,
    iterations: u64,
) -> Result<Vec<Value>, String> {
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    for line in output.lines() {
        let record: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
        let phase = &record["phase"];
        let name = phase["phase"].as_str().ok_or("missing phase name")?;
        let expected_iterations = if [
            "config-parse-and-compile",
            "engine-construction",
            "first-scan",
        ]
        .contains(&name)
        {
            1
        } else {
            iterations
        };
        if record["schema_version"] != 3
            || record["suite"] != "representative-v1"
            || record["workload"] != workload
            || record["measurement_scope"] != SCOPE
            || phase["scope"] != SCOPE
            || phase["iterations"] != expected_iterations
            || phase["complete"] != true
            || phase["errors"] != 0
            || !seen.insert(name.to_owned())
            || phase["elapsed_ns"].as_u64().is_none()
            || phase["findings"].as_u64().is_none()
            || phase["logical_units_per_iteration"].as_u64().is_none()
            || phase["logical_unit"].as_str().is_none_or(str::is_empty)
            || !phase["counts"].is_object()
        {
            return Err(
                "representative row has incomplete outcome, invalid phase, scope, counts or timing"
                    .into(),
            );
        }
        for key in ["input_fnv1a64", "config_fnv1a64", "outcome_fnv1a64"] {
            if !valid_fingerprint(&phase[key]) {
                return Err(format!("representative phase omits {key}"));
            }
        }
        let provenance = &record["provenance"];
        if provenance["binding"] != "bazel-action-graph"
            || provenance["build"] != prepared.build
            || provenance["source"] != prepared.source
            || provenance["host"] != prepared.host
            || provenance["baseline_eligible"] != (prepared.source["dirty"] == false)
            || provenance["executable_bytes"] != prepared.executable_bytes
            || provenance["executable_fnv1a64"] != prepared.executable_fnv1a64
            || provenance["upstream_revision"] != crate::REVISION
            || provenance["default_config_sha256"] != crate::CONFIG_SHA256
            || provenance["package_version"] != crate::RELEASE_VERSION
            || provenance["target_os"] != prepared.host["os"]
            || provenance["target_arch"] != prepared.host["arch"]
        {
            return Err("representative row has mismatched build/source provenance".into());
        }
        records.push(record);
    }
    let expected = required_phases(workload)?;
    if records.is_empty()
        || (!expected.is_empty()
            && seen != expected.iter().map(|name| (*name).to_owned()).collect())
    {
        return Err(format!(
            "representative {workload} omitted or added a phase"
        ));
    }
    Ok(records)
}

pub(super) fn stable_identity(record: &Value) -> Value {
    let mut phase = record["phase"].clone();
    phase
        .as_object_mut()
        .expect("validated phase is an object")
        .remove("elapsed_ns");
    phase
}

#[allow(clippy::cast_precision_loss)] // Throughput is an approximate display; exact counts are retained.
fn throughput(units: u64, iterations: u64, elapsed: u64) -> Value {
    if elapsed == 0 {
        Value::Null
    } else {
        json!((units as f64 * iterations as f64 * 1e9) / elapsed as f64)
    }
}

pub(super) fn statistics(mut samples: Vec<u64>) -> Result<Value, String> {
    if !(3..=31).contains(&samples.len()) {
        return Err("summary requires 3..=31 independent process samples".into());
    }
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let mut deviations = samples
        .iter()
        .map(|sample| sample.abs_diff(median))
        .collect::<Vec<_>>();
    deviations.sort_unstable();
    Ok(
        json!({"samples":samples.len(),"median_ns":median,"minimum_ns":samples[0],"maximum_ns":samples[samples.len()-1],"median_absolute_deviation_ns":deviations[deviations.len()/2],"median_definition":"upper-middle-order-statistic","raw_ns_per_iteration":samples}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_windows_git_requires_a_file_and_preserves_path_precedence() {
        let scratch = crate::ScopedTempDir::new("windows-git-selection").unwrap();
        let first = scratch.path.join("first installation \u{03a9}");
        let second = scratch.path.join("second installation");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let search_path = std::env::join_paths([&first, &second]).unwrap();
        assert!(installed_windows_git(&search_path).is_err());
        std::fs::create_dir(first.join("git.exe")).unwrap();
        std::fs::write(second.join("git.exe"), b"synthetic selection fixture").unwrap();
        let expected = second.join("git.exe").canonicalize().unwrap();
        assert!(expected.is_absolute());
        assert_eq!(installed_windows_git(&search_path).unwrap(), expected);
        std::fs::remove_dir(first.join("git.exe")).unwrap();
        std::fs::write(first.join("git.exe"), b"synthetic selection fixture").unwrap();
        assert_eq!(
            installed_windows_git(&search_path).unwrap(),
            first.join("git.exe").canonicalize().unwrap()
        );
    }

    #[test]
    fn quality_tool_bindings_override_stale_paths_only_on_the_selected_child() {
        let directory = std::env::temp_dir().join("quality tools \u{03a9}");
        let cli = directory.join("rustleaks");
        let git = directory.join("git");
        let tools = QualityTestTools {
            cli: Executable {
                path: cli.clone(),
                identity: json!({}),
            },
            git: Executable {
                path: git.clone(),
                identity: json!({}),
            },
        };
        let mut command = Command::new("cargo");
        command
            .env("RUSTLEAKS_PERF_CLI", "stale-cli")
            .env("RUSTLEAKS_PERF_GIT", "stale-git")
            .env("CARGO_TARGET_DIR", "retained-target")
            .env("PATH", "retained-path");
        let git_variables = [
            "GIT_DIR",
            "GIT_PAGER",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "Git_Work_Tree",
        ];
        for name in git_variables {
            command.env(name, "synthetic-git-override");
        }
        let mut unrelated = Command::new("cargo");
        unrelated.env("GIT_DIR", "unrelated-directory");
        tools.bind(&mut command);
        let binding = |name: &str| {
            command
                .get_envs()
                .find(|(key, _)| *key == name)
                .and_then(|(_, value)| value)
        };
        assert_eq!(binding("RUSTLEAKS_PERF_CLI"), Some(cli.as_os_str()));
        assert_eq!(binding("RUSTLEAKS_PERF_GIT"), Some(git.as_os_str()));
        assert_eq!(
            binding("CARGO_TARGET_DIR"),
            Some(std::ffi::OsStr::new("retained-target"))
        );
        assert_eq!(binding("PATH"), Some(std::ffi::OsStr::new("retained-path")));
        for name in git_variables {
            assert_eq!(
                command
                    .get_envs()
                    .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(name))
                    .map(|(_, value)| value),
                Some(None)
            );
        }
        assert_eq!(
            unrelated.get_envs().collect::<Vec<_>>(),
            [(
                std::ffi::OsStr::new("GIT_DIR"),
                Some(std::ffi::OsStr::new("unrelated-directory")),
            )]
        );
    }

    #[test]
    fn representative_bounds_and_dispersion_are_explicit() {
        assert!(Request::parse(&["--samples".into(), "2".into()]).is_err());
        assert!(Request::parse(&["--iterations".into(), "1001".into()]).is_err());
        let result = statistics(vec![90, 10, 20, 30, 40, 50, 60]).unwrap();
        assert_eq!(result["median_ns"], 40);
        assert_eq!(result["median_absolute_deviation_ns"], 20);
        assert!(result.get("p95").is_none());
        assert!(statistics(vec![1, 2]).is_err());
    }

    #[test]
    fn representative_identity_rejects_skipped_work_counts() {
        let mut record = json!({"phase":{"phase":"steady-scan","elapsed_ns":1,"logical_units_per_iteration":1024,"findings":1,"input_fnv1a64":"1234567890abcdef","complete":true}});
        let expected = stable_identity(&record);
        record["phase"]["elapsed_ns"] = json!(2);
        assert_eq!(expected, stable_identity(&record));
        record["phase"]["logical_units_per_iteration"] = json!(0);
        assert_ne!(expected, stable_identity(&record));
        record["phase"]["logical_units_per_iteration"] = json!(1024);
        record["phase"]["findings"] = json!(0);
        assert_ne!(expected, stable_identity(&record));
    }

    #[test]
    fn representative_gate_rejects_missing_phases_incomplete_work_and_wrong_provenance() {
        let prepared = Prepared {
            root: PathBuf::new(),
            binary: PathBuf::new(),
            source: json!({"dirty": false, "input_sha256":"source"}),
            build: json!({"timing_scope": SCOPE, "workload_definition_sha256":"definitions"}),
            host: json!({"os":"test-os", "arch":"test-arch"}),
            executable_bytes: 1,
            executable_fnv1a64: "0123456789abcdef".into(),
        };
        let records = required_phases("core-mixed-1-kib").unwrap().iter().map(|phase| json!({
            "schema_version":3,"suite":"representative-v1","workload":"core-mixed-1-kib","measurement_scope":SCOPE,
            "phase":{"phase":phase,"scope":SCOPE,"iterations":1,"complete":true,"errors":0,"findings":1,"elapsed_ns":1,"logical_units_per_iteration":1024,"logical_unit":"input-bytes","counts":{"workers":1},"input_fnv1a64":"0123456789abcdef","config_fnv1a64":"0123456789abcdef","outcome_fnv1a64":"0123456789abcdef"},
            "provenance":{"binding":"bazel-action-graph","build":prepared.build,"source":prepared.source,"host":prepared.host,"baseline_eligible":true,"executable_bytes":1,"executable_fnv1a64":prepared.executable_fnv1a64,"upstream_revision":crate::REVISION,"default_config_sha256":crate::CONFIG_SHA256,"package_version":crate::RELEASE_VERSION,"target_os":"test-os","target_arch":"test-arch"}
        })).collect::<Vec<_>>();
        let encode = |records: &[Value]| {
            records
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        validate(&encode(&records), &prepared, "core-mixed-1-kib", 1).unwrap();
        assert!(validate(&encode(&records[..3]), &prepared, "core-mixed-1-kib", 1).is_err());
        for pointer in [
            "/phase/complete",
            "/phase/scope",
            "/provenance/build/workload_definition_sha256",
            "/provenance/source/input_sha256",
            "/phase/input_fnv1a64",
        ] {
            let mut changed = records.clone();
            *changed[0].pointer_mut(pointer).unwrap() = json!("invalid");
            assert!(
                validate(&encode(&changed), &prepared, "core-mixed-1-kib", 1).is_err(),
                "accepted mutation {pointer}"
            );
        }
    }
}
