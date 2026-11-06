//! Private, bounded local fuzz evidence and reviewed corpus reuse.

mod corpus;
pub(crate) mod private;
pub(crate) mod process;
pub(crate) mod profiles;

#[path = "../../rustleaks-core/tests/support/campaign_profile.rs"]
#[allow(dead_code)] // Shared harness policy also contains target-only helpers.
mod campaign_profile;
#[path = "../../rustleaks-sources/fuzz/support/source_frame.rs"]
#[allow(dead_code)] // Frame decoders also serve the fuzz targets and ordinary proofs.
mod source_frame;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::tooling::{sha256_bytes, sha256_file};
use private::Bundle;
use process::Outcome;
use profiles::{Deadline, Profile};

#[derive(Clone, Copy)]
struct Target {
    workspace: &'static str,
    name: &'static str,
    max_len: u64,
    features: &'static [&'static str],
}

const TARGETS: &[Target] = &[
    Target {
        workspace: "rustleaks-core",
        name: "go_regex",
        max_len: 4096,
        features: &["default"],
    },
    Target {
        workspace: "rustleaks-core",
        name: "config",
        max_len: 8192,
        features: &["default"],
    },
    Target {
        workspace: "rustleaks-core",
        name: "fragment_scan",
        max_len: 8192,
        features: &["default"],
    },
    Target {
        workspace: "rustleaks-core",
        name: "session",
        max_len: 16_384,
        features: &["default"],
    },
    Target {
        workspace: "rustleaks-sources",
        name: "archive",
        max_len: 8192,
        features: &["default", "archives", "fuzzing"],
    },
    Target {
        workspace: "rustleaks-sources",
        name: "reader_schedule",
        max_len: 4096,
        features: &["default", "archives", "fuzzing"],
    },
    Target {
        workspace: "rustleaks-sources",
        name: "git_patch",
        max_len: 16_384,
        features: &["default", "archives", "fuzzing"],
    },
    Target {
        workspace: "rustleaks-report",
        name: "template",
        max_len: 8192,
        features: &["default"],
    },
];

impl Target {
    fn directory(self, root: &Path) -> PathBuf {
        root.join("crates").join(self.workspace).join("fuzz")
    }
}

#[derive(Clone, Copy)]
struct Limits {
    runs: u64,
    seconds: u64,
    seed: u64,
}

impl Limits {
    fn environment() -> Result<Self, String> {
        Ok(Self {
            runs: crate::fuzz_campaign_bound("RUSTLEAKS_FUZZ_RUNS", 16, 1_000_000)?,
            seconds: crate::fuzz_campaign_bound("RUSTLEAKS_FUZZ_MAX_TOTAL_TIME", 20, 600)?,
            seed: crate::fuzz_campaign_bound("RUSTLEAKS_FUZZ_SEED", 1, u64::from(u32::MAX))?,
        })
    }

    fn from_record(record: &Value) -> Result<Self, String> {
        fn bounded(record: &Value, field: &str, maximum: u64) -> Result<u64, String> {
            record["limits"][field]
                .as_u64()
                .filter(|value| *value > 0 && *value <= maximum)
                .ok_or_else(|| format!("invalid saved {field} bound"))
        }
        if record["limits"]["timeout_seconds"] != 5
            || record["limits"]["rss_limit_mb"] != 2048
            || record["limits"]["log_bytes"] != process::LOG_LIMIT
        {
            return Err("saved fuzz resource policy is incompatible".into());
        }
        Ok(Self {
            runs: bounded(record, "runs", 1_000_000)?,
            seconds: bounded(record, "seconds", 600)?,
            seed: bounded(record, "seed", u64::from(u32::MAX))?,
        })
    }
}

/// The ordinary gate keeps its existing budgets and all eight targets.
pub(crate) fn smoke(root: &Path) -> Result<(), String> {
    run(root, &["run".into()])
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    run_bounded(root, arguments, Deadline::new(None))
}

pub(crate) fn run_bounded(
    root: &Path,
    arguments: &[String],
    outer: Deadline,
) -> Result<(), String> {
    private::supported()?;
    let request = Request::parse(arguments)?;
    let bundle = Bundle::new(request.output.as_deref()).map_err(|_| {
        "fuzz: cannot create private output; destination must be new with an existing parent"
            .to_owned()
    })?;
    let deadline = outer.intersect(Deadline::new(
        request.deadline.or(request.profile.map(|_| 7200)),
    ));
    let invocation = request.normalized(outer, deadline);
    let result = execute(root, &bundle, &request, deadline, &invocation);
    bundle.finish(result)
}

struct Request {
    operation: String,
    source: Option<PathBuf>,
    target: Option<String>,
    artifact: Option<String>,
    output: Option<PathBuf>,
    reviewed: Option<PathBuf>,
    reviewed_hash: Option<String>,
    profile: Option<Profile>,
    selected: Option<Vec<String>>,
    seconds: Option<u64>,
    runs: Option<u64>,
    seed: Option<u64>,
    deadline: Option<u64>,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let usage = "usage: fuzz run [--output NEW_PATH] [--corpus REVIEWED_PATH] [--profile smoke|extended|deep] [--targets NAME,...] [--seconds N] [--runs N] [--seed N] [--deadline-seconds N] | fuzz <replay|minimize> BUNDLE TARGET --output NEW_PATH | fuzz <reproduce|tmin> BUNDLE TARGET ARTIFACT_SHA256 --output NEW_PATH | fuzz promote BUNDLE TARGET --output NEW_PATH --reviewed-sha256 HASH";
        let (operation, rest) = arguments.split_first().ok_or(usage)?;
        let mut request = Self {
            operation: operation.clone(),
            source: None,
            target: None,
            artifact: None,
            output: None,
            reviewed: None,
            reviewed_hash: None,
            profile: None,
            selected: None,
            seconds: None,
            runs: None,
            seed: None,
            deadline: None,
        };
        let rest = match operation.as_str() {
            "run" => rest,
            "replay" | "minimize" | "promote" | "reproduce" | "tmin" => {
                let [source, target, rest @ ..] = rest else {
                    return Err(usage.into());
                };
                request.source = Some(PathBuf::from(source));
                request.target = Some(target.clone());
                if matches!(operation.as_str(), "reproduce" | "tmin") {
                    let [artifact, rest @ ..] = rest else {
                        return Err(usage.into());
                    };
                    if !valid_hash(artifact) {
                        return Err(usage.into());
                    }
                    request.artifact = Some(artifact.clone());
                    rest
                } else {
                    rest
                }
            }
            _ => return Err(usage.into()),
        };
        if rest.len() % 2 != 0 {
            return Err(usage.into());
        }
        for option in rest.chunks_exact(2) {
            match option[0].as_str() {
                "--profile" if operation == "run" && request.profile.is_none() => {
                    request.profile = Some(Profile::parse(&option[1])?);
                }
                "--targets" if operation == "run" && request.selected.is_none() => {
                    request.selected = Some(profiles::targets(&option[1])?);
                }
                "--seconds" if operation == "run" && request.seconds.is_none() => {
                    request.seconds = Some(profiles::bounded(&option[1], 600, "seconds")?);
                }
                "--runs" if operation == "run" && request.runs.is_none() => {
                    request.runs = Some(profiles::bounded(&option[1], 1_000_000, "runs")?);
                }
                "--seed" if operation == "run" && request.seed.is_none() => {
                    request.seed =
                        Some(profiles::bounded(&option[1], u64::from(u32::MAX), "seed")?);
                }
                "--deadline-seconds" if request.deadline.is_none() => {
                    request.deadline =
                        Some(profiles::bounded(&option[1], 7200, "deadline-seconds")?);
                }
                "--output" if request.output.is_none() => {
                    request.output = Some(PathBuf::from(&option[1]));
                }
                "--corpus" if operation == "run" && request.reviewed.is_none() => {
                    request.reviewed = Some(PathBuf::from(&option[1]));
                }
                "--reviewed-sha256"
                    if operation == "promote"
                        && request.reviewed_hash.is_none()
                        && valid_hash(&option[1]) =>
                {
                    request.reviewed_hash = Some(option[1].clone());
                }
                _ => return Err(usage.into()),
            }
        }
        if operation != "run" && request.output.is_none()
            || operation == "promote" && request.reviewed_hash.is_none()
        {
            return Err(usage.into());
        }
        Ok(request)
    }
    fn normalized(&self, outer: Deadline, deadline: Deadline) -> Value {
        let targets = if self.operation == "run" {
            TARGETS
                .iter()
                .filter(|target| {
                    self.selected
                        .as_ref()
                        .is_none_or(|names| names.iter().any(|name| name == target.name))
                })
                .map(|target| target.name.to_owned())
                .collect::<Vec<_>>()
        } else {
            self.target.iter().cloned().collect()
        };
        let local_seconds = self.deadline.or(self.profile.map(|_| 7200));
        json!({"operation":self.operation,"targets":targets,
            "profile":if self.operation=="run" {self.profile.unwrap_or(Profile::Smoke).record()} else {Value::Null},
            "profile_source":if self.operation!="run" {"saved-target-manifest"} else if self.profile.is_some() {"explicit-profile"} else {"legacy-smoke-default"},
            "limit_overrides":{"runs":self.runs,"seconds":self.seconds,"seed":self.seed},
            "limit_source":if self.operation!="run" {"saved-target-manifest"} else if self.profile.is_some() {"profile-defaults-and-explicit-overrides"} else {"legacy-environment-and-explicit-overrides"},
            "wrapper_deadline":{"requested_seconds":self.deadline,"local_seconds":local_seconds,
                "local_source":if self.deadline.is_some() {"explicit-option"} else if self.profile.is_some() {"profile-default"} else {"unbounded-legacy-default"},
                "inherited_at_start":outer.snapshot(),"effective_at_start":deadline.snapshot(),
                "replay_policy":"fresh invocation deadline; saved elapsed wall-clock budget is not reused"}})
    }

    fn limits(&self) -> Result<Limits, String> {
        let mut limits = if let Some(profile) = self.profile {
            Limits {
                runs: profile.runs(),
                seconds: profile.seconds(),
                seed: 1,
            }
        } else {
            Limits::environment()?
        };
        if let Some(runs) = self.runs {
            limits.runs = runs;
        }
        if let Some(seconds) = self.seconds {
            limits.seconds = seconds;
        }
        if let Some(seed) = self.seed {
            limits.seed = seed;
        }
        Ok(limits)
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn execute(
    root: &Path,
    bundle: &Bundle,
    request: &Request,
    deadline: Deadline,
    invocation: &Value,
) -> Result<(), String> {
    private::json(
        &bundle.path.join("bundle.json"),
        &json!({
            "schema_version": 1, "id": bundle.id, "state": "preparing", "operation": request.operation, "request": invocation,
        }),
    )?;
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if bundle.path.starts_with(&root) {
        return Err("private fuzz output must be outside the source checkout".into());
    }
    let preparation = bundle.path.join("preparation");
    private::directory(&preparation)?;
    let identity = observe_identity(&root, &preparation, deadline)?;
    private::json(
        &bundle.path.join("bundle.json"),
        &json!({
            "schema_version": 1, "id": bundle.id, "state": "running",
            "operation": request.operation, "identity": identity, "request": invocation,
        }),
    )?;
    if request.operation == "run" {
        build(&root, &preparation, deadline)?;
        run_targets(&root, bundle, request, deadline, invocation, &identity)?;
    } else {
        let original = *TARGETS
            .iter()
            .find(|target| Some(target.name) == request.target.as_deref())
            .ok_or("unknown fuzz target")?;
        let source = request.source.as_ref().ok_or("missing source bundle")?;
        let record = private::read_json(&source.join(original.name).join("manifest.json"))?;
        let profile = Profile::from_record(&record["profile"])?;
        let target = Target {
            max_len: profile.maximum_input(original.name)?,
            ..original
        };
        if record["schema_version"] != 1
            || record["target"] != target.name
            || record["identity"]["environment"] != identity
            || record["limits"]["max_len"] != target.max_len
        {
            return Err("saved fuzz environment is stale or incompatible".into());
        }
        let limits = Limits::from_record(&record)?;
        if request.operation == "replay"
            && !matches!(record["operation"].as_str(), Some("run" | "replay"))
        {
            return Err("campaign replay requires a run or replay bundle; use the recorded artifact for reproduce/tmin".into());
        }
        if request.operation == "promote" {
            corpus::promote(
                &source.join(target.name).join("final-corpus"),
                &bundle.path,
                &record,
                request
                    .reviewed_hash
                    .as_deref()
                    .ok_or("missing review hash")?,
                target.max_len,
            )?;
        } else {
            build(&root, &preparation, deadline)?;
            campaign(
                &root,
                bundle,
                target,
                &identity,
                limits,
                None,
                Some((&source.join(target.name), &record)),
                request,
                profile,
                deadline,
            )?;
        }
    }
    let verification = bundle.path.join("verification");
    private::directory(&verification)?;
    if observe_identity(&root, &verification, deadline)? != identity {
        return Err("fuzz source or tool identity changed during the operation".into());
    }
    private::json(
        &bundle.path.join("bundle.json"),
        &json!({
            "schema_version": 1, "id": bundle.id, "state": "success", "operation": request.operation, "identity": identity, "request": invocation,
        }),
    )
}

fn run_targets(
    root: &Path,
    bundle: &Bundle,
    request: &Request,
    deadline: Deadline,
    invocation: &Value,
    identity: &Value,
) -> Result<(), String> {
    let limits = request.limits()?;
    let profile = request.profile.unwrap_or(Profile::Smoke);
    let reviewed_target = request
        .reviewed
        .as_ref()
        .map(|path| private::read_json(&path.join("review.json")))
        .transpose()?;
    if let Some(reviewed) = &reviewed_target
        && !TARGETS
            .iter()
            .any(|target| reviewed["target"] == target.name)
    {
        return Err("unknown reviewed corpus target".into());
    }
    let mut outcomes = Vec::new();
    let mut failed = false;
    for original in TARGETS {
        let selected = request
            .selected
            .as_ref()
            .is_none_or(|names| names.iter().any(|name| name == original.name));
        let skipped = if !selected {
            Some("not-selected")
        } else if deadline.expired() {
            Some("whole-run-deadline")
        } else if failed && request.profile.is_none() {
            Some("prior-target-failed")
        } else {
            None
        };
        if let Some(reason) = skipped {
            outcomes.push(json!({"target": original.name, "status": "skipped", "reason": reason, "requested": selected}));
            if selected {
                failed = true;
            }
        } else {
            let target = Target {
                max_len: profile.maximum_input(original.name)?,
                ..*original
            };
            let imported = request.reviewed.as_deref().filter(|_| {
                reviewed_target
                    .as_ref()
                    .is_some_and(|value| value["target"] == target.name)
            });
            let result = campaign(
                root, bundle, target, identity, limits, imported, None, request, profile, deadline,
            );
            if let Err(error) = &result {
                failed = true;
                let path = bundle.path.join(format!("{}-failure.txt", target.name));
                let _ = private::write(&path, error.as_bytes());
            }
            outcomes.push(json!({"target": target.name, "status": if result.is_ok() { "pass" } else { "fail" }, "requested": true, "manifest": format!("{}/manifest.json", target.name)}));
        }
        private::json(
            &bundle.path.join("outcomes.json"),
            &json!({"schema_version": 1, "profile": profile.record(), "targets": outcomes, "request": invocation}),
        )?;
    }
    if failed {
        return Err("one or more requested fuzz targets failed or were skipped".into());
    }
    Ok(())
}

fn captured(
    root: &Path,
    directory: &Path,
    label: &str,
    program: &str,
    arguments: &[String],
    timeout: Duration,
    deadline: Deadline,
) -> Result<String, String> {
    let directory = directory.join(label);
    private::directory(&directory)?;
    let mut command = process::command(root, program, arguments);
    let (timeout, supervisor) = deadline.supervisor(timeout);
    private::json(
        &directory.join("command.json"),
        &json!({"program": program, "arguments": arguments, "supervisor":supervisor,
            "outcome": if timeout.is_zero() {"not-started-deadline"} else {"preparing"}}),
    )?;
    if timeout.is_zero() {
        return Err("whole-run deadline exhausted".into());
    }
    let outcome = process::run(&mut command, &directory, timeout, process::LOG_LIMIT)?;
    private::json(
        &directory.join("command.json"),
        &json!({"program": program, "arguments": arguments, "supervisor":supervisor, "outcome": outcome.name()}),
    )?;
    if outcome != Outcome::Success {
        return Err(format!("{label}: {}", outcome.name()));
    }
    fs::read_to_string(directory.join("stdout.log")).map_err(|error| error.to_string())
}

pub(crate) fn observe_identity(
    root: &Path,
    directory: &Path,
    deadline: Deadline,
) -> Result<Value, String> {
    let timeout = Duration::from_secs(30);
    let revision = captured(
        root,
        directory,
        "revision",
        "git",
        &["rev-parse".into(), "HEAD".into()],
        timeout,
        deadline,
    )?;
    let paths = captured(
        root,
        directory,
        "sources",
        "git",
        &[
            "ls-files".into(),
            "--cached".into(),
            "--others".into(),
            "--exclude-standard".into(),
            "-z".into(),
        ],
        timeout,
        deadline,
    )?;
    let sources = source_inventory(root, &paths)?;
    let rustc = captured(
        root,
        directory,
        "rustc",
        "rustc",
        &[format!("+{}", crate::FUZZ_TOOLCHAIN), "-vV".into()],
        timeout,
        deadline,
    )?;
    let compiler_path = captured(
        root,
        directory,
        "compiler-path",
        "rustup",
        &[
            "which".into(),
            "--toolchain".into(),
            crate::FUZZ_TOOLCHAIN.into(),
            "rustc".into(),
        ],
        timeout,
        deadline,
    )?;
    let cargo = captured(
        root,
        directory,
        "cargo",
        "cargo",
        &[format!("+{}", crate::FUZZ_TOOLCHAIN), "-vV".into()],
        timeout,
        deadline,
    )?;
    let fuzz = captured(
        root,
        directory,
        "cargo-fuzz",
        "cargo",
        &["fuzz".into(), "--version".into()],
        timeout,
        deadline,
    )?;
    if fuzz.trim() != crate::CARGO_FUZZ_VERSION {
        return Err("cargo-fuzz version drift".into());
    }
    let host = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or("compiler host identity missing")?;
    let mut locks = BTreeMap::new();
    for path in [
        "Cargo.lock",
        "cargo-bazel-lock.json",
        "MODULE.bazel.lock",
        "crates/rustleaks-core/fuzz/Cargo.lock",
        "crates/rustleaks-sources/fuzz/Cargo.lock",
        "crates/rustleaks-report/fuzz/Cargo.lock",
    ] {
        locks.insert(path, sha256_file(&root.join(path))?);
    }
    Ok(json!({
        "revision": revision.trim(), "source_tree_sha256": sha256_bytes(&serde_json::to_vec(&sources).map_err(|error| error.to_string())?),
        "locks": locks, "rules_sha256": sha256_file(&root.join("crates/rustleaks-core/default/gitleaks.toml"))?,
        "rustc": rustc, "rustc_binary_sha256": sha256_file(Path::new(compiler_path.trim()))?,
        "cargo": cargo, "cargo_fuzz": fuzz.trim(), "toolchain": crate::FUZZ_TOOLCHAIN,
        "host": host, "sanitizer": "address", "trace_compares": false,
        "environment_policy": "clear except PATH HOME CARGO_HOME RUSTUP_HOME TMPDIR; offline Cargo; LC_ALL=C; umask=077",
    }))
}

fn source_inventory<'a>(root: &Path, paths: &'a str) -> Result<BTreeMap<&'a str, Value>, String> {
    let mut sources = BTreeMap::new();
    for path in paths.split('\0').filter(|path| !path.is_empty()) {
        let path_object = Path::new(path);
        if path_object.is_absolute()
            || path_object
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err("invalid source inventory path".into());
        }
        let absolute = root.join(path_object);
        let metadata = fs::symlink_metadata(&absolute).map_err(|error| error.to_string())?;
        let hash = if metadata.file_type().is_symlink() {
            sha256_bytes(
                fs::read_link(&absolute)
                    .map_err(|error| error.to_string())?
                    .as_os_str()
                    .as_encoded_bytes(),
            )
        } else if metadata.is_file() {
            sha256_file(&absolute)?
        } else {
            return Err("non-file in fuzz source inventory".into());
        };
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            metadata.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0;
        sources.insert(
            path,
            json!({"sha256": hash, "mode": mode, "symlink": metadata.file_type().is_symlink()}),
        );
    }
    Ok(sources)
}

fn build(root: &Path, directory: &Path, deadline: Deadline) -> Result<(), String> {
    for workspace in ["rustleaks-core", "rustleaks-sources", "rustleaks-report"] {
        captured(
            root,
            directory,
            &format!("check-{workspace}"),
            "cargo",
            &[
                format!("+{}", crate::FUZZ_TOOLCHAIN),
                "check".into(),
                "--locked".into(),
                "--offline".into(),
                "--all-targets".into(),
                "--manifest-path".into(),
                format!("crates/{workspace}/fuzz/Cargo.toml"),
            ],
            Duration::from_mins(10),
            deadline,
        )?;
    }
    Ok(())
}

fn seed(
    root: &Path,
    directory: &Path,
    target: Target,
    profile: Profile,
    deadline: Deadline,
) -> Result<PathBuf, String> {
    let generated = directory.join("generated");
    private::directory(&generated)?;
    let corpus = generated.join("corpus");
    match target.name {
        "go_regex" | "archive" => {
            let executable = std::env::current_exe().map_err(|error| error.to_string())?;
            let executable = executable.to_str().ok_or("non-UTF-8 xtask path")?;
            let arguments = if target.name == "go_regex" {
                vec![
                    "generate".into(),
                    "regex-fuzz-seeds".into(),
                    root.join("compat/regex-corpus/requests-v1.jsonl")
                        .to_string_lossy()
                        .into_owned(),
                    corpus.to_string_lossy().into_owned(),
                ]
            } else {
                vec![
                    "generate".into(),
                    "archive-fuzz-seeds".into(),
                    generated.to_string_lossy().into_owned(),
                ]
            };
            // The generator's own output files inherit umask 077 from the
            // wrapper, including retained provenance and license files.
            captured(
                root,
                directory,
                "seed-generation",
                executable,
                &arguments,
                Duration::from_mins(1),
                deadline,
            )?;
        }
        _ => {
            private::directory(&corpus)?;
            corpus::copy(
                &target.directory(root).join("seeds").join(target.name),
                &corpus,
                target.max_len,
            )?;
        }
    }
    for (name, input) in source_frame::seeds(target.name) {
        if input.len() as u64 > target.max_len {
            return Err("source frame seed exceeds the target input bound".into());
        }
        private::write(&corpus.join(name), &input)?;
    }
    if profile == Profile::Deep {
        let input =
            campaign_profile::deep_seed(target.name).ok_or("missing structured deep seed")?;
        if input.len() as u64
            <= TARGETS
                .iter()
                .find(|original| original.name == target.name)
                .ok_or("unknown target")?
                .max_len
            || input.len() as u64 > target.max_len
        {
            return Err("deep seed does not cross the smoke input bound".into());
        }
        private::write(&corpus.join("structured-deep-input"), &input)?;
    }
    Ok(corpus)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One audited target lifecycle retains failures at every phase.
fn campaign(
    root: &Path,
    bundle: &Bundle,
    target: Target,
    environment: &Value,
    limits: Limits,
    reviewed: Option<&Path>,
    saved: Option<(&Path, &Value)>,
    request: &Request,
    profile: Profile,
    deadline: Deadline,
) -> Result<(), String> {
    let directory = bundle.path.join(target.name);
    private::directory(&directory)?;
    private::json(
        &directory.join("manifest.json"),
        &json!({
            "schema_version": 1, "target": target.name, "operation": request.operation,
            "environment": environment, "outcome": "preparing",
            "limits": {"runs": limits.runs, "seconds": limits.seconds, "seed": limits.seed},
        }),
    )?;
    let seeds = seed(root, &directory, target, profile, deadline)?;
    let dictionary = target
        .directory(root)
        .join("dictionaries")
        .join(format!("{}.dict", target.name));
    let identity = json!({"environment": environment, "target": target.name, "features": target.features,
        "manifest_sha256": sha256_file(&target.directory(root).join("Cargo.toml"))?,
        "dictionary_sha256": sha256_file(&dictionary)?, "seeds": corpus::inventory(&seeds, target.max_len)?, "max_len": target.max_len,
        "profile": profile.record()});
    if let Some((_, record)) = saved
        && record["identity"] != identity
    {
        return Err("saved fuzz target provenance is stale or incompatible".into());
    }
    let initial = directory.join("initial-corpus");
    let working = directory.join("corpus");
    let artifacts = directory.join("artifacts");
    for path in [&initial, &working, &artifacts] {
        private::directory(path)?;
    }
    if let Some((source, record)) = saved {
        let (name, inventory) = if request.operation == "minimize" {
            if record["outcome"] != "success" {
                return Err("corpus minimization requires a successful campaign".into());
            }
            ("final-corpus", &record["final_corpus"])
        } else {
            ("initial-corpus", &record["initial_corpus"])
        };
        corpus::verify(&source.join(name), inventory, target.max_len)?;
        corpus::copy(&source.join(name), &initial, target.max_len)?;
    } else {
        corpus::copy(&seeds, &initial, target.max_len)?;
        if let Some(reviewed) = reviewed {
            corpus::import(reviewed, &initial, &identity, target.name, target.max_len)?;
        }
    }
    let initial_inventory = corpus::inventory(&initial, target.max_len)?;
    if request.operation != "minimize" {
        corpus::copy(&initial, &working, target.max_len)?;
    }
    private::write(
        &directory.join("dictionary.dict"),
        &fs::read(&dictionary).map_err(|error| error.to_string())?,
    )?;
    let mut inputs = vec![working.clone()];
    if request.operation == "minimize" {
        inputs.push(initial.clone());
    }
    if let Some(hash) = &request.artifact {
        let (source, record) = saved.ok_or("missing artifact source")?;
        let files = record["artifacts"]["files"]
            .as_object()
            .ok_or("missing artifact inventory")?;
        let (name, _) = files
            .iter()
            .find(|(_, value)| value["sha256"] == hash.as_str())
            .ok_or("artifact hash not found")?;
        corpus::verify(
            &source.join("artifacts"),
            &record["artifacts"],
            target.max_len,
        )?;
        let input = directory.join("reproducer");
        private::write(
            &input,
            &fs::read(source.join("artifacts").join(name)).map_err(|error| error.to_string())?,
        )?;
        inputs = vec![input];
    }
    let arguments = arguments(
        root,
        target,
        &directory,
        &inputs,
        limits,
        &request.operation,
        environment["host"].as_str().ok_or("missing fuzz host")?,
    );
    let mut record = json!({"schema_version": 1, "target": target.name, "operation": request.operation, "profile": profile.record(),
        "identity": identity, "limits": {"runs": limits.runs, "seconds": limits.seconds, "seed": limits.seed,
            "timeout_seconds": 5, "rss_limit_mb": 2048, "max_len": target.max_len, "log_bytes": process::LOG_LIMIT},
        "program": "cargo", "arguments": arguments, "initial_corpus": initial_inventory,
        "outcome": "running", "source_artifact_sha256": request.artifact,
    });
    record["cache_key_sha256"] = json!(sha256_bytes(&serde_json::to_vec(&json!({
        "identity": record["identity"], "initial_corpus": record["initial_corpus"], "limits": record["limits"],
    })).map_err(|error| error.to_string())?));
    private::json(&directory.join("manifest.json"), &record)?;
    let logs = directory.join("logs");
    private::directory(&logs)?;
    let mut command = process::command(root, "cargo", &arguments);
    let binary_root = root.join("target/private-fuzz-build");
    command.env("CARGO_TARGET_DIR", &binary_root);
    command.env("RUSTLEAKS_FUZZ_PROFILE", profile.name());
    let (timeout, supervisor) = deadline.supervisor(Duration::from_secs(limits.seconds + 120));
    record["supervisor"] = supervisor;
    if timeout.is_zero() {
        record["outcome"] = json!("not-started-deadline");
    }
    private::json(&directory.join("manifest.json"), &record)?;
    if timeout.is_zero() {
        return Err("whole-run deadline exhausted".into());
    }
    let outcome = process::run_monitored(&mut command, &logs, timeout, process::LOG_LIMIT, || {
        let result = corpus::check_bounds(&working, target.max_len)
            .and_then(|()| corpus::check_bounds(&artifacts, target.max_len));
        if let Err(error) = &result
            && !directory.join("monitor-failure.txt").exists()
        {
            private::write(&directory.join("monitor-failure.txt"), error.as_bytes())?;
        }
        result
    })?;
    record["outcome"] = json!(outcome.name());
    if directory.join("monitor-failure.txt").is_file() {
        record["monitor_failure_sha256"] =
            json!(sha256_file(&directory.join("monitor-failure.txt"))?);
    }
    // Persist termination first. A malformed/oversized artifact must not hide
    // the original failure or cause the bundle to be discarded.
    private::json(&directory.join("manifest.json"), &record)?;
    record["artifacts"] = corpus::inventory(&artifacts, target.max_len)?;
    let final_corpus = directory.join("final-corpus");
    private::directory(&final_corpus)?;
    record["final_corpus"] = corpus::copy(&working, &final_corpus, target.max_len)?;
    record["stdout_sha256"] = json!(sha256_file(&logs.join("stdout.log"))?);
    record["stderr_sha256"] = json!(sha256_file(&logs.join("stderr.log"))?);
    record["feedback"] = feedback(&String::from_utf8_lossy(
        &fs::read(logs.join("stderr.log")).map_err(|error| error.to_string())?,
    ));
    record["classification"] = json!(classify(outcome, &record["artifacts"]));
    let binary = binary_root
        .join(environment["host"].as_str().ok_or("missing fuzz host")?)
        .join("release")
        .join(target.name);
    record["binary_sha256"] = if binary.is_file() {
        json!(sha256_file(&binary)?)
    } else {
        Value::Null
    };
    record["cargo_target_dir"] = json!(binary_root);
    if let Some((_, previous)) = saved
        && !previous["binary_sha256"].is_null()
    {
        record["binary_matches_source_bundle"] =
            json!(record["binary_sha256"] == previous["binary_sha256"]);
    }
    private::json(&directory.join("manifest.json"), &record)?;
    println!(
        "fuzz: target {}; {}; corpus files {}; artifacts {}; bundle {}",
        target.name,
        outcome.name(),
        record["final_corpus"]["files"]
            .as_object()
            .map_or(0, serde_json::Map::len),
        record["artifacts"]["files"]
            .as_object()
            .map_or(0, serde_json::Map::len),
        bundle.id
    );
    if outcome != Outcome::Success {
        return Err(format!("target {}: {}", target.name, outcome.name()));
    }
    if record["binary_sha256"].is_null() {
        return Err("successful fuzz run omitted its compiled binary identity".into());
    }
    if record["binary_matches_source_bundle"] == false {
        return Err(
            "replayed fuzz binary differs from the saved binary; reproduction is not exact".into(),
        );
    }
    Ok(())
}

fn arguments(
    root: &Path,
    target: Target,
    directory: &Path,
    inputs: &[PathBuf],
    limits: Limits,
    operation: &str,
    host: &str,
) -> Vec<String> {
    let mut arguments = vec![
        format!("+{}", crate::FUZZ_TOOLCHAIN),
        "fuzz".into(),
        "run".into(),
        "--fuzz-dir".into(),
        target.directory(root).to_string_lossy().into_owned(),
        "--no-trace-compares".into(),
        "--sanitizer".into(),
        "address".into(),
        "--target".into(),
        host.into(),
        "--target-dir".into(),
        root.join("target/private-fuzz-build")
            .to_string_lossy()
            .into_owned(),
        target.name.into(),
    ];
    arguments.extend(
        inputs
            .iter()
            .map(|path| path.to_string_lossy().into_owned()),
    );
    arguments.extend([
        "--".into(),
        format!(
            "-runs={}",
            if operation == "reproduce" {
                1
            } else {
                limits.runs
            }
        ),
        format!("-max_total_time={}", limits.seconds),
        "-timeout=5".into(),
        "-rss_limit_mb=2048".into(),
        format!("-seed={}", limits.seed),
        format!("-dict={}", directory.join("dictionary.dict").display()),
        format!(
            "-artifact_prefix={}/",
            directory.join("artifacts").display()
        ),
    ]);
    // libFuzzer's crash minimizer sets its input limit from the validated
    // reproducer and asserts that -max_len has not already initialized it.
    if operation != "tmin" {
        arguments.push(format!("-max_len={}", target.max_len));
    }
    if operation == "minimize" {
        arguments.push("-merge=1".into());
        arguments.push(format!(
            "-merge_control_file={}",
            directory.join("merge-control").display()
        ));
    }
    if operation == "tmin" {
        arguments.push("-minimize_crash=1".into());
        arguments.push(format!(
            "-exact_artifact_path={}",
            directory.join("artifacts/minimized-input").display()
        ));
    }
    arguments
}

/// Parse numeric libFuzzer feedback only; never copy diagnostic lines publicly.
fn feedback(stderr: &str) -> Value {
    let mut coverage = None;
    let mut features = None;
    let mut executions = None;
    for line in stderr.lines().filter(|line| line.starts_with('#')) {
        let mut words = line.split_whitespace();
        if let Some(value) = words
            .next()
            .and_then(|word| word.strip_prefix('#'))
            .and_then(|word| word.parse::<u64>().ok())
        {
            executions = Some(value);
        }
        while let Some(word) = words.next() {
            if word == "cov:" {
                coverage = words
                    .next()
                    .and_then(|word| word.parse::<u64>().ok())
                    .or(coverage);
            } else if word == "ft:" {
                features = words
                    .next()
                    .and_then(|word| word.parse::<u64>().ok())
                    .or(features);
            }
        }
    }
    json!({"scope": "libfuzzer-instrumented-feedback-not-source-coverage", "covered_edges": coverage, "features": features, "executions": executions})
}
fn classify(outcome: Outcome, artifacts: &Value) -> &'static str {
    if outcome == Outcome::Timeout {
        return "runner-timeout";
    }
    if let Some(files) = artifacts["files"].as_object() {
        if files.keys().any(|name| name.starts_with("oom-")) {
            return "out-of-memory";
        }
        if files.keys().any(|name| name.starts_with("timeout-")) {
            return "input-timeout";
        }
        if files
            .keys()
            .any(|name| name.starts_with("crash-") || name.starts_with("leak-"))
        {
            return "crash-or-sanitizer";
        }
    }
    outcome.name()
}
