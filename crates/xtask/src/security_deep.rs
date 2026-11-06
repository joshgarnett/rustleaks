//! Optional serial local review. It does not change release qualification.

mod coverage;
mod evidence;
#[cfg(test)]
mod tests;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::fuzzing::profiles::{self, Deadline, Profile};
use crate::fuzzing::{self, private, process};
use crate::tooling::sha256_file;

const TARGETS: &[&str] = &[
    "go_regex",
    "config",
    "fragment_scan",
    "session",
    "archive",
    "reader_schedule",
    "git_patch",
    "template",
];
const STRESS: &[(&str, &str)] = &[
    ("core", "//crates/rustleaks-core:security_stress_test"),
    ("sources", "//crates/rustleaks-sources:security_stress_test"),
    ("report", "//crates/rustleaks-report:security_stress_test"),
];
const MIRI: &[(&str, &str, &str)] = &[
    (
        "decoder",
        "rustleaks-core",
        "decoder::tests::maps_nested_segments_to_the_original_candidate",
    ),
    (
        "session",
        "rustleaks-core",
        "session::tests::canonical_order_observes_raw_and_nested_state_without_deduplicating",
    ),
];

struct Request {
    output: Option<PathBuf>,
    profile: Profile,
    targets: Vec<String>,
    seconds: Option<u64>,
    seed: u64,
    deadline_seconds: u64,
    coverage: String,
    baseline: Option<PathBuf>,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut request = Self {
            output: None,
            profile: Profile::Deep,
            targets: TARGETS.iter().map(|name| (*name).into()).collect(),
            seconds: None,
            seed: 1,
            deadline_seconds: 7200,
            coverage: "auto".into(),
            baseline: None,
        };
        if !arguments.len().is_multiple_of(2) {
            return Err("security-deep options require values".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for pair in arguments.chunks_exact(2) {
            if !seen.insert(&pair[0]) {
                return Err("duplicate security-deep option".into());
            }
            match pair[0].as_str() {
                "--output" => request.output = Some(PathBuf::from(&pair[1])),
                "--profile" => request.profile = Profile::parse(&pair[1])?,
                "--targets" => request.targets = profiles::targets(&pair[1])?,
                "--seconds" => request.seconds = Some(profiles::bounded(&pair[1], 600, "seconds")?),
                "--seed" => request.seed = profiles::bounded(&pair[1], u64::from(u32::MAX), "seed")?,
                "--deadline-seconds" => request.deadline_seconds = profiles::bounded(&pair[1], 7200, "deadline-seconds")?,
                "--coverage" if ["auto", "off", "required"].contains(&pair[1].as_str()) => request.coverage.clone_from(&pair[1]),
                "--baseline" => request.baseline = Some(PathBuf::from(&pair[1])),
                _ => return Err("unknown security-deep option; expected --output, --profile, --targets, --seconds, --seed, --deadline-seconds, --coverage or --baseline".into()),
            }
        }
        Ok(request)
    }
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    private::supported()?;
    let request = Request::parse(arguments)?;
    let deadline = Deadline::new(Some(request.deadline_seconds));
    let bundle = private::Bundle::new(request.output.as_deref())
        .map_err(
            |_| "security-deep: output must be a new private directory with an existing parent",
        )?
        .retaining_success();
    let result = execute(root, &bundle, &request, deadline);
    bundle.finish_named(result, "security-deep")
}

struct Step {
    status: &'static str,
    reason: Option<&'static str>,
    data: Value,
}
impl Step {
    fn pass(data: Value) -> Self {
        Self {
            status: "pass",
            reason: None,
            data,
        }
    }
    fn fail(reason: &'static str, data: Value) -> Self {
        Self {
            status: "fail",
            reason: Some(reason),
            data,
        }
    }
    fn skipped(reason: &'static str) -> Self {
        Self {
            status: "skipped",
            reason: Some(reason),
            data: Value::Null,
        }
    }
}

struct Run<'a> {
    root: &'a Path,
    bundle: &'a private::Bundle,
    deadline: Deadline,
    started: Instant,
    report: Value,
}

impl Run<'_> {
    fn save(&self) -> Result<(), String> {
        private::json(&self.bundle.path.join("report.json"), &self.report)
    }

    fn stage(
        &mut self,
        name: &str,
        required: bool,
        action: impl FnOnce(&Path, &Path, Deadline) -> Result<Step, String>,
    ) -> Result<bool, String> {
        let directory = self.bundle.path.join(name);
        private::directory(&directory)?;
        let started = Instant::now();
        let step = if self.deadline.expired() {
            Step::skipped("whole-run-deadline")
        } else {
            match action(self.root, &directory, self.deadline) {
                Ok(step) => step,
                Err(error) => {
                    private::write(&directory.join("failure.txt"), error.as_bytes())?;
                    Step::fail("stage-error-see-private-log", Value::Null)
                }
            }
        };
        let passed = step.status == "pass";
        self.report["stages"].as_array_mut().ok_or("invalid report stage list")?.push(json!({"name": name, "required": required, "status": step.status, "reason": step.reason, "elapsed_ms": started.elapsed().as_millis(), "evidence": step.data}));
        self.save()?;
        println!(
            "security-deep: stage {name}; {}; bundle {}",
            step.status, self.bundle.id
        );
        Ok(passed)
    }
}

#[allow(clippy::too_many_lines)] // A serial plan preserves an explicit outcome for every requested stage.
fn execute(
    root: &Path,
    bundle: &private::Bundle,
    request: &Request,
    deadline: Deadline,
) -> Result<(), String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    if bundle.path.starts_with(&root) {
        return Err("private review output must be outside the source checkout".into());
    }
    private::json(
        &bundle.path.join("bundle.json"),
        &json!({"schema_version":1,"id":bundle.id,"state":"running","operation":"security-deep"}),
    )?;
    let mut run = Run {
        root: &root,
        bundle,
        deadline,
        started: Instant::now(),
        report: json!({"schema_version":1,"operation":"security-deep","profile":request.profile.record(),"requested_targets":request.targets,"campaign_seconds":request.seconds.unwrap_or(request.profile.seconds()),"seed":request.seed,"whole_run_deadline_seconds":request.deadline_seconds,"release_qualification_changed":false,"stages":[],"complete":false,"cleanup_grace_seconds":5,"memory_scope":"fuzz children retain 2048 MiB RSS limit; trusted builds, security tools and Miri have time/output limits, not a whole-pass RSS quota"}),
    };
    run.save()?;
    let mut identity = Value::Null;
    let observed = run.stage("identity", true, |root, directory, deadline| {
        identity = fuzzing::observe_identity(root, directory, deadline)?;
        Ok(Step::pass(identity.clone()))
    })?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let executable = executable.to_str().ok_or("non-UTF-8 xtask executable")?;
    run.stage("security-policy", true, |root, directory, deadline| {
        if !observed {
            return Ok(Step::skipped("identity-unavailable"));
        }
        let result = command(
            root,
            directory,
            "policy",
            executable,
            &["security-check".into()],
            deadline,
            1800,
            &[],
        )?;
        if result != process::Outcome::Success {
            return Ok(Step::fail(
                "policy-command-failed",
                json!({"outcome":result.name()}),
            ));
        }
        Ok(Step::pass(
            json!({"outcome":"success","scope":"unchanged repository security-check"}),
        ))
    })?;
    run.stage("dependency-evidence", true, |root, directory, deadline| {
        if !observed { return Ok(Step::skipped("identity-unavailable")); }
        let snapshot = evidence::snapshot(root, directory, &identity, deadline)?;
        let delta = evidence::compare(&snapshot, request.baseline.as_deref())?;
        private::json(&bundle.path.join("dependency-snapshot.json"), &snapshot)?;
        private::json(&bundle.path.join("dependency-delta.json"), &delta)?;
        Ok(Step::pass(json!({"snapshot_sha256":sha256_file(&bundle.path.join("dependency-snapshot.json"))?, "delta":delta})))
    })?;
    let stress_build = run.stage("stress-build", true, |root, directory, deadline| {
        if !observed { return Ok(Step::skipped("identity-unavailable")); }
        let mut arguments = vec!["--batch".into(),"build".into()];
        arguments.extend(STRESS.iter().map(|(_, target)| (*target).into()));
        let outcome = command(root, directory, "build", "bazelisk", &arguments, deadline, 1200, &[])?;
        Ok(if outcome == process::Outcome::Success { Step::pass(json!({"scope":"Bazel batch preparation; compiler memory is not bounded by fuzz RSS policy"})) } else { Step::fail("build-failed", json!({"outcome":outcome.name()})) })
    })?;
    for (name, label) in STRESS {
        run.stage(&format!("stress-{name}"), true, |root, directory, deadline| {
            if !stress_build { return Ok(Step::skipped("stress-build-unavailable")); }
            let outcome = command(root, directory, "resolve", "bazelisk", &["--batch".into(),"cquery".into(),(*label).into(),"--output=files".into()], deadline, 120, &[])?;
            require_success(outcome)?;
            let output = fs::read_to_string(directory.join("resolve/stdout.log")).map_err(|error| error.to_string())?;
            let candidates = output.lines().filter(|line| line.ends_with("/security_stress_test")).collect::<Vec<_>>();
            let [relative] = candidates.as_slice() else { return Err("stress target must resolve exactly one executable".into()); };
            let binary = root.join(relative);
            let outcome = command(root, directory, "driver", binary.to_str().ok_or("non-UTF-8 stress binary")?, &["--exact".into(),"security_stress_driver".into(),"--ignored".into(),"--nocapture".into()], deadline, 300, &[])?;
            require_success(outcome)?;
            let output = fs::read_to_string(directory.join("driver/stdout.log")).map_err(|error| error.to_string())?;
            let records = stress_records(&output, name)?;
            Ok(Step::pass(json!({"binary_sha256":sha256_file(&binary)?,"cases":records,"coverage_scope":"deterministic structured boundary tests; not fuzz coverage"})))
        })?;
    }
    for (name, package, case) in MIRI {
        run.stage(&format!("miri-{name}"), true, |root, directory, deadline| {
            if !observed { return Ok(Step::skipped("identity-unavailable")); }
            let target = root.join("target/private-deep-miri");
            let arguments = [format!("+{}",crate::MIRI_TOOLCHAIN),"miri".into(),"test".into(),"-p".into(),(*package).into(),"--lib".into(),"--locked".into(),"--offline".into(),(*case).into(),"--".into(),"--exact".into()];
            let outcome = command(root, directory, "miri", "cargo", &arguments, deadline, 600, &[("CARGO_TARGET_DIR",target.to_string_lossy().into_owned())])?;
            require_success(outcome)?;
            let stdout = fs::read_to_string(directory.join("miri/stdout.log")).map_err(|error| error.to_string())?;
            if !stdout.contains("test result: ok. 1 passed;") { return Err("Miri did not execute exactly one selected case".into()); }
            Ok(Step::pass(json!({"toolchain":crate::MIRI_TOOLCHAIN,"package":package,"case":case,"scope":"executed Miri path only"})))
        })?;
    }
    for target in TARGETS {
        let selected = request.targets.iter().any(|name| name == target);
        let fuzz_output = bundle.path.join(format!("campaign-{target}"));
        let passed = run.stage(&format!("fuzz-{target}"), selected, |root, _, deadline| {
            if !selected {
                return Ok(Step::skipped("not-selected"));
            }
            if !observed {
                return Ok(Step::skipped("identity-unavailable"));
            }
            let arguments = vec![
                "run".into(),
                "--profile".into(),
                request.profile.name().into(),
                "--targets".into(),
                (*target).into(),
                "--seconds".into(),
                request
                    .seconds
                    .unwrap_or(request.profile.seconds())
                    .to_string(),
                "--seed".into(),
                request.seed.to_string(),
                "--output".into(),
                fuzz_output.to_string_lossy().into_owned(),
            ];
            let result = fuzzing::run_bounded(root, &arguments, deadline);
            let record = private::read_json(&fuzz_output.join(target).join("manifest.json")).ok();
            let data = campaign_summary(record.as_ref());
            Ok(if result.is_ok() {
                Step::pass(data)
            } else {
                Step::fail("campaign-failed", data)
            })
        })?;
        run.stage(
            &format!("coverage-{target}"),
            selected && request.coverage == "required",
            |root, directory, deadline| {
                if !selected {
                    return Ok(Step::skipped("not-selected"));
                }
                if request.coverage == "off" {
                    return Ok(Step::skipped("operator-disabled"));
                }
                if !passed {
                    return Ok(Step::skipped("successful-corpus-unavailable"));
                }
                coverage::collect(
                    root,
                    directory,
                    &fuzz_output,
                    target,
                    &identity,
                    request.profile,
                    deadline,
                    request.coverage == "required",
                )
            },
        )?;
    }
    run.stage(
        "identity-verification",
        true,
        |root, directory, deadline| {
            if !observed {
                return Ok(Step::skipped("identity-unavailable"));
            }
            let after = fuzzing::observe_identity(root, directory, deadline)?;
            if after != identity {
                return Err("source or tool identity changed during the deep run".into());
            }
            Ok(Step::pass(json!({"unchanged":true})))
        },
    )?;
    let stages = run.report["stages"].as_array().ok_or("invalid stages")?;
    let (failed, skipped) = completion(stages);
    run.report["complete"] = json!(!failed);
    run.report["result"] = json!(if failed {
        "fail-or-incomplete"
    } else if skipped > 0 {
        "pass-with-explicit-skips"
    } else {
        "pass"
    });
    run.report["elapsed_ms"] = json!(run.started.elapsed().as_millis());
    run.report["source_identity"] = identity;
    run.save()?;
    private::json(
        &bundle.path.join("bundle.json"),
        &json!({"schema_version":1,"id":bundle.id,"state":if failed {"failure"} else {"success"},"operation":"security-deep","report_sha256":sha256_file(&bundle.path.join("report.json"))?}),
    )?;
    if failed {
        Err("deep profile has failed or incomplete requested stages".into())
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)] // All child limits and environment additions are explicit at the call site.
fn command(
    root: &Path,
    directory: &Path,
    label: &str,
    program: &str,
    arguments: &[String],
    deadline: Deadline,
    seconds: u64,
    environment: &[(&str, String)],
) -> Result<process::Outcome, String> {
    let directory = directory.join(label);
    private::directory(&directory)?;
    let (timeout, supervisor) = deadline.supervisor(Duration::from_secs(seconds));
    private::json(
        &directory.join("command.json"),
        &json!({"program":program,"arguments":arguments,"timeout_ms":timeout.as_millis(),"supervisor":supervisor,"environment":environment,"outcome":if timeout.is_zero(){"not-started-deadline"}else{"preparing"}}),
    )?;
    if timeout.is_zero() {
        return Err("whole-run deadline exhausted".into());
    }
    let mut command = process::command(root, program, arguments);
    command.env("BUILD_WORKSPACE_DIRECTORY", root);
    for (name, value) in environment {
        command.env(name, value);
    }
    let outcome = process::run(&mut command, &directory, timeout, process::LOG_LIMIT)?;
    private::json(
        &directory.join("command.json"),
        &json!({"program":program,"arguments":arguments,"timeout_ms":timeout.as_millis(),"supervisor":supervisor,"environment":environment,"outcome":outcome.name()}),
    )?;
    Ok(outcome)
}
fn require_success(outcome: process::Outcome) -> Result<(), String> {
    if outcome == process::Outcome::Success {
        Ok(())
    } else {
        Err(format!("child command: {}", outcome.name()))
    }
}
fn stress_records(stdout: &str, package: &str) -> Result<Vec<Value>, String> {
    let expected: &[&str] = match package {
        "core" => &[
            "regex-long-haystack",
            "session-large-metadata",
            "core-full-fragment",
            "core-nested-decode",
            "core-many-findings",
            "core-config-selection",
        ],
        "sources" => &[
            "archive-full-frame",
            "archive-member-exact",
            "archive-member-over",
            "archive-depth",
            "archive-entries-exact",
            "archive-entries-over",
            "archive-total-exact",
            "archive-total-over",
            "reader-long-schedule",
        ],
        "report" => &[
            "template-source",
            "template-output-exact",
            "template-output-over",
            "template-actions-exact",
            "template-actions-over",
        ],
        _ => return Err("unknown structured test package".into()),
    };
    let mut observed = std::collections::BTreeSet::new();
    let mut records = Vec::new();
    for line in stdout.lines().filter(|line| line.starts_with('{')) {
        let record: Value = serde_json::from_str(line).map_err(|_| "invalid stress report")?;
        if record["kind"] != "security-stress" || record["status"] != "pass" {
            return Err("stress driver reported an incomplete case".into());
        }
        let case = record["case"]
            .as_str()
            .ok_or("stress record omits case identity")?;
        if !observed.insert(case.to_owned()) {
            return Err("duplicate structured test case".into());
        }
        records.push(record);
    }
    if observed != expected.iter().map(|name| (*name).to_owned()).collect() {
        return Err("stress driver omitted or changed required case evidence".into());
    }
    Ok(records)
}
fn campaign_summary(record: Option<&Value>) -> Value {
    let Some(record) = record else {
        return json!({"classification":"preparation-failed","manifest_available":false});
    };
    let initial = record["initial_corpus"]["files"]
        .as_object()
        .map_or(0, serde_json::Map::len);
    let final_count = record["final_corpus"]["files"]
        .as_object()
        .map_or(0, serde_json::Map::len);
    let growth = i64::try_from(final_count)
        .ok()
        .zip(i64::try_from(initial).ok())
        .map(|(after, before)| after - before);
    json!({"classification":record["classification"],"outcome":record["outcome"],"limits":record["limits"],"profile":record["profile"],"feedback":record["feedback"],"initial_files":initial,"final_files":final_count,"corpus_growth_files":growth,"initial_bytes":record["initial_corpus"]["bytes"],"final_bytes":record["final_corpus"]["bytes"],"artifact_count":record["artifacts"]["files"].as_object().map_or(0,serde_json::Map::len),"binary_sha256":record["binary_sha256"]})
}

fn completion(stages: &[Value]) -> (bool, usize) {
    let failed = stages.iter().any(|stage| {
        stage["status"] == "fail" || (stage["required"] == true && stage["status"] != "pass")
    });
    let skipped = stages
        .iter()
        .filter(|stage| stage["status"] == "skipped")
        .count();
    (failed, skipped)
}
