//! Scan the large fixture cases and compare each report with its answers.
//!
//! This is the only part of the fixtures command that runs a scanner. It is a
//! manual check. No test, `just ci` or qualify run starts it. Its output names
//! units and counts, never a planted value.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{private, sha256_bytes, verification};

#[cfg(test)]
#[path = "check_tests.rs"]
mod tests;

/// The example profile in `docs/user/complete-scanning.md`, byte for byte.
/// It is a diagnosis profile, not a production default.
const ORIGINAL_LIMITS: &str = "\
# Example profile. These values are a starting point, not tuned defaults.
version=1
target_bytes=8388608
operation_original_bytes=268435456
operation_fragments=200000
operation_issues=1024
workers=1
queue_capacity=1
fragment_decoded_bytes=33554432
operation_decoded_bytes=134217728
fragment_work_units=10000000
operation_work_units=100000000
fragment_finding_records=100000
operation_finding_records=200000
fragment_finding_payload_bytes=33554432
operation_finding_payload_bytes=67108864
fragment_collected_spans=500000
operation_collected_spans=2000000
fragment_normalization_bytes=268435456
operation_normalization_bytes=536870912
archive_entries=10000
archive_member_bytes=8388608
archive_total_bytes=33554432
archive_spool_bytes=8388608
git_patch_bytes=33554432
git_patch_lines=500000
git_stderr_bytes=1048576
git_blob_bytes=8388608
git_metadata_bytes=1048576
git_path_bytes=65536
git_files=100000
git_hunks=200000
scm_link_bytes=4194304
operation_scm_link_bytes=33554432
";

const USAGE: &str = "usage: perf fixtures --check <absolute-fixture-directory> [--cli <absolute-path>] [--profile <absolute-path>]";
const DEFAULT_CLI: &str = "bazel-bin/crates/rustleaks-cli/rustleaks";
const PACKS: [&str; 3] = [
    "rustleaks-extra-v1",
    "rustleaks-providers-v1",
    "rustleaks-connections-v1",
];
const JUDGED_RULE: &str = "github-pat";
const STATUS_PREFIX: &str = "rustleaks_scan_status";
const PROFILE_LIMIT: u64 = 16 * 1024;
const MANIFEST_LIMIT: u64 = 128 * 1024 * 1024;
const INPUT_LIMIT: u64 = 2 * 1024 * 1024;
const REPORT_LIMIT: u64 = 1024 * 1024 * 1024;
const STDERR_LIMIT: u64 = 64 * 1024 * 1024;
/// The CLI gets `--timeout 600`. This later deadline only catches a hung child.
const CHILD_DEADLINE: Duration = Duration::from_mins(11);

#[derive(Debug, PartialEq, Eq)]
struct Request {
    directory: PathBuf,
    cli: Option<PathBuf>,
    profile: Option<PathBuf>,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut directory = None;
        let mut cli = None;
        let mut profile = None;
        let mut arguments = arguments.iter();
        while let Some(flag) = arguments.next() {
            let slot = match flag.as_str() {
                "--check" => &mut directory,
                "--cli" => &mut cli,
                "--profile" => &mut profile,
                _ => return Err(USAGE.into()),
            };
            let path = PathBuf::from(arguments.next().ok_or(USAGE)?);
            if slot.is_some() {
                return Err(USAGE.into());
            }
            if !path.is_absolute() {
                return Err(format!("{flag} requires an absolute path"));
            }
            *slot = Some(path);
        }
        Ok(Self {
            directory: directory.ok_or(USAGE)?,
            cli,
            profile,
        })
    }
}

/// One `rustleaks_scan_status` line, split into its `key=value` fields.
#[derive(Debug, PartialEq, Eq)]
struct Status(BTreeMap<String, String>);

impl Status {
    fn get(&self, key: &str) -> &str {
        self.0.get(key).map_or("none", String::as_str)
    }
}

fn parse_status(stderr: &str) -> Result<Status, String> {
    let mut lines = stderr
        .lines()
        .filter(|line| line.split_ascii_whitespace().next() == Some(STATUS_PREFIX));
    let line = lines.next().ok_or("no status line")?;
    if lines.next().is_some() {
        return Err("more than one status line".into());
    }
    let mut fields = BTreeMap::new();
    for token in line.split_ascii_whitespace().skip(1) {
        let (key, value) = token.split_once('=').ok_or("malformed status field")?;
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err("repeated status field".into());
        }
    }
    let status = Status(fields);
    for required in ["status", "reason", "resource", "budget_scope", "work_units"] {
        if !status.0.contains_key(required) {
            let mut problem = format!("status line lacks {required}");
            if let Some(reason) = status.0.get("reason") {
                let _ = write!(problem, "; reason={}", shown("reason", reason));
            }
            return Err(problem);
        }
    }
    Ok(status)
}

/// The comparison key. Columns are not compared.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    case: String,
    value: String,
    line: u64,
    depth: u64,
}

fn expected_keys(manifest: &Value) -> Result<Vec<Key>, String> {
    let case = manifest["id"].as_str().ok_or("manifest lacks an id")?;
    let depth = manifest["decode_depth"]
        .as_u64()
        .ok_or("manifest lacks a decode depth")?;
    let position = if depth == 0 {
        "plaintext_position"
    } else {
        "source_carrier_position"
    };
    manifest["plants"]
        .as_array()
        .ok_or("manifest lacks plants")?
        .iter()
        .map(|plant| {
            Ok(Key {
                case: case.to_owned(),
                value: plant["value"]
                    .as_str()
                    .ok_or("plant lacks a value")?
                    .to_owned(),
                line: plant[position]["start"]["line"]
                    .as_u64()
                    .ok_or("plant lacks a start line")?,
                depth,
            })
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// Scan `DIR/inputs/<id>/`, which holds only `input.txt`.
    Input(String),
    /// Scan a private directory holding each case as `<id>.txt`.
    View,
}

#[derive(Debug)]
struct Unit {
    name: String,
    target: Target,
    cases: Vec<String>,
    expected: Vec<Key>,
}

impl Unit {
    fn case_for_file(&self, file: &str) -> Option<&str> {
        let name = Path::new(file).file_name()?.to_str()?;
        match &self.target {
            Target::Input(id) => (name == "input.txt").then_some(id.as_str()),
            Target::View => {
                let id = name.strip_suffix(".txt")?;
                self.cases
                    .iter()
                    .map(String::as_str)
                    .find(|case| *case == id)
            }
        }
    }
}

struct Selection {
    family: &'static str,
    units: Vec<Unit>,
    index: BTreeMap<String, usize>,
}

impl Selection {
    fn new(family: &str) -> Result<Self, String> {
        let family = match family {
            "boundaries" => "boundaries",
            "density" => "density",
            "decoded-carrier" => "decoded-carrier",
            _ => return Err("no check subset for this family".into()),
        };
        Ok(Self {
            family,
            units: Vec::new(),
            index: BTreeMap::new(),
        })
    }

    /// The unit for a case, or `None` when the case is outside the subset.
    fn unit_name(&self, manifest: &Value) -> Result<Option<String>, String> {
        let id = manifest["id"].as_str().ok_or("manifest lacks an id")?;
        Ok(match self.family {
            "boundaries" => {
                let anchor = manifest["details"]["anchor_byte"]
                    .as_u64()
                    .ok_or("boundary manifest lacks an anchor")?;
                let kind = if manifest["decode_depth"] == 0 {
                    "raw"
                } else {
                    "base64"
                };
                Some(format!("boundary-{kind}-{anchor}"))
            }
            "density" => matches!(manifest["input_bytes"].as_u64(), Some(524_288 | 2_097_152))
                .then(|| id.to_owned()),
            _ => (manifest["details"]["inner_records"] == 4_096).then(|| id.to_owned()),
        })
    }

    fn add(&mut self, manifest: &Value) -> Result<(), String> {
        let Some(name) = self.unit_name(manifest)? else {
            return Ok(());
        };
        let id = manifest["id"].as_str().ok_or("manifest lacks an id")?;
        if manifest["expected_canonical_family"] != JUDGED_RULE {
            return Err(format!("case {id} does not expect the judged rule"));
        }
        let index = *self.index.entry(name.clone()).or_insert_with(|| {
            let target = if self.family == "boundaries" {
                Target::View
            } else {
                Target::Input(id.to_owned())
            };
            self.units.push(Unit {
                name,
                target,
                cases: Vec::new(),
                expected: Vec::new(),
            });
            self.units.len() - 1
        });
        let unit = &mut self.units[index];
        if unit.target != Target::View && !unit.cases.is_empty() {
            return Err("a single-input unit received a second case".into());
        }
        unit.cases.push(id.to_owned());
        unit.expected.extend(expected_keys(manifest)?);
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Observed {
    keys: Vec<Key>,
    other_rules: usize,
}

fn observed_keys(report: &Value, unit: &Unit) -> Result<Observed, String> {
    let entries = report.as_array().ok_or("report is not a JSON array")?;
    let mut observed = Observed::default();
    for entry in entries {
        if entry["RuleID"] != JUDGED_RULE {
            observed.other_rules += 1;
            continue;
        }
        let file = entry["File"].as_str().ok_or("finding lacks a file")?;
        let case = unit
            .case_for_file(file)
            .ok_or("finding names a file outside the scan unit")?;
        let mut depth = 0;
        for tag in entry["Tags"].as_array().map_or(&[][..], Vec::as_slice) {
            if let Some(value) = tag
                .as_str()
                .and_then(|tag| tag.strip_prefix("decode-depth:"))
            {
                depth = value.parse().map_err(|_| "malformed decode-depth tag")?;
            }
        }
        observed.keys.push(Key {
            case: case.to_owned(),
            value: entry["Secret"]
                .as_str()
                .ok_or("finding lacks a secret")?
                .to_owned(),
            line: entry["StartLine"]
                .as_u64()
                .ok_or("finding lacks a start line")?,
            depth,
        });
    }
    Ok(observed)
}

/// Multiset difference: (expected but not observed, observed but not expected).
fn compare(expected: &[Key], observed: &[Key]) -> (usize, usize) {
    let mut balance = BTreeMap::<&Key, isize>::new();
    for key in expected {
        *balance.entry(key).or_default() += 1;
    }
    for key in observed {
        *balance.entry(key).or_default() -= 1;
    }
    balance
        .values()
        .fold((0, 0), |(missing, extra), &count| match count {
            1.. => (missing + count.unsigned_abs(), extra),
            ..0 => (missing, extra + count.unsigned_abs()),
            0 => (missing, extra),
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Exact,
    Stopped,
    Failed,
}

impl Outcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

fn classify(exit: Option<i32>, status: Option<&Status>, missing: usize, extra: usize) -> Outcome {
    let Some(status) = status else {
        return Outcome::Failed;
    };
    let resource = status.get("resource");
    // A stop must name a real resource: not `none`, `unknown` or an odd value.
    let named = !matches!(resource, "none" | "unknown") && shown("resource", resource) == resource;
    match (exit, status.get("status"), status.get("reason")) {
        (Some(0 | 1), "complete", "complete") if missing == 0 && extra == 0 => Outcome::Exact,
        (Some(2), "incomplete", "resource_exhaustion") if named && extra == 0 => Outcome::Stopped,
        _ => Outcome::Failed,
    }
}

/// Status values are short fixed names or whole numbers. Anything else,
/// such as a token, is not echoed.
fn shown<'a>(key: &str, value: &'a str) -> &'a str {
    let allowed = |byte: u8| {
        if key == "work_units" {
            byte.is_ascii_digit()
        } else {
            byte.is_ascii_lowercase() || byte == b'_'
        }
    };
    if (1..=32).contains(&value.len()) && value.bytes().all(allowed)
        || key == "work_units" && value == "none"
    {
        value
    } else {
        "invalid"
    }
}

struct Evaluation {
    outcome: Outcome,
    status: Option<Status>,
    observed: usize,
    missing: usize,
    extra: usize,
    other_rules: usize,
    problem: Option<String>,
}

fn evaluate(
    unit: &Unit,
    exit: Option<i32>,
    stderr: Result<String, String>,
    report: Result<Value, String>,
) -> Evaluation {
    let (status, status_problem) = match stderr.and_then(|stderr| parse_status(&stderr)) {
        Ok(status) => (Some(status), None),
        Err(problem) => (None, Some(problem)),
    };
    let (observed, report_problem) = match report.and_then(|report| observed_keys(&report, unit)) {
        Ok(observed) => (observed, None),
        Err(problem) => (Observed::default(), Some(problem)),
    };
    let (missing, extra) = compare(&unit.expected, &observed.keys);
    let mut outcome = classify(exit, status.as_ref(), missing, extra);
    let problem = status_problem.or(report_problem);
    if problem.is_some() {
        outcome = Outcome::Failed;
    }
    Evaluation {
        outcome,
        status,
        observed: observed.keys.len(),
        missing,
        extra,
        other_rules: observed.other_rules,
        problem,
    }
}

fn line(unit: &Unit, evaluation: &Evaluation, exit: Option<i32>, seconds: f64) -> String {
    let field = |key: &str| {
        evaluation
            .status
            .as_ref()
            .map_or("none", |status| shown(key, status.get(key)))
            .to_owned()
    };
    let mut line = format!(
        "fixture-check {} outcome={} status={} reason={} resource={} budget_scope={} expected={} observed={} missing={} extra={} other_rules={} work_units={} seconds={seconds:.2}",
        unit.name,
        evaluation.outcome.name(),
        field("status"),
        field("reason"),
        field("resource"),
        field("budget_scope"),
        unit.expected.len(),
        evaluation.observed,
        evaluation.missing,
        evaluation.extra,
        evaluation.other_rules,
        field("work_units"),
    );
    if evaluation.outcome == Outcome::Failed {
        let exit = exit.map_or_else(|| "none".to_owned(), |code| code.to_string());
        let _ = write!(line, " exit={exit}");
        if let Some(problem) = &evaluation.problem {
            let _ = write!(line, " problem=\"{problem}\"");
        }
    }
    line
}

pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    let request = Request::parse(arguments)?;
    let root = fs::canonicalize(crate::workspace_root()?).map_err(|error| error.to_string())?;
    if request.directory.starts_with(&root) {
        return Err("checked fixtures must be outside the checkout".into());
    }
    verification::run(&request.directory)?;
    let cli = resolve_cli(request.cli.as_deref(), &root)?;
    if let Some(profile) = &request.profile {
        private::regular_file(profile, PROFILE_LIMIT).map_err(
            |_| "the profile must be a regular file of at most 16 KiB with no symlinks in its path",
        )?;
    }
    let inventory = private::read_json(&request.directory.join("inventory.json"))?;
    let family = inventory["family"]
        .as_str()
        .ok_or("inventory lacks a family")?;
    let mut selection = Selection::new(family)?;
    for case in inventory["cases"]
        .as_array()
        .ok_or("inventory lacks cases")?
    {
        let id = case["id"].as_str().ok_or("inventory case lacks an id")?;
        let path = request.directory.join("answers").join(format!("{id}.json"));
        private::regular_file(&path, MANIFEST_LIMIT)
            .map_err(|_| format!("answer for case {id} is not a bounded regular file"))?;
        let bytes = fs::read(&path).map_err(|error| error.to_string())?;
        let manifest = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        selection.add(&manifest)?;
    }
    let bundle = private::Bundle::new(None)?;
    if bundle.path.starts_with(&root) {
        let _ = fs::remove_dir(&bundle.path);
        return Err("the scratch folder must be outside the checkout; set TMPDIR".into());
    }
    let result = scan_units(
        &bundle.path,
        &request.directory,
        &selection,
        &cli,
        request.profile.as_deref(),
    );
    if let Err(error) = &result {
        eprintln!("fixture-check: {error}");
        eprintln!(
            "fixture-check: scratch folder kept at {}",
            bundle.path.display()
        );
    }
    bundle.finish_named(result, "fixture-check")
}

fn resolve_cli(cli: Option<&Path>, root: &Path) -> Result<PathBuf, String> {
    let path = match cli {
        Some(path) => path.to_owned(),
        // `bazel-bin` is a symlink, and checked paths reject symlinks.
        None => fs::canonicalize(root.join(DEFAULT_CLI)).map_err(
            |_| "build the CLI first: bazelisk build -c opt //crates/rustleaks-cli:rustleaks",
        )?,
    };
    private::checked_path(&path)
        .map_err(|_| "the CLI path must exist and must not contain symlinks")?;
    let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("the CLI must be a regular file".into());
    }
    Ok(path)
}

/// The fixed CLI invocation shared by every unit.
struct Scanner {
    cli: PathBuf,
    profile: PathBuf,
    ignore: PathBuf,
    home: PathBuf,
    temporary: PathBuf,
}

impl Scanner {
    fn new(bundle: &Path, cli: &Path, profile: Option<&Path>) -> Result<Self, String> {
        let scanner = Self {
            cli: cli.to_owned(),
            profile: profile.map_or_else(|| bundle.join("original.limits"), Path::to_owned),
            ignore: bundle.join("empty-ignore"),
            home: bundle.join("home"),
            temporary: bundle.join("tmp"),
        };
        private::directory(&scanner.home)?;
        private::directory(&scanner.temporary)?;
        private::write(&scanner.ignore, b"")?;
        if profile.is_none() {
            private::write(&scanner.profile, ORIGINAL_LIMITS.as_bytes())?;
        }
        Ok(scanner)
    }

    fn command(&self, target: &Path, report: &Path, stderr: &Path) -> Result<Command, String> {
        let mut command = Command::new(&self.cli);
        command
            .arg("dir")
            .arg(target)
            .args(PACKS.into_iter().flat_map(|pack| ["--native-pack", pack]))
            .arg("--complete-profile")
            .arg(&self.profile)
            .args([
                "--max-decode-depth",
                "5",
                "--max-archive-depth",
                "0",
                "--base64-mode",
                "compatible",
                "--no-banner",
                "--no-color",
                "--log-level",
                "warn",
                "--report-format",
                "json",
                "--report-path",
            ])
            .arg(report)
            .arg("--rustleaks-ignore-path")
            .arg(&self.ignore)
            .args(["--timeout", "600"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("HOME", &self.home)
            .env("TMPDIR", &self.temporary)
            .current_dir(&self.home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(private::file(stderr)?);
        Ok(command)
    }
}

/// The directory to scan for a unit. A view holds copies named `<id>.txt`.
fn target(unit: &Unit, unit_directory: &Path, directory: &Path) -> Result<PathBuf, String> {
    match &unit.target {
        Target::Input(id) => Ok(directory.join("inputs").join(id)),
        Target::View => {
            let view = unit_directory.join("view");
            private::directory(&view)?;
            for case in &unit.cases {
                let input = directory.join("inputs").join(case).join("input.txt");
                private::regular_file(&input, INPUT_LIMIT)
                    .map_err(|_| format!("input for case {case} is not a bounded regular file"))?;
                let bytes = fs::read(&input).map_err(|error| error.to_string())?;
                private::write(&view.join(format!("{case}.txt")), &bytes)?;
            }
            Ok(view)
        }
    }
}

fn scan_units(
    bundle: &Path,
    directory: &Path,
    selection: &Selection,
    cli: &Path,
    profile: Option<&Path>,
) -> Result<(), String> {
    let scanner = Scanner::new(bundle, cli, profile)?;
    let cli_sha256 =
        sha256_bytes(&fs::read(cli).map_err(|error| format!("cannot read the CLI: {error}"))?);
    println!(
        "fixture-check cli path={} sha256={cli_sha256}",
        cli.display()
    );
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut failed = Vec::new();
    for (index, unit) in selection.units.iter().enumerate() {
        let unit_directory = bundle.join(format!("unit-{index}"));
        let report = unit_directory.join("report.json");
        let stderr = unit_directory.join("stderr.txt");
        let setup = private::directory(&unit_directory)
            .and_then(|()| target(unit, &unit_directory, directory))
            .and_then(|target| scanner.command(&target, &report, &stderr));
        let mut command = setup.map_err(|error| format!("unit {} setup: {error}", unit.name))?;
        let started = Instant::now();
        let exit = wait(&mut command).map_err(|error| format!("unit {}: {error}", unit.name))?;
        let seconds = started.elapsed().as_secs_f64();
        let evaluation = evaluate(unit, exit, read_stderr(&stderr), read_report(&report));
        println!("{}", line(unit, &evaluation, exit, seconds));
        *counts.entry(evaluation.outcome.name()).or_default() += 1;
        if evaluation.outcome == Outcome::Failed {
            failed.push(unit.name.as_str());
        }
    }
    let count = |name| counts.get(name).copied().unwrap_or(0);
    println!(
        "fixture-check summary family={} units={} exact={} stopped={} failed={} cli_sha256={cli_sha256}",
        selection.family,
        selection.units.len(),
        count("exact"),
        count("stopped"),
        count("failed"),
    );
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} fixture-check units failed, including {}",
            failed.len(),
            failed[..failed.len().min(3)].join(", ")
        ))
    }
}

/// Exit code, or `None` after a signal or the hung-child deadline.
fn wait(command: &mut Command) -> Result<Option<i32>, String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start the CLI: {error}"))?;
    let deadline = Instant::now() + CHILD_DEADLINE;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(status.code());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn read_stderr(path: &Path) -> Result<String, String> {
    private::regular_file(path, STDERR_LIMIT)
        .map_err(|_| "stderr is not a bounded regular file".to_owned())?;
    let bytes = fs::read(path).map_err(|_| "stderr cannot be read".to_owned())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_report(path: &Path) -> Result<Value, String> {
    private::regular_file(path, REPORT_LIMIT).map_err(|_| "no bounded report file".to_owned())?;
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "report is not valid JSON".into())
}
