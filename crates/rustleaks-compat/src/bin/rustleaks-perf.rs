//! Deterministic, unpublished performance and compatibility workload runner.
#![forbid(unsafe_code)]

#[path = "../perf/benchmark_data.rs"]
mod benchmark_data;

use std::error::Error;
use std::fs::{self, File};
use std::hint::black_box;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use benchmark_data::{
    AGGREGATE_PATH_INVALID, AGGREGATE_REGEX_INVALID, AGGREGATE_REGEX_VALID, BENCH_COMMITS,
    BENCH_PATH_PATTERNS, BENCH_REGEX_PATTERNS, BM_COMMIT_ALLOWED, BM_COMMIT_NOT_ALLOWED,
    BM_PATH_ALLOWED, BM_PATH_NOT_ALLOWED, BM_REGEX_ALLOWED, BM_REGEX_NOT_ALLOWED,
    PRIVATE_KEY_SAMPLE,
};
use rustleaks_core::config::{CompiledConfig, ConfigLoader, DEFAULT_CONFIG_SHA256};
use rustleaks_core::model::{Finding, Fragment, Location, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_core::{Engine, UPSTREAM_REVISION};
use rustleaks_report::{JsonReporter, Reporter, SarifReporter};
use rustleaks_sources::{
    CancellationToken, DEFAULT_CHUNK_SIZE, DirectoryOptions, DirectorySource, SourceRunner,
    SourceTermination,
};
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_INPUT_BYTES: usize = 1_048_576;
const HOSTILE_INPUT_BYTES: usize = 262_144;
const SOURCE_FILES: usize = 64;
const SOURCE_FILE_BYTES: usize = 131_072;
const REPORT_FINDINGS: usize = 10_000;
const MAX_ITERATIONS: usize = 10;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

const SIMPLE_CONFIG: &str = r#"
[[rules]]
id = "token"
description = "token"
regex = '''token=([A-Z0-9]{16})'''
secretGroup = 1
keywords = ["token"]
"#;

const HOSTILE_CONFIG: &str = r#"
[[rules]]
id = "hostile"
description = "hostile"
regex = '''(?:a|aa)*b'''
"#;

const CAPTURE_ENTROPY_CONFIG: &str = r#"
[[rules]]
id = "capture-entropy"
description = "capture-entropy"
regex = '''token=([A-Za-z0-9]+)'''
secretGroup = 1
entropy = 3.0
keywords = ["token"]
"#;

const WORKLOADS: &[&str] = &[
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Metric {
    logical_bytes: u64,
    result_count: u64,
    output_bytes: u64,
    fingerprint: u64,
}

#[derive(Serialize)]
struct Provenance {
    upstream_revision: &'static str,
    default_config_sha256: &'static str,
    rust_revision: String,
    rustc: String,
    package_version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    available_parallelism: usize,
    executable_bytes: u64,
    executable_fnv1a64: String,
}

#[derive(Serialize)]
struct Record<'a> {
    schema_version: u32,
    workload: &'a str,
    iterations: usize,
    elapsed_ns: u64,
    ns_per_iteration: u64,
    logical_bytes: u64,
    result_count: u64,
    output_bytes: u64,
    outcome_fnv1a64: String,
    invariant: &'static str,
    provenance: &'a Provenance,
}

#[derive(Clone, Copy)]
struct Expected {
    logical_bytes: u64,
    result_count: u64,
    output_bytes: u64,
    fingerprint: u64,
    description: &'static str,
}

struct Args {
    workloads: Vec<&'static str>,
    iterations: usize,
}

struct FixtureDir {
    path: PathBuf,
}

impl FixtureDir {
    fn create() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("rustleaks-perf-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        let line = b"ordinary source bytes without credential markers 0123456789\n";
        for index in 0..SOURCE_FILES {
            let mut bytes = Vec::with_capacity(SOURCE_FILE_BYTES);
            while bytes.len() + line.len() <= SOURCE_FILE_BYTES {
                bytes.extend_from_slice(line);
            }
            bytes.resize(SOURCE_FILE_BYTES, b'x');
            fs::write(path.join(format!("file-{index:03}.txt")), bytes)?;
        }
        Ok(Self { path })
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("rustleaks-perf-"));
        if safe_name && self.path.parent() == Some(std::env::temp_dir().as_path()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("rustleaks-perf: {error}");
        std::process::exit(2);
    }
}

fn real_main() -> Result<(), Box<dyn Error>> {
    let args = parse_args(std::env::args().skip(1))?;
    let provenance = provenance()?;
    for workload in args.workloads {
        let (elapsed_ns, metric) = run_workload(workload, args.iterations)?;
        let expected = expected(workload);
        validate_metric(workload, &metric, expected)?;
        let elapsed_ns = u64::try_from(elapsed_ns)?;
        let record = Record {
            schema_version: SCHEMA_VERSION,
            workload,
            iterations: args.iterations,
            elapsed_ns,
            ns_per_iteration: elapsed_ns / u64::try_from(args.iterations)?,
            logical_bytes: metric.logical_bytes,
            result_count: metric.result_count,
            output_bytes: metric.output_bytes,
            outcome_fnv1a64: format!("{:016x}", metric.fingerprint),
            invariant: expected.description,
            provenance: &provenance,
        };
        println!("{}", serde_json::to_string(&record)?);
    }
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, Box<dyn Error>> {
    let mut selected = None;
    let mut iterations = 1usize;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--list" => {
                for workload in WORKLOADS {
                    println!("{workload}");
                }
                std::process::exit(0);
            }
            "--workload" => selected = Some(args.next().ok_or("--workload requires a value")?),
            "--iterations" => {
                iterations = args
                    .next()
                    .ok_or("--iterations requires a value")?
                    .parse()?;
            }
            _ => return Err(format!("unknown argument '{arg}'").into()),
        }
    }
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        return Err(format!("iterations must be in 1..={MAX_ITERATIONS}").into());
    }
    let workloads = match selected.as_deref() {
        None | Some("all") => WORKLOADS.to_vec(),
        Some(id) => vec![
            *WORKLOADS
                .iter()
                .find(|candidate| **candidate == id)
                .ok_or_else(|| format!("unknown workload '{id}'"))?,
        ],
    };
    Ok(Args {
        workloads,
        iterations,
    })
}

fn provenance() -> Result<Provenance, Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    let metadata = executable.metadata()?;
    if metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err("benchmark executable exceeds 128 MiB provenance limit".into());
    }
    let mut file = File::open(&executable)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut hash = FNV_OFFSET;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash = fnv_extend(hash, &buffer[..read]);
    }
    Ok(Provenance {
        upstream_revision: UPSTREAM_REVISION,
        default_config_sha256: DEFAULT_CONFIG_SHA256,
        rust_revision: command_line("git", &["rev-parse", "HEAD"], 128),
        rustc: command_line("rustc", &["-Vv"], 1024),
        package_version: env!("CARGO_PKG_VERSION"),
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        available_parallelism: std::thread::available_parallelism()?.get(),
        executable_bytes: metadata.len(),
        executable_fnv1a64: format!("{hash:016x}"),
    })
}

fn command_line(program: &str, args: &[&str], maximum: usize) -> String {
    let Ok(output) = Command::new(program).args(args).output() else {
        return "unavailable".to_owned();
    };
    if !output.status.success() || output.stdout.len() > maximum {
        return "unavailable".to_owned();
    }
    String::from_utf8(output.stdout).map_or_else(
        |_| "unavailable".to_owned(),
        |value| value.trim().replace('\n', "; "),
    )
}

fn run_workload(id: &str, iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    match id {
        "default-compile" => run_default_compile(iterations),
        "default-no-keyword" => run_default_keyword(iterations, KeywordCase::None),
        "default-one-keyword" => run_default_keyword(iterations, KeywordCase::One),
        "default-many-keywords" => run_default_keyword(iterations, KeywordCase::Many),
        "default-positive" => run_default_positive(iterations),
        "regex-hostile-miss" => run_scan(
            iterations,
            engine(HOSTILE_CONFIG)?,
            Fragment::builder(vec![b'a'; HOSTILE_INPUT_BYTES]).build(),
            ScanOptions::default(),
        ),
        "regex-capture-entropy" => run_capture_entropy(iterations),
        "decode-five-level" => run_decode_five(iterations),
        "decode-large-base64-like" => run_scan(
            iterations,
            engine(SIMPLE_CONFIG)?,
            Fragment::builder(base64_like_input()).build(),
            ScanOptions::builder().max_decode_depth(5).build(),
        ),
        "source-directory-1" => run_source(iterations, 1),
        "source-directory-4" => run_source(iterations, 4),
        "report-json" => run_report(iterations, ReportKind::Json),
        "report-sarif" => run_report(iterations, ReportKind::Sarif),
        "bm-0001" => run_bm_commit(iterations, BM_COMMIT_ALLOWED, true),
        "bm-0002" => run_bm_commit(iterations, BM_COMMIT_NOT_ALLOWED, false),
        "bm-0003" => run_bm_aggregate_paths(iterations),
        "bm-0004" => run_bm_aggregate_regexes(iterations),
        "bm-0005" => run_bm_path(iterations, BM_PATH_ALLOWED, true),
        "bm-0006" => run_bm_path(iterations, BM_PATH_NOT_ALLOWED, false),
        "bm-0007" => run_bm_regex(iterations, BM_REGEX_ALLOWED, true),
        "bm-0008" => run_bm_regex(iterations, BM_REGEX_NOT_ALLOWED, false),
        _ => Err(format!("unknown workload '{id}'").into()),
    }
}

fn engine(config: &str) -> Result<Engine, Box<dyn Error>> {
    Ok(Engine::builder(ConfigLoader::new().load_toml(config)?).build()?)
}

fn run_default_compile(iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let start = Instant::now();
    let mut last = None;
    for _ in 0..iterations {
        let config = ConfigLoader::new().load_default()?;
        let metric = config_metric(&config);
        let detector = Engine::builder(config).build()?;
        black_box(&detector);
        last = Some(metric);
    }
    Ok((
        start.elapsed().as_nanos(),
        last.ok_or("no compile iteration")?,
    ))
}

#[derive(Clone, Copy)]
enum KeywordCase {
    None,
    One,
    Many,
}

fn run_default_keyword(
    iterations: usize,
    case: KeywordCase,
) -> Result<(u128, Metric), Box<dyn Error>> {
    let config = ConfigLoader::new().load_default()?;
    let input = match case {
        KeywordCase::None => vec![0u8; DEFAULT_INPUT_BYTES],
        KeywordCase::One => keyword_input(&config, 1)?,
        KeywordCase::Many => keyword_input(&config, 64)?,
    };
    let matched = config
        .keywords()
        .iter()
        .filter(|keyword| contains_bytes(&input, keyword.as_bytes()))
        .count();
    let required = match case {
        KeywordCase::None => 0,
        KeywordCase::One => 1,
        KeywordCase::Many => 64,
    };
    if matched != required {
        return Err(format!("keyword fixture matched {matched}, expected {required}").into());
    }
    run_scan(
        iterations,
        Engine::builder(config).build()?,
        Fragment::builder(input).build(),
        ScanOptions::default(),
    )
}

fn keyword_input(config: &CompiledConfig, count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let selected = config
        .keywords()
        .iter()
        .filter(|keyword| {
            !keyword.is_empty()
                && !config
                    .keywords()
                    .iter()
                    .any(|other| other != *keyword && keyword.contains(other))
        })
        .take(count)
        .collect::<Vec<_>>();
    if selected.len() != count {
        return Err(format!("only {} independent keywords", selected.len()).into());
    }
    let mut unit = Vec::new();
    for keyword in selected {
        unit.extend_from_slice(keyword.as_bytes());
        unit.push(0);
    }
    let mut input = Vec::with_capacity(DEFAULT_INPUT_BYTES);
    while input.len() + unit.len() <= DEFAULT_INPUT_BYTES {
        input.extend_from_slice(&unit);
    }
    input.resize(DEFAULT_INPUT_BYTES, 0);
    Ok(input)
}

fn run_default_positive(iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let config = ConfigLoader::new()
        .load_default()?
        .select_rules(["private-key"])?;
    run_scan(
        iterations,
        Engine::builder(config).build()?,
        Fragment::builder(PRIVATE_KEY_SAMPLE.as_bytes()).build(),
        ScanOptions::default(),
    )
}

fn run_capture_entropy(iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut input = b"token=".to_vec();
    for index in 0..4096 {
        input.push(alphabet[index % alphabet.len()]);
    }
    input.resize(64 * 1024, b'!');
    run_scan(
        iterations,
        engine(CAPTURE_ENTROPY_CONFIG)?,
        Fragment::builder(input).build(),
        ScanOptions::default(),
    )
}

fn run_decode_five(iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let mut input = Vec::new();
    for index in 0..128 {
        input.extend_from_slice(format!("token={index:016} ").as_bytes());
    }
    for _ in 0..5 {
        input = base64(&input);
    }
    run_scan(
        iterations,
        engine(SIMPLE_CONFIG)?,
        Fragment::builder(input).build(),
        ScanOptions::builder().max_decode_depth(5).build(),
    )
}

fn base64_like_input() -> Vec<u8> {
    let unit = b"A0A0A0A0A0A0A0A0+/";
    let mut input = Vec::with_capacity(DEFAULT_INPUT_BYTES);
    while input.len() + unit.len() <= DEFAULT_INPUT_BYTES {
        input.extend_from_slice(unit);
    }
    input.resize(DEFAULT_INPUT_BYTES, b'A');
    input
}

#[allow(clippy::needless_pass_by_value)]
fn run_scan(
    iterations: usize,
    detector: Engine,
    fragment: Fragment,
    options: ScanOptions,
) -> Result<(u128, Metric), Box<dyn Error>> {
    let mut last = None;
    let start = Instant::now();
    for _ in 0..iterations {
        let outcome = detector.scan_fragment(black_box(&fragment), &options);
        last = Some(Metric {
            logical_bytes: u64::try_from(fragment.content().len())?,
            result_count: u64::try_from(outcome.findings().len())?,
            output_bytes: 0,
            fingerprint: findings_fingerprint(outcome.findings()),
        });
    }
    Ok((start.elapsed().as_nanos(), last.ok_or("no scan iteration")?))
}

fn run_source(iterations: usize, workers: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let fixture = FixtureDir::create()?;
    let detector = engine(SIMPLE_CONFIG)?;
    let runner = SourceRunner::new(workers, workers * 2)?;
    let mut last = None;
    let start = Instant::now();
    for _ in 0..iterations {
        let mut source = DirectorySource::with_options(
            &fixture.path,
            DirectoryOptions::new(DEFAULT_CHUNK_SIZE)?,
        );
        let outcome = runner.run(
            &mut source,
            &detector,
            ScanOptions::default(),
            &SessionPolicy::default(),
            &CancellationToken::new(),
        );
        if outcome.termination() != &SourceTermination::Completed || !outcome.issues().is_empty() {
            return Err("directory workload did not complete without issues".into());
        }
        let mut hash = findings_fingerprint(outcome.findings());
        hash = fnv_extend(hash, &outcome.scanned_bytes().to_le_bytes());
        last = Some(Metric {
            logical_bytes: outcome.scanned_bytes(),
            result_count: u64::try_from(outcome.findings().len())?,
            output_bytes: 0,
            fingerprint: hash,
        });
    }
    Ok((
        start.elapsed().as_nanos(),
        last.ok_or("no source iteration")?,
    ))
}

#[derive(Clone, Copy)]
enum ReportKind {
    Json,
    Sarif,
}

fn run_report(iterations: usize, kind: ReportKind) -> Result<(u128, Metric), Box<dyn Error>> {
    let findings = report_findings()?;
    let simple = ConfigLoader::new().load_toml(SIMPLE_CONFIG)?;
    let sarif = SarifReporter::try_from_config(&simple)?;
    let mut last = None;
    let start = Instant::now();
    for _ in 0..iterations {
        let mut output = Vec::new();
        match kind {
            ReportKind::Json => JsonReporter.write(&mut output, black_box(&findings))?,
            ReportKind::Sarif => sarif.write(&mut output, black_box(&findings))?,
        }
        last = Some(Metric {
            logical_bytes: u64::try_from(findings.len())?,
            result_count: u64::try_from(findings.len())?,
            output_bytes: u64::try_from(output.len())?,
            fingerprint: fnv_extend(FNV_OFFSET, &output),
        });
    }
    Ok((
        start.elapsed().as_nanos(),
        last.ok_or("no report iteration")?,
    ))
}

fn report_findings() -> Result<Vec<Finding>, Box<dyn Error>> {
    let mut findings = Vec::new();
    findings.try_reserve_exact(REPORT_FINDINGS)?;
    for index in 0..REPORT_FINDINGS {
        findings.push(
            Finding::builder()
                .rule_id("token")
                .description("token")
                .location(Location::new(index + 1, index + 1, 1, 22)?)
                .line("token=ABCDEFGHIJKLMNOP")
                .match_text("token=ABCDEFGHIJKLMNOP")
                .secret("ABCDEFGHIJKLMNOP")
                .file(format!("src/file-{index:05}.txt"))
                .entropy(4.0)
                .tags(["benchmark", "json"])
                .fingerprint(format!("src/file-{index:05}.txt:token:{}", index + 1))
                .build()?,
        );
    }
    Ok(findings)
}

fn run_bm_commit(
    iterations: usize,
    candidate: &str,
    expected_allowed: bool,
) -> Result<(u128, Metric), Box<dyn Error>> {
    let config = allowlist_config("commits", BENCH_COMMITS)?;
    let detector = engine(&config)?;
    run_boolean(
        iterations,
        || {
            let fragment = Fragment::builder(b"probe".as_slice())
                .commit(candidate)
                .build();
            Ok(detector
                .scan_fragment(&fragment, &ScanOptions::default())
                .findings()
                .is_empty())
        },
        expected_allowed,
        candidate.len(),
    )
}

fn run_bm_path(
    iterations: usize,
    candidate: &str,
    expected_allowed: bool,
) -> Result<(u128, Metric), Box<dyn Error>> {
    let config_text = allowlist_config("paths", BENCH_PATH_PATTERNS)?;
    let config = ConfigLoader::new().load_toml(&config_text)?;
    run_boolean(
        iterations,
        || Ok(config.source_path_allowed(candidate.as_bytes(), None)),
        expected_allowed,
        candidate.len(),
    )
}

fn run_bm_regex(
    iterations: usize,
    candidate: &str,
    expected_allowed: bool,
) -> Result<(u128, Metric), Box<dyn Error>> {
    let config = allowlist_config("regexes", BENCH_REGEX_PATTERNS)?;
    let detector = engine(&config)?;
    run_boolean(
        iterations,
        || Ok(regex_allowed_by_engine(&detector, candidate)),
        expected_allowed,
        candidate.len(),
    )
}

fn run_bm_aggregate_paths(iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let config = ConfigLoader::new().load_default()?;
    let start = Instant::now();
    let mut last = None;
    for _ in 0..iterations {
        let mut hash = FNV_OFFSET;
        let mut allowed = 0u64;
        for candidate in AGGREGATE_PATH_INVALID {
            let value = config.source_path_allowed(candidate.as_bytes(), None);
            if !value {
                return Err(format!("BM-0003 expected allowed path '{candidate}'").into());
            }
            allowed += u64::from(value);
            hash = fnv_extend(hash, &[u8::from(value)]);
        }
        last = Some(Metric {
            logical_bytes: u64::try_from(
                AGGREGATE_PATH_INVALID
                    .iter()
                    .map(|value| value.len())
                    .sum::<usize>(),
            )?,
            result_count: allowed,
            output_bytes: 0,
            fingerprint: hash,
        });
    }
    Ok((
        start.elapsed().as_nanos(),
        last.ok_or("no BM-0003 iteration")?,
    ))
}

fn run_bm_aggregate_regexes(iterations: usize) -> Result<(u128, Metric), Box<dyn Error>> {
    let detector = default_allowlist_probe()?;
    let start = Instant::now();
    let mut last = None;
    for _ in 0..iterations {
        let mut hash = FNV_OFFSET;
        let mut correct = 0u64;
        for candidate in AGGREGATE_REGEX_INVALID {
            let value = regex_allowed_by_engine(&detector, candidate);
            if !value {
                return Err(format!("BM-0004 expected allowed value '{candidate}'").into());
            }
            correct += 1;
            hash = fnv_extend(hash, &[1]);
        }
        for candidate in AGGREGATE_REGEX_VALID {
            let value = regex_allowed_by_engine(&detector, candidate);
            if value {
                return Err(format!("BM-0004 expected non-allowed value '{candidate}'").into());
            }
            correct += 1;
            hash = fnv_extend(hash, &[0]);
        }
        last = Some(Metric {
            logical_bytes: u64::try_from(
                AGGREGATE_REGEX_INVALID
                    .iter()
                    .chain(AGGREGATE_REGEX_VALID)
                    .map(|value| value.len())
                    .sum::<usize>(),
            )?,
            result_count: correct,
            output_bytes: 0,
            fingerprint: hash,
        });
    }
    Ok((
        start.elapsed().as_nanos(),
        last.ok_or("no BM-0004 iteration")?,
    ))
}

fn default_allowlist_probe() -> Result<Engine, Box<dyn Error>> {
    let config = ConfigLoader::new().load_toml(
        r#"
[extend]
useDefault = true

[[rules]]
id = "perf-probe"
description = "perf-probe"
regex = '''(?s).+'''
"#,
    )?;
    Ok(Engine::builder(config.select_rules(["perf-probe"])?).build()?)
}

fn regex_allowed_by_engine(detector: &Engine, candidate: &str) -> bool {
    detector
        .scan_fragment(
            &Fragment::builder(candidate.as_bytes()).build(),
            &ScanOptions::default(),
        )
        .findings()
        .is_empty()
}

fn run_boolean<F>(
    iterations: usize,
    mut operation: F,
    expected_allowed: bool,
    logical_bytes: usize,
) -> Result<(u128, Metric), Box<dyn Error>>
where
    F: FnMut() -> Result<bool, Box<dyn Error>>,
{
    let start = Instant::now();
    let mut last = false;
    for _ in 0..iterations {
        last = black_box(operation()?);
        if last != expected_allowed {
            return Err(format!("boolean outcome {last} != {expected_allowed}").into());
        }
    }
    Ok((
        start.elapsed().as_nanos(),
        Metric {
            logical_bytes: u64::try_from(logical_bytes)?,
            result_count: u64::from(last),
            output_bytes: 0,
            fingerprint: fnv_extend(FNV_OFFSET, &[u8::from(last)]),
        },
    ))
}

fn allowlist_config(field: &str, values: &[&str]) -> Result<String, Box<dyn Error>> {
    if values.len() > 1_000 {
        return Err("benchmark allowlist exceeds 1,000 values".into());
    }
    let mut config = String::from(
        "[[rules]]\nid = \"probe\"\ndescription = \"probe\"\nregex = '''(?s).+'''\n\n[[allowlists]]\n",
    );
    config.push_str(field);
    config.push_str(" = [");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            config.push(',');
        }
        let normalized = value.replace("\\\\", "\\");
        config.push_str(&serde_json::to_string(&normalized)?);
    }
    config.push_str("]\n");
    Ok(config)
}

fn config_metric(config: &CompiledConfig) -> Metric {
    let mut hash = FNV_OFFSET;
    for id in config.ordered_rule_ids() {
        hash = fnv_extend(hash, id.as_bytes());
        hash = fnv_extend(hash, &[0]);
    }
    Metric {
        logical_bytes: u64::try_from(rustleaks_core::config::DEFAULT_CONFIG_BYTES.len())
            .expect("default config length fits u64"),
        result_count: u64::try_from(config.rules().len()).expect("rule count fits u64"),
        output_bytes: 0,
        fingerprint: hash,
    }
}

fn findings_fingerprint(findings: &[Finding]) -> u64 {
    let mut hash = FNV_OFFSET;
    let finding_count = u64::try_from(findings.len()).expect("finding count fits u64");
    hash = fnv_extend(hash, &finding_count.to_le_bytes());
    for finding in findings {
        let location = finding.location();
        for bytes in [
            finding.rule_id().as_bytes(),
            finding.description().as_bytes(),
            finding.line().as_bytes(),
            finding.match_text().as_bytes(),
            finding.secret().as_bytes(),
            finding.file().as_bytes(),
            finding.symlink_file().as_bytes(),
            finding.commit().as_bytes(),
            finding.link().as_bytes(),
            finding.author().as_bytes(),
            finding.email().as_bytes(),
            finding.date().as_bytes(),
            finding.message().as_bytes(),
            finding.fingerprint().as_bytes(),
        ] {
            hash = fnv_extend(hash, bytes);
            hash = fnv_extend(hash, &[0xff]);
        }
        for coordinate in [
            location.start_line(),
            location.end_line(),
            location.start_column(),
            location.end_column(),
        ] {
            let coordinate = u64::try_from(coordinate).expect("finding coordinate fits u64");
            hash = fnv_extend(hash, &coordinate.to_le_bytes());
        }
        hash = fnv_extend(hash, &finding.entropy().to_bits().to_le_bytes());
        for tag in finding.tags() {
            hash = fnv_extend(hash, tag.as_bytes());
            hash = fnv_extend(hash, &[0xfe]);
        }
        for required in finding.required_findings() {
            hash = fnv_extend(hash, required.rule_id().as_bytes());
            hash = fnv_extend(hash, required.match_text().as_bytes());
            hash = fnv_extend(hash, required.secret().as_bytes());
        }
    }
    hash
}

fn fnv_extend(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn base64(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[(a >> 2) as usize]);
        output.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize]);
        output.push(if chunk.len() > 1 {
            TABLE[(((b & 15) << 2) | (c >> 6)) as usize]
        } else {
            b'='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(c & 63) as usize]
        } else {
            b'='
        });
    }
    output
}

#[allow(clippy::too_many_lines)]
fn expected(id: &str) -> Expected {
    let empty = fnv_extend(FNV_OFFSET, &0u64.to_le_bytes());
    match id {
        "default-compile" => Expected::new(
            97_731,
            222,
            0,
            0xbba0_f636_d5a0_2d49,
            "222 compiled default rules",
        ),
        "default-no-keyword" => Expected::new(
            1_048_576,
            0,
            0,
            empty,
            "zero matched keywords and zero findings",
        ),
        "default-one-keyword" => Expected::new(
            1_048_576,
            0,
            0,
            empty,
            "one distinct matched keyword and zero findings",
        ),
        "default-many-keywords" => Expected::new(
            1_048_576,
            0,
            0,
            empty,
            "64 distinct matched keywords and zero findings",
        ),
        "default-positive" => Expected::new(
            143,
            1,
            0,
            0x58e4_f5aa_b1da_7b3f,
            "one exact private-key finding",
        ),
        "regex-hostile-miss" => {
            Expected::new(262_144, 0, 0, empty, "bounded ambiguous-alternation miss")
        }
        "regex-capture-entropy" => Expected::new(
            65_536,
            1,
            0,
            0x0386_49fa_fe73_2c81,
            "one 4096-byte capture passing entropy",
        ),
        "decode-five-level" => Expected::new(
            12_428,
            128,
            0,
            0x0d90_76d6_9519_4702,
            "128 findings after five decode passes",
        ),
        "decode-large-base64-like" => Expected::new(
            1_048_576,
            0,
            0,
            empty,
            "large base64-like input yields zero findings",
        ),
        "source-directory-1" | "source-directory-4" => Expected::new(
            8_388_608,
            0,
            0,
            0x3cee_0642_681c_47e5,
            "complete issue-free 8 MiB directory scan",
        ),
        "report-json" => Expected::new(
            10_000,
            10_000,
            4_406_685,
            0x1336_2a3d_2685_4efc,
            "exact 10,000-finding JSON bytes",
        ),
        "report-sarif" => Expected::new(
            10_000,
            10_000,
            7_308_202,
            0x8293_a2e4_39c3_f929,
            "exact 10,000-finding SARIF bytes",
        ),
        "bm-0001" => Expected::new(
            40,
            1,
            0,
            fnv_extend(FNV_OFFSET, &[1]),
            "BM-0001 accepted commit is allowed",
        ),
        "bm-0002" => Expected::new(
            40,
            0,
            0,
            fnv_extend(FNV_OFFSET, &[0]),
            "BM-0002 absent commit is not allowed",
        ),
        "bm-0003" => Expected::new(
            1_153,
            AGGREGATE_PATH_INVALID.len() as u64,
            0,
            0x43b1_03a3_07f3_ee9d,
            "BM-0003 complete aggregate path set is allowed",
        ),
        "bm-0004" => Expected::new(
            874,
            (AGGREGATE_REGEX_INVALID.len() + AGGREGATE_REGEX_VALID.len()) as u64,
            0,
            0x188c_1f94_5093_510b,
            "BM-0004 aggregate regex booleans are exact",
        ),
        "bm-0005" => Expected::new(
            BM_PATH_ALLOWED.len() as u64,
            1,
            0,
            fnv_extend(FNV_OFFSET, &[1]),
            "BM-0005 accepted path is allowed",
        ),
        "bm-0006" => Expected::new(
            BM_PATH_NOT_ALLOWED.len() as u64,
            0,
            0,
            fnv_extend(FNV_OFFSET, &[0]),
            "BM-0006 absent path is not allowed",
        ),
        "bm-0007" => Expected::new(
            BM_REGEX_ALLOWED.len() as u64,
            1,
            0,
            fnv_extend(FNV_OFFSET, &[1]),
            "BM-0007 matching value is allowed",
        ),
        "bm-0008" => Expected::new(
            BM_REGEX_NOT_ALLOWED.len() as u64,
            0,
            0,
            fnv_extend(FNV_OFFSET, &[0]),
            "BM-0008 nonmatching value is not allowed",
        ),
        _ => unreachable!("validated workload ID"),
    }
}

impl Expected {
    const fn new(
        logical_bytes: u64,
        result_count: u64,
        output_bytes: u64,
        fingerprint: u64,
        description: &'static str,
    ) -> Self {
        Self {
            logical_bytes,
            result_count,
            output_bytes,
            fingerprint,
            description,
        }
    }
}

fn validate_metric(id: &str, actual: &Metric, expected: Expected) -> Result<(), Box<dyn Error>> {
    if actual.logical_bytes != expected.logical_bytes {
        return Err(format!(
            "{id} logical bytes {} != {}",
            actual.logical_bytes, expected.logical_bytes
        )
        .into());
    }
    if actual.result_count != expected.result_count {
        return Err(format!(
            "{id} result count {} != {}",
            actual.result_count, expected.result_count
        )
        .into());
    }
    if actual.output_bytes != expected.output_bytes {
        return Err(format!(
            "{id} output bytes {} != {}",
            actual.output_bytes, expected.output_bytes
        )
        .into());
    }
    if actual.fingerprint != expected.fingerprint {
        return Err(format!(
            "{id} fingerprint {:016x} != {:016x}",
            actual.fingerprint, expected.fingerprint
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_bounded_and_ids_are_unique() {
        let unique = WORKLOADS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), WORKLOADS.len());
        assert!(parse_args(["--iterations".into(), "0".into()]).is_err());
        assert!(parse_args(["--iterations".into(), "11".into()]).is_err());
        assert!(parse_args(["--workload".into(), "missing".into()]).is_err());
    }

    #[test]
    fn exact_upstream_benchmark_inputs_and_outcomes_run() {
        for id in (1..=8).map(|value| format!("bm-{value:04}")) {
            let (_, metric) = run_workload(&id, 1).expect("benchmark workload");
            validate_metric(&id, &metric, expected(&id)).expect("benchmark invariant");
        }
    }

    #[test]
    fn all_performance_categories_run_with_invariants() {
        for id in WORKLOADS.iter().take(13) {
            let (_, metric) = run_workload(id, 1).expect("performance workload");
            validate_metric(id, &metric, expected(id)).expect("performance invariant");
        }
    }

    #[test]
    fn base64_encoder_has_pinned_boundaries() {
        assert_eq!(base64(b""), b"");
        assert_eq!(base64(b"f"), b"Zg==");
        assert_eq!(base64(b"fo"), b"Zm8=");
        assert_eq!(base64(b"foo"), b"Zm9v");
    }
}
