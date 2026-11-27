#![forbid(unsafe_code)]
#![allow(missing_docs)]
//! Scans the inputs of the core corpora under `testdata/` with
//! `rustleaks-core` directly and through the C ABI, and requires the same
//! result from both: the same findings, field by field and in the same
//! order, and the same completion and usage.
//!
//! The test compares two implementations at run time. It stores no expected
//! values, so the recorded outcomes of the corpora are not read.
//!
//! A case gives a configuration, the scanned bytes, a path and the scan
//! options. The C ABI takes only the content and the path of a fragment, so
//! both sides scan a fragment with only those two fields; a case whose
//! fragment also has Git metadata, a symlink path, a Windows path, a start
//! line or the required-rule flag runs with those fields left out, and the
//! summary counts it. Cases that load a configuration from several files
//! need a file resolver, which the C ABI does not have, so they are skipped
//! and counted.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Base64Mode, Fragment, ScanOptions};
use rustleaks_core::{ScanBudget, ScanControl, ScanOutcome, ScanTermination};
use rustleaks_ffi::abi::{
    ERROR_CONFIG, ERROR_ENGINE, OPTION_MAX_INPUT_BYTES, OPTION_WORKERS, SCAN_SET_ALLOW_COMMENTS,
    SCAN_SET_DECODE_DEPTH, SCAN_SET_REDACTION_PERCENT, StatusView, TERMINATION_BUDGET,
    TERMINATION_CANCELLED, TERMINATION_COMPLETE, TERMINATION_OTHER, UNLIMITED,
};
use rustleaks_ffi::harness::{self, Options, scan_args};
use serde_json::Value;

/// The finding record budget that the library uses by default.
const DEFAULT_MAX_FINDING_RECORDS: usize = 100_000;

/// The most differences that the failure message shows in full.
const SHOWN_DIFFERENCES: usize = 10;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// One scan request.
#[derive(Clone, Debug)]
struct Case {
    name: String,
    input: Vec<u8>,
    path: Vec<u8>,
    decode_depth: u64,
    redaction_percent: u64,
    allow_comments: bool,
    repeat: usize,
}

/// Cases grouped by configuration. `None` is the built-in rules.
type Groups = BTreeMap<Option<Vec<u8>>, Vec<Case>>;

#[derive(Default)]
struct Counts {
    cases: usize,
    reduced: usize,
    skipped: BTreeMap<&'static str, usize>,
}

impl Counts {
    fn skip(&mut self, reason: &'static str) {
        *self.skipped.entry(reason).or_default() += 1;
    }
}

/// Decodes standard base64 with padding.
fn base64(text: &str) -> Vec<u8> {
    fn value(byte: u8) -> u32 {
        match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            other => panic!("not a base64 byte: {other:#04x}"),
        }
    }
    let text = text.as_bytes();
    assert!(text.len().is_multiple_of(4), "base64 text without padding");
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for chunk in text.chunks(4) {
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        let bits = chunk[..4 - padding]
            .iter()
            .enumerate()
            .fold(0, |bits, (index, byte)| {
                bits | (value(*byte) << (18 - 6 * index))
            });
        let bytes = bits.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - padding]);
    }
    out
}

fn field_base64(value: &Value, field: &str) -> Vec<u8> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(base64)
        .unwrap_or_default()
}

fn json_lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("a JSON line"))
        .collect()
}

/// Reads the detection requests of a corpus folder.
fn load_corpus(name: &str, groups: &mut Groups, counts: &mut Counts) {
    let folder = testdata().join(name);
    for request in json_lines(&folder.join("requests-v1.jsonl")) {
        let id = request["id"].as_str().expect("an id");
        if request
            .get("operation")
            .and_then(Value::as_str)
            .is_some_and(|operation| operation != "detect")
        {
            continue;
        }
        if request
            .get("config_files")
            .and_then(Value::as_array)
            .is_some_and(|files| !files.is_empty())
        {
            counts.skip("configuration in several files");
            continue;
        }
        let config = if request.get("use_default").and_then(Value::as_bool) == Some(true) {
            None
        } else if let Some(fixture) = request
            .get("config_fixture")
            .and_then(Value::as_str)
            .filter(|fixture| !fixture.is_empty())
        {
            let path = testdata()
                .join("fixtures/upstream/testdata/config")
                .join(fixture);
            Some(std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())))
        } else {
            let config = field_base64(&request, "config_base64");
            if config.is_empty() {
                counts.skip("no configuration");
                continue;
            }
            Some(config)
        };
        let fragment = &request["fragment"];
        let metadata = [
            "windows_file_base64",
            "symlink_file_base64",
            "commit_base64",
            "author_base64",
            "email_base64",
            "date_base64",
            "message_base64",
        ]
        .iter()
        .any(|field| !field_base64(fragment, field).is_empty())
            || fragment["inherited_from_finding"].as_bool() == Some(true)
            || fragment["start_line"]
                .as_i64()
                .is_some_and(|line| line != 0);
        if metadata {
            counts.reduced += 1;
        }
        let options = &request["options"];
        let number = |field: &str| options[field].as_i64().unwrap_or(0);
        counts.cases += 1;
        groups.entry(config).or_default().push(Case {
            name: format!("{name}/{id}"),
            input: field_base64(fragment, "content_base64"),
            path: field_base64(fragment, "file_base64"),
            // A depth below zero means no decoding.
            decode_depth: u64::try_from(number("max_decode_depth")).unwrap_or(0),
            redaction_percent: u64::try_from(number("redact_percent")).unwrap_or(0),
            allow_comments: options["ignore_allow_marker"].as_bool() != Some(true),
            repeat: request
                .get("detect_repeat_count")
                .and_then(Value::as_u64)
                .map_or(1, |count| usize::try_from(count).unwrap().max(1)),
        });
    }
}

/// Reads the generator samples, which run with every built-in rule, once
/// without decoding and once with two decoding passes.
fn load_generator_corpus(groups: &mut Groups, counts: &mut Counts) {
    let samples = json_lines(&testdata().join("generator-corpus/samples-v1.jsonl"));
    let cases = groups.entry(None).or_default();
    for sample in samples {
        counts.cases += 1;
        let id = sample["case_id"].as_str().expect("a case_id");
        for decode_depth in [0, 2] {
            cases.push(Case {
                name: format!("generator-corpus/{id} (decode depth {decode_depth})"),
                input: field_base64(&sample, "input_base64"),
                path: field_base64(&sample, "path_base64"),
                decode_depth,
                redaction_percent: 0,
                allow_comments: true,
                repeat: 1,
            });
        }
    }
}

/// The C ABI and the direct engine for one configuration, or the error that
/// both returned.
struct Pair {
    direct: rustleaks_core::Engine,
    ffi: harness::Engine,
}

/// Builds both engines. Returns `Err` with a difference, or `Ok(None)` when
/// both failed in the same way.
fn build(config: Option<&[u8]>, workers: usize) -> Result<Option<Pair>, String> {
    let direct = direct_engine(config);
    let mut options = Options::new().expect("options");
    if let Some(config) = config {
        options.set_config(config).expect("set_config");
    }
    options
        .set_u64(OPTION_MAX_INPUT_BYTES, UNLIMITED)
        .expect("max input");
    options
        .set_u64(OPTION_WORKERS, u64::try_from(workers).unwrap())
        .expect("workers");
    let ffi = harness::Engine::new(&options);
    match (direct, ffi) {
        (Ok(direct), Ok(ffi)) => Ok(Some(Pair { direct, ffi })),
        (Err((kind, message)), Err(error)) => {
            if error.kind != kind || message.as_ref().is_some_and(|text| *text != error.message) {
                Err(format!(
                    "engine errors differ: core {kind} {message:?}, C ABI {} {:?}",
                    error.kind, error.message
                ))
            } else {
                Ok(None)
            }
        }
        (Ok(_), Err(error)) => Err(format!(
            "only the C ABI failed to build: {} {:?}",
            error.kind, error.message
        )),
        (Err((kind, message)), Ok(_)) => {
            Err(format!("only core failed to build: {kind} {message:?}"))
        }
    }
}

/// Builds the engine with core alone. An error has the C ABI error kind and
/// the core message, or no message when the configuration is not UTF-8.
fn direct_engine(config: Option<&[u8]>) -> Result<rustleaks_core::Engine, (i32, Option<String>)> {
    let loader = ConfigLoader::new();
    let loaded = match config {
        None => loader.load_default(),
        Some(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| (ERROR_CONFIG, None))?;
            loader.load_toml(text)
        }
    }
    .map_err(|error| (ERROR_CONFIG, Some(error.to_string())))?;
    rustleaks_core::Engine::builder(loaded)
        .build()
        .map_err(|error| (ERROR_ENGINE, Some(error.to_string())))
}

/// The fields that both sides report for one finding.
#[derive(Debug, PartialEq)]
struct Compared {
    rule_id: Vec<u8>,
    description: Vec<u8>,
    tags: Vec<Vec<u8>>,
    secret: Vec<u8>,
    match_text: Vec<u8>,
    line: Vec<u8>,
    start_line: u64,
    end_line: u64,
    start_column: u64,
    end_column: u64,
    secret_range: Option<(u64, u64)>,
    match_range: Option<(u64, u64)>,
    entropy_bits: u64,
}

fn number(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

fn direct_findings(outcome: &ScanOutcome) -> Vec<Compared> {
    outcome
        .findings()
        .iter()
        .map(|finding| {
            let location = finding.location();
            let range = |range: rustleaks_core::model::FindingRange| {
                range
                    .exact()
                    .map(|range| (number(range.start()), number(range.end())))
            };
            Compared {
                rule_id: finding.rule_id().as_bytes().to_vec(),
                description: finding.description().as_bytes().to_vec(),
                tags: finding
                    .tags()
                    .iter()
                    .map(|tag| tag.as_bytes().to_vec())
                    .collect(),
                secret: finding.secret().as_bytes().to_vec(),
                match_text: finding.match_text().as_bytes().to_vec(),
                line: finding.line().as_bytes().to_vec(),
                start_line: number(location.start_line()),
                end_line: number(location.end_line()),
                start_column: number(location.start_column()),
                end_column: number(location.end_column()),
                secret_range: range(finding.secret_range()),
                match_range: range(finding.match_range()),
                entropy_bits: f64::from(finding.entropy()).to_bits(),
            }
        })
        .collect()
}

fn ffi_findings(findings: Vec<harness::Finding>) -> Vec<Compared> {
    findings
        .into_iter()
        .map(|finding| Compared {
            rule_id: finding.rule_id,
            description: finding.description,
            tags: finding.tags,
            secret: finding.secret,
            match_text: finding.match_text,
            line: finding.line,
            start_line: finding.start_line,
            end_line: finding.end_line,
            start_column: finding.start_column,
            end_column: finding.end_column,
            secret_range: finding.secret_range,
            match_range: finding.match_range,
            entropy_bits: finding.entropy.to_bits(),
        })
        .collect()
}

/// The status that the C ABI should report for a core outcome.
fn direct_status(outcome: &ScanOutcome) -> (i32, [u64; 6]) {
    let usage = outcome.usage();
    let termination = match outcome.termination() {
        None => TERMINATION_COMPLETE,
        Some(ScanTermination::Cancelled) => TERMINATION_CANCELLED,
        Some(ScanTermination::BudgetExceeded { .. }) => TERMINATION_BUDGET,
        Some(_) => TERMINATION_OTHER,
    };
    (
        termination,
        [
            number(usage.decoded_bytes()),
            number(usage.work_units()),
            number(usage.finding_records()),
            number(usage.finding_payload_bytes()),
            number(usage.collected_spans()),
            number(usage.normalization_bytes()),
        ],
    )
}

fn ffi_status(status: &StatusView) -> (i32, [u64; 6]) {
    (
        status.termination,
        [
            status.decoded_bytes,
            status.work_units,
            status.finding_records,
            status.finding_payload_bytes,
            status.collected_spans,
            status.normalization_bytes,
        ],
    )
}

/// Bytes as an escaped string, short enough for a failure message.
fn show(bytes: &[u8]) -> String {
    const LIMIT: usize = 160;
    let shown = bytes
        .get(..LIMIT)
        .unwrap_or(bytes)
        .escape_ascii()
        .to_string();
    if bytes.len() > LIMIT {
        format!("\"{shown}\"... ({} bytes)", bytes.len())
    } else {
        format!("\"{shown}\"")
    }
}

fn describe(finding: &Compared) -> String {
    format!(
        "{} lines {}-{} columns {}-{} secret {} match {} secret range {:?} match range {:?} \
         entropy {} tags {:?} line {}",
        String::from_utf8_lossy(&finding.rule_id),
        finding.start_line,
        finding.end_line,
        finding.start_column,
        finding.end_column,
        show(&finding.secret),
        show(&finding.match_text),
        finding.secret_range,
        finding.match_range,
        f64::from_bits(finding.entropy_bits),
        finding
            .tags
            .iter()
            .map(|tag| String::from_utf8_lossy(tag).into_owned())
            .collect::<Vec<_>>(),
        show(&finding.line),
    )
}

/// A readable account of how two finding lists differ.
fn diff(direct: &[Compared], ffi: &[Compared]) -> String {
    let mut text = format!(
        "core reported {} findings, the C ABI {}\n",
        direct.len(),
        ffi.len()
    );
    let first = direct
        .iter()
        .zip(ffi)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| direct.len().min(ffi.len()));
    let _ = writeln!(text, "  first difference at finding {first}");
    for (label, findings) in [("core", direct), ("C ABI", ffi)] {
        for (index, finding) in findings.iter().enumerate().skip(first).take(3) {
            let _ = writeln!(text, "  {label} [{index}]: {}", describe(finding));
        }
    }
    text
}

/// Scans one case both ways and returns the differences and the number of
/// findings compared.
fn compare(pair: &Pair, case: &Case) -> (Vec<String>, usize) {
    let options = ScanOptions::builder()
        .max_decode_depth(usize::try_from(case.decode_depth).unwrap())
        .base64_mode(Base64Mode::Compatible)
        .redaction_percent(usize::try_from(case.redaction_percent).unwrap())
        .honor_allow_markers(case.allow_comments)
        .build();
    let control = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_finding_records(DEFAULT_MAX_FINDING_RECORDS));
    let fragment = direct_fragment(case);
    let mut args = scan_args(&case.path);
    args.overrides = SCAN_SET_DECODE_DEPTH | SCAN_SET_REDACTION_PERCENT | SCAN_SET_ALLOW_COMMENTS;
    args.decode_depth = case.decode_depth;
    args.redaction_percent = case.redaction_percent;
    args.allow_comments = u8::from(case.allow_comments);

    let mut differences = Vec::new();
    let mut compared = 0;
    for run in 0..case.repeat {
        let label = if case.repeat > 1 {
            format!("{} (scan {})", case.name, run + 1)
        } else {
            case.name.clone()
        };
        let outcome = pair
            .direct
            .scan_fragment_controlled(&fragment, &options, &control);
        let result = match pair.ffi.scan(&case.input, Some(&args), None) {
            Ok(result) => result,
            Err(error) => {
                differences.push(format!(
                    "{label}: the C ABI scan failed: {} {:?}",
                    error.kind, error.message
                ));
                continue;
            }
        };
        if let Some(finding) = result
            .findings
            .iter()
            .find(|finding| finding.path != case.path)
        {
            differences.push(format!(
                "{label}: the C ABI reported path {} for scan path {}",
                show(&finding.path),
                show(&case.path)
            ));
        }
        let (direct_status, ffi_status) = (direct_status(&outcome), ffi_status(&result.status));
        if direct_status != ffi_status {
            differences.push(format!(
                "{label}: status differs: core {direct_status:?}, C ABI {ffi_status:?} \
                 (termination, then decoded bytes, work units, finding records, payload bytes, \
                 collected spans, normalization bytes)"
            ));
        }
        let direct = direct_findings(&outcome);
        let ffi = ffi_findings(result.findings);
        if direct != ffi {
            differences.push(format!("{label}: {}", diff(&direct, &ffi)));
        }
        compared += direct.len();
    }
    (differences, compared)
}

/// The fragment that the C ABI builds for a path: on Windows a path with a
/// `\` becomes a `/` path, with the original kept as the Windows path.
fn direct_fragment(case: &Case) -> Fragment {
    let builder = Fragment::builder(case.input.clone());
    if cfg!(windows) && case.path.contains(&b'\\') {
        let normalized = case
            .path
            .iter()
            .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
            .collect::<Vec<_>>();
        builder
            .file_path(normalized)
            .windows_file_path(case.path.clone())
            .build()
    } else {
        builder.file_path(case.path.clone()).build()
    }
}

#[test]
fn the_c_abi_reports_what_core_reports_for_every_corpus_input() {
    let mut groups = Groups::new();
    let mut counts = BTreeMap::new();
    for corpus in [
        "detect-corpus",
        "allowlist-corpus",
        "composite-corpus",
        "decoder-corpus",
    ] {
        let mut corpus_counts = Counts::default();
        load_corpus(corpus, &mut groups, &mut corpus_counts);
        counts.insert(corpus, corpus_counts);
    }
    let mut generator = Counts::default();
    load_generator_corpus(&mut groups, &mut generator);
    counts.insert("generator-corpus", generator);

    let threads = std::thread::available_parallelism().map_or(1, |count| count.get().min(8));
    let differences = Mutex::new(Vec::new());
    let findings = AtomicUsize::new(0);
    let scans = AtomicUsize::new(0);
    for (config, cases) in &groups {
        let pair = match build(config.as_deref(), threads) {
            Ok(Some(pair)) => pair,
            Ok(None) => continue,
            Err(difference) => {
                let names = cases.iter().map(|case| case.name.as_str());
                differences.lock().unwrap().push(format!(
                    "{}: {difference}",
                    names.collect::<Vec<_>>().join(", ")
                ));
                continue;
            }
        };
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..threads.min(cases.len()) {
                scope.spawn(|| {
                    while let Some(case) = cases.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let (found, compared) = compare(&pair, case);
                        findings.fetch_add(compared, Ordering::Relaxed);
                        scans.fetch_add(case.repeat, Ordering::Relaxed);
                        if !found.is_empty() {
                            differences.lock().unwrap().extend(found);
                        }
                    }
                });
            }
        });
    }

    let mut summary = String::new();
    for (corpus, count) in &counts {
        let _ = writeln!(
            summary,
            "{corpus}: {} cases, {} with fragment fields left out, skipped {:?}",
            count.cases, count.reduced, count.skipped
        );
    }
    let _ = writeln!(
        summary,
        "{} configurations, {} scans, {} findings compared",
        groups.len(),
        scans.load(Ordering::Relaxed),
        findings.load(Ordering::Relaxed)
    );
    println!("{summary}");

    let differences = differences.into_inner().unwrap();
    assert!(
        differences.is_empty(),
        "{} cases differ between core and the C ABI. The first ones:\n{}\n{summary}",
        differences.len(),
        differences
            .iter()
            .take(SHOWN_DIFFERENCES)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    for (corpus, count) in &counts {
        assert!(count.cases > 0, "{corpus} has no cases to compare");
    }
    assert!(
        findings.load(Ordering::Relaxed) > 5_000,
        "too few findings were compared to show anything"
    );
}

#[test]
fn base64_decodes_padding() {
    assert_eq!(base64(""), b"");
    assert_eq!(base64("YQ=="), b"a");
    assert_eq!(base64("YWI="), b"ab");
    assert_eq!(base64("YWJj"), b"abc");
    assert_eq!(base64("/+8A"), [0xff, 0xef, 0x00]);
}
