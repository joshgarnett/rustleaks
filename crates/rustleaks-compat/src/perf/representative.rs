//! Versioned operation-only workloads, including host-calibrated fragment budgets.

use std::error::Error;
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::{CompiledConfig, ConfigLoader, DEFAULT_CONFIG_BYTES};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::session::{ScanSession, SessionPolicy};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanOutcome};
use rustleaks_report::{JsonReporter, Reporter, SarifReporter};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{FNV_OFFSET, SIMPLE_CONFIG, fnv_extend, representative_io};

#[path = "fragment_workloads.rs"]
mod fragment_workloads;

#[path = "decode_workloads.rs"]
mod decode_workloads;
#[path = "edge_workloads.rs"]
mod edge_workloads;
#[path = "normalization_workloads.rs"]
mod normalization_workloads;
#[path = "report_workloads.rs"]
mod report_workloads;
#[path = "source_scale_workloads.rs"]
mod source_scale_workloads;
#[path = "worker_workloads.rs"]
mod worker_workloads;

#[path = "investigation.rs"]
mod investigation;
pub use investigation::main as investigate;

pub const SCOPE: &str = "representative-v1-operation-only";
pub const MAX_ITERATIONS: usize = 1_000;
pub const WORKLOADS: &[&str] = &[
    "core-mixed-1-kib",
    "core-mixed-16-kib",
    "core-mixed-256-kib",
    "core-dense-16-kib",
    "core-minified-16-kib",
    "core-utf8-invalid-16-kib",
    "core-multiline-16-kib",
    "core-many-rules-16-kib",
    "core-default-no-hit-16-kib",
    "core-default-one-keyword-16-kib",
    "core-default-many-keywords-16-kib",
    "core-default-positive",
    "core-decode-depth-0",
    "core-decode-depth-5",
    "session-merge-10000",
    "serialize-json-10000",
    "serialize-sarif-10000",
];

/// Counts and identities describe one complete operation, never a byte estimate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "phase is part of the versioned serialized phase contract"
)]
pub struct Phase {
    pub phase: String,
    pub iterations: usize,
    pub elapsed_ns: u64,
    pub logical_unit: String,
    pub logical_units_per_iteration: u64,
    pub input_fnv1a64: String,
    pub config_fnv1a64: String,
    pub outcome_fnv1a64: String,
    pub findings: u64,
    pub errors: u64,
    pub complete: bool,
    pub counts: Value,
    pub scope: String,
}

pub fn fingerprint(bytes: &[u8]) -> String {
    format!("{:016x}", fnv_extend(FNV_OFFSET, bytes))
}

pub fn main(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    if arguments == ["--representative-startup"] {
        println!("rustleaks-representative-startup-v1");
        return Ok(());
    }
    if arguments == ["--representative-list"] {
        for id in WORKLOADS
            .iter()
            .chain(fragment_workloads::WORKLOADS)
            .chain(edge_workloads::WORKLOADS)
            .chain(normalization_workloads::WORKLOADS)
            .chain(worker_workloads::WORKLOADS)
            .chain(decode_workloads::WORKLOADS)
            .chain(report_workloads::WORKLOADS)
            .chain(representative_io::WORKLOADS)
            .chain(source_scale_workloads::WORKLOADS)
        {
            println!("{id}");
        }
        return Ok(());
    }
    let mut arguments = arguments.iter();
    if arguments.next().map(String::as_str) != Some("--representative") {
        return Err("expected --representative".into());
    }
    let mut workload = None;
    let mut iterations = 25;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--workload" => workload = arguments.next().map(String::as_str),
            "--iterations" => {
                iterations = arguments.next().ok_or("missing iterations")?.parse()?;
            }
            _ => return Err(format!("unknown representative argument {argument}").into()),
        }
    }
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        return Err("representative iterations must be in 1..=1000".into());
    }
    let workload = workload.ok_or("representative requires one --workload")?;
    // Executable hashing is deliberately before preparation and phase timers.
    let provenance = super::provenance()?;
    let phases = if decode_workloads::WORKLOADS.contains(&workload) {
        decode_workloads::run(workload, iterations)?
    } else if report_workloads::WORKLOADS.contains(&workload) {
        report_workloads::run(workload, iterations)?
    } else if worker_workloads::WORKLOADS.contains(&workload) {
        worker_workloads::run(workload, iterations)?
    } else if fragment_workloads::WORKLOADS.contains(&workload) {
        fragment_workloads::run(workload, iterations)?
    } else if single_core_workload(workload) {
        run(workload, iterations)?
    } else if representative_io::WORKLOADS.contains(&workload) {
        representative_io::run(workload, iterations)?
    } else if source_scale_workloads::WORKLOADS.contains(&workload) {
        source_scale_workloads::run(workload, iterations)?
    } else {
        return Err(format!("unknown representative workload {workload}").into());
    };
    if phases.is_empty() {
        return Err("representative workload returned no phases".into());
    }
    for phase in phases {
        if !phase.complete || phase.errors != 0 {
            return Err("representative workload is incomplete or has errors".into());
        }
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schema_version": 3,
                "suite": "representative-v1",
                "workload": workload,
                "measurement_scope": SCOPE,
                "phase": phase,
                "provenance": provenance,
            }))?
        );
    }
    Ok(())
}

fn single_core_workload(id: &str) -> bool {
    WORKLOADS.contains(&id)
        || edge_workloads::WORKLOADS.contains(&id)
        || normalization_workloads::WORKLOADS.contains(&id)
}

struct Fixture {
    input: Vec<u8>,
    config: String,
    expected: Vec<Finding>,
    legacy_fingerprint: Option<u64>,
    expected_rules: usize,
    depth: usize,
    decoded_bytes: usize,
    keyword_count: usize,
    expected_work: Option<usize>,
}

impl Fixture {
    #[allow(clippy::too_many_lines)] // Keep fixed fixture construction and expected spans together.
    fn new(id: &str) -> Result<Self, Box<dyn Error>> {
        if edge_workloads::WORKLOADS.contains(&id) {
            return edge_workloads::fixture(id);
        }
        if normalization_workloads::WORKLOADS.contains(&id) {
            return normalization_workloads::fixture(id);
        }
        if id.starts_with("core-default-") {
            return Self::default_control(id);
        }
        if id.starts_with("core-decode-") {
            let mut input = b"token=ABCDEFGHIJKLMNOP ".repeat(32);
            let mut decoded_bytes = 0;
            for _ in 0..5 {
                decoded_bytes += input.len();
                input = super::base64(&input);
            }
            let depth = if id.ends_with('5') { 5 } else { 0 };
            return Ok(Self {
                input,
                // No matching rule isolates decode orchestration from finding creation.
                // The public API still includes normalization and rule dispatch.
                config: SIMPLE_CONFIG.replace("token", "absentmarker"),
                expected: Vec::new(),
                legacy_fingerprint: None,
                expected_rules: 1,
                depth,
                decoded_bytes: if depth == 0 { 0 } else { decoded_bytes },
                keyword_count: 0,
                expected_work: None,
            });
        }
        let size = match id {
            "core-mixed-1-kib" => 1_024,
            "core-mixed-256-kib" => 256 * 1_024,
            _ => 16 * 1_024,
        };
        let mut config = SIMPLE_CONFIG.to_owned();
        let mut expected_rules = 1;
        if id == "core-many-rules-16-kib" {
            for index in 0..127 {
                writeln!(
                    config,
                    "\n[[rules]]\nid = \"absent-{index:03}\"\nregex = '''marker{index:03}=([A-Z]{{16}})'''\nsecretGroup = 1\nkeywords = [\"marker{index:03}\"]"
                )
                .expect("writing to a String cannot fail");
            }
            expected_rules = 128;
        }
        let multiline = id == "core-multiline-16-kib";
        let matched: &[u8] = if multiline {
            config = SIMPLE_CONFIG.replace("token=([A-Z0-9]{16})", "token=\\n([A-Z0-9]{16})\\nend");
            b"token=\nABCDEFGHIJKLMNOP\nend"
        } else {
            b"token=ABCDEFGHIJKLMNOP"
        };
        let mut input = Vec::with_capacity(size);
        let mut spans = Vec::new();
        if id == "core-minified-16-kib" {
            input.extend_from_slice(b"const a=[");
            for _ in 0..16 {
                input.extend_from_slice(b"{\"value\":\"");
                let start = input.len();
                input.extend_from_slice(matched);
                spans.push((start, input.len()));
                input.extend_from_slice(b"\"},");
            }
            input.resize(size, b' ');
        } else {
            let stride = if id == "core-dense-16-kib" { 32 } else { 1_024 };
            while input.len() + stride <= size {
                if id == "core-utf8-invalid-16-kib" {
                    input.extend_from_slice("// café 日本語 ".as_bytes());
                    input.extend_from_slice(&[0xff, 0xfe, b'\n']);
                } else {
                    input.extend_from_slice(b"// synthetic source\n");
                }
                let start = input.len();
                input.extend_from_slice(matched);
                spans.push((start, input.len()));
                input.extend_from_slice(b"\n");
                // The dense case is intentionally 64-byte records to retain 256 findings.
                let boundary = input.len().div_ceil(stride) * stride;
                while input.len() + 36 < boundary {
                    input.extend_from_slice(b"let count = values.len(); // fixture\n");
                }
                input.resize(boundary.min(size), b' ');
            }
            input.resize(size, b' ');
        }
        let expected = spans
            .into_iter()
            .map(|(start, end)| expected_token(&input, start, end, multiline))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            input,
            config,
            expected,
            legacy_fingerprint: None,
            expected_rules,
            depth: 0,
            decoded_bytes: 0,
            keyword_count: 0,
            expected_work: None,
        })
    }

    fn default_control(id: &str) -> Result<Self, Box<dyn Error>> {
        let input = match id {
            "core-default-no-hit-16-kib" => vec![0; 16 * 1_024],
            "core-default-one-keyword-16-kib" | "core-default-many-keywords-16-kib" => Vec::new(),
            "core-default-positive" => super::PRIVATE_KEY_SAMPLE.as_bytes().to_vec(),
            _ => return Err("unknown default control".into()),
        };
        let positive = id == "core-default-positive";
        Ok(Self {
            input,
            config: String::from_utf8(DEFAULT_CONFIG_BYTES.to_vec())?,
            expected: Vec::new(),
            legacy_fingerprint: positive.then_some(0x58e4_f5aa_b1da_7b3f),
            expected_rules: if positive { 1 } else { 222 },
            depth: 0,
            decoded_bytes: 0,
            keyword_count: match id {
                "core-default-one-keyword-16-kib" => 1,
                "core-default-many-keywords-16-kib" => 64,
                _ => 0,
            },
            expected_work: None,
        })
    }

    fn compile(&self) -> Result<CompiledConfig, Box<dyn Error>> {
        let config = ConfigLoader::new().load_toml(&self.config)?;
        if self.legacy_fingerprint.is_some() {
            Ok(config.select_rules(["private-key"])?)
        } else {
            Ok(config)
        }
    }

    fn validate(&self, outcome: &ScanOutcome) -> Result<(), Box<dyn Error>> {
        if !outcome.is_complete() || outcome.termination().is_some() {
            return Err("representative scan did not complete".into());
        }
        if outcome.usage().decoded_bytes() != self.decoded_bytes {
            return Err("representative decoded-byte count differs".into());
        }
        if self.expected_work.is_some_and(|work| {
            outcome.usage().work_units() != work
                || outcome.usage().finding_records() != self.expected.len()
        }) {
            return Err("representative independent work or finding-record count differs".into());
        }
        if let Some(expected) = self.legacy_fingerprint {
            if outcome.findings().len() != 1
                || super::findings_fingerprint(outcome.findings()) != expected
            {
                return Err("default positive differs from its legacy control".into());
            }
            let range = FindingRange::Exact(ByteRange::new(0, self.input.len())?);
            if outcome.findings()[0].match_range() != range
                || outcome.findings()[0].secret_range() != range
            {
                return Err("default positive changed its exact original-byte ranges".into());
            }
        } else if outcome.findings() != self.expected {
            let mismatch = self
                .expected
                .iter()
                .zip(outcome.findings())
                .position(|(expected, actual)| expected != actual)
                .unwrap_or(0);
            return Err(format!("representative exact findings differ: expected {}, observed {}; first mismatch {mismatch}: expected {:?}, observed {:?}", self.expected.len(), outcome.findings().len(), self.expected.get(mismatch), outcome.findings().get(mismatch)).into());
        }
        Ok(())
    }
}

/// The fixture has known literal matches; this does not call a regex or the detector.
#[allow(
    clippy::naive_bytecount,
    reason = "keep the bounded fixture oracle independent and outside measurement timers"
)]
fn expected_token(
    input: &[u8],
    start: usize,
    end: usize,
    multiline: bool,
) -> Result<Finding, Box<dyn Error>> {
    let line_start = input[..start]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap_or(0);
    let line_end = input[end..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(input.len(), |offset| end + offset);
    let end_line_start = input[..end]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap_or(0);
    let start_line = input[..start].iter().filter(|byte| **byte == b'\n').count();
    let end_line = input[..end].iter().filter(|byte| **byte == b'\n').count();
    let secret_start = start + if multiline { 7 } else { 6 };
    Ok(Finding::builder()
        .rule_id("token")
        .description("token")
        .location(Location::new(
            start_line,
            end_line,
            start - line_start + 1,
            end - end_line_start,
        )?)
        .match_range(FindingRange::Exact(ByteRange::new(start, end)?))
        .secret_range(FindingRange::Exact(ByteRange::new(
            secret_start,
            secret_start + 16,
        )?))
        .line(&input[line_start..line_end])
        .match_text(&input[start..end])
        .secret("ABCDEFGHIJKLMNOP")
        .entropy(4.0)
        .build()?)
}

fn phase(
    name: &str,
    iterations: usize,
    elapsed_ns: u64,
    units: u64,
    unit: &str,
    input: &[u8],
    config: &[u8],
) -> Phase {
    Phase {
        phase: name.into(),
        iterations,
        elapsed_ns,
        logical_unit: unit.into(),
        logical_units_per_iteration: units,
        input_fnv1a64: fingerprint(input),
        config_fnv1a64: fingerprint(config),
        outcome_fnv1a64: fingerprint(&[]),
        findings: 0,
        errors: 0,
        complete: true,
        counts: json!({"workers": 1, "retained_outcomes": 1}),
        scope: SCOPE.into(),
    }
}

fn elapsed(start: Instant) -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(start.elapsed().as_nanos())?)
}

#[allow(clippy::too_many_lines)] // The first/steady timer ordering is part of the protocol.
pub fn run(id: &str, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    if id == "session-merge-10000" {
        return run_session(iterations);
    }
    if id.starts_with("serialize-") {
        return run_report(id, iterations);
    }
    let mut fixture = Fixture::new(id)?;
    let start = Instant::now();
    let config = black_box(fixture.compile()?);
    let compile_ns = elapsed(start)?;
    if config.rules().len() != fixture.expected_rules {
        return Err("representative compiled-rule count differs".into());
    }
    if fixture.expected_rules == 222
        && super::config_metric(&config).fingerprint != 0xbba0_f636_d5a0_2d49
    {
        return Err("representative default compiled rules differ from legacy control".into());
    }
    if fixture.keyword_count > 0 {
        fixture.input = super::keyword_input(&config, fixture.keyword_count, 16 * 1_024)?;
        let matched = config
            .keywords()
            .iter()
            .filter(|keyword| super::contains_bytes(&fixture.input, keyword.as_bytes()))
            .count();
        if matched != fixture.keyword_count {
            return Err("representative keyword fixture matched the wrong keyword count".into());
        }
    }
    let rule_ids = config.ordered_rule_ids().join("\0");
    let mut compile = phase(
        "config-parse-and-compile",
        1,
        compile_ns,
        fixture.config.len() as u64,
        "config-bytes",
        fixture.config.as_bytes(),
        fixture.config.as_bytes(),
    );
    compile.outcome_fnv1a64 = fingerprint(rule_ids.as_bytes());
    compile.counts["rules"] = json!(fixture.expected_rules);
    compile.counts["selection_included"] = json!(fixture.legacy_fingerprint.is_some());
    let start = Instant::now();
    let detector = black_box(Engine::builder(config).build()?);
    let build_ns = elapsed(start)?;
    let mut build = phase(
        "engine-construction",
        1,
        build_ns,
        fixture.expected_rules as u64,
        "compiled-rules",
        fixture.config.as_bytes(),
        fixture.config.as_bytes(),
    );
    build.outcome_fnv1a64.clone_from(&compile.outcome_fnv1a64);
    let fragment = Fragment::builder(fixture.input.clone()).build();
    let options = ScanOptions::builder()
        .max_decode_depth(fixture.depth)
        .build();
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(2_000_000)
            .max_finding_records(20_000)
            .max_decoded_bytes(16 * 1024 * 1024),
    );
    let mut phases = vec![compile, build];
    for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
        let mut total = 0;
        let mut result = phase(
            name,
            count,
            0,
            fixture.input.len() as u64,
            "input-bytes",
            &fixture.input,
            fixture.config.as_bytes(),
        );
        result.counts["decode_depth"] = json!(fixture.depth);
        result.counts["independent_default_keywords"] = json!(fixture.keyword_count);
        result.counts["operation"] = json!(if fixture.depth == 0 {
            "scan"
        } else {
            "scan-with-decoding"
        });
        result.counts["budget"] =
            json!({"work_units":2_000_000,"finding_records":20_000,"decoded_bytes":16*1024*1024});
        for _ in 0..count {
            let start = Instant::now();
            let outcome = black_box(detector.scan_fragment_controlled(
                black_box(&fragment),
                black_box(&options),
                &control,
            ));
            total += elapsed(start)?;
            fixture.validate(&outcome)?;
            let signature = outcome_signature(&outcome);
            if result.outcome_fnv1a64 != fingerprint(&[]) && result.outcome_fnv1a64 != signature {
                return Err("representative outcome changed between iterations".into());
            }
            result.outcome_fnv1a64 = signature;
            result.findings = outcome.findings().len() as u64;
            result.counts["decoded_bytes"] = json!(outcome.usage().decoded_bytes());
            result.counts["work_units"] = json!(outcome.usage().work_units());
            result.counts["finding_records"] = json!(outcome.usage().finding_records());
            // Outcome verification and destruction are outside each timer.
        }
        result.elapsed_ns = total;
        phases.push(result);
    }
    Ok(phases)
}

fn outcome_signature(outcome: &ScanOutcome) -> String {
    let mut hash = super::findings_fingerprint(outcome.findings());
    for finding in outcome.findings() {
        for range in [finding.match_range(), finding.secret_range()] {
            hash = fnv_extend(hash, format!("{range:?}").as_bytes());
        }
    }
    for value in [
        outcome.usage().decoded_bytes(),
        outcome.usage().work_units(),
        outcome.usage().finding_records(),
    ] {
        hash = fnv_extend(hash, &(value as u64).to_le_bytes());
    }
    format!("{hash:016x}")
}

fn run_report(id: &str, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    let findings = super::report_findings()?;
    let config = ConfigLoader::new().load_toml(SIMPLE_CONFIG)?;
    let sarif = SarifReporter::try_from_config(&config)?;
    let is_json = id == "serialize-json-10000";
    let legacy = super::expected(if is_json {
        "report-json"
    } else {
        "report-sarif"
    });
    let mut result = phase(
        "report-serialization",
        iterations,
        0,
        findings.len() as u64,
        "findings",
        &super::findings_fingerprint(&findings).to_le_bytes(),
        SIMPLE_CONFIG.as_bytes(),
    );
    for _ in 0..iterations {
        let mut output = Vec::new();
        let start = Instant::now();
        if is_json {
            JsonReporter.write(black_box(&mut output), black_box(&findings))?;
        } else {
            sarif.write(black_box(&mut output), black_box(&findings))?;
        }
        black_box(&output);
        result.elapsed_ns += elapsed(start)?;
        if output.len() as u64 != legacy.output_bytes
            || fnv_extend(FNV_OFFSET, &output) != legacy.fingerprint
        {
            return Err("report differs from exact legacy output bytes".into());
        }
        result.outcome_fnv1a64 = fingerprint(&output);
        result.counts["output_bytes"] = json!(output.len());
    }
    result.findings = findings.len() as u64;
    Ok(vec![result])
}

fn run_session(iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    let findings = super::report_findings()?;
    let policy = SessionPolicy::default();
    let mut result = phase(
        "session-merge",
        iterations,
        0,
        findings.len() as u64,
        "findings",
        &super::findings_fingerprint(&findings).to_le_bytes(),
        b"default-session-policy",
    );
    for _ in 0..iterations {
        let mut batches = Vec::new();
        for chunk in findings.chunks(100) {
            let mut batch = policy.new_batch();
            for finding in chunk {
                batch.add_finding(finding.clone());
            }
            batches.push(batch);
        }
        let mut session = ScanSession::new(policy.clone());
        let start = Instant::now();
        for batch in batches {
            session.merge(black_box(batch))?;
        }
        black_box(&session);
        result.elapsed_ns += elapsed(start)?;
        if session.findings() != findings {
            return Err("session merge changed exact findings".into());
        }
        result.outcome_fnv1a64 =
            format!("{:016x}", super::findings_fingerprint(session.findings()));
    }
    result.findings = findings.len() as u64;
    result.counts["batches"] = json!(100);
    result.counts["consumed_batch_destruction_inside_timer"] = json!(true);
    Ok(vec![result])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_exact_outcomes_and_phase_boundaries() {
        for id in WORKLOADS {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            assert!(phases.iter().all(|phase| phase.complete
                && phase.errors == 0
                && phase.iterations == 1
                && phase.scope == SCOPE));
            if id.starts_with("core-") {
                assert_eq!(phases.len(), 4);
                assert_eq!(phases[2].phase, "first-scan");
                assert_eq!(phases[3].phase, "steady-scan");
                assert_eq!(phases[2].outcome_fnv1a64, phases[3].outcome_fnv1a64);
            }
        }
    }

    #[test]
    fn skipped_input_and_partial_scan_are_rejected() {
        let fixture = Fixture::new("core-mixed-1-kib").unwrap();
        let detector = Engine::builder(fixture.compile().unwrap()).build().unwrap();
        let skipped = detector.scan_fragment(
            &Fragment::builder(&b""[..]).build(),
            &ScanOptions::default(),
        );
        assert!(fixture.validate(&skipped).is_err());
        let fragment = Fragment::builder(fixture.input.clone()).build();
        let partial = detector.scan_fragment_controlled(
            &fragment,
            &ScanOptions::default(),
            &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
        );
        assert!(!partial.is_complete());
        assert!(fixture.validate(&partial).is_err());
    }
}
