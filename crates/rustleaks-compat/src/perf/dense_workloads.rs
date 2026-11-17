//! Dense findings, long lines and many findings at library level.
//!
//! The dense shapes adapt the Kingfisher dense findings script (case names
//! `visible-catalog`, `single-line-visible`, `single-line-filter` and
//! `base64-uris`) to Rustleaks rules. Each shape runs at sizes that double
//! from 25,000 to 400,000 bytes, so the time ratio between neighbouring
//! sizes shows growth that is worse than linear. No upstream code or bytes are
//! copied. Expected findings come from the plants and their byte offsets.

use std::fmt;
use std::fs::File;
use std::hint::black_box;
use std::io::{BufReader, BufWriter, Write as _};
use std::time::Instant;

use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{Finding, Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanControl, ScanOutcome};
use rustleaks_report::{JsonReporter, Reporter};
use serde::Deserialize;
use serde::de::{Deserializer, SeqAccess, Visitor};
use serde_json::json;

use super::source_scale_workloads::{FindingKey, GITHUB_RULE, Scratch, key, verify_findings};
use super::suite_support::{
    DATABASE_URI_RULE, Lcg, Result, checked_github_token, keyword_census, pack_config,
};
use super::{Phase, elapsed, fingerprint, outcome_signature, phase};

pub(super) const WORKLOADS: &[&str] = &[
    "dense-github-lines",
    "dense-github-one-line",
    "dense-filter-one-line",
    "dense-base64-uris",
    "dense-long-line-sparse",
    "memory-many-findings-scan",
    "memory-many-findings-json",
];

/// Nominal sizes of the dense series. Each shape fills whole records up to the
/// size, so the exact byte count is in each phase row.
pub(super) const DENSE_SIZES: &[usize] = &[25_000, 50_000, 100_000, 200_000, 400_000];
/// Unit tests check the first two sizes of each series.
const SERIES_LENGTH: usize = if cfg!(test) { 2 } else { DENSE_SIZES.len() };
pub(super) const LONG_LINE_MIB: &[usize] = &[1, 4, 16];
const SCALE: usize = if cfg!(test) { 64 } else { 1 };
const MIB: usize = 1024 * 1024;
const LONG_LINE_TOKENS: usize = 8;
const MANY_FINDINGS: usize = 300_000 / SCALE;
const MANY_CONFIG: &str = "[[rules]]\nid = 'perf-many'\ndescription = 'many findings'\nregex = 'tok_[0-9]{12}'\nkeywords = ['tok_']\n";
const CLOUDFLARE_RULE: &str = "cloudflare-api-key";

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    if !(1..=super::MAX_ITERATIONS).contains(&iterations) {
        return Err("dense iterations are outside representative bounds".into());
    }
    match id {
        "dense-github-lines" | "dense-github-one-line" | "dense-filter-one-line" => {
            let config = ConfigLoader::new().load_default()?;
            series(id, iterations, config, b"default".to_vec(), 0)
        }
        "dense-base64-uris" => {
            let (config, _, identity) = pack_config(&["rustleaks-connections-v1"])?;
            series(id, iterations, config, identity, 1)
        }
        "dense-long-line-sparse" => {
            let config = ConfigLoader::new().load_default()?;
            series(id, iterations, config, b"default".to_vec(), 0)
        }
        "memory-many-findings-scan" | "memory-many-findings-json" => many_findings(id, iterations),
        _ => Err(format!("unknown dense workload {id}").into()),
    }
}

/// One generated input and its exact findings.
struct Shape {
    bytes: Vec<u8>,
    expected: Vec<FindingKey>,
    records: usize,
}

/// `ghp_` tokens, one per line (`visible-catalog`).
fn github_lines(size: usize) -> Result<Shape> {
    let mut bytes = Vec::with_capacity(size);
    let mut expected = Vec::new();
    let mut line = 1;
    while bytes.len() + 41 <= size {
        let token = checked_github_token(line)?;
        expected.push(key(
            GITHUB_RULE,
            "",
            "",
            line,
            if line == 1 { 1 } else { 2 },
            &token,
        ));
        bytes.extend_from_slice(&token);
        bytes.push(b'\n');
        line += 1;
    }
    Ok(finish(bytes, expected))
}

/// `ghp_` tokens separated by single spaces on one line (`single-line-visible`).
fn github_one_line(size: usize) -> Result<Shape> {
    let mut bytes = Vec::with_capacity(size);
    let mut expected = Vec::new();
    let mut index = 1;
    while bytes.len() + 41 <= size {
        let token = checked_github_token(index)?;
        expected.push(key(GITHUB_RULE, "", "", 1, bytes.len() + 1, &token));
        bytes.extend_from_slice(&token);
        bytes.push(b' ');
        index += 1;
    }
    Ok(finish(bytes, expected))
}

/// `cloudflare = '<40 bytes>'` records on one line (`single-line-filter`). Each
/// value is 20 `a` bytes then 20 `b` bytes, entropy 1.0, below the rule's
/// threshold of 2, so the entropy filter rejects it. The last record has a
/// value of 40 distinct-enough bytes and is the one expected finding, so a scan
/// that skips the line cannot pass.
fn filter_one_line(size: usize) -> Shape {
    const RECORD: &[u8] = b"cloudflare = 'aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb' ";
    const CONTROL: &[u8] = b"k3j5h7g9f2d4s6a8q1w3e5r7t9y2u4i6o8p1z3x5";
    let mut bytes = Vec::with_capacity(size);
    while bytes.len() + 2 * RECORD.len() <= size {
        bytes.extend_from_slice(RECORD);
    }
    let start = bytes.len();
    bytes.extend_from_slice(b"cloudflare = '");
    bytes.extend_from_slice(CONTROL);
    bytes.extend_from_slice(b"' ");
    finish(
        bytes,
        vec![key(CLOUDFLARE_RULE, "", "", 1, start + 1, CONTROL)],
    )
}

/// `mysql://user:<24 alphanumerics>@db.invalid/test ` repeated to three
/// quarters of the size, then encoded as one Base64 string (`base64-uris`).
/// Each password is a finding of the connections pack database URI rule in
/// decoded text. Decoded findings report the columns of the encoded text, so
/// every one starts at line 1, column 1.
fn base64_uris(size: usize) -> Shape {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = Lcg::new(0x7572_6973);
    let mut plain = Vec::with_capacity(size);
    let mut expected = Vec::new();
    while plain.len() + 50 <= size * 3 / 4 {
        let password = rng.string(ALPHABET, 24);
        plain.extend_from_slice(b"mysql://user:");
        plain.extend_from_slice(&password);
        plain.extend_from_slice(b"@db.invalid/test ");
        expected.push(key(DATABASE_URI_RULE, "", "", 1, 1, &password));
    }
    finish(super::super::base64(&plain), expected)
}

/// One line of filler words with eight `ghp_` tokens spread evenly.
fn long_line_sparse(config: &CompiledConfig, size: usize) -> Result<Shape> {
    let mut rng = Lcg::new(0x6c6f_6e67);
    let spacing = size / LONG_LINE_TOKENS;
    let mut bytes = Vec::with_capacity(size + 64);
    let mut filler = Vec::with_capacity(size);
    let mut expected = Vec::new();
    for index in 0..LONG_LINE_TOKENS {
        let token = checked_github_token(1_000 + index)?;
        expected.push(key(GITHUB_RULE, "", "", 1, bytes.len() + 1, &token));
        bytes.extend_from_slice(&token);
        bytes.push(b' ');
        while bytes.len() < (index + 1) * spacing {
            let word = super::suite_support::prose_line(&mut rng);
            let word = &word[..word.len() - 1];
            filler.extend_from_slice(word);
            filler.push(b' ');
            bytes.extend_from_slice(word);
            bytes.push(b' ');
        }
    }
    keyword_census(config, &filler)?;
    Ok(finish(bytes, expected))
}

fn finish(bytes: Vec<u8>, mut expected: Vec<FindingKey>) -> Shape {
    let records = expected.len();
    expected.sort();
    Shape {
        bytes,
        expected,
        records,
    }
}

fn validate(outcome: &ScanOutcome, shape: &Shape, decoded: bool) -> Result<()> {
    if !outcome.is_complete() || outcome.termination().is_some() {
        return Err("dense scan did not complete".into());
    }
    if decoded != (outcome.usage().decoded_bytes() > 0) {
        return Err("dense scan decoded bytes do not match the shape".into());
    }
    verify_findings(outcome.findings(), &shape.expected)?;
    Ok(())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the engine takes ownership of the compiled configuration"
)]
fn series(
    id: &str,
    iterations: usize,
    config: CompiledConfig,
    identity: Vec<u8>,
    depth: usize,
) -> Result<Vec<Phase>> {
    let long_line = id == "dense-long-line-sparse";
    let sizes = if long_line {
        LONG_LINE_MIB
            .iter()
            .map(|mib| mib * MIB / SCALE)
            .collect::<Vec<_>>()
    } else {
        DENSE_SIZES[..SERIES_LENGTH].to_vec()
    };
    let mut shapes = Vec::with_capacity(sizes.len());
    for size in &sizes {
        shapes.push(match id {
            "dense-github-lines" => github_lines(*size)?,
            "dense-github-one-line" => github_one_line(*size)?,
            "dense-filter-one-line" => filter_one_line(*size),
            "dense-base64-uris" => base64_uris(*size),
            _ => long_line_sparse(&config, *size)?,
        });
    }
    let engine = Engine::builder(config).build()?;
    let options = ScanOptions::builder().max_decode_depth(depth).build();
    // Build matchers on first use outside the timers with the smallest shape.
    let warm = Fragment::builder(shapes[0].bytes.clone())
        .start_line(1)
        .build();
    validate(
        &engine.scan_fragment_controlled(&warm, &options, &ScanControl::unlimited()),
        &shapes[0],
        depth > 0,
    )?;
    let mut phases = Vec::with_capacity(shapes.len());
    let names = if long_line {
        LONG_LINE_MIB
            .iter()
            .map(|mib| format!("scan-{mib}-mib"))
            .collect::<Vec<_>>()
    } else {
        DENSE_SIZES
            .iter()
            .map(|size| format!("scan-{size}-bytes"))
            .collect::<Vec<_>>()
    };
    for (shape, name) in shapes.iter().zip(names) {
        let fragment = Fragment::builder(shape.bytes.clone()).start_line(1).build();
        let mut result = phase(
            &name,
            iterations,
            0,
            shape.bytes.len() as u64,
            "input-bytes",
            &shape.bytes,
            &identity,
        );
        for _ in 0..iterations {
            let start = Instant::now();
            let outcome = black_box(engine.scan_fragment_controlled(
                black_box(&fragment),
                &options,
                &ScanControl::unlimited(),
            ));
            result.elapsed_ns += elapsed(start)?;
            // Validation and outcome destruction stay outside the timer.
            validate(&outcome, shape, depth > 0)?;
            result.outcome_fnv1a64 = outcome_signature(&outcome);
            result.counts = json!({
                "workers": 1, "decode_depth": depth, "records": shape.records,
                "lines": shape.bytes.iter().filter(|byte| **byte == b'\n').count().max(1),
                "work_units": outcome.usage().work_units(),
                "decoded_bytes": outcome.usage().decoded_bytes(),
                "finding_payload_bytes": outcome.usage().finding_payload_bytes(),
            });
        }
        result.findings = shape.expected.len() as u64;
        phases.push(result);
    }
    Ok(phases)
}

/// Line `n` (from 1) holds `tok_` and `n` in 12 digits.
fn many_token(line: usize) -> String {
    format!("tok_{line:012}")
}

/// Checks findings in order without building a second copy of them.
fn validate_many(outcome: &ScanOutcome) -> Result<()> {
    if !outcome.is_complete() || outcome.termination().is_some() {
        return Err("many-findings scan did not complete".into());
    }
    if outcome.findings().len() != MANY_FINDINGS {
        return Err(format!(
            "many-findings scan found {} findings, the input has {MANY_FINDINGS}",
            outcome.findings().len()
        )
        .into());
    }
    let mut sorted = outcome.findings().iter().collect::<Vec<&Finding>>();
    sorted.sort_by_key(|finding| finding.location().start_line());
    for (index, finding) in sorted.into_iter().enumerate() {
        let line = index + 1;
        if finding.rule_id().as_bytes() != b"perf-many"
            || finding.location().start_line() != line
            || finding.location().start_column() != if line == 1 { 1 } else { 2 }
            || finding.secret().as_bytes() != many_token(line).as_bytes()
        {
            return Err(format!("many-findings finding for line {line} differs").into());
        }
    }
    Ok(())
}

/// The report fields that identify one planted finding.
#[derive(Deserialize)]
struct ReportRow {
    #[serde(rename = "RuleID")]
    rule: String,
    #[serde(rename = "StartLine")]
    line: usize,
    #[serde(rename = "Secret")]
    secret: String,
}

/// Streams a JSON report array from the file. The check holds one element and
/// one line number per element, never the report text.
struct ReportCheck;

impl<'de> Visitor<'de> for ReportCheck {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON array of findings")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<usize, A::Error> {
        let mut rows = Vec::new();
        while let Some(row) = sequence.next_element::<ReportRow>()? {
            rows.push((
                row.line,
                row.rule == "perf-many" && row.secret == many_token(row.line),
            ));
        }
        rows.sort_unstable();
        for (index, (line, matches)) in rows.iter().enumerate() {
            if *line != index + 1 || !matches {
                return Err(serde::de::Error::custom(
                    "report row differs from the plant",
                ));
            }
        }
        Ok(rows.len())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keep the scan, report timers and their checks together"
)]
fn many_findings(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    let mut input = Vec::with_capacity(MANY_FINDINGS * 17);
    for line in 1..=MANY_FINDINGS {
        input.extend_from_slice(many_token(line).as_bytes());
        input.push(b'\n');
    }
    let engine = Engine::builder(ConfigLoader::new().load_toml(MANY_CONFIG)?).build()?;
    let fragment = Fragment::builder(input.clone()).start_line(1).build();
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let mut scan = phase(
        "scan",
        iterations,
        0,
        input.len() as u64,
        "input-bytes",
        &input,
        MANY_CONFIG.as_bytes(),
    );
    let mut outcome = None;
    for _ in 0..iterations {
        // Drop the previous outcome before the next scan so at most one is held.
        drop(outcome.take());
        let start = Instant::now();
        let current = black_box(engine.scan_fragment_controlled(
            black_box(&fragment),
            &options,
            &ScanControl::unlimited(),
        ));
        scan.elapsed_ns += elapsed(start)?;
        validate_many(&current)?;
        scan.outcome_fnv1a64 = outcome_signature(&current);
        outcome = Some(current);
    }
    let outcome = outcome.ok_or("many-findings scan did not run")?;
    scan.findings = MANY_FINDINGS as u64;
    scan.counts = json!({
        "workers": 1, "decode_depth": 0, "finding_records": outcome.usage().finding_records(),
        "finding_payload_bytes": outcome.usage().finding_payload_bytes(),
        "retained_outcomes": 1,
    });
    let mut phases = vec![scan];
    if id == "memory-many-findings-json" {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("report.json");
        let mut report = phase(
            "report-json-file",
            iterations,
            0,
            MANY_FINDINGS as u64,
            "findings",
            &input,
            MANY_CONFIG.as_bytes(),
        );
        for _ in 0..iterations {
            let start = Instant::now();
            let mut writer = BufWriter::new(File::create(&path)?);
            JsonReporter.write(black_box(&mut writer), black_box(outcome.findings()))?;
            writer.flush()?;
            drop(writer);
            report.elapsed_ns += elapsed(start)?;
            let bytes = std::fs::metadata(&path)?.len();
            let mut reader =
                serde_json::Deserializer::from_reader(BufReader::new(File::open(&path)?));
            let rows = (&mut reader).deserialize_seq(ReportCheck)?;
            reader.end()?;
            if rows != MANY_FINDINGS {
                return Err("JSON report row count differs from the plants".into());
            }
            report.outcome_fnv1a64 = fingerprint(format!("rows={rows};bytes={bytes}").as_bytes());
            report.counts = json!({
                "workers": 1, "output_bytes": bytes, "writer": "buffered-file",
                "check": "streamed from the file after the timer",
            });
        }
        report.findings = MANY_FINDINGS as u64;
        phases.push(report);
    }
    Ok(phases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_shapes_have_exact_outcomes_at_test_scale() {
        for id in WORKLOADS {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            assert!(!phases.is_empty(), "{id}");
            assert!(
                phases
                    .iter()
                    .all(|phase| phase.complete && phase.errors == 0)
            );
        }
    }

    #[test]
    fn dense_shapes_double_in_size_and_records() {
        for size in [25_000, 50_000] {
            let lines = github_lines(size).unwrap();
            assert_eq!(lines.records, size / 41);
            let one = github_one_line(size).unwrap();
            assert_eq!(one.records, size / 41);
            assert!(one.bytes.iter().all(|byte| *byte != b'\n'));
        }
        assert_eq!(filter_one_line(25_000).records, 1);
    }
}
