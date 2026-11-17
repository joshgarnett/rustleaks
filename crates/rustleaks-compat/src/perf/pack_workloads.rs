//! Native rule pack workloads at library level: startup with each pack and all
//! packs, keyword admission, a mixed input with plants, and shared-engine
//! worker scaling.
//!
//! These workloads guard the pack scan paths: one shared keyword pass for
//! native rules, the allowlist compile cache, matcher construction on first
//! use, and the required-literal skip for keyword-less pack rules. Expected
//! findings come from the planted values and their byte offsets.

use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanControl, ScanOutcome};
use serde_json::json;

use super::source_scale_workloads::{FindingKey, GITHUB_RULE, key, token_row, verify_findings};
use super::suite_support::{
    DATABASE_URI_RULE, Lcg, PACKS, PackSelection, Result, check_rule_count, checked_github_token,
    compile_packs, database_uri, keyword_census, pack_selection, prose_line,
};
use super::worker_workloads::with_team;
use super::{Phase, elapsed, fingerprint, outcome_signature, phase};

pub(super) const WORKLOADS: &[&str] = &[
    "packs-startup-none",
    "packs-startup-extra",
    "packs-startup-providers",
    "packs-startup-connections",
    "packs-startup-all",
    "packs-keywords-none",
    "packs-keywords-all",
    "packs-mixed-none",
    "packs-mixed-all",
    "packs-workers-all-1",
    "packs-workers-all-4",
    "packs-workers-all-8",
];

const KIB: usize = 1024;
/// Unit tests run the same generators over smaller inputs.
const SCALE: usize = if cfg!(test) { 16 } else { 1 };
const KEYWORD_BYTES: usize = 256 * KIB / SCALE;
const MIXED_BYTES: usize = 1024 * KIB / SCALE;
const WORKER_FRAGMENT_BYTES: usize = 64 * KIB / SCALE;
const WORKER_FRAGMENTS: usize = 64;
/// One plant of each kind per this many filler lines.
const PLANT_EVERY: usize = 64;

fn selected_packs(id: &str) -> Result<Vec<&'static str>> {
    let all = PACKS.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    let suffix = id.rsplit('-').next().ok_or("missing pack selection")?;
    let suffix = if id.starts_with("packs-workers-") {
        "all"
    } else {
        suffix
    };
    Ok(match suffix {
        "none" => Vec::new(),
        "all" => all,
        "extra" => vec!["rustleaks-extra-v1"],
        "providers" => vec!["rustleaks-providers-v1"],
        "connections" => vec!["rustleaks-connections-v1"],
        _ => return Err(format!("unknown pack selection in {id}").into()),
    })
}

/// A scan input and its exact expected findings.
struct Input {
    bytes: Vec<u8>,
    expected: Vec<FindingKey>,
    plants: usize,
}

/// Lines of filler with a GitHub token row and a database URI row planted
/// every `PLANT_EVERY` lines. The URI is a finding only with the connections
/// pack. Columns follow the one-fragment rule: the first line counts from 1,
/// later lines from 2.
fn mixed_input(config: &CompiledConfig, size: usize, connections: bool) -> Result<Input> {
    let mut rng = Lcg::new(0x7061_636b);
    let mut bytes = Vec::with_capacity(size + 128);
    let mut filler = Vec::with_capacity(size);
    let mut expected = Vec::new();
    let mut line = 1_usize;
    let mut plants = 0_usize;
    while bytes.len() < size {
        let column = if line == 1 { 1 } else { 2 };
        if line % PLANT_EVERY == 2 {
            let token = checked_github_token(plants)?;
            expected.push(key(GITHUB_RULE, "", "", line, column, &token));
            bytes.extend_from_slice(&token_row(&token));
            plants += 1;
        } else if line % PLANT_EVERY == PLANT_EVERY / 2 {
            let (uri, password) = database_uri(plants);
            if connections {
                expected.push(key(DATABASE_URI_RULE, "", "", line, column, &password));
            }
            bytes.extend_from_slice(&uri);
            bytes.push(b'\n');
            plants += 1;
        } else {
            let text = prose_line(&mut rng);
            filler.extend_from_slice(&text);
            bytes.extend_from_slice(&text);
        }
        line += 1;
    }
    keyword_census(config, &filler)?;
    expected.sort();
    Ok(Input {
        bytes,
        expected,
        plants,
    })
}

/// A small input with one GitHub token and one database URI.
fn startup_input(config: &CompiledConfig, connections: bool) -> Result<Input> {
    let mut rng = Lcg::new(0x7374_6172);
    let first = prose_line(&mut rng);
    keyword_census(config, &first)?;
    let token = checked_github_token(7)?;
    let (uri, password) = database_uri(7);
    let mut bytes = first;
    bytes.extend_from_slice(&token_row(&token));
    bytes.extend_from_slice(&uri);
    bytes.push(b'\n');
    let mut expected = vec![key(GITHUB_RULE, "", "", 2, 2, &token)];
    if connections {
        expected.push(key(DATABASE_URI_RULE, "", "", 3, 2, &password));
    }
    expected.sort();
    Ok(Input {
        bytes,
        expected,
        plants: 2,
    })
}

/// Every keyword of the selected configuration that contains no other keyword,
/// each followed by a NUL byte and repeated. A bare keyword between NUL bytes
/// is too short for every rule pattern, so the keywords produce no finding. A
/// GitHub token row after the keywords is the one expected finding, so a scan
/// that skips the input cannot pass.
fn keyword_input(config: &CompiledConfig, size: usize) -> Result<Input> {
    let independent = config
        .keywords()
        .iter()
        .filter(|keyword| {
            !keyword.is_empty()
                && !config
                    .keywords()
                    .iter()
                    .any(|other| other != *keyword && keyword.contains(other.as_str()))
        })
        .collect::<Vec<_>>();
    let mut bytes = super::super::keyword_input(config, independent.len(), size)?;
    if !independent
        .iter()
        .all(|keyword| super::super::contains_bytes(&bytes, keyword.as_bytes()))
    {
        return Err("keyword input omits an independent keyword".into());
    }
    let token = checked_github_token(9)?;
    bytes.push(b'\n');
    let line = line_count(&bytes) + 1;
    bytes.extend_from_slice(&token_row(&token));
    Ok(Input {
        bytes,
        expected: vec![key(GITHUB_RULE, "", "", line, 2, &token)],
        plants: independent.len() + 1,
    })
}

#[allow(
    clippy::naive_bytecount,
    reason = "bounded fixture count outside timers"
)]
fn line_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

fn validate(outcome: &ScanOutcome, expected: &[FindingKey]) -> Result<()> {
    if !outcome.is_complete() || outcome.termination().is_some() {
        return Err("pack scan did not complete".into());
    }
    if outcome.usage().decoded_bytes() != 0 {
        return Err("pack scan decoded bytes at depth 0".into());
    }
    verify_findings(outcome.findings(), expected)?;
    Ok(())
}

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>> {
    if !WORKLOADS.contains(&id) {
        return Err(format!("unknown pack workload {id}").into());
    }
    if !(1..=super::MAX_ITERATIONS).contains(&iterations) {
        return Err("pack iterations are outside representative bounds".into());
    }
    let packs = selected_packs(id)?;
    let connections = packs.contains(&"rustleaks-connections-v1");
    // Pack text, its declared rule count and the identity bytes are prepared
    // before the timer, which covers only the native policy compile.
    let selection = pack_selection(&packs)?;
    let start = Instant::now();
    let config = black_box(compile_packs(&selection)?);
    let compile_ns = elapsed(start)?;
    check_rule_count(&config, &selection)?;
    let PackSelection {
        rules, identity, ..
    } = selection;
    let input = if id.starts_with("packs-startup-") {
        startup_input(&config, connections)?
    } else if id.starts_with("packs-keywords-") {
        keyword_input(&config, KEYWORD_BYTES)?
    } else if id.starts_with("packs-mixed-") {
        mixed_input(&config, MIXED_BYTES, connections)?
    } else {
        mixed_input(&config, WORKER_FRAGMENT_BYTES, connections)?
    };
    let rule_ids = fingerprint(config.ordered_rule_ids().join("\0").as_bytes());
    let mut compile = phase(
        "config-parse-and-compile",
        1,
        compile_ns,
        identity.len() as u64,
        "config-bytes",
        &identity,
        &identity,
    );
    compile.outcome_fnv1a64.clone_from(&rule_ids);
    compile.counts = json!({"rules": rules, "packs": packs, "loader": "native-policy"});
    let start = Instant::now();
    let engine = black_box(Engine::builder(config).build()?);
    let mut construction = phase(
        "engine-construction",
        1,
        elapsed(start)?,
        rules as u64,
        "compiled-rules",
        &identity,
        &identity,
    );
    construction.outcome_fnv1a64 = rule_ids;
    if id.starts_with("packs-workers-") {
        return run_workers(
            id,
            iterations,
            &engine,
            &input,
            &identity,
            vec![compile, construction],
        );
    }
    let fragment = Fragment::builder(input.bytes.clone()).start_line(1).build();
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let mut phases = vec![compile, construction];
    for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
        let mut result = phase(
            name,
            count,
            0,
            input.bytes.len() as u64,
            "input-bytes",
            &input.bytes,
            &identity,
        );
        for _ in 0..count {
            let start = Instant::now();
            let outcome = black_box(engine.scan_fragment_controlled(
                black_box(&fragment),
                &options,
                &ScanControl::unlimited(),
            ));
            result.elapsed_ns += elapsed(start)?;
            // Validation and outcome destruction stay outside the timer.
            validate(&outcome, &input.expected)?;
            let signature = outcome_signature(&outcome);
            if result.outcome_fnv1a64 != fingerprint(&[]) && result.outcome_fnv1a64 != signature {
                return Err("pack outcome changed between iterations".into());
            }
            result.outcome_fnv1a64 = signature;
            result.counts = json!({
                "workers": 1, "packs": packs, "decode_depth": 0, "plants": input.plants,
                "work_units": outcome.usage().work_units(),
                "finding_records": outcome.usage().finding_records(),
            });
        }
        result.findings = input.expected.len() as u64;
        phases.push(result);
    }
    Ok(phases)
}

fn run_workers(
    id: &str,
    iterations: usize,
    engine: &Engine,
    input: &Input,
    identity: &[u8],
    mut phases: Vec<Phase>,
) -> Result<Vec<Phase>> {
    let workers: usize = id
        .rsplit('-')
        .next()
        .ok_or("missing worker count")?
        .parse()?;
    let fragments = (0..WORKER_FRAGMENTS)
        .map(|_| Fragment::builder(input.bytes.clone()).start_line(1).build())
        .collect::<Vec<_>>();
    let total = input.bytes.len() * WORKER_FRAGMENTS;
    with_team(
        engine,
        &[],
        workers,
        &fragments,
        ScanControl::unlimited(),
        |team| {
            let mut expected_signature = None;
            for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
                let mut result = phase(
                    name,
                    count,
                    0,
                    total as u64,
                    "input-bytes",
                    &input.bytes,
                    identity,
                );
                for _ in 0..count {
                    let (elapsed_ns, signature) =
                        team.batch(|outcome| validate(outcome, &input.expected))?;
                    if expected_signature
                        .as_ref()
                        .is_some_and(|expected| expected != &signature)
                    {
                        return Err("pack worker outcome changed across batches".into());
                    }
                    result.elapsed_ns = result
                        .elapsed_ns
                        .checked_add(elapsed_ns)
                        .ok_or("pack worker elapsed time overflow")?;
                    result.outcome_fnv1a64.clone_from(&signature);
                    expected_signature = Some(signature);
                }
                result.findings = (input.expected.len() * WORKER_FRAGMENTS) as u64;
                result.counts = json!({
                    "workers": workers, "ownership": "shared", "fragments": WORKER_FRAGMENTS,
                    "fragment_bytes": input.bytes.len(), "decode_depth": 0,
                    "timer_includes": "command dispatch, scans, result collection",
                });
                phases.push(result);
            }
            Ok(phases)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_workloads_have_exact_outcomes_at_test_scale() {
        for id in WORKLOADS {
            let phases = run(id, 1).unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_eq!(phases.len(), 4, "{id}");
            assert_eq!(phases[2].outcome_fnv1a64, phases[3].outcome_fnv1a64, "{id}");
        }
    }
}
