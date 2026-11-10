//! Contention cases on the shared-engine worker machinery with exact outcomes.
//!
//! Every fragment in a case is byte-identical, so one independently specified
//! outcome validates all workers regardless of completion order.

use std::time::Instant;

use rustleaks_core::config::{ConfigLoader, DEFAULT_CONFIG_BYTES};
use rustleaks_core::model::Fragment;
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde_json::json;

use super::super::worker_workloads::with_team;
use super::super::{Phase, elapsed, fingerprint, phase};
use super::{
    Context, Expected, Fallible, GITHUB_PAT_RULE, Lcg, MIB, Plant, RuleMeta, Scan,
    ensure_default_rules, filler, ghp_token, tiny_content, tiny_fragment, validate,
};

const SMALL_FRAGMENTS: usize = 64_000;
/// Line width of the dense fragment; one synthetic token per line.
const DENSE_STRIDE: usize = 64;

struct Case {
    workers: usize,
    fragments: Vec<Fragment>,
    probe: Scan,
    rules: Vec<RuleMeta>,
    input_bytes: usize,
}

fn small_case(ctx: Context<'_>, workers: usize) -> Fallible<Case> {
    let content = tiny_content(&ctx, 512)?;
    let expected = ctx.expected(&content, Vec::new(), 0)?;
    let fragments = (0..SMALL_FRAGMENTS)
        .map(|index| tiny_fragment(&content, index))
        .collect();
    Ok(Case {
        workers,
        fragments,
        probe: Scan {
            fragment: tiny_fragment(&content, 0),
            expected,
        },
        rules: ctx.rules,
        input_bytes: SMALL_FRAGMENTS * 512,
    })
}

fn dense_case(mut ctx: Context<'_>, workers: usize) -> Fallible<Case> {
    let rule = ctx.rule_index(GITHUB_PAT_RULE)?;
    let size = 4 * MIB;
    let mut rng = Lcg::new(0x6465_6e73);
    let mut raw = Vec::with_capacity(size);
    let mut plants = Vec::with_capacity(size / DENSE_STRIDE);
    while raw.len() + DENSE_STRIDE <= size {
        let start = raw.len();
        raw.extend_from_slice(&ghp_token(&mut rng));
        plants.push(Plant {
            rule,
            matched: (start, raw.len()),
            secret: (start, raw.len()),
        });
        raw.push(b' ');
        // Padding stays outside the token; the newline ends the line.
        raw.extend_from_slice(&filler(start + DENSE_STRIDE - 1 - raw.len()));
        raw.push(b'\n');
    }
    raw.resize(size, b'\n');
    let candidates = plants.len();
    let expected: Expected = ctx.expected(&raw, plants, candidates)?;
    let fragment = Fragment::builder(raw).build();
    let fragments = (0..workers).map(|_| fragment.clone()).collect();
    Ok(Case {
        workers,
        fragments,
        probe: Scan { fragment, expected },
        rules: ctx.rules,
        input_bytes: workers * size,
    })
}

#[allow(clippy::too_many_lines)] // Keep construction and persistent-worker phase boundaries together.
pub(super) fn run(id: &str, iterations: usize) -> Fallible<Vec<Phase>> {
    let start = Instant::now();
    let config = ConfigLoader::new().load_default()?;
    let compile_ns = elapsed(start)?;
    ensure_default_rules(&config)?;
    let ctx = Context::new(&config);
    let case = match id {
        "core-contention-16-threads-512-b" => small_case(ctx, 16)?,
        "core-contention-32-threads-512-b" => small_case(ctx, 32)?,
        "core-contention-dense-8-threads-4-mib" => dense_case(ctx, 8)?,
        _ => return Err(format!("unknown contention workload {id}").into()),
    };
    let rule_ids = fingerprint(config.ordered_rule_ids().join("\0").as_bytes());
    let mut compile = phase(
        "config-parse-and-compile",
        1,
        compile_ns,
        DEFAULT_CONFIG_BYTES.len() as u64,
        "config-bytes",
        DEFAULT_CONFIG_BYTES,
        DEFAULT_CONFIG_BYTES,
    );
    compile.outcome_fnv1a64.clone_from(&rule_ids);
    compile.counts["rules"] = json!(222);
    let start = Instant::now();
    let detector = Engine::builder(config).build()?;
    let mut construction = phase(
        "engine-construction",
        1,
        elapsed(start)?,
        222,
        "compiled-rules",
        DEFAULT_CONFIG_BYTES,
        DEFAULT_CONFIG_BYTES,
    );
    construction.outcome_fnv1a64 = rule_ids;
    let expected = &case.probe.expected;
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(expected.work.ok_or("contention requires exact work")?)
            .max_decoded_bytes(0)
            .max_finding_records(expected.findings.len()),
    );
    let input_hash = {
        let mut hash = super::super::super::FNV_OFFSET;
        for fragment in &case.fragments {
            hash = super::super::super::fnv_extend(hash, fragment.content().as_bytes());
        }
        format!("{hash:016x}")
    };
    with_team(
        &detector,
        &[],
        case.workers,
        &case.fragments,
        control,
        |team| {
            let mut phases = vec![compile, construction];
            let mut reference = None;
            for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
                let mut result = phase(
                    name,
                    count,
                    0,
                    case.input_bytes as u64,
                    "input-bytes",
                    &[],
                    DEFAULT_CONFIG_BYTES,
                );
                result.input_fnv1a64.clone_from(&input_hash);
                result.findings = (expected.findings.len() * case.fragments.len()) as u64;
                result.counts = json!({
                    "workers": case.workers,
                    "ownership": "shared",
                    "retained_engines": 1,
                    "retained_outcomes": case.fragments.len(),
                    "fragments": case.fragments.len(),
                    "fragment_bytes": case.probe.fragment.content().len(),
                    "decode_depth": 0,
                    "work_units": expected.work.map(|work| work * case.fragments.len()),
                    "decoded_bytes": 0,
                    "finding_records": expected.findings.len() * case.fragments.len(),
                    "operation": "concurrent-fragment-batch",
                });
                for _ in 0..count {
                    let (elapsed_ns, signature) =
                        team.batch(|outcome| validate(&case.rules, &case.probe, outcome))?;
                    if reference
                        .as_ref()
                        .is_some_and(|previous| previous != &signature)
                    {
                        return Err("contention outcome changed across batches".into());
                    }
                    result.elapsed_ns = result
                        .elapsed_ns
                        .checked_add(elapsed_ns)
                        .ok_or("contention elapsed time overflow")?;
                    result.outcome_fnv1a64.clone_from(&signature);
                    reference = Some(signature);
                }
                phases.push(result);
            }
            Ok(phases)
        },
    )
}
