//! Fixed fragment batches on persistent caller-owned worker threads.

use std::error::Error;
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Instant;

use rustleaks_core::config::{ConfigLoader, DEFAULT_CONFIG_BYTES};
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanOutcome};
use serde_json::json;

use super::fragment_workloads::Fixture;
use super::{Phase, elapsed, fingerprint, outcome_signature, phase};

const FIXTURE: &str = "core-fragments-json-12-mib-by-16-kib";
const FRAGMENTS: usize = 768;
const INPUT_BYTES: usize = 12 * 1024 * 1024;

pub(super) const WORKLOADS: &[&str] = &[
    "core-workers-default-shared-1",
    "core-workers-default-shared-4",
    "core-workers-default-shared-8",
    "core-workers-default-cloned-1",
    "core-workers-default-cloned-4",
    "core-workers-default-cloned-8",
];

#[derive(Clone, Copy)]
struct Specification {
    workers: usize,
    cloned: bool,
}

impl Specification {
    fn parse(id: &str) -> Result<Self, Box<dyn Error>> {
        if !WORKLOADS.contains(&id) {
            return Err("unknown worker workload".into());
        }
        let workers = id
            .rsplit_once('-')
            .ok_or("missing worker count")?
            .1
            .parse()?;
        Ok(Self {
            workers,
            cloned: id.contains("-cloned-"),
        })
    }

    const fn ownership(self) -> &'static str {
        if self.cloned {
            "clone-per-worker"
        } else {
            "shared"
        }
    }
}

type Batch = Vec<(usize, ScanOutcome)>;

enum Message {
    Ready(usize),
    Complete(usize, Batch),
    Panicked(usize),
}

struct Team {
    commands: Vec<SyncSender<Batch>>,
    completed: Receiver<Message>,
    buffers: Vec<Option<Batch>>,
    fragment_count: usize,
}

impl Team {
    fn await_ready(&self) -> Result<(), Box<dyn Error>> {
        let mut seen = vec![false; self.commands.len()];
        for _ in 0..self.commands.len() {
            let Message::Ready(worker) = self.completed.recv()? else {
                return Err("worker omitted its ready marker".into());
            };
            if worker >= seen.len() || seen[worker] {
                return Err("invalid or duplicated ready worker".into());
            }
            seen[worker] = true;
        }
        Ok(())
    }

    fn batch(
        &mut self,
        validate: impl Fn(&ScanOutcome) -> Result<(), Box<dyn Error>>,
    ) -> Result<(u64, String), Box<dyn Error>> {
        let inputs = self
            .buffers
            .iter_mut()
            .map(Option::take)
            .collect::<Option<Vec<_>>>()
            .ok_or("missing worker result buffer")?;
        let mut batches = Vec::with_capacity(self.commands.len());
        // Buffers and threads already exist. This wall timer includes command
        // dispatch, all scans, result-vector pushes and completion messages.
        let start = Instant::now();
        for (sender, buffer) in self.commands.iter().zip(inputs) {
            sender
                .send(buffer)
                .map_err(|_| "worker command channel closed")?;
        }
        for _ in 0..self.commands.len() {
            match self.completed.recv()? {
                Message::Complete(worker, outcomes) => batches.push((worker, outcomes)),
                Message::Panicked(worker) => {
                    return Err(format!("scan worker {worker} panicked").into());
                }
                Message::Ready(_) => return Err("unexpected repeated ready marker".into()),
            }
        }
        let elapsed_ns = elapsed(start)?;

        // No worker validates, hashes or destroys outcomes while scans are
        // timed. Validate each original fragment index exactly once, regardless
        // of thread completion order, before reusing the empty result buffers.
        let mut seen_workers = vec![false; self.commands.len()];
        let mut signatures = vec![None; self.fragment_count];
        for (worker, mut outcomes) in batches {
            if worker >= seen_workers.len() || seen_workers[worker] {
                return Err("invalid or duplicated completed worker".into());
            }
            seen_workers[worker] = true;
            let expected_count = (worker..self.fragment_count)
                .step_by(self.commands.len())
                .count();
            if outcomes.len() != expected_count {
                return Err("worker skipped or added a fragment".into());
            }
            for (index, outcome) in outcomes.drain(..) {
                if index % self.commands.len() != worker {
                    return Err("worker returned another partition's fragment".into());
                }
                let signature = signatures.get_mut(index).ok_or("invalid fragment index")?;
                if signature.is_some() {
                    return Err("worker returned a duplicate fragment".into());
                }
                validate(&outcome)?;
                *signature = Some(outcome_signature(&outcome));
            }
            self.buffers[worker] = Some(outcomes);
        }
        let signatures = signatures
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or("worker batch omitted a fragment")?;
        Ok((elapsed_ns, fingerprint(signatures.concat().as_bytes())))
    }
}

fn with_team<T>(
    detector: &Engine,
    clones: &[Engine],
    workers: usize,
    fragments: &[Fragment],
    control: ScanControl<'static>,
    run: impl FnOnce(&mut Team) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    if ![1, 4, 8].contains(&workers) || (!clones.is_empty() && clones.len() != workers) {
        return Err("invalid worker or engine count".into());
    }
    thread::scope(|scope| {
        let (completed, receiver) = mpsc::sync_channel(workers);
        let mut team = Team {
            commands: Vec::with_capacity(workers),
            completed: receiver,
            buffers: Vec::with_capacity(workers),
            fragment_count: fragments.len(),
        };
        for worker in 0..workers {
            let (sender, commands) = mpsc::sync_channel::<Batch>(1);
            team.commands.push(sender);
            team.buffers.push(Some(Vec::with_capacity(
                (worker..fragments.len()).step_by(workers).count(),
            )));
            let completed = completed.clone();
            let detector = clones.get(worker).unwrap_or(detector);
            let _handle = thread::Builder::new()
                .name(format!("rustleaks-perf-{worker}"))
                .spawn_scoped(scope, move || {
                    if completed.send(Message::Ready(worker)).is_err() {
                        return;
                    }
                    while let Ok(mut outcomes) = commands.recv() {
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            for index in (worker..fragments.len()).step_by(workers) {
                                let outcome = black_box(detector.scan_fragment_controlled(
                                    black_box(&fragments[index]),
                                    &ScanOptions::default(),
                                    &control,
                                ));
                                outcomes.push((index, outcome));
                            }
                            outcomes
                        }));
                        if let Ok(outcomes) = result {
                            if completed.send(Message::Complete(worker, outcomes)).is_err() {
                                return;
                            }
                        } else {
                            let _ = completed.send(Message::Panicked(worker));
                            return;
                        }
                    }
                })?;
        }
        drop(completed);
        team.await_ready()?;
        let result = run(&mut team);
        // Closing command and result channels also releases workers on errors.
        // The scope joins all of them before the engines or fragments can drop.
        drop(team);
        result
    })
}

#[allow(clippy::too_many_lines)] // Keep construction and persistent-worker phase boundaries together.
pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    let specification = Specification::parse(id)?;
    if !(1..=super::MAX_ITERATIONS).contains(&iterations) {
        return Err("worker iterations are outside representative bounds".into());
    }
    let start = Instant::now();
    let config = ConfigLoader::new().load_default()?;
    let compile_ns = elapsed(start)?;
    if config.rules().len() != 222
        || super::super::config_metric(&config).fingerprint != 0xbba0_f636_d5a0_2d49
    {
        return Err("worker default configuration differs from the legacy invariant".into());
    }
    let fixture = Fixture::new(FIXTURE, &config)?;
    if fixture.fragments.len() != FRAGMENTS || fixture.input.len() != INPUT_BYTES {
        return Err("worker fixture must contain 768 fragments totaling 12 MiB".into());
    }
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
    construction.outcome_fnv1a64.clone_from(&rule_ids);
    let start = Instant::now();
    let clones = if specification.cloned {
        (0..specification.workers)
            .map(|_| detector.clone())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut cloning = phase(
        "engine-clone-setup",
        1,
        elapsed(start)?,
        clones.len() as u64,
        "engine-clones",
        DEFAULT_CONFIG_BYTES,
        DEFAULT_CONFIG_BYTES,
    );
    cloning.outcome_fnv1a64 = rule_ids;
    cloning.counts = json!({
        "workers":specification.workers, "ownership":specification.ownership(),
        "clones":clones.len(), "retained_engines":1 + clones.len(),
        "source_engine_warmed":false,
    });
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(fixture.work_per_fragment)
            .max_decoded_bytes(0)
            .max_finding_records(1),
    );
    with_team(
        &detector,
        &clones,
        specification.workers,
        &fixture.fragments,
        control,
        |team| {
            let mut phases = vec![compile, construction, cloning];
            let mut expected_signature = None;
            for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
                let mut result = phase(
                    name,
                    count,
                    0,
                    INPUT_BYTES as u64,
                    "input-bytes",
                    &fixture.input,
                    DEFAULT_CONFIG_BYTES,
                );
                result.findings = FRAGMENTS as u64;
                result.counts = json!({
                    "workers":specification.workers, "ownership":specification.ownership(),
                    "retained_engines":1 + clones.len(), "retained_outcomes":FRAGMENTS,
                    "fragments":FRAGMENTS, "fragment_bytes":16 * 1024, "decode_depth":0,
                    "admitted_rules_per_fragment":fixture.admitted_rules,
                    "keyword_occurrences_per_fragment":fixture.keyword_occurrences_per_fragment,
                    "work_units":fixture.work_per_fragment * FRAGMENTS,
                    "decoded_bytes":0, "finding_records":FRAGMENTS,
                    "operation":"concurrent-fragment-batch",
                    "timer_includes":"command dispatch, scans, result collection",
                    "validation_and_outcome_destruction":"after all workers complete, outside timer",
                    "warmup":"none; first batch searches on persistent workers",
                });
                for _ in 0..count {
                    let (elapsed_ns, signature) =
                        team.batch(|outcome| fixture.validate(outcome))?;
                    if expected_signature
                        .as_ref()
                        .is_some_and(|expected| expected != &signature)
                    {
                        return Err("worker outcome changed across batches".into());
                    }
                    result.elapsed_ns = result
                        .elapsed_ns
                        .checked_add(elapsed_ns)
                        .ok_or("worker elapsed time overflow")?;
                    result.outcome_fnv1a64.clone_from(&signature);
                    expected_signature = Some(signature);
                }
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
    fn persistent_workers_validate_small_batches_in_both_ownership_modes() {
        let raw = b"token=ABCDEFGHIJKLMNOP";
        let config = ConfigLoader::new()
            .load_toml(super::super::SIMPLE_CONFIG)
            .unwrap();
        let detector = Engine::builder(config).build().unwrap();
        let fragments = (0..8)
            .map(|_| Fragment::builder(raw.as_slice()).build())
            .collect::<Vec<_>>();
        let expected = super::super::expected_token(raw, 0, raw.len(), false).unwrap();
        let control = ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_work_units(4)
                .max_finding_records(1)
                .max_decoded_bytes(0),
        );
        for id in WORKLOADS {
            let specification = Specification::parse(id).unwrap();
            let clones = if specification.cloned {
                (0..specification.workers)
                    .map(|_| detector.clone())
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            with_team(
                &detector,
                &clones,
                specification.workers,
                &fragments,
                control,
                |team| {
                    let validate = |outcome: &ScanOutcome| -> Result<(), Box<dyn Error>> {
                        if !outcome.is_complete()
                            || outcome.termination().is_some()
                            || outcome.findings() != std::slice::from_ref(&expected)
                            || outcome.usage().work_units() != 4
                            || outcome.usage().finding_records() != 1
                            || outcome.usage().decoded_bytes() != 0
                        {
                            return Err("small worker fixture changed".into());
                        }
                        Ok(())
                    };
                    let (_, first) = team.batch(validate)?;
                    let (_, second) = team.batch(validate)?;
                    assert_eq!(first, second);
                    Ok(())
                },
            )
            .unwrap();
        }
    }
}
