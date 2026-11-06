//! Separate steady-operation protocol for profiling and calibration.
//! This does not change representative or legacy measurements.

use std::error::Error;
use std::hint::black_box;
use std::io::{BufRead, Read, Write};
use std::time::{Duration, Instant};

use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde_json::{Value, json};

use super::{Fixture, WORKLOADS, fingerprint, outcome_signature};

const SCOPE: &str = "investigation-v1-steady-scan-only";
const WINDOW_SCOPE: &str = "investigation-v2-summed-scan-windows";

struct Worker {
    fixture: Fixture,
    detector: Engine,
    fragment: Fragment,
    options: ScanOptions,
    control: ScanControl<'static>,
    identity: Value,
}

impl Worker {
    fn new(workload: &str) -> Result<Self, Box<dyn Error>> {
        if !workload.starts_with("core-") || !WORKLOADS.contains(&workload) {
            return Err("investigation requires a representative core workload".into());
        }
        let mut fixture = Fixture::new(workload)?;
        let config = fixture.compile()?;
        if config.rules().len() != fixture.expected_rules
            || fixture.expected_rules == 222
                && super::super::config_metric(&config).fingerprint != 0xbba0_f636_d5a0_2d49
        {
            return Err("investigation compiled rules differ".into());
        }
        if fixture.keyword_count > 0 {
            fixture.input = super::super::keyword_input(&config, fixture.keyword_count, 16 * 1024)?;
            let matched = config
                .keywords()
                .iter()
                .filter(|keyword| super::super::contains_bytes(&fixture.input, keyword.as_bytes()))
                .count();
            if matched != fixture.keyword_count {
                return Err("investigation keyword count differs".into());
            }
        }
        let detector = Engine::builder(config).build()?;
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
        // Setup and this warm scan finish before the ready marker or any timer.
        let warm = detector.scan_fragment_controlled(&fragment, &options, &control);
        fixture.validate(&warm)?;
        let identity = json!({
            "workload": workload, "input_bytes": fixture.input.len(),
            "input_fnv1a64": fingerprint(&fixture.input),
            "config_fnv1a64": fingerprint(fixture.config.as_bytes()),
            "outcome_fnv1a64": outcome_signature(&warm),
            "rules": fixture.expected_rules, "keywords": fixture.keyword_count,
            "findings": warm.findings().len(), "decoded_bytes": warm.usage().decoded_bytes(),
            "work_units": warm.usage().work_units(), "finding_records": warm.usage().finding_records(),
            "complete": true, "errors": 0,
        });
        Ok(Self {
            fixture,
            detector,
            fragment,
            options,
            control,
            identity,
        })
    }

    fn scan(&self) -> Result<u64, Box<dyn Error>> {
        let start = Instant::now();
        let outcome = black_box(self.detector.scan_fragment_controlled(
            black_box(&self.fragment),
            black_box(&self.options),
            &self.control,
        ));
        let elapsed = u64::try_from(start.elapsed().as_nanos())?;
        self.fixture.validate(&outcome)?;
        if self.identity["outcome_fnv1a64"] != outcome_signature(&outcome) {
            return Err("investigation outcome or work counts changed".into());
        }
        Ok(elapsed)
    }

    fn sample(&self, iterations: u64, extra_passes: u64) -> Result<Value, Box<dyn Error>> {
        if !(1..=100).contains(&iterations) || extra_passes > 1 {
            return Err("sample bounds are iterations 1..=100 and extra passes 0..=1".into());
        }
        let mut elapsed_ns = 0_u64;
        for _ in 0..iterations * (extra_passes + 1) {
            elapsed_ns = elapsed_ns
                .checked_add(self.scan()?)
                .ok_or("elapsed overflow")?;
        }
        Ok(
            json!({"kind":"sample", "scope":SCOPE, "identity":self.identity,
            "iterations":iterations, "extra_passes":extra_passes,
            "actual_scan_count":iterations*(extra_passes+1), "elapsed_ns":elapsed_ns,
            "ns_per_logical_iteration":elapsed_ns/iterations,
            "control":"extra pass is deliberate redundant work, not changed production behavior"}),
        )
    }

    fn window(
        &self,
        blocks: u64,
        iterations: u64,
        extra_passes: u64,
        mut output: impl FnMut(&Value) -> Result<(), Box<dyn Error>>,
    ) -> Result<(), Box<dyn Error>> {
        if !(1..=16).contains(&blocks) || !(1..=100).contains(&iterations) || extra_passes > 1 {
            return Err(
                "window bounds are blocks 1..=16, iterations 1..=100 and extra passes 0..=1".into(),
            );
        }
        let total_iterations = blocks.checked_mul(iterations).ok_or("iteration overflow")?;
        let mut elapsed_ns = 0_u64;
        let mut actual_scan_count = 0_u64;
        for block_index in 0..blocks {
            // This is the existing sample operation; every scan retains its
            // original timer, validation, and outcome destruction boundary.
            let sample = self.sample(iterations, extra_passes)?;
            elapsed_ns = elapsed_ns
                .checked_add(
                    sample["elapsed_ns"]
                        .as_u64()
                        .ok_or("invalid sample elapsed")?,
                )
                .ok_or("window elapsed overflow")?;
            actual_scan_count = actual_scan_count
                .checked_add(
                    sample["actual_scan_count"]
                        .as_u64()
                        .ok_or("invalid sample scan count")?,
                )
                .ok_or("window scan count overflow")?;
            output(&json!({
                "schema_version":2,"kind":"window-component","scope":WINDOW_SCOPE,
                "block_index":block_index,"window_blocks":blocks,
                "iterations_per_block":iterations,"extra_passes":extra_passes,
                "identity":self.identity,"sample":sample,
            }))?;
        }
        output(&json!({
            "schema_version":2,"kind":"window-complete","scope":WINDOW_SCOPE,
            "window_blocks":blocks,"iterations_per_block":iterations,
            "extra_passes":extra_passes,"total_iterations":total_iterations,
            "actual_scan_count":actual_scan_count,"elapsed_ns":elapsed_ns,
            "identity":self.identity,
        }))
    }

    fn profile(&self, seconds: u64) -> Result<Value, Box<dyn Error>> {
        if !(1..=60).contains(&seconds) {
            return Err("profile seconds must be in 1..=60".into());
        }
        let start = Instant::now();
        let mut scans = 0_u64;
        let mut scan_ns = 0_u64;
        while start.elapsed() < Duration::from_secs(seconds) {
            scan_ns = scan_ns
                .checked_add(self.scan()?)
                .ok_or("elapsed overflow")?;
            scans += 1;
        }
        Ok(json!({"kind":"profile-complete", "identity":self.identity,
            "scope":"steady-scan-loop-includes-validation-and-outcome-destruction",
            "requested_seconds":seconds, "actual_scan_count":scans,
            "scan_elapsed_ns":scan_ns, "loop_elapsed_ns":u64::try_from(start.elapsed().as_nanos())?}))
    }
}

fn emit(value: &Value) -> Result<(), Box<dyn Error>> {
    println!("{value}");
    std::io::stdout().flush()?;
    Ok(())
}

pub fn main(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let [mode, option, workload] = arguments else {
        return Err("expected --investigate --workload ID".into());
    };
    if mode != "--investigate" || option != "--workload" {
        return Err("expected --investigate --workload ID".into());
    }
    let provenance = super::super::provenance()?;
    let worker = Worker::new(workload)?;
    emit(&json!({"schema_version":1,"kind":"ready","scope":SCOPE,
        "identity":worker.identity,"provenance":provenance,
        "setup":"configuration,engine,fixture and one validated warm scan complete"}))?;
    let mut input = std::io::stdin().lock();
    for _ in 0..100 {
        let mut line = String::new();
        if input.by_ref().take(129).read_line(&mut line)? == 0 {
            return Err("investigation controller disconnected before quit".into());
        }
        if line.len() > 128 || !line.ends_with('\n') {
            return Err("invalid investigation command".into());
        }
        let words = line.split_whitespace().collect::<Vec<_>>();
        match words.as_slice() {
            ["sample", count, extra] => emit(&worker.sample(count.parse()?, extra.parse()?)?)?,
            ["window", blocks, count, extra] => {
                worker.window(blocks.parse()?, count.parse()?, extra.parse()?, emit)?;
            }
            ["profile", seconds] => emit(&worker.profile(seconds.parse()?)?)?,
            ["quit"] => {
                emit(&json!({"kind":"finished"}))?;
                return Ok(());
            }
            _ => return Err("unknown investigation command".into()),
        }
    }
    Err("investigation command count exceeded".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_worker_retains_the_representative_fixture_and_exact_outcome() {
        let worker = Worker::new("core-dense-16-kib").unwrap();
        // These identities and counts are the existing representative fixture's
        // contract, not a separate dense input created for investigation.
        assert_eq!(
            worker.identity,
            json!({
                "workload": "core-dense-16-kib", "input_bytes": 16384,
                "input_fnv1a64": "3e812ba2e5c2f925", "config_fnv1a64": "f8b26dc4f7787416",
                "outcome_fnv1a64": "b80de9ceab6a9984", "rules": 1, "keywords": 0,
                "findings": 256, "decoded_bytes": 0, "work_units": 514,
                "finding_records": 256, "complete": true, "errors": 0,
            })
        );
        worker.scan().unwrap();
    }

    #[test]
    fn redundant_work_control_preserves_exact_outcomes_and_counts_its_work() {
        let worker = Worker::new("core-mixed-1-kib").unwrap();
        let ordinary = worker.sample(2, 0).unwrap();
        let control = worker.sample(2, 1).unwrap();
        assert_eq!(ordinary["identity"], control["identity"]);
        assert_eq!(ordinary["actual_scan_count"], 2);
        assert_eq!(control["actual_scan_count"], 4);
        assert!(worker.sample(0, 0).is_err());
        assert!(worker.sample(101, 0).is_err());
        assert!(worker.sample(1, 2).is_err());
        assert!(Worker::new("serialize-json-10000").is_err());
    }

    #[test]
    fn window_emits_ordered_legacy_samples_and_only_then_completion() {
        let worker = Worker::new("core-mixed-1-kib").unwrap();
        for (blocks, extra, expected_scans) in [(1, 0, 1), (10, 1, 20)] {
            let mut records = Vec::new();
            worker
                .window(blocks, 1, extra, |record| {
                    records.push(record.clone());
                    Ok(())
                })
                .unwrap();
            assert_eq!(records.len(), usize::try_from(blocks + 1).unwrap());
            let complete = records.pop().unwrap();
            assert_eq!(complete["kind"], "window-complete");
            assert_eq!(complete["total_iterations"], blocks);
            assert_eq!(complete["actual_scan_count"], expected_scans);
            assert_eq!(complete["identity"], worker.identity);
            let mut sum = 0_u64;
            for (index, component) in records.iter().enumerate() {
                assert_eq!(component["kind"], "window-component");
                assert_eq!(component["block_index"], index);
                assert_eq!(component["scope"], WINDOW_SCOPE);
                assert_eq!(component["sample"]["kind"], "sample");
                assert_eq!(component["sample"]["scope"], SCOPE);
                assert_eq!(component["sample"]["identity"], worker.identity);
                assert_eq!(component["sample"]["actual_scan_count"], extra + 1);
                sum = sum
                    .checked_add(component["sample"]["elapsed_ns"].as_u64().unwrap())
                    .unwrap();
            }
            assert_eq!(complete["elapsed_ns"], sum);
        }
    }

    #[test]
    fn invalid_or_interrupted_windows_never_emit_completion() {
        let worker = Worker::new("core-mixed-1-kib").unwrap();
        for (blocks, iterations, extra) in
            [(0, 1, 0), (17, 1, 0), (1, 0, 0), (1, 101, 0), (1, 1, 2)]
        {
            let mut emitted = false;
            assert!(
                worker
                    .window(blocks, iterations, extra, |_| {
                        emitted = true;
                        Ok(())
                    })
                    .is_err()
            );
            assert!(!emitted);
        }
        let mut records = Vec::new();
        assert!(
            worker
                .window(10, 1, 0, |record| {
                    records.push(record.clone());
                    Err("synthetic output failure".into())
                })
                .is_err()
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["kind"], "window-component");
    }
}
