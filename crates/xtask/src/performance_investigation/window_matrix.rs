//! One prepared build and a fixed, bounded baseline observation matrix.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{Prepared, Request, directory, evidence, run_prepared_window, write};

const MATRIX_SECONDS: u64 = 3_600;
const CELL_SECONDS: u64 = 900;
const IDLE_SECONDS: u64 = 5;
const WORKLOADS: [&str; 4] = [
    "core-dense-16-kib",
    "core-mixed-16-kib",
    "core-default-no-hit-16-kib",
    "core-decode-depth-5",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cell {
    run: u64,
    workload: &'static str,
    blocks: u64,
    first_side: &'static str,
}

fn schedule() -> Vec<Cell> {
    let mut cells = Vec::with_capacity(16);
    for run in 1..=2 {
        for index in 0..WORKLOADS.len() {
            let workload = WORKLOADS[if run == 1 { index } else { 3 - index }];
            for blocks in if run == 1 { [1, 10] } else { [10, 1] } {
                cells.push(Cell {
                    run,
                    workload,
                    blocks,
                    first_side: if run == 1 { "a" } else { "b" },
                });
            }
        }
    }
    cells
}

trait Clock {
    fn now(&self) -> Instant;
    fn idle(&self);
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn idle(&self) {
        std::thread::sleep(Duration::from_secs(IDLE_SECONDS));
    }
}

fn before_deadline(now: Instant, deadline: Instant) -> Result<(), String> {
    if now >= deadline {
        Err("observation matrix absolute deadline exceeded".into())
    } else {
        Ok(())
    }
}

fn bounded_deadline(now: Instant, parent: Instant) -> Result<Instant, String> {
    before_deadline(now, parent)?;
    Ok(now
        .checked_add(Duration::from_secs(CELL_SECONDS))
        .ok_or("observation cell deadline overflow")?
        .min(parent))
}

fn manifest(cells: &[Cell]) -> Value {
    let rows = cells
        .iter()
        .enumerate()
        .map(|(index, cell)| {
            json!({"index":index,"run":cell.run,"workload":cell.workload,
                "window_blocks":cell.blocks,"first_side":cell.first_side,
                "status":"uncollected","directory":format!("cell-{index:02}"),
                "pairs_per_stage":9,"iterations_per_block":100})
        })
        .collect::<Vec<_>>();
    json!({"schema_version":2,"kind":"observation-window-matrix",
        "protocol":"observation-window-v2","status":"collecting","complete":false,
        "matrix_deadline_seconds":MATRIX_SECONDS,"cell_deadline_seconds":CELL_SECONDS,
        "worker_deadline_seconds":120,"idle_before_each_cell_seconds":IDLE_SECONDS,
        "schedule":rows,"completed_cells":0,"stop":null,
        "work_ceilings":{"workers":864,"component_responses":4752,"timed_scans":554_400,
            "warm_scans":864,"commands":1728,"responses":7344},
        "k1_role":"descriptive-reference-only","later_trial_window_blocks":10,
        "later_trial_eligible":false,"candidate_timing_authorized":false,
        "release_threshold_created":false})
}

fn stop(report: &mut Value, index: usize, detail: &str, partial: bool) {
    if partial {
        report["schedule"][index]["status"] = json!("failed-or-partial");
    }
    report["schedule"][index]["detail"] = json!(detail);
    report["stop"] = json!({"cell_index":index,"detail":detail});
    report["status"] = json!("stopped-incomplete-no-gate");
    report["complete"] = json!(false);
    report["later_trial_eligible"] = json!(false);
}

#[allow(clippy::too_many_lines)] // Keep deadline and status transitions in one ordered loop.
fn execute<C, F, P>(
    clock: &C,
    started: Instant,
    cells: &[Cell],
    mut collect: F,
    mut persist: P,
) -> Result<Value, String>
where
    C: Clock,
    F: FnMut(usize, &Cell, Instant) -> Result<Value, String>,
    P: FnMut(&Value) -> Result<(), String>,
{
    let deadline = started
        .checked_add(Duration::from_secs(MATRIX_SECONDS))
        .ok_or("observation matrix deadline overflow")?;
    let mut report = manifest(cells);
    persist(&report)?;
    for (index, cell) in cells.iter().enumerate() {
        let cell_deadline = match bounded_deadline(clock.now(), deadline) {
            Ok(value) => value,
            Err(error) => {
                stop(&mut report, index, &error, false);
                break;
            }
        };
        let idle_end = clock.now().checked_add(Duration::from_secs(IDLE_SECONDS));
        if idle_end.is_none_or(|end| end >= cell_deadline) {
            stop(
                &mut report,
                index,
                "insufficient cell time for fixed idle",
                false,
            );
            break;
        }
        clock.idle();
        if let Err(error) = before_deadline(clock.now(), cell_deadline) {
            stop(&mut report, index, &error, false);
            break;
        }
        report["schedule"][index]["status"] = json!("collecting");
        persist(&report)?;
        let result = before_deadline(clock.now(), cell_deadline)
            .and_then(|()| collect(index, cell, cell_deadline));
        match result {
            Ok(calibration) if clock.now() < cell_deadline => {
                report["schedule"][index]["status"] = json!("complete");
                report["schedule"][index]["calibration"] = calibration;
                report["completed_cells"] = json!(index + 1);
            }
            Ok(_) => {
                stop(
                    &mut report,
                    index,
                    "cell returned after its absolute deadline",
                    true,
                );
                break;
            }
            Err(error) => {
                stop(&mut report, index, &error, true);
                break;
            }
        }
        persist(&report)?;
        if clock.now() >= cell_deadline {
            report["completed_cells"] = json!(index);
            stop(
                &mut report,
                index,
                "cell postcheck exceeded its absolute deadline",
                true,
            );
            break;
        }
    }
    if report["stop"].is_null() && clock.now() >= deadline {
        let index = cells
            .len()
            .checked_sub(1)
            .ok_or("empty observation matrix")?;
        report["completed_cells"] = json!(index);
        stop(
            &mut report,
            index,
            "matrix final postcheck exceeded its absolute deadline",
            true,
        );
    }
    if report["stop"].is_null() {
        report["complete"] = json!(true);
        let eligible = report["schedule"]
            .as_array()
            .ok_or("matrix omitted schedule")?
            .iter()
            .filter(|cell| cell["window_blocks"] == 10)
            .all(|cell| {
                cell["status"] == "complete"
                    && cell["calibration"]["status"] == "informational-calibration-validated"
            });
        report["later_trial_eligible"] = json!(eligible);
        report["status"] = json!(if eligible {
            "baseline-qualified-for-later-protocol-review"
        } else {
            "baseline-unqualified-no-gate"
        });
    }
    persist(&report)?;
    if report["complete"] == true && clock.now() >= deadline {
        let index = cells
            .len()
            .checked_sub(1)
            .ok_or("empty observation matrix")?;
        report["completed_cells"] = json!(index);
        stop(
            &mut report,
            index,
            "matrix final persistence exceeded its absolute deadline",
            true,
        );
        persist(&report)?;
    }
    Ok(report)
}

fn validate_cell(report: &Value, cell: &Cell, prepared: &Prepared) -> Result<Value, String> {
    if report["source"] != prepared.source
        || report["build"] != prepared.build
        || report["host"] != prepared.host
        || report["workload"] != cell.workload
        || report["window_blocks"].as_u64() != Some(cell.blocks)
        || report["iterations_per_block"].as_u64() != Some(100)
        || report["pairs_per_stage"].as_u64() != Some(9)
        || report["first_side"] != cell.first_side
        || report["measurement_scope"] != super::WINDOW_SCOPE
        || report["policy"]["id"] != super::WINDOW_POLICY
    {
        return Err("prepared matrix cell provenance or request changed".into());
    }
    let rows = report["rows"]
        .as_array()
        .ok_or("matrix cell omitted rows")?;
    let first = rows.first().ok_or("matrix cell has no rows")?;
    if first["window_blocks"].as_u64() != Some(cell.blocks)
        || first["iterations_per_block"].as_u64() != Some(100)
        || first["identity"] != report["identity"]
        || first["identity"]["workload"] != cell.workload
    {
        return Err("matrix cell rows differ from the scheduled workload or window".into());
    }
    let classification = super::classify_windows(rows, 9, cell.first_side)?;
    if classification != report["calibration"] {
        return Err("matrix cell classification differs from its rows".into());
    }
    Ok(classification)
}

pub(super) fn run(prepared: &Prepared, output: &Path) -> Result<Value, String> {
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(MATRIX_SECONDS))
        .ok_or("observation matrix deadline overflow")?;
    let cells = schedule();
    let mut checkpoint = 0_u64;
    let mut identities = BTreeMap::new();
    let mut report = execute(
        &SystemClock,
        started,
        &cells,
        |index, cell, deadline| {
            let destination = output.join(format!("cell-{index:02}"));
            directory(&destination)?;
            let request = Request {
                output: destination.clone(),
                workload: cell.workload.into(),
                seconds: 15,
                pairs: 9,
                iterations: 100,
                window_blocks: Some(cell.blocks),
                first_side: cell.first_side.into(),
            };
            let result = run_prepared_window(prepared, &request, deadline);
            match result {
                Ok(cell_report) => {
                    write(&destination.join("report.json"), &cell_report)?;
                    let calibration = validate_cell(&cell_report, cell, prepared)?;
                    let identity = &cell_report["identity"];
                    if identities
                        .get(cell.workload)
                        .is_some_and(|expected| expected != identity)
                    {
                        return Err(
                            "workload identity changed between observation matrix cells".into()
                        );
                    }
                    identities.insert(cell.workload, identity.clone());
                    Ok(calibration)
                }
                Err(error) => {
                    write(
                        &destination.join("matrix-cell-failure.json"),
                        &json!({"detail":error}),
                    )?;
                    Err(error)
                }
            }
        },
        |progress| {
            let destination = output.join(format!("matrix-progress-{checkpoint:02}.json"));
            checkpoint += 1;
            write(&destination, progress)
        },
    )?;
    let final_check = prepared
        .ensure_unchanged()
        .and_then(|()| before_deadline(Instant::now(), deadline));
    if let Err(error) = final_check {
        report["complete"] = json!(false);
        report["later_trial_eligible"] = json!(false);
        report["status"] = json!("stopped-incomplete-no-gate");
        report["final_postcheck_failure"] = json!(error);
    }
    report["source_baseline_eligible"] = json!(prepared.source["dirty"] == false);
    if prepared.source["dirty"] != false {
        report["later_trial_eligible"] = json!(false);
        if report["complete"] == true {
            report["status"] = json!("baseline-unqualified-no-gate");
        }
    }
    report["provenance"] = evidence(prepared, "observation-window-matrix");
    report["provenance"]["wall_deadline_seconds"] = json!(MATRIX_SECONDS);
    report["completed_seconds"] = json!(started.elapsed().as_secs_f64());
    write(&output.join("matrix.json"), &report)?;
    if report["complete"] == true && Instant::now() >= deadline {
        report["complete"] = json!(false);
        report["later_trial_eligible"] = json!(false);
        report["status"] = json!("stopped-incomplete-no-gate");
        report["final_postcheck_failure"] =
            json!("matrix persistence exceeded its absolute deadline");
        let failure = output.join("matrix-final-postcheck-failure.json");
        write(&failure, &report)?;
        // Replace only this invocation's provisional snapshot; retain every raw row.
        std::fs::rename(&failure, output.join("matrix.json")).map_err(|error| error.to_string())?;
    }
    if report["complete"] != true {
        return Err(
            "observation matrix stopped; partial evidence and uncollected schedule retained".into(),
        );
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell as ClockCell;

    struct FakeClock(ClockCell<Instant>);

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.0.get()
        }

        fn idle(&self) {
            self.advance(IDLE_SECONDS);
        }
    }

    impl FakeClock {
        fn advance(&self, seconds: u64) {
            self.0.set(self.now() + Duration::from_secs(seconds));
        }
    }

    fn passed() -> Value {
        json!({"status":"informational-calibration-validated"})
    }

    #[test]
    fn fixed_schedule_conserves_counts_and_reverses_both_orders() {
        let cells = schedule();
        assert_eq!(cells.len(), 16);
        assert_eq!(cells[0].workload, WORKLOADS[0]);
        assert_eq!(cells[0].blocks, 1);
        assert_eq!(cells[8].workload, WORKLOADS[3]);
        assert_eq!(cells[8].blocks, 10);
        let mut counts = [0_u64; 6];
        for cell in &cells {
            for stage in 0..3 {
                for pair in 0..9 {
                    let order = if (pair % 2 == 0) == (cell.first_side == "a") {
                        ["a", "b"]
                    } else {
                        ["b", "a"]
                    };
                    for side in order {
                        let extra = u64::from(stage == 2 && side == "b");
                        counts[0] += 1;
                        counts[1] += cell.blocks;
                        counts[2] += 100 * cell.blocks * (extra + 1);
                        counts[3] += 1;
                        counts[4] += 2;
                        counts[5] += cell.blocks + 3;
                    }
                }
            }
        }
        assert_eq!(counts, [864, 4_752, 554_400, 864, 1_728, 7_344]);
        for workload in WORKLOADS {
            for blocks in [1, 10] {
                let matching = cells
                    .iter()
                    .filter(|cell| cell.workload == workload && cell.blocks == blocks)
                    .collect::<Vec<_>>();
                assert_eq!(matching.len(), 2);
                assert_eq!([matching[0].first_side, matching[1].first_side], ["a", "b"]);
            }
        }
    }

    #[test]
    fn statistical_failure_continues_and_only_k10_controls_eligibility() {
        for failing_blocks in [1, 10] {
            let start = Instant::now();
            let clock = FakeClock(ClockCell::new(start));
            let mut calls = 0;
            let report = execute(
                &clock,
                start,
                &schedule(),
                |_, cell, _| {
                    calls += 1;
                    Ok(if cell.blocks == failing_blocks {
                        json!({"status":"unstable-or-insensitive-no-gate"})
                    } else {
                        passed()
                    })
                },
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(calls, 16);
            assert_eq!(report["complete"], true);
            assert_eq!(report["later_trial_eligible"], failing_blocks == 1);
        }
    }

    #[test]
    fn protocol_failure_keeps_complete_partial_and_uncollected_cells() {
        let start = Instant::now();
        let clock = FakeClock(ClockCell::new(start));
        let mut calls = 0;
        let report = execute(
            &clock,
            start,
            &schedule(),
            |index, _, _| {
                calls += 1;
                if index == 1 {
                    Err("synthetic process failure".into())
                } else {
                    Ok(passed())
                }
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(report["schedule"][0]["status"], "complete");
        assert_eq!(report["schedule"][1]["status"], "failed-or-partial");
        assert_eq!(report["schedule"][2]["status"], "uncollected");
        assert_eq!(report["complete"], false);
        assert_eq!(report["later_trial_eligible"], false);
    }

    #[test]
    fn absolute_cell_and_parent_deadlines_reject_late_success_without_retry() {
        let start = Instant::now();
        let clock = FakeClock(ClockCell::new(start));
        let mut calls = 0;
        let report = execute(
            &clock,
            start,
            &schedule(),
            |_, _, deadline| {
                calls += 1;
                assert_eq!(deadline, start + Duration::from_mins(15));
                clock.advance(CELL_SECONDS - IDLE_SECONDS);
                Ok(passed())
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(report["schedule"][0]["status"], "failed-or-partial");
        assert_eq!(report["schedule"][1]["status"], "uncollected");
        let near_end = start + Duration::from_secs(3_500);
        assert_eq!(
            bounded_deadline(near_end, start + Duration::from_hours(1)).unwrap(),
            start + Duration::from_hours(1)
        );
        assert!(bounded_deadline(start, start).is_err());
    }

    #[test]
    fn exhausted_root_budget_starts_no_worker_or_idle() {
        let start = Instant::now();
        let clock = FakeClock(ClockCell::new(start + Duration::from_secs(3_596)));
        let report = execute(
            &clock,
            start,
            &schedule(),
            |_, _, _| panic!("must not collect"),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(clock.now(), start + Duration::from_secs(3_596));
        assert_eq!(report["schedule"][0]["status"], "uncollected");
        assert_eq!(report["completed_cells"], 0);
    }

    #[test]
    fn late_checkpoint_invalidates_the_cell_and_preserves_uncollected_remainder() {
        let start = Instant::now();
        let clock = FakeClock(ClockCell::new(start));
        let mut calls = 0;
        let report = execute(
            &clock,
            start,
            &schedule(),
            |_, _, _| {
                calls += 1;
                Ok(passed())
            },
            |progress| {
                if progress["completed_cells"] == 1 && progress["stop"].is_null() {
                    clock.advance(CELL_SECONDS);
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(report["schedule"][0]["status"], "failed-or-partial");
        assert_eq!(report["schedule"][1]["status"], "uncollected");
        assert_eq!(report["completed_cells"], 0);
        assert_eq!(report["later_trial_eligible"], false);
    }

    #[test]
    fn late_final_persistence_cannot_return_a_qualified_complete_matrix() {
        let start = Instant::now();
        let clock = FakeClock(ClockCell::new(start));
        let mut last_checkpoint = Value::Null;
        let report = execute(
            &clock,
            start,
            &schedule(),
            |_, _, _| Ok(passed()),
            |progress| {
                if progress["complete"] == true {
                    clock.0.set(start + Duration::from_secs(MATRIX_SECONDS));
                }
                last_checkpoint = progress.clone();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(report["complete"], false);
        assert_eq!(report["later_trial_eligible"], false);
        assert_eq!(last_checkpoint, report);
        assert_eq!(report["schedule"][15]["status"], "failed-or-partial");
    }
}
