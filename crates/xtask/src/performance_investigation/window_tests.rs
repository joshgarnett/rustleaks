//! Independent synthetic controls for the observation-window boundary.

use super::{CONTROLLER, classify_windows, validate_window};
use serde_json::{Value, json};

const WINDOW_SCOPE: &str = "investigation-v2-summed-scan-windows";
const SAMPLE_SCOPE: &str = "investigation-v1-steady-scan-only";

fn identity() -> Value {
    json!({
        "workload":"core-dense-16-kib","input_bytes":16384,
        "input_fnv1a64":"3e812ba2e5c2f925","config_fnv1a64":"f8b26dc4f7787416",
        "outcome_fnv1a64":"b80de9ceab6a9984","rules":1,"keywords":0,
        "findings":256,"decoded_bytes":0,"work_units":514,
        "finding_records":256,"complete":true,"errors":0,
    })
}

fn component(index: usize, blocks: u64, extra: u64, elapsed: u64) -> Value {
    json!({
        "schema_version":2,"kind":"window-component","scope":WINDOW_SCOPE,
        "block_index":index,"window_blocks":blocks,"iterations_per_block":100,
        "extra_passes":extra,"identity":identity(),
        "sample":{
            "kind":"sample","scope":SAMPLE_SCOPE,"identity":identity(),
            "iterations":100,"extra_passes":extra,
            "actual_scan_count":if extra == 0 {100} else {200},
            "elapsed_ns":elapsed,"ns_per_logical_iteration":elapsed/100,
            "control":"extra pass is deliberate redundant work, not changed production behavior",
        },
    })
}

fn transcript(blocks: u64, extra: u64) -> Value {
    // Deliberately irregular durations expose averaging, sorting, truncation,
    // and accidentally retaining only the final component.
    let durations: &[u64] = match (blocks, extra) {
        (1, 0) => &[137],
        (1, 1) => &[274],
        (10, 0) => &[101, 203, 307, 409, 503, 601, 701, 809, 907, 1009],
        (10, 1) => &[202, 406, 614, 818, 1006, 1202, 1402, 1618, 1814, 2018],
        _ => panic!("undeclared synthetic transcript"),
    };
    let (iterations, scans, elapsed) = match (blocks, extra) {
        (1, 0) => (100, 100, 137),
        (1, 1) => (100, 200, 274),
        (10, 0) => (1000, 1000, 5550),
        (10, 1) => (1000, 2000, 11100),
        _ => unreachable!(),
    };
    json!({
        "ready":{
            "schema_version":1,"kind":"ready","scope":SAMPLE_SCOPE,
            "identity":identity(),"provenance":{"binding":"bazel-action-graph"},
            "setup":"configuration,engine,fixture and one validated warm scan complete",
        },
        "components":durations.iter().enumerate().map(|(index, elapsed)|
            component(index, blocks, extra, *elapsed)).collect::<Vec<_>>(),
        "complete":{
            "schema_version":2,"kind":"window-complete","scope":WINDOW_SCOPE,
            "window_blocks":blocks,"iterations_per_block":100,"extra_passes":extra,
            "total_iterations":iterations,"actual_scan_count":scans,
            "elapsed_ns":elapsed,"identity":identity(),
        },
        "finished":{"kind":"finished"},"exit_code":0,"stdout_eof":true,
    })
}

#[test]
fn windows_preserve_every_component_and_sum_integer_work() {
    for (blocks, extra, iterations, scans, elapsed) in [
        (1, 0, 100, 100, 137),
        (1, 1, 100, 200, 274),
        (10, 0, 1000, 1000, 5550),
        (10, 1, 1000, 2000, 11100),
    ] {
        let input = transcript(blocks, extra);
        let result = validate_window(&input, blocks, 100, extra, &identity()).unwrap();
        assert_eq!(result["total_iterations"], iterations);
        assert_eq!(result["actual_scan_count"], scans);
        assert_eq!(result["elapsed_ns"], elapsed);
        assert_eq!(result["components"], input["components"]);
    }
}

#[test]
fn missing_duplicated_reordered_and_extra_components_are_rejected() {
    let valid = transcript(10, 0);
    for mutation in 0..5 {
        let mut invalid = valid.clone();
        let components = invalid["components"].as_array_mut().unwrap();
        match mutation {
            0 => {
                components.remove(3);
            }
            1 => components[4] = components[3].clone(),
            2 => components.swap(3, 4),
            3 => components[3]["block_index"] = json!(11),
            4 => components.push(components[9].clone()),
            _ => unreachable!(),
        }
        assert!(validate_window(&invalid, 10, 100, 0, &identity()).is_err());
    }
}

#[test]
fn scope_identity_work_and_termination_are_all_required() {
    let valid = transcript(10, 0);
    for path in [
        "/ready/schema_version",
        "/ready/scope",
        "/ready/provenance/binding",
        "/ready/identity/workload",
        "/components/3/schema_version",
        "/components/3/kind",
        "/components/3/scope",
        "/components/3/identity/outcome_fnv1a64",
        "/components/3/sample/scope",
        "/components/3/sample/identity/input_fnv1a64",
        "/components/3/sample/identity/config_fnv1a64",
        "/components/3/sample/identity/findings",
        "/components/3/sample/identity/decoded_bytes",
        "/components/3/sample/identity/work_units",
        "/components/3/sample/identity/finding_records",
        "/components/3/sample/identity/complete",
        "/components/3/sample/identity/errors",
        "/components/3/sample/iterations",
        "/components/3/sample/extra_passes",
        "/components/3/sample/actual_scan_count",
        "/components/3/sample/ns_per_logical_iteration",
        "/complete/kind",
        "/complete/scope",
        "/complete/identity/input_bytes",
        "/complete/window_blocks",
        "/complete/iterations_per_block",
        "/complete/extra_passes",
        "/complete/total_iterations",
        "/complete/actual_scan_count",
        "/complete/elapsed_ns",
        "/finished/kind",
        "/exit_code",
        "/stdout_eof",
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(path).unwrap() = Value::Null;
        assert!(
            validate_window(&invalid, 10, 100, 0, &identity()).is_err(),
            "accepted damaged {path}"
        );
    }
    let mut contradictory = valid;
    contradictory["finished"]["complete"] = json!(false);
    assert!(validate_window(&contradictory, 10, 100, 0, &identity()).is_err());
}

#[test]
fn malformed_integers_zero_time_and_overflow_are_protocol_failures() {
    let valid = transcript(10, 0);
    for path in [
        "/components/3/block_index",
        "/components/3/window_blocks",
        "/components/3/iterations_per_block",
        "/components/3/extra_passes",
        "/components/3/sample/actual_scan_count",
        "/components/3/sample/elapsed_ns",
        "/complete/total_iterations",
        "/complete/actual_scan_count",
        "/complete/elapsed_ns",
    ] {
        for value in [
            Value::Null,
            json!(true),
            json!("100"),
            json!(-1),
            json!(1.5),
            serde_json::from_str("18446744073709551616").unwrap(),
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert!(
                validate_window(&invalid, 10, 100, 0, &identity()).is_err(),
                "accepted malformed integer at {path}"
            );
        }
    }
    let mut zero = valid.clone();
    zero["components"][0]["sample"]["elapsed_ns"] = json!(0);
    zero["components"][0]["sample"]["ns_per_logical_iteration"] = json!(0);
    zero["complete"]["elapsed_ns"] = json!(5449);
    assert!(validate_window(&zero, 10, 100, 0, &identity()).is_err());

    let mut overflow = valid;
    overflow["components"][0]["sample"]["elapsed_ns"] = json!(u64::MAX);
    overflow["components"][0]["sample"]["ns_per_logical_iteration"] = json!(u64::MAX / 100);
    // MAX + 5,449 would wrap to 5,448. A wrapping implementation must fail
    // this control even though its forged aggregate remains positive.
    overflow["complete"]["elapsed_ns"] = json!(5448);
    assert!(validate_window(&overflow, 10, 100, 0, &identity()).is_err());
}

fn matrix(first_side: &str, a: u64, training_b: u64, heldout_b: u64, control_b: u64) -> Vec<Value> {
    let mut rows = Vec::new();
    for (stage, b) in [
        ("training-aa", training_b),
        ("validation-aa", heldout_b),
        ("control-ab", control_b),
    ] {
        for pair in 0..5 {
            let order = if (pair % 2 == 0) == (first_side == "a") {
                ["a", "b"]
            } else {
                ["b", "a"]
            };
            for side in order {
                let extra = u64::from(stage == "control-ab" && side == "b");
                let elapsed = if side == "a" { a } else { b };
                rows.push(json!({
                    "schema_version":2,"scope":WINDOW_SCOPE,
                    "stage":stage,"pair":pair,"side":side,"order":order,
                    "window_blocks":1,"iterations_per_block":100,"total_iterations":100,
                    "extra_passes":extra,"actual_scan_count":if extra == 0 {100} else {200},
                    "elapsed_ns":elapsed,"identity":identity(),
                    "components":[component(0,1,extra,elapsed)],
                }));
            }
        }
    }
    rows
}

#[test]
fn exact_band_boundaries_heldout_and_control_are_independent() {
    let a = 9_007_199_254_740_992;
    for first in ["a", "b"] {
        let valid = matrix(first, a, a + 1, a + 2, a + 3);
        let result = classify_windows(&valid, 5, first).unwrap();
        assert_eq!(result["status"], "informational-calibration-validated");
        assert_eq!(result["held_out_aa_within_band"], true);
        assert_eq!(result["every_control_pair_exceeds_band"], true);
        assert_eq!(
            result["empirical_band_exact"],
            json!({"numerator":"2","denominator":"9007199254740992"})
        );
        assert_eq!(result.get("timer_precision_bound_ns"), Some(&Value::Null));
        assert_eq!(result["integer_aggregation_rounding_ns"], 0);

        let equality = matrix(first, a, a + 1, a + 2, a + 2);
        let result = classify_windows(&equality, 5, first).unwrap();
        assert_eq!(result["held_out_aa_within_band"], true);
        assert_eq!(result["every_control_pair_exceeds_band"], false);
        assert_eq!(result["status"], "unstable-or-insensitive-no-gate");

        let heldout = matrix(first, a, a + 1, a + 3, a + 3);
        let result = classify_windows(&heldout, 5, first).unwrap();
        assert_eq!(result["held_out_aa_within_band"], false);
        assert_eq!(result["every_control_pair_exceeds_band"], true);
        assert_eq!(result["status"], "unstable-or-insensitive-no-gate");
    }
}

#[test]
fn one_failed_pair_is_not_hidden_and_zero_training_never_qualifies() {
    let valid = matrix("a", 1000, 1001, 1002, 2000);
    for (stage, elapsed, field) in [
        ("validation-aa", 1003, "held_out_aa_within_band"),
        ("control-ab", 1002, "every_control_pair_exceeds_band"),
    ] {
        let mut invalid = valid.clone();
        let row = invalid
            .iter_mut()
            .find(|row| row["stage"] == stage && row["pair"] == 4 && row["side"] == "b")
            .unwrap();
        row["elapsed_ns"] = json!(elapsed);
        row["components"][0]["sample"]["elapsed_ns"] = json!(elapsed);
        row["components"][0]["sample"]["ns_per_logical_iteration"] = json!(elapsed / 100);
        let result = classify_windows(&invalid, 5, "a").unwrap();
        assert_eq!(result[field], false);
        assert_eq!(result["status"], "unstable-or-insensitive-no-gate");
        assert_eq!(invalid.len(), 30);
    }
    let zero = matrix("a", 1000, 1000, 1000, 2000);
    let result = classify_windows(&zero, 5, "a").unwrap();
    assert_eq!(result["status"], "degenerate-training-no-gate");
    assert_eq!(result["held_out_aa_within_band"], true);
    assert_eq!(result["every_control_pair_exceeds_band"], true);
}

#[test]
fn complete_matrix_order_identity_and_extra_work_are_mandatory() {
    let valid = matrix("a", 1000, 1001, 1002, 2000);
    assert!(classify_windows(&valid, 5, "b").is_err());
    for mutation in 0..8 {
        let mut invalid = valid.clone();
        match mutation {
            0 => {
                invalid.pop();
            }
            1 => invalid[3] = invalid[2].clone(),
            2 => invalid.swap(0, 1),
            3 => invalid[0]["stage"] = json!("unknown"),
            4 => invalid[0]["order"] = json!(["b", "a"]),
            5 => invalid[0]["identity"]["work_units"] = json!(515),
            6 => {
                invalid[29]["actual_scan_count"] = json!(100);
                invalid[29]["components"][0]["sample"]["actual_scan_count"] = json!(100);
            }
            7 => {
                invalid[29]["extra_passes"] = json!(0);
                invalid[29]["actual_scan_count"] = json!(100);
                invalid[29]["components"][0]["extra_passes"] = json!(0);
                invalid[29]["components"][0]["sample"]["extra_passes"] = json!(0);
                invalid[29]["components"][0]["sample"]["actual_scan_count"] = json!(100);
            }
            _ => unreachable!(),
        }
        assert!(
            classify_windows(&invalid, 5, "a").is_err(),
            "accepted matrix damage {mutation}"
        );
    }
}

#[test]
fn exact_classifier_rejects_cross_product_overflow() {
    let mut rows = matrix("a", 1, u64::MAX, 1, u64::MAX);
    for row in &mut rows {
        if row["stage"] == "validation-aa" && row["pair"] == 0 {
            row["elapsed_ns"] = json!(u64::MAX);
            row["components"][0]["sample"]["elapsed_ns"] = json!(u64::MAX);
            row["components"][0]["sample"]["ns_per_logical_iteration"] = json!(u64::MAX / 100);
        }
    }
    assert!(classify_windows(&rows, 5, "a").is_err());
}

#[test]
#[cfg(unix)]
fn prepared_binding_rejects_source_and_executable_mutation() {
    use std::fs;
    use std::process::Command;

    use super::super::{Prepared, fnv1a64, sha256_file, source_snapshot};

    let temporary = crate::ScopedTempDir::new("window-binding-controls").unwrap();
    let root = temporary.path.join("source");
    fs::create_dir(&root).unwrap();
    for arguments in [
        vec!["init", "--quiet"],
        vec![
            "-c",
            "user.name=synthetic control",
            "-c",
            "user.email=control@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "synthetic fixture",
        ],
    ] {
        let result = Command::new("git")
            .current_dir(&root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(result.status.success(), "synthetic Git fixture failed");
    }
    let input = root.join("input.rs");
    fs::write(&input, b"let a = 1;").unwrap();
    let binary = temporary.path.join("synthetic-binary");
    let executable_bytes = b"synthetic binary A";
    fs::write(&binary, executable_bytes).unwrap();
    let prepared = Prepared {
        root: root.clone(),
        binary: binary.clone(),
        source: source_snapshot(&root).unwrap(),
        build: json!({"executable_sha256":sha256_file(&binary).unwrap(),
            "compiler_version":"synthetic compiler","rust_action_graph_sha256":"synthetic graph"}),
        host: json!({"os":"synthetic","arch":"synthetic"}),
        executable_bytes: u64::try_from(executable_bytes.len()).unwrap(),
        executable_fnv1a64: format!("{:016x}", fnv1a64(executable_bytes)),
    };
    assert!(prepared.ensure_unchanged().is_ok());
    let mut ready = transcript(1, 0)["ready"].clone();
    ready["provenance"] = json!({"binding":"unbound-runner",
        "executable_bytes":prepared.executable_bytes,
        "executable_fnv1a64":prepared.executable_fnv1a64});
    let bound: Value = serde_json::from_str(&prepared.bind(&ready.to_string()).unwrap()).unwrap();
    assert_eq!(bound["provenance"]["build"], prepared.build);
    assert_eq!(bound["provenance"]["source"], prepared.source);
    for field in ["binding", "executable_bytes", "executable_fnv1a64"] {
        let mut wrong = ready.clone();
        wrong["provenance"][field] = Value::Null;
        assert!(prepared.bind(&wrong.to_string()).is_err(), "{field}");
    }

    fs::write(&input, b"let a = 2;").unwrap();
    assert!(prepared.ensure_unchanged().is_err());
    fs::write(&input, b"let a = 1;").unwrap();
    assert!(prepared.ensure_unchanged().is_ok());
    fs::write(&binary, b"synthetic binary B").unwrap();
    assert!(prepared.ensure_unchanged().is_err());
}

#[test]
#[cfg(unix)]
#[allow(clippy::too_many_lines)] // Each independent fake worker crosses the actual supervisor boundary.
fn collector_rejects_incomplete_failed_unbounded_or_trailing_output() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let temporary = crate::ScopedTempDir::new("window-process-controls").unwrap();
    let mut fixture = transcript(1, 0);
    fixture["ready"]["provenance"]["binding"] = json!("unbound-runner");
    for case in [
        "complete",
        "stdout-at-bound",
        "stderr-at-bound",
        "partial-window",
        "missing-finished",
        "contradictory-finished",
        "failed-exit",
        "duplicate-finished",
        "trailing-bytes",
        "hang-after-finished",
        "stdout-over-bound",
        "stderr-over-bound",
        "stderr-over-bound-parent",
        "descendant-holds-output",
    ] {
        let work = temporary.path.join(case);
        let output = work.join("output");
        fs::create_dir_all(&output).unwrap();
        let worker = work.join("worker.py");
        fs::write(&worker, FAKE_WORKER).unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(work.join("fixture.json"), fixture.to_string()).unwrap();
        fs::write(work.join("case.txt"), case).unwrap();
        // Protocol fixtures are not host-speed tests. Keep intentional stalls
        // short while allowing cold process startup on shared native runners.
        let intentional_stall = matches!(case, "hang-after-finished" | "descendant-holds-output");
        let collector_seconds = if intentional_stall { "5" } else { "30" };
        let parent_seconds = if intentional_stall { 10 } else { 45 };
        let mut command = Command::new("python3");
        command
            .args(["-c", CONTROLLER, "sample-window"])
            .arg(&worker)
            .arg("core-dense-16-kib")
            .arg(&output)
            .args([collector_seconds, "100", "0", "1"]);
        let result = super::collect_supervised(
            &mut command,
            &output,
            Instant::now() + Duration::from_secs(parent_seconds),
        );
        let success = matches!(case, "complete" | "stdout-at-bound" | "stderr-at-bound");
        let parent: Value = serde_json::from_slice(
            &fs::read(output.join("parent-completion.json")).unwrap_or_else(|error| {
                panic!("{case}: missing parent completion: {error}; {result:?}")
            }),
        )
        .unwrap_or_else(|error| panic!("{case}: invalid parent completion: {error}; {result:?}"));
        // These receipts contain only synthetic fixture status. Keep them in a
        // failed assertion so hosted failures retain the actual failure class.
        let collector_receipt = fs::read_to_string(output.join("collector-completion.json"));
        assert_eq!(
            result.is_ok(),
            success,
            "{case}: {result:?}; parent={parent}; collector={collector_receipt:?}"
        );
        assert_eq!(parent["cleanup_complete"], true, "{case}: {parent}");
        assert_eq!(parent["deadline_met"], true, "{case}: {parent}");
        assert_eq!(parent["outcome"] == "success", success, "{case}: {parent}");
        let parent_enforced_limit =
            parent["outcome"] == "corpus-limit" && parent["monitor_failure"] == "evidence-limit";
        if parent_enforced_limit {
            // The parent can kill the collector before its finally block writes
            // a receipt. Only this independently observed violation permits it.
            assert!(
                matches!(case, "stderr-over-bound" | "stderr-over-bound-parent"),
                "{case}: unexpected parent enforcement: {parent}"
            );
            assert_eq!(
                fs::metadata(output.join("worker-stderr.txt"))
                    .unwrap()
                    .len(),
                65_537,
                "{case}: parent rejected a different evidence bound: {parent}"
            );
        } else {
            let completion: Value = serde_json::from_slice(
                &fs::read(output.join("collector-completion.json")).unwrap_or_else(|error| {
                    panic!("{case}: missing collector completion: {error}; {parent}; {result:?}")
                }),
            )
            .unwrap_or_else(|error| {
                panic!("{case}: invalid collector completion: {error}; {parent}; {result:?}")
            });
            assert_eq!(
                completion["status"],
                if success { "complete" } else { "failed" },
                "{case}: {completion}"
            );
            assert_eq!(completion["cleanup_complete"], true, "{case}: {completion}");
        }
        if case == "stderr-over-bound-parent" {
            assert!(parent_enforced_limit, "{case}: {parent}");
            assert!(
                !output.join("collector-completion.json").exists(),
                "stopped collector unexpectedly wrote its completion receipt"
            );
        }
        let pid = fs::read_to_string(work.join("worker-pid.txt")).unwrap();
        let worker_exists = || {
            Command::new("/bin/kill")
                .args(["-0", pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        };
        if worker_exists() {
            // A group kill can leave an orphan zombie for the host to reap.
            // A live or stopped worker must still fail, including after SIGSTOP.
            let state = Command::new("ps")
                .args(["-o", "stat=", "-p", pid.trim()])
                .output()
                .unwrap();
            let zombie = state.status.success()
                && String::from_utf8_lossy(&state.stdout)
                    .trim_start()
                    .starts_with('Z');
            assert!(
                (parent_enforced_limit && zombie) || !worker_exists(),
                "{case}: worker survived collector return: {state:?}"
            );
        }
        let raw = fs::read_to_string(output.join("worker-stdout.jsonl")).unwrap();
        assert!(raw.contains("\"kind\":\"ready\""), "{case}");
        if !matches!(
            case,
            "stdout-over-bound" | "stderr-over-bound" | "stderr-over-bound-parent"
        ) {
            assert!(raw.contains("\"kind\":\"window-component\""), "{case}");
        }
        if matches!(case, "descendant-holds-output" | "stderr-over-bound-parent") {
            let heartbeat = work.join("heartbeat.txt");
            let after = fs::read(&heartbeat).unwrap();
            std::thread::sleep(Duration::from_millis(150));
            assert_eq!(
                fs::read(heartbeat).unwrap(),
                after,
                "{case}: process heartbeat continued after cleanup"
            );
        }
        if let Ok(raw_result) = result {
            let actual: Value = serde_json::from_str(&raw_result).unwrap();
            assert_eq!(actual["finished"], json!({"kind":"finished"}));
            assert_eq!(actual["exit_code"], 0);
            assert_eq!(actual["stdout_eof"], true);
            assert_eq!(actual["components"], fixture["components"]);
        }
    }
}

#[test]
#[cfg(unix)]
fn supervisor_enforces_absolute_deadline_and_its_own_capture_limit() {
    use std::fs;
    use std::process::Command;
    use std::time::{Duration, Instant};

    let temporary = crate::ScopedTempDir::new("window-supervisor-controls").unwrap();
    let expired = temporary.path.join("expired");
    fs::create_dir(&expired).unwrap();
    let sentinel = temporary.path.join("must-not-start.txt");
    let mut command = Command::new("python3");
    command
        .args([
            "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('started')",
        ])
        .arg(&sentinel);
    assert!(super::collect_supervised(&mut command, &expired, Instant::now()).is_err());
    assert!(
        !sentinel.exists(),
        "expired absolute deadline admitted work"
    );
    let completion: Value =
        serde_json::from_slice(&fs::read(expired.join("parent-completion.json")).unwrap()).unwrap();
    assert_eq!(completion["outcome"], "deadline-before-spawn");
    assert_eq!(completion["deadline_met"], false);

    let oversized = temporary.path.join("oversized");
    fs::create_dir(&oversized).unwrap();
    let mut command = Command::new("python3");
    command.args([
        "-c",
        "import sys; sys.stdout.buffer.write(b'x' * (4 * 1024 * 1024 + 1))",
    ]);
    assert!(
        super::collect_supervised(
            &mut command,
            &oversized,
            Instant::now() + Duration::from_secs(10),
        )
        .is_err()
    );
    let completion: Value =
        serde_json::from_slice(&fs::read(oversized.join("parent-completion.json")).unwrap())
            .unwrap();
    assert_eq!(completion["outcome"], "output-limit");
    assert_eq!(completion["cleanup_complete"], true);
    assert!(
        fs::metadata(oversized.join("parent-stdout.json"))
            .unwrap()
            .len()
            <= 4 * 1024 * 1024
    );
}

#[cfg(unix)]
const FAKE_WORKER: &str = r#"#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path(__file__).parent
fixture = json.loads((root / 'fixture.json').read_text())
case = (root / 'case.txt').read_text()
(root / 'worker-pid.txt').write_text(str(os.getpid()))
def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)
ready = fixture['ready']
if case == 'stdout-at-bound':
    ready['padding'] = ''
    ready['padding'] = 'x' * (65536 - len(json.dumps(ready, separators=(',', ':')).encode()) - 1)
emit(ready)
assert sys.stdin.readline() == 'window 1 100 0\n'
if case == 'stderr-over-bound-parent':
    (root / 'heartbeat.txt').write_text('0')
    os.kill(os.getppid(), signal.SIGSTOP)
    sys.stderr.write('x' * 65537)
    sys.stderr.flush()
    for n in range(1, 3000):
        (root / 'heartbeat.txt').write_text(str(n))
        time.sleep(.02)
if case == 'stdout-over-bound':
    sys.stdout.write('x' * 65537)
    sys.stdout.flush()
    time.sleep(30)
if case in ('stderr-at-bound', 'stderr-over-bound'):
    sys.stderr.write('x' * (65536 + (case == 'stderr-over-bound')))
    sys.stderr.flush()
for component in fixture['components']:
    emit(component)
if case == 'partial-window':
    raise SystemExit(0)
emit(fixture['complete'])
assert sys.stdin.readline() == 'quit\n'
if case == 'missing-finished':
    raise SystemExit(0)
if case == 'descendant-holds-output':
    code = "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nfor n in range(3000):\n p.write_text(str(n)); time.sleep(.02)\n"
    subprocess.Popen([sys.executable, '-c', code, str(root / 'heartbeat.txt')])
    ready_by = time.monotonic() + 3
    while not (root / 'heartbeat.txt').exists():
        assert time.monotonic() < ready_by, 'descendant did not become ready'
        time.sleep(.01)
if case == 'contradictory-finished':
    emit({'kind': 'finished', 'complete': False})
else:
    emit(fixture['finished'])
if case == 'failed-exit':
    raise SystemExit(7)
if case == 'duplicate-finished':
    emit(fixture['finished'])
if case == 'trailing-bytes':
    sys.stdout.write('trailing')
    sys.stdout.flush()
if case == 'hang-after-finished':
    time.sleep(30)
"#;
