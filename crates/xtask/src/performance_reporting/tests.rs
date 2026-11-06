use super::*;

fn fixture() -> Value {
    let source = json!({"revision":"a".repeat(40),"dirty":false,"input_sha256":"b".repeat(64)});
    let build = json!({"schema_version":1,"system":"bazel","timing_scope":MEASUREMENT_SCOPE,
        "default_config_sha256":crate::CONFIG_SHA256,"executable_sha256":"c".repeat(64),
        "compiler_sha256":"d".repeat(64),"workload_definition_sha256":"e".repeat(64),
        "target":"aarch64-apple-darwin","compile_action_key":"private action key"});
    let host = json!({"os":"macos","arch":"aarch64","cpu":"Apple M1 Max"});
    let rows = super::super::PERF_INVARIANTS.iter().map(|invariant| {
        json!({"schema_version":2,"iterations":1,"warmup_iterations":0,
            "measurement_scope":MEASUREMENT_SCOPE,"workload":invariant.workload,
            "logical_bytes":invariant.logical_bytes,"result_count":invariant.result_count,
            "output_bytes":invariant.output_bytes,"outcome_fnv1a64":invariant.outcome_fnv1a64,
            "logical_unit":if invariant.workload.starts_with("report-") {"findings"} else {"input-bytes"},
            "elapsed_ns":100,"ns_per_iteration":100,"invariant":"synthetic outcome verified",
            "provenance":{"upstream_revision":crate::REVISION,"default_config_sha256":crate::CONFIG_SHA256,
                "package_version":crate::RELEASE_VERSION,"binding":"bazel-action-graph",
                "executable_bytes":1024,"executable_fnv1a64":"0123456789abcdef",
                "source":source,"build":build,"host":host,"baseline_eligible":true,
                "target_os":"macos","target_arch":"aarch64"}})
    }).collect::<Vec<_>>();
    json!({"schema_version":1,"kind":KIND,"complete":true,"source":source,"build":build,
        "host":host,"executable_bytes":1024,"executable_fnv1a64":"0123456789abcdef",
        "measurement_scope":MEASUREMENT_SCOPE,"budget_requested":false,"calibrated_host":false,
        "host_qualification":null,"rows":rows,"budget_samples":[],"outcome":"complete"})
}

fn with_budgets() -> Value {
    let mut value = fixture();
    value["budget_requested"] = json!(true);
    value["calibrated_host"] = json!(true);
    value["host_qualification"] = json!({"machine_model":"MacBookPro18,2","chip_type":"Apple M1 Max","physical_memory":"32 GB","number_processors":"proc 10:8:2:0"});
    value["budget_samples"] = json!(M1_MAX_PERF_BUDGETS.iter().map(|budget| {
        let row = value["rows"].as_array().unwrap().iter().find(|row| row["workload"]==budget.workload).unwrap();
        json!({"workload":budget.workload,"warmup":row,"samples":(0..7).map(|index| json!({"index":index,"row":row,"peak_rss_bytes":if index<3 {Some(1024)} else {None}})).collect::<Vec<_>>()})
    }).collect::<Vec<_>>());
    value
}

fn summary(value: &Value) -> Result<Value, String> {
    import::summarize(value, None, "report-consistency-only")
}

#[test]
fn complete_invariants_are_informational_and_unknown_hosts_skip_requested_budgets() {
    let mut value = fixture();
    let result = summary(&value).unwrap();
    assert_eq!(result["status"], "informational-timing");
    assert_eq!(result["verification"], "report-consistency-only");
    assert_eq!(result["release_gate"], false);
    validate_public_summary(&result).unwrap();
    value["budget_requested"] = json!(true);
    assert_eq!(
        summary(&value).unwrap()["status"],
        "skipped-legacy-host-budget"
    );
    value["outcome"] = json!("invariant-failure");
    assert_eq!(summary(&value).unwrap()["status"], "invariant-failure");
}

#[test]
fn inherited_budget_decisions_preserve_median_and_rss_controls() {
    let mut value = with_budgets();
    assert_eq!(summary(&value).unwrap()["status"], "legacy-budget-passed");
    // A single slow sample cannot change a seven-process median.
    for index in 0..3 {
        value["budget_samples"][0]["samples"][index]["row"]["elapsed_ns"] = json!(1_000_000_000);
        value["budget_samples"][0]["samples"][index]["row"]["ns_per_iteration"] =
            json!(1_000_000_000);
    }
    assert_eq!(summary(&value).unwrap()["status"], "legacy-budget-passed");
    value["budget_samples"][0]["samples"][3]["row"]["elapsed_ns"] = json!(1_000_000_000);
    value["budget_samples"][0]["samples"][3]["row"]["ns_per_iteration"] = json!(1_000_000_000);
    assert_eq!(summary(&value).unwrap()["status"], "qualified-regression");
    let mut value = with_budgets();
    value["budget_samples"][0]["samples"][0]["peak_rss_bytes"] = json!(100_000_000);
    assert_eq!(summary(&value).unwrap()["status"], "qualified-regression");
}

#[test]
fn incomplete_unknown_and_forged_collection_records_fail_closed() {
    for (pointer, replacement) in [
        ("/schema_version", json!(99)),
        ("/complete", json!(false)),
        ("/rows/0/schema_version", json!(99)),
        ("/rows/0/result_count", json!(99)),
        ("/rows/0/provenance/binding", json!("unbound-runner")),
        (
            "/rows/0/provenance/source/input_sha256",
            json!("f".repeat(64)),
        ),
        (
            "/rows/0/provenance/build/executable_sha256",
            json!("f".repeat(64)),
        ),
        ("/rows/0/measurement_scope", json!(PROFILE_SCOPE)),
        ("/source/revision", json!("/Users/synthetic/private")),
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(summary(&value).is_err(), "accepted {pointer}");
    }
    let mut value = fixture();
    value["rows"].as_array_mut().unwrap().pop();
    assert!(summary(&value).is_err());
    let mut value = fixture();
    let row = value["rows"][0].clone();
    value["rows"].as_array_mut().unwrap().push(row);
    assert!(summary(&value).is_err());
    let mut value = with_budgets();
    value["budget_samples"][0]["samples"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(summary(&value).is_err());
    let mut value = with_budgets();
    value["budget_samples"][0]["samples"][2]["peak_rss_bytes"] = Value::Null;
    assert!(summary(&value).is_err());
}

#[test]
fn public_projection_cannot_copy_diagnostics_paths_or_action_keys() {
    let mut value = fixture();
    let marker = "/Users/synthetic/private-finding-value";
    value["build"]["compile_action_key"] = json!(marker);
    value["build"]["compiler_version"] = json!(marker);
    value["host"]["cpu"] = json!(marker);
    for row in value["rows"].as_array_mut().unwrap() {
        row["provenance"]["build"]["compile_action_key"] = json!(marker);
        row["provenance"]["build"]["compiler_version"] = json!(marker);
        row["provenance"]["host"]["cpu"] = json!(marker);
        row["invariant"] = json!(marker);
    }
    let mut result = summary(&value).unwrap();
    validate_public_summary(&result).unwrap();
    let text = result.to_string();
    assert!(!text.contains(marker));
    assert!(!text.contains("compile_action_key"));
    result["diagnostic"] = json!(marker);
    assert!(validate_public_summary(&result).is_err());
    let mut result = summary(&value).unwrap();
    result["identity"]["target"] = json!(marker);
    assert!(validate_public_summary(&result).is_err());
    let mut result = summary(&value).unwrap();
    result["measurements"][0]["workload"] = json!(marker);
    assert!(validate_public_summary(&result).is_err());
}

#[test]
fn options_reject_missing_values_duplicate_or_mixed_modes() {
    for args in [
        vec!["--output"],
        vec!["--input"],
        vec!["--output", "relative"],
        vec![
            "--output",
            "/private/tmp/output",
            "--output",
            "/private/tmp/again",
        ],
        vec![
            "--output",
            "/private/tmp/output",
            "--input",
            "/private/tmp/input",
            "--legacy-budget",
        ],
    ] {
        assert!(Request::parse(&args.iter().map(ToString::to_string).collect::<Vec<_>>()).is_err());
    }
}

fn profile_fixture() -> Value {
    let mut value = fixture();
    value["kind"] = json!("profile");
    value["measurement_scope"] = json!(PROFILE_SCOPE);
    value["build"]["timing_scope"] = json!(PROFILE_SCOPE);
    value["release_gate"] = json!(false);
    let identity = json!({"workload":"core-dense-16-kib","complete":true,"errors":0,
        "input_bytes":16384,"rules":1,"keywords":1,"findings":256,"decoded_bytes":0,
        "work_units":16384,"finding_records":256,"input_fnv1a64":"0123456789abcdef",
        "config_fnv1a64":"0123456789abcdef","outcome_fnv1a64":"0123456789abcdef"});
    let mut provenance = value["rows"][0]["provenance"].clone();
    provenance["build"] = value["build"].clone();
    value["result"] = json!({"ready":{"schema_version":1,"kind":"ready","scope":SAMPLE_SCOPE,"identity":identity,"provenance":provenance},"status":"unsupported-host"});
    value
}

#[test]
fn unavailable_profile_is_distinct_from_incomplete_or_forged_profile() {
    let mut value = profile_fixture();
    assert_eq!(
        summary(&value).unwrap()["status"],
        "unavailable-profile-tool"
    );
    value["result"]["status"] = json!("complete");
    assert!(summary(&value).is_err());
    value["result"]["profile"] = json!({"kind":"profile-complete","identity":value["result"]["ready"]["identity"],"actual_scan_count":1});
    assert!(summary(&value).is_err());
}

#[test]
#[cfg(unix)]
fn private_import_checks_complete_artifacts_permissions_missing_and_changed_files() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rustleaks-report-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    private::directory(&scratch).unwrap();
    let mut value = profile_fixture();
    value["result"]["status"] = json!("complete");
    value["result"]["profile"] = json!({"kind":"profile-complete","identity":value["result"]["ready"]["identity"],"actual_scan_count":1});
    for (index, (role, pointer)) in import::PROFILE_ARTIFACTS
        .iter()
        .zip([
            "cpu",
            "memory_before/heap",
            "memory_before/vm",
            "memory_after/heap",
            "memory_after/vm",
        ])
        .enumerate()
    {
        let (text, observation) = match index {
            0 => (
                "Call graph:\n    12 Thread_1\n      12 core::scan (in rustleaks_perf) + 8 [0x1]\n\nTotal number in stack:\n",
                json!({"sampled_thread_sections":1,"thread_sample_total":12,"symbolized_frame_rows":1,"target_symbolized_frame_rows":1,"scope":"thread sample counts; nested frame rows are not independent samples"}),
            ),
            1 | 3 => (
                "All zones: 2 nodes (64 bytes)\nCOUNT BYTES AVG CLASS_NAME TYPE BINARY\n 2 64 32.0 non-object\n",
                json!({"live_nodes":2,"live_bytes":64,"populated_class_rows":1,"scope":"live retained heap snapshot; not allocation history"}),
            ),
            _ => (
                "REGION TYPE SIZE SIZE SIZE SIZE SIZE SIZE SIZE COUNT\nMALLOC 4K 2K 1K 0K 0K 0K 0K 1\nTOTAL 4K 2K 1K 0K 0K 0K 0K 1\n",
                json!({"virtual_bytes":4096,"resident_bytes":2048,"dirty_bytes":1024,"regions":1,"populated_region_rows":1,"scope":"rounded native VM summary; not allocation-site attribution"}),
            ),
        };
        let bytes = text.as_bytes();
        private::write(&scratch.join(role), bytes).unwrap();
        let hash = sha256_bytes(bytes);
        value["files"][*role] = json!(hash);
        let tool = json!({"status":"complete","exit_code":0,"tool_sha256":"a".repeat(64),"observation_sha256":hash,"observation":observation});
        if let Some((stage, kind)) = pointer.split_once('/') {
            value["result"][stage][kind] = tool;
        } else {
            value["result"][pointer] = tool;
        }
    }
    let result = import::summarize(&value, Some(&scratch), "report-consistency-only").unwrap();
    assert_eq!(result["status"], "complete-profile");
    validate_public_summary(&result).unwrap();
    let file = scratch.join("cpu-stacks.txt");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(import::summarize(&value, Some(&scratch), "report-consistency-only").is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, b"changed").unwrap();
    let mut forged = value.clone();
    let forged_hash = sha256_bytes(b"changed");
    forged["files"]["cpu-stacks.txt"] = json!(forged_hash);
    forged["result"]["cpu"]["observation_sha256"] = json!(forged_hash);
    assert!(import::summarize(&forged, Some(&scratch), "report-consistency-only").is_err());
    assert!(import::summarize(&value, Some(&scratch), "report-consistency-only").is_err());
    fs::remove_file(&file).unwrap();
    assert!(import::summarize(&value, Some(&scratch), "report-consistency-only").is_err());
    for role in import::PROFILE_ARTIFACTS.iter().skip(1) {
        fs::remove_file(scratch.join(role)).unwrap();
    }
    fs::remove_dir(scratch).unwrap();
}

#[test]
fn structured_native_failure_and_exact_host_qualification_are_preserved() {
    assert_eq!(
        runner_failure(
            "Python RSS collector for default-compile exited exit status: 2:\nrustleaks-perf-status: invariant-failure-v1\nprivate details"
        ),
        "invariant-failure"
    );
    assert_eq!(
        runner_failure("rustleaks-perf-status: invariant-failure-v1\nraw detail"),
        "invariant-failure"
    );
    assert_eq!(
        runner_failure("prefix rustleaks-perf-status: invariant-failure-v1"),
        "execution-failure"
    );
    let mut value = fixture();
    value["outcome"] = json!("execution-failure");
    assert_eq!(summary(&value).unwrap()["status"], "execution-failure");
    for field in [
        "machine_model",
        "chip_type",
        "physical_memory",
        "number_processors",
    ] {
        let mut value = with_budgets();
        value["host_qualification"][field] = json!("different");
        assert!(summary(&value).is_err());
    }
    let mut value = profile_fixture();
    value["result"]["ready"]["provenance"]["build"]["executable_sha256"] = json!("f".repeat(64));
    assert!(summary(&value).is_err());
}

fn calibration_fixture(window: bool, blocks: u64, pairs: usize, first: &str) -> Value {
    let mut value = profile_fixture();
    value["kind"] = json!("calibration");
    value["schema_version"] = json!(if window { 2 } else { 1 });
    value["measurement_scope"] = json!(if window { WINDOW_SCOPE } else { SAMPLE_SCOPE });
    value["build"]["timing_scope"] = json!(MEASUREMENT_SCOPE);
    value["baseline_eligible"] = json!(true);
    value["controller_sha256"] = json!("a".repeat(64));
    value["identity"] = value["result"]["ready"]["identity"].clone();
    value["workload"] = json!("core-dense-16-kib");
    value["pairs_per_stage"] = json!(pairs);
    value["window_blocks"] = json!(blocks);
    value["iterations_per_block"] = json!(100);
    value["first_side"] = json!(first);
    value["policy"] = json!({"id":if window {"empirical-paired-window-band-v2"} else {"empirical-paired-band-v1"}});
    let identity = value["identity"].clone();
    let mut rows = Vec::new();
    for stage in ["training-aa", "validation-aa", "control-ab"] {
        for pair in 0..pairs {
            let order = if (pair % 2 == 0) == (first == "a") {
                ["a", "b"]
            } else {
                ["b", "a"]
            };
            for side in order {
                let extra = u64::from(stage == "control-ab" && side == "b");
                let elapsed = if extra == 1 {
                    2000
                } else if side == "b" {
                    1010
                } else {
                    1000
                };
                let mut row = json!({"stage":stage,"pair":pair,"side":side,"order":order,
                    "identity":identity,"extra_passes":extra,"elapsed_ns":elapsed,"iterations":100,"actual_scan_count":100*(extra+1)});
                if window {
                    row["schema_version"] = json!(2);
                    row["scope"] = json!(WINDOW_SCOPE);
                    row["window_blocks"] = json!(blocks);
                    row["iterations_per_block"] = json!(100);
                    row["total_iterations"] = json!(blocks * 100);
                    row["elapsed_ns"] = json!(elapsed * blocks);
                    row["actual_scan_count"] = json!(blocks * 100 * (extra + 1));
                    row["components"]=json!((0..blocks).map(|index| json!({"schema_version":2,"kind":"window-component","scope":WINDOW_SCOPE,
                        "block_index":index,"window_blocks":blocks,"iterations_per_block":100,"extra_passes":extra,"identity":identity,
                        "sample":{"kind":"sample","scope":SAMPLE_SCOPE,"identity":identity,"iterations":100,"extra_passes":extra,
                            "actual_scan_count":100*(extra+1),"elapsed_ns":elapsed,"ns_per_logical_iteration":elapsed/100}})).collect::<Vec<_>>());
                }
                rows.push(row);
            }
        }
    }
    value["calibration"] = if window {
        super::super::investigation::classify_windows(&rows, pairs, first).unwrap()
    } else {
        super::super::investigation::classify(&rows, pairs).unwrap()
    };
    value["rows"] = json!(rows);
    value
}

#[test]
fn historical_calibration_adapters_recompute_rows_but_remain_informational() {
    let mut v1 = calibration_fixture(false, 1, 5, "a");
    let baseline = summary(&v1).unwrap();
    for row in v1["rows"].as_array_mut().unwrap() {
        row["total_iterations"] = json!(1);
    }
    assert_eq!(summary(&v1).unwrap(), baseline);
    for window in [false, true] {
        let value = calibration_fixture(window, 1, 5, "a");
        let result = summary(&value).unwrap();
        assert_eq!(result["status"], "informational-timing");
        validate_public_summary(&result).unwrap();
        for pointer in ["/rows/0/actual_scan_count", "/rows/0/identity/work_units"] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = json!(0);
            assert!(summary(&changed).is_err());
        }
        let mut changed = value.clone();
        changed["calibration"]["held_out_aa_within_band"] = json!(false);
        assert!(summary(&changed).is_err());
        let mut changed = value.clone();
        changed["rows"].as_array_mut().unwrap().pop();
        assert!(summary(&changed).is_err());
        let mut changed = value.clone();
        changed["schema_version"] = json!(9);
        assert!(summary(&changed).is_err());
    }
}

fn representative_fixture() -> Value {
    let base = fixture();
    let mut provenance = base["rows"][0]["provenance"].clone();
    provenance["build"]["timing_scope"] = json!(REPRESENTATIVE_SCOPE);
    let workload = "core-mixed-1-kib";
    let phases = super::super::representative_suite::required_phases(workload).unwrap();
    let mut rows = Vec::new();
    for sample in 0..3 {
        for phase in &phases {
            rows.push(json!({"schema_version":3,"suite":"representative-v1","workload":workload,"measurement_scope":REPRESENTATIVE_SCOPE,
                "threshold_evaluation":"none-uncalibrated","sample_index":sample,"sample_count":3,"ns_per_iteration":100+sample,
                "provenance":provenance,"phase":{"phase":phase,"scope":REPRESENTATIVE_SCOPE,"iterations":1,"complete":true,"errors":0,
                    "findings":1,"elapsed_ns":100+sample,"logical_units_per_iteration":1024,"logical_unit":"input-bytes","counts":{"workers":1},
                    "input_fnv1a64":"0123456789abcdef","config_fnv1a64":"0123456789abcdef","outcome_fnv1a64":"0123456789abcdef"}}));
        }
    }
    let stats = super::super::representative_suite::statistics(vec![100, 101, 102]).unwrap();
    for phase in phases {
        rows.push(json!({"schema_version":3,"suite":"representative-v1","kind":"summary","workload":workload,"phase":phase,
        "measurement_scope":REPRESENTATIVE_SCOPE,"statistics":stats,"p95":null,"threshold_evaluation":"none-uncalibrated",
        "source":provenance["source"],"build":provenance["build"],"host":provenance["host"]}));
    }
    rows.push(json!({"schema_version":3,"suite":"representative-v1","kind":"run-complete","source":provenance["source"],
        "executable_sha256":provenance["build"]["executable_sha256"],"baseline_eligible":true}));
    json!({"kind":"representative-jsonl","rows":rows})
}

#[test]
fn representative_import_requires_raw_process_samples_summaries_and_final_marker() {
    let value = representative_fixture();
    let result = summary(&value).unwrap();
    assert_eq!(result["status"], "informational-timing");
    validate_public_summary(&result).unwrap();
    let encoded = value["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(import::parse(encoded.as_bytes()).unwrap(), value);
    for index in [0, 4, 12, 16] {
        let mut changed = value.clone();
        changed["rows"].as_array_mut().unwrap().remove(index);
        assert!(summary(&changed).is_err());
    }
    for (pointer, replacement) in [
        ("/rows/0/phase/complete", json!(false)),
        ("/rows/4/phase/findings", json!(2)),
        ("/rows/12/statistics/median_ns", json!(999)),
        ("/rows/0/workload", json!("core-/Users/synthetic/private")),
        (
            "/rows/0/provenance/build/executable_sha256",
            json!("f".repeat(64)),
        ),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(summary(&changed).is_err(), "accepted {pointer}");
    }
}

#[test]
#[cfg(unix)]
fn fixed_window_matrix_import_binds_all_private_companions_and_rejects_paths() {
    let scratch = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rustleaks-matrix-import-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    private::directory(&scratch).unwrap();
    let workloads = [
        "core-dense-16-kib",
        "core-mixed-16-kib",
        "core-default-no-hit-16-kib",
        "core-decode-depth-5",
    ];
    let mut cells = Vec::new();
    let mut provenance = Value::Null;
    for index in 0..16 {
        let run = if index < 8 { 1 } else { 2 };
        let slot = (index % 8) / 2;
        let workload = workloads[if run == 1 { slot } else { 3 - slot }];
        let blocks = if (index % 2 == 0) == (run == 1) {
            1
        } else {
            10
        };
        let side = if run == 1 { "a" } else { "b" };
        let role = format!("cell-{index:02}");
        let mut report = calibration_fixture(true, blocks, 9, side);
        report["workload"] = json!(workload);
        report["identity"]["workload"] = json!(workload);
        for row in report["rows"].as_array_mut().unwrap() {
            row["identity"]["workload"] = json!(workload);
            for component in row["components"].as_array_mut().unwrap() {
                component["identity"]["workload"] = json!(workload);
                component["sample"]["identity"]["workload"] = json!(workload);
            }
        }
        if index == 0 {
            provenance =
                json!({"source":report["source"],"build":report["build"],"host":report["host"]});
        }
        private::directory(&scratch.join(&role)).unwrap();
        private::json(&scratch.join(&role).join("report.json"), &report).unwrap();
        cells.push(json!({"index":index,"run":run,"workload":workload,"window_blocks":blocks,"first_side":side,"directory":role,
            "status":"complete","pairs_per_stage":9,"iterations_per_block":100,"calibration":report["calibration"]}));
    }
    let matrix = json!({"schema_version":2,"kind":"observation-window-matrix","protocol":"observation-window-v2","complete":true,
        "completed_cells":16,"stop":null,"release_threshold_created":false,"status":"baseline-qualified-for-later-protocol-review",
        "schedule":cells,"provenance":provenance,"later_trial_eligible":true,"source_baseline_eligible":true});
    let matrix: Value = serde_json::from_slice(&serde_json::to_vec(&matrix).unwrap()).unwrap();
    let result = import::summarize(&matrix, Some(&scratch), "report-consistency-only").unwrap();
    assert_eq!(result["status"], "informational-timing");
    validate_public_summary(&result).unwrap();
    assert!(result["companion_sha256"].as_str().is_some());
    let mut forged = matrix.clone();
    forged["schedule"][0]["directory"] = json!("../private");
    assert!(import::summarize(&forged, Some(&scratch), "report-consistency-only").is_err());
    fs::remove_file(scratch.join("cell-00/report.json")).unwrap();
    assert!(import::summarize(&matrix, Some(&scratch), "report-consistency-only").is_err());
    for index in 0..16 {
        let directory = scratch.join(format!("cell-{index:02}"));
        if index != 0 {
            fs::remove_file(directory.join("report.json")).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }
    fs::remove_dir(scratch).unwrap();
}
