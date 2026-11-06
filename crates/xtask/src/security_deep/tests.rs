#![cfg(any(target_os = "linux", target_os = "macos"))]

use super::*;

#[test]
fn profiles_and_selection_are_explicit_and_bounded() {
    let default = Request::parse(&[]).unwrap();
    assert_eq!(default.profile, Profile::Deep);
    assert_eq!(default.targets.len(), 8);
    assert_eq!(default.deadline_seconds, 7200);
    let request = Request::parse(&[
        "--profile".into(),
        "extended".into(),
        "--targets".into(),
        "config,archive".into(),
        "--seconds".into(),
        "60".into(),
        "--deadline-seconds".into(),
        "1800".into(),
    ])
    .unwrap();
    assert_eq!(request.profile, Profile::Extended);
    assert_eq!(request.targets, ["config", "archive"]);
    for arguments in [
        vec!["--deadline-seconds", "0"],
        vec!["--deadline-seconds", "7201"],
        vec!["--seconds", "601"],
        vec!["--targets", "config,config"],
        vec!["--targets", "unknown"],
        vec!["--coverage", "pretend"],
        vec!["--profile", "deep", "--profile", "smoke"],
    ] {
        assert!(
            Request::parse(
                &arguments
                    .iter()
                    .map(|value| (*value).into())
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }
}

#[test]
fn preparation_expiry_skips_requested_targets_without_starting_them() {
    let bundle = private::Bundle::new(None).unwrap().retaining_success();
    let mut run = Run {
        root: &bundle.path,
        bundle: &bundle,
        deadline: Deadline::new(Some(0)),
        started: Instant::now(),
        report: json!({"stages":[]}),
    };
    let mut executed = false;
    assert!(
        !run.stage("preparation", true, |_, _, _| {
            executed = true;
            Ok(Step::pass(Value::Null))
        })
        .unwrap()
    );
    for target in ["config", "archive"] {
        assert!(
            !run.stage(target, true, |_, _, _| {
                executed = true;
                Ok(Step::pass(Value::Null))
            })
            .unwrap()
        );
    }
    assert!(!executed);
    let stages = run.report["stages"].as_array().unwrap();
    assert_eq!(stages.len(), 3);
    assert!(
        stages
            .iter()
            .all(|stage| stage["status"] == "skipped" && stage["reason"] == "whole-run-deadline")
    );
    assert_eq!(completion(stages), (true, 3));
    drop(run);
    let path = bundle.path.clone();
    let error = bundle
        .finish_named(Err("incomplete synthetic review".into()), "security-deep")
        .unwrap_err();
    assert!(!error.contains("incomplete synthetic review"));
    assert!(path.join("report.json").is_file());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn optional_capability_skips_are_distinct_from_failed_or_missing_required_work() {
    assert_eq!(
        completion(&[
            json!({"status":"pass","required":true}),
            json!({"status":"skipped","required":false})
        ]),
        (false, 1)
    );
    assert_eq!(
        completion(&[json!({"status":"skipped","required":true})]),
        (true, 1)
    );
    assert_eq!(
        completion(&[json!({"status":"fail","required":false})]),
        (true, 0)
    );
    assert!(stress_records("test result: ok. 0 passed", "report").is_err());
    let rows = [
        "template-source",
        "template-output-exact",
        "template-output-over",
        "template-actions-exact",
        "template-actions-over",
    ]
    .iter()
    .map(|case| json!({"kind":"security-stress","status":"pass","case":case}).to_string())
    .collect::<Vec<_>>();
    assert_eq!(stress_records(&rows.join("\n"), "report").unwrap().len(), 5);
    assert!(stress_records(&rows[1..].join("\n"), "report").is_err());
    assert!(stress_records(&format!("{}\n{}", rows.join("\n"), rows[0]), "report").is_err());
}

#[test]
fn successful_deep_report_is_retained_while_ordinary_smoke_scratch_cleans() {
    let ordinary = private::Bundle::new(None).unwrap();
    let ordinary_path = ordinary.path.clone();
    ordinary.finish(Ok(())).unwrap();
    assert!(!ordinary_path.exists());
    let deep = private::Bundle::new(None).unwrap().retaining_success();
    let path = deep.path.clone();
    private::json(&path.join("report.json"), &json!({"complete":true})).unwrap();
    deep.finish_named(Ok(()), "security-deep").unwrap();
    assert!(path.join("report.json").is_file());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn expired_stage_command_preserves_requested_and_effective_supervisor_budgets() {
    let bundle = private::Bundle::new(None).unwrap();
    assert!(
        command(
            &bundle.path,
            &bundle.path,
            "expired-child",
            "/bin/sh",
            &[],
            Deadline::new(Some(0)),
            90,
            &[]
        )
        .is_err()
    );
    let record = private::read_json(&bundle.path.join("expired-child/command.json")).unwrap();
    assert_eq!(record["timeout_ms"], 0);
    assert_eq!(record["supervisor"]["requested_maximum_ms"], 90_000);
    assert_eq!(record["supervisor"]["effective_timeout_ns"], 0);
    assert_eq!(record["supervisor"]["deadline_constrained"], true);
    assert_eq!(record["outcome"], "not-started-deadline");
    assert!(!bundle.path.join("expired-child/stdout.log").exists());
    fs::remove_dir_all(&bundle.path).unwrap();
}
