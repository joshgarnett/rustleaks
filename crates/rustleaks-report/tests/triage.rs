#![allow(missing_docs)]

use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::native::NativePolicy;
use rustleaks_core::triage::{
    ReviewOccurrence, ReviewPolicy, ReviewReason, ReviewRecord, ReviewSource,
};
use rustleaks_core::{ScanBudget, ScanControl};
use rustleaks_report::triage::{
    MAX_REVIEW_JSON_BYTES, TriageReportError, read_review_records, write_review_projection,
    write_review_records,
};

const PACK: &str = r#"
[[rules]]
id = "rustleaks.example"
regex = '''example=(TEST-[A-Z]{4})'''
secretGroup = 1
keywords = ["example="]
"#;

#[test]
fn artifacts_round_trip_without_source_secrets_or_configuration() {
    let engine = NativePolicy::builder()
        .with_pack("example-v1", PACK)
        .unwrap()
        .build()
        .unwrap();
    let policy = ReviewPolicy::caller_bound(engine.identity(), "registry-policy-001").unwrap();
    let source = ReviewSource::caller_bound("snapshot-001").unwrap();
    let scan = engine.scan_fragment_controlled(
        &Fragment::builder(b"example=TEST-ABCD")
            .file_path("SENSITIVE-PATH")
            .build(),
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::bounded(32),
    );
    let record = ReviewRecord::new(
        policy.reference(),
        scan.options(),
        ReviewOccurrence::from_finding(source.clone(), &scan.scan().findings()[0], 0).unwrap(),
        ReviewReason::SyntheticFixture,
        100,
    )
    .unwrap();
    let mut bytes = Vec::new();
    write_review_records(&mut bytes, std::slice::from_ref(&record)).unwrap();
    assert_eq!(read_review_records(&bytes).unwrap(), [record]);
    let text = std::str::from_utf8(&bytes).unwrap();
    for sensitive in [
        "TEST-ABCD",
        "SENSITIVE-PATH",
        "regex",
        "example=(",
        "secretGroup",
    ] {
        assert!(!text.contains(sensitive), "unexpected field {sensitive}");
    }
    let restored = read_review_records(&bytes).unwrap();
    let review = policy.review(&scan, &source, &restored, 10).unwrap();
    let mut projection = Vec::new();
    write_review_projection(&mut projection, &review).unwrap();
    let projection = std::str::from_utf8(&projection).unwrap();
    for sensitive in [
        "TEST-ABCD",
        "SENSITIVE-PATH",
        "registry-policy-001",
        "snapshot-001",
        "rustleaks.example",
    ] {
        assert!(!projection.contains(sensitive));
    }
    let value: serde_json::Value = serde_json::from_str(projection).unwrap();
    assert_eq!(value["occurrences"][0]["state"], "acknowledged");
    assert_eq!(value["complete"], true);
    assert!(!projection.contains("safe"));
    let mut repeated = Vec::new();
    write_review_records(&mut repeated, &restored).unwrap();
    assert_eq!(bytes, repeated);
}

#[test]
fn partial_projection_stays_partial() {
    let engine = NativePolicy::builder().build().unwrap();
    let policy = ReviewPolicy::for_builtin(engine.identity()).unwrap();
    let scan = engine.scan_fragment_controlled(
        &Fragment::new(b"synthetic input"),
        &ScanOptions::default(),
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
        ExplanationOptions::disabled(),
    );
    let review = policy
        .review(
            &scan,
            &ReviewSource::caller_bound("snapshot-001").unwrap(),
            &[],
            0,
        )
        .unwrap();
    let mut bytes = Vec::new();
    write_review_projection(&mut bytes, &review).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["occurrences"], serde_json::json!([]));
}

#[test]
fn malformed_unknown_and_oversized_artifacts_fail_without_echoing_input() {
    for bytes in [
        br#"{"schema_version":1,"records":[],"secret":"SENTINEL"}"#.as_slice(),
        br#"{"schema_version":1,"records":[{"secret":"SENTINEL"}]}"#,
        b"SENTINEL",
    ] {
        let error = read_review_records(bytes).unwrap_err();
        assert!(!error.to_string().contains("SENTINEL"));
    }
    assert!(matches!(
        read_review_records(br#"{"schema_version":2,"records":[]}"#),
        Err(TriageReportError::UnsupportedVersion)
    ));
    assert!(matches!(
        read_review_records(&vec![b' '; MAX_REVIEW_JSON_BYTES + 1]),
        Err(TriageReportError::LimitExceeded)
    ));
    let too_many =
        serde_json::json!({"schema_version": 1, "records": vec![serde_json::Value::Null; 4097]});
    assert!(matches!(
        read_review_records(&serde_json::to_vec(&too_many).unwrap()),
        Err(TriageReportError::LimitExceeded)
    ));
}
