#![allow(missing_docs)]

use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::model::{FindingRange, Fragment, ScanOptions};
use rustleaks_core::native::{NativeEngine, NativeExtension, NativePolicy, NativeScanOutcome};
use rustleaks_core::triage::{
    MAX_REVIEW_RECORDS, PresentationGroups, RecordState, ReviewClassification, ReviewError,
    ReviewOccurrence, ReviewPolicy, ReviewReason, ReviewRecord, ReviewSource, validate_records,
};
use rustleaks_core::{ScanBudget, ScanControl};

const PACK: &str = r#"
[[rules]]
id = "rustleaks.example-a"
regex = '''example=(TEST-[A-Z]{4})'''
secretGroup = 1
keywords = ["example="]

[[rules]]
id = "rustleaks.example-b"
regex = '''example=(TEST-[A-Z]{4})'''
secretGroup = 1
keywords = ["example="]
"#;

fn engine() -> NativeEngine {
    NativePolicy::builder()
        .with_pack("example-v1", PACK)
        .unwrap()
        .build()
        .unwrap()
}

fn scan(engine: &NativeEngine, input: &[u8], options: ScanOptions) -> NativeScanOutcome {
    engine.scan_fragment_controlled(
        &Fragment::new(input),
        &options,
        &ScanControl::unlimited(),
        ExplanationOptions::disabled(),
    )
}

fn source() -> ReviewSource {
    ReviewSource::caller_bound("snapshot-001").unwrap()
}

fn policy(engine: &NativeEngine) -> ReviewPolicy {
    ReviewPolicy::caller_bound(engine.identity(), "registry-policy-001").unwrap()
}

fn record(policy: &ReviewPolicy, scan: &NativeScanOutcome, index: usize) -> ReviewRecord {
    ReviewRecord::new(
        policy.reference(),
        scan.options(),
        ReviewOccurrence::from_finding(source(), &scan.scan().findings()[index], index).unwrap(),
        ReviewReason::SyntheticFixture,
        100,
    )
    .unwrap()
}

#[test]
fn review_is_deterministic_and_never_removes_acknowledged_occurrences() {
    let engine = engine();
    let policy = policy(&engine);
    let outcome = scan(
        &engine,
        b"example=TEST-ABCD example=TEST-EFGH",
        ScanOptions::default(),
    );
    assert_eq!(outcome.scan().findings().len(), 4);
    let records = [record(&policy, &outcome, 0)];
    let first = policy.review(&outcome, &source(), &records, 99).unwrap();
    let second = policy.review(&outcome, &source(), &records, 99).unwrap();
    assert_eq!(first.classifications(), second.classifications());
    assert_eq!(first.record_states(), second.record_states());
    assert_eq!(first.findings(), outcome.scan().findings());
    assert_eq!(
        first.classifications(),
        [
            ReviewClassification::Acknowledged { record_index: 0 },
            ReviewClassification::New,
            ReviewClassification::New,
            ReviewClassification::New,
        ]
    );
    assert_eq!(
        first.record_states(),
        [RecordState::Active { finding_index: 0 }]
    );
    let expired = policy.review(&outcome, &source(), &records, 100).unwrap();
    assert_eq!(expired.record_states(), [RecordState::Expired]);
    assert!(
        expired
            .classifications()
            .iter()
            .all(|state| *state == ReviewClassification::New)
    );
    assert!(!format!("{first:?}").contains("TEST-ABCD"));
}

#[test]
fn line_shifts_and_source_replacements_require_fresh_review() {
    let engine = engine();
    let policy = policy(&engine);
    let before = scan(&engine, b"example=TEST-ABCD", ScanOptions::default());
    let records = [record(&policy, &before, 0)];
    let shifted = scan(&engine, b"\nexample=TEST-ABCD", ScanOptions::default());
    let shifted_source = ReviewSource::caller_bound("snapshot-002").unwrap();
    let review = policy
        .review(&shifted, &shifted_source, &records, 10)
        .unwrap();
    assert_eq!(review.record_states(), [RecordState::StaleSource]);
    assert!(
        review
            .classifications()
            .iter()
            .all(|state| *state == ReviewClassification::New)
    );
    // Even an incorrectly reused source ID cannot match a changed location.
    let review = policy.review(&shifted, &source(), &records, 10).unwrap();
    assert_eq!(review.record_states(), [RecordState::StaleOccurrence]);
    let replaced = scan(&engine, b"example=TEST-EFGH", ScanOptions::default());
    let review = policy
        .review(&replaced, &shifted_source, &records, 10)
        .unwrap();
    assert_eq!(review.record_states(), [RecordState::StaleSource]);
}

#[test]
fn exact_rule_and_extension_changes_cannot_reuse_policy_binding() {
    let original = engine();
    let policy = policy(&original);
    let before = scan(&original, b"example=TEST-ABCD", ScanOptions::default());
    let records = [record(&policy, &before, 0)];
    let upgraded = NativePolicy::builder()
        .with_pack("example-v1", &PACK.replace("[A-Z]{4}", "[A-Z]{4,5}"))
        .unwrap()
        .build()
        .unwrap();
    let after = scan(&upgraded, b"example=TEST-ABCD", ScanOptions::default());
    assert_eq!(
        policy.review(&after, &source(), &records, 10).unwrap_err(),
        ReviewError::PolicyMismatch
    );
    let upgraded_policy =
        ReviewPolicy::caller_bound(upgraded.identity(), "registry-policy-002").unwrap();
    assert_eq!(
        upgraded_policy
            .review(&after, &source(), &records, 10)
            .unwrap()
            .record_states(),
        [RecordState::StalePolicy]
    );
    assert!(matches!(
        ReviewPolicy::for_builtin(original.identity()),
        Err(ReviewError::CustomPolicyBindingRequired)
    ));
    let base = NativePolicy::builder().build().unwrap();
    let extended = NativePolicy::builder()
        .with_extension(NativeExtension::GithubClassicPatV1)
        .build()
        .unwrap();
    assert_ne!(
        ReviewPolicy::for_builtin(base.identity())
            .unwrap()
            .reference(),
        ReviewPolicy::for_builtin(extended.identity())
            .unwrap()
            .reference()
    );
}

#[test]
fn actual_scan_options_are_part_of_review_eligibility() {
    let engine = engine();
    let policy = policy(&engine);
    let before = scan(&engine, b"example=TEST-ABCD", ScanOptions::default());
    let records = [record(&policy, &before, 0)];
    for options in [
        ScanOptions::builder().max_decode_depth(1).build(),
        ScanOptions::builder().max_target_bytes(Some(1_000)).build(),
        ScanOptions::builder().redaction_percent(100).build(),
        ScanOptions::builder().honor_allow_markers(false).build(),
    ] {
        let changed = scan(&engine, b"example=TEST-ABCD", options);
        let review = policy.review(&changed, &source(), &records, 10).unwrap();
        assert_eq!(review.record_states(), [RecordState::StaleOptions]);
        assert!(
            review
                .classifications()
                .iter()
                .all(|state| *state == ReviewClassification::New)
        );
    }
}

#[test]
fn missing_partial_occurrences_are_inconclusive() {
    let engine = engine();
    let policy = policy(&engine);
    let before = scan(&engine, b"example=TEST-ABCD", ScanOptions::default());
    let records = [record(&policy, &before, 0)];
    let partial = engine.scan_fragment_controlled(
        &Fragment::new(b"example=TEST-ABCD"),
        &ScanOptions::default(),
        &ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(0)),
        ExplanationOptions::disabled(),
    );
    let review = policy.review(&partial, &source(), &records, 10).unwrap();
    assert!(!review.is_complete());
    assert_eq!(
        review.record_states(),
        [RecordState::UnobservedInPartialScan]
    );
    let groups = PresentationGroups::for_scan(partial.scan()).unwrap();
    assert!(groups.groups().is_empty());
    assert!(!groups.is_complete());
    assert_eq!(groups.termination(), partial.scan().termination());
}

#[test]
fn groups_preserve_all_occurrences_and_never_merge_separate_spans() {
    let engine = engine();
    let result = scan(
        &engine,
        b"example=TEST-ABCD example=TEST-ABCD",
        ScanOptions::default(),
    );
    let groups = PresentationGroups::for_scan(result.scan()).unwrap();
    assert_eq!(groups.groups().len(), 2);
    assert!(groups.groups().iter().all(|group| group.len() == 2));
    let mut indices = groups
        .groups()
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    indices.sort_unstable();
    assert_eq!(indices, [0, 1, 2, 3]);
    assert_eq!(groups.findings(), result.scan().findings());
    for group in groups.groups() {
        assert_eq!(
            groups.findings()[group[0]].secret_range(),
            groups.findings()[group[1]].secret_range()
        );
    }
    assert!(!format!("{groups:?}").contains("TEST-ABCD"));
}

#[test]
fn encoded_occurrences_stay_distinct_and_retain_unavailable_exact_spans() {
    let engine = engine();
    let policy = policy(&engine);
    let outcome = scan(
        &engine,
        b"ZXhhbXBsZT1URVNULUFCQ0Q= ZXhhbXBsZT1URVNULUFCQ0Q=",
        ScanOptions::builder().max_decode_depth(1).build(),
    );
    assert_eq!(outcome.scan().findings().len(), 4);
    assert!(
        outcome
            .scan()
            .findings()
            .iter()
            .all(|finding| finding.secret_range() == FindingRange::Unavailable)
    );
    let groups = PresentationGroups::for_scan(outcome.scan()).unwrap();
    assert_eq!(groups.groups(), [vec![0], vec![1], vec![2], vec![3]]);
    let records = [record(&policy, &outcome, 0)];
    let review = policy.review(&outcome, &source(), &records, 10).unwrap();
    assert_eq!(
        review
            .classifications()
            .iter()
            .filter(|state| matches!(state, ReviewClassification::Acknowledged { .. }))
            .count(),
        1
    );
    assert_eq!(review.occurrences()[0].secret_range(), None);
}

#[test]
fn records_and_identifiers_have_hard_limits_and_ambiguous_duplicates_fail() {
    assert!(ReviewSource::caller_bound("").is_err());
    assert!(ReviewSource::caller_bound("source with notes").is_err());
    assert!(ReviewSource::caller_bound(&"x".repeat(257)).is_err());
    let engine = engine();
    let policy = policy(&engine);
    let outcome = scan(&engine, b"example=TEST-ABCD", ScanOptions::default());
    let record = record(&policy, &outcome, 0);
    assert_eq!(
        validate_records(&[record.clone(), record.clone()]),
        Err(ReviewError::DuplicateRecord)
    );
    assert_eq!(
        validate_records(&vec![record; MAX_REVIEW_RECORDS + 1]),
        Err(ReviewError::LimitExceeded)
    );
}
