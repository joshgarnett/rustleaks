#![allow(missing_docs)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanBudgetKind, ScanControl, ScanTermination};

fn engine(config: &str) -> Engine {
    Engine::builder(ConfigLoader::new().load_toml(config).unwrap())
        .build()
        .unwrap()
}

fn two_rule_engine() -> Engine {
    engine(
        r#"
[[rules]]
id = "a-first"
regex = '''A'''

[[rules]]
id = "b-second"
regex = '''B'''
"#,
    )
}

#[test]
fn unlimited_control_preserves_the_legacy_scan_result() {
    let engine = two_rule_engine();
    let fragment = Fragment::new(b"A B");
    let legacy = engine.scan_fragment(&fragment, &ScanOptions::default());
    let controlled = engine.scan_fragment_controlled(
        &fragment,
        &ScanOptions::default(),
        &ScanControl::unlimited(),
    );

    assert_eq!(controlled, legacy);
    assert!(controlled.is_complete());
    assert_eq!(controlled.termination(), None);
    assert_eq!(controlled.findings().len(), 2);
    assert_eq!(controlled.usage().finding_records(), 2);
    assert!(controlled.usage().work_units() > 0);
}

#[test]
fn exact_work_boundary_completes_and_one_less_returns_a_structured_partial() {
    let engine = two_rule_engine();
    let fragment = Fragment::new(b"A B");
    let options = ScanOptions::default();
    let probe = engine.scan_fragment_controlled(&fragment, &options, &ScanControl::unlimited());
    let exact_units = probe.usage().work_units();
    assert!(exact_units > 0);

    let exact =
        ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_work_units(exact_units));
    let exact_outcome = engine.scan_fragment_controlled(&fragment, &options, &exact);
    assert!(exact_outcome.is_complete());
    assert_eq!(exact_outcome, probe);

    let below = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_work_units(exact_units - 1));
    let below_outcome = engine.scan_fragment_controlled(&fragment, &options, &below);
    assert_eq!(below_outcome.usage().work_units(), exact_units - 1);
    assert!(matches!(
        below_outcome.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::WorkUnits,
            limit,
            consumed,
            requested: 1,
        }) if *limit == exact_units - 1 && *consumed == exact_units - 1
    ));
}

#[test]
fn decoded_byte_budget_is_cumulative_in_successful_pass_output_bytes() {
    let engine = engine(
        r#"
[[rules]]
id = "decoded"
regex = '''secret=(decoded-secret)'''
secretGroup = 1
keywords = ["secret"]
"#,
    );
    let fragment = Fragment::new(b"secret=ZGVjb2RlZC1zZWNyZXQ=");
    let options = ScanOptions::builder().max_decode_depth(1).build();
    let probe = engine.scan_fragment_controlled(&fragment, &options, &ScanControl::unlimited());
    let decoded_bytes = probe.usage().decoded_bytes();
    assert!(decoded_bytes > 0);
    assert_eq!(probe.findings().len(), 1);

    let exact = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_decoded_bytes(decoded_bytes));
    let exact_outcome = engine.scan_fragment_controlled(&fragment, &options, &exact);
    assert!(exact_outcome.is_complete());
    assert_eq!(exact_outcome, probe);

    let below = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_decoded_bytes(decoded_bytes - 1));
    let below_outcome = engine.scan_fragment_controlled(&fragment, &options, &below);
    assert!(below_outcome.findings().is_empty());
    assert_eq!(below_outcome.usage().decoded_bytes(), 0);
    assert!(matches!(
        below_outcome.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::DecodedBytes,
            limit,
            consumed: 0,
            requested,
        }) if *limit == decoded_bytes - 1 && *requested == decoded_bytes
    ));
}

#[test]
fn work_budget_polls_inside_decoder_owned_candidate_loops() {
    let engine = engine(
        r#"
[[rules]]
id = "decoded"
regex = '''secret=(decoded-secret)'''
secretGroup = 1
keywords = ["secret"]
"#,
    );
    let fragment = Fragment::new(b"secret=ZGVjb2RlZC1zZWNyZXQ=");
    let raw_only = engine.scan_fragment_controlled(
        &fragment,
        &ScanOptions::default(),
        &ScanControl::unlimited(),
    );
    let through_decode_entry = raw_only.usage().work_units() + 1;
    let control = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_work_units(through_decode_entry));
    let outcome = engine.scan_fragment_controlled(
        &fragment,
        &ScanOptions::builder().max_decode_depth(1).build(),
        &control,
    );

    assert!(outcome.findings().is_empty());
    assert_eq!(outcome.usage().decoded_bytes(), 0);
    assert!(matches!(
        outcome.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::WorkUnits,
            limit,
            consumed,
            requested: 1,
        }) if *limit == through_decode_entry && *consumed == through_decode_entry
    ));
}

#[test]
fn finding_record_budget_keeps_only_completed_top_level_rules() {
    let engine = two_rule_engine();
    let control =
        ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(1));
    let outcome =
        engine.scan_fragment_controlled(&Fragment::new(b"A B"), &ScanOptions::default(), &control);

    assert_eq!(outcome.findings().len(), 1);
    assert_eq!(outcome.findings()[0].rule_id().as_bytes(), b"a-first");
    assert_eq!(outcome.usage().finding_records(), 1);
    assert!(matches!(
        outcome.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::FindingRecords,
            limit: 1,
            consumed: 1,
            requested: 1,
        })
    ));
}

#[test]
fn incomplete_composite_projection_is_rolled_back() {
    let engine = engine(
        r#"
[[rules]]
id = "a-primary"
regex = '''PRIMARY'''
  [[rules.required]]
  id = "z-auxiliary"

[[rules]]
id = "z-auxiliary"
regex = '''AUX'''
skipReport = true
"#,
    );
    let control =
        ScanControl::unlimited().with_budget(ScanBudget::unlimited().max_finding_records(2));
    let outcome = engine.scan_fragment_controlled(
        &Fragment::new(b"PRIMARY AUX"),
        &ScanOptions::default(),
        &control,
    );

    assert!(outcome.findings().is_empty());
    assert_eq!(outcome.usage().finding_records(), 2);
    assert!(matches!(
        outcome.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::FindingRecords,
            limit: 2,
            consumed: 2,
            requested: 1,
        })
    ));
}

#[test]
fn cancellation_is_observed_before_allocation_and_between_rules() {
    let engine = two_rule_engine();
    let already_cancelled = AtomicBool::new(true);
    let immediate = engine.scan_fragment_controlled(
        &Fragment::new(b"A B"),
        &ScanOptions::default(),
        &ScanControl::cancellable(&already_cancelled),
    );
    assert_eq!(immediate.termination(), Some(&ScanTermination::Cancelled));
    assert_eq!(immediate.usage().work_units(), 0);
    assert!(immediate.findings().is_empty());
    let complete_empty = engine.scan_fragment(
        &Fragment::new(b"no configured match"),
        &ScanOptions::default(),
    );
    assert!(complete_empty.findings().is_empty());
    assert_ne!(immediate, complete_empty);

    let polls = AtomicUsize::new(0);
    let cancel_after_first_rule = || polls.fetch_add(1, Ordering::SeqCst) >= 5;
    let controlled = ScanControl::cancellable(&cancel_after_first_rule);
    let partial = engine.scan_fragment_controlled(
        &Fragment::new(b"A B"),
        &ScanOptions::default(),
        &controlled,
    );
    assert_eq!(partial.termination(), Some(&ScanTermination::Cancelled));
    assert_eq!(partial.findings().len(), 1);
    assert_eq!(partial.findings()[0].rule_id().as_bytes(), b"a-first");
}
