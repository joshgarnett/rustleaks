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

#[test]
fn completed_rule_prefixes_preserve_session_filters_duplicates_and_merge_order() {
    use rustleaks_core::session::{
        Baseline, IgnoreSet, ScanSession, SessionPolicy, global_fingerprint,
        sort_findings_canonical,
    };
    let engine = two_rule_engine();
    let outcomes: Vec<_> = (0..3)
        .map(|index| {
            let fragment = Fragment::builder(b"A B".to_vec())
                .file_path(format!("source-{index}"))
                .build();
            let control = ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_finding_records(1));
            let outcome =
                engine.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
            assert!(!outcome.is_complete());
            assert_eq!(outcome.findings().len(), 1);
            assert_eq!(outcome.findings()[0].rule_id().as_bytes(), b"a-first");
            outcome
        })
        .collect();
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for ignore in [false, true] {
        for baseline in [false, true] {
            let mut builder = SessionPolicy::builder();
            if ignore {
                let fingerprint = global_fingerprint(&outcomes[1].findings()[0]);
                builder =
                    builder.ignores(IgnoreSet::parse_go_compatible(fingerprint.as_bytes()).ignores);
            }
            if baseline {
                builder = builder.baseline(Baseline::from_findings(outcomes[2].findings()));
            }
            let policy = builder.build();
            let mut expected = Vec::new();
            for (index, outcome) in outcomes.iter().enumerate() {
                if (ignore && index == 1) || (baseline && index == 2) {
                    continue;
                }
                let finding = policy
                    .classify(outcome.findings()[0].clone())
                    .into_parts()
                    .0;
                expected.extend([finding.clone(), finding]);
            }
            sort_findings_canonical(&mut expected);
            for insertion in permutations {
                for merge in permutations {
                    let mut batches: Vec<_> = (0..3).map(|_| policy.new_batch()).collect();
                    for index in insertion {
                        for batch in [index, (index + 1) % 3] {
                            batches[batch].add_finding(outcomes[index].findings()[0].clone());
                        }
                    }
                    let mut session = ScanSession::new(policy.clone());
                    for index in merge {
                        session.merge(batches[index].clone()).unwrap();
                    }
                    // An equal-valued policy is still a distinct session identity.
                    let before = session.snapshot();
                    let mut foreign = SessionPolicy::default().new_batch();
                    foreign.add_finding(outcomes[0].findings()[0].clone());
                    assert!(session.merge(foreign).is_err());
                    assert_eq!(session.findings(), before);
                    let mut actual = session.into_findings();
                    sort_findings_canonical(&mut actual);
                    assert_eq!(actual, expected);
                }
            }
        }
    }
}

#[test]
fn nested_decode_cancellation_and_zero_combined_budgets_are_explicit() {
    let engine = engine(
        r#"
[[rules]]
id = "decoded"
regex = '''secret=(decoded-secret)'''
secretGroup = 1
keywords = ["secret"]
"#,
    );
    let fragment = Fragment::new(b"c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFE9");
    let options = ScanOptions::builder().max_decode_depth(2).build();
    let complete = engine.scan_fragment(&fragment, &options);
    assert_eq!(complete.findings().len(), 1);
    let mut cancelled = 0;
    let mut cancelled_after_decode = 0;
    for after in (0..complete.usage().work_units() + 4).chain(std::iter::once(usize::MAX)) {
        let polls = AtomicUsize::new(0);
        let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= after;
        let control = ScanControl::cancellable(&cancel);
        let outcome = engine.scan_fragment_controlled(&fragment, &options, &control);
        if outcome.is_complete() {
            assert_eq!(outcome, complete);
        } else {
            cancelled += 1;
            if outcome.usage().decoded_bytes() > 0 {
                cancelled_after_decode += 1;
            }
            assert_eq!(outcome.termination(), Some(&ScanTermination::Cancelled));
            assert!(outcome.findings().is_empty());
        }
    }
    assert!(cancelled > 0 && cancelled_after_decode > 0);
    let zero = ScanBudget::unlimited()
        .max_decoded_bytes(0)
        .max_work_units(0)
        .max_finding_records(0);
    let outcome = engine.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(zero),
    );
    assert!(outcome.findings().is_empty());
    assert_eq!(outcome.usage().work_units(), 0);
    assert!(matches!(
        outcome.termination(),
        Some(ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::WorkUnits,
            limit: 0,
            consumed: 0,
            ..
        })
    ));
    let cancel = AtomicBool::new(true);
    let outcome = engine.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::cancellable(&cancel).with_budget(zero),
    );
    assert_eq!(outcome.termination(), Some(&ScanTermination::Cancelled));
}
