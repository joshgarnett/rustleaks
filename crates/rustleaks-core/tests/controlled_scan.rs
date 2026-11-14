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

const DOUBLE_ENCODED_TOKEN: &[u8] = b"ZEc5clpXNDlRVUpEUkVWR1IwaEpTa3RNVFU1UFVBPT0=";

fn double_encoded_token_engine() -> Engine {
    engine(
        r#"
[[rules]]
id = "token"
regex = '''token=([A-Z]{16})'''
secretGroup = 1
keywords = ["token"]
"#,
    )
}

/// One `k=<token encoded twice>` line per finding, so depth two decodes
/// `lines` candidates against `lines` predecessors.
fn double_encoded_lines(lines: usize) -> Fragment {
    let mut input = Vec::new();
    for _ in 0..lines {
        input.extend_from_slice(b"k=");
        input.extend_from_slice(DOUBLE_ENCODED_TOKEN);
        input.push(b'\n');
    }
    Fragment::new(input)
}

/// Work from the documented decoder checkpoints for depth two with `lines`
/// lines and more than one match per pass: `lines * lines` predecessor visits
/// plus `10 * lines + 6` units for matches, candidates, segments, and passes.
const fn double_encoded_work(lines: usize) -> usize {
    lines * lines + 10 * lines + 6
}

#[test]
fn predecessor_charging_matches_a_per_unit_signal_at_every_budget() {
    let engine = double_encoded_token_engine();
    let options = ScanOptions::builder().max_decode_depth(2).build();
    let never = || false;
    for lines in [2, 3] {
        let fragment = double_encoded_lines(lines);
        let total = double_encoded_work(lines);
        let complete =
            engine.scan_fragment_controlled(&fragment, &options, &ScanControl::unlimited());
        assert!(complete.is_complete());
        assert_eq!(complete.findings().len(), lines);
        assert_eq!(complete.usage().work_units(), total);

        for budget in 0..=total {
            let limited = ScanBudget::unlimited().max_work_units(budget);
            let plain = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::unlimited().with_budget(limited),
            );
            let polled = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::cancellable(&never).with_budget(limited),
            );
            assert_eq!(plain.usage(), polled.usage(), "budget {budget}");
            assert_eq!(plain.termination(), polled.termination(), "budget {budget}");
            assert_eq!(plain.findings(), polled.findings(), "budget {budget}");
            if budget < total {
                assert_eq!(plain.usage().work_units(), budget, "budget {budget}");
                assert!(matches!(
                    plain.termination(),
                    Some(ScanTermination::BudgetExceeded {
                        kind: ScanBudgetKind::WorkUnits,
                        limit,
                        consumed,
                        requested: 1,
                    }) if *limit == budget && *consumed == budget
                ));
            } else {
                assert!(plain.is_complete());
            }
        }
    }
}

#[test]
fn predecessor_visits_poll_cancellation_once_per_work_unit() {
    let engine = double_encoded_token_engine();
    let options = ScanOptions::builder().max_decode_depth(2).build();
    for lines in [2, 3, 4, 5] {
        let polls = AtomicUsize::new(0);
        let count_polls = || {
            polls.fetch_add(1, Ordering::SeqCst);
            false
        };
        let outcome = engine.scan_fragment_controlled(
            &double_encoded_lines(lines),
            &options,
            &ScanControl::cancellable(&count_polls),
        );
        assert!(outcome.is_complete());
        // Polls beyond one per work unit: the initial check, two post-decode
        // checks, two decoded-byte charges, and per finding one record charge
        // and one final-filter check.
        assert_eq!(
            polls.load(Ordering::SeqCst),
            double_encoded_work(lines) + 5 + 2 * lines,
            "{lines} lines"
        );
    }
}

fn bounded_outcome(
    engine: &Engine,
    fragment: &Fragment,
    options: &ScanOptions,
    budget: ScanBudget,
) -> rustleaks_core::ScanOutcome {
    engine.scan_fragment_controlled(
        fragment,
        options,
        &ScanControl::unlimited().with_budget(budget),
    )
}

#[test]
fn finding_payload_is_admitted_before_long_line_copies_with_inclusive_limits() {
    let engine = engine("[[rules]]\nid = 'r'\nregex = 'X'\n");
    let mut bytes = vec![b'.'; 32_768];
    bytes.extend_from_slice(b"X X X");
    let fragment = Fragment::new(bytes);
    // Each record owns the 32,773-byte physical line, one-byte rule ID,
    // one-byte match and one-byte secret. No descriptions or metadata exist.
    let per_record = 32_776;
    for maximum in [3 * per_record, 3 * per_record + 1] {
        let outcome = bounded_outcome(
            &engine,
            &fragment,
            &ScanOptions::default(),
            ScanBudget::unlimited().max_finding_payload_bytes(maximum),
        );
        assert!(outcome.is_complete());
        assert_eq!(outcome.findings().len(), 3);
        assert_eq!(outcome.usage().finding_payload_bytes(), 3 * per_record);
        assert_eq!(outcome.usage().finding_records(), 3);
    }
    let partial = bounded_outcome(
        &engine,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_finding_payload_bytes(3 * per_record - 1),
    );
    assert!(partial.findings().is_empty());
    assert_eq!(partial.usage().finding_records(), 2);
    assert_eq!(partial.usage().finding_payload_bytes(), 2 * per_record);
    assert_eq!(
        partial.termination(),
        Some(&ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::FindingPayloadBytes,
            limit: 3 * per_record - 1,
            consumed: 2 * per_record,
            requested: per_record,
        })
    );
}

#[test]
fn finding_payload_includes_paths_tags_and_commit_fields() {
    use rustleaks_core::model::CommitMetadata;
    let engine =
        engine("[[rules]]\nid = 'r'\ndescription = 'desc'\nregex = 'X'\ntags = ['one', 'two']\n");
    let fragment = Fragment::builder("X")
        .file_path("file")
        .symlink_file("link")
        .commit("sha")
        .commit_metadata(
            CommitMetadata::builder()
                .sha("not-copied")
                .author_name("author")
                .author_email("email")
                .date("date")
                .message("message")
                .build(),
        )
        .build();
    // ID + description + three X fields + paths + commit + tags + metadata.
    let payload = 1 + 4 + 3 + 4 + 4 + 3 + 6 + 6 + 5 + 4 + 7;
    let exact = bounded_outcome(
        &engine,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_finding_payload_bytes(payload),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.findings().len(), 1);
    assert_eq!(exact.usage().finding_payload_bytes(), payload);
    let partial = bounded_outcome(
        &engine,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_finding_payload_bytes(payload - 1),
    );
    assert_eq!(partial.usage().finding_payload_bytes(), 0);
    assert_eq!(partial.usage().finding_records(), 0);
    assert!(!partial.is_complete());
}

#[test]
fn path_only_findings_and_required_projections_admit_payload() {
    let path_engine = engine("[[rules]]\nid = 'r'\npath = 'file'\n");
    let fragment = Fragment::builder("").file_path("file").build();
    // Rule ID, file path, and match text "file detected: file".
    let payload = 1 + 4 + 15 + 4;
    for maximum in [payload - 1, payload, payload + 1] {
        let outcome = bounded_outcome(
            &path_engine,
            &fragment,
            &ScanOptions::default(),
            ScanBudget::unlimited().max_finding_payload_bytes(maximum),
        );
        assert_eq!(outcome.is_complete(), maximum >= payload);
        assert_eq!(
            outcome.usage().finding_records(),
            usize::from(maximum >= payload)
        );
        assert_eq!(
            outcome.usage().finding_payload_bytes(),
            if maximum >= payload { payload } else { 0 }
        );
    }

    let composite = engine(
        "[[rules]]\nid = 'p'\nregex = 'P'\n[[rules.required]]\nid = 'a'\n[[rules]]\nid = 'a'\nregex = 'A'\nskipReport = true\n",
    );
    let fragment = Fragment::new("P A");
    // Primary and auxiliary each own 1 + 3 + 1 + 1 bytes; projection owns
    // another identical six bytes. Discarded auxiliary records still count.
    let exact = bounded_outcome(
        &composite,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_finding_payload_bytes(18),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.findings().len(), 1);
    assert_eq!(exact.findings()[0].required_findings().len(), 1);
    assert_eq!(exact.usage().finding_payload_bytes(), 18);
    assert_eq!(exact.usage().finding_records(), 3);
    let partial = bounded_outcome(
        &composite,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_finding_payload_bytes(17),
    );
    assert!(partial.findings().is_empty());
    assert_eq!(partial.usage().finding_records(), 2);
    assert_eq!(
        partial.termination(),
        Some(&ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::FindingPayloadBytes,
            limit: 17,
            consumed: 12,
            requested: 6,
        })
    );
}

#[test]
fn collected_spans_bound_dense_and_empty_matches_before_candidate_work() {
    for (pattern, bytes, count) in [("X", "XXX", 3), ("(?:)", "abc", 4)] {
        let engine = engine(&format!("[[rules]]\nid = 'r'\nregex = '{pattern}'\n"));
        let fragment = Fragment::new(bytes);
        for maximum in [count - 1, count, count + 1] {
            let outcome = bounded_outcome(
                &engine,
                &fragment,
                &ScanOptions::default(),
                ScanBudget::unlimited().max_collected_spans(maximum),
            );
            assert_eq!(outcome.is_complete(), maximum >= count);
            assert_eq!(outcome.usage().collected_spans(), maximum.min(count));
            if maximum < count {
                assert_eq!(outcome.usage().work_units(), 2);
                assert_eq!(outcome.usage().finding_records(), 0);
                assert_eq!(
                    outcome.termination(),
                    Some(&ScanTermination::BudgetExceeded {
                        kind: ScanBudgetKind::CollectedSpans,
                        limit: maximum,
                        consumed: maximum,
                        requested: 1,
                    })
                );
            }
        }
    }
}

#[test]
fn bounded_enumeration_preserves_keyword_anchor_results_and_cancels_between_spans() {
    let anchored = engine("[[rules]]\nid = 'r'\nregex = 'token=[A-Z]{4}'\nkeywords = ['token']\n");
    let fragment = Fragment::new("token=ABCD token=EFGH token=IJKL");
    let legacy = anchored.scan_fragment(&fragment, &ScanOptions::default());
    let exact = bounded_outcome(
        &anchored,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_collected_spans(3),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.findings(), legacy.findings());
    assert_eq!(exact.usage().work_units(), legacy.usage().work_units());
    assert_eq!(exact.usage().collected_spans(), 3);
    let partial = bounded_outcome(
        &anchored,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_collected_spans(2),
    );
    assert!(!partial.is_complete());
    assert_eq!(partial.usage().collected_spans(), 2);

    let dense = engine("[[rules]]\nid = 'r'\nregex = 'X'\n");
    let polls = AtomicUsize::new(0);
    // Initial, pass, rule, first-span polls succeed; second-span poll cancels.
    let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= 4;
    let control = ScanControl::cancellable(&cancel)
        .with_budget(ScanBudget::unlimited().max_collected_spans(3));
    let cancelled =
        dense.scan_fragment_controlled(&Fragment::new("XXX"), &ScanOptions::default(), &control);
    assert_eq!(cancelled.termination(), Some(&ScanTermination::Cancelled));
    assert_eq!(cancelled.usage().collected_spans(), 1);
    assert_eq!(cancelled.usage().work_units(), 2);
    assert_eq!(cancelled.usage().finding_records(), 0);
}

#[test]
fn decoder_candidate_enumeration_shares_the_cumulative_span_limit() {
    let engine = engine("[[rules]]\nid = 'r'\nregex = 'NEVER'\n");
    let fragment = Fragment::new("YWJjZGVmZ2hpamts\nYWJjZGVmZ2hpamts\n");
    let options = ScanOptions::builder().max_decode_depth(1).build();
    for maximum in [1, 2, 3] {
        let outcome = bounded_outcome(
            &engine,
            &fragment,
            &options,
            ScanBudget::unlimited().max_collected_spans(maximum),
        );
        assert_eq!(outcome.is_complete(), maximum >= 2);
        assert_eq!(outcome.usage().collected_spans(), maximum.min(2));
        assert!(outcome.findings().is_empty());
        assert_eq!(
            outcome.usage().decoded_bytes(),
            if maximum >= 2 { 26 } else { 0 }
        );
        if maximum == 1 {
            assert_eq!(outcome.usage().work_units(), 3);
            assert_eq!(
                outcome.termination(),
                Some(&ScanTermination::BudgetExceeded {
                    kind: ScanBudgetKind::CollectedSpans,
                    limit: 1,
                    consumed: 1,
                    requested: 1,
                })
            );
        }
    }
}

#[test]
fn decoded_finding_payload_charges_original_line_and_generated_tags() {
    let engine = engine("[[rules]]\nid = 'r'\nregex = 'abcdefghijkl'\n");
    let fragment = Fragment::new("YWJjZGVmZ2hpamts");
    let options = ScanOptions::builder().max_decode_depth(1).build();
    // Rule ID + encoded source line + decoded match/secret + two tags.
    let payload = 1 + 16 + 12 + 12 + 14 + 14;
    for maximum in [payload - 1, payload, payload + 1] {
        let outcome = bounded_outcome(
            &engine,
            &fragment,
            &options,
            ScanBudget::unlimited().max_finding_payload_bytes(maximum),
        );
        assert_eq!(outcome.is_complete(), maximum >= payload);
        assert_eq!(
            outcome.usage().finding_payload_bytes(),
            if maximum >= payload { payload } else { 0 }
        );
        assert_eq!(
            outcome.usage().finding_records(),
            usize::from(maximum >= payload)
        );
        if maximum >= payload {
            assert_eq!(outcome.findings()[0].secret().as_bytes(), b"abcdefghijkl");
        }
    }
}

#[test]
fn normalization_limits_admit_invalid_byte_amplification_before_allocation() {
    let engine = engine("[[rules]]\nid = 'r'\nregex = 'Z'\n");
    let fragment = Fragment::new(vec![0xff; 4_096]);
    // Each invalid source byte creates three normalized bytes and one offset.
    let payload = (3 + std::mem::size_of::<usize>()) * 4_096;
    for maximum in [payload - 1, payload, payload + 1] {
        let outcome = bounded_outcome(
            &engine,
            &fragment,
            &ScanOptions::default(),
            ScanBudget::unlimited().max_normalization_bytes(maximum),
        );
        assert_eq!(outcome.is_complete(), maximum >= payload);
        assert!(outcome.findings().is_empty());
        assert_eq!(
            outcome.usage().normalization_bytes(),
            if maximum >= payload { payload } else { 0 }
        );
        if maximum < payload {
            assert_eq!(
                outcome.termination(),
                Some(&ScanTermination::BudgetExceeded {
                    kind: ScanBudgetKind::NormalizationBytes,
                    limit: maximum,
                    consumed: 0,
                    requested: payload,
                })
            );
        }
    }
    let borrowed = bounded_outcome(
        &engine,
        &Fragment::new("valid UTF-8 é"),
        &ScanOptions::default(),
        ScanBudget::unlimited().max_normalization_bytes(0),
    );
    assert!(borrowed.is_complete());
    assert_eq!(borrowed.usage().normalization_bytes(), 0);
}

#[test]
fn normalization_usage_includes_capture_allowlist_path_and_decoder_searches() {
    let unit = 3 + std::mem::size_of::<usize>();
    let capture = engine("[[rules]]\nid = 'r'\nregex = '(.)'\n");
    let fragment = Fragment::new(b"\xff");
    let exact = bounded_outcome(
        &capture,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_normalization_bytes(2 * unit),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.findings()[0].secret().as_bytes(), b"\xff");
    assert_eq!(exact.usage().normalization_bytes(), 2 * unit);
    let partial = bounded_outcome(
        &capture,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_normalization_bytes(unit),
    );
    assert_eq!(partial.usage().finding_records(), 0);
    assert_eq!(
        partial.termination(),
        Some(&ScanTermination::BudgetExceeded {
            kind: ScanBudgetKind::NormalizationBytes,
            limit: unit,
            consumed: unit,
            requested: unit,
        })
    );

    let line = engine(
        "[[rules]]\nid = 'r'\nregex = 'X'\n[[rules.allowlists]]\nregexTarget = 'line'\nregexes = ['NEVER']\n",
    );
    let fragment = Fragment::new(b"\xffX");
    let exact = bounded_outcome(
        &line,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_normalization_bytes(2 * (unit + 1)),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.usage().normalization_bytes(), 2 * (unit + 1));

    let path = engine("[[rules]]\nid = 'r'\npath = 'X'\n");
    let fragment = Fragment::builder("").file_path(b"\xffX").build();
    let exact = bounded_outcome(
        &path,
        &fragment,
        &ScanOptions::default(),
        ScanBudget::unlimited().max_normalization_bytes(unit + 1),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.usage().normalization_bytes(), unit + 1);

    let decoder = engine("[[rules]]\nid = 'r'\nregex = 'NEVER'\n");
    let exact = bounded_outcome(
        &decoder,
        &Fragment::new(b"\xff"),
        &ScanOptions::builder().max_decode_depth(1).build(),
        ScanBudget::unlimited().max_normalization_bytes(2 * unit),
    );
    assert!(exact.is_complete());
    assert_eq!(exact.usage().normalization_bytes(), 2 * unit);
}

fn owned_finding_fields(finding: &rustleaks_core::model::Finding) -> usize {
    [
        finding.rule_id(),
        finding.description(),
        finding.line(),
        finding.match_text(),
        finding.secret(),
        finding.file(),
        finding.symlink_file(),
        finding.commit(),
        finding.link(),
        finding.author(),
        finding.email(),
        finding.date(),
        finding.message(),
        finding.fingerprint(),
    ]
    .into_iter()
    .map(rustleaks_core::model::ByteText::len)
    .chain(
        finding
            .tags()
            .iter()
            .map(rustleaks_core::model::ByteText::len),
    )
    .chain(finding.required_findings().iter().flat_map(|required| {
        [
            required.rule_id().len(),
            required.line().len(),
            required.match_text().len(),
            required.secret().len(),
        ]
    }))
    .sum()
}

#[test]
fn redaction_and_session_retained_fields_obey_the_conservative_payload_bound() {
    use rustleaks_core::session::SessionPolicy;
    let decimal_digits = usize::MAX.to_string().len();
    for pattern in ["(?:)", "X", "(X?)"] {
        let engine = engine(&format!("[[rules]]\nid = 'r'\nregex = '{pattern}'\n"));
        for raw in [b"XXX".as_slice(), b"\xffX", "éX".as_bytes(), b""] {
            let fragment = Fragment::builder(raw)
                .file_path("path")
                .commit("commit")
                .build();
            for percent in [1, 50, 99, 100, 150] {
                let outcome = bounded_outcome(
                    &engine,
                    &fragment,
                    &ScanOptions::builder().redaction_percent(percent).build(),
                    ScanBudget::unlimited()
                        .max_finding_payload_bytes(1_024)
                        .max_finding_records(16),
                );
                assert!(outcome.is_complete());
                let payload = outcome.usage().finding_payload_bytes();
                let records = outcome.usage().finding_records();
                let redacted: usize = outcome.findings().iter().map(owned_finding_fields).sum();
                assert!(redacted <= 9 * payload + 24 * records);
                let mut batch = SessionPolicy::default().new_batch();
                for finding in outcome.into_findings() {
                    batch.add_finding(finding);
                }
                let classified: usize = batch.findings().iter().map(owned_finding_fields).sum();
                assert!(classified <= 10 * payload + (decimal_digits + 27) * records);
            }
        }
    }
    // Empty-secret full redaction inserts eight bytes at every rune boundary.
    // Four empty matches each retain: rule ID 1, line 35, match 8, secret 8.
    let empty = engine("[[rules]]\nid = 'r'\nregex = '(?:)'\n");
    let outcome = bounded_outcome(
        &empty,
        &Fragment::new("XXX"),
        &ScanOptions::builder().redaction_percent(100).build(),
        ScanBudget::unlimited().max_finding_payload_bytes(16),
    );
    assert!(outcome.is_complete());
    assert_eq!(outcome.usage().finding_payload_bytes(), 16);
    assert_eq!(outcome.usage().finding_records(), 4);
    assert_eq!(
        outcome
            .findings()
            .iter()
            .map(owned_finding_fields)
            .sum::<usize>(),
        208
    );
}
