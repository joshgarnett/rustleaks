//! Deterministic budget, publication, and ownership contracts for small scans.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine as _;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Finding, Fragment, Location, ScanOptions};
use rustleaks_core::session::{
    Baseline, IgnoreSet, PolicyMismatch, ScanSession, SessionPolicy, SuppressionReason,
};
use rustleaks_core::{
    Engine, ScanBudget, ScanBudgetKind, ScanControl, ScanOutcome, ScanTermination,
};

fn engine(config: &str) -> Engine {
    Engine::builder(ConfigLoader::new().load_toml(config).unwrap())
        .build()
        .unwrap()
}

fn transaction_engine() -> Engine {
    engine(
        r#"
[[rules]]
id = "a-first"
regex = '''A'''
[[rules]]
id = "b-middle"
regex = '''B'''
[[rules]]
id = "c-last"
regex = '''C'''
"#,
    )
}

fn assert_exceeded(
    outcome: &ScanOutcome,
    kind: ScanBudgetKind,
    limit: usize,
    consumed: usize,
    requested: usize,
) {
    assert!(!outcome.is_complete());
    assert_eq!(
        outcome.termination(),
        Some(&ScanTermination::BudgetExceeded {
            kind,
            limit,
            consumed,
            requested,
        })
    );
}

fn assert_raw_prefix(outcome: &ScanOutcome, middle_count: usize, published: usize) {
    let mut expected = vec![(b"a-first".as_slice(), 0)];
    expected.extend((0..middle_count).map(|index| (b"b-middle".as_slice(), 2 + 2 * index)));
    expected.push((b"c-last".as_slice(), 2 + 2 * middle_count));
    assert_eq!(outcome.findings().len(), published);
    for (finding, (rule_id, offset)) in outcome.findings().iter().zip(expected) {
        assert_eq!(finding.rule_id().as_bytes(), rule_id);
        assert_eq!(
            finding.match_range().exact().unwrap().as_range(),
            offset..offset + 1
        );
        assert_eq!(finding.secret_range(), finding.match_range());
    }
}

#[test]
fn every_small_work_boundary_publishes_only_completed_rules() {
    let engine = transaction_engine();
    for middle_count in 1..=4 {
        let fragment = Fragment::new(format!("A {}C", "B ".repeat(middle_count)));
        // One pass, three rule entries, and middle_count + 2 match candidates.
        let total_work = middle_count + 6;
        for limit in 0..=total_work + 1 {
            let control = ScanControl::unlimited().with_budget(
                ScanBudget::unlimited()
                    .max_work_units(limit)
                    .max_finding_records(middle_count + 2)
                    .max_decoded_bytes(0),
            );
            let outcome =
                engine.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
            let published = if limit >= total_work {
                middle_count + 2
            } else if limit >= middle_count + 4 {
                middle_count + 1
            } else {
                usize::from(limit >= 3)
            };
            let admitted = usize::from(limit >= 3)
                + limit.saturating_sub(4).min(middle_count)
                + usize::from(limit >= total_work);
            assert_raw_prefix(&outcome, middle_count, published);
            assert_eq!(outcome.usage().work_units(), limit.min(total_work));
            assert_eq!(outcome.usage().finding_records(), admitted);
            assert_eq!(outcome.usage().decoded_bytes(), 0);
            if limit < total_work {
                assert_exceeded(&outcome, ScanBudgetKind::WorkUnits, limit, limit, 1);
            } else {
                assert!(outcome.is_complete());
                assert_eq!(outcome.termination(), None);
            }
        }
    }
}

#[test]
fn every_small_record_boundary_retains_charges_but_rolls_back_unfinished_rules() {
    let engine = transaction_engine();
    for middle_count in 1..=4 {
        let fragment = Fragment::new(format!("A {}C", "B ".repeat(middle_count)));
        let total_records = middle_count + 2;
        for limit in 0..=total_records + 1 {
            let control = ScanControl::unlimited().with_budget(
                ScanBudget::unlimited()
                    .max_finding_records(limit)
                    .max_work_units(middle_count + 6)
                    .max_decoded_bytes(0),
            );
            let outcome =
                engine.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
            let (published, work) = if limit >= total_records {
                (total_records, middle_count + 6)
            } else if limit == total_records - 1 {
                (total_records - 1, middle_count + 6)
            } else if limit == 0 {
                (0, 3)
            } else {
                (1, limit + 4)
            };
            assert_raw_prefix(&outcome, middle_count, published);
            assert_eq!(outcome.usage().work_units(), work);
            assert_eq!(outcome.usage().finding_records(), limit.min(total_records));
            assert_eq!(outcome.usage().decoded_bytes(), 0);
            if limit < total_records {
                assert_exceeded(&outcome, ScanBudgetKind::FindingRecords, limit, limit, 1);
            } else {
                assert!(outcome.is_complete());
                assert_eq!(outcome.termination(), None);
            }
        }
    }
}

#[test]
fn empty_matches_keep_invalid_byte_progression_and_budget_charges() {
    let engine = engine("[[rules]]\nid = 'empty'\nregex = 'a*'");
    let raw = b"\xffaaa\x80";
    let fragment = Fragment::new(raw);
    let options = ScanOptions::default();
    // Each invalid byte is one rune. The empty match at 4 is suppressed
    // because it abuts 1..4; advancing over the final invalid byte reaches 5.
    // One pass, one rule and three candidates consume exactly five work units.
    let complete = engine.scan_fragment_controlled(
        &fragment,
        &options,
        &ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_work_units(5)
                .max_finding_records(3)
                .max_decoded_bytes(0),
        ),
    );
    assert!(complete.is_complete());
    assert_eq!(complete.termination(), None);
    assert_eq!(complete.usage().work_units(), 5);
    assert_eq!(complete.usage().finding_records(), 3);
    assert_eq!(complete.usage().decoded_bytes(), 0);
    assert_eq!(complete.findings().len(), 3);
    for (finding, (range, coordinates)) in complete.findings().iter().zip([
        (0..0, (0, 0, 1, 0)),
        (1..4, (0, 0, 2, 4)),
        (5..5, (1, 1, 1, 0)),
    ]) {
        assert_eq!(finding.rule_id().as_bytes(), b"empty");
        assert_eq!(finding.match_range().exact().unwrap().as_range(), range);
        assert_eq!(finding.secret_range(), finding.match_range());
        assert_eq!(finding.match_text().as_bytes(), &raw[range.clone()]);
        assert_eq!(finding.secret().as_bytes(), &raw[range]);
        assert_eq!(finding.line().as_bytes(), raw);
        assert_eq!(finding.entropy().to_bits(), 0);
        let location = finding.location();
        assert_eq!(
            (
                location.start_line(),
                location.end_line(),
                location.start_column(),
                location.end_column(),
            ),
            coordinates,
        );
    }

    for (work_limit, record_limit, kind, limit, charged_work) in [
        (4, 3, ScanBudgetKind::WorkUnits, 4, 4),
        (5, 2, ScanBudgetKind::FindingRecords, 2, 5),
    ] {
        let control = ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_work_units(work_limit)
                .max_finding_records(record_limit)
                .max_decoded_bytes(0),
        );
        let partial = engine.scan_fragment_controlled(&fragment, &options, &control);
        assert_exceeded(&partial, kind, limit, limit, 1);
        assert!(partial.findings().is_empty());
        assert_eq!(partial.usage().work_units(), charged_work);
        assert_eq!(partial.usage().finding_records(), 2);
        assert_eq!(partial.usage().decoded_bytes(), 0);
    }
}

#[test]
fn nested_decode_limits_charge_whole_passes_before_scanning_them() {
    let engine = engine("[[rules]]\nid = 'decoded'\nregex = 'marker=VALUE'");
    for padding in 0..=3 {
        let plain = format!("{} marker=VALUE", " ".repeat(padding));
        let inner = base64::engine::general_purpose::STANDARD.encode(plain.as_bytes());
        let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let fragment = Fragment::new(outer);
        let total_bytes = inner.len() + plain.len();
        let options = ScanOptions::builder().max_decode_depth(2).build();
        for limit in [
            0,
            inner.len() - 1,
            inner.len(),
            total_bytes - 1,
            total_bytes,
            total_bytes + 1,
        ] {
            let control = ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_decoded_bytes(limit));
            let outcome = engine.scan_fragment_controlled(&fragment, &options, &control);
            if limit < inner.len() {
                assert_exceeded(
                    &outcome,
                    ScanBudgetKind::DecodedBytes,
                    limit,
                    0,
                    inner.len(),
                );
                assert_eq!(outcome.usage().decoded_bytes(), 0);
                assert_eq!(outcome.usage().finding_records(), 0);
                assert!(outcome.findings().is_empty());
            } else if limit < total_bytes {
                assert_exceeded(
                    &outcome,
                    ScanBudgetKind::DecodedBytes,
                    limit,
                    inner.len(),
                    plain.len(),
                );
                assert_eq!(outcome.usage().decoded_bytes(), inner.len());
                assert_eq!(outcome.usage().finding_records(), 0);
                assert!(outcome.findings().is_empty());
            } else {
                assert!(outcome.is_complete());
                assert_eq!(outcome.termination(), None);
                assert_eq!(outcome.usage().decoded_bytes(), total_bytes);
                assert_eq!(outcome.usage().finding_records(), 1);
                assert_eq!(outcome.findings().len(), 1);
                assert_eq!(outcome.findings()[0].secret().as_bytes(), b"marker=VALUE");
            }
        }
    }
}

#[test]
fn completeness_distinguishes_outcomes_with_identical_findings_and_usage() {
    let engine = engine(
        r#"
[[rules]]
id = "a-specific"
regex = '''A'''
[[rules]]
id = "z-generic"
regex = '''A'''
"#,
    );
    let fragment = Fragment::new(b"A");
    let options = ScanOptions::default();
    let complete = engine.scan_fragment(&fragment, &options);
    assert_eq!(complete.findings().len(), 1);
    assert_eq!(complete.findings()[0].rule_id().as_bytes(), b"a-specific");
    assert_eq!(complete.usage().work_units(), 5);
    assert_eq!(complete.usage().finding_records(), 2);
    // Final filtering can stop after retaining the specific finding and before
    // suppressing the generic finding. That prefix has the complete findings
    // and usage but a different termination. Poll counts are not an API promise;
    // this bounded search leaves headroom for extra polls in this tiny fixture.
    let partial = (0..64)
        .find_map(|threshold| {
            let polls = AtomicUsize::new(0);
            let cancel = || polls.fetch_add(1, Ordering::SeqCst) >= threshold;
            let candidate = engine.scan_fragment_controlled(
                &fragment,
                &options,
                &ScanControl::cancellable(&cancel),
            );
            (candidate.termination() == Some(&ScanTermination::Cancelled)
                && candidate.findings() == complete.findings()
                && candidate.usage() == complete.usage())
            .then_some(candidate)
        })
        .expect("cancellation during final filtering must expose the finalized specific finding");
    assert_eq!(partial.findings(), complete.findings());
    assert_eq!(partial.usage(), complete.usage());
    assert!(complete.is_complete());
    assert!(!partial.is_complete());
    assert_eq!(partial.termination(), Some(&ScanTermination::Cancelled));
    assert_ne!(partial, complete);
}

#[test]
fn reused_control_resets_usage_and_observes_the_current_cancellation_signal() {
    let engine = transaction_engine();
    let cancelled = AtomicBool::new(false);
    let control = ScanControl::cancellable(&cancelled).with_budget(
        ScanBudget::unlimited()
            .max_work_units(8)
            .max_finding_records(4),
    );
    let fragment = Fragment::new(b"A B B C");
    for _ in 0..3 {
        let complete =
            engine.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
        assert!(complete.is_complete());
        assert_raw_prefix(&complete, 2, 4);
        assert_eq!(complete.usage().work_units(), 8);
        assert_eq!(complete.usage().finding_records(), 4);

        let partial = engine.scan_fragment_controlled(
            &Fragment::new(b"B B B B B"),
            &ScanOptions::default(),
            &control,
        );
        assert_exceeded(&partial, ScanBudgetKind::FindingRecords, 4, 4, 1);
        assert_eq!(partial.usage().work_units(), 8);
        assert!(partial.findings().is_empty());

        cancelled.store(true, Ordering::Release);
        let stopped = engine.scan_fragment_controlled(&fragment, &ScanOptions::default(), &control);
        assert_eq!(stopped.termination(), Some(&ScanTermination::Cancelled));
        assert!(!stopped.is_complete());
        assert_eq!(stopped.usage().work_units(), 0);
        assert_eq!(stopped.usage().finding_records(), 0);
        assert!(stopped.findings().is_empty());
        cancelled.store(false, Ordering::Release);
    }
}

fn session_finding(line: usize) -> Finding {
    Finding::builder()
        .rule_id("state")
        .file("fixture.txt")
        .commit("commit-a")
        .secret("synthetic-value")
        .location(Location::new(line, line, 1, 15).unwrap())
        .build()
        .unwrap()
}

#[test]
fn interleaved_sessions_keep_policy_identity_and_owned_batches_isolated() {
    let policy = SessionPolicy::builder()
        .ignores(
            IgnoreSet::parse_go_compatible(b"fixture.txt:state:1\ncommit-a:fixture.txt:state:2")
                .ignores,
        )
        .baseline(Baseline::from_findings(&[session_finding(3)]))
        .build();
    let mut first = ScanSession::new(policy.clone());
    let mut second = ScanSession::new(policy.clone());
    let mut batch = first.new_batch();
    for (line, reason) in [
        (1, Some(SuppressionReason::GlobalIgnore)),
        (2, Some(SuppressionReason::CommitIgnore)),
        (3, Some(SuppressionReason::Baseline)),
        (4, None),
    ] {
        let outcome = batch.add_finding(session_finding(line));
        assert_eq!(outcome.suppression_reason(), reason);
        assert_eq!(
            outcome.fingerprint().as_bytes(),
            format!("commit-a:fixture.txt:state:{line}").as_bytes()
        );
        assert!(first.findings().is_empty());
        assert!(second.findings().is_empty());
    }
    let mut batch_clone = batch.clone();
    assert!(batch_clone.add_finding(session_finding(4)).is_accepted());
    assert_eq!(batch.findings().len(), 1);
    second.merge(batch_clone).unwrap();
    assert!(first.findings().is_empty());
    first.merge(batch).unwrap();
    assert_eq!(first.findings().len(), 1);
    assert_eq!(second.findings().len(), 2);
    assert_eq!(second.findings()[0], second.findings()[1]);

    let original = first.snapshot();
    let mut snapshot = first.snapshot();
    snapshot.clear();
    assert_eq!(first.findings(), original);
    let mut foreign = SessionPolicy::default().new_batch();
    assert!(foreign.add_finding(session_finding(1)).is_accepted());
    assert_eq!(first.merge(foreign), Err(PolicyMismatch));
    assert_eq!(first.findings(), original);
    assert_eq!(second.findings().len(), 2);
    let mut later = policy.new_batch();
    assert!(later.add_finding(session_finding(4)).is_accepted());
    first.merge(later).unwrap();
    assert_eq!(first.findings(), second.findings());
}
