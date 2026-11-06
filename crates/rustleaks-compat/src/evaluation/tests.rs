#![allow(clippy::float_cmp)] // Golden rates use exact, hand-calculated fractions.

use std::path::PathBuf;

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;

use super::model::{Case, Positive, Span, fingerprint};
use super::score::{Counts, Observation, Rates, score};
use super::{
    assess, check_generated_corpus, evaluate_corpus, generated_corpus, generator, json, model,
};

fn labeled_case() -> Case {
    Case {
        id: "hand-counted".into(),
        leakage_group: "hand-counted".into(),
        split: "holdout".into(),
        stratum: "metric-control".into(),
        rationale: "Explicitly hand-counted synthetic observation labels.".into(),
        input: b"..abc.....def.......unknown...".to_vec(),
        path: "settings.conf".into(),
        content_fnv1a64: fingerprint(b"..abc.....def.......unknown..."),
        selected_rules: vec!["alpha".into()],
        positives: vec![
            Positive {
                span: Span { start: 2, end: 5 },
                expected_secret: b"abc".to_vec(),
                family: "alpha".into(),
                rule_ids: vec!["alpha".into()],
            },
            Positive {
                span: Span { start: 10, end: 13 },
                expected_secret: b"def".to_vec(),
                family: "alpha".into(),
                rule_ids: vec!["alpha".into()],
            },
        ],
        negative_regions: vec![
            Span { start: 0, end: 2 },
            Span { start: 5, end: 10 },
            Span { start: 13, end: 20 },
            Span { start: 27, end: 30 },
        ],
        unknown_regions: vec![Span { start: 20, end: 27 }],
        decode_depth: 0,
        max_work_units: 100_000,
    }
}

fn observed(span: Option<(usize, usize)>, secret: &[u8], rule: &str) -> Observation {
    Observation {
        span: span.map(|(start, end)| Span { start, end }),
        secret: secret.to_vec(),
        rule: rule.into(),
    }
}

#[test]
fn golden_counts_keep_duplicates_unknown_values_and_locations_separate() {
    let case = labeled_case();
    let observations = [
        observed(Some((2, 5)), b"abc", "other"),
        observed(Some((2, 5)), b"abc", "other"),
        observed(Some((15, 18)), b"bad", "other"),
        observed(Some((20, 27)), b"unknown", "other"),
        observed(None, b"def", "alpha"),
        observed(Some((9, 13)), b"def", "alpha"),
    ];
    let result = score(&case, &observations);
    assert_eq!(
        result.counts,
        Counts {
            true_positives: 1,
            false_positives: 2,
            false_negatives: 1,
            duplicate_alerts: 1,
            attribution_mismatches: 1,
            location_mismatches: 1,
            unknown_alerts: 1,
            unlocated_alerts: 1,
            negative_false_alerts: 1,
            reviewed_negative_bytes: 17,
            unknown_bytes: 7,
            observed_alerts: 6,
            expected_case_distinct_values: 2,
            recognized_case_distinct_values: 2,
        }
    );
    assert_eq!(result.missing_positive_indices, [1]);
    let rates = Rates::from(result.counts);
    assert_eq!(rates.exact_span_precision, Some(1.0 / 3.0));
    assert_eq!(rates.exact_span_recall, Some(0.5));
    assert_eq!(rates.case_distinct_value_recall, Some(1.0));
    assert_eq!(rates.unknown_alert_fraction, Some(0.4));
}

#[test]
fn duplicate_rule_order_does_not_change_attribution_or_occurrence_count() {
    let case = labeled_case();
    let mut observations = vec![
        observed(Some((2, 5)), b"abc", "other"),
        observed(Some((2, 5)), b"abc", "alpha"),
    ];
    let before = score(&case, &observations).counts;
    observations.reverse();
    assert_eq!(score(&case, &observations).counts, before);
    assert_eq!(before.true_positives, 1);
    assert_eq!(before.duplicate_alerts, 1);
    assert_eq!(before.attribution_mismatches, 0);
}

#[test]
fn wrong_value_at_correct_span_is_not_a_true_positive() {
    let result = score(
        &labeled_case(),
        &[observed(Some((2, 5)), b"wrong", "alpha")],
    );
    assert_eq!(result.counts.true_positives, 0);
    assert_eq!(result.counts.false_positives, 1);
    assert_eq!(result.counts.false_negatives, 2);
}

#[test]
fn empty_denominators_are_undefined() {
    let rates = Rates::from(Counts::default());
    assert_eq!(rates.exact_span_precision, None);
    assert_eq!(rates.exact_span_recall, None);
    assert_eq!(rates.negative_false_alerts_per_mib, None);
    assert_eq!(rates.unknown_alert_fraction, None);
    assert_eq!(rates.case_distinct_value_recall, None);
}

fn engine(pattern: &str) -> Engine {
    let text = format!("[[rules]]\nid = 'alpha'\nregex = '''{pattern}'''\n");
    let config = ConfigLoader::new().load_toml(&text).unwrap();
    Engine::builder(config).build().unwrap()
}

#[test]
fn detector_mutations_change_true_false_and_missing_counts() {
    let case = labeled_case();
    let baseline = assess("baseline", &engine("abc|def"), [&case].into_iter(), None);
    assert_eq!(baseline.counts.true_positives, 2);
    assert_eq!(baseline.counts.false_positives, 0);
    let removed = assess("removed", &engine("NEVER"), [&case].into_iter(), None);
    assert_eq!(removed.counts.false_negatives, 2);
    let broadened = assess(
        "broadened",
        &engine("abc|def|\\.\\."),
        [&case].into_iter(),
        None,
    );
    assert!(broadened.counts.false_positives > baseline.counts.false_positives);
}

#[test]
fn incomplete_scans_cannot_appear_as_complete_clean_negatives() {
    let mut case = labeled_case();
    case.max_work_units = 0;
    let assessment = assess("limited", &engine("abc|def"), [&case].into_iter(), None);
    assert_eq!(assessment.status, "incomplete");
    assert_eq!(assessment.completed_cases, 0);
    assert_eq!(assessment.counts.false_negatives, 2);
    assert_eq!(assessment.cases[0].missing_positive_indices, [0, 1]);
    assert!(assessment.cases[0].termination.is_some());
    assert!(!assessment.cases[0].scan_complete);
}

#[test]
fn labels_and_provenance_cannot_silently_drift() {
    let generated = generated_corpus().unwrap();
    check_generated_corpus(&generated).unwrap();
    let mut corpus = model::parse(&generated).unwrap();
    corpus.cases[0].positives.clear();
    assert!(model::validate(&corpus).is_err());
    let mut corpus = model::parse(&generated).unwrap();
    corpus.cases[0].input.push(0);
    assert!(model::validate(&corpus).is_err());
    let mut corpus = model::parse(&generated).unwrap();
    corpus.cases[0].rationale.push_str(" changed");
    assert!(check_generated_corpus(&json(&corpus).unwrap()).is_err());
}

#[test]
fn template_families_and_duplicate_values_cannot_leak_across_splits() {
    let mut corpus = generator::corpus();
    corpus.cases[1].split = "tune".into();
    assert!(model::validate(&corpus).is_err());
    corpus.cases[1].leakage_group = "renamed-group".into();
    assert!(model::validate(&corpus).is_err());
}

#[test]
fn arbitrary_json_errors_do_not_echo_input_values() {
    let sentinel = b"{\"SECRET_SENTINEL\": \"SECRET_SENTINEL\"}";
    let error = evaluate_corpus(sentinel).unwrap_err();
    assert!(!error.contains("SECRET_SENTINEL"));
}

#[test]
fn committed_corpus_and_baseline_replay_exactly() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../compat/quality-corpus");
    let corpus = std::fs::read(root.join("cases-v1.json")).unwrap();
    check_generated_corpus(&corpus).unwrap();
    let baseline = evaluate_corpus(&corpus).unwrap();
    assert_eq!(
        std::fs::read(root.join("baseline-v1.json")).unwrap(),
        baseline
    );
    let report: serde_json::Value = serde_json::from_slice(&baseline).unwrap();
    assert_eq!(report["assessments"][0]["selection"], "all-default-rules");
    assert!(report["assessments"].as_array().unwrap().len() > 1);
    let rendered = String::from_utf8(baseline).unwrap();
    for case in model::parse(&corpus).unwrap().cases {
        for positive in case.positives {
            if let Ok(secret) = std::str::from_utf8(&positive.expected_secret) {
                assert!(
                    !rendered.contains(secret),
                    "report disclosed a synthetic value"
                );
            }
        }
    }
}

#[test]
fn individual_rule_denominators_exclude_unrelated_positive_families() {
    let mut case = labeled_case();
    case.positives[1].rule_ids = vec!["beta".into()];
    let assessment = assess("alpha", &engine("abc"), [&case].into_iter(), Some("alpha"));
    assert_eq!(assessment.counts.true_positives, 1);
    assert_eq!(assessment.counts.false_negatives, 0);
    assert_eq!(assessment.cases[0].scored_positive_indices, [0]);
    assert_eq!(assessment.counts.unknown_bytes, 10);
}

#[test]
fn changed_loaded_default_bytes_fail_identity_check() {
    let mut changed = rustleaks_core::config::DEFAULT_CONFIG_BYTES.to_vec();
    changed[0] ^= 1;
    assert!(super::verify_config_bytes(&changed).is_err());
}

#[test]
fn native_pilot_preserves_held_out_coverage_and_reviewed_negative_alerts() {
    use rustleaks_core::native::{EXTRA_RULES_V1, NativePolicy};
    let corpus = generator::corpus();
    model::validate(&corpus).unwrap();
    let default = Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap();
    let native = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .unwrap()
        .build()
        .unwrap();
    let baseline = assess("default", &default, corpus.cases.iter(), None);
    let candidate = assess("native", native.engine(), corpus.cases.iter(), None);
    assert_eq!(baseline.status, "measured");
    assert_eq!(candidate.status, "measured");
    for (before, after) in baseline.cases.iter().zip(&candidate.cases) {
        assert_eq!(before.case_id, after.case_id);
        assert!(
            after.counts.true_positives >= before.counts.true_positives,
            "{} loses occurrence coverage",
            before.case_id
        );
        assert!(
            after.counts.recognized_case_distinct_values
                >= before.counts.recognized_case_distinct_values,
            "{} loses value recognition",
            before.case_id
        );
        assert!(
            after.counts.negative_false_alerts <= before.counts.negative_false_alerts,
            "{} adds reviewed-negative alerts",
            before.case_id
        );
        let allowed_contextual_duplicate =
            usize::from(before.case_id == "mongodb-provider-overlap");
        assert!(
            after.counts.duplicate_alerts
                <= before.counts.duplicate_alerts + allowed_contextual_duplicate,
            "{} adds unreviewed duplicate alerts",
            before.case_id
        );
        for index in &after.missing_positive_indices {
            assert!(
                before.missing_positive_indices.contains(index),
                "{} loses positive {index}",
                before.case_id
            );
        }
    }
    for case in &corpus.cases {
        if case.stratum != "native-pilot" {
            continue;
        }
        let actual = candidate
            .cases
            .iter()
            .find(|value| value.case_id == case.id)
            .unwrap();
        assert_eq!(
            actual.counts.recognized_case_distinct_values,
            actual.counts.expected_case_distinct_values,
            "{} misses a pilot value",
            case.id
        );
        if case.decode_depth == 0 {
            assert_eq!(
                actual.counts.false_negatives, 0,
                "{} misses a pilot occurrence",
                case.id
            );
            assert_eq!(
                actual.counts.attribution_mismatches, 0,
                "{} misses provider attribution",
                case.id
            );
        } else {
            // Existing decoded mapping honestly remains unavailable.
            assert!(actual.counts.unlocated_alerts > 0);
        }
    }
}
