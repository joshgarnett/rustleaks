use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::model::{Case, Span};

#[derive(Clone)]
pub(super) struct Observation {
    pub span: Option<Span>,
    pub rule: String,
    pub secret: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub(super) struct Counts {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub duplicate_alerts: usize,
    pub attribution_mismatches: usize,
    pub location_mismatches: usize,
    pub unknown_alerts: usize,
    pub unlocated_alerts: usize,
    pub negative_false_alerts: usize,
    pub reviewed_negative_bytes: usize,
    pub unknown_bytes: usize,
    pub observed_alerts: usize,
    pub expected_case_distinct_values: usize,
    pub recognized_case_distinct_values: usize,
}

impl Counts {
    pub fn add(&mut self, other: Self) {
        self.true_positives += other.true_positives;
        self.false_positives += other.false_positives;
        self.false_negatives += other.false_negatives;
        self.duplicate_alerts += other.duplicate_alerts;
        self.attribution_mismatches += other.attribution_mismatches;
        self.location_mismatches += other.location_mismatches;
        self.unknown_alerts += other.unknown_alerts;
        self.unlocated_alerts += other.unlocated_alerts;
        self.negative_false_alerts += other.negative_false_alerts;
        self.reviewed_negative_bytes += other.reviewed_negative_bytes;
        self.unknown_bytes += other.unknown_bytes;
        self.observed_alerts += other.observed_alerts;
        self.expected_case_distinct_values += other.expected_case_distinct_values;
        self.recognized_case_distinct_values += other.recognized_case_distinct_values;
    }
}

#[derive(Serialize)]
pub(super) struct Rates {
    pub exact_span_precision: Option<f64>,
    pub exact_span_recall: Option<f64>,
    pub case_distinct_value_recall: Option<f64>,
    pub negative_false_alerts_per_mib: Option<f64>,
    pub unknown_alert_fraction: Option<f64>,
}

#[allow(clippy::cast_precision_loss)] // Counts are bounded by the validated corpus and scan budgets.
fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

impl From<Counts> for Rates {
    fn from(counts: Counts) -> Self {
        Self {
            exact_span_precision: ratio(
                counts.true_positives,
                counts.true_positives + counts.false_positives,
            ),
            exact_span_recall: ratio(
                counts.true_positives,
                counts.true_positives + counts.false_negatives,
            ),
            case_distinct_value_recall: ratio(
                counts.recognized_case_distinct_values,
                counts.expected_case_distinct_values,
            ),
            negative_false_alerts_per_mib: ratio(
                counts.negative_false_alerts,
                counts.reviewed_negative_bytes,
            )
            .map(|rate| rate * 1_048_576.0),
            unknown_alert_fraction: ratio(
                counts.unknown_alerts + counts.unlocated_alerts,
                counts.observed_alerts - counts.duplicate_alerts,
            ),
        }
    }
}

pub(super) struct Scored {
    pub counts: Counts,
    pub family_recall: BTreeMap<String, (usize, usize)>,
    pub missing_positive_indices: Vec<usize>,
}

pub(super) fn score(case: &Case, observations: &[Observation]) -> Scored {
    let mut counts = Counts {
        reviewed_negative_bytes: case
            .negative_regions
            .iter()
            .map(|span| span.end - span.start)
            .sum(),
        unknown_bytes: case
            .unknown_regions
            .iter()
            .map(|span| span.end - span.start)
            .sum(),
        observed_alerts: observations.len(),
        ..Counts::default()
    };
    let expected_values: BTreeSet<_> = case
        .positives
        .iter()
        .map(|positive| positive.expected_secret.as_slice())
        .collect();
    counts.expected_case_distinct_values = expected_values.len();
    counts.recognized_case_distinct_values = expected_values
        .iter()
        .filter(|expected| {
            observations
                .iter()
                .any(|observed| observed.secret.as_slice() == **expected)
        })
        .count();
    let mut located: BTreeMap<(Span, &[u8]), Vec<&str>> = BTreeMap::new();
    for observation in observations {
        if let Some(span) = observation.span {
            located
                .entry((span, observation.secret.as_slice()))
                .or_default()
                .push(&observation.rule);
        } else {
            counts.unlocated_alerts += 1;
        }
    }
    let mut matched = BTreeSet::new();
    for ((span, secret), rules) in located {
        counts.duplicate_alerts += rules.len() - 1;
        if let Some((index, positive)) = case.positives.iter().enumerate().find(|(_, positive)| {
            positive.span == span && positive.expected_secret.as_slice() == secret
        }) {
            matched.insert(index);
            counts.true_positives += 1;
            if !rules.iter().any(|rule| {
                positive
                    .rule_ids
                    .iter()
                    .any(|expected| expected.as_str() == *rule)
            }) {
                counts.attribution_mismatches += 1;
            }
        } else if case
            .unknown_regions
            .iter()
            .any(|region| region.overlaps(span))
        {
            counts.unknown_alerts += 1;
        } else {
            counts.false_positives += 1;
            if case
                .positives
                .iter()
                .any(|positive| positive.span.overlaps(span))
            {
                counts.location_mismatches += 1;
            } else {
                counts.negative_false_alerts += 1;
            }
        }
    }
    let mut family_recall: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut missing_positive_indices = Vec::new();
    for (index, positive) in case.positives.iter().enumerate() {
        let count = family_recall.entry(positive.family.clone()).or_default();
        if matched.contains(&index) {
            count.0 += 1;
        } else {
            count.1 += 1;
            missing_positive_indices.push(index);
        }
    }
    counts.false_negatives = missing_positive_indices.len();
    Scored {
        counts,
        family_recall,
        missing_positive_indices,
    }
}
