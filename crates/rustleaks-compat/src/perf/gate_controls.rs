//! Adverse controls for optional shared content prefilters.
//!
//! Each fixture has exactly nine eligible rules, so a query after eight empty
//! full searches has only one remaining search to save. These are synthetic
//! cost controls, not representative production traffic or expected speedups.
//! Input bytes and resource expectations follow the constructors and existing
//! checkpoint contracts, independently of any prefilter implementation.

use std::error::Error;
use std::fmt::Write;

use rustleaks_core::ScanOutcome;

use super::{Fixture, normalization_workloads};

const KIB: usize = 1_024;
const MIB: usize = 1_024 * KIB;
const RULES: usize = 9;

pub(super) const WORKLOADS: &[&str] = &[
    "core-gate-nine-misses-4-mib",
    "core-gate-late-punctuation-4-mib",
    "core-gate-cheap-anchors-4-mib",
    "core-gate-invalid-nine-misses-256-kib",
    "core-gate-decoded-nine-misses-256-kib",
];

#[derive(Clone, Copy)]
enum Shape {
    MarkerFree,
    LatePunctuation,
    CheapAnchors,
    Invalid,
}

fn config(anchored: bool) -> String {
    let mut config = String::new();
    // No leading repetition means the first expression cannot use the
    // existing literal-anchor shape. The second has one bounded prefix and
    // one recorded literal, and its fixed tail admits a cheap empty result.
    let regex = if anchored {
        r"[\w.-]{0,50}?(?:svc|xyz)=([A-Z0-9]{4})"
    } else {
        r"svc=([A-Z0-9]{4})"
    };
    for index in 0..RULES {
        writeln!(
            config,
            "[[rules]]\nid = \"gate-{index:02}\"\nregex = '''{regex}'''\nsecretGroup = 1"
        )
        .expect("writing to a String cannot fail");
        if anchored {
            config.push_str("keywords = [\"svc\", \"xyz\"]\n");
        }
    }
    config
}

fn build(size: usize, shape: Shape) -> Fixture {
    let anchored = matches!(shape, Shape::CheapAnchors);
    let mut input = vec![b'z'; size];
    match shape {
        Shape::MarkerFree => {}
        // There is no marker in the first 256 bytes, or anywhere before EOF.
        // A presence query reads the entire input and rejects no rule here.
        Shape::LatePunctuation => input[size - 1] = b'=',
        // One keyword hit shared by nine rules. Every recorded occurrence
        // completes cheaply with zero spans. This must not itself justify a
        // full-input presence query, even after the eighth empty anchor.
        Shape::CheapAnchors => input[..3].copy_from_slice(b"svc"),
        Shape::Invalid => input[size - 1] = 0xff,
    }
    Fixture {
        input,
        config: config(anchored),
        expected: Vec::new(),
        control_fingerprint: None,
        expected_rules: RULES,
        depth: 0,
        decoded_bytes: 0,
        keyword_count: 0,
        // One pass, nine admitted rules, and at most one keyword occurrence.
        // No expression can match these bytes, so there are no candidates.
        expected_work: Some(1 + RULES + usize::from(anchored)),
    }
}

pub(super) fn fixture(id: &str) -> Result<Fixture, Box<dyn Error>> {
    match id {
        "core-gate-nine-misses-4-mib" => Ok(build(4 * MIB, Shape::MarkerFree)),
        "core-gate-late-punctuation-4-mib" => Ok(build(4 * MIB, Shape::LatePunctuation)),
        "core-gate-cheap-anchors-4-mib" => Ok(build(4 * MIB, Shape::CheapAnchors)),
        "core-gate-invalid-nine-misses-256-kib" => Ok(build(256 * KIB, Shape::Invalid)),
        "core-gate-decoded-nine-misses-256-kib" => {
            // Reuse the maintained percent constructor and its closed-form
            // decoded extent. The sole %41 run becomes A bytes plus padding;
            // neither original nor decoded input contains '=' or 'svc'.
            let mut fixture = normalization_workloads::fixture(
                "core-normalization-percent-valid-256-kib-depth-1",
            )?;
            fixture.config = config(false);
            fixture.expected_rules = RULES;
            // Two pass/rule pairs plus dispatch, candidate, transform and
            // replacement: 2 * (1 + 9) + 4 = 24 work checkpoints.
            fixture.expected_work = Some(2 * (1 + RULES) + 4);
            Ok(fixture)
        }
        _ => Err(format!("unknown content-gate control {id}").into()),
    }
}

pub(super) fn validate(
    id: &str,
    fixture: &Fixture,
    outcome: &ScanOutcome,
) -> Result<(), Box<dyn Error>> {
    if !WORKLOADS.contains(&id) {
        return Ok(());
    }
    // The shared fixture validator checks completion, exact findings, work,
    // decoded bytes and records. Check the remaining resource dimensions too.
    let normalized = if id == "core-gate-invalid-nine-misses-256-kib" {
        fixture.input.len() + 2 + size_of::<usize>()
    } else {
        0
    };
    let spans = usize::from(id == "core-gate-decoded-nine-misses-256-kib");
    if outcome.usage().normalization_bytes() != normalized
        || outcome.usage().collected_spans() != spans
        || outcome.usage().finding_payload_bytes() != 0
    {
        return Err("content-gate control resource accounting differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rustleaks_core::model::{Fragment, ScanOptions};
    use rustleaks_core::{Engine, ScanBudget, ScanBudgetKind, ScanControl, ScanTermination};

    use super::*;

    fn scan(fixture: &Fixture, budget: ScanBudget) -> rustleaks_core::ScanOutcome {
        Engine::builder(fixture.compile().unwrap())
            .build()
            .unwrap()
            .scan_fragment_controlled(
                &Fragment::new(fixture.input.clone()),
                &ScanOptions::builder()
                    .max_decode_depth(fixture.depth)
                    .build(),
                &ScanControl::unlimited().with_budget(budget),
            )
    }

    #[test]
    fn fixed_inputs_make_the_final_rule_the_only_remaining_opportunity() {
        for &id in WORKLOADS {
            let fixture = fixture(id).unwrap();
            assert_eq!(fixture.expected_rules, RULES);
            assert_eq!(fixture.config.matches("[[rules]]").count(), RULES);
            assert!(fixture.config.contains("id = \"gate-08\""));
            assert!(fixture.expected.is_empty());
            assert_eq!(fixture.keyword_count, 0);
            assert!(fixture.input.len() >= 8 * KIB);
            let equals = fixture.input.iter().position(|byte| *byte == b'=');
            if id == "core-gate-late-punctuation-4-mib" {
                assert_eq!(equals, Some(fixture.input.len() - 1));
                assert!(
                    fixture.input[..fixture.input.len() - 1]
                        .iter()
                        .all(|byte| *byte == b'z')
                );
            } else {
                assert_eq!(equals, None);
            }
        }
        assert!(fixture("unknown").is_err());
    }

    #[test]
    fn small_controls_preserve_all_resource_counts_with_and_without_finite_spans() {
        for shape in [
            Shape::MarkerFree,
            Shape::LatePunctuation,
            Shape::CheapAnchors,
            Shape::Invalid,
        ] {
            let fixture = build(8 * KIB, shape);
            let normalized = if matches!(shape, Shape::Invalid) {
                fixture.input.len() + 2 + size_of::<usize>()
            } else {
                0
            };
            let budget = ScanBudget::unlimited()
                .max_work_units(fixture.expected_work.unwrap())
                .max_finding_records(0)
                .max_finding_payload_bytes(0)
                .max_decoded_bytes(0)
                .max_normalization_bytes(normalized);
            // The unlimited-span arm retains the anchor path; a finite span
            // limit deliberately exercises the existing controlled collector.
            for budget in [budget, budget.max_collected_spans(0)] {
                let outcome = scan(&fixture, budget);
                fixture.validate(&outcome).unwrap();
                assert_eq!(outcome.usage().collected_spans(), 0);
                assert_eq!(outcome.usage().normalization_bytes(), normalized);
                assert_eq!(outcome.usage().finding_payload_bytes(), 0);
            }
        }
    }

    #[test]
    fn work_limits_preserve_the_pass_and_ninth_rule_boundaries() {
        let fixture = build(8 * KIB, Shape::MarkerFree);
        for limit in [0, 1, 9, 10] {
            let outcome = scan(&fixture, ScanBudget::unlimited().max_work_units(limit));
            assert!(outcome.findings().is_empty());
            assert_eq!(outcome.usage().work_units(), limit);
            if limit == 10 {
                fixture.validate(&outcome).unwrap();
            } else {
                assert_eq!(
                    outcome.termination(),
                    Some(&ScanTermination::BudgetExceeded {
                        kind: ScanBudgetKind::WorkUnits,
                        limit,
                        consumed: limit,
                        requested: 1,
                    })
                );
                assert!(!outcome.is_complete());
            }
        }
    }

    #[test]
    fn invalid_bytes_still_fail_at_the_original_normalization_boundary() {
        let fixture = build(8 * KIB, Shape::Invalid);
        let normalized = fixture.input.len() + 2 + size_of::<usize>();
        for limit in [normalized - 1, normalized, normalized + 1] {
            let outcome = scan(
                &fixture,
                ScanBudget::unlimited()
                    .max_normalization_bytes(limit)
                    .max_collected_spans(0),
            );
            if limit < normalized {
                assert!(!outcome.is_complete());
                assert!(outcome.findings().is_empty());
                assert_eq!(outcome.usage().work_units(), 2);
                assert_eq!(outcome.usage().normalization_bytes(), 0);
                assert_eq!(
                    outcome.termination(),
                    Some(&ScanTermination::BudgetExceeded {
                        kind: ScanBudgetKind::NormalizationBytes,
                        limit,
                        consumed: 0,
                        requested: normalized,
                    })
                );
            } else {
                fixture.validate(&outcome).unwrap();
                assert_eq!(outcome.usage().normalization_bytes(), normalized);
            }
        }
    }

    #[test]
    fn decoded_control_preserves_the_exact_replacement_budget() {
        let fixture = fixture("core-gate-decoded-nine-misses-256-kib").unwrap();
        // 262144 = 87381 three-byte escapes and one trailing space.
        assert_eq!(fixture.decoded_bytes, 87_382);
        for limit in [87_381, 87_382, 87_383] {
            let outcome = scan(
                &fixture,
                ScanBudget::unlimited()
                    .max_work_units(24)
                    .max_finding_records(0)
                    .max_finding_payload_bytes(0)
                    .max_collected_spans(1)
                    .max_normalization_bytes(0)
                    .max_decoded_bytes(limit),
            );
            assert_eq!(outcome.usage().collected_spans(), 1);
            assert_eq!(outcome.usage().normalization_bytes(), 0);
            assert_eq!(outcome.usage().finding_payload_bytes(), 0);
            if limit < fixture.decoded_bytes {
                assert!(!outcome.is_complete());
                assert!(outcome.findings().is_empty());
                assert_eq!(outcome.usage().work_units(), 14);
                assert_eq!(outcome.usage().decoded_bytes(), 0);
                assert_eq!(
                    outcome.termination(),
                    Some(&ScanTermination::BudgetExceeded {
                        kind: ScanBudgetKind::DecodedBytes,
                        limit,
                        consumed: 0,
                        requested: fixture.decoded_bytes,
                    })
                );
            } else {
                fixture.validate(&outcome).unwrap();
            }
        }
    }
}
