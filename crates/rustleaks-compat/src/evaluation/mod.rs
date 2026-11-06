//! Independent, bounded evaluation of synthetic detection-quality fixtures.
//!
//! The generated corpus describes intended secret occurrences and reviewed
//! negatives independently of detector output. Rates describe this corpus only.
//! Reports omit input and secret bytes; identifiers are still metadata.

mod generator;
mod model;
mod pilot;
mod score;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use rustleaks_core::config::{
    ConfigLoader, DEFAULT_CONFIG_BYTES, DEFAULT_CONFIG_REVISION, DEFAULT_CONFIG_SHA256,
};
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::native::{EXTRA_RULES_V1, NativePolicy};
use rustleaks_core::{Engine, ScanBudget, ScanControl};
use serde::Serialize;

use model::{CONFIG_SHA256, Case, PROFILE, Span, fingerprint};
use score::{Counts, Observation, Rates};

#[derive(Serialize)]
struct CaseResult {
    case_id: String,
    split: String,
    stratum: String,
    scan_complete: bool,
    termination: Option<String>,
    scored_positive_indices: Vec<usize>,
    missing_positive_indices: Vec<usize>,
    counts: Counts,
    rates: Rates,
}

#[derive(Default, Serialize)]
struct FamilyRecall {
    exact_span_true_positives: usize,
    exact_span_false_negatives: usize,
}

#[derive(Serialize)]
struct Assessment {
    selection: String,
    status: &'static str,
    total_cases: usize,
    completed_cases: usize,
    completion_rate: f64,
    counts: Counts,
    rates: Rates,
    per_family: BTreeMap<String, FamilyRecall>,
    cases: Vec<CaseResult>,
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    scope: &'static str,
    profile: &'static str,
    package_version: &'static str,
    default_config_sha256: &'static str,
    loaded_config_fnv1a64: String,
    native_pack: &'static str,
    native_pack_fnv1a64: String,
    corpus_fnv1a64: String,
    evaluator_source_fnv1a64: String,
    generator_source_fnv1a64: String,
    fingerprint_purpose: &'static str,
    assessments: Vec<Assessment>,
}

/// Generates the canonical, fully synthetic corpus as stable JSON bytes.
///
/// # Errors
/// Returns an error if generated labels violate the schema or JSON cannot be encoded.
pub fn generated_corpus() -> Result<Vec<u8>, String> {
    verify_config_bytes(DEFAULT_CONFIG_BYTES)?;
    let corpus = generator::corpus();
    model::validate(&corpus)?;
    json(&corpus)
}

/// Verifies exact agreement with the maintained generator, including labels.
///
/// # Errors
/// Returns an error for invalid, changed or stale corpus bytes.
pub fn check_generated_corpus(bytes: &[u8]) -> Result<(), String> {
    model::parse(bytes)?;
    if bytes != generated_corpus()? {
        return Err("quality corpus differs from its maintained generator".into());
    }
    Ok(())
}

/// Compares the full default and opt-in native profiles and selected individual rules.
///
/// The report exposes exact-location scores separately from distinct-value
/// recognition. Unmapped decoded findings are never assigned an invented range.
/// Incomplete scans retain their missing positive inventory and status.
///
/// # Errors
/// Returns an error for invalid corpus/configuration or report serialization.
pub fn evaluate_corpus(bytes: &[u8]) -> Result<Vec<u8>, String> {
    verify_config_bytes(DEFAULT_CONFIG_BYTES)?;
    let corpus = model::parse(bytes)?;
    let config = ConfigLoader::new()
        .load_default()
        .map_err(|_| "cannot compile default quality-evaluation configuration")?;
    let engine = Engine::builder(config.clone())
        .build()
        .map_err(|_| "cannot build default quality-evaluation engine")?;
    let mut assessments = vec![assess(
        "all-default-rules",
        &engine,
        corpus.cases.iter(),
        None,
    )];
    let native = NativePolicy::builder()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .map_err(|_| "cannot load native quality-evaluation pack")?
        .build()
        .map_err(|_| "cannot build native quality-evaluation engine")?;
    assessments.push(assess(
        "all-native-rules",
        native.engine(),
        corpus.cases.iter(),
        None,
    ));
    let mut selections: BTreeMap<&str, Vec<&Case>> = BTreeMap::new();
    for case in &corpus.cases {
        for rule in &case.selected_rules {
            selections.entry(rule).or_default().push(case);
        }
    }
    for (rule, cases) in selections {
        let selected_config = if rule.starts_with("rustleaks.") {
            native.engine().config()
        } else {
            &config
        };
        let selected = selected_config
            .select_rules([rule])
            .map_err(|_| "quality corpus selects an unknown rule")?;
        let engine = Engine::builder(selected)
            .build()
            .map_err(|_| "cannot build selected quality-evaluation engine")?;
        assessments.push(assess(rule, &engine, cases.into_iter(), Some(rule)));
    }
    let source = [
        include_bytes!("mod.rs").as_slice(),
        include_bytes!("model.rs").as_slice(),
        include_bytes!("score.rs").as_slice(),
    ]
    .concat();
    json(&Report {
        schema_version: 1,
        scope: "Synthetic intent labels; no deployment accuracy or live validity claim. Exact-span and case-distinct-value recall are separate metrics.",
        profile: PROFILE,
        package_version: env!("CARGO_PKG_VERSION"),
        default_config_sha256: CONFIG_SHA256,
        loaded_config_fnv1a64: fingerprint(DEFAULT_CONFIG_BYTES),
        native_pack: "rustleaks-extra-v1",
        native_pack_fnv1a64: fingerprint(EXTRA_RULES_V1.as_bytes()),
        corpus_fnv1a64: fingerprint(bytes),
        evaluator_source_fnv1a64: fingerprint(&source),
        generator_source_fnv1a64: corpus.generator_source_fnv1a64,
        fingerprint_purpose: "FNV-1a fingerprints detect accidental drift; they are not authenticity or collision-resistance guarantees. Source and build revision must accompany release evidence.",
        assessments,
    })
}

fn json(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| "cannot encode quality JSON")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn observe(engine: &Engine, case: &Case) -> (Vec<Observation>, Option<String>) {
    let fragment = Fragment::builder(case.input.clone())
        .file_path(case.path.clone())
        .build();
    let options = ScanOptions::builder()
        .max_decode_depth(case.decode_depth)
        .build();
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(case.max_work_units)
            .max_decoded_bytes(1024 * 1024)
            .max_finding_records(256),
    );
    let outcome = engine.scan_fragment_controlled(&fragment, &options, &control);
    let observations = outcome
        .findings()
        .iter()
        .map(|finding| Observation {
            span: finding.secret_range().exact().map(|range| Span {
                start: range.start(),
                end: range.end(),
            }),
            rule: finding.rule_id().to_string_lossy().into_owned(),
            secret: finding.secret().as_bytes().to_vec(),
        })
        .collect();
    let termination = outcome.termination().map(ToString::to_string);
    (observations, termination)
}

fn assess<'a>(
    selection: &str,
    engine: &Engine,
    cases: impl Iterator<Item = &'a Case>,
    selected_rule: Option<&str>,
) -> Assessment {
    let mut results = Vec::new();
    let mut counts = Counts::default();
    let mut per_family: BTreeMap<String, FamilyRecall> = BTreeMap::new();
    let mut completed = 0;
    for original in cases {
        let (projected, indices) = project(original, selected_rule);
        let case = &projected;
        let (observations, termination) = observe(engine, case);
        let scored = score::score(case, &observations);
        counts.add(scored.counts);
        for (family, (true_positives, false_negatives)) in scored.family_recall {
            let total = per_family.entry(family).or_default();
            total.exact_span_true_positives += true_positives;
            total.exact_span_false_negatives += false_negatives;
        }
        completed += usize::from(termination.is_none());
        results.push(CaseResult {
            case_id: case.id.clone(),
            split: case.split.clone(),
            stratum: case.stratum.clone(),
            scan_complete: termination.is_none(),
            termination,
            missing_positive_indices: scored
                .missing_positive_indices
                .into_iter()
                .map(|index| indices[index])
                .collect(),
            scored_positive_indices: indices,
            counts: scored.counts,
            rates: scored.counts.into(),
        });
    }
    #[allow(clippy::cast_precision_loss)] // Validated corpora contain at most 256 cases.
    let completion_rate = completed as f64 / results.len() as f64;
    Assessment {
        selection: selection.into(),
        status: if completed == results.len() {
            "measured"
        } else {
            "incomplete"
        },
        total_cases: results.len(),
        completed_cases: completed,
        completion_rate,
        counts,
        rates: counts.into(),
        per_family,
        cases: results,
    }
}

fn project(case: &Case, selected_rule: Option<&str>) -> (Case, Vec<usize>) {
    let mut projected = case.clone();
    projected.positives.clear();
    let mut indices = Vec::new();
    for (index, positive) in case.positives.iter().enumerate() {
        if selected_rule
            .is_none_or(|rule| positive.rule_ids.iter().any(|expected| expected == rule))
        {
            projected.positives.push(positive.clone());
            indices.push(index);
        } else {
            // A provider-specific run is not expected to recognize other families.
            projected.unknown_regions.push(positive.span);
        }
    }
    (projected, indices)
}

fn verify_config_bytes(actual: &[u8]) -> Result<(), String> {
    let mirror = include_bytes!("../../../../compat/config-corpus/default-gitleaks.toml");
    if actual != mirror
        || DEFAULT_CONFIG_SHA256 != CONFIG_SHA256
        || DEFAULT_CONFIG_REVISION != "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b"
    {
        return Err(
            "quality evaluation default configuration differs from its pinned mirror".into(),
        );
    }
    Ok(())
}
