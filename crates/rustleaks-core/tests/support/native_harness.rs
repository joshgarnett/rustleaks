//! Shared helpers for the rule coverage tests.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustleaks_core::Engine;
use rustleaks_core::config::CompiledConfig;
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::native::{
    CONNECTION_RULES_V1, EXTRA_RULES_V1, NativePolicy, PROVIDER_RULES_V1,
};
use serde::Deserialize;

/// The default rules followed by the providers, connections and extra packs.
pub fn all_packs_config() -> CompiledConfig {
    NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)
        .unwrap()
        .with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)
        .unwrap()
        .compile()
        .unwrap()
        .0
}

/// Returns `baseline_rule_ids` from a coverage data file in `tests/support/`.
///
/// Each list is a fixed comparison set of rule IDs. It does not follow rule
/// file changes.
pub fn baseline_rule_ids(json: &str) -> Vec<String> {
    #[derive(Deserialize)]
    struct Baseline {
        baseline_rule_ids: Vec<String>,
    }
    serde_json::from_str::<Baseline>(json)
        .unwrap()
        .baseline_rule_ids
}

/// Scans with default options and requires a complete outcome.
pub fn scan(engine: &Engine, bytes: &[u8], path: &str) -> Vec<Finding> {
    scan_with_depth(engine, bytes, path, 0)
}

/// Scans with `max_decode_depth` and requires a complete outcome.
pub fn scan_with_depth(
    engine: &Engine,
    bytes: &[u8],
    path: &str,
    max_decode_depth: usize,
) -> Vec<Finding> {
    let fragment = Fragment::builder(bytes).file_path(path).build();
    let result = engine.scan_fragment(
        &fragment,
        &ScanOptions::builder()
            .max_decode_depth(max_decode_depth)
            .build(),
    );
    assert!(result.is_complete(), "{path}");
    result.findings().to_vec()
}

/// Findings of one rule, in scan order.
pub fn for_rule<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    findings
        .iter()
        .filter(|finding| finding.rule_id().as_bytes() == rule.as_bytes())
        .collect()
}

pub fn base64_bytes(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

pub fn exact_range([start, end]: [usize; 2]) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

pub fn optional_range(value: Option<[usize; 2]>) -> FindingRange {
    value.map_or(FindingRange::Unavailable, exact_range)
}

pub fn coordinates(value: Location) -> [usize; 4] {
    [
        value.start_line(),
        value.end_line(),
        value.start_column(),
        value.end_column(),
    ]
}

/// Shannon entropy over bytes, in bits per byte.
#[allow(clippy::cast_precision_loss)] // Test inputs are far below 2^52 bytes.
pub fn byte_entropy(bytes: &[u8]) -> f64 {
    let mut histogram = [0usize; 256];
    for byte in bytes {
        histogram[usize::from(*byte)] += 1;
    }
    histogram
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}
