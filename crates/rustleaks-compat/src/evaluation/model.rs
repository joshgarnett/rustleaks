use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub(super) const MAX_CORPUS_BYTES: usize = 1024 * 1024;
pub(super) const PROFILE: &str = "gitleaks-b58d3f1";
pub(super) const CONFIG_SHA256: &str =
    "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Positive {
    pub span: Span,
    pub expected_secret: Vec<u8>,
    pub family: String,
    pub rule_ids: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Case {
    pub id: String,
    pub leakage_group: String,
    pub split: String,
    pub stratum: String,
    pub rationale: String,
    pub input: Vec<u8>,
    pub path: String,
    pub content_fnv1a64: String,
    pub selected_rules: Vec<String>,
    pub positives: Vec<Positive>,
    pub negative_regions: Vec<Span>,
    pub unknown_regions: Vec<Span>,
    pub decode_depth: usize,
    pub max_work_units: usize,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Corpus {
    pub schema_version: u32,
    pub generator: String,
    pub generator_source_fnv1a64: String,
    pub license: String,
    pub provenance: String,
    pub intended_population: String,
    pub profile: String,
    pub default_config_sha256: String,
    pub cases: Vec<Case>,
}

pub(super) fn fingerprint(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{hash:016x}")
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
}

pub(super) fn parse(bytes: &[u8]) -> Result<Corpus, String> {
    if bytes.len() > MAX_CORPUS_BYTES {
        return Err("quality corpus exceeds 1 MiB".into());
    }
    // Serde's detailed diagnostics can echo arbitrary input strings.
    let corpus: Corpus =
        serde_json::from_slice(bytes).map_err(|_| "invalid quality corpus JSON")?;
    validate(&corpus)?;
    Ok(corpus)
}

pub(super) fn validate(corpus: &Corpus) -> Result<(), String> {
    if corpus.schema_version != 1
        || corpus.profile != PROFILE
        || corpus.default_config_sha256 != CONFIG_SHA256
        || corpus.generator != "rustleaks-quality-v1"
        || corpus.license != "MIT"
        || corpus.generator_source_fnv1a64 != super::generator::source_fingerprint()
    {
        return Err("unsupported quality corpus identity or generator fingerprint".into());
    }
    if corpus.cases.is_empty() || corpus.cases.len() > 256 {
        return Err("quality corpus requires between 1 and 256 cases".into());
    }
    let mut ids = BTreeSet::new();
    let mut groups = BTreeMap::new();
    let mut contents = BTreeMap::new();
    let mut secret_values = BTreeMap::new();
    for (index, case) in corpus.cases.iter().enumerate() {
        validate_case(case).map_err(|error| format!("quality case {index}: {error}"))?;
        if !ids.insert(&case.id) {
            return Err("quality corpus has duplicate case identifiers".into());
        }
        if let Some(previous) = contents.insert(&case.input, &case.split)
            && previous != &case.split
        {
            return Err("quality corpus repeats content across splits".into());
        }
        for positive in &case.positives {
            if let Some(previous) = secret_values.insert(&positive.expected_secret, &case.split)
                && previous != &case.split
            {
                return Err("quality corpus repeats an intended secret value across splits".into());
            }
        }
        if let Some(previous) = groups.insert(&case.leakage_group, &case.split)
            && previous != &case.split
        {
            return Err("quality corpus leaks a template family across splits".into());
        }
    }
    Ok(())
}

fn validate_case(case: &Case) -> Result<(), &'static str> {
    if !identifier(&case.id)
        || !identifier(&case.leakage_group)
        || !identifier(&case.stratum)
        || !matches!(case.split.as_str(), "tune" | "holdout")
        || case.rationale.is_empty()
        || case.rationale.len() > 1024
        || case.input.is_empty()
        || case.input.len() > 65_536
        || case.path.len() > 256
        || case.content_fnv1a64 != fingerprint(&case.input)
        || case.decode_depth > 2
        || case.max_work_units > 100_000
    {
        return Err("invalid metadata, content fingerprint or resource bound");
    }
    if case.selected_rules.is_empty()
        || case.selected_rules.len() > 8
        || case.selected_rules.iter().any(|rule| !identifier(rule))
        || case.selected_rules.iter().collect::<BTreeSet<_>>().len() != case.selected_rules.len()
        || case.positives.len() > 64
        || case.negative_regions.len() > 128
        || case.unknown_regions.len() > 64
    {
        return Err("invalid selected rules or label count");
    }
    let mut regions = Vec::new();
    for positive in &case.positives {
        if positive.expected_secret.is_empty()
            || positive.expected_secret.len() > 65_536
            || !identifier(&positive.family)
            || positive.rule_ids.is_empty()
            || positive.rule_ids.len() > 8
            || positive.rule_ids.iter().any(|rule| !identifier(rule))
        {
            return Err("invalid positive attribution");
        }
        regions.push(positive.span);
    }
    regions.extend(&case.negative_regions);
    regions.extend(&case.unknown_regions);
    regions.sort_unstable();
    let mut end = 0;
    for region in regions {
        if region.start != end || region.end <= region.start || region.end > case.input.len() {
            return Err("labels must partition every input byte without gaps or overlaps");
        }
        end = region.end;
    }
    if end != case.input.len() {
        return Err("labels omit input bytes");
    }
    Ok(())
}
