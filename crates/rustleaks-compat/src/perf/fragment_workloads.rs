//! Default-rule throughput fixtures with independently counted work checkpoints.

use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::{CompiledConfig, ConfigLoader, DEFAULT_CONFIG_BYTES};
use rustleaks_core::model::{ByteRange, Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanOutcome};
use serde_json::json;

use super::{Phase, elapsed, fingerprint, outcome_signature, phase};

const KIB: usize = 1_024;
const MIB: usize = 1_024 * KIB;
const UNIT_BYTES: usize = 16 * KIB;
const PROVIDERS: &[&str] = &[
    "adafruit",
    "adobe",
    "airtable",
    "algolia",
    "alibaba",
    "asana",
    "beamer",
    "bitbucket",
    "bittrex",
    "meraki",
    "cloudflare",
    "codecov",
    "coinbase",
    "confluent",
    "contentful",
    "databricks",
    "datadog",
    "digitalocean",
    "discord",
    "doppler",
    "dropbox",
    "facebook",
    "fastly",
    "figma",
    "finicity",
    "flutterwave",
    "frameio",
    "freshbooks",
    "github",
    "gitlab",
    "grafana",
    "hashicorp",
];

pub const WORKLOADS: &[&str] = &[
    "core-fragments-json-16-kib",
    "core-fragments-json-256-kib",
    "core-fragments-json-1-mib",
    "core-fragments-json-4-mib",
    "core-fragments-json-12-mib-by-16-kib",
    "core-fragments-json-12-mib-by-256-kib",
    "core-fragments-log-16-kib",
    "core-fragments-log-256-kib",
    "core-fragments-log-1-mib",
    "core-fragments-log-4-mib",
    "core-fragments-log-12-mib-by-16-kib",
    "core-fragments-log-12-mib-by-256-kib",
    "core-fragments-invalid-4-mib",
    "core-fragments-invalid-12-mib-by-16-kib",
];

struct Fixture {
    fragments: Vec<Fragment>,
    input: Vec<u8>,
    work_per_fragment: usize,
    keyword_occurrences_per_fragment: usize,
    admitted_rules: usize,
    expected: Finding,
}

impl Fixture {
    #[allow(clippy::too_many_lines, clippy::naive_bytecount)]
    fn new(id: &str, config: &CompiledConfig) -> Result<Self, Box<dyn Error>> {
        if !WORKLOADS.contains(&id) {
            return Err("unknown fragment workload".into());
        }
        let fragment_bytes = if id.ends_with("16-kib") {
            UNIT_BYTES
        } else if id.ends_with("256-kib") {
            256 * KIB
        } else if id.ends_with("1-mib") {
            MIB
        } else {
            4 * MIB
        };
        let total_bytes = if id.contains("12-mib-by") {
            12 * MIB
        } else {
            fragment_bytes
        };
        let mut unit = Vec::with_capacity(UNIT_BYTES);
        for (index, provider) in PROVIDERS.iter().enumerate() {
            let record = if id.contains("-json-") {
                format!("{{\"service\":\"{provider}\",\"state\":\"idle\",\"events\":7}}\n")
            } else {
                format!("2026-01-01 00:00:00 INFO service {provider} state idle events 7\n")
            };
            unit.extend_from_slice(record.as_bytes());
            if id.contains("-invalid-") {
                unit.extend_from_slice(&[0xff, 0xc0, 0x80, b'\n']);
            }
            // Fixed-width records place keywords throughout every fragment.
            unit.resize((index + 1) * 512 - 1, b' ');
            unit.push(b'\n');
        }
        if unit.len() != UNIT_BYTES {
            return Err("fragment fixture unit size changed".into());
        }
        let sample = super::super::PRIVATE_KEY_SAMPLE.as_bytes();
        let mut final_unit = unit.clone();
        let sample_start = UNIT_BYTES - sample.len() - 1;
        final_unit[sample_start - 1] = b'\n';
        final_unit[sample_start..UNIT_BYTES - 1].copy_from_slice(sample);
        // Count overlapping literals independently of the production matcher.
        // These fixtures are ASCII except invalid bytes, which cannot form a
        // keyword. Lowercasing each unit also counts the uppercase key header.
        let lower_unit = unit.to_ascii_lowercase();
        let lower_final = final_unit.to_ascii_lowercase();
        let occurrences = |bytes: &[u8]| {
            config
                .keywords()
                .iter()
                .map(|keyword| {
                    bytes
                        .windows(keyword.len())
                        .filter(|window| *window == keyword.as_bytes())
                        .count()
                })
                .sum::<usize>()
        };
        let admitted_rules = config
            .rules()
            .values()
            .filter(|rule| {
                rule.keywords().is_empty()
                    || rule.keywords().iter().any(|keyword| {
                        lower_final
                            .windows(keyword.len())
                            .any(|window| window == keyword.as_bytes())
                    })
            })
            .count();
        if admitted_rules < 32 {
            return Err("fragment fixture must admit at least 32 default rules".into());
        }
        let units_per_fragment = fragment_bytes / UNIT_BYTES;
        let keyword_occurrences_per_fragment =
            occurrences(&lower_unit) * (units_per_fragment - 1) + occurrences(&lower_final);
        // One pass, one checkpoint per keyword occurrence and admitted rule,
        // and one candidate match. Only the reviewed private-key sample matches.
        let work_per_fragment = 2 + keyword_occurrences_per_fragment + admitted_rules;
        let mut fragment_input = unit.repeat(units_per_fragment - 1);
        fragment_input.extend_from_slice(&final_unit);
        let input = fragment_input.repeat(total_bytes / fragment_bytes);
        let start = fragment_bytes - sample.len() - 1;
        let end = fragment_bytes - 1;
        // The key begins after a newline and ends immediately before a newline.
        // Its three internal newlines put the last line three rows later.
        let start_line = fragment_input[..start]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        let range = FindingRange::Exact(ByteRange::new(start, end)?);
        let expected = Finding::builder()
            .rule_id("private-key")
            .description(config.rules()["private-key"].description())
            .location(Location::new(start_line, start_line + 3, 2, 26)?)
            .match_range(range)
            .secret_range(range)
            .line(&fragment_input[start - 1..end])
            .match_text(sample)
            .secret(sample)
            .entropy(sample_entropy(sample))
            .build()?;
        let fragments = input
            .chunks_exact(fragment_bytes)
            .map(|bytes| Fragment::builder(bytes).build())
            .collect();
        Ok(Self {
            fragments,
            input,
            work_per_fragment,
            keyword_occurrences_per_fragment,
            admitted_rules,
            expected,
        })
    }

    fn validate(&self, outcome: &ScanOutcome) -> Result<(), Box<dyn Error>> {
        if !outcome.is_complete()
            || outcome.termination().is_some()
            || outcome.findings() != std::slice::from_ref(&self.expected)
            || outcome.usage().work_units() != self.work_per_fragment
            || outcome.usage().decoded_bytes() != 0
            || outcome.usage().finding_records() != 1
        {
            return Err(format!(
                "fragment invariant failed: expected one exact private-key finding, complete, work={}; observed findings={}, complete={}, work={}, decoded={}, records={}",
                self.work_per_fragment,
                outcome.findings().len(),
                outcome.is_complete(),
                outcome.usage().work_units(),
                outcome.usage().decoded_bytes(),
                outcome.usage().finding_records(),
            )
            .into());
        }
        Ok(())
    }
}

// This byte-histogram oracle is independent of regex captures and the engine's
// rune-based entropy helper. The reviewed sample contains ASCII bytes only.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn sample_entropy(sample: &[u8]) -> f32 {
    let mut counts = [0_u32; 256];
    for byte in sample {
        counts[usize::from(*byte)] += 1;
    }
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let frequency = f64::from(count) / sample.len() as f64;
            -frequency * frequency.log2()
        })
        .sum::<f64>() as f32
}

#[allow(clippy::too_many_lines)] // Keep first and steady operation timers auditable together.
pub fn run(id: &str, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    let start = Instant::now();
    let config = ConfigLoader::new().load_default()?;
    let compile_ns = elapsed(start)?;
    if config.rules().len() != 222
        || super::super::config_metric(&config).fingerprint != 0xbba0_f636_d5a0_2d49
    {
        return Err("fragment default configuration differs from the legacy invariant".into());
    }
    let fixture = Fixture::new(id, &config)?;
    let rule_ids = config.ordered_rule_ids().join("\0");
    let mut compile = phase(
        "config-parse-and-compile",
        1,
        compile_ns,
        DEFAULT_CONFIG_BYTES.len() as u64,
        "config-bytes",
        DEFAULT_CONFIG_BYTES,
        DEFAULT_CONFIG_BYTES,
    );
    compile.outcome_fnv1a64 = fingerprint(rule_ids.as_bytes());
    compile.counts["rules"] = json!(222);
    let start = Instant::now();
    let detector = Engine::builder(config).build()?;
    let mut build = phase(
        "engine-construction",
        1,
        elapsed(start)?,
        222,
        "compiled-rules",
        DEFAULT_CONFIG_BYTES,
        DEFAULT_CONFIG_BYTES,
    );
    build.outcome_fnv1a64.clone_from(&compile.outcome_fnv1a64);
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let control = ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(fixture.work_per_fragment)
            .max_decoded_bytes(0)
            .max_finding_records(1),
    );
    let mut phases = vec![compile, build];
    for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
        let mut result = phase(
            name,
            count,
            0,
            fixture.input.len() as u64,
            "input-bytes",
            &fixture.input,
            DEFAULT_CONFIG_BYTES,
        );
        result.counts = json!({
            "workers":1, "retained_outcomes":1, "decode_depth":0,
            "fragments":fixture.fragments.len(),
            "fragment_bytes":fixture.fragments[0].content().len(),
            "admitted_rules_per_fragment":fixture.admitted_rules,
            "keyword_occurrences_per_fragment":fixture.keyword_occurrences_per_fragment,
            "work_units":fixture.work_per_fragment * fixture.fragments.len(),
            "decoded_bytes":0, "finding_records":fixture.fragments.len(),
            "operation":"sum-of-fragment-scans-one-engine",
        });
        result.findings = fixture.fragments.len() as u64;
        for _ in 0..count {
            let mut signatures = String::new();
            for fragment in &fixture.fragments {
                let start = Instant::now();
                let outcome = black_box(detector.scan_fragment_controlled(
                    black_box(fragment),
                    black_box(&options),
                    &control,
                ));
                result.elapsed_ns += elapsed(start)?;
                fixture.validate(&outcome)?;
                signatures.push_str(&outcome_signature(&outcome));
            }
            let signature = fingerprint(signatures.as_bytes());
            if result.outcome_fnv1a64 != fingerprint(&[]) && result.outcome_fnv1a64 != signature {
                return Err("fragment operation changed between iterations".into());
            }
            result.outcome_fnv1a64 = signature;
        }
        phases.push(result);
    }
    Ok(phases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_shapes_and_independent_counts_cover_the_matrix() {
        let config = ConfigLoader::new().load_default().unwrap();
        for id in WORKLOADS {
            let fixture = Fixture::new(id, &config).unwrap();
            assert_eq!(
                fixture.input.len(),
                fixture
                    .fragments
                    .iter()
                    .map(|f| f.content().len())
                    .sum::<usize>()
            );
            assert!(fixture.admitted_rules >= 32);
            assert_eq!(
                std::str::from_utf8(&fixture.input).is_err(),
                id.contains("-invalid-")
            );
        }
    }

    #[test]
    fn fragment_invariants_reject_skipped_and_budget_terminated_scans() {
        let config = ConfigLoader::new().load_default().unwrap();
        let fixture = Fixture::new("core-fragments-json-16-kib", &config).unwrap();
        let detector = Engine::builder(config).build().unwrap();
        let options = ScanOptions::default();
        let complete = detector.scan_fragment(&fixture.fragments[0], &options);
        fixture.validate(&complete).unwrap();
        let skipped = detector.scan_fragment(&Fragment::builder(&b""[..]).build(), &options);
        assert!(fixture.validate(&skipped).is_err());
        let partial = detector.scan_fragment_controlled(
            &fixture.fragments[0],
            &options,
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_work_units(fixture.work_per_fragment - 1)),
        );
        assert!(fixture.validate(&partial).is_err());
    }
}
