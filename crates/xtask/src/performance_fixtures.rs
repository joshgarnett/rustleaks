//! Independent development fixtures. Generation and `--verify` never invoke a
//! scanner. Only the manual `--check` mode in `check.rs` runs one.
//!
//! Dense scaling and multiple decoded values in one carrier are independently
//! authored adaptations of benchmark ideas in Kingfisher commit
//! `01e7b817376fbf2272be8f162bd32309bf97ee1f`. No upstream code or fixture bytes
//! are incorporated. The existing performance workload lists are unchanged.

use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::fuzzing::private;
use crate::tooling::sha256_bytes;

#[path = "performance_fixtures/boundaries.rs"]
mod boundaries;
#[path = "performance_fixtures/check.rs"]
mod check;
#[path = "performance_fixtures/connections.rs"]
mod connections;
#[path = "performance_fixtures/density.rs"]
mod density;
#[cfg(test)]
#[path = "performance_fixtures/tests.rs"]
mod tests;
#[path = "performance_fixtures/verification.rs"]
mod verification;
#[path = "performance_fixtures/verification_details.rs"]
mod verification_details;
#[path = "performance_fixtures/verification_domain.rs"]
mod verification_domain;
#[path = "performance_fixtures/verification_seed.rs"]
mod verification_seed;

const DEVELOPMENT_SEED: &str = "rustleaks.kingfisher-expansion.v1.dev.2026-11-13";
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const FAMILIES: &[&str] = &[
    "boundaries",
    "density",
    "decoded-carrier",
    "connections",
    "partitions",
];

/// Offsets are zero-based, half-open byte intervals in the stated byte stream.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Plant {
    value: Vec<u8>,
    span: Range<usize>,
    carrier: Range<usize>,
}

struct Fixture {
    id: String,
    family: &'static str,
    input: Vec<u8>,
    /// Innermost to outermost payloads. Empty for an unencoded input.
    layers: Vec<Vec<u8>>,
    outer: Option<Range<usize>>,
    plants: Vec<Plant>,
    /// Construction evidence and policy requirements, never observed results.
    details: Value,
    timing_eligible: bool,
    pat_contract: bool,
}

impl Fixture {
    fn plain(id: String, family: &'static str, input: Vec<u8>) -> Self {
        Self {
            id,
            family,
            input,
            layers: Vec::new(),
            outer: None,
            plants: Vec::new(),
            details: json!({}),
            timing_eligible: false,
            pat_contract: true,
        }
    }

    fn plaintext(&self) -> &[u8] {
        self.layers.first().map_or(&self.input, Vec::as_slice)
    }

    fn validate_construction(&self) -> Result<(), String> {
        let plaintext = self.plaintext();
        for plant in &self.plants {
            if plaintext.get(plant.span.clone()) != Some(plant.value.as_slice())
                || plant.carrier.start > plant.span.start
                || plant.carrier.end < plant.span.end
                || plant.carrier.end > plaintext.len()
            {
                return Err(format!("{} has an invalid literal plant", self.id));
            }
        }
        if let Some(outer) = &self.outer {
            let last = self.layers.last().ok_or("encoded fixture lacks layers")?;
            if self.input.get(outer.clone()) != Some(STANDARD.encode(last).as_bytes()) {
                return Err(format!("{} outer encoding differs", self.id));
            }
            for pair in self.layers.windows(2) {
                if STANDARD.encode(&pair[0]).as_bytes() != pair[1].as_slice() {
                    return Err(format!("{} inner encoding differs", self.id));
                }
            }
        } else if !self.layers.is_empty() {
            return Err("unencoded fixture contains encoding layers".into());
        }
        if self.pat_contract {
            // Independent literal grammar census, not a scanner or regex call.
            // It also rejects an alleged negative containing a valid substring.
            let actual = plaintext
                .windows(40)
                .enumerate()
                .filter(|(_, bytes)| {
                    bytes.starts_with(b"ghp_") && bytes[4..].iter().all(u8::is_ascii_alphanumeric)
                })
                .map(|(start, bytes)| (start, bytes.to_vec()))
                .collect::<Vec<_>>();
            let expected = self
                .plants
                .iter()
                .map(|plant| (plant.span.start, plant.value.clone()))
                .collect::<Vec<_>>();
            if actual != expected {
                return Err(format!(
                    "{} literal PAT census differs from its plants",
                    self.id
                ));
            }
        }
        if self.details["identity_pattern"] == "unique"
            && self
                .plants
                .iter()
                .map(|plant| &plant.value)
                .collect::<BTreeSet<_>>()
                .len()
                != self.plants.len()
        {
            return Err(format!("{} distinct-value generator collided", self.id));
        }
        Ok(())
    }

    fn manifest(&self) -> Value {
        let plaintext = self.plaintext();
        let source_newlines = newline_offsets(&self.input);
        let plaintext_newlines = newline_offsets(plaintext);
        let plants = self.plants.iter().enumerate().map(|(ordinal, plant)| {
            json!({
                "ordinal": ordinal,
                "value": String::from_utf8_lossy(&plant.value),
                "value_sha256": sha256_bytes(&plant.value),
                "plaintext_secret_bytes": interval(&plant.span),
                "plaintext_carrier_bytes": interval(&plant.carrier),
                "physical_source_secret_bytes": if self.outer.is_none() { Some(interval(&plant.span)) } else { None },
                "physical_source_carrier_bytes": interval(self.outer.as_ref().unwrap_or(&plant.carrier)),
                "plaintext_position": physical_position(&plaintext_newlines, &plant.span),
                "source_carrier_position": physical_position(&source_newlines, self.outer.as_ref().unwrap_or(&plant.carrier)),
            })
        }).collect::<Vec<_>>();
        json!({
            "schema": "rustleaks.development-fixture.v1",
            "id": self.id,
            "family": self.family,
            "partition": "development",
            "expected_canonical_family": if self.pat_contract { Some("github-pat") } else { None },
            "expectation_scope": if self.pat_contract { "declared-canonical-family-only; unrelated-native-findings-are-not-rejected" } else { "unscored-connection-policy-proposal" },
            "rule_identity_contract": "retain-native-identifiers; canonical-family-mapping-requires-an-audited-profile-map",
            "input_path": format!("inputs/{}/input.txt", self.id),
            "input_bytes": self.input.len(),
            "input_sha256": sha256_bytes(&self.input),
            "plaintext_sha256": sha256_bytes(plaintext),
            "decode_depth": self.layers.len(),
            "physical_source_encoded_carrier_bytes": self.outer.as_ref().map(interval),
            "encoding_layers": self.layers.iter().map(|bytes| json!({"bytes": bytes.len(), "sha256": sha256_bytes(bytes)})).collect::<Vec<_>>(),
            "plants": plants,
            "expected_occurrences": self.pat_contract.then_some(self.plants.len()),
            "expected_unique_values": self.pat_contract.then(|| self.plants.iter().map(|plant| &plant.value).collect::<BTreeSet<_>>().len()),
            "literal_planted_values": self.plants.len(),
            "result_requirement": if self.pat_contract { "complete-with-exact-planted-occurrences" } else { "policy-review-required-before-scoring" },
            "timing_eligible_after_scope_and_quality_gate": self.timing_eligible,
            "coordinate_contract": {
                "intervals": "zero-based-half-open-physical-byte-offsets",
                "positions": "one-based-lines-and-byte-columns-LF-delimited",
                "legacy_columns": "not-the-physical-oracle; validate-legacy-coordinates-separately",
                "decoded_public_byte_ranges": "unavailable; retain-inner-and-outer-construction-spans-separately"
            },
            "details": self.details,
        })
    }
}

fn interval(range: &Range<usize>) -> Value {
    json!({"start": range.start, "end": range.end})
}

fn newline_offsets(bytes: &[u8]) -> Vec<usize> {
    bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        .collect()
}

fn physical_position(newlines: &[usize], span: &Range<usize>) -> Value {
    let position = |offset: usize| {
        let preceding = newlines.partition_point(|newline| *newline < offset);
        let line = preceding + 1;
        let column = preceding
            .checked_sub(1)
            .map_or(offset + 1, |index| offset - newlines[index]);
        json!({"line": line, "byte_column": column})
    };
    json!({"start": position(span.start), "end_exclusive": position(span.end)})
}

/// SHA-256 domain separation and rejection sampling are fixed fixture contracts.
fn seeded_value(family: &str, ordinal: usize, length: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(length);
    let mut counter = 0_usize;
    let limit = 256 / ALPHABET.len() * ALPHABET.len();
    while bytes.len() < length {
        let key = format!("{DEVELOPMENT_SEED}\0{family}\0development\0{ordinal}\0{counter}");
        for byte in Sha256::digest(key.as_bytes()) {
            if usize::from(byte) < limit {
                bytes.push(ALPHABET[usize::from(byte) % ALPHABET.len()]);
                if bytes.len() == length {
                    break;
                }
            }
        }
        counter += 1;
    }
    bytes
}

fn pat(family: &str, ordinal: usize) -> Vec<u8> {
    let mut value = b"ghp_".to_vec();
    value.extend(seeded_value(family, ordinal, 36));
    value
}

fn negative(mut value: Vec<u8>, prefix: bool) -> Vec<u8> {
    value[if prefix { 0 } else { 22 }] = if prefix { b'z' } else { b'_' };
    value
}

struct Request {
    output: PathBuf,
    family: String,
}

impl Request {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut output = None;
        let mut family = None;
        let mut arguments = arguments.iter();
        while let Some(flag) = arguments.next() {
            match flag.as_str() {
                "--output" if output.is_none() => output = Some(PathBuf::from(arguments.next().ok_or("missing output path")?)),
                "--family" if family.is_none() => family = Some(arguments.next().ok_or("missing fixture family")?.clone()),
                _ => return Err("usage: perf fixtures --family <boundaries|density|decoded-carrier|connections|partitions> --output <new-absolute-directory>".into()),
            }
        }
        let output = output.ok_or("fixtures require --output")?;
        let family = family.ok_or("fixtures require --family")?;
        if !output.is_absolute() || !FAMILIES.contains(&family.as_str()) {
            return Err("fixtures require an absolute output path and a declared family".into());
        }
        Ok(Self { output, family })
    }
}

pub(crate) fn run(arguments: &[String]) -> Result<(), String> {
    if let [flag, path] = arguments
        && flag == "--verify"
    {
        return verification::run(std::path::Path::new(path));
    }
    if arguments.iter().any(|argument| argument == "--check") {
        return check::run(arguments);
    }
    let request = Request::parse(arguments)?;
    let parent = request.output.parent().ok_or("missing output parent")?;
    private::checked_path(parent)?;
    let root = fs::canonicalize(crate::workspace_root()?).map_err(|error| error.to_string())?;
    if request.output.starts_with(root) {
        return Err("generated benchmark inputs and answers must be outside the checkout".into());
    }
    private::directory(&request.output)?;
    private::directory(&request.output.join("inputs"))?;
    private::directory(&request.output.join("answers"))?;
    let mut inventory = Vec::new();
    let mut emit = |fixture: Fixture| -> Result<(), String> {
        fixture.validate_construction()?;
        let manifest = fixture.manifest();
        let directory = request.output.join("inputs").join(&fixture.id);
        private::directory(&directory)?;
        private::write(&directory.join("input.txt"), &fixture.input)?;
        private::json(
            &request
                .output
                .join("answers")
                .join(format!("{}.json", fixture.id)),
            &manifest,
        )?;
        inventory.push(json!({
            "id": fixture.id,
            "input_sha256": manifest["input_sha256"],
            "input_bytes": fixture.input.len(),
            "expected_occurrences": manifest["expected_occurrences"],
            "manifest_path": format!("answers/{}.json", fixture.id),
            "manifest_sha256": sha256_bytes(&serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?),
        }));
        Ok(())
    };
    match request.family.as_str() {
        "boundaries" => boundaries::generate(&mut emit)?,
        "density" => density::generate(&mut emit)?,
        "decoded-carrier" => density::generate_decoded(&mut emit)?,
        "connections" => connections::generate(&mut emit)?,
        "partitions" => boundaries::generate_partitions(&mut emit)?,
        _ => unreachable!("request validated family"),
    }
    private::json(
        &request.output.join("inventory.json"),
        &json!({
            "schema": "rustleaks.development-fixtures.v1",
            "development_seed": DEVELOPMENT_SEED,
            "seed_recipe": "SHA256(seed || NUL || family || NUL || development || NUL || decimal-ordinal || NUL || decimal-counter); reject bytes >= 248; map accepted bytes modulo 62",
            "alphabet": String::from_utf8_lossy(ALPHABET),
            "family": request.family,
            "domain": "full-family-v1",
            "partition": "development",
            "logical_case_count": inventory.len(),
            "distinct_input_count": inventory.iter().filter_map(|case| case["input_sha256"].as_str()).collect::<BTreeSet<_>>().len(),
            "reader_schedule_expectations": if request.family == "partitions" { 16 } else { 0 },
            "cases": inventory,
            "scanners_invoked": false,
            "measurements_run": false,
            "construction_only": true,
            "input_scope": "each inputs/<case>/ directory independently; never scan the bundle root or answers",
        }),
    )?;
    println!(
        "constructed {} development cases; no scanner or timing was run",
        inventory.len()
    );
    Ok(())
}
