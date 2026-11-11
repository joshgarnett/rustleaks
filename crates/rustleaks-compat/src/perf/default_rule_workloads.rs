//! Default-rule scan workloads specified from generator plants.
//!
//! Expected findings, exact spans and work counts come from each generator's
//! plant list and from literal keyword counts over the configuration. No
//! expected value is read back from an engine scan. Go and Gitleaks semantics
//! are restated here (keyword lowercasing, `location()`, Shannon entropy) so a
//! behavior change surfaces as a fixture failure instead of a changed baseline.
//!
//! Default-config work is `1 + K + A + C`: one scan pass, one checkpoint per
//! overlapping keyword occurrence `K`, one per admitted rule `A`, and one per
//! regex candidate `C`.

use std::collections::BTreeSet;
use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::{CompiledConfig, ConfigLoader, DEFAULT_CONFIG_BYTES};
use rustleaks_core::model::{ByteRange, FindingRange, Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanOutcome};
use serde_json::{Value, json};

use super::{Phase, elapsed, fingerprint, outcome_signature, phase};

#[path = "default_rule_contention.rs"]
mod contention;
#[path = "default_rule_custom.rs"]
mod custom;
#[path = "default_rule_realistic.rs"]
mod realistic;

const KIB: usize = 1_024;
const MIB: usize = 1_024 * KIB;
const DEFAULT_RULE_COUNT: usize = 222;
const DEFAULT_RULES_FINGERPRINT: u64 = 0xbba0_f636_d5a0_2d49;
/// `generic-api-key` rejects a secret whose entropy does not exceed this value.
const GENERIC_ENTROPY: f64 = 3.5;
const GENERIC_RULE: &str = "generic-api-key";
const GITHUB_PAT_RULE: &str = "github-pat";

pub(super) const WORKLOADS: &[&str] = &[
    "core-admission-1-rules-4-mib",
    "core-admission-16-rules-4-mib",
    "core-admission-64-rules-4-mib",
    "core-admission-150-rules-4-mib",
    "core-prose-keywords-16-kib",
    "core-prose-keywords-1-mib",
    "core-near-miss-entropy-256-kib",
    "core-near-miss-stopword-256-kib",
    "core-near-miss-rule-allowlist-256-kib",
    "core-near-miss-global-allowlist-256-kib",
    "core-tiny-64-b",
    "core-tiny-128-b",
    "core-tiny-256-b",
    "core-tiny-512-b",
    "core-all-admitted-16-kib",
    "core-all-admitted-4-mib",
    "core-keyword-run-repeat-1-mib",
    "core-keyword-run-blob-1-mib",
    "core-prefix-storm-1-mib",
    "core-thrash-generic-1-mib",
    "core-multibyte-cjk-4-mib",
    "core-multibyte-cyrillic-4-mib",
    "core-groupless-private-key-64-kib",
    "core-groupless-ghp-4096",
    "core-generic-filter-4096",
    "core-generic-filter-16384",
    "core-generic-filter-65536",
    "core-minified-findings-1024-on-1-mib",
    "core-minified-findings-tail-256-kib",
    "core-minified-findings-huge-secret-64-kib",
    "core-realistic-lockfile-allowlisted-path-256-kib",
    "core-realistic-lockfile-other-path-256-kib",
    "core-realistic-env-256-kib",
    "core-realistic-k8s-yaml-256-kib",
    "core-realistic-jwt-log-256-kib",
    "core-realistic-multi-language-256-kib",
    "core-realistic-binary-256-kib",
    "core-realistic-utf16-256-kib",
    "core-custom-config-1000-rules",
    "core-custom-config-5000-rules",
    "core-custom-config-allowlist-heavy",
    "core-custom-config-keywordless-50",
    "core-long-lived-diverse",
    "core-contention-16-threads-512-b",
    "core-contention-32-threads-512-b",
    "core-contention-dense-8-threads-4-mib",
];

type Fallible<T> = Result<T, Box<dyn Error>>;

/// Filler vocabulary with no default keyword as a literal substring.
/// [`Census`] checks enforce this on every generated input.
const WORDS: &[&str] = &[
    "lorem",
    "ipsum",
    "dolor",
    "amet",
    "consectetur",
    "adipiscing",
    "elit",
    "tempor",
    "incididunt",
    "labore",
    "dolore",
    "magna",
    "aliqua",
    "enim",
    "minim",
    "veniam",
    "quis",
    "nostrud",
    "exercitation",
    "ullamco",
    "laboris",
    "nisi",
    "aliquip",
    "commodo",
    "consequat",
    "duis",
    "aute",
    "irure",
    "voluptate",
    "velit",
    "esse",
    "cillum",
    "fugiat",
    "nulla",
    "pariatur",
    "excepteur",
    "sint",
    "occaecat",
    "cupidatat",
    "proident",
    "sunt",
    "culpa",
    "officia",
    "deserunt",
    "mollit",
    "anim",
    "laborum",
];

/// Documentation sentences dense in generic keywords. They contain none of the
/// `generic-api-key` assignment operators, so no template rule can produce a
/// candidate: `=`, `>`, `:`, `|`, `?` and `,` are all absent.
const PROSE: &[&str] = &[
    "The service reads the api key from the environment and rotates the token every hour.\n",
    "Never commit a secret or password to version control and audit each auth change.\n",
    "An access token grants limited access while the refresh token stays in the secret store.\n",
    "Set the password policy before enabling password auth for new user accounts.\n",
    "Each api client presents a signed token and the auth layer validates the secret key.\n",
    "Rotate every credential after an incident and revoke the old api token at once.\n",
    "The key derivation step stretches the password before the secret reaches the database.\n",
    "Operators grant access per role so that each token carries the least auth scope.\n",
];

/// Characters that cannot spell a default keyword or `generic-api-key` stopword
/// except by the bounded checks in [`Forbidden`]. Vowels, `k`, `s` and `y` are
/// absent to rule out the short keywords `ey`, `sk`, `key` and `s.`.
const VALUE_ALPHABET: &[u8] = b"256789bcdfghjlmnpqrtvwxzBCDFGHJLMNPQRTVWXZ";
const VALUE_LETTERS: &[u8] = b"bcdfghjlmnpqrtvwxzBCDFGHJLMNPQRTVWXZ";
/// Restricted to characters that spell no default keyword except when planted.
const BLOB_ALPHABET: &[u8] = b"0123456789GHJMNPQRTUVWXZ+/";
const TOKEN_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

struct Lcg(u64);

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(0x5851_f42d_4c95_7f2d)
            .wrapping_add(0x1234_5678_9abc_def1);
        self.0 ^ (self.0 >> 32)
    }

    #[allow(clippy::cast_possible_truncation)] // The modulo keeps the result below `bound`.
    fn below(&mut self, bound: usize) -> usize {
        ((self.next() >> 16) % bound as u64) as usize
    }

    fn pick<'a, T: ?Sized>(&mut self, values: &'a [&'a T]) -> &'a T {
        values[self.below(values.len())]
    }

    fn string(&mut self, alphabet: &[u8], length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
    }
}

/// Keyword-view of the input under Go's `strings.ToLower`, for literal counting.
///
/// Per the pinned Unicode table only U+0130 and U+212A lowercase into ASCII, so
/// all other non-ASCII bytes can stay as they are: they can never complete an
/// ASCII keyword. Neither lead byte can be a UTF-8 continuation byte, so these
/// byte sequences always decode as those two code points.
fn keyword_view(input: &[u8]) -> Vec<u8> {
    if input.is_ascii() {
        return input.to_ascii_lowercase();
    }
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index..].starts_with(&[0xE2, 0x84, 0xAA]) {
            output.push(b'k');
            index += 3;
        } else if input[index..].starts_with(&[0xC4, 0xB0]) {
            output.push(b'i');
            index += 2;
        } else {
            output.push(input[index].to_ascii_lowercase());
            index += 1;
        }
    }
    output
}

/// Literal keyword occurrences, counted without the production automaton.
struct Census<'c> {
    occurrences: usize,
    matched: BTreeSet<&'c str>,
}

fn census<'c>(config: &'c CompiledConfig, input: &[u8]) -> Census<'c> {
    let view = keyword_view(input);
    let mut buckets = vec![Vec::new(); 256];
    for keyword in config.keywords() {
        if let Some(first) = keyword.as_bytes().first() {
            buckets[usize::from(*first)].push(keyword.as_str());
        }
    }
    let mut occurrences = 0;
    let mut matched = BTreeSet::new();
    for position in 0..view.len() {
        for keyword in &buckets[usize::from(view[position])] {
            if view[position..].starts_with(keyword.as_bytes()) {
                occurrences += 1;
                matched.insert(*keyword);
            }
        }
    }
    Census {
        occurrences,
        matched,
    }
}

/// Rules with no keywords are always admitted; others need one literal hit.
fn admitted_rules(config: &CompiledConfig, census: &Census<'_>) -> usize {
    config
        .rules()
        .values()
        .filter(|rule| {
            rule.keywords().is_empty()
                || rule
                    .keywords()
                    .iter()
                    .any(|keyword| census.matched.contains(keyword.as_str()))
        })
        .count()
}

/// Upstream `shannonEntropy`, summed in ascending symbol order. Go iterates a
/// map, so that order is the canonical choice among Go's admissible results.
/// Every planted secret is ASCII, which makes bytes and runes equivalent.
fn go_entropy(secret: &[u8]) -> Fallible<f64> {
    ensure(secret.is_ascii(), "planted secret must be ASCII")?;
    if secret.is_empty() {
        return Ok(0.0);
    }
    let mut counts = [0_u32; 128];
    for byte in secret {
        counts[usize::from(*byte)] += 1;
    }
    #[allow(clippy::cast_precision_loss)] // Secret lengths are far below 2^52.
    let inverse_length = 1.0 / secret.len() as f64;
    Ok(counts
        .iter()
        .filter(|count| **count > 0)
        .fold(0.0, |entropy, count| {
            let frequency = f64::from(*count) * inverse_length;
            entropy - frequency * frequency.log2()
        }))
}

fn ensure(condition: bool, message: &str) -> Fallible<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

#[derive(Default)]
struct GoLocation {
    start_line: usize,
    end_line: usize,
    start_column: usize,
    end_column: usize,
    start_index: usize,
    end_index: usize,
}

/// Restates the pinned upstream `location()` helper. Its per-newline loop is
/// replaced by binary search only because fixtures hold up to 65,536 plants.
fn go_location(newlines: &[usize], raw: &[u8], start: usize, end: usize) -> GoLocation {
    let mut location = GoLocation::default();
    let mut line_set = false;
    let start_line = newlines.partition_point(|newline| *newline <= start);
    if start_line < newlines.len() {
        line_set = true;
        let previous = start_line.checked_sub(1).map_or(0, |line| newlines[line]);
        location.start_line = start_line;
        location.end_line = start_line;
        location.start_column = start - previous + 1;
        location.start_index = previous;
        location.end_index = newlines[start_line];
    }
    let end_line = newlines.partition_point(|newline| *newline < end);
    if end_line < newlines.len() && (end_line != 0 || end > 0) {
        let previous = end_line.checked_sub(1).map_or(0, |line| newlines[line]);
        location.end_line = end_line;
        location.end_column = end - previous;
        location.end_index = newlines[end_line];
    }
    if !line_set {
        // Upstream's "no line matched" path: the line starts at zero and ends
        // at the first CR or LF after the match, or at the end of the raw text.
        let previous = newlines[newlines.len() - 1];
        location.start_line = newlines.len();
        location.end_line = newlines.len();
        location.start_column = start - previous + 1;
        location.end_column = end - previous;
        location.start_index = 0;
        location.end_index = raw[end..]
            .iter()
            .position(|byte| matches!(byte, b'\n' | b'\r'))
            .map_or(raw.len(), |distance| end + distance);
    }
    location
}

fn newline_positions(raw: &[u8]) -> Vec<usize> {
    let positions = raw
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        .collect::<Vec<_>>();
    if positions.is_empty() {
        // Upstream inserts one virtual newline for a fragment without any.
        vec![raw.len()]
    } else {
        positions
    }
}

struct RuleMeta {
    id: String,
    description: String,
}

/// A planted candidate that must survive every filter.
#[derive(Clone, Copy)]
struct Plant {
    rule: usize,
    /// Match span, excluding the trailing newlines that the engine trims.
    matched: (usize, usize),
    secret: (usize, usize),
}

struct ExpectedFinding {
    rule: usize,
    matched: (usize, usize),
    secret: (usize, usize),
    line: (usize, usize),
    location: [usize; 4],
    entropy: f32,
}

struct Expected {
    work: Option<usize>,
    findings: Vec<ExpectedFinding>,
}

struct Scan {
    fragment: Fragment,
    expected: Expected,
}

struct Plan {
    rules: Vec<RuleMeta>,
    scans: Vec<Scan>,
    scans_per_operation: usize,
    counts: Value,
}

struct Context<'c> {
    config: &'c CompiledConfig,
    rules: Vec<RuleMeta>,
}

impl<'c> Context<'c> {
    fn new(config: &'c CompiledConfig) -> Self {
        Self {
            config,
            rules: Vec::new(),
        }
    }

    fn rule_index(&mut self, id: &str) -> Fallible<usize> {
        if let Some(index) = self.rules.iter().position(|rule| rule.id == id) {
            return Ok(index);
        }
        let rule = self
            .config
            .rule(id)
            .ok_or_else(|| format!("fixture names unknown rule {id}"))?;
        self.rules.push(RuleMeta {
            id: id.to_owned(),
            description: rule.description().to_owned(),
        });
        Ok(self.rules.len() - 1)
    }

    /// Findings are ordered by rule id, as the engine's rule map iterates them,
    /// then by position within one rule's enumeration.
    fn expected(
        &self,
        raw: &[u8],
        mut plants: Vec<Plant>,
        candidates: usize,
    ) -> Fallible<Expected> {
        let census = census(self.config, raw);
        let admitted = admitted_rules(self.config, &census);
        plants.sort_by(|left, right| {
            self.rules[left.rule]
                .id
                .as_bytes()
                .cmp(self.rules[right.rule].id.as_bytes())
                .then(left.matched.0.cmp(&right.matched.0))
        });
        let newlines = newline_positions(raw);
        let mut findings = Vec::with_capacity(plants.len());
        for plant in plants {
            let location = go_location(&newlines, raw, plant.matched.0, plant.matched.1);
            #[allow(clippy::cast_possible_truncation)] // Finding entropy is stored as f32.
            let entropy = go_entropy(&raw[plant.secret.0..plant.secret.1])? as f32;
            findings.push(ExpectedFinding {
                rule: plant.rule,
                matched: plant.matched,
                secret: plant.secret,
                line: (location.start_index, location.end_index),
                location: [
                    location.start_line,
                    location.end_line,
                    location.start_column,
                    location.end_column,
                ],
                entropy,
            });
        }
        Ok(Expected {
            work: Some(1 + census.occurrences + admitted + candidates),
            findings,
        })
    }
}

fn validate(rules: &[RuleMeta], scan: &Scan, outcome: &ScanOutcome) -> Fallible<()> {
    let usage = outcome.usage();
    if !outcome.is_complete() || outcome.termination().is_some() {
        return Err(format!(
            "scan did not complete: {:?}; work {}",
            outcome.termination(),
            usage.work_units()
        )
        .into());
    }
    if usage.decoded_bytes() != 0 {
        return Err("depth-zero scan reported decoded bytes".into());
    }
    if usage.finding_records() != scan.expected.findings.len() {
        return Err(format!(
            "finding records {} differ from planted {}",
            usage.finding_records(),
            scan.expected.findings.len()
        )
        .into());
    }
    if let Some(work) = scan.expected.work
        && usage.work_units() != work
    {
        return Err(format!(
            "work units {} differ from independent count {work}",
            usage.work_units()
        )
        .into());
    }
    if outcome.findings().len() != scan.expected.findings.len() {
        return Err(format!(
            "retained findings {} differ from planted {}",
            outcome.findings().len(),
            scan.expected.findings.len()
        )
        .into());
    }
    let content = scan.fragment.content().as_bytes();
    for (index, (expected, actual)) in scan
        .expected
        .findings
        .iter()
        .zip(outcome.findings())
        .enumerate()
    {
        let rule = &rules[expected.rule];
        let location = actual.location();
        let exact = |(start, end)| FindingRange::Exact(ByteRange::new(start, end).expect("range"));
        let mismatch = if actual.rule_id().as_bytes() != rule.id.as_bytes() {
            Some("rule id")
        } else if actual.description().as_bytes() != rule.description.as_bytes() {
            Some("description")
        } else if [
            location.start_line(),
            location.end_line(),
            location.start_column(),
            location.end_column(),
        ] != expected.location
        {
            Some("location")
        } else if actual.match_range() != exact(expected.matched) {
            Some("match range")
        } else if actual.secret_range() != exact(expected.secret) {
            Some("secret range")
        } else if actual.match_text().as_bytes() != &content[expected.matched.0..expected.matched.1]
        {
            Some("match text")
        } else if actual.secret().as_bytes() != &content[expected.secret.0..expected.secret.1] {
            Some("secret")
        } else if actual.line().as_bytes() != &content[expected.line.0..expected.line.1] {
            Some("line")
        } else if actual.entropy().to_bits() != expected.entropy.to_bits() {
            Some("entropy")
        } else if actual.file().as_bytes() != scan.fragment.file_path().as_bytes()
            || actual.commit().as_bytes() != scan.fragment.commit().as_bytes()
            || !actual.symlink_file().as_bytes().is_empty()
        {
            Some("source metadata")
        } else if !actual.tags().is_empty() || !actual.required_findings().is_empty() {
            Some("tags or required findings")
        } else {
            None
        };
        if let Some(field) = mismatch {
            return Err(format!(
                "finding {index} of rule {} differs in {field}: observed location {location:?}, entropy {}, expected location {:?}, entropy {}",
                rule.id,
                actual.entropy(),
                expected.location,
                expected.entropy
            )
            .into());
        }
    }
    Ok(())
}

fn budget(expected: &Expected) -> ScanControl<'static> {
    ScanControl::unlimited().with_budget(
        ScanBudget::unlimited()
            .max_work_units(expected.work.unwrap_or(usize::MAX))
            .max_finding_records(expected.findings.len())
            .max_decoded_bytes(0),
    )
}

fn input_fingerprint(scans: &[Scan]) -> String {
    let mut hash = super::super::FNV_OFFSET;
    for scan in scans {
        hash = super::super::fnv_extend(hash, scan.fragment.content().as_bytes());
    }
    format!("{hash:016x}")
}

fn ensure_default_rules(config: &CompiledConfig) -> Fallible<()> {
    ensure(
        config.rules().len() == DEFAULT_RULE_COUNT
            && super::super::config_metric(config).fingerprint == DEFAULT_RULES_FINGERPRINT,
        "default configuration differs from the legacy invariant",
    )
}

fn operation_totals(plan: &Plan) -> (Value, usize) {
    let scans = plan.scans.len();
    let mut work = Some(0_usize);
    let mut findings = 0;
    for index in 0..plan.scans_per_operation {
        let expected = &plan.scans[index % scans].expected;
        work = work.zip(expected.work).map(|(total, one)| total + one);
        findings += expected.findings.len();
    }
    (work.map_or(Value::Null, |total| json!(total)), findings)
}

#[allow(clippy::too_many_lines)] // Keep first and steady operation timers auditable together.
pub(super) fn run(id: &str, iterations: usize) -> Fallible<Vec<Phase>> {
    if !WORKLOADS.contains(&id) {
        return Err(format!("unknown default-rule workload {id}").into());
    }
    if id.starts_with("core-contention-") {
        return contention::run(id, iterations);
    }
    let toml = custom::config_text(id);
    let start = Instant::now();
    let config = match toml.as_deref() {
        Some(text) => ConfigLoader::new().load_toml(text)?,
        None => ConfigLoader::new().load_default()?,
    };
    let compile_ns = elapsed(start)?;
    let config_bytes = toml.as_deref().map_or(DEFAULT_CONFIG_BYTES, str::as_bytes);
    if toml.is_none() {
        ensure_default_rules(&config)?;
    }
    let rule_count = config.rules().len() as u64;
    let plan = build(id, &config)?;
    let rule_ids = fingerprint(config.ordered_rule_ids().join("\0").as_bytes());
    let mut compile = phase(
        "config-parse-and-compile",
        1,
        compile_ns,
        config_bytes.len() as u64,
        "config-bytes",
        config_bytes,
        config_bytes,
    );
    compile.outcome_fnv1a64.clone_from(&rule_ids);
    compile.counts["rules"] = json!(rule_count);
    let start = Instant::now();
    let detector = Engine::builder(config).build()?;
    let mut build_phase = phase(
        "engine-construction",
        1,
        elapsed(start)?,
        rule_count,
        "compiled-rules",
        config_bytes,
        config_bytes,
    );
    build_phase.outcome_fnv1a64 = rule_ids;
    let options = ScanOptions::builder().max_decode_depth(0).build();
    let controls = plan
        .scans
        .iter()
        .map(|scan| budget(&scan.expected))
        .collect::<Vec<_>>();
    let input_hash = input_fingerprint(&plan.scans);
    let input_bytes = (0..plan.scans_per_operation)
        .map(|index| {
            plan.scans[index % plan.scans.len()]
                .fragment
                .content()
                .len() as u64
        })
        .sum::<u64>();
    let (work_units, findings) = operation_totals(&plan);
    let mut phases = vec![compile, build_phase];
    for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
        let mut result = phase(
            name,
            count,
            0,
            input_bytes,
            "input-bytes",
            &[],
            config_bytes,
        );
        result.input_fnv1a64.clone_from(&input_hash);
        result.findings = findings as u64;
        result.counts = json!({
            "workers": 1,
            "retained_outcomes": 1,
            "decode_depth": 0,
            "fragments": plan.scans.len(),
            "scans_per_operation": plan.scans_per_operation,
            "work_units": work_units,
            "finding_records": findings,
            "decoded_bytes": 0,
            "operation": "sum-of-fragment-scans-one-engine",
            "family": plan.counts,
        });
        for _ in 0..count {
            let mut signatures = vec![None; plan.scans.len()];
            for scan_index in 0..plan.scans_per_operation {
                let index = scan_index % plan.scans.len();
                let scan = &plan.scans[index];
                let start = Instant::now();
                let outcome = black_box(detector.scan_fragment_controlled(
                    black_box(&scan.fragment),
                    black_box(&options),
                    &controls[index],
                ));
                result.elapsed_ns += elapsed(start)?;
                validate(&plan.rules, scan, &outcome)?;
                let signature = outcome_signature(&outcome);
                match &signatures[index] {
                    Some(previous) if previous != &signature => {
                        return Err("repeated scan of one fragment changed its outcome".into());
                    }
                    Some(_) => {}
                    None => signatures[index] = Some(signature),
                }
            }
            let joined = signatures.into_iter().flatten().collect::<String>();
            let signature = fingerprint(joined.as_bytes());
            if result.outcome_fnv1a64 != fingerprint(&[]) && result.outcome_fnv1a64 != signature {
                return Err("default-rule operation changed between iterations".into());
            }
            result.outcome_fnv1a64 = signature;
        }
        phases.push(result);
    }
    Ok(phases)
}

fn single(ctx: Context<'_>, scan: Scan, counts: Value) -> Plan {
    Plan {
        rules: ctx.rules,
        scans: vec![scan],
        scans_per_operation: 1,
        counts,
    }
}

fn ascii_scan(ctx: &Context<'_>, raw: Vec<u8>, plants: Vec<Plant>, c: usize) -> Fallible<Scan> {
    let expected = ctx.expected(&raw, plants, c)?;
    Ok(Scan {
        fragment: Fragment::builder(raw).build(),
        expected,
    })
}

#[allow(clippy::too_many_lines)] // One flat dispatch keeps every fixed fixture size in a single place.
fn build(id: &str, config: &CompiledConfig) -> Fallible<Plan> {
    let mut ctx = Context::new(config);
    if let Some(plan) = custom::build(id, &mut ctx)? {
        return Ok(plan);
    }
    if id.starts_with("core-realistic-") || id == "core-long-lived-diverse" {
        return realistic::build(id, ctx);
    }
    let (scan, counts) = match id {
        "core-admission-1-rules-4-mib" => admission(&mut ctx, 1, 4 * MIB)?,
        "core-admission-16-rules-4-mib" => admission(&mut ctx, 16, 4 * MIB)?,
        "core-admission-64-rules-4-mib" => admission(&mut ctx, 64, 4 * MIB)?,
        "core-admission-150-rules-4-mib" => admission(&mut ctx, 150, 4 * MIB)?,
        "core-prose-keywords-16-kib" => prose(&ctx, 16 * KIB)?,
        "core-prose-keywords-1-mib" => prose(&ctx, MIB)?,
        "core-near-miss-entropy-256-kib" => near_miss(&ctx, Killer::Entropy, NEAR_MISS_LINES)?,
        "core-near-miss-stopword-256-kib" => near_miss(&ctx, Killer::Stopword, NEAR_MISS_LINES)?,
        "core-near-miss-rule-allowlist-256-kib" => {
            near_miss(&ctx, Killer::RuleAllowlist, NEAR_MISS_LINES)?
        }
        "core-near-miss-global-allowlist-256-kib" => {
            near_miss(&ctx, Killer::GlobalAllowlist, NEAR_MISS_LINES)?
        }
        "core-tiny-64-b" => return tiny(ctx, 64, TINY_FRAGMENTS),
        "core-tiny-128-b" => return tiny(ctx, 128, TINY_FRAGMENTS),
        "core-tiny-256-b" => return tiny(ctx, 256, TINY_FRAGMENTS),
        "core-tiny-512-b" => return tiny(ctx, 512, TINY_FRAGMENTS),
        "core-all-admitted-16-kib" => all_admitted(&ctx, 16 * KIB)?,
        "core-all-admitted-4-mib" => all_admitted(&ctx, 4 * MIB)?,
        "core-keyword-run-repeat-1-mib" => keyword_run_repeat(&ctx, MIB)?,
        "core-keyword-run-blob-1-mib" => keyword_run_blob(&ctx, MIB)?,
        "core-prefix-storm-1-mib" => prefix_storm(&ctx, MIB)?,
        "core-thrash-generic-1-mib" => thrash_generic(&ctx, MIB)?,
        "core-multibyte-cjk-4-mib" => multibyte(&mut ctx, Script::Cjk, 4 * MIB, 8)?,
        "core-multibyte-cyrillic-4-mib" => multibyte(&mut ctx, Script::Cyrillic, 4 * MIB, 8)?,
        "core-groupless-private-key-64-kib" => groupless_private_key(&mut ctx, 64 * KIB)?,
        "core-groupless-ghp-4096" => groupless_tokens(&mut ctx, 4_096)?,
        "core-minified-findings-1024-on-1-mib" => minified_one_line(&mut ctx, 1_024, MIB)?,
        "core-minified-findings-tail-256-kib" => minified_tail(&mut ctx, 1_024, 256 * KIB)?,
        "core-minified-findings-huge-secret-64-kib" => huge_secret(&mut ctx, 64 * KIB)?,
        _ => return Err(format!("unbuilt default-rule workload {id}").into()),
    };
    Ok(single(ctx, scan, counts))
}

/// Printable filler text that never contains a default keyword.
fn filler(size: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(size + 16);
    let mut word = 0;
    while output.len() < size {
        output.extend_from_slice(WORDS[word % WORDS.len()].as_bytes());
        word += 1;
        output.push(if word % 16 == 0 { b'\n' } else { b' ' });
    }
    output.truncate(size);
    output
}

const ADMISSION_WINDOW: usize = 4 * KIB;

/// Deterministic keywords that contain no other keyword, preferring one per
/// otherwise-uncovered rule so that admitted rules track the keyword count.
fn admission_keywords(config: &CompiledConfig, count: usize) -> Fallible<Vec<&str>> {
    let mut candidates = config
        .keywords()
        .iter()
        .map(String::as_str)
        .filter(|keyword| {
            keyword
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                && !config
                    .keywords()
                    .iter()
                    .any(|other| other != keyword && keyword.contains(other.as_str()))
        })
        .map(|keyword| {
            let owners = config
                .rules()
                .values()
                .filter(|rule| rule.keywords().iter().any(|owned| owned == keyword))
                .map(rustleaks_core::config::CompiledRule::id)
                .collect::<BTreeSet<_>>();
            (keyword, owners)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(keyword, owners)| (owners.len(), *keyword));
    let mut covered = BTreeSet::new();
    let mut selected = Vec::with_capacity(count);
    for (keyword, owners) in &candidates {
        if selected.len() < count && owners.is_disjoint(&covered) {
            covered.extend(owners.iter().copied());
            selected.push(*keyword);
        }
    }
    for (keyword, _) in &candidates {
        if selected.len() < count && !selected.contains(keyword) {
            selected.push(*keyword);
        }
    }
    ensure(
        selected.len() == count,
        "default config has too few independent keywords",
    )?;
    Ok(selected)
}

fn admission(ctx: &mut Context<'_>, count: usize, size: usize) -> Fallible<(Scan, Value)> {
    let selected = admission_keywords(ctx.config, count)?;
    let mut raw = Vec::with_capacity(size);
    for (index, keyword) in selected.iter().enumerate() {
        raw.extend_from_slice(keyword.as_bytes());
        raw.push(if (index + 1) % 8 == 0 { b'\n' } else { b' ' });
    }
    ensure(
        raw.len() <= ADMISSION_WINDOW,
        "admission keywords exceed their window",
    )?;
    raw.extend_from_slice(&filler(ADMISSION_WINDOW - raw.len()));
    raw.extend_from_slice(&filler(size - ADMISSION_WINDOW));
    let literal = census(ctx.config, &raw);
    ensure(
        literal.occurrences == count && literal.matched.len() == count,
        "admission input must hold each selected keyword exactly once",
    )?;
    let admitted = admitted_rules(ctx.config, &literal);
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((
        scan,
        json!({"distinct_keywords": count, "admitted_rules": admitted, "keyword_window_bytes": ADMISSION_WINDOW}),
    ))
}

fn prose(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    let mut raw = Vec::with_capacity(size + 128);
    let mut sentence = 0;
    while raw.len() < size {
        raw.extend_from_slice(PROSE[sentence % PROSE.len()].as_bytes());
        sentence += 1;
    }
    raw.truncate(size);
    let literal = census(ctx.config, &raw);
    let admitted = admitted_rules(ctx.config, &literal);
    let occurrences = literal.occurrences;
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((
        scan,
        json!({"keyword_occurrences": occurrences, "admitted_rules": admitted, "secrets": 0}),
    ))
}

/// Words a generated value must not contain, limited to those spelled wholly
/// from the generator's alphabet so that each check stays small.
struct Forbidden {
    words: Vec<Vec<u8>>,
}

impl Forbidden {
    fn new(config: &CompiledConfig, alphabets: &[&[u8]]) -> Fallible<Self> {
        let allowed = alphabets
            .iter()
            .flat_map(|alphabet| alphabet.iter())
            .map(u8::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        let rule = config
            .rule(GENERIC_RULE)
            .ok_or("default config has no generic-api-key rule")?;
        let words = config
            .keywords()
            .iter()
            .map(String::as_str)
            .chain(
                rule.allowlists()
                    .iter()
                    .flat_map(rustleaks_core::config::CompiledAllowlist::stop_words),
            )
            .filter(|word| word.bytes().all(|byte| allowed.contains(&byte)))
            .map(|word| word.as_bytes().to_vec())
            .collect();
        Ok(Self { words })
    }

    /// True when no word occurs in `value`, except an explicit planted word.
    fn clean(&self, value: &[u8], planted: Option<&[u8]>) -> bool {
        let lowered = value.to_ascii_lowercase();
        !self.words.iter().any(|word| {
            Some(word.as_slice()) != planted
                && lowered
                    .windows(word.len())
                    .any(|window| window == word.as_slice())
        })
    }
}

fn clean_value(
    rng: &mut Lcg,
    forbidden: &Forbidden,
    alphabet: &[u8],
    length: usize,
) -> Fallible<Vec<u8>> {
    for _ in 0..1_000 {
        let value = rng.string(alphabet, length);
        if forbidden.clean(&value, None) {
            return Ok(value);
        }
    }
    Err("no clean value within the attempt bound".into())
}

/// A value with at least one digit, which keeps it outside the rule allowlist
/// `^[a-zA-Z_.-]+$`, and with entropy above the generic threshold.
fn generic_value(rng: &mut Lcg, forbidden: &Forbidden, length: usize) -> Fallible<Vec<u8>> {
    for _ in 0..1_000 {
        let mut value = clean_value(rng, forbidden, VALUE_ALPHABET, length)?;
        value[0] = b'7';
        if forbidden.clean(&value, None) && go_entropy(&value)? > GENERIC_ENTROPY {
            return Ok(value);
        }
    }
    Err("no generic value within the attempt bound".into())
}

const NEAR_MISS_LINES: usize = 4_096;
/// A 64-byte line: the four bytes of `key=`, the value, and a newline.
const NEAR_MISS_VALUE: usize = 59;
const NEAR_MISS_ENTROPY_ALPHABET: &[u8] = b"0123456789a";
const NEAR_MISS_STOPWORD: &[u8] = b"000000";
const NEAR_MISS_GLOBAL_WORD: &[u8] = b"false";
const NEAR_MISS_PLANT_AT: usize = 20;

/// The single filter expected to reject every candidate of a near-miss input.
#[derive(Clone, Copy, Debug)]
enum Killer {
    Entropy,
    Stopword,
    RuleAllowlist,
    GlobalAllowlist,
}

#[cfg(test)]
impl Killer {
    /// Value offset and replacement byte that defeat only this killer.
    const fn positive_flip(self) -> (usize, u8) {
        match self {
            // A twelfth symbol takes eleven even symbols above 3.5 bits.
            Self::Entropy => (3, b'z'),
            // Breaks the stopword run; `x` cannot form a stopword from zeros.
            Self::Stopword => (NEAR_MISS_PLANT_AT + 2, b'x'),
            // A digit leaves the letters-only `^[a-zA-Z_.-]+$` allowlist.
            Self::RuleAllowlist => (0, b'7'),
            // Breaks `false`, the unanchored global `^true|false|null$` branch.
            Self::GlobalAllowlist => (NEAR_MISS_PLANT_AT + 2, b'7'),
        }
    }
}

fn near_miss_value(
    killer: Killer,
    line: usize,
    rng: &mut Lcg,
    forbidden: &[Forbidden; 3],
) -> Fallible<Vec<u8>> {
    match killer {
        Killer::Entropy => {
            // Eleven nearly even symbols stay at or below 3.5 bits; rotation
            // varies the bytes without changing the symbol counts' shape.
            let alphabet = NEAR_MISS_ENTROPY_ALPHABET;
            let value = (0..NEAR_MISS_VALUE)
                .map(|offset| alphabet[(offset + line) % alphabet.len()])
                .collect::<Vec<_>>();
            ensure(
                go_entropy(&value)? <= GENERIC_ENTROPY,
                "entropy near-miss exceeds the generic threshold",
            )?;
            Ok(value)
        }
        Killer::Stopword => {
            for _ in 0..1_000 {
                let mut value = clean_value(rng, &forbidden[0], VALUE_ALPHABET, NEAR_MISS_VALUE)?;
                value[0] = b'7';
                let run = NEAR_MISS_PLANT_AT..NEAR_MISS_PLANT_AT + NEAR_MISS_STOPWORD.len();
                value[run].copy_from_slice(NEAR_MISS_STOPWORD);
                if forbidden[1].clean(&value, Some(NEAR_MISS_STOPWORD))
                    && go_entropy(&value)? > GENERIC_ENTROPY
                {
                    return Ok(value);
                }
            }
            Err("no stopword near-miss within the attempt bound".into())
        }
        Killer::RuleAllowlist => {
            for _ in 0..1_000 {
                let value = clean_value(rng, &forbidden[0], VALUE_LETTERS, NEAR_MISS_VALUE)?;
                if go_entropy(&value)? > GENERIC_ENTROPY {
                    return Ok(value);
                }
            }
            Err("no letters-only near-miss within the attempt bound".into())
        }
        Killer::GlobalAllowlist => {
            for _ in 0..1_000 {
                let mut value = clean_value(rng, &forbidden[0], VALUE_ALPHABET, NEAR_MISS_VALUE)?;
                value[0] = b'7';
                let run = NEAR_MISS_PLANT_AT..NEAR_MISS_PLANT_AT + NEAR_MISS_GLOBAL_WORD.len();
                value[run].copy_from_slice(NEAR_MISS_GLOBAL_WORD);
                if forbidden[2].clean(&value, None) && go_entropy(&value)? > GENERIC_ENTROPY {
                    return Ok(value);
                }
            }
            Err("no global-allowlist near-miss within the attempt bound".into())
        }
    }
}

/// `key=<value>\n` lines: `key` starts each line, so the leftmost match of
/// `generic-api-key` begins at the line start. The value is one run of class
/// characters and the newline is the terminator. Each line is one candidate.
fn near_miss_input(ctx: &Context<'_>, killer: Killer, lines: usize) -> Fallible<Vec<u8>> {
    let forbidden = [
        Forbidden::new(ctx.config, &[VALUE_ALPHABET])?,
        Forbidden::new(ctx.config, &[VALUE_ALPHABET, NEAR_MISS_STOPWORD])?,
        Forbidden::new(ctx.config, &[VALUE_ALPHABET, NEAR_MISS_GLOBAL_WORD])?,
    ];
    let mut rng = Lcg::new(0x6e65_6172);
    let mut raw = Vec::with_capacity(lines * 64);
    for line in 0..lines {
        raw.extend_from_slice(b"key=");
        raw.extend_from_slice(&near_miss_value(killer, line, &mut rng, &forbidden)?);
        raw.push(b'\n');
    }
    Ok(raw)
}

fn near_miss(ctx: &Context<'_>, killer: Killer, lines: usize) -> Fallible<(Scan, Value)> {
    let raw = near_miss_input(ctx, killer, lines)?;
    let scan = ascii_scan(ctx, raw, Vec::new(), lines)?;
    Ok((
        scan,
        json!({"candidates": lines, "killer": format!("{killer:?}"), "findings": 0}),
    ))
}

const TINY_FRAGMENTS: usize = 100_000;

/// Every fragment carries a path and a commit that no default allowlist names,
/// so the global and rule-level commit and path checks all run. Contents hold
/// one `token` and otherwise only filler, which admits one rule beyond the
/// keywordless path rule and produces no candidate.
fn tiny(ctx: Context<'_>, size: usize, fragments: usize) -> Fallible<Plan> {
    let plan = tiny_scans(&ctx, size, fragments)?;
    Ok(Plan {
        rules: ctx.rules,
        scans: plan,
        scans_per_operation: fragments,
        counts: json!({"fragment_bytes": size, "fragments": fragments, "path_and_commit_set": true}),
    })
}

fn tiny_scans(ctx: &Context<'_>, size: usize, fragments: usize) -> Fallible<Vec<Scan>> {
    let content = tiny_content(ctx, size)?;
    let expected = ctx.expected(&content, Vec::new(), 0)?;
    let work = expected.work;
    let mut scans = Vec::with_capacity(fragments);
    for index in 0..fragments {
        scans.push(Scan {
            fragment: tiny_fragment(&content, index),
            expected: Expected {
                work,
                findings: Vec::new(),
            },
        });
    }
    Ok(scans)
}

fn tiny_content(ctx: &Context<'_>, size: usize) -> Fallible<Vec<u8>> {
    let mut content = b"token ".to_vec();
    content.extend_from_slice(&filler(size - content.len()));
    let literal = census(ctx.config, &content);
    ensure(
        literal.occurrences == 1 && literal.matched.contains("token"),
        "tiny content must hold exactly one keyword",
    )?;
    Ok(content)
}

fn tiny_fragment(content: &[u8], index: usize) -> Fragment {
    Fragment::builder(content)
        .file_path(format!("src/pkg{index:05}/module{index:05}.rs"))
        .commit(format!("{:040x}", index + 1))
        .build()
}

/// Every default keyword appears once. `<add key=` and `_gitlab_session=` are
/// the only keywords with an assignment operator, so they sit at the very end
/// with no valid value after them, and no keyword can start a candidate.
fn all_admitted(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const OPERATOR_KEYWORDS: [&str; 2] = ["_gitlab_session=", "<add key="];
    let mut raw = Vec::with_capacity(size);
    for (index, keyword) in ctx
        .config
        .keywords()
        .iter()
        .filter(|keyword| !OPERATOR_KEYWORDS.contains(&keyword.as_str()))
        .enumerate()
    {
        raw.extend_from_slice(keyword.as_bytes());
        raw.push(if (index + 1) % 8 == 0 { b'\n' } else { b' ' });
    }
    let tail = OPERATOR_KEYWORDS.join(" ");
    ensure(
        raw.len() + tail.len() < size,
        "keywords exceed the all-admitted size",
    )?;
    raw.extend_from_slice(&filler(size - raw.len() - tail.len()));
    raw.extend_from_slice(tail.as_bytes());
    let literal = census(ctx.config, &raw);
    let admitted = admitted_rules(ctx.config, &literal);
    // Independent of the engine: literal lowercase presence over the config.
    ensure(
        literal.matched.len() == ctx.config.keywords().len()
            && admitted == ctx.config.rules().len(),
        "all-admitted input must present every keyword and admit every rule",
    )?;
    let occurrences = literal.occurrences;
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((
        scan,
        json!({"admitted_rules": admitted, "keyword_occurrences": occurrences}),
    ))
}

/// `keykeykey...` has no assignment operator, so `generic-api-key` has no
/// candidate; `jwt`, admitted through `ey`, needs a dot that never occurs.
fn keyword_run_repeat(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    let mut raw = b"key".repeat(size / 3);
    raw.resize(size, b'x');
    let occurrences = census(ctx.config, &raw).occurrences;
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((scan, json!({"keyword_occurrences": occurrences})))
}

/// One operator-free base64-like line with keywords embedded every 512 bytes.
fn keyword_run_blob(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const PLANTED: [&[u8]; 7] = [
        b"key",
        b"token",
        b"secret",
        b"api",
        b"password",
        b"auth",
        b"credential",
    ];
    let mut raw = Lcg::new(0x626c_6f62).string(BLOB_ALPHABET, size);
    let clean = census(ctx.config, &raw);
    ensure(
        clean.occurrences == 0,
        "blob alphabet spelled a default keyword",
    )?;
    let mut planted = 0;
    let mut position = 256;
    while position + 16 < size {
        let word = PLANTED[planted % PLANTED.len()];
        raw[position..position + word.len()].copy_from_slice(word);
        planted += 1;
        position += 512;
    }
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((scan, json!({"planted_keywords": planted})))
}

/// Dense secret-like prefixes whose tails are far too short for any rule.
fn prefix_storm(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const PREFIXES: [&str; 12] = [
        "ghp_",
        "sk-",
        "xoxb-",
        "xoxp-",
        "github_pat_",
        "glpat-",
        "sk_live",
        "AKIA",
        "npm_",
        "dop_v1_",
        "hf_",
        "ops_",
    ];
    let mut rng = Lcg::new(0x7072_6566);
    let mut raw = Vec::with_capacity(size + 32);
    let mut tokens = 0;
    while raw.len() < size {
        raw.extend_from_slice(rng.pick(&PREFIXES).as_bytes());
        let tail = 1 + rng.below(6);
        raw.extend_from_slice(&rng.string(b"256789bcdfgh", tail));
        raw.push(b' ');
        tokens += 1;
    }
    raw.truncate(size);
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((scan, json!({"prefix_tokens": tokens})))
}

/// High-variety `generic-api-key` contexts with no candidate. Every line has a
/// keyword, separators and an operator, then a value of at most eight bytes
/// and a newline. The rule's value group needs at least ten bytes, and `:=`
/// can also parse as `:` with `=` leading the value (`[\w.=-]` holds `=`), so
/// nine value bytes would reach the minimum and form a real candidate.
fn thrash_generic(ctx: &Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const PREFIXES: [&str; 8] = [
        "",
        "svc.",
        "app-cfg_",
        "db.main.",
        "x-y-z.",
        "module_12.",
        "edge-node-7_",
        "tenant.a.b-c_",
    ];
    const KEYWORDS: [&str; 16] = [
        "access",
        "auth",
        "Api",
        "API",
        "api",
        "credential",
        "creds",
        "KEY",
        "key",
        "Key",
        "passwd",
        "password",
        "secret",
        "Secret",
        "token",
        "TOKEN",
    ];
    const SEPARATORS: [&str; 7] = ["", " ", "\t", "  ", ".setting", "-cfg", "_v2"];
    const OPERATORS: [&str; 9] = ["=", "=>", ":", ":=", "::=", "?=", "||", ",", ">"];
    const QUOTES: [&str; 3] = ["", "\"", "'"];
    let mut rng = Lcg::new(0x7468_7261);
    let mut raw = Vec::with_capacity(size + 80);
    let mut lines = 0;
    while raw.len() < size {
        raw.extend_from_slice(rng.pick(&PREFIXES).as_bytes());
        raw.extend_from_slice(rng.pick(&KEYWORDS).as_bytes());
        raw.extend_from_slice(rng.pick(&SEPARATORS).as_bytes());
        raw.extend_from_slice(rng.pick(&OPERATORS).as_bytes());
        raw.extend_from_slice(rng.pick(&QUOTES).as_bytes());
        let value_length = 1 + rng.below(8);
        raw.extend_from_slice(&rng.string(b"256789bcdfgh._-", value_length));
        raw.push(b'\n');
        lines += 1;
    }
    raw.truncate(size);
    let scan = ascii_scan(ctx, raw, Vec::new(), 0)?;
    Ok((scan, json!({"lines": lines})))
}

#[derive(Clone, Copy)]
enum Script {
    Cjk,
    Cyrillic,
}

const CJK_PROSE: &[&str] = &[
    "本文档介绍服务的部署方式与注意事项。配置文件需要妥善保管并定期更新。\n",
    "这是一段说明文字，用于展示多字节文本的处理性能。系统会逐行读取内容。\n",
    "これは説明文書のサンプルです。設定の内容を確認してから反映してください。\n",
    "運用チームは定期的に手順を見直し、変更履歴を記録しています。\n",
];

const CYRILLIC_PROSE: &[&str] = &[
    "ДОКУМЕНТАЦИЯ ОПИСЫВАЕТ РАЗВЕРТЫВАНИЕ СЕРВИСА И ПРАВИЛА ЭКСПЛУАТАЦИИ\n",
    "ОПЕРАТОРЫ ПРОВЕРЯЮТ ИЗМЕНЕНИЯ ПЕРЕД ВЫПУСКОМ НОВОЙ ВЕРСИИ СИСТЕМЫ\n",
    "ЖУРНАЛЫ ХРАНЯТСЯ ОТДЕЛЬНО И РЕГУЛЯРНО АРХИВИРУЮТСЯ АВТОМАТИЧЕСКИ\n",
    "КОМАНДА ОБНОВЛЯЕТ НАСТРОЙКИ ТОЛЬКО ПОСЛЕ ПОЛНОЙ ПРОВЕРКИ РЕЗУЛЬТАТА\n",
];

/// Plain-word line admitting rules without forming any candidate. `\u{212A}ey`
/// lowercases to the ASCII keyword `key` under Go's `strings.ToLower`, while
/// `\u{17F}ecret` stays non-ASCII and therefore never counts as `secret`.
const KEYWORD_LINE: &str = "key token secret api password auth \u{212A}ey \u{17F}ecret\n";

/// Keyword spellings for planted `generic-api-key` candidates.
///
/// `(?i)` makes Go fold `k` with U+212A and `s` with U+017F, so the regex
/// accepts all of these. Keyword admission is per fragment and already
/// satisfied by the plain `key` above, so `\u{17F}ecret=` is still scanned even
/// though it is not a literal keyword occurrence itself.
const MULTIBYTE_PLANTS: [&str; 4] = ["\u{212A}ey", "\u{212A}EY", "\u{17F}ecret", "token"];

/// Prose interrupted by planted candidates, each alone on its own line so the
/// leftmost match begins at the variant and the newline is the terminator.
fn multibyte(
    ctx: &mut Context<'_>,
    script: Script,
    size: usize,
    plants: usize,
) -> Fallible<(Scan, Value)> {
    let prose = match script {
        Script::Cjk => CJK_PROSE,
        Script::Cyrillic => CYRILLIC_PROSE,
    };
    let forbidden = Forbidden::new(ctx.config, &[VALUE_ALPHABET])?;
    let rule = ctx.rule_index(GENERIC_RULE)?;
    let mut rng = Lcg::new(0x6d62_7974);
    let mut raw = Vec::with_capacity(size + 256);
    raw.extend_from_slice(KEYWORD_LINE.as_bytes());
    let stride = size / (plants + 1);
    let mut planted = Vec::with_capacity(plants);
    let mut sentence = 0;
    while raw.len() < size {
        if planted.len() < plants && raw.len() >= stride * (planted.len() + 1) {
            let spelling = MULTIBYTE_PLANTS[planted.len() % MULTIBYTE_PLANTS.len()];
            let start = raw.len();
            raw.extend_from_slice(spelling.as_bytes());
            raw.push(b'=');
            let value = generic_value(&mut rng, &forbidden, 32)?;
            let secret = raw.len();
            raw.extend_from_slice(&value);
            planted.push(Plant {
                rule,
                matched: (start, raw.len()),
                secret: (secret, raw.len()),
            });
            raw.push(b'\n');
        }
        raw.extend_from_slice(prose[sentence % prose.len()].as_bytes());
        sentence += 1;
    }
    // Prose ends at a newline, so removing whole trailing lines keeps every
    // remaining code point valid and restores the exact requested size.
    while raw.len() > size {
        raw.pop();
        while raw.last().is_some_and(|byte| *byte != b'\n') {
            raw.pop();
        }
    }
    raw.resize(size, b'\n');
    ensure(
        std::str::from_utf8(&raw).is_ok(),
        "multibyte prose must remain valid UTF-8",
    )?;
    ensure(
        planted.iter().all(|plant| plant.matched.1 < raw.len()),
        "a planted multibyte candidate was truncated",
    )?;
    let count = planted.len();
    let scan = ascii_scan(ctx, raw, planted, count)?;
    Ok((scan, json!({"planted_findings": count})))
}

/// One PEM block filling the fragment. `private-key` has no capture group, so
/// the secret is the whole match, from `-----BEGIN` through the first
/// `KEY-----` after its 64-byte minimum body.
fn groupless_private_key(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const HEADER: &[u8] = b"-----BEGIN PRIVATE KEY-----\n";
    const FOOTER: &[u8] = b"-----END PRIVATE KEY-----";
    let rule = ctx.rule_index("private-key")?;
    let mut raw = b"synthetic fixture header line\n".to_vec();
    let start = raw.len();
    raw.extend_from_slice(HEADER);
    let mut rng = Lcg::new(0x7065_6d31);
    // Room for one 65-byte body line, the footer, and its terminating newline.
    while raw.len() + 65 + FOOTER.len() < size {
        raw.extend_from_slice(&rng.string(TOKEN_ALPHABET, 64));
        raw.push(b'\n');
    }
    raw.extend_from_slice(FOOTER);
    let end = raw.len();
    raw.push(b'\n');
    let filler_bytes = size - raw.len();
    raw.extend_from_slice(&filler(filler_bytes));
    let scan = ascii_scan(
        ctx,
        raw,
        vec![Plant {
            rule,
            matched: (start, end),
            secret: (start, end),
        }],
        1,
    )?;
    Ok((scan, json!({"block_bytes": end - start})))
}

fn ghp_token(rng: &mut Lcg) -> Vec<u8> {
    let mut token = b"ghp_".to_vec();
    token.extend_from_slice(&rng.string(TOKEN_ALPHABET, 36));
    token
}

/// `github-pat` has no capture group and no content allowlist: each synthetic
/// token is one candidate and its whole match is the secret.
fn groupless_tokens(ctx: &mut Context<'_>, tokens: usize) -> Fallible<(Scan, Value)> {
    let rule = ctx.rule_index(GITHUB_PAT_RULE)?;
    let mut rng = Lcg::new(0x6768_7030);
    let mut raw = Vec::with_capacity(tokens * 41);
    let mut plants = Vec::with_capacity(tokens);
    for _ in 0..tokens {
        let start = raw.len();
        raw.extend_from_slice(&ghp_token(&mut rng));
        plants.push(Plant {
            rule,
            matched: (start, raw.len()),
            secret: (start, raw.len()),
        });
        raw.push(b'\n');
    }
    let scan = ascii_scan(ctx, raw, plants, tokens)?;
    Ok((scan, json!({"tokens": tokens})))
}

/// Records of one synthetic token and `z` padding, with no newline anywhere.
fn minified_tokens(
    ctx: &mut Context<'_>,
    rng: &mut Lcg,
    raw: &mut Vec<u8>,
    tokens: usize,
    record: usize,
) -> Fallible<Vec<Plant>> {
    let rule = ctx.rule_index(GITHUB_PAT_RULE)?;
    let mut plants = Vec::with_capacity(tokens);
    for _ in 0..tokens {
        let start = raw.len();
        raw.extend_from_slice(&ghp_token(rng));
        plants.push(Plant {
            rule,
            matched: (start, raw.len()),
            secret: (start, raw.len()),
        });
        raw.push(b' ');
        raw.resize(start + record, b'z');
    }
    Ok(plants)
}

/// 1,024 accepted findings on one unbroken line. Each finding copies the whole
/// line, so this costs about 1 GiB of line bytes per scan by design.
fn minified_one_line(ctx: &mut Context<'_>, tokens: usize, size: usize) -> Fallible<(Scan, Value)> {
    let mut raw = Vec::with_capacity(size);
    let mut rng = Lcg::new(0x6d69_6e31);
    let plants = minified_tokens(ctx, &mut rng, &mut raw, tokens, size / tokens)?;
    ensure(raw.len() == size, "minified line must fill the fragment")?;
    let scan = ascii_scan(ctx, raw, plants, tokens)?;
    Ok((scan, json!({"findings_on_one_line": tokens})))
}

/// Findings after the last newline take upstream's no-line-matched location
/// path, in which each finding's line begins at offset zero.
fn minified_tail(ctx: &mut Context<'_>, tokens: usize, size: usize) -> Fallible<(Scan, Value)> {
    let mut raw = filler(60);
    raw.retain(|byte| *byte != b'\n');
    raw.push(b'\n');
    let mut rng = Lcg::new(0x6d69_6e32);
    let plants = minified_tokens(ctx, &mut rng, &mut raw, tokens, 255)?;
    ensure(raw.len() <= size, "tail records exceed the fragment")?;
    raw.resize(size, b'z');
    let scan = ascii_scan(ctx, raw, plants, tokens)?;
    Ok((scan, json!({"findings_after_last_newline": tokens})))
}

/// One 64 KiB `generic-api-key` secret. A `+` follows the first ten class bytes,
/// so the bounded `[\w.=-]{10,150}` alternative cannot reach a terminator and
/// the unbounded `[a-z0-9][a-z0-9+/]{11,}` alternative matches the whole run.
/// Twelve near-even symbols exceed the entropy threshold, and digits with `+`
/// and `/` cannot spell any stopword other than `000000`, which never occurs.
fn huge_secret(ctx: &mut Context<'_>, size: usize) -> Fallible<(Scan, Value)> {
    const CYCLE: &[u8] = b"0123456789+/";
    let rule = ctx.rule_index(GENERIC_RULE)?;
    let mut raw = b"key=".to_vec();
    let secret_start = raw.len();
    raw.extend((0..size).map(|index| CYCLE[index % CYCLE.len()]));
    let end = raw.len();
    ensure(
        go_entropy(&raw[secret_start..end])? > GENERIC_ENTROPY,
        "huge secret must exceed the generic entropy threshold",
    )?;
    raw.push(b'\n');
    let scan = ascii_scan(
        ctx,
        raw,
        vec![Plant {
            rule,
            matched: (0, end),
            secret: (secret_start, end),
        }],
        1,
    )?;
    Ok((scan, json!({"secret_bytes": size})))
}

#[cfg(test)]
#[path = "default_rule_tests.rs"]
mod tests;
