//! Decoder workloads with closed-form findings, decoded bytes and work counts.
//!
//! Expectations come from the generator and from reading the checkpoint charges
//! in `decoder/mod.rs` and `engine.rs`, never from engine output. A scan pass
//! charges one unit, plus one per keyword occurrence and, for an admitted rule,
//! one unit plus one per content-regex candidate. One decode attempt charges:
//!
//! * one dispatch unit;
//! * one unit per encoding-regex match;
//! * one shadow-filter unit per match, only when more than one match exists;
//! * one candidate unit per surviving match;
//! * one unit per predecessor for every candidate with a non-empty decoded
//!   value (the N x N term at `decoder/mod.rs:252-258`);
//! * one assembly unit per segment, when any segment exists.

use std::error::Error;
use std::hint::black_box;
use std::time::Instant;

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Finding, FindingRange, Fragment, Location, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanOutcome};
use serde_json::json;

use super::{FNV_OFFSET, Phase, SIMPLE_CONFIG, elapsed, fingerprint, fnv_extend, phase};

const KIB: usize = 1_024;
const MIB: usize = 1_024 * KIB;
const TOKEN: &[u8] = b"token=ABCDEFGHIJKLMNOP";
const TOKEN_PREFIX: usize = b"token=".len();
const SECRET: &[u8] = b"ABCDEFGHIJKLMNOP";
const KEYWORD: &[u8] = b"token";

// 20,000 is the shape requested for the depth-2 predecessor term: its N x N
// checkpoints stay within seconds per scan, so N was not reduced.
const MANY_LINES: usize = 20_000;
const LONG_TOKENS: usize = 10_000;
const LONG_STRIDE: usize = 104;
const LONG_BYTES: usize = MIB;
// 228-byte lockfile records fill 4 MiB with 16 bytes of padding.
const LOOKALIKE_RECORD_BYTES: usize = 228;
const LOOKALIKE_BYTES: usize = 4 * MIB;
const FILLER_LINE_BYTES: usize = 64;
const FILLER_LINES: usize = 4 * MIB / FILLER_LINE_BYTES;
const NEEDLE_LINE: usize = 32_000;
const HEX_UNICODE_PAIR_BYTES: usize = 182;
const HEX_UNICODE_BYTES: usize = 256 * KIB;

const ALLOWLISTED_CONFIG: &str = "\n[[allowlists]]\nregexes = ['''^ABCDEFGHIJKLMNOP$''']\n";
// Every word is shorter than the 16-byte base64 candidate floor. The text has
// no percent sign, backslash or `U+`, so the encoding regex has no match.
const WORDS: &[&str] = &[
    "the",
    "quiet",
    "river",
    "carried",
    "small",
    "stones",
    "past",
    "meadows",
    "under",
    "evening",
    "light",
    "while",
    "several",
    "herons",
    "watched",
    "patiently",
    "from",
    "reeds",
    "along",
    "northern",
    "banks",
];
// Six-letter words join into 24-letter identifiers. Letters only means the
// base64 decoder rejects them before attempting either alphabet.
const IDENTIFIER_WORDS: &[&str] = &[
    "render", "commit", "branch", "module", "vendor", "import", "export", "config", "widget",
    "stream", "parser", "buffer", "layout", "header", "footer", "socket", "router", "server",
    "client", "worker", "scheme", "filter", "format", "output", "source", "target", "result",
];

pub(super) const WORKLOADS: &[&str] = &[
    "core-decode-many-base64-depth-1",
    "core-decode-many-base64-depth-2",
    "core-decode-long-line-many-findings",
    "core-decode-long-line-allowlisted",
    "core-decode-lookalike-4-mib-depth-1",
    "core-decode-none-4-mib-depth-5",
    "core-decode-nested-needle-4-mib-depth-5",
    "core-decode-hex-unicode-256-kib",
];

enum Expected {
    Exact(Vec<Finding>),
    /// One line holds every token. Building 1 MiB `line` copies for each
    /// expected finding would double the workload's retained memory.
    LongLine {
        tokens: usize,
        stride: usize,
        token_bytes: usize,
    },
}

struct Fixture {
    input: Vec<u8>,
    config: String,
    expected: Expected,
    expected_findings: usize,
    depth: usize,
    decoded_bytes: usize,
    work_units: usize,
}

impl Fixture {
    fn control(&self) -> ScanControl<'static> {
        ScanControl::unlimited().with_budget(
            ScanBudget::unlimited()
                .max_work_units(self.work_units)
                .max_finding_records(self.expected_findings)
                .max_decoded_bytes(self.decoded_bytes),
        )
    }

    fn validate(&self, outcome: &ScanOutcome) -> Result<(), Box<dyn Error>> {
        let usage = outcome.usage();
        if !outcome.is_complete()
            || outcome.termination().is_some()
            || usage.work_units() != self.work_units
            || usage.decoded_bytes() != self.decoded_bytes
            || usage.finding_records() != self.expected_findings
            || outcome.findings().len() != self.expected_findings
        {
            return Err(format!(
                "decoder invariant failed: expected complete, work={}, decoded={}, records={}, findings={}; observed complete={}, work={}, decoded={}, records={}, findings={}",
                self.work_units,
                self.decoded_bytes,
                self.expected_findings,
                self.expected_findings,
                outcome.is_complete(),
                usage.work_units(),
                usage.decoded_bytes(),
                usage.finding_records(),
                outcome.findings().len(),
            )
            .into());
        }
        match &self.expected {
            Expected::Exact(expected) => {
                if let Some(index) = outcome
                    .findings()
                    .iter()
                    .zip(expected)
                    .position(|(observed, expected)| observed != expected)
                {
                    return Err(format!("decoder finding {index} differs from its plant").into());
                }
                Ok(())
            }
            Expected::LongLine {
                tokens,
                stride,
                token_bytes,
            } => self.validate_long_line(outcome, *tokens, *stride, *token_bytes),
        }
    }

    fn validate_long_line(
        &self,
        outcome: &ScanOutcome,
        tokens: usize,
        stride: usize,
        token_bytes: usize,
    ) -> Result<(), Box<dyn Error>> {
        if outcome.findings().len() != tokens {
            return Err("long-line finding count differs".into());
        }
        let tags = ["decoded:base64", "decode-depth:1"];
        for (index, finding) in outcome.findings().iter().enumerate() {
            let start = index * stride;
            let end = start + token_bytes;
            // A fragment with no newline uses the pinned fallback line: line
            // zero, previous offset zero, and the whole fragment as its line.
            let location = Location::new(0, 0, start + 1, end)?;
            if finding.rule_id().as_bytes() != b"token"
                || finding.description().as_bytes() != b"token"
                || finding.location() != location
                || finding.match_range() != FindingRange::Unavailable
                || finding.secret_range() != FindingRange::Unavailable
                || finding.match_text().as_bytes() != TOKEN
                || finding.secret().as_bytes() != SECRET
                || finding.entropy().to_bits() != secret_entropy(SECRET).to_bits()
                || finding.tags().len() != tags.len()
                || !finding
                    .tags()
                    .iter()
                    .zip(tags)
                    .all(|(observed, expected)| observed.as_bytes() == expected.as_bytes())
                || finding.line().as_bytes() != self.input.as_slice()
            {
                return Err(format!("long-line finding {index} differs from its plant").into());
            }
        }
        Ok(())
    }
}

/// Work charged by one decode attempt. Fixtures here have no shadowed matches,
/// so `matches` also counts the candidates reaching the segment loop.
const fn decode_work(matches: usize, segments: usize, predecessors: usize) -> usize {
    let shadow_filter = if matches > 1 { matches } else { 0 };
    1 + matches + shadow_filter + matches + segments * predecessors + segments
}

fn encode(input: &[u8]) -> Vec<u8> {
    super::super::base64(input)
}

fn hex_encode(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    input
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .collect()
}

fn unicode_escape(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .flat_map(|byte| format!("\\u{byte:04x}").into_bytes())
        .collect()
}

/// Deterministic bytes that the decoder's printable filter always rejects.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the eight high state bits are the deterministic byte"
)]
fn non_printable(seed: u32, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(2_654_435_761).wrapping_add(7);
            0x80 | (state >> 24) as u8
        })
        .collect()
}

/// Counts keyword windows independently of the prefilter under test.
fn keyword_occurrences(bytes: &[u8]) -> usize {
    bytes
        .to_ascii_lowercase()
        .windows(KEYWORD.len())
        .filter(|window| *window == KEYWORD)
        .count()
}

fn require_keyword_free(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if keyword_occurrences(bytes) != 0 {
        return Err("encoded fixture pass must contain no rule keyword".into());
    }
    Ok(())
}

/// A base64 plant must be a candidate, reach an alphabet, and not be hex.
fn require_base64_plant(encoded: &[u8]) -> Result<(), Box<dyn Error>> {
    let reaches_alphabet = encoded
        .iter()
        .any(|byte| matches!(byte, b'0'..=b'9' | b'+' | b'/' | b'-' | b'_'));
    let hex_prefix = encoded.len() >= 32 && encoded[..32].iter().all(u8::is_ascii_hexdigit);
    if encoded.len() < 16 || !reaches_alphabet || hex_prefix {
        return Err("base64 plant would not be classified as a decodable candidate".into());
    }
    Ok(())
}

// The histogram is independent of the engine's rune walk. Frequencies here are
// exact binary fractions because every secret has exactly 16 bytes.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn secret_entropy(secret: &[u8]) -> f32 {
    let mut counts = [0_usize; 256];
    for byte in secret {
        counts[usize::from(*byte)] += 1;
    }
    counts
        .iter()
        .filter(|count| **count > 0)
        .fold(0.0_f64, |entropy, count| {
            let frequency = *count as f64 / secret.len() as f64;
            entropy - frequency * frequency.log2()
        }) as f32
}

/// The original-source coordinates of one planted encoded span.
struct Span {
    line: usize,
    /// Offset of the preceding newline byte, or zero on line zero.
    previous: usize,
    /// Offset of the newline ending this line.
    line_end: usize,
    start: usize,
    end: usize,
}

// Pinned upstream columns are measured from the preceding newline byte, and a
// line after the first begins with that newline.
fn expected_finding(
    input: &[u8],
    span: &Span,
    decoded: &[u8],
    tags: &[&str],
) -> Result<Finding, Box<dyn Error>> {
    let secret = &decoded[TOKEN_PREFIX..];
    Ok(Finding::builder()
        .rule_id("token")
        .description("token")
        .location(Location::new(
            span.line,
            span.line,
            span.start - span.previous + 1,
            span.end - span.previous,
        )?)
        .line(&input[span.previous..span.line_end])
        .match_text(decoded)
        .secret(secret)
        .entropy(secret_entropy(secret))
        .tags(tags.iter().copied())
        .build()?)
}

fn many_base64(lines: usize, depth: usize) -> Result<Fixture, Box<dyn Error>> {
    if !(1..=2).contains(&depth) {
        return Err("many-base64 depth must be one or two".into());
    }
    let once = encode(TOKEN);
    require_base64_plant(&once)?;
    require_keyword_free(&once)?;
    let token = if depth == 1 {
        once.clone()
    } else {
        encode(&once)
    };
    require_base64_plant(&token)?;
    require_keyword_free(&token)?;
    let line_bytes = line_bytes_for(&token);
    let mut input = Vec::with_capacity(lines * line_bytes);
    for _ in 0..lines {
        input.extend_from_slice(b"k=");
        input.extend_from_slice(&token);
        input.push(b'\n');
    }
    let depth_tag = format!("decode-depth:{depth}");
    let tags = ["decoded:base64", depth_tag.as_str()];
    let mut expected = Vec::with_capacity(lines);
    for line in 0..lines {
        let start = line * line_bytes + b"k=".len();
        let end = start + token.len();
        let span = Span {
            line,
            previous: if line == 0 { 0 } else { line * line_bytes - 1 },
            line_end: end,
            start,
            end,
        };
        expected.push(expected_finding(&input, &span, TOKEN, &tags)?);
    }
    // Every encoded pass is keyword-free, so only the final decoded pass admits
    // the rule. It then charges one keyword hit and one candidate per line.
    let plain_pass = lines * line_bytes_for(TOKEN);
    let final_pass = 1 + lines + 1 + lines;
    let (decoded_bytes, work_units) = if depth == 1 {
        (plain_pass, 1 + decode_work(lines, lines, 0) + final_pass)
    } else {
        // Pass 1 decodes N candidates against the N segments of pass 0, which
        // charges N * N predecessor checkpoints. For N > 1 the total is
        // N * N + 10 * N + 6.
        (
            lines * line_bytes_for(&once) + plain_pass,
            1 + decode_work(lines, lines, 0) + 1 + decode_work(lines, lines, lines) + final_pass,
        )
    };
    Ok(Fixture {
        input,
        config: SIMPLE_CONFIG.to_owned(),
        expected_findings: expected.len(),
        expected: Expected::Exact(expected),
        depth,
        decoded_bytes,
        work_units,
    })
}

/// One `k=<token>` line including its newline.
const fn line_bytes_for(token: &[u8]) -> usize {
    b"k=".len() + token.len() + b"\n".len()
}

fn long_line(
    tokens: usize,
    stride: usize,
    total: usize,
    allowlisted: bool,
) -> Result<Fixture, Box<dyn Error>> {
    let token = encode(TOKEN);
    require_base64_plant(&token)?;
    require_keyword_free(&token)?;
    if stride <= token.len() || tokens * stride > total {
        return Err("long-line layout does not fit".into());
    }
    let mut input = Vec::with_capacity(total);
    for _ in 0..tokens {
        input.extend_from_slice(&token);
        input.resize(input.len() + stride - token.len(), b' ');
    }
    input.resize(total, b' ');
    let config = if allowlisted {
        format!("{SIMPLE_CONFIG}{ALLOWLISTED_CONFIG}")
    } else {
        SIMPLE_CONFIG.to_owned()
    };
    let expected_findings = if allowlisted { 0 } else { tokens };
    let expected = if allowlisted {
        Expected::Exact(Vec::new())
    } else {
        Expected::LongLine {
            tokens,
            stride,
            token_bytes: token.len(),
        }
    };
    Ok(Fixture {
        input,
        config,
        expected,
        expected_findings,
        depth: 1,
        decoded_bytes: total - tokens * (token.len() - TOKEN.len()),
        // Allowlisting removes findings after candidate charging, so both
        // variants charge the same work.
        work_units: 1 + decode_work(tokens, tokens, 0) + 1 + tokens + 1 + tokens,
    })
}

fn identifier(index: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(24);
    let mut remaining = index;
    for position in 0..4 {
        let word = IDENTIFIER_WORDS[remaining % IDENTIFIER_WORDS.len()].as_bytes();
        remaining /= IDENTIFIER_WORDS.len();
        if position == 0 {
            output.extend_from_slice(word);
        } else {
            output.push(word[0].to_ascii_uppercase());
            output.extend_from_slice(&word[1..]);
        }
    }
    output
}

/// Each record plants exactly three rejected candidates. The `sha512-` prefix
/// joins the base64 alphabet run, so neither alphabet accepts that span; the
/// digest and identifier reject at the printable filter and alphabet gate.
#[allow(
    clippy::cast_possible_truncation,
    reason = "record indices are bounded by the 4 MiB fixture"
)]
fn lookalike(records: usize, total: usize) -> Result<Fixture, Box<dyn Error>> {
    if records * LOOKALIKE_RECORD_BYTES > total {
        return Err("lookalike records exceed the fixture".into());
    }
    let mut input = Vec::with_capacity(total);
    for record in 0..records {
        let seed = record as u32;
        input.extend_from_slice(b"\"integrity\": \"sha512-");
        input.extend_from_slice(&encode(&non_printable(seed.wrapping_mul(3) + 1, 66)));
        input.extend_from_slice(b"==\",\n\"digest\": \"");
        input.extend_from_slice(&hex_encode(&non_printable(seed.wrapping_mul(5) + 2, 32)));
        input.extend_from_slice(b"\",\n\"name\": \"");
        input.extend_from_slice(&identifier(record));
        input.extend_from_slice(b"\",\n");
    }
    if input.len() != records * LOOKALIKE_RECORD_BYTES {
        return Err("lookalike record size changed".into());
    }
    input.resize(total, b' ');
    require_keyword_free(&input)?;
    let candidates = records * 3;
    Ok(Fixture {
        input,
        config: SIMPLE_CONFIG.to_owned(),
        expected: Expected::Exact(Vec::new()),
        expected_findings: 0,
        depth: 1,
        decoded_bytes: 0,
        // The pass start plus a decode attempt whose candidates all reject.
        work_units: 1 + decode_work(candidates, 0, 0),
    })
}

fn filler_lines(count: usize, first_line: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(count * FILLER_LINE_BYTES);
    for index in 0..count {
        let start = output.len();
        let mut word = (first_line + index) * 7;
        loop {
            let next = WORDS[word % WORDS.len()];
            let used = output.len() - start;
            let separator = usize::from(used != 0);
            if used + separator + next.len() > FILLER_LINE_BYTES - 1 {
                break;
            }
            if separator == 1 {
                output.push(b' ');
            }
            output.extend_from_slice(next.as_bytes());
            word += 1;
        }
        output.resize(start + FILLER_LINE_BYTES - 1, b' ');
        output.push(b'\n');
    }
    output
}

fn prose_none(lines: usize) -> Result<Fixture, Box<dyn Error>> {
    let input = filler_lines(lines, 0);
    require_keyword_free(&input)?;
    Ok(Fixture {
        input,
        config: SIMPLE_CONFIG.to_owned(),
        expected: Expected::Exact(Vec::new()),
        expected_findings: 0,
        depth: 5,
        decoded_bytes: 0,
        // One pass start and a decode dispatch whose encoding regex finds nothing.
        work_units: 2,
    })
}

fn nested_needle(before: usize, after: usize) -> Result<Fixture, Box<dyn Error>> {
    let mut chain = vec![TOKEN.to_vec()];
    for _ in 0..5 {
        let encoded = encode(&chain[chain.len() - 1]);
        require_base64_plant(&encoded)?;
        require_keyword_free(&encoded)?;
        chain.push(encoded);
    }
    let needle = &chain[5];
    let needle_line_bytes = 2 * FILLER_LINE_BYTES;
    if needle.len() >= needle_line_bytes {
        return Err("needle does not fit its line".into());
    }
    let mut input = filler_lines(before, 0);
    require_keyword_free(&input)?;
    let start = input.len();
    input.extend_from_slice(needle);
    let end = input.len();
    input.resize(start + needle_line_bytes - 1, b' ');
    let line_end = input.len();
    input.push(b'\n');
    let suffix = filler_lines(after, before + 2);
    require_keyword_free(&suffix)?;
    input.extend_from_slice(&suffix);
    let span = Span {
        line: before,
        previous: start.saturating_sub(1),
        line_end,
        start,
        end,
    };
    let expected = expected_finding(&input, &span, TOKEN, &["decoded:base64", "decode-depth:5"])?;
    // Pass k shrinks the needle from chain[5] to chain[5 - k] in place.
    let decoded_bytes = (1..=5)
        .map(|pass| input.len() - needle.len() + chain[5 - pass].len())
        .sum();
    // Pass 0 has no predecessors, passes 1 to 4 each compare against one
    // segment, and pass 5 charges its keyword, rule and candidate.
    let work_units = (1 + decode_work(1, 1, 0)) + 4 * (1 + decode_work(1, 1, 1)) + (1 + 1 + 1 + 1);
    Ok(Fixture {
        input,
        config: SIMPLE_CONFIG.to_owned(),
        expected_findings: 1,
        expected: Expected::Exact(vec![expected]),
        depth: 5,
        decoded_bytes,
        work_units,
    })
}

/// Alternating hex and `\uXXXX` lines, each decoding to one distinct finding.
fn hex_unicode(pairs: usize, total: usize) -> Result<Fixture, Box<dyn Error>> {
    if pairs * HEX_UNICODE_PAIR_BYTES > total {
        return Err("hex and unicode segments exceed the fixture".into());
    }
    let mut input = Vec::with_capacity(total);
    let mut expected = Vec::with_capacity(pairs * 2);
    let mut decoded_bytes = total;
    let mut previous = 0;
    for pair in 0..pairs {
        let plaintext = format!("token={pair:016}").into_bytes();
        for (kind, prefix, encoded) in [
            ("decoded:hex", b"h=", hex_encode(&plaintext)),
            ("decoded:unicode", b"u=", unicode_escape(&plaintext)),
        ] {
            require_keyword_free(&encoded)?;
            input.extend_from_slice(prefix);
            let start = input.len();
            input.extend_from_slice(&encoded);
            let end = input.len();
            input.push(b'\n');
            let span = Span {
                line: expected.len(),
                previous,
                line_end: end,
                start,
                end,
            };
            expected.push(expected_finding(
                &input,
                &span,
                &plaintext,
                &[kind, "decode-depth:1"],
            )?);
            previous = end;
            decoded_bytes -= encoded.len() - plaintext.len();
        }
    }
    input.resize(total, b' ');
    let segments = pairs * 2;
    Ok(Fixture {
        input,
        config: SIMPLE_CONFIG.to_owned(),
        expected_findings: expected.len(),
        expected: Expected::Exact(expected),
        depth: 1,
        decoded_bytes,
        // Every decoded line holds one keyword occurrence and one candidate.
        work_units: 1 + decode_work(segments, segments, 0) + 1 + segments + 1 + segments,
    })
}

fn fixture(id: &str) -> Result<Fixture, Box<dyn Error>> {
    match id {
        "core-decode-many-base64-depth-1" => many_base64(MANY_LINES, 1),
        "core-decode-many-base64-depth-2" => many_base64(MANY_LINES, 2),
        "core-decode-long-line-many-findings" => {
            long_line(LONG_TOKENS, LONG_STRIDE, LONG_BYTES, false)
        }
        "core-decode-long-line-allowlisted" => {
            long_line(LONG_TOKENS, LONG_STRIDE, LONG_BYTES, true)
        }
        "core-decode-lookalike-4-mib-depth-1" => {
            lookalike(LOOKALIKE_BYTES / LOOKALIKE_RECORD_BYTES, LOOKALIKE_BYTES)
        }
        "core-decode-none-4-mib-depth-5" => prose_none(FILLER_LINES),
        "core-decode-nested-needle-4-mib-depth-5" => {
            nested_needle(NEEDLE_LINE, FILLER_LINES - NEEDLE_LINE - 2)
        }
        "core-decode-hex-unicode-256-kib" => hex_unicode(
            HEX_UNICODE_BYTES / HEX_UNICODE_PAIR_BYTES,
            HEX_UNICODE_BYTES,
        ),
        _ => Err(format!("unknown decoder workload {id}").into()),
    }
}

/// Finding bytes are compared in `validate`, so this hash records only each
/// line's length. Hashing 1 MiB per finding would dominate the long-line loop.
fn outcome_signature(outcome: &ScanOutcome) -> String {
    let mut hash = FNV_OFFSET;
    for finding in outcome.findings() {
        for bytes in [
            finding.rule_id().as_bytes(),
            finding.match_text().as_bytes(),
        ] {
            hash = fnv_extend(hash, bytes);
            hash = fnv_extend(hash, &[0xff]);
        }
        hash = fnv_extend(hash, finding.secret().as_bytes());
        let location = finding.location();
        for value in [
            location.start_line(),
            location.end_line(),
            location.start_column(),
            location.end_column(),
            finding.line().len(),
            finding.tags().len(),
        ] {
            hash = fnv_extend(hash, &(value as u64).to_le_bytes());
        }
        for tag in finding.tags() {
            hash = fnv_extend(hash, tag.as_bytes());
        }
    }
    for value in [
        outcome.usage().decoded_bytes(),
        outcome.usage().work_units(),
        outcome.usage().finding_records(),
    ] {
        hash = fnv_extend(hash, &(value as u64).to_le_bytes());
    }
    format!("{hash:016x}")
}

pub(super) fn run(id: &str, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    run_fixture(&fixture(id)?, iterations)
}

fn run_fixture(fixture: &Fixture, iterations: usize) -> Result<Vec<Phase>, Box<dyn Error>> {
    let config_bytes = fixture.config.as_bytes();
    let start = Instant::now();
    let config = black_box(ConfigLoader::new().load_toml(&fixture.config)?);
    let compile_ns = elapsed(start)?;
    if config.rules().len() != 1 {
        return Err("decoder fixture must compile exactly one rule".into());
    }
    let rule_ids = config.ordered_rule_ids().join("\0");
    let mut compile = phase(
        "config-parse-and-compile",
        1,
        compile_ns,
        config_bytes.len() as u64,
        "config-bytes",
        config_bytes,
        config_bytes,
    );
    compile.outcome_fnv1a64 = fingerprint(rule_ids.as_bytes());
    compile.counts["rules"] = json!(1);
    let start = Instant::now();
    let detector = black_box(Engine::builder(config).build()?);
    let mut build = phase(
        "engine-construction",
        1,
        elapsed(start)?,
        1,
        "compiled-rules",
        config_bytes,
        config_bytes,
    );
    build.outcome_fnv1a64.clone_from(&compile.outcome_fnv1a64);
    let fragment = Fragment::builder(fixture.input.clone()).build();
    let options = ScanOptions::builder()
        .max_decode_depth(fixture.depth)
        .build();
    let control = fixture.control();
    let mut phases = vec![compile, build];
    for (name, count) in [("first-scan", 1), ("steady-scan", iterations)] {
        let mut result = phase(
            name,
            count,
            0,
            fixture.input.len() as u64,
            "input-bytes",
            &fixture.input,
            config_bytes,
        );
        result.counts = json!({
            "workers": 1,
            "retained_outcomes": 1,
            "operation": "scan-with-decoding",
            "decode_depth": fixture.depth,
            "decoded_bytes": fixture.decoded_bytes,
            "work_units": fixture.work_units,
            "finding_records": fixture.expected_findings,
        });
        result.findings = fixture.expected_findings as u64;
        for _ in 0..count {
            let start = Instant::now();
            let outcome = black_box(detector.scan_fragment_controlled(
                black_box(&fragment),
                black_box(&options),
                &control,
            ));
            result.elapsed_ns += elapsed(start)?;
            fixture.validate(&outcome)?;
            let signature = outcome_signature(&outcome);
            if result.outcome_fnv1a64 != fingerprint(&[]) && result.outcome_fnv1a64 != signature {
                return Err("decoder outcome changed between iterations".into());
            }
            result.outcome_fnv1a64 = signature;
        }
        phases.push(result);
    }
    Ok(phases)
}

#[cfg(test)]
mod tests {
    use rustleaks_core::ScanTermination;

    use super::*;

    fn scan(fixture: &Fixture, control: &ScanControl<'_>) -> ScanOutcome {
        Engine::builder(ConfigLoader::new().load_toml(&fixture.config).unwrap())
            .build()
            .unwrap()
            .scan_fragment_controlled(
                &Fragment::builder(fixture.input.clone()).build(),
                &ScanOptions::builder()
                    .max_decode_depth(fixture.depth)
                    .build(),
                control,
            )
    }

    fn assert_controls_pass(fixture: &Fixture) {
        fixture
            .validate(&scan(fixture, &fixture.control()))
            .unwrap();
    }

    #[test]
    fn depth_two_work_matches_a_hand_counted_case() {
        // Four lines. Pass 0: start 1; decode 1 dispatch + 4 matches +
        // 4 shadow + 4 candidates + 4 assembly = 17. Pass 1: start 1; decode
        // 17 + 16 predecessor checkpoints = 33. Pass 2: start 1 + 4 keyword
        // hits + 1 rule + 4 candidates. Sum: 1 + 17 + 1 + 33 + 1 + 4 + 1 + 4.
        let fixture = many_base64(4, 2).unwrap();
        assert_eq!(fixture.work_units, 62);
        assert_eq!(fixture.work_units, 4 * 4 + 10 * 4 + 6);
        assert_eq!(fixture.expected_findings, 4);
        assert_controls_pass(&fixture);
        let outcome = scan(&fixture, &fixture.control());
        assert_eq!(outcome.usage().work_units(), 62);
        assert!(outcome.findings().iter().all(|finding| {
            finding
                .tags()
                .iter()
                .any(|tag| tag.as_bytes() == b"decode-depth:2")
        }));
    }

    #[test]
    fn depth_one_many_lines_matches_its_closed_form() {
        let fixture = many_base64(5, 1).unwrap();
        assert_eq!(fixture.work_units, 6 * 5 + 4);
        assert_eq!(fixture.decoded_bytes, 5 * line_bytes_for(TOKEN));
        assert_controls_pass(&fixture);
    }

    #[test]
    fn long_line_controls_cover_retained_and_allowlisted_tokens() {
        let retained = long_line(4, 64, 400, false).unwrap();
        assert_eq!(retained.work_units, 6 * 4 + 4);
        assert_controls_pass(&retained);
        let allowlisted = long_line(4, 64, 400, true).unwrap();
        assert_eq!(allowlisted.work_units, retained.work_units);
        assert_eq!(allowlisted.decoded_bytes, retained.decoded_bytes);
        assert_controls_pass(&allowlisted);
        assert!(
            allowlisted
                .validate(&scan(&retained, &retained.control()))
                .is_err()
        );
    }

    #[test]
    fn lookalike_records_reject_every_candidate() {
        let fixture = lookalike(8, 8 * LOOKALIKE_RECORD_BYTES).unwrap();
        assert_eq!(fixture.work_units, 1 + 1 + 3 * 24);
        assert_controls_pass(&fixture);
    }

    #[test]
    fn prose_without_candidates_charges_only_the_decode_dispatch() {
        let fixture = prose_none(16).unwrap();
        assert_eq!(fixture.work_units, 2);
        assert_controls_pass(&fixture);
    }

    #[test]
    fn nested_needle_maps_five_passes_to_the_original_span() {
        let fixture = nested_needle(2, 2).unwrap();
        assert_eq!(fixture.work_units, 33);
        assert_controls_pass(&fixture);
    }

    #[test]
    fn hex_unicode_lines_decode_to_per_segment_findings() {
        let fixture = hex_unicode(3, 3 * HEX_UNICODE_PAIR_BYTES).unwrap();
        assert_eq!(fixture.work_units, 6 * 6 + 4);
        assert_controls_pass(&fixture);
    }

    #[test]
    fn declared_workloads_keep_their_fixed_shapes() {
        for id in WORKLOADS {
            let fixture = fixture(id).unwrap();
            assert!(fixture.input.len() <= 4 * MIB, "{id}");
        }
        assert_eq!(
            fixture("core-decode-none-4-mib-depth-5")
                .unwrap()
                .input
                .len(),
            4 * MIB
        );
        assert_eq!(
            fixture("core-decode-nested-needle-4-mib-depth-5")
                .unwrap()
                .input
                .len(),
            4 * MIB
        );
        assert_eq!(
            fixture("core-decode-lookalike-4-mib-depth-1")
                .unwrap()
                .input
                .len(),
            4 * MIB
        );
        assert_eq!(
            fixture("core-decode-hex-unicode-256-kib")
                .unwrap()
                .input
                .len(),
            256 * KIB
        );
        assert_eq!(
            fixture("core-decode-long-line-many-findings")
                .unwrap()
                .input
                .len(),
            MIB
        );
        assert!(fixture("unknown").is_err());
    }

    #[test]
    fn skipped_and_budget_terminated_scans_are_rejected() {
        let fixture = many_base64(4, 2).unwrap();
        let unlimited = ScanControl::unlimited();
        let empty = Fixture {
            input: Vec::new(),
            ..many_base64(4, 2).unwrap()
        };
        assert!(fixture.validate(&scan(&empty, &unlimited)).is_err());
        let partial = scan(
            &fixture,
            &ScanControl::unlimited()
                .with_budget(ScanBudget::unlimited().max_work_units(fixture.work_units - 1)),
        );
        assert!(!partial.is_complete());
        assert!(matches!(
            partial.termination(),
            Some(ScanTermination::BudgetExceeded { .. })
        ));
        assert!(fixture.validate(&partial).is_err());
    }

    #[test]
    fn phases_report_the_required_order_and_fixed_identities() {
        let fixture = many_base64(4, 1).unwrap();
        let phases = run_fixture(&fixture, 2).unwrap();
        assert_eq!(
            phases
                .iter()
                .map(|phase| phase.phase.as_str())
                .collect::<Vec<_>>(),
            [
                "config-parse-and-compile",
                "engine-construction",
                "first-scan",
                "steady-scan"
            ]
        );
        assert_eq!(phases[2].outcome_fnv1a64, phases[3].outcome_fnv1a64);
        assert_eq!(phases[3].iterations, 2);
    }
}
