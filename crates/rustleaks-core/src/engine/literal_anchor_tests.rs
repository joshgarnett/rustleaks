use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;

use super::*;
use crate::config::ConfigLoader;
use crate::explanation::ExplanationOptions;
use crate::model::ByteText;

const TEMPLATE_PREFIX: &str = r"(?i)[\w.-]{0,50}?";
const DOUBLE_PREFIX: &str = r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?";
/// Template-shaped default rules that must stay on the full search.
///
/// `atlassian-api-token` has a top-level alternation. In every other rule the
/// regex literal is absent from the rule's keywords, so recording keyword
/// occurrences would not cover it: for example `lob` against `test_`/`live_`,
/// and `new-york-times,` against `new-york-times`.
const TEMPLATES_WITHOUT_KEYWORD_LITERALS: [&str; 8] = [
    "atlassian-api-token",
    "lob-api-key",
    "lob-pub-api-key",
    "new-relic-browser-api-token",
    "new-relic-insert-key",
    "new-relic-user-api-key",
    "nytimes-access-token",
    "typeform-api-token",
];

struct AnchoredRule<'a> {
    rule: &'a CompiledRule,
    regex: &'a GoRegex,
    anchor: &'a RuleLiteralAnchor,
}

fn default_engine() -> Engine {
    Engine::builder(ConfigLoader::new().load_default().unwrap())
        .build()
        .unwrap()
}

fn anchored_rules(engine: &Engine) -> Vec<AnchoredRule<'_>> {
    engine
        .config
        .rules
        .values()
        .zip(&engine.rule_literal_anchors)
        .filter_map(|(rule, anchor)| {
            Some(AnchoredRule {
                rule,
                regex: rule.regex_matcher.as_ref()?,
                anchor: anchor.as_ref()?,
            })
        })
        .collect()
}

fn without_anchors(engine: &Engine) -> Engine {
    let mut disabled = engine.clone();
    disabled
        .rule_literal_anchors
        .iter_mut()
        .for_each(|anchor| *anchor = None);
    disabled.recorded_keywords.clear();
    disabled
}

/// All occurrences from the production keyword automaton, without any limit.
fn automaton_occurrences(engine: &Engine, indexes: &[usize], lowered: &[u8]) -> Vec<usize> {
    let mut starts = engine
        .prefilter
        .as_ref()
        .unwrap()
        .find_overlapping_iter(lowered)
        .filter(|found| indexes.contains(&found.pattern().as_usize()))
        .map(|found| found.start())
        .collect::<Vec<_>>();
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// Compares both enumeration paths and returns the number of matches.
fn assert_paths_agree(
    engine: &Engine,
    rule: &AnchoredRule<'_>,
    input: &[u8],
    label: &str,
) -> usize {
    if !input.is_ascii() {
        return 0;
    }
    let normalized = NormalizedHaystack::new(input);
    let expected = rule.regex.find_all_normalized(&normalized);
    let starts = automaton_occurrences(
        engine,
        &rule.anchor.keyword_indexes,
        &input.to_ascii_lowercase(),
    );
    assert_eq!(
        rule.regex
            .find_all_literal_anchored_unbudgeted(&normalized, &starts)
            .unwrap(),
        expected,
        "{label}: anchored enumeration differs for {} on {:?}",
        rule.rule.id,
        String::from_utf8_lossy(input)
    );
    // A budgeted run may decline, but must never disagree when it completes.
    if let Some(budgeted) =
        rule.regex
            .find_all_literal_anchored(&normalized, rule.anchor.candidate, &starts)
    {
        assert_eq!(budgeted, expected, "{label}: budgeted result");
    }
    assert_eq!(
        rule.regex.find_all(input),
        expected,
        "{label}: reference enumeration"
    );
    expected.len()
}

#[test]
fn default_config_eligibility_is_exactly_the_keyword_templates() {
    let engine = default_engine();
    let anchored = anchored_rules(&engine);
    let eligible = anchored
        .iter()
        .map(|rule| rule.rule.id.as_str())
        .collect::<Vec<_>>();
    let expected = engine
        .config
        .rules
        .values()
        .filter(|rule| {
            let source = rule.regex.as_deref().unwrap_or_default();
            (source.starts_with(TEMPLATE_PREFIX) || source.starts_with(DOUBLE_PREFIX))
                && !TEMPLATES_WITHOUT_KEYWORD_LITERALS.contains(&rule.id.as_str())
        })
        .map(|rule| rule.id.as_str())
        .collect::<Vec<_>>();
    // Derived from the rule source text and the reviewed list below, not from
    // the analysis under test.
    assert_eq!(eligible, expected);
    assert_eq!(eligible.len(), 93);
    for id in [
        "cisco-meraki-api-key",
        "cohere-api-token",
        "generic-api-key",
        "okta-access-token",
        "privateai-api-token",
        "sumologic-access-id",
    ] {
        assert!(eligible.contains(&id), "{id} must be eligible");
    }
    for id in [
        "azure-ad-client-secret",
        "hashicorp-tf-api-token",
        "maxmind-license-key",
        "sourcegraph-access-token",
    ]
    .into_iter()
    .chain(TEMPLATES_WITHOUT_KEYWORD_LITERALS)
    {
        assert!(!eligible.contains(&id), "{id} must stay on the full search");
    }
    // Every recorded keyword is consumed by a plan and no other is recorded.
    let mut consumed = vec![false; engine.keyword_count];
    for rule in &anchored {
        assert!(!rule.anchor.keyword_indexes.is_empty());
        for &keyword in &rule.anchor.keyword_indexes {
            consumed[keyword] = true;
        }
    }
    assert_eq!(consumed, engine.recorded_keywords);
}

#[test]
fn a_literal_outside_the_rule_keywords_is_ineligible() {
    let config = |keywords: &str| {
        format!(
            r#"
[[rules]]
id = "probe"
regex = '''(?i)[\w.-]{{0,10}}?(?:apple|pear)=([a-z]{{4}})'''
keywords = [{keywords}]
"#
        )
    };
    let build = |keywords: &str| {
        Engine::builder(ConfigLoader::new().load_toml(&config(keywords)).unwrap())
            .build()
            .unwrap()
    };
    assert!(build(r#""apple""#).rule_literal_anchors[0].is_none());
    assert!(build(r#""apple", "pear""#).rule_literal_anchors[0].is_some());
    // An extra keyword that is not a literal cannot affect exactness.
    assert!(build(r#""apple", "pear", "fig""#).rule_literal_anchors[0].is_some());
    // A keywordless rule has no occurrence source.
    let keywordless = Engine::builder(
        ConfigLoader::new()
            .load_toml(
                r#"
[[rules]]
id = "probe"
regex = '''(?i)[\w.-]{0,10}?(?:apple)=([a-z]{4})'''
"#,
            )
            .unwrap(),
    )
    .build()
    .unwrap();
    assert!(keywordless.rule_literal_anchors[0].is_none());
    assert!(keywordless.recorded_keywords.is_empty());
}

#[test]
fn occurrence_limits_saturate_and_inactive_passes_decline() {
    let mut occurrences = KeywordOccurrences::default();
    occurrences.begin_pass(None, 2);
    assert!(occurrences.rule_starts(&[0]).is_none());

    let length = ATTEMPT_COST_FLOOR * 3;
    occurrences.begin_pass(Some(length), 2);
    assert_eq!(
        occurrences.rule_starts(&[0, 1]).unwrap().as_ref(),
        &[] as &[usize]
    );
    for start in 0..4 {
        occurrences.record(0, start);
    }
    occurrences.record(1, 2);
    assert_eq!(occurrences.rule_starts(&[1]).unwrap().as_ref(), &[2]);
    occurrences.record(1, 9);
    assert_eq!(
        occurrences.rule_starts(&[0, 1]).unwrap().as_ref(),
        &[0, 1, 2, 3, 9]
    );
    occurrences.record(0, 4);
    assert!(occurrences.rule_starts(&[0]).is_none());
    assert!(occurrences.rule_starts(&[0, 1]).is_none());
    assert_eq!(occurrences.rule_starts(&[1]).unwrap().as_ref(), &[2, 9]);

    // A new pass clears saturation and earlier offsets.
    occurrences.begin_pass(Some(length), 2);
    assert_eq!(
        occurrences.rule_starts(&[0]).unwrap().as_ref(),
        &[] as &[usize]
    );
}

#[test]
fn default_keywords_build_a_full_dfa_with_bounded_memory() {
    let engine = default_engine();
    let prefilter = engine.prefilter.as_ref().unwrap();
    assert_eq!(prefilter.kind(), AhoCorasickKind::DFA);
    assert!(prefilter.memory_usage() < 1 << 20);
}

#[test]
fn keyword_dfa_kind_matches_the_automatic_kind_on_keyword_hits() {
    let engine = default_engine();
    let dfa = engine.prefilter.as_ref().unwrap();
    let keywords = engine
        .config
        .keywords
        .iter()
        .filter(|keyword| !keyword.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    let automatic = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .build(&keywords)
        .unwrap();
    let hits = |automaton: &AhoCorasick, input: &[u8]| {
        automaton
            .find_overlapping_iter(input)
            .map(|found| (found.pattern().as_usize(), found.start(), found.end()))
            .collect::<Vec<_>>()
    };
    let mut compared = 0_usize;
    for sample in samples().iter().step_by(11) {
        let input = decoded(sample).to_ascii_lowercase();
        assert_eq!(hits(dfa, &input), hits(&automatic, &input));
        compared += 1;
    }
    assert!(compared > 300);
    let dense = b"apikeyauthtokensecretpasswordcredentials".repeat(64);
    assert_eq!(hits(dfa, &dense), hits(&automatic, &dense));
}

#[test]
fn oversized_keyword_sets_keep_the_automatic_automaton() {
    let long = "k".repeat(96);
    let keywords = (0..200)
        .map(|index| format!("\"{long}{index}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!("[[rules]]\nid = \"probe\"\nregex = '''x'''\nkeywords = [{keywords}]\n");
    let engine = Engine::builder(ConfigLoader::new().load_toml(&config).unwrap())
        .build()
        .unwrap();
    assert!(
        engine
            .config
            .keywords
            .iter()
            .map(String::len)
            .sum::<usize>()
            > KEYWORD_DFA_BYTE_LIMIT
    );
    assert_ne!(
        engine.prefilter.as_ref().unwrap().kind(),
        AhoCorasickKind::DFA
    );
}

#[derive(Deserialize)]
struct Sample {
    rule_id: String,
    polarity: String,
    input_base64: String,
}

fn samples() -> Vec<Sample> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/generator-corpus/samples-v1.jsonl");
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn decoded(sample: &Sample) -> Vec<u8> {
    BASE64_STANDARD.decode(&sample.input_base64).unwrap()
}

#[test]
fn every_eligible_default_rule_agrees_on_every_frozen_rule_sample() {
    let engine = default_engine();
    let rules = anchored_rules(&engine);
    let samples = samples();
    assert_eq!(samples.len(), 6_770);
    let inputs = samples.iter().map(decoded).collect::<Vec<_>>();
    let ascii = inputs.iter().filter(|input| input.is_ascii()).count();
    assert!(ascii > 6_000, "only {ascii} ASCII samples");
    let mut compared = 0_usize;
    let mut matched = 0_usize;
    for rule in &rules {
        for (index, input) in inputs.iter().enumerate() {
            matched += assert_paths_agree(&engine, rule, input, &format!("sample {index}"));
            compared += 1;
        }
    }
    assert_eq!(compared, rules.len() * inputs.len());
    assert!(
        matched > 3_000,
        "only {matched} matches across rule samples"
    );
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(limit).unwrap()).unwrap()
    }
}

/// Builds boundary inputs from a seed that places a literal at `literal_at`.
fn boundary_variants(
    seed: &[u8],
    literal_at: usize,
    literal: &[u8],
    max_leading: usize,
    filler: u8,
    stop: u8,
) -> Vec<Vec<u8>> {
    let prefix = &seed[..literal_at];
    let body = &seed[literal_at..];
    let run = |count: usize| vec![filler; count];
    let with = |parts: &[&[u8]]| parts.concat();
    let short = max_leading.saturating_sub(1);
    let half = max_leading / 2;
    let doubled_literal = literal.repeat(40);
    let dotted = literal
        .iter()
        .copied()
        .chain(*b".")
        .cycle()
        .take((literal.len() + 1) * 20)
        .collect::<Vec<_>>();
    let mut mixed_case = literal.to_ascii_uppercase();
    if let Some(first) = mixed_case.first_mut() {
        *first = first.to_ascii_lowercase();
    }
    vec![
        seed.to_vec(),
        body.to_vec(),
        // Exactly N characters of walk-back, one more, and one fewer.
        with(&[&run(max_leading), body]),
        with(&[&run(max_leading + 1), body]),
        with(&[&run(short), body]),
        // Class boundaries on the left of the walk-back.
        with(&[&[stop], &run(max_leading), body]),
        with(&[&run(half), &[stop], &run(3), body]),
        with(&[&[stop], body]),
        // Adjacent and repeated matches, for prior-match-end clamping.
        with(&[body, body]),
        with(&[body, &[filler], body]),
        with(&[body, b"\n", body]),
        with(&[seed, seed]),
        // Adjacent and overlapping literals before the real one.
        with(&[literal, body]),
        with(&[literal, literal, body]),
        with(&[&literal[..literal.len() - 1], body]),
        with(&[&run(2), literal, &run(2), body]),
        // keykey runs.
        with(&[&doubled_literal, body]),
        with(&[&dotted, body]),
        doubled_literal.clone(),
        // Literal at the very start and at the very end.
        with(&[prefix, literal]),
        with(&[&run(max_leading), literal]),
        literal.to_vec(),
        // Truncated and extended tails reach the `$` and `\z` boundaries.
        seed[..seed.len().saturating_sub(1)].to_vec(),
        with(&[seed, b"\n"]),
        with(&[seed, b"\r\n"]),
        with(&[seed, b" "]),
        // Case variants of the whole input and of the literal alone.
        seed.to_ascii_uppercase(),
        seed.to_ascii_lowercase(),
        with(&[prefix, &mixed_case, &body[literal.len().min(body.len())..]]),
        // Multi-line input, moving the line break through the leading window.
        with(&[&run(half), b"\n", &run(half), body]),
        with(&[prefix, b"\n", body]),
    ]
}

/// Unbounded-tail inputs in the spirit of `generic-api-key` for any literal.
fn long_tail_variants(literal: &[u8], filler: u8) -> Vec<Vec<u8>> {
    let run = |byte: u8, count: usize| vec![byte; count];
    let mut embedded = run(b'a', 400);
    embedded.splice(120..120, literal.iter().copied());
    embedded.splice(300..300, literal.iter().copied());
    let with = |parts: &[&[u8]]| parts.concat();
    vec![
        with(&[literal, b"=", &run(b'a', 400)]),
        with(&[literal, b"=", &run(b'a', 400), b"\""]),
        with(&[literal, b" := '", &run(b'b', 400), b"'\n"]),
        with(&[&run(filler, 20), literal, b"=", &embedded, b";"]),
        with(&[literal, b"=", &embedded]),
        with(&[&embedded, literal]),
        with(&[literal, b"=", &run(b'Z', 300), b"=", b"\n"]),
        with(&[
            literal,
            b"=",
            &run(b'a', 12),
            literal,
            b"=",
            &run(b'a', 12),
            b"\n",
        ]),
    ]
}

#[test]
fn every_eligible_default_rule_agrees_on_seeded_adversarial_inputs() {
    let engine = default_engine();
    let rules = anchored_rules(&engine);
    let mut seeds_by_rule = BTreeMap::<&str, Vec<Vec<u8>>>::new();
    let samples = samples();
    for sample in &samples {
        if sample.polarity.starts_with("ordinary") {
            let seeds = seeds_by_rule.entry(sample.rule_id.as_str()).or_default();
            if seeds.len() < 6 {
                seeds.push(decoded(sample));
            }
        }
    }
    let mut rng = Rng(0x5eed_1234_5678_9abc);
    let mut compared = 0_usize;
    let mut matched = 0_usize;
    for rule in &rules {
        let shape = rule.regex.literal_anchor().unwrap();
        let candidate = &shape.candidates()[rule.anchor.candidate];
        let max_leading = shape.max_leading();
        let filler = (b'a'..=b'z')
            .find(|byte| shape.leading_contains(*byte))
            .unwrap_or(b'-');
        let stop = (0_u8..0x80)
            .find(|byte| !shape.leading_contains(*byte) && *byte != b'\n')
            .unwrap_or(b' ');
        let seeds = seeds_by_rule
            .get(rule.rule.id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut inputs = Vec::new();
        for literal in candidate.literals() {
            inputs.extend(long_tail_variants(literal, filler));
            let lowered = literal.to_ascii_lowercase();
            for seed in &seeds {
                let lowered_seed = seed.to_ascii_lowercase();
                let literal_at = lowered_seed
                    .windows(lowered.len())
                    .position(|window| window == lowered)
                    .unwrap_or(0);
                let found_seed;
                let (seed_bytes, literal_at) = if lowered_seed
                    .windows(lowered.len())
                    .any(|window| window == lowered)
                {
                    (seed.as_slice(), literal_at)
                } else {
                    found_seed = [lowered.as_slice(), b"=", seed.as_slice()].concat();
                    (found_seed.as_slice(), 0)
                };
                inputs.extend(boundary_variants(
                    seed_bytes,
                    literal_at,
                    &lowered,
                    max_leading,
                    filler,
                    stop,
                ));
            }
        }
        let mutation_alphabet: &[u8] = b"keytoK=:\"' .-_\n\r\t;,`azAZ09+/";
        let bases = inputs.len();
        for index in 0..bases.min(64) {
            for _ in 0..8 {
                let mut mutated = inputs[index].clone();
                if mutated.is_empty() {
                    continue;
                }
                for _ in 0..=rng.below(6) {
                    let at = rng.below(mutated.len());
                    match rng.below(3) {
                        0 => mutated[at] = mutation_alphabet[rng.below(mutation_alphabet.len())],
                        1 => mutated
                            .insert(at, mutation_alphabet[rng.below(mutation_alphabet.len())]),
                        _ => {
                            mutated.remove(at);
                            if mutated.is_empty() {
                                break;
                            }
                        }
                    }
                }
                inputs.push(mutated);
            }
        }
        for input in &inputs {
            matched += assert_paths_agree(&engine, rule, input, "adversarial");
            compared += 1;
        }
    }
    assert!(compared > 20_000, "only {compared} adversarial comparisons");
    assert!(matched > 5_000, "only {matched} adversarial matches");
}

#[test]
fn generic_api_key_unbounded_tail_matches_the_full_search() {
    let engine = default_engine();
    let rules = anchored_rules(&engine);
    let generic = rules
        .iter()
        .find(|rule| rule.rule.id == "generic-api-key")
        .expect("generic-api-key must be eligible");
    let long_value = "k3yq".repeat(120);
    let mut matched = 0_usize;
    for input in [
        format!("access_token = \"{long_value}\"\n"),
        format!("x api_key={long_value};"),
        format!("TOKEN: {long_value}"),
        format!("password  := '{long_value}'"),
        format!("secret={long_value}===\n"),
        format!("auth = {long_value}\n{long_value}\n"),
        format!("credential={long_value},key={long_value},"),
        format!("creds {long_value} key {long_value}"),
        "key=".repeat(200),
        format!("key= {}", "=".repeat(200)),
        format!("{}token=abcdefghijklm\n", "a-b.c".repeat(40)),
        format!("{}token=abcdefghijklm\n", "x".repeat(51)),
        format!("passwd{}\n", "=".repeat(16)),
    ] {
        matched += assert_paths_agree(&engine, generic, input.as_bytes(), "generic tail");
    }
    assert!(matched >= 8, "only {matched} generic-api-key matches");
}

/// Representative template rule, enumerated across each field of its grammar.
#[test]
fn representative_template_rule_agrees_across_its_grammar_slots() {
    let engine = default_engine();
    let rules = anchored_rules(&engine);
    let adafruit = rules
        .iter()
        .find(|rule| rule.rule.id == "adafruit-api-key")
        .expect("adafruit-api-key must be eligible");
    let value32 = "a".repeat(32);
    let value31 = "b".repeat(31);
    let value33 = "c".repeat(33);
    let run50 = "x".repeat(50);
    let run51 = "x".repeat(51);
    let leading = ["", "a", "x-.", ".", run50.as_str(), run51.as_str(), "x\nx"];
    let literal = ["adafruit", "ADAFRUIT", "AdaFruit"];
    let filler = ["", "_token", " - "];
    let quote = ["", "\"", "' "];
    let operator = ["=", ":", ":=", "=>", ",", "?=", "||", ">"];
    let before_value = ["", "\"", "= "];
    let value = [value32.as_str(), value31.as_str(), value33.as_str()];
    let terminator = ["", "\"", ";", "\n", "\\n", " ", "'x"];
    let trailing = ["", "adafruit"];
    let mut compared = 0_usize;
    let mut matched = 0_usize;
    for leading in leading {
        for literal in literal {
            for filler in filler {
                for quote in quote {
                    for operator in operator {
                        for before_value in before_value {
                            for value in value {
                                for terminator in terminator {
                                    for trailing in trailing {
                                        let input = format!(
                                            "{leading}{literal}{filler}{quote}{operator}\
                                             {before_value}{value}{terminator}{trailing}"
                                        );
                                        matched += assert_paths_agree(
                                            &engine,
                                            adafruit,
                                            input.as_bytes(),
                                            "grammar slots",
                                        );
                                        compared += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(compared, 7 * 3 * 3 * 3 * 8 * 3 * 3 * 7 * 2);
    assert!(matched > 1_000, "only {matched} template matches");
}

#[test]
fn scan_outcomes_and_explanations_are_identical_with_and_without_anchoring() {
    let engine = default_engine();
    let disabled = without_anchors(&engine);
    let options = ScanOptions::default();
    let control = ScanControl::unlimited();
    let samples = samples();
    let mut inputs = samples
        .iter()
        .filter(|sample| sample.polarity.starts_with("ordinary"))
        .step_by(7)
        .map(decoded)
        .collect::<Vec<_>>();
    // A short sample cannot afford an anchored attempt, so these wrap each
    // sample in padding that the budget accepts. The padding bytes are outside
    // every leading class, so they cannot create or extend a match.
    let padding = vec![b' '; 2 * 1024];
    let mut padded = inputs
        .iter()
        .map(|input| [padding.as_slice(), input.as_slice(), padding.as_slice()].concat())
        .collect::<Vec<_>>();
    // A class run longer than N places the true start at exactly N bytes
    // before the literal, so a wrong recorded offset selects a different start.
    let class_run = vec![b'x'; 120];
    let long_run = inputs
        .iter()
        .map(|input| {
            [
                padding.as_slice(),
                class_run.as_slice(),
                input.as_slice(),
                padding.as_slice(),
            ]
            .concat()
        })
        .collect::<Vec<_>>();
    padded.extend(long_run);
    padded.extend([
        [
            padding.as_slice(),
            b"token = \"aaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        ]
        .concat()
        .repeat(16),
        [padding.as_slice(), b"api_key=abcdefghijklmnop;"]
            .concat()
            .repeat(16),
    ]);
    let padded_count = padded.len();
    let padded_for_non_ascii = padded
        .iter()
        .step_by(padded_count / 60)
        .cloned()
        .collect::<Vec<_>>();
    inputs.extend(padded);
    // U+212A lowercases to one byte, so it shifts every later offset between
    // the folded copy and the raw bytes. Only an ASCII-gated pass can be exact.
    let mut non_ascii = Vec::new();
    for input in inputs.iter().take(40).chain(padded_for_non_ascii.iter()) {
        non_ascii.push([input.as_slice(), "é".as_bytes()].concat());
        non_ascii.push([input.as_slice(), b"\xff"].concat());
        non_ascii.push(["\u{212A}".as_bytes(), input.as_slice()].concat());
        non_ascii.push([input.as_slice(), "\u{212A}ey".as_bytes()].concat());
    }
    inputs.extend(non_ascii);
    inputs.extend([
        b"key=".repeat(4096),
        b"key ".repeat(4096),
        b"key".repeat(4096),
        b"token = \"aaaaaaaaaaaaaaaaaaaaaaaa\"\n".repeat(64),
    ]);
    assert!(padded_count > 800, "only {padded_count} padded inputs");
    let mut findings = 0_usize;
    for input in &inputs {
        let fragment = Fragment::builder(ByteText::new(input.clone())).build();
        let (left, left_log) = engine.scan_fragment_explained(
            &fragment,
            &options,
            &control,
            ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
            false,
        );
        let (right, right_log) = disabled.scan_fragment_explained(
            &fragment,
            &options,
            &control,
            ExplanationOptions::bounded(ExplanationOptions::MAX_RECORDS),
            false,
        );
        assert_eq!(left, right);
        assert_eq!(left_log, right_log);
        findings += left.findings().len();
    }
    assert!(findings > 500, "only {findings} findings compared");
}
