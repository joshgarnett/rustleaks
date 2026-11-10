//! Differential evidence against the former eager PikeVM search path.
//!
//! The frontend is shared deliberately: these tests compare backend selection,
//! captures, iteration and byte mapping, not the independent Go syntax contract.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use regex_automata::{
    Input, MatchKind,
    nfa::thompson::{self, WhichCaptures, pikevm::PikeVM},
    util::syntax,
};
use serde::Deserialize;

use super::{ByteSpan, CaptureSpans, GoRegex, Translator, utf8_rune_width};

struct Reference {
    backend: PikeVM,
    captures: usize,
}

impl Reference {
    fn compile(source: &str) -> Option<Self> {
        let translated = Translator::new(source).translate().ok()?;
        let captures = translated.capture_names.len();
        let pattern = translated.pattern;
        let build = move || {
            PikeVM::builder()
                .configure(PikeVM::config().match_kind(MatchKind::LeftmostFirst))
                .syntax(
                    syntax::Config::new()
                        .unicode(true)
                        .utf8(true)
                        .nest_limit(super::NEST_LIMIT),
                )
                .thompson(
                    thompson::Config::new()
                        .utf8(true)
                        .which_captures(WhichCaptures::All)
                        .nfa_size_limit(Some(super::COMPILED_SIZE_LIMIT)),
                )
                .build(&pattern)
                .ok()
        };
        let backend = if source.bytes().filter(|byte| *byte == b'(').count()
            > super::DEEP_COMPILE_THRESHOLD
        {
            std::thread::Builder::new()
                .stack_size(super::DEEP_COMPILE_STACK_SIZE)
                .spawn(build)
                .unwrap()
                .join()
                .unwrap()?
        } else {
            build()?
        };
        Some(Self { backend, captures })
    }

    // Retain the previous normalization and iteration implementation separately
    // from production helpers so sharing a normalized pass cannot hide a byte
    // remapping or empty-match progression regression.
    fn captures_all(&self, haystack: &[u8]) -> Vec<CaptureSpans> {
        let (bytes, boundaries) = normalize(haystack);
        let end = bytes.len();
        let mut position = 0;
        let mut previous_match_end = None;
        let mut results = Vec::new();
        let mut cache = self.backend.create_cache();
        let mut captures = self.backend.create_captures();

        while position <= end {
            self.backend.captures(
                &mut cache,
                Input::new(&bytes).span(position..end),
                &mut captures,
            );
            let Some(whole) = captures.get_group(0) else {
                break;
            };
            let mut accept = true;
            if whole.end == position {
                if previous_match_end == Some(whole.start) {
                    accept = false;
                }
                let width = utf8_rune_width(&bytes[position..]);
                if width == 0 {
                    position = end + 1;
                } else {
                    position += width;
                }
            } else {
                position = whole.end;
            }
            previous_match_end = Some(whole.end);

            if accept {
                results.push(CaptureSpans {
                    spans: (0..self.captures)
                        .map(|index| {
                            captures.get_group(index).map(|span| match &boundaries {
                                Some(boundaries) => ByteSpan {
                                    start: boundaries[span.start],
                                    end: boundaries[span.end],
                                },
                                None => ByteSpan {
                                    start: span.start,
                                    end: span.end,
                                },
                            })
                        })
                        .collect(),
                });
            }
        }
        results
    }
}

fn normalize(original: &[u8]) -> (Cow<'_, [u8]>, Option<Vec<usize>>) {
    if std::str::from_utf8(original).is_ok() {
        return (Cow::Borrowed(original), None);
    }
    let mut bytes = Vec::with_capacity(original.len());
    let mut boundaries = Vec::with_capacity(original.len() + 1);
    boundaries.push(0);
    let mut offset = 0;
    while offset < original.len() {
        let width = utf8_rune_width(&original[offset..]);
        if width > 1 || original[offset].is_ascii() {
            bytes.extend_from_slice(&original[offset..offset + width]);
            boundaries.extend((1..=width).map(|step| offset + step));
            offset += width;
        } else {
            bytes.extend_from_slice("\u{fffd}".as_bytes());
            boundaries.extend([offset, offset, offset + 1]);
            offset += 1;
        }
    }
    (Cow::Owned(bytes), Some(boundaries))
}

struct Pair {
    reference: Reference,
    current: GoRegex,
}

impl Pair {
    fn compile(pattern: &str) -> Option<Self> {
        let reference = Reference::compile(pattern);
        let current = GoRegex::compile(pattern).ok();
        assert_eq!(
            reference.is_some(),
            current.is_some(),
            "backend compile acceptance differs for {pattern:?}"
        );
        Some(Self {
            reference: reference?,
            current: current?,
        })
    }

    fn compare(&self, id: &str, input: &[u8]) {
        let expected = self.reference.captures_all(input);
        assert_eq!(self.current.captures_all(input), expected, "{id}: captures");
        assert_eq!(
            self.current.captures(input).as_ref(),
            expected.first(),
            "{id}: first captures"
        );
        assert_eq!(
            self.current.find_all(input),
            expected.iter().map(CaptureSpans::whole).collect::<Vec<_>>(),
            "{id}: whole matches"
        );
        assert_eq!(
            self.current.is_match(input),
            !expected.is_empty(),
            "{id}: match existence"
        );
    }
}

#[derive(Deserialize)]
struct RegexRequest {
    id: String,
    pattern_base64: String,
    input_base64: String,
}

#[test]
fn pikevm_differential_covers_the_complete_regex_corpus() {
    let mut compiled = BTreeMap::new();
    let mut request_count = 0;
    for line in include_str!("../../../../compat/regex-corpus/requests-v1.jsonl").lines() {
        let request: RegexRequest = serde_json::from_str(line).unwrap();
        let pattern = BASE64_STANDARD.decode(request.pattern_base64).unwrap();
        let input = BASE64_STANDARD.decode(request.input_base64).unwrap();
        request_count += 1;
        let Ok(pattern) = String::from_utf8(pattern) else {
            // Both wrappers require UTF-8 pattern source at their boundary.
            continue;
        };
        let pair = compiled
            .entry(pattern.clone())
            .or_insert_with(|| Pair::compile(&pattern));
        if let Some(pair) = pair {
            pair.compare(&request.id, &input);
        }
    }
    assert_eq!(request_count, 3_618);
}

#[derive(Deserialize)]
struct RuleSample {
    case_id: String,
    rule_id: String,
    input_base64: String,
    path_base64: Option<String>,
}

#[test]
fn pikevm_differential_covers_every_default_rule_sample() {
    let default: toml::Value = toml::from_str(include_str!("../../default/gitleaks.toml")).unwrap();
    let rules = default["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| {
            let compile = |key| {
                rule.get(key)
                    .and_then(toml::Value::as_str)
                    .map(|pattern| Pair::compile(pattern).unwrap())
            };
            (
                rule["id"].as_str().unwrap().to_owned(),
                (compile("regex"), compile("path")),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/generator-corpus/samples-v1.jsonl");
    let samples = std::fs::read_to_string(path).unwrap();
    let mut sample_count = 0;
    for line in samples.lines() {
        let sample: RuleSample = serde_json::from_str(line).unwrap();
        let (regex, path_regex) = &rules[&sample.rule_id];
        if let Some(regex) = regex {
            let input = BASE64_STANDARD.decode(sample.input_base64).unwrap();
            regex.compare(&sample.case_id, &input);
        }
        if let (Some(regex), Some(path)) = (path_regex, sample.path_base64) {
            let path = BASE64_STANDARD.decode(path).unwrap();
            regex.compare(&format!("{}/path", sample.case_id), &path);
        }
        sample_count += 1;
    }
    assert_eq!(sample_count, 6_770);
}

#[test]
fn pikevm_differential_covers_synthetic_bytes_and_empty_matches() {
    let inputs = [
        b"".as_slice(),
        b"aaab a\n\nb",
        "aéΩ\u{fffd}z".as_bytes(),
        b"\xffa\xc0\x80\xe2\x82b\xf0\x80\x80\x80\n",
        b"\nsecret = \"abcdefghijklmnop\";\n",
    ];
    for pattern in [
        "",
        "()",
        "a*",
        "a*?",
        "a|",
        "|a",
        "(?:a?)(b*)",
        "(a*)|(b*)",
        "(?m)^|$",
        "(?s:.)*?",
        "(?s:(.))",
        r"\b|\B",
        r"(\x{FFFD})+",
        r"([^\w])?",
        r"(?P<word>\pL+)|(?P<space>\s*)",
        r#"(?i)secret\s*=\s*["']([^"']+)["']"#,
    ] {
        let pair = Pair::compile(pattern).unwrap();
        for (index, input) in inputs.iter().enumerate() {
            pair.compare(&format!("synthetic/{pattern}/{index}"), input);
        }
    }
}
