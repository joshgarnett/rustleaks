use std::collections::BTreeMap;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;

use super::super::{ByteSpan, GoRegex, NormalizedHaystack};
use super::ATTEMPT_COST_FLOOR;

fn compile(pattern: &str) -> GoRegex {
    GoRegex::compile(pattern).unwrap()
}

fn literals(regex: &GoRegex) -> Vec<Vec<Vec<u8>>> {
    regex
        .literal_anchor()
        .map(|shape| {
            shape
                .candidates()
                .iter()
                .map(|candidate| {
                    candidate
                        .literals()
                        .iter()
                        .map(|literal| literal.to_vec())
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Asserts that `pattern` offers exactly `expected` as one literal-node choice.
#[track_caller]
fn assert_candidate(pattern: &str, expected: &[&str]) {
    let expected = expected
        .iter()
        .map(|literal| literal.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let found = literals(&compile(pattern));
    assert!(
        found.contains(&expected),
        "{pattern}: {expected:?} not offered in {found:?}"
    );
}

fn assert_every_candidate_matches(regex: &GoRegex, haystack: &[u8], label: &str) {
    let expected = regex.find_all(haystack);
    for (index, found) in regex
        .literal_anchored_candidates(haystack)
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            found,
            expected,
            "{label}: candidate {index} for {:?} on {:?}",
            regex.source(),
            String::from_utf8_lossy(haystack)
        );
    }
}

// Shape analysis works on the parsed HIR, so these assert the forms that
// parser simplification actually produces rather than the source spelling.
#[test]
fn analysis_accepts_keyword_templates_after_hir_simplification() {
    assert_candidate(r"(?i)[\w.-]{0,50}?(?:key|token)=x", &["key", "token"]);
    // A greedy leading repetition has the same language of starts.
    assert_candidate(r"(?i)[\w.-]{0,50}(?:key)=x", &["key"]);
    // Non-capturing groups flatten, so repetitions and literal positions become
    // adjacent children of one concatenation.
    assert_candidate(r"[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:key))=x", &["key"]);
    // Common alternation prefixes are factored by the parser and enumerated
    // back into the full literal set.
    assert_candidate(r"(?i)[\w.-]{0,50}?(?:keys|key)=x", &["key", "keys"]);
    assert_candidate(
        r"(?i)[\w.-]{0,50}?(?:passw(?:or)?d)=x",
        &["passwd", "password"],
    );
    // An optional literal class position stays finite.
    assert_candidate(
        r"(?i)[\w.-]{0,50}?(?:private[_-]?ai)=x",
        &["private-ai", "private_ai", "privateai"],
    );
    // Case-restricted positions lowercase to one byte, so `[Aa]pi|API` stays
    // a single literal. `generic-api-key` depends on this.
    assert_candidate(r"(?i)[\w.-]{0,50}?(?:(?-i:[Aa]pi|API))=x", &["api"]);
    // Digits and punctuation in a literal are matched as single bytes. The
    // parser merges adjacent non-letter literals into one node, so the boundary
    // of a literal node can only fall where a different kind of node begins.
    assert_candidate(r"(?i)[\w.-]{0,50}?(?:co_api-1)[a-z]", &["co_api-1"]);
    // Every literal-node length is a candidate; the engine picks the longest
    // whose whole set is keywords.
    let all = literals(&compile(r"(?i)[\w.-]{0,50}?(?:ab)cd=x"));
    assert_eq!(
        all.iter().map(|set| set[0].len()).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
}

#[test]
fn analysis_ignores_unreachable_non_ascii_class_members() {
    // (?i) adds U+212A and U+017F to these classes. Only ASCII members count.
    let shape = compile(r"(?i)[\w.-]{0,50}?sk=x");
    let shape = shape.literal_anchor().unwrap();
    assert_eq!(&shape.candidates()[1].literals()[0][..], b"sk");
    // Folding also gives a Kelvin-sign spelling its ASCII members, so an ASCII
    // keyword occurrence still covers every ASCII match of this position.
    let folded = compile(r"(?i)[\w.-]{0,50}?(?:\x{212A}ey)=x");
    let folded = folded.literal_anchor().unwrap();
    assert_eq!(&folded.candidates()[2].literals()[0][..], b"key");
}

#[test]
fn analysis_rejects_ineligible_shapes() {
    for pattern in [
        // Leading look-around changes which starts are possible.
        r"(?i)\b[\w.-]{0,50}?(?:key)=x",
        r"(?i)^[\w.-]{0,50}?(?:key)=x",
        // Look-around between the prefix and the literal.
        r"(?i)[\w.-]{0,50}?\b(?:key)=x",
        // A capture before or around the literal node.
        r"(?i)([\w.-]{0,50}?)(?:key)=x",
        r"(?i)[\w.-]{0,50}?(key)=x",
        // Minimum above zero or an unbounded maximum.
        r"(?i)[\w.-]{1,50}?(?:key)=x",
        r"(?i)[\w.-]*?(?:key)=x",
        r"(?i)[\w.-]+?(?:key)=x",
        // No leading class repetition at all.
        r"(?i)(?:key)=x",
        // A leading repetition over more than one position.
        r"(?i)(?:ab){0,5}?(?:key)=x",
        // Top-level alternation.
        r"(?i)[\w.-]{0,50}?key|x",
        // A language that contains the empty string.
        r"(?i)[\w.-]{0,50}?(?:key)?",
        r"(?i)[\w.-]{0,50}?(?:key|)",
        // A literal position without an ASCII member, even after case folding.
        r"(?i)[\w.-]{0,50}?(?:\x{3B1}ey)=x",
        // Non-ASCII literal bytes.
        r"(?i)[\w.-]{0,50}?(?:é)=x",
        r"(?i)[\w.-]{0,50}?(?:\x{2603}ey)=x",
        r"(?-i)[\w.-]{0,50}?(?:\x{212A}ey)=x",
        // An unbounded literal node.
        r"(?i)[\w.-]{0,50}?(?:k+)=x",
    ] {
        assert!(
            compile(pattern).literal_anchor().is_none(),
            "expected rejection of {pattern}"
        );
    }
}

#[test]
fn analysis_requires_the_same_ascii_class_across_leading_repetitions() {
    // The second repetition is not over C, so the shape stops before it and
    // the literal node cannot be enumerated.
    assert!(
        compile(r"[a-z]{0,5}?[0-9]{0,5}?(?:key)=x")
            .literal_anchor()
            .is_none()
    );
    // Identical ASCII projection across different folding is accepted.
    assert!(
        compile(r"[\w.-]{0,5}?(?i:[\w.-]{0,5}?(?:key))=x")
            .literal_anchor()
            .is_some()
    );
}

#[test]
fn analysis_bounds_literal_enumeration() {
    // Without a common prefix the parser cannot factor this into a shorter node.
    let many = (0..70)
        .map(|index| format!("a{index:02}"))
        .chain(["z".to_owned()])
        .collect::<Vec<_>>()
        .join("|");
    assert!(
        compile(&format!("(?i)[a-z]{{0,5}}?(?:{many})=x"))
            .literal_anchor()
            .is_none()
    );
    // Over-long literals stop the walk; shorter choices remain sound.
    let long = "k".repeat(65);
    let longest = literals(&compile(&format!("(?i)[a-z]{{0,5}}?(?:{long})=x")))
        .into_iter()
        .flatten()
        .map(|literal| literal.len())
        .max();
    assert_eq!(longest, Some(64));
    // Five leading repetitions total 5,000 characters, above the 4,096 cap.
    assert!(
        compile(
            r"(?i)[a-z]{0,1000}?[a-z]{0,1000}?[a-z]{0,1000}?[a-z]{0,1000}?[a-z]{0,1000}?(?:key)=x"
        )
        .literal_anchor()
        .is_none()
    );
}

// Exhaustive enumeration over every string of a small alphabet. These expressions
// keep the template structure but make the leading window short enough that
// every class boundary, overlap and clamp is reached.
#[test]
fn exhaustive_small_alphabet_matches_the_unanchored_path() {
    for (pattern, alphabet, maximum_length) in [
        // Template shape.
        (r"(?i)[ab]{0,2}?(?:ab)=([ab]{1,2})(?:;|$)", &b"ab=;"[..], 8),
        // Greedy leading repetition.
        (r"(?i)[ab]{0,2}(?:ab)=([ab]{1,2})(?:;|$)", b"ab=;", 8),
        // Two leading repetitions over the same class.
        (
            r"[ab]{0,1}?(?i:[ab]{0,1}?(?:ab)=)([ab]{1,2})(?:;|$)",
            b"ab=;",
            8,
        ),
        // Overlapping literals with a shared prefix; the parser factors them.
        (r"(?i)[ab]{0,2}?(?:aba|ab|a)=[ab]{1,3}(?:;|$)", b"ab=;", 8),
        // A literal that overlaps itself and the class.
        (r"(?i)[ab]{0,3}?(?:aa)=?", b"ab=", 8),
        // Unbounded tail.
        (r"(?i)[ab]{0,2}?(?:ab)[ab=]*;", b"ab=;", 7),
        // Word boundary after the literal.
        (r"(?i)[ab=]{0,1}?(?:ab)\b=?", b"ab=;", 7),
        // Multi-line end of input.
        (r"(?im)[ab]{0,2}?(?:ab)=[ab]{1,2}$", b"ab=\n", 7),
        // End-of-text context from a translated dollar.
        (r"(?i)[ab]{0,2}?(?:ab)$", b"ab\n", 8),
        // Matches can be adjacent, so prior-match clamping is exercised.
        (r"(?i)[ab]{0,1}?(?:ab)", b"ab", 12),
    ] {
        let regex = compile(pattern);
        assert!(
            regex.literal_anchor().is_some(),
            "{pattern} must be eligible"
        );
        let mut haystack = Vec::new();
        for_each_string(alphabet, maximum_length, &mut haystack, &mut |input| {
            assert_every_candidate_matches(&regex, input, "exhaustive");
        });
    }
}

fn for_each_string(
    alphabet: &[u8],
    maximum_length: usize,
    current: &mut Vec<u8>,
    visit: &mut impl FnMut(&[u8]),
) {
    visit(current);
    if current.len() == maximum_length {
        return;
    }
    for &byte in alphabet {
        current.push(byte);
        for_each_string(alphabet, maximum_length, current, visit);
        current.pop();
    }
}

#[derive(Deserialize)]
struct RegexRequest {
    id: String,
    pattern_base64: String,
    input_base64: String,
}

#[test]
fn frozen_regex_corpus_matches_the_unanchored_path_when_eligible() {
    let mut compiled = BTreeMap::new();
    let mut eligible_inputs = 0_usize;
    for line in include_str!("../../../../../compat/regex-corpus/requests-v1.jsonl").lines() {
        let request: RegexRequest = serde_json::from_str(line).unwrap();
        let Ok(pattern) =
            String::from_utf8(BASE64_STANDARD.decode(request.pattern_base64).unwrap())
        else {
            continue;
        };
        let input = BASE64_STANDARD.decode(request.input_base64).unwrap();
        let regex = compiled
            .entry(pattern.clone())
            .or_insert_with(|| GoRegex::compile(&pattern).ok());
        let Some(regex) = regex else { continue };
        if regex.literal_anchor().is_some() && input.is_ascii() {
            assert_every_candidate_matches(regex, &input, &request.id);
            eligible_inputs += 1;
        }
    }
    // Pinned so a shape-analysis change that silently stops exercising this
    // corpus fails here instead of passing vacuously.
    assert!(
        eligible_inputs >= 20,
        "only {eligible_inputs} eligible inputs"
    );
}

#[test]
fn non_ascii_haystacks_have_no_anchored_results() {
    let regex = compile(r"(?i)[\w.-]{0,50}?(?:key)=x");
    assert!(regex.literal_anchor().is_some());
    assert!(!regex.literal_anchored_candidates(b"key=x").is_empty());
    for haystack in [
        "\u{212A}ey=x".as_bytes(),
        "é key=x".as_bytes(),
        b"key=x\xff",
    ] {
        assert!(regex.literal_anchored_candidates(haystack).is_empty());
    }
}

#[test]
fn folded_non_ascii_variants_still_match_on_the_unanchored_path() {
    // U+212A folds to k and U+017F to s, so an ordinary search matches inputs
    // where no ASCII keyword occurs. Such inputs are not pure ASCII and never
    // reach the anchored path.
    let regex = compile(r"(?i)[\w.-]{0,50}?(?:key|ſk)=x");
    assert!(!regex.find_all("\u{212A}ey=x".as_bytes()).is_empty());
    assert!(!"\u{212A}ey=x".is_ascii());
}

#[test]
fn budget_rejects_dense_occurrences_for_finite_tails() {
    let regex = compile(r"(?i)[a-z]{0,50}?(?:key)x");
    let shape = regex.literal_anchor().unwrap();
    let haystack = "key".repeat(200);
    let normalized = NormalizedHaystack::new(haystack.as_bytes());
    let occurrences: Vec<usize> = (0..200).map(|index| index * 3).collect();
    assert!(
        regex
            .find_all_literal_anchored(&normalized, shape.candidates().len() - 1, &occurrences)
            .is_none()
    );
    // The fallback is still exact: the unbudgeted path must agree with it.
    assert_eq!(
        regex.literal_anchored_candidates(haystack.as_bytes()),
        vec![regex.find_all(haystack.as_bytes()); shape.candidates().len()]
    );
}

#[test]
fn budget_admits_sparse_occurrences_and_finds_matches() {
    let regex = compile(r"(?i)[a-z]{0,8}?(?:key)=x");
    let shape = regex.literal_anchor().unwrap();
    let candidate = shape.candidates().len() - 1;
    let mut haystack = vec![b'.'; 4096];
    haystack[1000..1005].copy_from_slice(b"key=x");
    haystack[3000..3005].copy_from_slice(b"key=x");
    let normalized = NormalizedHaystack::new(&haystack);
    let found = regex
        .find_all_literal_anchored(&normalized, candidate, &[1000, 3000])
        .unwrap();
    assert_eq!(found, regex.find_all(&haystack));
    assert_eq!(
        found,
        [
            ByteSpan {
                start: 1000,
                end: 1005
            },
            ByteSpan {
                start: 3000,
                end: 3005
            }
        ]
    );
}

#[test]
fn budget_abandons_attempts_that_stay_alive_through_an_unbounded_tail() {
    // With an unbounded tail, no attempt can stop early on this input, so the
    // total scan would be quadratic if only occurrence density were checked.
    let regex = compile(r"(?i)[a-z]{0,8}?(?:key)[a-z=]*;");
    let shape = regex.literal_anchor().unwrap();
    let candidate = shape.candidates().len() - 1;
    let length = 1 << 16;
    let spacing = (ATTEMPT_COST_FLOOR + 8 + 3) * 2;
    let mut haystack = vec![b'a'; length];
    let occurrences: Vec<usize> = (0..length / spacing).map(|index| index * spacing).collect();
    for &occurrence in &occurrences {
        haystack[occurrence..occurrence + 3].copy_from_slice(b"key");
    }
    let normalized = NormalizedHaystack::new(&haystack);
    assert!(
        regex
            .find_all_literal_anchored(&normalized, candidate, &occurrences)
            .is_none()
    );
    // Stops at the first byte the tail cannot consume, so the same occurrences
    // become affordable when runs are short.
    for offset in (32..length).step_by(64) {
        haystack[offset] = b' ';
    }
    for &occurrence in &occurrences {
        haystack[occurrence..occurrence + 3].copy_from_slice(b"key");
    }
    let normalized = NormalizedHaystack::new(&haystack);
    let affordable = regex
        .find_all_literal_anchored(&normalized, candidate, &occurrences)
        .unwrap();
    assert_eq!(affordable, regex.find_all(&haystack));
}

#[test]
fn the_budget_never_changes_results_only_the_path() {
    // Any input accepted by the budget must equal the unanchored enumeration.
    let regex = compile(r"(?i)[a-z]{0,4}?(?:key)=?[a-z]{0,3}");
    let shape = regex.literal_anchor().unwrap();
    let candidate = shape.candidates().len() - 1;
    let mut haystack = b"zzkey=abc ".repeat(40);
    haystack.extend_from_slice(&[b' '; 8192]);
    let occurrences: Vec<usize> = (0..40).map(|index| index * 10 + 2).collect();
    let normalized = NormalizedHaystack::new(&haystack);
    let found = regex
        .find_all_literal_anchored(&normalized, candidate, &occurrences)
        .unwrap();
    assert_eq!(found, regex.find_all(&haystack));
    assert_eq!(found.len(), 40);
}

#[test]
fn seeded_adversarial_synthetic_expressions_match_the_unanchored_path() {
    let patterns = [
        r#"(?i)[a-z0-9.-]{0,6}?(?:key|ke|token)(?:[ \t\w.-]{0,4})[\s'"]{0,2}(?:=|:|=>)[\x60'"\s=]{0,2}([a-z0-9]{4})(?:[\x60'"\s;]|\\[nr]|$)"#,
        r#"(?i)[a-z0-9.-]{0,6}(?:key|ke|token)(?:[ \t\w.-]{0,4})[\s'"]{0,2}(?:=|:|=>)[\x60'"\s=]{0,2}([a-z0-9]{4})(?:[\x60'"\s;]|\\[nr]|$)"#,
        r"[a-zA-Z0-9.-]{0,3}?(?i:[a-z0-9.-]{0,3}?(?:key|token)[ ]{0,2})(?:=|:)([a-f0-9]{4})(?:;|$)",
        r#"(?i)[a-z0-9.-]{0,6}?(?:key|token)(?:\s*=\s*)([a-z0-9+/]{4,}={0,3})(?:[\x60'"\s;]|$)"#,
        r"(?i)[a-z0-9.-]{0,6}?(?:key)\b(?:=)([a-z]{2})\b",
        r"(?im)[a-z0-9.-]{0,6}?(?:key|token)=([a-z]{2})$",
    ];
    let alphabet: &[u8] = b"keyKEYtoknaz09.-_ \t\n\r'\"`=:;,\\+/";
    let mut state = 0x5eed_0001_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state & 0xffff_ffff).unwrap()
    };
    for pattern in patterns {
        let regex = compile(pattern);
        assert!(
            regex.literal_anchor().is_some(),
            "{pattern} must be eligible"
        );
        for iteration in 0..4_000 {
            let length = next() % 96;
            let haystack = (0..length)
                .map(|_| alphabet[next() % alphabet.len()])
                .collect::<Vec<_>>();
            assert_every_candidate_matches(&regex, &haystack, &format!("seeded/{iteration}"));
        }
    }
}
