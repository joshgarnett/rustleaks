//! Literal sets that every match of an expression must contain.
//!
//! The analysis returns a small set of ASCII strings, lowercased, such that
//! each match contains at least one of them, ignoring ASCII case. A buffer
//! without any of them cannot contain a match. The result is a necessary
//! condition only: a present literal does not imply a match.
//!
//! Only ASCII literals and ASCII classes contribute. Unicode case folding can
//! turn an ASCII letter into a class with non-ASCII members, such as the
//! Kelvin sign for `k`, so such classes stop the analysis instead of being
//! narrowed to ASCII. ASCII bytes stay unchanged when invalid UTF-8 is
//! normalized, so a literal found in a normalized haystack is also found in
//! the raw bytes, and the raw bytes can be checked instead.

use std::collections::BTreeSet;

use regex_syntax::hir::{Class, Hir, HirKind};

/// Shortest literal that is worth a check.
const MIN_LITERAL_LEN: usize = 3;
/// Largest number of strings kept for one node.
const SET_LIMIT: usize = 64;
/// Longest string kept for one node.
const STRING_LIMIT: usize = 64;
/// Largest number of distinct folded bytes kept for one class.
const CLASS_LIMIT: usize = 16;

type Set = BTreeSet<Vec<u8>>;

#[derive(Default)]
struct Info {
    /// Every string the node can match, folded to ASCII lowercase.
    exact: Option<Set>,
    /// Strings of which every match contains at least one, folded.
    necessary: Option<Set>,
}

impl Info {
    fn exact(set: Set) -> Self {
        Self {
            necessary: Some(set.clone()),
            exact: Some(set),
        }
    }
}

/// Largest number of sets kept for one expression.
const SETS_LIMIT: usize = 4;

/// Folded literals of which every match contains one.
pub(crate) type LiteralSet = Box<[Box<[u8]>]>;

/// Returns sets of folded literals, best first, such that every match
/// contains one literal of each set, or `None` when no useful set is known.
///
/// The first set is the best set for the whole expression. The others come
/// from separate parts of a top-level concatenation, so a buffer can be
/// ruled out by any one of them, for example when the first set only
/// repeats a rule's keywords.
pub(crate) fn required_literals(hir: &Hir) -> Option<Box<[LiteralSet]>> {
    let mut top = hir;
    while let HirKind::Capture(capture) = top.kind() {
        top = &capture.sub;
    }
    let mut candidates = Vec::new();
    if let HirKind::Concat(children) = top.kind() {
        concat_into(children, &mut candidates);
    } else if let Some(set) = analyze(top).necessary {
        candidates.push(set);
    }
    let mut sets: Vec<Set> = Vec::new();
    for set in candidates {
        let set = minimize(set);
        if set.is_empty()
            || set.len() > SET_LIMIT
            || set.iter().any(|literal| literal.len() < MIN_LITERAL_LEN)
            || sets.contains(&set)
        {
            continue;
        }
        let position = sets
            .iter()
            .position(|current| better(&set, Some(current)))
            .unwrap_or(sets.len());
        sets.insert(position, set);
    }
    sets.truncate(SETS_LIMIT);
    if sets.is_empty() {
        return None;
    }
    Some(
        sets.into_iter()
            .map(|set| set.into_iter().map(Vec::into_boxed_slice).collect())
            .collect(),
    )
}

fn analyze(hir: &Hir) -> Info {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Info::exact(BTreeSet::from([Vec::new()])),
        HirKind::Literal(literal) => {
            if literal.0.is_ascii() && literal.0.len() <= STRING_LIMIT {
                Info::exact(BTreeSet::from([literal.0.to_ascii_lowercase()]))
            } else {
                Info::default()
            }
        }
        HirKind::Class(class) => class_bytes(class).map_or_else(Info::default, |bytes| {
            Info::exact(bytes.into_iter().map(|byte| vec![byte]).collect())
        }),
        HirKind::Capture(capture) => analyze(&capture.sub),
        HirKind::Repetition(repetition) => {
            if repetition.min == 0 {
                return Info::default();
            }
            let sub = analyze(&repetition.sub);
            if repetition.min == 1 && repetition.max == Some(1) {
                sub
            } else {
                Info {
                    exact: None,
                    necessary: sub.necessary,
                }
            }
        }
        HirKind::Concat(children) => concat(children),
        HirKind::Alternation(children) => alternation(children),
    }
}

/// Folded bytes of a small ASCII-only class.
fn class_bytes(class: &Class) -> Option<BTreeSet<u8>> {
    let mut bytes = BTreeSet::new();
    match class {
        Class::Unicode(class) => {
            for range in class.ranges() {
                let (start, end) = (u32::from(range.start()), u32::from(range.end()));
                if end > 0x7f || end - start >= 128 {
                    return None;
                }
                for value in start..=end {
                    bytes.insert(u8::try_from(value).ok()?.to_ascii_lowercase());
                    if bytes.len() > CLASS_LIMIT {
                        return None;
                    }
                }
            }
        }
        Class::Bytes(class) => {
            for range in class.ranges() {
                if range.end() > 0x7f {
                    return None;
                }
                for value in range.start()..=range.end() {
                    bytes.insert(value.to_ascii_lowercase());
                    if bytes.len() > CLASS_LIMIT {
                        return None;
                    }
                }
            }
        }
    }
    if bytes.is_empty() { None } else { Some(bytes) }
}

fn product(left: &Set, right: &Set) -> Option<Set> {
    if left.len().saturating_mul(right.len()) > SET_LIMIT {
        return None;
    }
    let mut out = BTreeSet::new();
    for prefix in left {
        for suffix in right {
            if prefix.len() + suffix.len() > STRING_LIMIT {
                return None;
            }
            let mut joined = prefix.clone();
            joined.extend_from_slice(suffix);
            out.insert(joined);
        }
    }
    Some(out)
}

/// Drops each string that contains another member.
///
/// A match that contains the longer string also contains the shorter one,
/// so the condition stays the same.
fn minimize(set: Set) -> Set {
    let members = set.iter().cloned().collect::<Vec<_>>();
    set.into_iter()
        .filter(|candidate| {
            !members.iter().any(|other| {
                other.len() < candidate.len()
                    && candidate
                        .windows(other.len().max(1))
                        .any(|window| other.is_empty() || window == other.as_slice())
            })
        })
        .collect()
}

/// Prefers sets whose shortest string is longer, then smaller sets.
fn better(candidate: &Set, current: Option<&Set>) -> bool {
    let shortest = |set: &Set| set.iter().map(Vec::len).min().unwrap_or(0);
    current.is_none_or(|current| {
        (shortest(candidate), std::cmp::Reverse(candidate.len()))
            > (shortest(current), std::cmp::Reverse(current.len()))
    })
}

fn concat(children: &[Hir]) -> Info {
    let mut best: Option<Set> = None;
    let mut offer = |set: Set| {
        let set = minimize(set);
        if !set.is_empty() && better(&set, best.as_ref()) {
            best = Some(set);
        }
    };
    let exact = concat_offers(children, &mut offer);
    Info {
        exact,
        necessary: best,
    }
}

/// Collects every set that a concatenation offers, in the order offered.
fn concat_into(children: &[Hir], sets: &mut Vec<Set>) {
    concat_offers(children, &mut |set| sets.push(set));
}

/// Offers each set of which every match of the concatenation contains one,
/// and returns the exact set of the whole concatenation, if known.
fn concat_offers(children: &[Hir], offer: &mut dyn FnMut(Set)) -> Option<Set> {
    // A run of adjacent children with exact sets matches one string of their
    // product, so every match contains one of those strings.
    let mut run = Some(BTreeSet::from([Vec::new()]));
    let mut all_exact = true;
    for child in children {
        let info = analyze(child);
        match (&run, &info.exact) {
            (Some(current), Some(exact)) => {
                if let Some(joined) = product(current, exact) {
                    run = Some(joined);
                } else {
                    offer(current.clone());
                    run = Some(exact.clone());
                    all_exact = false;
                }
            }
            (None, Some(exact)) => run = Some(exact.clone()),
            (current, None) => {
                if let Some(current) = current {
                    offer(current.clone());
                }
                run = Some(BTreeSet::from([Vec::new()]));
                all_exact = false;
            }
        }
        if let Some(necessary) = info.necessary {
            offer(necessary);
        }
    }
    if let Some(current) = run.clone() {
        offer(current);
    }
    if all_exact { run } else { None }
}

fn alternation(children: &[Hir]) -> Info {
    let mut exact = Some(BTreeSet::new());
    let mut necessary = Some(BTreeSet::new());
    for child in children {
        let info = analyze(child);
        exact = match (exact, info.exact) {
            (Some(mut all), Some(set)) if all.len() + set.len() <= SET_LIMIT => {
                all.extend(set);
                Some(all)
            }
            _ => None,
        };
        necessary = match (necessary, info.necessary) {
            (Some(mut all), Some(set)) if all.len() + set.len() <= SET_LIMIT => {
                all.extend(set);
                Some(all)
            }
            _ => None,
        };
    }
    Info { exact, necessary }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literals(pattern: &str) -> Option<Vec<String>> {
        all_literals(pattern).map(|mut sets| sets.remove(0))
    }

    fn all_literals(pattern: &str) -> Option<Vec<Vec<String>>> {
        let hir = regex_syntax::parse(pattern).unwrap();
        required_literals(&hir).map(|sets| {
            sets.iter()
                .map(|set| {
                    set.iter()
                        .map(|literal| String::from_utf8(literal.to_vec()).unwrap())
                        .collect()
                })
                .collect()
        })
    }

    #[test]
    fn keeps_each_part_of_a_top_level_concatenation() {
        // The best set comes first; the `lob` part stays as a second set.
        assert_eq!(
            all_literals(r"[a-z]{0,5}?lob[ a-z]{0,3}=((?:live|test)_[a-f0-9]{4})"),
            Some(vec![
                vec!["live_".to_owned(), "test_".to_owned()],
                vec!["lob".to_owned()],
            ])
        );
        // A capture around the whole expression is looked through.
        assert_eq!(
            all_literals(r"(abc[0-9]+wxyz)"),
            Some(vec![vec!["wxyz".to_owned()], vec!["abc".to_owned()]])
        );
        assert_eq!(all_literals(r"abc|[0-9]+"), None);
    }

    #[test]
    fn finds_inner_literals_behind_optional_prefixes() {
        assert_eq!(
            literals(r"(?:^|[;=(]|\b)(?:[sS][eE][rR][vV][eE][rR]|[hH][oO][sS][tT])[ \t]*=x"),
            Some(vec!["host".to_owned(), "server".to_owned()])
        );
        // `s?` is optional, so the run before it ends at `amqp`.
        assert_eq!(
            literals(r"\b(?:redis|amqps?)://[a-z]+"),
            Some(vec!["amqp".to_owned(), "redis".to_owned()])
        );
        assert_eq!(
            literals(r"[a-z]+@bitbucket\.org/"),
            Some(vec!["@bitbucket.org/".to_owned()])
        );
    }

    #[test]
    fn refuses_sets_that_cannot_rule_out_a_buffer() {
        // An optional part or a short literal gives no useful condition.
        assert_eq!(literals(r"(?:abc)?[0-9]+"), None);
        assert_eq!(literals(r"ab[0-9]+"), None);
        assert_eq!(literals(r"abc|[0-9]+"), None);
        // Unicode case folding adds non-ASCII members such as the Kelvin sign.
        assert_eq!(literals(r"(?i)key"), None);
        assert_eq!(literals(r"(?i-u)key"), Some(vec!["key".to_owned()]));
        assert_eq!(literals(r"\x{e9}t\x{e9}"), None);
    }

    #[test]
    fn every_match_contains_a_reported_literal() {
        let cases: [(&str, &[&[u8]]); 3] = [
            (
                r"(?:^|;)(?:[hH][oO][sS][tT]|dsn)\s*=\s*([a-z]+)",
                &[b"HOST=abc", b";dsn = q", b"Host=x"],
            ),
            (r"x(?:abc|abd)+y", &[b"xabcabdy", b"xabdy"]),
            (r"(?:tok|key)_[0-9]{2}", &[b"tok_12", b"key_99"]),
        ];
        for (pattern, inputs) in cases {
            let found = literals(pattern).unwrap();
            let regex = regex_automata::meta::Regex::new(pattern).unwrap();
            for input in inputs {
                let matched = regex.find(*input).expect("case input matches");
                let text = input[matched.range()].to_ascii_lowercase();
                assert!(
                    found.iter().any(|literal| text
                        .windows(literal.len())
                        .any(|w| w == literal.as_bytes())),
                    "{pattern} on {input:?}"
                );
            }
        }
    }
}
