//! Acceptance guards for validation that does not retain a search backend.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use serde::Deserialize;

use super::{GoRegex, GoRegexError};

fn compile_count(pattern: &str) -> Result<usize, GoRegexError> {
    GoRegex::compile(pattern).map(|regex| regex.capture_count())
}

#[derive(Deserialize)]
struct Request {
    pattern_base64: String,
}

#[test]
fn validation_matches_full_compile_for_frozen_and_default_patterns() {
    let mut patterns = BTreeSet::new();
    let mut requests = 0;
    for line in include_str!("../../../../compat/regex-corpus/requests-v1.jsonl").lines() {
        let request: Request = serde_json::from_str(line).unwrap();
        let bytes = BASE64_STANDARD.decode(request.pattern_base64).unwrap();
        if let Ok(pattern) = String::from_utf8(bytes) {
            patterns.insert(pattern);
        }
        requests += 1;
    }
    assert_eq!(requests, 3_618);
    let default = toml::from_str(include_str!("../../default/gitleaks.toml")).unwrap();
    collect_default_patterns(&default, &mut patterns);
    for pattern in patterns {
        assert_eq!(
            GoRegex::validate(&pattern),
            compile_count(&pattern),
            "{pattern:?}"
        );
    }
}

fn collect_default_patterns(value: &toml::Value, patterns: &mut BTreeSet<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                if matches!(key.as_str(), "regex" | "path") {
                    patterns.insert(value.as_str().unwrap().to_owned());
                } else if matches!(key.as_str(), "regexes" | "paths") {
                    let sources = value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|source| source.as_str().unwrap())
                        .collect::<Vec<_>>();
                    patterns.extend(sources.iter().map(|source| (*source).to_owned()));
                    if !sources.is_empty() {
                        patterns.insert(format!("(?:{})", sources.join("|")));
                    }
                } else {
                    collect_default_patterns(value, patterns);
                }
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                collect_default_patterns(value, patterns);
            }
        }
        _ => {}
    }
}

#[test]
fn validation_preserves_go_counts_including_hir_erased_captures() {
    for (pattern, count) in [
        ("", 0),
        ("()", 1),
        ("a|", 0),
        (r"\Q()\E", 0),
        ("(?P<1>a)", 1),
        ("(?P<x>a)(?P<x>b)", 2),
        ("(a)?(b*)", 2),
        ("(?P<x>a){0}", 1),
        ("((a)){0}", 2),
        (r"\b(\p{Greek}+)\B", 1),
    ] {
        assert_eq!(GoRegex::validate(pattern), Ok(count), "{pattern}");
        assert_eq!(compile_count(pattern), Ok(count), "{pattern}");
    }
}

#[test]
fn validation_keeps_translation_errors_before_parser_errors() {
    for (pattern, error) in [
        (
            "(",
            GoRegexError::Backend {
                message: "error parsing regex".into(),
            },
        ),
        (
            "\\",
            GoRegexError::Syntax {
                offset: 0,
                message: "trailing backslash".into(),
            },
        ),
        (
            "(\\",
            GoRegexError::Syntax {
                offset: 1,
                message: "trailing backslash".into(),
            },
        ),
        (
            r"\p{Age:3.0}",
            GoRegexError::Syntax {
                offset: 0,
                message: "invalid Go Unicode property".into(),
            },
        ),
    ] {
        assert_eq!(GoRegex::validate(pattern), Err(error.clone()), "{pattern}");
        assert_eq!(compile_count(pattern), Err(error), "{pattern}");
    }
}

#[test]
fn validation_handles_deep_captures_on_both_sides_of_the_stack_threshold() {
    // Captures survive HIR simplification, unlike nested noncapturing groups.
    for depth in [200, 201, 999] {
        let pattern = "(".repeat(depth) + "a" + &")".repeat(depth);
        assert_eq!(GoRegex::validate(&pattern), Ok(depth));
        let regex = GoRegex::compile(&pattern).unwrap();
        assert_eq!(regex.capture_count(), depth);
        assert!(regex.is_match(b"a"));
    }
    let too_deep = "(".repeat(1_000) + "a" + &")".repeat(1_000);
    let error = GoRegexError::Syntax {
        offset: 999,
        message: "expression nests too deeply".into(),
    };
    assert_eq!(GoRegex::validate(&too_deep), Err(error.clone()));
    assert_eq!(compile_count(&too_deep), Err(error));
}
