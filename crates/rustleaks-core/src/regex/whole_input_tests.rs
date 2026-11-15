use super::{ByteSpan, GoRegex, GoRegexError, PATTERN_SIZE_LIMIT};

#[test]
fn whole_input_anchors_follow_go_quoting_and_flag_interpretation() {
    for (pattern, accepted, rejected) in [
        (r"\Qabc", "abc", "xabc"),
        (r"\Q.a*", ".a*", ".aaaa"),
        (r"\Q.a*\E", ".a*", "x.a*"),
        (r"\Qabc\Edef", "abcdef", "abcdefx"),
        (r"\\Qabc", r"\Qabc", "abc"),
        (r"\\Qabc\\E", r"\Qabc\E", "abc"),
        (r"(?i)\QAbC", "aBc", "xaBc"),
        (r"(?i:\Qx\E)y", "Xy", "XY"),
        (r"(?m)^a$", "a", "a\n"),
        (r"(?s)a.*b", "a\nb", "xa\nb"),
        (r"(?U)a.*", "abc", "xabc"),
    ] {
        let regex = GoRegex::compile_whole(pattern).unwrap();
        assert_eq!(regex.source(), pattern);
        assert!(regex.is_match(accepted.as_bytes()), "{pattern}");
        assert!(!regex.is_match(rejected.as_bytes()), "{pattern}");
        assert!(!regex.is_match(format!("{accepted}x").as_bytes()) || pattern == r"(?U)a.*");
    }
}

#[test]
fn whole_input_constraints_participate_in_alternative_selection() {
    for pattern in ["a|ab", "ab|a", "|ab", "a*|ab"] {
        let regex = GoRegex::compile_whole(pattern).unwrap();
        assert!(regex.is_match(b"ab"), "{pattern}");
        assert!(!regex.is_match(b"abc"), "{pattern}");
        assert!(!regex.is_match(b"xab"), "{pattern}");
    }
    let regex = GoRegex::compile_whole("(a|ab)").unwrap();
    assert_eq!(regex.capture_count(), 1);
    assert_eq!(
        regex.captures_all(b"ab")[0].spans(),
        &[
            Some(ByteSpan { start: 0, end: 2 }),
            Some(ByteSpan { start: 0, end: 2 }),
        ]
    );
    assert!(GoRegex::compile_whole("").unwrap().is_match(b""));
    assert!(!GoRegex::compile_whole("").unwrap().is_match(b"x"));
    assert!(GoRegex::compile("a|ab").unwrap().is_match(b"xab"));
    assert_ne!(
        GoRegex::compile("a").unwrap(),
        GoRegex::compile_whole("a").unwrap()
    );
}

#[test]
fn whole_input_compilation_keeps_source_and_compiled_limits() {
    assert!(matches!(
        GoRegex::compile_whole(&"x".repeat(PATTERN_SIZE_LIMIT + 1)),
        Err(GoRegexError::PatternTooLarge { .. })
    ));
    assert!(GoRegex::compile_whole(r"\E").is_err());
    assert!(GoRegex::compile_whole("(").is_err());
    assert!(GoRegex::preflight_mode("a{1000}", 128, true, true).is_err());
}
