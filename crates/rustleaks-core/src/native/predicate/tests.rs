use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::{MAX_DECODED_BYTES, NativePredicate, parse};

fn make_predicate(decoded_max: usize) -> super::Base64UrlSegment {
    let value: toml::Value = toml::from_str(&format!(
        r#"
algorithm = "base64url-segment-go-regex-v1"
parts = 3
separator = "."
segment = 1
encodedMin = 1
encodedMax = 308
decodedMax = {decoded_max}
regex = ".*"
"#
    ))
    .unwrap();
    let NativePredicate::Base64UrlSegment(predicate) = parse(&value).unwrap() else {
        unreachable!()
    };
    predicate
}

#[test]
fn fixed_decode_guards_reject_every_non_url_alphabet_byte() {
    let predicate = make_predicate(231);
    let mut output = [0; MAX_DECODED_BYTES];
    // Four encoded ASCII 'A' bytes produce three NUL bytes, valid UTF-8.
    // Changing the last byte isolates the alphabet check; accepted
    // alphabet values also continue to produce valid UTF-8 here.
    let mut secret = *b"x.AAAA.y";
    for byte in 0..=255_u8 {
        secret[5] = byte;
        let allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_');
        assert_eq!(
            predicate.decode(&secret, &mut output).is_some(),
            allowed,
            "{byte}"
        );
    }
}

#[test]
fn decode_accepts_nonzero_pad_bits_and_rejects_utf8_and_length_errors() {
    let predicate = make_predicate(231);
    let mut output = [0; MAX_DECODED_BYTES];
    assert_eq!(
        predicate.decode(b"x.Zg.y", &mut output),
        Some(b"f".as_slice())
    );
    assert_eq!(
        predicate.decode(b"x.Zh.y", &mut output),
        Some(b"f".as_slice())
    );
    assert_eq!(
        predicate.decode(b"x.Zm8.y", &mut output),
        Some(b"fo".as_slice())
    );
    assert_eq!(
        predicate.decode(b"x.Zm9.y", &mut output),
        Some(b"fo".as_slice())
    );
    for invalid in [
        b"x._w.y".as_slice(),
        b"x.A.y",
        b"x.Zg==.y",
        b"x.Zg=.y",
        b"x.Zg.y.z",
        b"x.Zg",
        b"Zg",
        b"x..y",
    ] {
        assert_eq!(predicate.decode(invalid, &mut output), None);
    }
    for length in [230, 231, 232] {
        let encoded = URL_SAFE_NO_PAD.encode(vec![b'A'; length]);
        let secret = format!("x.{encoded}.y");
        assert_eq!(
            predicate
                .decode(secret.as_bytes(), &mut output)
                .map(<[u8]>::len),
            (length <= 231).then_some(length)
        );
    }
    let limited = make_predicate(230);
    let encoded = URL_SAFE_NO_PAD.encode([b'A'; 231]);
    assert_eq!(
        limited.decode(format!("x.{encoded}.y").as_bytes(), &mut output),
        None
    );
    assert_eq!(predicate.decode(&vec![b'A'; 927], &mut output), None);
}

#[test]
fn descriptor_preserves_quote_to_end_and_complete_alternatives() {
    for (pattern, accepted, rejected) in [
        (r"\Qabc", b"abc".as_slice(), b"abcx".as_slice()),
        (r"\Q.a*\E", b".a*", b".aaaa"),
        (r"\\Qabc", br"\Qabc", b"abc"),
        (r"(?i)\Qabc", b"ABC", b"ABCD"),
        (r"a|ab", b"ab", b"abc"),
        (r"(?m)^a$", b"a", b"a\n"),
    ] {
        let text = format!(
            r#"
algorithm = "base64url-segment-go-regex-v1"
parts = 3
separator = "."
segment = 1
encodedMin = 1
encodedMax = 308
decodedMax = 231
regex = '''{pattern}'''
"#
        );
        let value = toml::from_str(&text).unwrap();
        let NativePredicate::Base64UrlSegment(predicate) = parse(&value).unwrap() else {
            unreachable!()
        };
        let mut output = [0; MAX_DECODED_BYTES];
        for (payload, expected) in [(accepted, true), (rejected, false)] {
            let secret = format!("x.{}.y", URL_SAFE_NO_PAD.encode(payload));
            let decoded = predicate.decode(secret.as_bytes(), &mut output).unwrap();
            assert_eq!(predicate.matcher.is_match(decoded), expected, "{pattern}");
        }
    }
}
