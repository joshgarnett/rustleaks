//! Default rule cases that the recorded generator samples do not cover: the
//! two Dropbox rules without samples, and every positive sample
//! after one or two layers of encoding.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustleaks_core::Engine;
use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{
    ByteRange, ByteText, Finding, FindingRange, Fragment, Location, ScanOptions,
};
use serde::Deserialize;

fn default_config() -> &'static CompiledConfig {
    static CONFIG: OnceLock<CompiledConfig> = OnceLock::new();
    CONFIG.get_or_init(|| ConfigLoader::new().load_default().unwrap())
}

fn single_rule(rule: &str) -> Engine {
    Engine::builder(default_config().select_rules([rule]).unwrap())
        .build()
        .unwrap()
}

fn scan(engine: &Engine, input: &[u8], depth: usize) -> Vec<Finding> {
    let outcome = engine.scan_fragment(
        &Fragment::new(input),
        &ScanOptions::builder().max_decode_depth(depth).build(),
    );
    assert!(outcome.is_complete());
    outcome.findings().to_vec()
}

fn exact(start: usize, end: usize) -> FindingRange {
    FindingRange::Exact(ByteRange::new(start, end).unwrap())
}

// Synthetic body characters. They avoid the global allowlist stopwords and
// the words `true`, `false` and `null`.
fn body(alphabet: &str, length: usize) -> String {
    alphabet.chars().cycle().take(length).collect()
}

// Both Dropbox token rules share this prefix (from the default rule text):
// `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}` then an
// operator, up to five quote, space or `=` bytes, the secret group, and one
// terminator: a quote, backtick, whitespace, `;`, an escaped `n` or `r`, or
// the end of the text. The secret is the first capture group.
fn assert_dropbox(rule: &str, secret: &str) {
    let engine = single_rule(rule);
    // (bytes before the match, match up to the secret, bytes after the
    // secret, terminator bytes inside the match). The lazy name prefix makes
    // the match start at the first byte that can begin a name.
    for (before, assignment, tail, terminator) in [
        ("", "DROPBOX_TOKEN = \"", "\"", 1),
        ("", "dropbox_token: '", "'", 1),
        ("", "my.dropbox-token=", ";", 1),
        ("", "Dropbox_Token := `", "`", 1),
        ("\"", "dropboxToken\": \"", "\",", 1),
        ("x\n", "DROPBOX_TOKEN=", "", 0),
        ("x\n", "dropbox_key => ", "\\n", 2),
        ("x\n  ", "dropbox: ", " # comment", 1),
    ] {
        let input = format!("{before}{assignment}{secret}{tail}");
        let findings = scan(&engine, input.as_bytes(), 0);
        assert_eq!(findings.len(), 1, "{rule}: {assignment}");
        let finding = &findings[0];
        let start = before.len();
        let secret_start = start + assignment.len();
        let secret_end = secret_start + secret.len();
        let match_end = secret_end + terminator;
        assert_eq!(finding.rule_id().as_bytes(), rule.as_bytes());
        assert_eq!(finding.secret().as_bytes(), secret.as_bytes());
        assert_eq!(
            finding.match_text().as_bytes(),
            &input.as_bytes()[start..match_end]
        );
        assert_eq!(finding.secret_range(), exact(secret_start, secret_end));
        assert_eq!(finding.match_range(), exact(start, match_end));
        // Columns count from 1 on the first line and from the preceding LF
        // on later lines. The end column is the column of the last byte.
        let (line, origin) = if before.starts_with("x\n") {
            (1, 1)
        } else {
            (0, 0)
        };
        assert_eq!(
            finding.location(),
            Location::new(line, line, start - origin + 1, match_end - origin).unwrap(),
            "{rule}: {assignment}"
        );
    }
}

#[test]
fn dropbox_short_lived_token_has_exact_spans() {
    let secret = format!("sl.{}", body("Q7m2Z9v4L1c8R5s0N6b3X-_=", 135));
    assert_dropbox("dropbox-short-lived-api-token", &secret);
}

#[test]
fn dropbox_long_lived_token_has_exact_spans() {
    let secret = format!(
        "{}AAAAAAAAAA{}",
        body("q7m2z9v4l1c8", 11),
        body("Q7m2Z9v4L1c8R5s0N6b3X-_=", 43)
    );
    assert_dropbox("dropbox-long-lived-api-token", &secret);
}

#[test]
fn dropbox_token_near_misses_are_not_reported() {
    let short_body = body("Q7m2Z9v4L1c8R5s0N6b3X-_=", 135);
    let long_head = body("q7m2z9v4l1c8", 11);
    let long_tail = body("Q7m2Z9v4L1c8R5s0N6b3X-_=", 43);
    let cases = [
        (
            "dropbox-short-lived-api-token",
            format!("DROPBOX_TOKEN = \"sl.{short_body}\""),
        ),
        // One body byte short or long leaves no terminator after the group.
        (
            "dropbox-short-lived-api-token",
            format!("DROPBOX_TOKEN = \"sl.{}\"", &short_body[1..]),
        ),
        (
            "dropbox-short-lived-api-token",
            format!("DROPBOX_TOKEN = \"sl.{short_body}Q\""),
        ),
        // The prefix is `sl.`, not `sl-`.
        (
            "dropbox-short-lived-api-token",
            format!("DROPBOX_TOKEN = \"sl-{short_body}\""),
        ),
        // A byte outside the body class.
        (
            "dropbox-short-lived-api-token",
            format!(
                "DROPBOX_TOKEN = \"sl.{}!{}\"",
                &short_body[..67],
                &short_body[68..]
            ),
        ),
        // The keyword is required.
        (
            "dropbox-short-lived-api-token",
            format!("DRPBOX_TOKEN = \"sl.{short_body}\""),
        ),
        // No assignment operator between the name and the value.
        (
            "dropbox-short-lived-api-token",
            format!("DROPBOX_TOKEN \"sl.{short_body}\""),
        ),
        (
            "dropbox-long-lived-api-token",
            format!("DROPBOX_TOKEN = \"{long_head}AAAAAAAAAA{long_tail}\""),
        ),
        // Nine `A` bytes instead of ten.
        (
            "dropbox-long-lived-api-token",
            format!("DROPBOX_TOKEN = \"{long_head}qAAAAAAAAA{long_tail}\""),
        ),
        (
            "dropbox-long-lived-api-token",
            format!(
                "DROPBOX_TOKEN = \"{long_head}AAAAAAAAAA{}\"",
                &long_tail[1..]
            ),
        ),
        (
            "dropbox-long-lived-api-token",
            format!("DROPBOX_TOKEN = \"{long_head}AAAAAAAAAA{long_tail}!\""),
        ),
        (
            "dropbox-long-lived-api-token",
            format!("TOKEN = \"{long_head}AAAAAAAAAA{long_tail}\""),
        ),
    ];
    // The first case of each rule is the positive control.
    for (index, (rule, input)) in cases.iter().enumerate() {
        let expected = usize::from(index == 0 || index == 7);
        assert_eq!(
            scan(&single_rule(rule), input.as_bytes(), 0).len(),
            expected,
            "{rule}: case {index}"
        );
    }
}

#[derive(Deserialize)]
struct Sample {
    case_id: String,
    rule_id: String,
    polarity: String,
    input_base64: String,
    findings: Vec<SampleFinding>,
}

#[derive(Deserialize)]
struct SampleFinding {
    match_base64: String,
    secret_base64: String,
}

fn ordinary_positives() -> Vec<Sample> {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/generator-corpus/samples-v1.jsonl");
    fs::read_to_string(corpus)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Sample>(line).unwrap())
        .filter(|sample| sample.polarity == "ordinary_true")
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Encoding {
    Percent,
    Unicode,
    Hex,
    Base64,
}

impl Encoding {
    // Independent encoders; they do not call the decoder under test.
    fn encode(self, value: &[u8]) -> Vec<u8> {
        if self == Self::Base64 {
            return STANDARD.encode(value).into_bytes();
        }
        let mut encoded = String::new();
        for byte in value {
            match self {
                Self::Percent => write!(encoded, "%{byte:02X}"),
                Self::Unicode => write!(encoded, "\\u{byte:04x}"),
                Self::Hex => write!(encoded, "{byte:02x}"),
                Self::Base64 => unreachable!(),
            }
            .unwrap();
        }
        encoded.into_bytes()
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::Percent => "decoded:percent",
            Self::Unicode => "decoded:unicode",
            Self::Hex => "decoded:hex",
            Self::Base64 => "decoded:base64",
        }
    }

    /// Whether the decoder takes the whole encoded text as one
    /// candidate of this kind and restores the original bytes, from the
    /// candidate patterns and the per-kind output filters:
    /// percent, hex and Base64 keep a result only when every byte is in
    /// 0x09..=0x7e; hex needs at least 32 digits; Base64 needs 16 characters
    /// and one of `0-9+/-_`, and loses to the hex pattern when 32 hex digits
    /// start the text; unicode escapes restore only ASCII bytes. The unicode
    /// pattern `(?:U\+[a-fA-F0-9]{4}(?:\s|$))+` cannot take Base64 text of 16
    /// or more characters: it needs whitespace or the end after six bytes.
    fn restores(self, value: &[u8], encoded: &[u8]) -> bool {
        let printable = value.iter().all(|byte| (0x09..=0x7e).contains(byte));
        match self {
            Self::Percent => printable,
            Self::Unicode => value.is_ascii(),
            Self::Hex => printable && encoded.len() >= 32,
            Self::Base64 => {
                printable
                    && encoded.len() >= 16
                    && encoded
                        .iter()
                        .any(|byte| matches!(byte, b'0'..=b'9' | b'+' | b'/' | b'-' | b'_'))
                    && !(encoded.len() >= 32 && encoded[..32].iter().all(u8::is_ascii_hexdigit))
            }
        }
    }
}

fn tags(finding: &Finding) -> Vec<&[u8]> {
    finding.tags().iter().map(ByteText::as_bytes).collect()
}

/// Runs every positive sample through `chain` and checks the decoded finding
/// against the recorded depth-0 match and secret.
fn assert_encoded_samples(chain: &[Encoding]) -> (usize, usize) {
    let samples = ordinary_positives();
    assert_eq!(samples.len(), 6_368);
    let mut engines = BTreeMap::new();
    let mut restored = 0;
    let mut not_restored = 0;
    let mut failures = Vec::new();
    for sample in &samples {
        let engine = engines
            .entry(sample.rule_id.clone())
            .or_insert_with(|| single_rule(&sample.rule_id));
        let value = STANDARD.decode(&sample.input_base64).unwrap();
        let mut encoded = value.clone();
        let mut expected_restored = true;
        for encoding in chain {
            let next = encoding.encode(&encoded);
            expected_restored &= encoding.restores(&encoded, &next);
            encoded = next;
        }
        let findings = scan(engine, &encoded, chain.len());
        // The encoded text alone never matches the owning rule, so every
        // finding comes from decoded text.
        let decoded = findings
            .iter()
            .filter(|finding| {
                tags(finding).contains(&format!("decode-depth:{}", chain.len()).as_bytes())
            })
            .collect::<Vec<_>>();
        if decoded.len() != findings.len() {
            failures.push(format!("{}: raw finding on encoded text", sample.case_id));
            continue;
        }
        if !expected_restored {
            not_restored += 1;
            // Percent, hex and Base64 drop an unprintable result. Unicode
            // escapes decode to different bytes instead, so make no claim.
            if !chain.contains(&Encoding::Unicode) && !findings.is_empty() {
                failures.push(format!("{}: decoded an unrestorable value", sample.case_id));
            }
            continue;
        }
        restored += 1;
        let [expected] = sample.findings.as_slice() else {
            panic!("{}: one recorded finding", sample.case_id);
        };
        let [finding] = decoded.as_slice() else {
            failures.push(format!("{}: {} findings", sample.case_id, decoded.len()));
            continue;
        };
        let mut expected_tags = Vec::new();
        for encoding in [
            Encoding::Percent,
            Encoding::Unicode,
            Encoding::Hex,
            Encoding::Base64,
        ] {
            if chain.contains(&encoding) {
                expected_tags.push(encoding.tag().as_bytes().to_vec());
            }
        }
        expected_tags.push(format!("decode-depth:{}", chain.len()).into_bytes());
        // The encoded text is one line, so the location covers all of it.
        if finding.rule_id().as_bytes() != sample.rule_id.as_bytes()
            || finding.match_text().as_bytes()
                != STANDARD.decode(&expected.match_base64).unwrap().as_slice()
            || finding.secret().as_bytes()
                != STANDARD.decode(&expected.secret_base64).unwrap().as_slice()
            || tags(finding) != expected_tags.iter().map(Vec::as_slice).collect::<Vec<_>>()
            || finding.location() != Location::new(0, 0, 1, encoded.len()).unwrap()
            || finding.match_range() != FindingRange::Unavailable
            || finding.secret_range() != FindingRange::Unavailable
        {
            failures.push(format!("{}: decoded finding differs", sample.case_id));
        }
    }
    assert!(failures.is_empty(), "{chain:?}: {failures:#?}");
    (restored, not_restored)
}

// Each expected pair is (restored, not restored), counted from the recorded
// inputs with the rule in `Encoding::restores`. `GEN/JWT/ordinary_true/0052`
// holds UTF-8 bytes above 0x7e, so no encoding restores it. Encoded twice,
// `GEN/AWS/ordinary_true/0031` and `GEN/AWS/ordinary_true/0046` become Base64
// text without a digit or `+/-_`, which the decoder does not decode.
#[test]
fn every_positive_sample_is_found_inside_base64_at_depth_one() {
    assert_eq!(assert_encoded_samples(&[Encoding::Base64]), (6_367, 1));
}

#[test]
fn every_positive_sample_is_found_inside_hex_at_depth_one() {
    assert_eq!(assert_encoded_samples(&[Encoding::Hex]), (6_367, 1));
}

#[test]
fn every_positive_sample_is_found_inside_percent_encoding_at_depth_one() {
    assert_eq!(assert_encoded_samples(&[Encoding::Percent]), (6_367, 1));
}

#[test]
fn every_positive_sample_is_found_inside_unicode_escapes_at_depth_one() {
    assert_eq!(assert_encoded_samples(&[Encoding::Unicode]), (6_367, 1));
}

#[test]
fn every_positive_sample_is_found_inside_two_base64_layers_at_depth_two() {
    assert_eq!(
        assert_encoded_samples(&[Encoding::Base64, Encoding::Base64]),
        (6_365, 3)
    );
}

#[test]
fn every_positive_sample_is_found_inside_hex_then_base64_at_depth_two() {
    assert_eq!(
        assert_encoded_samples(&[Encoding::Hex, Encoding::Base64]),
        (6_367, 1)
    );
}

#[test]
fn one_layer_short_of_the_depth_finds_nothing() {
    let engine = single_rule("dropbox-short-lived-api-token");
    let secret = format!("sl.{}", body("Q7m2Z9v4L1c8R5s0N6b3X-_=", 135));
    let plain = format!("DROPBOX_TOKEN = \"{secret}\"");
    let once = Encoding::Base64.encode(plain.as_bytes());
    let twice = Encoding::Base64.encode(&once);
    assert_eq!(scan(&engine, plain.as_bytes(), 0).len(), 1);
    assert!(scan(&engine, &once, 0).is_empty());
    assert_eq!(scan(&engine, &once, 1).len(), 1);
    assert!(scan(&engine, &twice, 1).is_empty());
    assert_eq!(scan(&engine, &twice, 2).len(), 1);
    assert_eq!(scan(&engine, &twice, 5).len(), 1);
}

// The default private-key rule:
// `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`
// It has no capture group, so the secret is the whole match. The lazy body
// ends at the first `KEY-----` or `KEY BLOCK-----` after at least 64 bytes.
// The armor lines are built at run time so this file holds no key text.
fn armor(word: &str, label: &str) -> String {
    let dashes = "-".repeat(5);
    format!("{dashes}{word} {label}{dashes}")
}

fn key_body(lines: usize, separator: &str) -> String {
    (0..lines)
        .map(|line| body(&"Q7m2Z9v4L1c8R5s0N6b3X+/a"[line % 3..], 64))
        .collect::<Vec<_>>()
        .join(separator)
}

fn count_lf(bytes: &[u8]) -> usize {
    bytes.iter().map(|byte| usize::from(*byte == b'\n')).sum()
}

/// Location of `start..end`, from the column rule used above.
fn span_location(text: &[u8], start: usize, end: usize) -> Location {
    let position = |index: usize| {
        let before = &text[..index];
        let line = count_lf(before);
        let column = before
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(index + 1, |lf| index - lf + 1);
        (line, column)
    };
    let (start_line, start_column) = position(start);
    let (end_line, end_column) = position(end - 1);
    Location::new(start_line, end_line, start_column, end_column).unwrap()
}

/// Checks that `text` holds exactly the private keys that start at the
/// `BEGIN` armor offsets in `starts` and end after the following `END` armor.
fn assert_private_keys(name: &str, text: &str, starts: &[usize]) {
    let findings = scan(&single_rule("private-key"), text.as_bytes(), 0);
    assert_eq!(findings.len(), starts.len(), "{name}");
    let dashes = "-".repeat(5);
    for (finding, &start) in findings.iter().zip(starts) {
        // The match ends with the dashes that close the next END armor.
        let end_armor = start + text[start..].find(&format!("{dashes}END")).unwrap();
        let end = end_armor + 5 + text[end_armor + 5..].find(&dashes).unwrap() + 5;
        assert_eq!(
            finding.secret().as_bytes(),
            &text.as_bytes()[start..end],
            "{name}"
        );
        assert_eq!(
            finding.match_text().as_bytes(),
            &text.as_bytes()[start..end],
            "{name}"
        );
        assert_eq!(finding.match_range(), exact(start, end), "{name}");
        assert_eq!(finding.secret_range(), exact(start, end), "{name}");
        assert_eq!(
            finding.location(),
            span_location(text.as_bytes(), start, end),
            "{name}"
        );
    }
}

#[test]
fn private_keys_have_exact_offsets_with_lf_and_crlf_lines() {
    for (label, newline) in [("RSA PRIVATE KEY", "\n"), ("PRIVATE KEY", "\r\n")] {
        let text = [
            "# deploy key".to_owned(),
            armor("BEGIN", label),
            key_body(3, newline),
            armor("END", label),
            String::new(),
        ]
        .join(newline);
        let start = "# deploy key".len() + newline.len();
        assert_private_keys(label, &text, &[start]);
    }
}

#[test]
fn private_keys_with_numbered_lines_keep_the_numbers_inside_the_match() {
    // `cat -n` output: a right-aligned number and a tab before every line.
    let lines = [
        armor("BEGIN", "OPENSSH PRIVATE KEY"),
        key_body(1, ""),
        key_body(1, "").to_lowercase(),
        armor("END", "OPENSSH PRIVATE KEY"),
    ];
    let mut text = String::new();
    for (index, line) in lines.iter().enumerate() {
        writeln!(text, "{:>6}\t{line}", index + 1).unwrap();
    }
    assert_private_keys("numbered", &text, &[7]);
}

#[test]
fn private_keys_in_one_ini_value_and_pgp_blocks_have_exact_offsets() {
    // An INI value that holds the key with escaped line breaks.
    let prefix = "[ssh]\nhost = example.invalid\nidentity = ";
    let text = format!(
        "{prefix}{}\\n{}\\n{}\nport = 22\n",
        armor("BEGIN", "EC PRIVATE KEY"),
        key_body(2, "\\n"),
        armor("END", "EC PRIVATE KEY")
    );
    assert_private_keys("ini", &text, &[prefix.len()]);

    let text = format!(
        "{}\n\n{}\n{}\n",
        armor("BEGIN", "PGP PRIVATE KEY BLOCK"),
        key_body(2, "\n"),
        armor("END", "PGP PRIVATE KEY BLOCK")
    );
    assert_private_keys("pgp", &text, &[0]);

    // Two keys in one file give two findings; lowercase armor also matches.
    let first = format!(
        "{}\n{}\n{}\n",
        armor("BEGIN", "PRIVATE KEY"),
        key_body(2, "\n"),
        armor("END", "PRIVATE KEY")
    );
    let second = format!(
        "{}\n{}\n{}\n",
        armor("begin", "private key"),
        key_body(2, "\n"),
        armor("END", "PRIVATE KEY")
    );
    let text = format!("{first}\n{second}");
    assert_private_keys("two", &text, &[0, first.len() + 1]);
}

#[test]
fn private_key_placeholders_follow_the_body_length_rule() {
    // A body under 64 bytes is not a key.
    let short = format!(
        "{}\n{}\n{}\n",
        armor("BEGIN", "PRIVATE KEY"),
        "REPLACE_ME",
        armor("END", "PRIVATE KEY")
    );
    assert_private_keys("short placeholder", &short, &[]);
    let header_only = format!("key: \"{}\"\n", armor("BEGIN", "PRIVATE KEY"));
    assert_private_keys("header only", &header_only, &[]);
    // The rule has no placeholder filter: a long placeholder body is a match.
    let long = format!(
        "{}\n{}\n{}\n",
        armor("BEGIN", "PRIVATE KEY"),
        "PASTE_YOUR_KEY_HERE_".repeat(4),
        armor("END", "PRIVATE KEY")
    );
    assert_private_keys("long placeholder", &long, &[0]);
    // Without the END armor nothing matches, however long the body is.
    let open = format!("{}\n{}\n", armor("BEGIN", "PRIVATE KEY"), key_body(8, "\n"));
    assert_private_keys("no end", &open, &[]);
}
