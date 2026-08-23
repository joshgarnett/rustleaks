//! Golden tests for byte-preserving core models.

use rustleaks_core::model::{
    ByteRange, ByteText, CommitMetadata, Finding, Fragment, Location, ModelError, RequiredFinding,
    ScanOptions,
};

fn assert_send_sync<T: Send + Sync>() {}

// RUST-MODEL-001; MODEL-001
#[test]
fn byte_text_and_ranges_preserve_arbitrary_bytes() {
    let raw = [b'a', 0x00, 0xff, 0x80, b'z'];
    let text = ByteText::from(&raw);

    assert_eq!(text.as_bytes(), raw);
    assert_eq!(text.len(), raw.len());
    assert!(!text.is_empty());
    assert!(text.as_str().is_err());
    assert_eq!(text.to_string_lossy(), "a\0��z");
    assert_eq!(text.clone().into_bytes(), raw);
    assert_eq!(format!("{text:?}"), "ByteText([97, 0, 255, 128, 122])");

    let range = ByteRange::new(1, 4).expect("ordered byte range");
    assert_eq!(range.start(), 1);
    assert_eq!(range.end(), 4);
    assert_eq!(range.len(), 3);
    assert_eq!(&raw[range.as_range()], [0x00, 0xff, 0x80]);
    assert_eq!(RangeLike::from(range).0, 1..4);
    assert!(ByteRange::new(3, 3).expect("empty range").is_empty());
    assert_eq!(
        ByteRange::new(4, 3),
        Err(ModelError::InvalidByteRange { start: 4, end: 3 })
    );
    assert_eq!(
        ByteRange::from_start_len(usize::MAX, 1),
        Err(ModelError::ByteRangeOverflow {
            start: usize::MAX,
            len: 1,
        })
    );

    let fragment = Fragment::new(raw);
    assert_eq!(fragment.content().as_bytes(), raw);
    assert_eq!(fragment.start_line(), 0);
}

struct RangeLike(std::ops::Range<usize>);

impl From<ByteRange> for RangeLike {
    fn from(value: ByteRange) -> Self {
        Self(value.into())
    }
}

// RUST-MODEL-002; MODEL-002
#[test]
fn fragment_builder_preserves_zero_start_lines_paths_and_commit_metadata() {
    let metadata = CommitMetadata::builder()
        .sha([b'1', b'2', 0xff])
        .author_name([b'J', 0x80, b'n'])
        .author_email(b"author@example.test")
        .date(b"2026-07-22T09:50:33-07:00")
        .message([b'm', b's', b'g', 0xff])
        .build();

    let direct = Fragment::builder([0xff, b'\n', b'x'])
        .file_path([b's', b'r', b'c', b'/', 0xff])
        .symlink_file(b"link/to/source")
        .windows_file_path(br"src\file.txt")
        .commit([b'a', b'b', 0x80])
        .start_line(0)
        .commit_metadata(metadata.clone())
        .inherited_from_finding(true)
        .build();

    assert_eq!(direct.content().as_bytes(), [0xff, b'\n', b'x']);
    assert_eq!(
        direct.file_path().as_bytes(),
        [b's', b'r', b'c', b'/', 0xff]
    );
    assert_eq!(direct.symlink_file().as_bytes(), b"link/to/source");
    assert_eq!(direct.windows_file_path().as_bytes(), br"src\file.txt");
    assert_eq!(direct.commit().as_bytes(), [b'a', b'b', 0x80]);
    assert_eq!(direct.start_line(), 0);
    assert!(direct.inherited_from_finding());
    assert_eq!(direct.commit_metadata(), Some(&metadata));
    assert_eq!(metadata.sha().as_bytes(), [b'1', b'2', 0xff]);
    assert_eq!(metadata.author_name().as_bytes(), [b'J', 0x80, b'n']);
    assert_eq!(metadata.author_email().as_bytes(), b"author@example.test");
    assert_eq!(metadata.date().as_bytes(), b"2026-07-22T09:50:33-07:00");
    assert_eq!(metadata.message().as_bytes(), [b'm', b's', b'g', 0xff]);

    let file_fragment = Fragment::builder(b"contents").start_line(1).build();
    assert_eq!(file_fragment.start_line(), 1);
    assert!(file_fragment.commit_metadata().is_none());
}

#[test]
fn fragment_source_path_replacement_reuses_content_and_preserves_metadata() {
    let metadata = CommitMetadata::builder().sha("abc123").build();
    let fragment = Fragment::builder(vec![b'x'; 32 * 1024])
        .file_path("physical/file.txt")
        .symlink_file("physical/link.txt")
        .windows_file_path(r"physical\file.txt")
        .commit("abc123")
        .start_line(7)
        .commit_metadata(metadata.clone())
        .inherited_from_finding(true)
        .build();
    let content_pointer = fragment.content().as_bytes().as_ptr();

    let translated = fragment.with_source_paths(
        ByteText::from("logical/file.txt"),
        ByteText::from("logical/link.txt"),
        ByteText::from(r"logical\file.txt"),
    );

    assert_eq!(translated.content().as_bytes().as_ptr(), content_pointer);
    assert_eq!(translated.content().len(), 32 * 1024);
    assert_eq!(translated.file_path().as_bytes(), b"logical/file.txt");
    assert_eq!(translated.symlink_file().as_bytes(), b"logical/link.txt");
    assert_eq!(
        translated.windows_file_path().as_bytes(),
        br"logical\file.txt"
    );
    assert_eq!(translated.commit().as_bytes(), b"abc123");
    assert_eq!(translated.start_line(), 7);
    assert_eq!(translated.commit_metadata(), Some(&metadata));
    assert!(translated.inherited_from_finding());
}

// RUST-MODEL-003; MODEL-003
#[test]
fn findings_preserve_coordinates_entropy_tags_metadata_and_duplicates() {
    let direct_location = Location::new(0, 0, 2, 6).expect("direct location");
    assert_eq!(direct_location.start_line(), 0);
    assert_eq!(direct_location.end_line(), 0);
    assert_eq!(direct_location.start_column(), 2);
    assert_eq!(direct_location.end_column(), 6);
    assert_eq!(
        Location::new(3, 2, 0, 0),
        Err(ModelError::InvalidLineRange { start: 3, end: 2 })
    );
    assert_eq!(
        Location::new(3, 3, 7, 6),
        Err(ModelError::InvalidColumnRange { start: 7, end: 6 })
    );
    // An end column before the start column is valid across different lines.
    assert!(Location::new(3, 4, 7, 2).is_ok());

    let auxiliary = RequiredFinding::builder()
        .rule_id("aux-rule")
        .location(Location::new(0, 0, 8, 11).expect("auxiliary location"))
        .line([b'l', 0xff])
        .match_text([b'm', 0x80])
        .secret([b's', 0xfe])
        .build()
        .expect("complete required finding");

    let entropy = f32::from_bits(0x4049_0fdb);
    let fragment = Fragment::builder([b'x', 0xff]).start_line(0).build();
    let mut finding = Finding::builder()
        .rule_id("primary-rule")
        .description("description")
        .location(direct_location)
        .line([b'l', 0xff])
        .match_text([b'm', 0x80])
        .secret([b's', 0xfe])
        .file([b'f', b'/', 0xff])
        .symlink_file("link")
        .commit("abc123")
        .link("https://example.test/repo")
        .entropy(entropy)
        .author([b'a', 0xff])
        .email("author@example.test")
        .date("2026-07-22")
        .message([b'm', 0x80])
        .tags(["decoded:base64", "decoded:base64", "decode-depth:2"])
        .fingerprint("abc123:f:primary-rule:0")
        .fragment(fragment.clone())
        .required_findings([auxiliary.clone(), auxiliary.clone()])
        .build()
        .expect("complete finding");

    finding.add_required_findings([auxiliary.clone()]);

    assert_eq!(finding.rule_id().as_bytes(), b"primary-rule");
    assert_eq!(finding.description().as_bytes(), b"description");
    assert_eq!(finding.location(), direct_location);
    assert_eq!(finding.line().as_bytes(), [b'l', 0xff]);
    assert_eq!(finding.match_text().as_bytes(), [b'm', 0x80]);
    assert_eq!(finding.secret().as_bytes(), [b's', 0xfe]);
    assert_eq!(finding.file().as_bytes(), [b'f', b'/', 0xff]);
    assert_eq!(finding.symlink_file().as_bytes(), b"link");
    assert_eq!(finding.commit().as_bytes(), b"abc123");
    assert_eq!(finding.link().as_bytes(), b"https://example.test/repo");
    assert_eq!(finding.entropy().to_bits(), 0x4049_0fdb);
    assert_eq!(finding.author().as_bytes(), [b'a', 0xff]);
    assert_eq!(finding.email().as_bytes(), b"author@example.test");
    assert_eq!(finding.date().as_bytes(), b"2026-07-22");
    assert_eq!(finding.message().as_bytes(), [b'm', 0x80]);
    assert_eq!(finding.tags()[0], finding.tags()[1]);
    assert_eq!(finding.tags().len(), 3);
    assert_eq!(finding.fingerprint().as_bytes(), b"abc123:f:primary-rule:0");
    assert_eq!(finding.fragment(), Some(&fragment));
    assert_eq!(
        finding.required_findings(),
        &[auxiliary.clone(), auxiliary.clone(), auxiliary]
    );

    assert_eq!(
        Finding::builder()
            .location(direct_location)
            .build()
            .expect_err("rule ID is required"),
        ModelError::MissingField {
            model: "Finding",
            field: "rule_id",
        }
    );
    assert_eq!(
        RequiredFinding::builder()
            .rule_id("aux")
            .build()
            .expect_err("location is required"),
        ModelError::MissingField {
            model: "RequiredFinding",
            field: "location",
        }
    );
}

// RED-001; TM-0241..TM-0250
#[test]
fn finding_redaction_uses_go_bytes_round_to_even_and_keeps_auxiliaries() {
    let location = Location::new(0, 0, 1, 1).unwrap();
    let auxiliary = RequiredFinding::builder()
        .rule_id("auxiliary")
        .location(location)
        .line("aux-secret")
        .match_text("aux-secret")
        .secret("aux-secret")
        .build()
        .unwrap();
    let finding = Finding::builder()
        .rule_id("primary")
        .location(location)
        .line("secret and secret")
        .match_text("secret")
        .secret("secret")
        .required_findings([auxiliary])
        .build()
        .unwrap();

    for (percent, expected) in [
        (10, b"secre...".as_slice()),
        (75, b"se...".as_slice()),
        (90, b"s...".as_slice()),
    ] {
        let redacted = finding.clone().redacted(percent);
        assert_eq!(redacted.secret().as_bytes(), expected);
        assert_eq!(
            redacted.required_findings()[0].secret().as_bytes(),
            b"aux-secret"
        );
    }
    let fully = finding.redacted(1_000);
    assert_eq!(fully.secret().as_bytes(), b"REDACTED");
    assert_eq!(
        fully.line().as_bytes(),
        b"REDACTED and REDACTED",
        "every occurrence uses the original secret"
    );

    let short = Finding::builder()
        .rule_id("short")
        .location(location)
        .match_text("ss")
        .secret("ss")
        .build()
        .unwrap()
        .redacted(75);
    assert_eq!(short.secret().as_bytes(), b"...");

    let empty = Finding::builder()
        .rule_id("empty")
        .location(location)
        .line([b'A', 0xc3, 0xa9, 0xff])
        .match_text(Vec::<u8>::new())
        .secret(Vec::<u8>::new())
        .build()
        .unwrap();
    assert_eq!(empty.clone().redacted(75), empty);
    let empty_full = empty.redacted(100);
    assert_eq!(empty_full.secret().as_bytes(), b"REDACTED");
    assert_eq!(
        empty_full.line().as_bytes(),
        [
            b"REDACTED".as_slice(),
            b"A",
            b"REDACTED",
            &[0xc3, 0xa9],
            b"REDACTED",
            &[0xff],
            b"REDACTED",
        ]
        .concat()
    );
    assert_eq!(empty_full.match_text().as_bytes(), b"REDACTED");
}

#[test]
fn scan_options_preserve_upstream_domain_and_models_are_send_sync() {
    let defaults = ScanOptions::default();
    assert_eq!(defaults.max_decode_depth(), 0);
    assert_eq!(defaults.max_target_bytes(), None);
    assert_eq!(defaults.redaction_percent(), 0);
    assert!(defaults.honor_allow_markers());
    assert!(defaults.honor_gitleaks_allow());

    let options = ScanOptions::builder()
        .max_decode_depth(5)
        .max_target_bytes(Some(1_000_000))
        .redaction_percent(75)
        .honor_allow_markers(false)
        .build();
    assert_eq!(options.max_decode_depth(), 5);
    assert_eq!(options.max_target_bytes(), Some(1_000_000));
    assert_eq!(options.redaction_percent(), 75);
    assert!(!options.honor_gitleaks_allow());
    assert!(!options.honor_allow_markers());
    let oversized = ScanOptions::builder().redaction_percent(1_000).build();
    assert_eq!(oversized.redaction_percent(), 1_000);

    assert_send_sync::<ByteText>();
    assert_send_sync::<ByteRange>();
    assert_send_sync::<Fragment>();
    assert_send_sync::<CommitMetadata>();
    assert_send_sync::<Location>();
    assert_send_sync::<Finding>();
    assert_send_sync::<RequiredFinding>();
    assert_send_sync::<ScanOptions>();
    assert_send_sync::<ModelError>();
}

#[test]
fn finding_serde_uses_go_field_names_and_utf8_replacement() {
    let finding = Finding::builder()
        .rule_id("test-rule")
        .description("")
        .location(Location::new(1, 2, 1, 2).expect("valid location"))
        .line("not serialized")
        .match_text([b'm', 0xff, 0x80])
        .secret("a secret")
        .file("auth.py")
        .commit("0000000000000000")
        .author("John Doe")
        .email("johndoe@gmail.com")
        .date("10-19-2003")
        .message("opps")
        .build()
        .expect("complete finding");

    let value = serde_json::to_value(&finding).expect("serialize finding");
    assert_eq!(
        value,
        serde_json::json!({
            "RuleID": "test-rule",
            "Description": "",
            "StartLine": 1,
            "EndLine": 2,
            "StartColumn": 1,
            "EndColumn": 2,
            "Match": "m��",
            "Secret": "a secret",
            "File": "auth.py",
            "SymlinkFile": "",
            "Commit": "0000000000000000",
            "Entropy": 0.0,
            "Author": "John Doe",
            "Email": "johndoe@gmail.com",
            "Date": "10-19-2003",
            "Message": "opps",
            "Tags": [],
            "Fingerprint": ""
        })
    );
    assert!(value.get("Line").is_none());
    assert!(value.get("Link").is_none());
    assert!(value.get("Fragment").is_none());
}
