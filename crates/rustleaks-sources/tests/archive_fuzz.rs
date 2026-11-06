//! Deterministic coverage of the archive fuzz framing and decoder entry points.
#![cfg(feature = "archives")]

#[path = "../fuzz/support/archive_frame.rs"]
mod archive_frame;
#[path = "../fuzz/support/archive_harness.rs"]
mod archive_harness;
#[path = "../fuzz/support/archive_seeds.rs"]
mod archive_seeds;
#[allow(dead_code)]
#[path = "../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;
#[allow(dead_code)] // COPY is exercised by archive_semantics; these seeds use compression.
#[path = "../fuzz/support/sevenz_seeds.rs"]
mod sevenz_seeds;

use std::fs;
use std::path::{Path, PathBuf};

use archive_frame::{FORMAT_NAMES, Frame, HEADER_BYTES, MAGIC, MAX_INPUT_BYTES, encode};
use archive_harness::{MAX_MEMBER_BYTES, MAX_TOTAL_BYTES, exercise};
use rustleaks_sources::{SourceControl, SourceError, SourceEvent, SourceIssueKind};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_format_and_callback_mode_are_independently_selectable() {
    for selector in 0..=u8::MAX {
        for control in 0..=u8::MAX {
            let input = encode(selector, control, b"payload");
            let frame = Frame::decode(&input).expect("versioned frame");
            assert_eq!(frame.format, usize::from(selector) % FORMAT_NAMES.len());
            assert_eq!(frame.control, control);
            assert_eq!(frame.cancel_before(), control & 1 != 0);
            assert_eq!(frame.cancel_after_event(), control & 2 != 0);
            assert_eq!(frame.stop_after_event(), control & 4 != 0);
            assert_eq!(frame.payload, b"payload");
        }
    }
}

#[test]
fn framing_rejects_unsupported_versions_and_bounds_the_input() {
    for length in 0..HEADER_BYTES {
        assert!(Frame::decode(&vec![0; length]).is_none());
    }
    let mut input = encode(0, 0, b"payload");
    input[MAGIC.len() - 1] += 1;
    assert!(exercise(&input, |_| panic!("unsupported frame was visited")).is_none());
    let oversized = encode(0, 0, &vec![0; MAX_INPUT_BYTES * 2]);
    assert_eq!(
        Frame::decode(&oversized)
            .expect("bounded frame")
            .payload
            .len(),
        MAX_INPUT_BYTES - HEADER_BYTES,
    );
}

#[test]
fn every_seeded_format_decodes_complete_expected_content_in_normal_mode() {
    let seeds = archive_seeds::cases(&root()).expect("reviewed seeds");
    let mut formats = [false; 16];
    for seed in seeds {
        formats[usize::from(seed.format)] = true;
        let input = encode(seed.format, 0, &seed.payload);
        let mut actual = Vec::new();
        let mut issues = 0;
        let observation = exercise(&input, |event| match event {
            SourceEvent::Fragment { fragment, issue } => {
                actual.push(fragment.content().as_bytes().to_vec());
                issues += usize::from(issue.is_some());
            }
            SourceEvent::Issue(_) => issues += 1,
            _ => panic!("unhandled source event"),
        })
        .expect("valid frame");
        assert_eq!(observation.input_bytes, input.len());
        assert!(
            matches!(observation.result, Ok(SourceControl::Continue)),
            "seed {} did not complete",
            seed.id,
        );
        assert_eq!(issues, 0, "seed {} produced an issue", seed.id);
        let mut expected = seed.expected;
        actual.sort();
        expected.sort();
        // Do not print source-derived contents on failure.
        assert!(actual == expected, "seed {} content mismatch", seed.id);
        assert_eq!(observation.events, actual.len(), "seed {}", seed.id);
        assert_eq!(
            observation.emitted_bytes,
            expected.iter().map(Vec::len).sum::<usize>(),
            "seed {}",
            seed.id,
        );
        assert!(!seed.origin.is_empty());
    }
    assert_eq!(formats, [true; 16], "a fuzz format has no decoded seed");
    assert_eq!(formats.len(), FORMAT_NAMES.len());
}

#[test]
fn compressed_sevenz_seeds_regenerate_with_the_maintained_encoders() {
    let seeds = archive_seeds::cases(&root()).expect("reviewed seeds");
    let payload = archive_seeds::CODEC_PAYLOAD.repeat(8);
    assert_eq!(payload.len(), 224);
    for (id, method) in [
        ("7z-deflate", sevenz_seeds::Method::Deflate),
        ("7z-lz4", sevenz_seeds::Method::Lz4),
    ] {
        let seed = seeds
            .iter()
            .find(|seed| seed.id == id)
            .expect("compressed seed");
        let member = sevenz_seeds::Member::new("value.txt", &payload, method);
        assert!(member.packed.len() < payload.len());
        assert_eq!(seed.format, 2);
        assert_eq!(seed.expected.as_slice(), std::slice::from_ref(&payload));
        assert_eq!(seed.payload, sevenz_seeds::archive(&[member]));
    }
}

#[test]
fn every_format_reaches_pre_cancel_callback_cancel_and_stop() {
    for seed in archive_seeds::cases(&root()).expect("reviewed seeds") {
        for control in [1, 2, 4] {
            let input = encode(seed.format, control, &seed.payload);
            let observation = exercise(&input, |_| {}).expect("valid frame");
            if control == 1 {
                assert!(matches!(observation.result, Err(SourceError::Cancelled)));
                assert_eq!(observation.events, 0, "seed {}", seed.id);
            } else {
                assert_eq!(observation.events, 1, "seed {} mode {control}", seed.id);
                assert!(observation.emitted_bytes > 0, "seed {}", seed.id);
                if control == 4 {
                    assert!(matches!(observation.result, Ok(SourceControl::Stop)));
                } else {
                    // A one-fragment stream can complete at the callback that
                    // cancels it; multi-member traversal observes cancellation.
                    assert!(matches!(
                        observation.result,
                        Err(SourceError::Cancelled) | Ok(SourceControl::Continue)
                    ));
                }
            }
        }
    }
}

#[test]
fn member_limit_and_multifragment_event_bound_are_exercised() {
    for size in [MAX_MEMBER_BYTES, MAX_MEMBER_BYTES + 1] {
        let payload = vec![b' '; size];
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&payload, 6);
        let input = encode(14, 0, &compressed);
        assert!(input.len() <= MAX_INPUT_BYTES);
        let mut limit_issues = 0;
        let observation = exercise(&input, |event| {
            if let SourceEvent::Issue(issue) = event {
                assert_eq!(issue.kind(), SourceIssueKind::Limit);
                limit_issues += 1;
            }
        })
        .expect("valid frame");
        assert!(matches!(observation.result, Ok(SourceControl::Continue)));
        if size == MAX_MEMBER_BYTES {
            assert_eq!(observation.emitted_bytes, size);
            assert!(
                observation.events > 64,
                "old fixed event bound would miss this"
            );
            assert_eq!(limit_issues, 0);
        } else {
            assert_eq!(observation.emitted_bytes, 0);
            assert_eq!(limit_issues, 1);
        }
        assert!(observation.emitted_bytes <= MAX_TOTAL_BYTES);
    }
}

#[test]
fn legacy_seed_migration_preserves_original_selector_control_and_payload() {
    for name in ["tar-header.txt", "zip-header.txt"] {
        let legacy = fs::read(
            root()
                .join("crates/rustleaks-sources/fuzz/seeds/archive")
                .join(name),
        )
        .expect("committed legacy seed");
        let migrated = archive_frame::migrate_legacy(&legacy).expect("small seed");
        let frame = Frame::decode(&migrated).expect("migrated frame");
        assert_eq!(frame.format, usize::from(legacy[0]) % FORMAT_NAMES.len());
        assert_eq!(frame.control, legacy[0]);
        assert_eq!(frame.payload, &legacy[1..]);
    }
    assert!(archive_frame::migrate_legacy(&vec![0; MAX_INPUT_BYTES]).is_none());
}
