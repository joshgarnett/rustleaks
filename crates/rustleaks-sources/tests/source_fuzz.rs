//! Ordinary deterministic proofs for the framed reader and Git fuzz targets.
#![cfg(feature = "fuzzing")]
#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[allow(dead_code)]
#[path = "../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;
#[allow(dead_code)]
#[path = "../fuzz/support/git_harness.rs"]
mod git_harness;
#[allow(dead_code)]
#[path = "../fuzz/support/reader_harness.rs"]
mod reader_harness;
#[allow(dead_code)]
#[path = "../fuzz/support/source_frame.rs"]
mod source_frame;

use campaign_profile::{Profile, deep_seed};
use rustleaks_sources::{SourceControl, SourceError, SourceEvent, SourceIssueKind, SourceStage};
use source_frame::{Encoding, GIT_HEADER_BYTES, GitFrame, READER_HEADER_BYTES, ReaderFrame};

const LEGACY_READER: &[u8] = include_bytes!("../fuzz/seeds/reader_schedule/data-error.txt");
const LEGACY_GIT: &[u8] = include_bytes!("../fuzz/seeds/git_patch/basic.patch");

fn seed(target: &str, name: &str) -> Vec<u8> {
    source_frame::seeds(target)
        .into_iter()
        .find_map(|(candidate, data)| (candidate == name).then_some(data))
        .expect("known synthetic seed")
}

fn reader_input(controls: [u8; 6], schedule: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut input = source_frame::READER_MAGIC.to_vec();
    input.extend_from_slice(&controls);
    input.extend_from_slice(&u16::try_from(schedule.len()).unwrap().to_le_bytes());
    input.extend_from_slice(schedule);
    input.extend_from_slice(payload);
    input
}

fn capture_reader(
    input: &[u8],
    profile: Profile,
) -> (
    reader_harness::Observation,
    Vec<Vec<u8>>,
    Vec<(SourceStage, SourceIssueKind)>,
) {
    let mut fragments = Vec::new();
    let mut issues = Vec::new();
    let observation = reader_harness::exercise_with(input, profile, |event| match event {
        SourceEvent::Fragment { fragment, issue } => {
            fragments.push(fragment.content().as_bytes().to_vec());
            if let Some(issue) = issue {
                issues.push((issue.stage(), issue.kind()));
            }
        }
        SourceEvent::Issue(issue) => issues.push((issue.stage(), issue.kind())),
        _ => panic!("unexpected source event"),
    });
    (observation, fragments, issues)
}

#[test]
fn every_reader_control_changes_only_its_own_dimension() {
    let input = seed("reader_schedule", "reader-v1-consume");
    for profile in [Profile::Smoke, Profile::Deep] {
        let original = ReaderFrame::decode(&input, profile);
        assert_eq!(original.encoding, Encoding::V1);
        for offset in 4..10 {
            let mut changed = input.clone();
            changed[offset] = 255;
            let frame = ReaderFrame::decode(&changed, profile);
            let mut expected = original.controls;
            match offset {
                4 => expected.chunk_bytes = 64,
                5 => expected.read_ahead_bytes = 63,
                6 => expected.callback_stop = true,
                7 => expected.callback_error = true,
                8 => expected.cancel_before = true,
                9 => expected.cancel_in_callback = true,
                _ => unreachable!(),
            }
            assert_eq!(frame.controls, expected);
            assert_eq!(frame.schedule, original.schedule);
            assert_eq!(frame.payload, original.payload);
        }
    }
}

#[test]
fn framed_reader_seeds_reach_consumption_and_each_callback_control() {
    for profile in [Profile::Smoke, Profile::Deep] {
        let input = seed("reader_schedule", "reader-v1-consume");
        let (ordinary, fragments, issues) = capture_reader(&input, profile);
        assert_eq!(ordinary.result, Ok(SourceControl::Continue));
        assert_eq!(
            (
                ordinary.schedule_operations,
                ordinary.payload_reads,
                ordinary.events
            ),
            (3, 12, 3)
        );
        assert_eq!(ordinary.emitted_bytes, 12);
        assert_eq!(
            fragments,
            [b"abcd".to_vec(), b"EFGH".to_vec(), b"ijkl".to_vec()]
        );
        assert!(issues.is_empty());
        assert_eq!(ordinary, reader_harness::exercise(&input, profile));

        for (name, expected) in [
            ("reader-v1-stop", Ok(SourceControl::Stop)),
            (
                "reader-v1-callback-error",
                Err(SourceError::Callback(
                    rustleaks_sources::CallbackError::new("scheduled callback failure"),
                )),
            ),
            ("reader-v1-callback-cancel", Err(SourceError::Cancelled)),
        ] {
            let input = seed("reader_schedule", name);
            let (observation, fragments, issues) = capture_reader(&input, profile);
            assert_eq!(observation.result, expected);
            assert_eq!(
                (
                    observation.schedule_operations,
                    observation.payload_reads,
                    observation.emitted_bytes,
                    observation.events
                ),
                (1, 4, 4, 1)
            );
            assert_eq!(fragments, [b"abcd".to_vec()]);
            assert!(issues.is_empty());
        }
        let input = seed("reader_schedule", "reader-v1-pre-cancel");
        let (observation, fragments, issues) = capture_reader(&input, profile);
        assert_eq!(observation.result, Err(SourceError::Cancelled));
        assert_eq!(
            (
                observation.schedule_operations,
                observation.payload_reads,
                observation.emitted_bytes,
                observation.events
            ),
            (0, 0, 0, 0)
        );
        assert!(fragments.is_empty());
        assert!(issues.is_empty());
    }
}

#[test]
fn independent_chunk_and_read_ahead_reach_distinct_fragment_boundaries() {
    // Equivalence is asserted only for this finite synthetic ASCII stream with
    // EOF, no read errors, no MIME skip, and no callback control. Arbitrary
    // schedule/chunk changes can legitimately alter source semantics.
    let payload = b"abcdefghijklmnopqrstuvwxYZ1234";
    let input = reader_input([3, 0, 0, 0, 0, 0], &[15, 0x2f], payload);
    for profile in [Profile::Smoke, Profile::Deep] {
        let (baseline, fragments, issues) = capture_reader(&input, profile);
        assert_eq!(baseline.result, Ok(SourceControl::Continue));
        assert_eq!(fragments.concat(), payload);
        assert_eq!(
            fragments.iter().map(Vec::len).collect::<Vec<_>>(),
            [4, 4, 4, 3, 4, 4, 4, 3]
        );
        assert!(issues.is_empty());
        for (offset, value) in [(4, 7), (5, 4)] {
            let mut changed = input.clone();
            changed[offset] = value;
            let (observation, fragments, issues) = capture_reader(&changed, profile);
            assert_eq!(observation.result, Ok(SourceControl::Continue));
            assert_eq!(observation.schedule_operations, 2);
            assert_eq!(observation.payload_reads, payload.len());
            assert_eq!(observation.emitted_bytes, payload.len());
            assert_eq!(fragments.concat(), payload);
            assert!(fragments.iter().any(|bytes| bytes.len() == 8));
            assert!(observation.events < baseline.events);
            assert!(issues.is_empty());
        }
    }
}

#[test]
fn reader_schedule_statuses_reach_data_and_structured_issues() {
    for profile in [Profile::Smoke, Profile::Deep] {
        for (name, operations, consumed, emitted, issue) in [
            (
                "reader-v1-data-error",
                2,
                8,
                8,
                Some((SourceStage::Read, SourceIssueKind::Read)),
            ),
            (
                "reader-v1-overreport",
                2,
                4,
                4,
                Some((SourceStage::Limit, SourceIssueKind::Limit)),
            ),
            ("reader-v1-zero-progress", 2, 4, 4, None),
        ] {
            let input = seed("reader_schedule", name);
            let (observation, fragments, issues) = capture_reader(&input, profile);
            assert_eq!(observation.result, Ok(SourceControl::Continue));
            assert_eq!(
                (
                    observation.schedule_operations,
                    observation.payload_reads,
                    observation.emitted_bytes
                ),
                (operations, consumed, emitted)
            );
            assert_eq!(fragments.concat(), b"abcdEFGH"[..emitted]);
            assert_eq!(issues, issue.into_iter().collect::<Vec<_>>());
        }
        let input = reader_input([3, 4, 0, 0, 0, 0], &[4, 0], b"abcd");
        let (observation, fragments, issues) = capture_reader(&input, profile);
        assert_eq!(observation.result, Ok(SourceControl::Continue));
        assert_eq!(
            (
                observation.schedule_operations,
                observation.payload_reads,
                observation.emitted_bytes
            ),
            (2, 4, 0)
        );
        assert_eq!(fragments, [Vec::<u8>::new()]);
        assert_eq!(
            issues,
            [(SourceStage::BoundaryRead, SourceIssueKind::BoundaryRead)]
        );

        let input = reader_input([3, 0, 0, 0, 0, 0], &[1, 1, 0x21], b"abc");
        let (observation, fragments, issues) = capture_reader(&input, profile);
        assert_eq!(observation.result, Ok(SourceControl::Continue));
        assert_eq!(
            (
                observation.schedule_operations,
                observation.payload_reads,
                observation.emitted_bytes
            ),
            (3, 3, 3)
        );
        assert_eq!(fragments, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        assert!(issues.is_empty());
    }
}

#[test]
fn every_git_control_changes_only_its_own_dimension() {
    let input = seed("git_patch", "git-v1-parse");
    for profile in [Profile::Smoke, Profile::Deep] {
        let original = GitFrame::decode(&input, profile);
        assert_eq!(original.encoding, Encoding::V1);
        for offset in 4..7 {
            let mut changed = input.clone();
            changed[offset] = 255;
            let frame = GitFrame::decode(&changed, profile);
            let mut expected = original.controls;
            match offset {
                4 => expected.files = 32,
                5 => expected.hunks = 256,
                6 => expected.cancel_before = true,
                _ => unreachable!(),
            }
            assert_eq!(frame.controls, expected);
            assert_eq!(frame.patch, original.patch);
        }
    }
}

#[test]
fn framed_git_seeds_reach_parsing_and_independent_rejection_controls() {
    for profile in [Profile::Smoke, Profile::Deep] {
        let input = seed("git_patch", "git-v1-parse");
        let ordinary = git_harness::exercise(&input, profile);
        assert_eq!(ordinary.parsed, Some((2, 3)));
        assert_eq!(ordinary.patch_bytes, input.len() - GIT_HEADER_BYTES);
        for name in [
            "git-v1-file-limit",
            "git-v1-hunk-limit",
            "git-v1-pre-cancel",
        ] {
            let changed = seed("git_patch", name);
            assert_eq!(
                GitFrame::decode(&changed, profile).patch,
                GitFrame::decode(&input, profile).patch
            );
            let rejected = git_harness::exercise(&changed, profile);
            assert_eq!(rejected.parsed, None);
            assert_eq!(rejected.patch_bytes, ordinary.patch_bytes);
        }
    }
}

#[test]
fn git_hunk_limits_above_128_reach_parsing_without_precancellation() {
    let mut input = source_frame::GIT_MAGIC.to_vec();
    input.extend_from_slice(&[0, 128, 0]);
    input.extend_from_slice(b"diff --git a/many.txt b/many.txt\n--- a/many.txt\n+++ b/many.txt\n");
    for line in 1..=129 {
        input.extend_from_slice(format!("@@ -{},0 +{line} @@\n+synthetic\n", line - 1).as_bytes());
    }
    assert!(input.len() < Profile::Smoke.input_limit("git_patch").unwrap());
    for profile in [Profile::Smoke, Profile::Deep] {
        assert_eq!(
            git_harness::exercise(&input, profile).parsed,
            Some((1, 129))
        );
        // The former single byte requires 0x80 for the same 129-hunk
        // ceiling, which also pre-cancels every nonempty patch.
        let mut legacy = vec![128];
        legacy.extend_from_slice(&input[GIT_HEADER_BYTES..]);
        let frame = GitFrame::decode(&legacy, profile);
        assert_eq!(frame.controls.files, 1);
        assert_eq!(frame.controls.hunks, 129);
        assert!(frame.controls.cancel_before);
        assert_eq!(git_harness::exercise(&legacy, profile).parsed, None);
        let mut rejected = input.clone();
        rejected[5] = 127;
        assert_eq!(git_harness::exercise(&rejected, profile).parsed, None);
        let mut cancelled = input.clone();
        cancelled[6] = 1;
        assert_eq!(git_harness::exercise(&cancelled, profile).parsed, None);
    }
}

#[test]
fn framing_caps_include_headers_and_bound_oversized_schedules() {
    for profile in [Profile::Smoke, Profile::Deep] {
        let reader_cap = profile.input_limit("reader_schedule").unwrap();
        let git_cap = profile.input_limit("git_patch").unwrap();
        assert_eq!(
            (reader_cap, git_cap),
            if profile == Profile::Smoke {
                (4096, 16384)
            } else {
                (65536, 65536)
            }
        );
        let mut reader = reader_input([255; 6], &[15], b"payload");
        reader[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        reader.resize(reader_cap + 100, 15);
        let frame = ReaderFrame::decode(&reader, profile);
        assert_eq!(frame.input_bytes, reader_cap);
        assert_eq!(frame.schedule.len(), reader_cap - READER_HEADER_BYTES);
        assert!(frame.payload.is_empty());
        assert_eq!(
            (frame.controls.chunk_bytes, frame.controls.read_ahead_bytes),
            (64, 63)
        );

        let mut git = source_frame::GIT_MAGIC.to_vec();
        git.extend_from_slice(&[255; 3]);
        git.resize(git_cap + 100, b'.');
        let frame = GitFrame::decode(&git, profile);
        assert_eq!(frame.input_bytes, git_cap);
        assert_eq!(frame.patch.len(), git_cap - GIT_HEADER_BYTES);
        assert_eq!((frame.controls.files, frame.controls.hunks), (32, 256));
    }
    assert_eq!(
        (
            source_frame::MAX_GIT_LINES,
            source_frame::MAX_GIT_METADATA_BYTES,
            source_frame::MAX_GIT_PATH_BYTES
        ),
        (2048, 4096, 4096)
    );
}

#[test]
fn only_complete_known_headers_select_v1() {
    for profile in [Profile::Smoke, Profile::Deep] {
        for (target, name, header) in [
            ("reader_schedule", "reader-v1-consume", READER_HEADER_BYTES),
            ("git_patch", "git-v1-parse", GIT_HEADER_BYTES),
        ] {
            let input = seed(target, name);
            for length in 0..header {
                let encoding = if target == "reader_schedule" {
                    ReaderFrame::decode(&input[..length], profile).encoding
                } else {
                    GitFrame::decode(&input[..length], profile).encoding
                };
                assert_eq!(encoding, Encoding::Legacy);
            }
            for offset in 0..4 {
                let mut changed = input.clone();
                changed[offset] ^= 0x80;
                let encoding = if target == "reader_schedule" {
                    ReaderFrame::decode(&changed, profile).encoding
                } else {
                    GitFrame::decode(&changed, profile).encoding
                };
                assert_eq!(encoding, Encoding::Legacy);
            }
        }
    }
}

#[test]
fn legacy_control_bytes_keep_their_original_mapping_and_payloads() {
    for profile in [Profile::Smoke, Profile::Deep] {
        for control in 0_u8..=255 {
            let input = [control, 2, 0, 4, 0x24, b'a', b'b', b'c', b'd'];
            let reader = ReaderFrame::decode(&input, profile);
            assert_eq!(reader.encoding, Encoding::Legacy);
            assert_eq!(reader.controls.chunk_bytes, usize::from(control & 0x3f) + 1);
            assert_eq!(
                reader.controls.read_ahead_bytes,
                usize::from(control >> 2) & 0x3f
            );
            assert_eq!(reader.controls.callback_stop, control & 8 != 0);
            assert_eq!(reader.controls.callback_error, control & 16 != 0);
            assert_eq!(reader.controls.cancel_before, control & 64 != 0);
            assert_eq!(reader.controls.cancel_in_callback, control & 32 != 0);
            if profile == Profile::Smoke {
                assert_eq!(reader.schedule, &input[1..3]);
                assert_eq!(reader.payload, &input[3..]);
            } else {
                assert_eq!(reader.schedule, &input[3..5]);
                assert_eq!(reader.payload, &input[5..]);
            }
            let git = GitFrame::decode(&input, profile);
            assert_eq!(git.encoding, Encoding::Legacy);
            assert_eq!(git.controls.files, usize::from(control & 31) + 1);
            assert_eq!(git.controls.hunks, usize::from(control) + 1);
            assert_eq!(git.controls.cancel_before, control & 128 != 0);
            assert_eq!(git.patch, &input[1..]);
        }
    }
}

#[test]
fn existing_committed_and_generated_source_seeds_remain_legacy() {
    for profile in [Profile::Smoke, Profile::Deep] {
        assert_eq!(
            ReaderFrame::decode(LEGACY_READER, profile).encoding,
            Encoding::Legacy
        );
        assert_eq!(
            GitFrame::decode(LEGACY_GIT, profile).encoding,
            Encoding::Legacy
        );
        let reader = reader_harness::exercise(LEGACY_READER, profile);
        assert_eq!(reader.result, Err(SourceError::Cancelled));
        assert_eq!(
            (
                reader.schedule_operations,
                reader.payload_reads,
                reader.events
            ),
            (0, 0, 0)
        );
        assert_eq!(
            git_harness::exercise(LEGACY_GIT, profile).parsed,
            Some((1, 1))
        );
    }
    let reader = deep_seed("reader_schedule").unwrap();
    let git = deep_seed("git_patch").unwrap();
    assert_eq!(
        ReaderFrame::decode(&reader, Profile::Deep).encoding,
        Encoding::Legacy
    );
    assert_eq!(
        GitFrame::decode(&git, Profile::Deep).encoding,
        Encoding::Legacy
    );
    let observation = reader_harness::exercise(&reader, Profile::Deep);
    assert_eq!(observation.result, Ok(SourceControl::Continue));
    assert_eq!(observation.schedule_operations, 8192);
    assert_eq!(observation.payload_reads, 8192 * 15);
    assert_eq!(observation.emitted_bytes, observation.payload_reads);
    assert_eq!(
        git_harness::exercise(&git, Profile::Deep).parsed,
        Some((1, 1))
    );
}
