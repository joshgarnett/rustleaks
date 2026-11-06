//! In-memory larger archive/reader cases selected only by the deep operator.
#![cfg(feature = "archives")]
#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[allow(dead_code)]
#[path = "../fuzz/support/archive_frame.rs"]
mod archive_frame;
#[allow(dead_code)]
#[path = "../fuzz/support/archive_harness.rs"]
mod archive_harness;
#[allow(dead_code)]
#[path = "../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;
#[allow(dead_code)]
#[path = "../fuzz/support/reader_harness.rs"]
mod reader_harness;
#[allow(dead_code)]
#[path = "../fuzz/support/source_frame.rs"]
mod source_frame;

use std::io::Cursor;

use campaign_profile::{Profile, deep_seed, synthetic_tar};
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CancellationToken, FileOptions, Source,
    SourceControl, SourceEvent, SourceIssueKind,
};
use serde_json::json;

#[test]
fn profile_caps_and_long_schedule_are_explicit() {
    let smoke = Profile::Smoke.archive();
    let deep = Profile::Deep.archive();
    assert_eq!(
        (
            smoke.depth,
            smoke.entries,
            smoke.input_bytes,
            smoke.member_bytes,
            smoke.total_bytes
        ),
        (2, 8, 8192, 131_072, 131_072)
    );
    assert_eq!(
        (
            deep.depth,
            deep.entries,
            deep.input_bytes,
            deep.member_bytes,
            deep.total_bytes
        ),
        (4, 256, 65536, 1_048_576, 4_194_304)
    );
    let seed = deep_seed("reader_schedule").unwrap();
    let (_, schedule, payload) = campaign_profile::reader_parts(&seed, Profile::Deep);
    assert_eq!((schedule.len(), payload.len()), (8192, 8192));
    let (_, smoke_schedule, _) = campaign_profile::reader_parts(&seed, Profile::Smoke);
    assert!(smoke_schedule.len() <= 255);
    let archive = deep_seed("archive").unwrap();
    assert!(archive.len() > smoke.input_bytes);
    assert!(archive.len() < deep.input_bytes);
    assert_eq!(
        archive_frame::Frame::decode_bounded(&archive, deep.input_bytes)
            .unwrap()
            .payload
            .len()
            + archive_frame::HEADER_BYTES,
        archive.len()
    );
}

#[test]
#[ignore = "optional larger-input driver, invoked by the deep-security operator"]
fn security_stress_driver() {
    large_archive_frame_reaches_tail();
    archive_expansion_boundary();
    archive_depth_boundary();
    archive_entry_boundary();
    archive_aggregate_boundary();
    longer_reader_schedule_is_consumed();
}

fn large_archive_frame_reaches_tail() {
    let input = deep_seed("archive").unwrap();
    let mut output = Vec::new();
    let mut issues = 0;
    let deep = archive_harness::exercise_with_profile(&input, Profile::Deep, |event| match event {
        SourceEvent::Fragment { fragment, issue } => {
            output.extend_from_slice(fragment.content().as_bytes());
            issues += usize::from(issue.is_some());
        }
        SourceEvent::Issue(_) => issues += 1,
        _ => panic!("unexpected archive event"),
    })
    .unwrap();
    assert!(matches!(deep.result, Ok(SourceControl::Continue)));
    assert_eq!(deep.input_bytes, input.len());
    assert_eq!(deep.emitted_bytes, 32 * 1024);
    assert_eq!(output.len(), 32 * 1024);
    assert!(output.iter().all(|byte| *byte == b'.'));
    assert_eq!(issues, 0);
    let smoke = archive_harness::exercise(&input, |_| {}).unwrap();
    assert_eq!(smoke.input_bytes, Profile::Smoke.archive().input_bytes);
    assert!(smoke.emitted_bytes < deep.emitted_bytes);
    println!(
        "{}",
        json!({"kind":"security-stress","case":"archive-full-frame","status":"pass","input_bytes":input.len(),"admitted_frame_bytes":deep.input_bytes,"smoke_input_bytes":smoke.input_bytes,"emitted_bytes":deep.emitted_bytes,"termination":"complete"})
    );
}

fn archive_expansion_boundary() {
    let cap = Profile::Deep.archive().member_bytes;
    for extra in [0, 1] {
        let content = vec![b'.'; cap + extra];
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&content, 6);
        let input = archive_frame::encode(14, 0, &compressed);
        assert!(input.len() <= Profile::Deep.archive().input_bytes);
        let mut issues = 0;
        let outcome = archive_harness::exercise_with_profile(&input, Profile::Deep, |event| {
            if let SourceEvent::Issue(issue) = event {
                assert_eq!(issue.kind(), SourceIssueKind::Limit);
                issues += 1;
            }
        })
        .unwrap();
        assert!(matches!(outcome.result, Ok(SourceControl::Continue)));
        assert_eq!(outcome.emitted_bytes, if extra == 0 { cap } else { 0 });
        assert_eq!(issues, extra);
        println!(
            "{}",
            json!({"kind":"security-stress","case":if extra == 0 {"archive-member-exact"} else {"archive-member-over"},"status":"pass","input_bytes":input.len(),"expanded_bytes":content.len(),"emitted_bytes":outcome.emitted_bytes,"smoke_member_bytes":Profile::Smoke.archive().member_bytes,"limit":cap,"limit_issues":issues})
        );
    }
}

fn scan_tar(
    input: Vec<u8>,
    depth: usize,
    entries: usize,
    member: usize,
    total: usize,
) -> (usize, usize, usize) {
    let spool = input.len().max(1);
    let options =
        ArchiveOptions::new(ArchiveLimits::new(depth, entries, member, total, spool).unwrap())
            .emit_limit_issues(true);
    let mut source = ArchiveSource::with_options(
        Cursor::new(input),
        "structured.tar",
        FileOptions::new(64 * 1024)
            .unwrap()
            .max_boundary_read_ahead(0),
        options,
    );
    let mut bytes = 0;
    let mut fragments = 0;
    let mut issues = 0;
    let result = source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment { fragment, issue } => {
                bytes += fragment.content().len();
                fragments += 1;
                if let Some(issue) = issue {
                    assert_eq!(issue.kind(), SourceIssueKind::Limit);
                    issues += 1;
                }
            }
            SourceEvent::Issue(issue) => {
                assert_eq!(issue.kind(), SourceIssueKind::Limit);
                issues += 1;
            }
            _ => panic!("unexpected archive event"),
        }
        Ok(SourceControl::Continue)
    });
    assert!(matches!(result, Ok(SourceControl::Continue)));
    (bytes, fragments, issues)
}

fn archive_depth_boundary() {
    let payload = vec![b'.'; 16 * 1024];
    let mut input = synthetic_tar(&[("leaf.txt", &payload)]);
    for _ in 0..3 {
        input = synthetic_tar(&[("nested.tar", &input)]);
    }
    let cap = Profile::Deep.archive();
    let exact = scan_tar(
        input.clone(),
        cap.depth,
        cap.entries,
        cap.member_bytes,
        cap.total_bytes,
    );
    assert_eq!(exact, (payload.len(), 1, 0));
    let below = scan_tar(
        input.clone(),
        cap.depth - 1,
        cap.entries,
        cap.member_bytes,
        cap.total_bytes,
    );
    assert_eq!(below, (0, 0, 1));
    println!(
        "{}",
        json!({"kind":"security-stress","case":"archive-depth","status":"pass","input_bytes":input.len(),"depth":cap.depth,"smoke_depth":Profile::Smoke.archive().depth,"emitted_bytes":exact.0,"boundary":"exact-complete-one-less-limit-issue"})
    );
}

fn archive_entry_boundary() {
    let cap = Profile::Deep.archive();
    for extra in [0, 1] {
        let names = (0..cap.entries + extra)
            .map(|index| format!("entry-{index}.txt"))
            .collect::<Vec<_>>();
        let entries = names
            .iter()
            .map(|name| (name.as_str(), b".".as_slice()))
            .collect::<Vec<_>>();
        let input = synthetic_tar(&entries);
        let input_bytes = input.len();
        let outcome = scan_tar(
            input,
            cap.depth,
            cap.entries,
            cap.member_bytes,
            cap.total_bytes,
        );
        assert_eq!(outcome, (cap.entries, cap.entries, extra));
        println!(
            "{}",
            json!({"kind":"security-stress","case":if extra == 0 {"archive-entries-exact"} else {"archive-entries-over"},"status":"pass","input_bytes":input_bytes,"entries":entries.len(),"emitted_entries":outcome.1,"smoke_entries":Profile::Smoke.archive().entries,"limit":cap.entries,"limit_issues":outcome.2})
        );
    }
}

fn archive_aggregate_boundary() {
    let cap = Profile::Deep.archive();
    let payload = vec![b'.'; cap.member_bytes];
    for count in [4, 5] {
        let names = (0..count)
            .map(|index| format!("member-{index}.txt"))
            .collect::<Vec<_>>();
        let entries = names
            .iter()
            .map(|name| (name.as_str(), payload.as_slice()))
            .collect::<Vec<_>>();
        let input = synthetic_tar(&entries);
        let input_bytes = input.len();
        assert!(input_bytes < 6 * 1024 * 1024);
        let outcome = scan_tar(
            input,
            cap.depth,
            cap.entries,
            cap.member_bytes,
            cap.total_bytes,
        );
        assert_eq!(outcome.0, cap.total_bytes);
        assert_eq!(outcome.2, count - 4);
        println!(
            "{}",
            json!({"kind":"security-stress","case":if count == 4 {"archive-total-exact"} else {"archive-total-over"},"status":"pass","input_bytes":input_bytes,"expanded_bytes":count * cap.member_bytes,"emitted_bytes":outcome.0,"smoke_total_bytes":Profile::Smoke.archive().total_bytes,"limit":cap.total_bytes,"limit_issues":outcome.2})
        );
    }
}

fn longer_reader_schedule_is_consumed() {
    let input = deep_seed("reader_schedule").unwrap();
    let outcome = reader_harness::exercise(&input, Profile::Deep);
    assert!(matches!(outcome.result, Ok(SourceControl::Continue)));
    assert_eq!(outcome.schedule_operations, 8192);
    // Read buffering admits 15 bytes per instruction even with one-byte
    // output fragments; count consumed bytes independently from fragments.
    assert_eq!(outcome.payload_reads, 8192 * 15);
    assert_eq!(outcome.emitted_bytes, outcome.payload_reads);
    println!(
        "{}",
        json!({"kind":"security-stress","case":"reader-long-schedule","status":"pass","input_bytes":input.len(),"smoke_input_bytes":Profile::Smoke.input_limit("reader_schedule").unwrap(),"schedule_operations":outcome.schedule_operations,"payload_reads":outcome.payload_reads,"emitted_bytes":outcome.emitted_bytes,"termination":"complete"})
    );
}
