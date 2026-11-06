//! Finite semantic checks for complete compressed 7z members and source control.
#![cfg(feature = "archives")]
#![forbid(unsafe_code)]

#[path = "../fuzz/support/sevenz_seeds.rs"]
mod sevenz_seeds;

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CallbackError, Cancellation, CancellationToken,
    FileOptions, Source, SourceControl, SourceError, SourceEvent, SourceIssueKind, SourceStage,
};
use sevenz_seeds::{Member, Method, archive};

const METHODS: [Method; 3] = [Method::Copy, Method::Deflate, Method::Lz4];

#[derive(Default)]
struct Events {
    members: Vec<(Vec<u8>, Vec<u8>)>,
    issues: Vec<(SourceStage, SourceIssueKind)>,
}

impl Events {
    fn record(&mut self, event: SourceEvent) {
        match event {
            SourceEvent::Fragment { fragment, issue } => {
                if let Some(issue) = issue {
                    self.issues.push((issue.stage(), issue.kind()));
                }
                let path = fragment.file_path().as_bytes().to_vec();
                if let Some((last, bytes)) = self.members.last_mut()
                    && *last == path
                {
                    bytes.extend_from_slice(fragment.content().as_bytes());
                } else {
                    self.members
                        .push((path, fragment.content().as_bytes().to_vec()));
                }
            }
            SourceEvent::Issue(issue) => self.issues.push((issue.stage(), issue.kind())),
            _ => panic!("unexpected source event"),
        }
    }
}

fn limits(entries: usize, total: usize) -> ArchiveLimits {
    ArchiveLimits::new(4, entries, 1 << 20, total, 1 << 20).unwrap()
}

fn source(bytes: Vec<u8>, limits: ArchiveLimits) -> ArchiveSource {
    ArchiveSource::with_options(
        Cursor::new(bytes),
        "fixture.7z",
        FileOptions::default(),
        ArchiveOptions::new(limits),
    )
}

fn collect(bytes: Vec<u8>, limits: ArchiveLimits) -> Events {
    let mut events = Events::default();
    let result = source(bytes, limits).visit(&CancellationToken::new(), &mut |event| {
        events.record(event);
        Ok(SourceControl::Continue)
    });
    assert_eq!(result, Ok(SourceControl::Continue));
    events
}

fn payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| b'a' + u8::try_from(index % 23).unwrap())
        .collect()
}

#[test]
fn compressed_methods_preserve_complete_payloads_and_member_order() {
    for method in METHODS {
        for size in [1, 31, 127, 128, 4097, 32_769, 131_073] {
            let first = payload(size);
            let second = b"independent tail\n";
            let members = [
                Member::new("first.txt", &first, method),
                Member::new("second.txt", second, method),
            ];
            if !matches!(method, Method::Copy) && size > 4096 {
                assert!(members[0].packed.len() < first.len(), "actual compression");
            }
            let events = collect(archive(&members), limits(2, first.len() + second.len()));
            assert!(
                events.issues.is_empty(),
                "{method:?}/{size}: {:?}",
                events.issues
            );
            assert_eq!(
                events.members,
                [
                    (b"fixture.7z!first.txt".to_vec(), first),
                    (b"fixture.7z!second.txt".to_vec(), second.to_vec()),
                ],
                "{method:?}/{size}"
            );
        }
    }
}

struct CancelAt {
    remaining: AtomicUsize,
    observed: AtomicBool,
}

impl Cancellation for CancelAt {
    fn is_cancelled(&self) -> bool {
        let cancelled = self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_err();
        if cancelled {
            self.observed.store(true, Ordering::SeqCst);
        }
        cancelled
    }
}

#[test]
fn observed_cancellation_is_terminal_including_during_member_reads() {
    for method in METHODS {
        let content = payload(131_073);
        let bytes = archive(&[Member::new("value.txt", &content, method)]);
        let mut cancelled_cases = 0;
        let mut completed_cases = 0;
        for after in (0..48).chain(std::iter::once(usize::MAX)) {
            let cancellation = CancelAt {
                remaining: AtomicUsize::new(after),
                observed: AtomicBool::new(false),
            };
            let mut events = Events::default();
            let result =
                source(bytes.clone(), limits(1, 1 << 20)).visit(&cancellation, &mut |event| {
                    events.record(event);
                    Ok(SourceControl::Continue)
                });
            assert!(
                events.issues.is_empty(),
                "cancellation became an archive issue: {method:?}/{after}"
            );
            if cancellation.observed.load(Ordering::SeqCst) {
                cancelled_cases += 1;
                assert_eq!(result, Err(SourceError::Cancelled), "{method:?}/{after}");
            } else {
                completed_cases += 1;
                assert_eq!(result, Ok(SourceControl::Continue));
                assert_eq!(
                    events.members,
                    [(b"fixture.7z!value.txt".to_vec(), content.clone())]
                );
            }
        }
        // Exercise both outcomes without making any particular poll count public.
        assert!(cancelled_cases > 0 && completed_cases > 0);
    }
}

#[test]
fn crc_corruption_and_container_truncation_do_not_publish_unverified_members() {
    for method in METHODS {
        let content = payload(513);
        let mut member = Member::new("broken.txt", &content, method);
        member.crc ^= 1;
        let events = collect(archive(&[member]), limits(1, 1 << 20));
        assert!(events.members.is_empty(), "{method:?}");
        assert_eq!(
            events.issues,
            [(SourceStage::Decode, SourceIssueKind::Decode)]
        );
        let mut broken = Member::new("broken.txt", &content, method);
        match method {
            Method::Copy | Method::Lz4 => broken.packed[0] ^= 1,
            Method::Deflate => broken.packed[0] |= 0b110, // Reserved block type.
        }
        let events = collect(archive(&[broken]), limits(1, 1 << 20));
        assert!(events.members.is_empty(), "{method:?}");
        assert_eq!(
            events.issues,
            [(SourceStage::Decode, SourceIssueKind::Decode)]
        );
        let bytes = archive(&[Member::new("value.txt", &content, method)]);
        for length in [0, 6, 31, 32, bytes.len() - 1] {
            let events = collect(bytes[..length].to_vec(), limits(1, 1 << 20));
            assert!(events.members.is_empty(), "{method:?}/{length}");
            assert_eq!(
                events.issues,
                [(SourceStage::Archive, SourceIssueKind::CorruptArchive)]
            );
        }
    }
}

#[test]
fn entry_and_cumulative_limits_are_inclusive_across_compressed_members() {
    for method in METHODS {
        let first = payload(6000);
        let second = payload(7000);
        let bytes = archive(&[
            Member::new("first.txt", &first, method),
            Member::new("second.txt", &second, method),
        ]);
        for entries in [1, 2, 3] {
            for total in [12_999, 13_000, 13_001] {
                let events = collect(bytes.clone(), limits(entries, total));
                if entries < 2 || total < 13_000 {
                    assert!(events.members.is_empty(), "{method:?}/{entries}/{total}");
                    assert_eq!(
                        events.issues,
                        [(SourceStage::Limit, SourceIssueKind::Limit)]
                    );
                } else {
                    assert!(events.issues.is_empty());
                    assert_eq!(
                        events.members,
                        [
                            (b"fixture.7z!first.txt".to_vec(), first.clone()),
                            (b"fixture.7z!second.txt".to_vec(), second.clone()),
                        ]
                    );
                }
            }
        }
    }
}

#[test]
fn compressed_member_callbacks_preserve_stop_error_and_cancellation() {
    for method in METHODS {
        let bytes = archive(&[
            Member::new("first.txt", b"first", method),
            Member::new("second.txt", b"second", method),
        ]);
        for mode in 0..3 {
            let token = CancellationToken::new();
            let mut calls = 0;
            let callback_error = CallbackError::new("synthetic consumer failure");
            let result = source(bytes.clone(), limits(2, 1 << 20)).visit(&token, &mut |event| {
                calls += 1;
                assert!(matches!(event, SourceEvent::Fragment { issue: None, .. }));
                match mode {
                    0 => Ok(SourceControl::Stop),
                    1 => Err(callback_error.clone()),
                    _ => {
                        token.cancel();
                        Ok(SourceControl::Continue)
                    }
                }
            });
            assert_eq!(calls, 1, "{method:?}/{mode}");
            assert_eq!(
                result,
                match mode {
                    0 => Ok(SourceControl::Stop),
                    1 => Err(SourceError::Callback(callback_error)),
                    _ => Err(SourceError::Cancelled),
                }
            );
        }
    }
}

#[test]
fn nesting_charges_inner_archive_bytes_and_decoded_members_once_each() {
    for method in METHODS {
        let content = payload(513);
        let inner = archive(&[Member::new("value.txt", &content, method)]);
        let tail = b"tail\n";
        let bytes = archive(&[
            Member::new("inner.7z", &inner, method),
            Member::new("tail.txt", tail, method),
        ]);
        let total = inner.len() + content.len() + tail.len();
        for ceiling in [total - 1, total, total + 1] {
            let events = collect(bytes.clone(), limits(3, ceiling));
            let mut expected = vec![(b"fixture.7z!inner.7z!value.txt".to_vec(), content.clone())];
            if ceiling >= total {
                expected.push((b"fixture.7z!tail.txt".to_vec(), tail.to_vec()));
                assert!(events.issues.is_empty());
            } else {
                assert_eq!(
                    events.issues,
                    [(SourceStage::Limit, SourceIssueKind::Limit)]
                );
            }
            assert_eq!(events.members, expected, "{method:?}/{ceiling}");
        }
        for entries in [2, 3] {
            let events = collect(bytes.clone(), limits(entries, total));
            if entries == 2 {
                assert_eq!(
                    events.members,
                    [(b"fixture.7z!tail.txt".to_vec(), tail.to_vec())]
                );
                assert_eq!(
                    events.issues,
                    [(SourceStage::Limit, SourceIssueKind::Limit)]
                );
            } else {
                assert_eq!(events.members.len(), 2);
                assert!(events.issues.is_empty());
            }
        }
    }
}

#[test]
fn decoded_member_limits_are_inclusive_for_each_method() {
    for method in METHODS {
        let content = payload(7000);
        let bytes = archive(&[Member::new("value.txt", &content, method)]);
        for ceiling in [6999, 7000, 7001] {
            let limits = ArchiveLimits::new(4, 1, ceiling, 1 << 20, 1 << 20).unwrap();
            let events = collect(bytes.clone(), limits);
            if ceiling < content.len() {
                assert!(events.members.is_empty());
                assert_eq!(
                    events.issues,
                    [(SourceStage::Limit, SourceIssueKind::Limit)]
                );
            } else {
                assert!(events.issues.is_empty());
                assert_eq!(
                    events.members,
                    [(b"fixture.7z!value.txt".to_vec(), content.clone())]
                );
            }
        }
    }
}

fn graph_collect(bytes: Vec<u8>, limits: ArchiveLimits, strict: bool) -> Events {
    let mut events = Events::default();
    let mut source = ArchiveSource::with_options(
        Cursor::new(bytes),
        "fixture.7z",
        FileOptions::default(),
        ArchiveOptions::new(limits).strict_7z_member_lengths(strict),
    );
    assert_eq!(
        source.visit(&CancellationToken::new(), &mut |event| {
            events.record(event);
            Ok(SourceControl::Continue)
        }),
        Ok(SourceControl::Continue)
    );
    events
}

fn graph_folders<'a>(
    layout: usize,
    first: &'a [u8],
    second: &'a [u8],
    methods: &[Method],
) -> Vec<sevenz_seeds::Folder<'a>> {
    use sevenz_seeds::Folder;
    match layout {
        0 => vec![Folder::new(&[("first.txt", first)], methods)],
        1 => vec![Folder::new(
            &[("first.txt", first), ("second.txt", second)],
            methods,
        )],
        _ => vec![
            Folder::new(&[("first.txt", first)], methods),
            Folder::new(&[("second.txt", second)], methods),
        ],
    }
}

#[test]
fn linear_coder_graphs_preserve_single_solid_and_multiple_folder_bytes() {
    let first = payload(4097);
    let second = b"independent folder tail\n";
    for before in METHODS {
        for after in METHODS {
            for layout in 0..3 {
                let folders = graph_folders(layout, &first, second, &[before, after]);
                let bytes = sevenz_seeds::folder_archive(&folders);
                let expected = if layout == 0 {
                    vec![(b"fixture.7z!first.txt".to_vec(), first.clone())]
                } else {
                    vec![
                        (b"fixture.7z!first.txt".to_vec(), first.clone()),
                        (b"fixture.7z!second.txt".to_vec(), second.to_vec()),
                    ]
                };
                let total = first.len() + if layout == 0 { 0 } else { second.len() };
                for strict in [false, true] {
                    for ceiling in [total - 1, total, total + 1] {
                        let events =
                            graph_collect(bytes.clone(), limits(expected.len(), ceiling), strict);
                        if ceiling < total {
                            assert!(events.members.is_empty());
                            assert_eq!(
                                events.issues,
                                [(SourceStage::Limit, SourceIssueKind::Limit)]
                            );
                        } else {
                            assert!(events.issues.is_empty(), "{before:?}/{after:?}/{layout}");
                            assert_eq!(events.members, expected, "{before:?}/{after:?}/{layout}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn declared_early_eof_is_compatible_by_default_and_rejected_only_when_requested() {
    let first = payload(513);
    let second = b"independent tail\n";
    for method in METHODS {
        for layout in 0..3 {
            let mut folders = graph_folders(layout, &first, second, &[method]);
            folders.last_mut().unwrap().overstate_last_member(7);
            let bytes = sevenz_seeds::folder_archive(&folders);
            let compatible = graph_collect(bytes.clone(), limits(2, 1 << 20), false);
            assert!(compatible.issues.is_empty(), "{method:?}/{layout}");
            let mut expected = vec![(b"fixture.7z!first.txt".to_vec(), first.clone())];
            if layout != 0 {
                expected.push((b"fixture.7z!second.txt".to_vec(), second.to_vec()));
            }
            assert_eq!(compatible.members, expected, "{method:?}/{layout}");
            let strict = graph_collect(bytes, limits(2, 1 << 20), true);
            assert!(
                strict.members.is_empty(),
                "archive is atomic before publication"
            );
            assert_eq!(
                strict.issues,
                [(SourceStage::Decode, SourceIssueKind::Decode)]
            );
        }
    }
}

#[test]
fn graph_crc_failure_and_invalid_bindings_publish_no_members() {
    use sevenz_seeds::{Folder, folder_archive};
    for method in METHODS {
        for layout in 0..3 {
            let mut folders = graph_folders(
                layout,
                b"first content",
                b"second content",
                &[method, Method::Copy],
            );
            folders.last_mut().unwrap().members.last_mut().unwrap().crc ^= 1;
            for strict in [false, true] {
                let events = graph_collect(folder_archive(&folders), limits(2, 1 << 20), strict);
                assert!(events.members.is_empty());
                assert_eq!(
                    events.issues,
                    [(SourceStage::Decode, SourceIssueKind::Decode)]
                );
            }
        }
    }
    for pairs in [vec![(2, 0)], vec![(1, 2)]] {
        let mut folder = Folder::new(
            &[("value.txt", b"synthetic bytes")],
            &[Method::Copy, Method::Copy],
        );
        folder.bind_pairs = pairs;
        let events = graph_collect(folder_archive(&[folder]), limits(1, 1 << 20), true);
        assert!(events.members.is_empty());
        assert_eq!(
            events.issues,
            [(SourceStage::Decode, SourceIssueKind::CorruptArchive)]
        );
    }
}

#[test]
fn solid_and_multiple_folder_names_remain_virtual_metadata() {
    use sevenz_seeds::{Folder, folder_archive};
    for method in METHODS {
        for solid in [false, true] {
            for unsafe_name in ["../escape.txt", "/absolute.txt", "C:/device.txt"] {
                let files: &[(&str, &[u8])] = &[
                    ("safe.txt", b"safe bytes"),
                    (unsafe_name, b"untrusted member"),
                ];
                let folders = if solid {
                    vec![Folder::new(files, &[method, Method::Copy])]
                } else {
                    files
                        .iter()
                        .map(|file| Folder::new(&[*file], &[method, Method::Copy]))
                        .collect()
                };
                let events = graph_collect(folder_archive(&folders), limits(2, 1 << 20), true);
                assert_eq!(
                    events.members,
                    [
                        (b"fixture.7z!safe.txt".to_vec(), b"safe bytes".to_vec()),
                        (
                            format!("fixture.7z!{unsafe_name}").into_bytes(),
                            b"untrusted member".to_vec()
                        ),
                    ]
                );
                assert!(events.issues.is_empty(), "{method:?}/{solid}/{unsafe_name}");
            }
        }
    }
}

#[test]
fn cyclic_and_duplicate_coder_bindings_are_rejected_before_decoding() {
    use sevenz_seeds::{Folder, folder_archive};
    for pairs in [
        vec![(1, 0), (1, 1)],
        vec![(1, 0), (2, 0)],
        vec![(1, 1), (2, 2)],
        vec![(2, 1), (1, 2)],
    ] {
        let mut folder = Folder::new(&[("value.txt", b"synthetic bytes")], &[Method::Copy; 3]);
        folder.bind_pairs = pairs.clone();
        let mut header = Folder::new(&[("header", &[1, 0])], &[Method::Copy; 3]);
        header.bind_pairs = pairs;
        for strict in [false, true] {
            for bytes in [
                folder_archive(std::slice::from_ref(&folder)),
                sevenz_seeds::encoded_header_archive(&header),
            ] {
                let events = graph_collect(bytes, limits(1, 1 << 20), strict);
                assert!(events.members.is_empty());
                assert_eq!(
                    events.issues,
                    [(SourceStage::Decode, SourceIssueKind::CorruptArchive)]
                );
            }
        }
    }
    // A complete empty Header is independently specified as Header, End.
    let empty_header = Folder::new(&[("header", &[1, 0])], &[Method::Copy; 3]);
    let empty = graph_collect(
        sevenz_seeds::encoded_header_archive(&empty_header),
        limits(1, 1 << 20),
        true,
    );
    assert!(empty.members.is_empty() && empty.issues.is_empty());
    let mut reordered = Folder::new(&[("value.txt", b"synthetic bytes")], &[Method::Copy; 3]);
    reordered.bind_pairs = vec![(0, 1), (2, 0)];
    let events = graph_collect(folder_archive(&[reordered]), limits(1, 1 << 20), true);
    assert!(events.issues.is_empty());
    assert_eq!(
        events.members,
        [(
            b"fixture.7z!value.txt".to_vec(),
            b"synthetic bytes".to_vec()
        )]
    );
}

#[test]
fn strict_length_policy_preserves_callback_stop_and_error_across_folder_layouts() {
    for layout in 0..3 {
        for short in [false, true] {
            let mut folders = graph_folders(
                layout,
                b"first content",
                b"second content",
                &[Method::Deflate, Method::Lz4],
            );
            if short {
                folders.last_mut().unwrap().overstate_last_member(7);
            }
            for fail in [false, true] {
                let mut source = ArchiveSource::with_options(
                    Cursor::new(sevenz_seeds::folder_archive(&folders)),
                    "fixture.7z",
                    FileOptions::default(),
                    ArchiveOptions::new(limits(2, 1 << 20)).strict_7z_member_lengths(true),
                );
                let error = CallbackError::new("synthetic consumer failure");
                let mut calls = 0;
                let outcome = source.visit(&CancellationToken::new(), &mut |event| {
                    calls += 1;
                    assert_eq!(matches!(event, SourceEvent::Issue(_)), short);
                    if fail {
                        Err(error.clone())
                    } else {
                        Ok(SourceControl::Stop)
                    }
                });
                assert_eq!(calls, 1);
                assert_eq!(
                    outcome,
                    if fail {
                        Err(SourceError::Callback(error))
                    } else {
                        Ok(SourceControl::Stop)
                    }
                );
            }
        }
    }
}
