//! Archive exercise shared by libFuzzer and deterministic source tests.

use std::hint::black_box;
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CancellationToken, FileOptions, Source,
    SourceControl, SourceError, SourceEvent,
};

use super::archive_frame::{FORMAT_NAMES, Frame, HEADER_BYTES};
use super::campaign_profile::Profile;

// Decoder memory caps use the member-byte limit. LZIP needs at least 42 KiB;
// the reviewed compressed RAR3/RAR5 seeds declare 128 KiB windows. Keep the
// aggregate output limit unchanged while admitting those decoding paths.
pub const MAX_MEMBER_BYTES: usize = 128 * 1024;
pub const MAX_TOTAL_BYTES: usize = 128 * 1024;

pub struct Observation {
    pub result: Result<SourceControl, SourceError>,
    pub events: usize,
    pub emitted_bytes: usize,
    pub input_bytes: usize,
}

pub fn exercise(data: &[u8], observe: impl FnMut(&SourceEvent)) -> Option<Observation> {
    exercise_with_profile(data, Profile::Smoke, observe)
}

pub fn exercise_with_profile(
    data: &[u8],
    profile: Profile,
    mut observe: impl FnMut(&SourceEvent),
) -> Option<Observation> {
    let caps = profile.archive();
    let frame = Frame::decode_bounded(data, caps.input_bytes)?;
    let limits = ArchiveLimits::new(
        caps.depth,
        caps.entries,
        caps.member_bytes,
        caps.total_bytes,
        caps.input_bytes,
    )
    .expect("fixed fuzz limits are positive");
    let file_options = FileOptions::new(caps.chunk_bytes)
        .expect("fixed chunk size is positive")
        .max_boundary_read_ahead(128);
    let options = ArchiveOptions::new(limits).emit_limit_issues(true);
    let mut source = ArchiveSource::with_options(
        Cursor::new(frame.payload.to_vec()),
        FORMAT_NAMES[frame.format],
        file_options,
        options,
    );
    let cancellation = CancellationToken::new();
    if frame.cancel_before() {
        cancellation.cancel();
    }

    let mut events = 0_usize;
    let mut emitted_bytes = 0_usize;
    let visit = catch_unwind(AssertUnwindSafe(|| {
        source.visit(&cancellation, &mut |event| {
            events += 1;
            match &event {
                SourceEvent::Fragment { fragment, issue } => {
                    emitted_bytes = emitted_bytes
                        .checked_add(fragment.content().len())
                        .expect("bounded event-byte accounting");
                    black_box(issue);
                }
                SourceEvent::Issue(issue) => {
                    black_box((issue.stage(), issue.kind(), issue.message()));
                }
                _ => {}
            }
            // Short decoder reads can produce one fragment per byte. Allow
            // terminal/empty issues for every entry and the outer source too.
            let max_events = caps.total_bytes + 2 * (caps.entries + 1);
            assert!(events <= max_events, "archive event limit");
            assert!(
                emitted_bytes <= caps.total_bytes,
                "archive emitted-byte limit"
            );
            observe(&event);
            if frame.cancel_after_event() {
                cancellation.cancel();
            }
            Ok(if frame.stop_after_event() {
                SourceControl::Stop
            } else {
                SourceControl::Continue
            })
        })
    }));
    let result = match visit {
        Ok(result) => result,
        Err(payload) => resume_unwind(payload),
    };
    if frame.cancel_before() {
        assert!(matches!(result, Err(SourceError::Cancelled)));
        assert_eq!(events, 0);
    }
    Some(Observation {
        result,
        events,
        emitted_bytes,
        input_bytes: frame.payload.len() + HEADER_BYTES,
    })
}
