//! Archive exercise shared by libFuzzer and deterministic source tests.

use std::hint::black_box;
use std::io::{Cursor, Read};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CancellationToken, FileOptions, Source,
    SourceControl, SourceError, SourceEvent, SourceIssueKind, SourceStage,
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

/// One event in a form that two runs can compare.
#[derive(Debug, Eq, PartialEq)]
enum Recorded {
    Fragment(
        Vec<u8>,
        usize,
        Vec<u8>,
        Option<(SourceStage, SourceIssueKind)>,
    ),
    Issue(SourceStage, SourceIssueKind),
}

/// Returns the payload in reads of one to seven bytes.
struct SmallReads {
    payload: Vec<u8>,
    position: usize,
    step: usize,
}

impl Read for SmallReads {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.step = self.step % 7 + 1;
        let count = output
            .len()
            .min(self.step)
            .min(self.payload.len() - self.position);
        output[..count].copy_from_slice(&self.payload[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

pub fn exercise_with_profile(
    data: &[u8],
    profile: Profile,
    mut observe: impl FnMut(&SourceEvent),
) -> Option<Observation> {
    let caps = profile.archive();
    let frame = Frame::decode_bounded(data, caps.input_bytes)?;
    let (observation, recorded) = run(
        &frame,
        caps,
        Cursor::new(frame.payload.to_vec()),
        &mut observe,
    );
    // Archives stream from their input, so the read sizes of the input must
    // not change any event. Cancellation after an event is observed at the
    // next poll, which can come at a different point, so skip that case.
    if !frame.cancel_after_event() {
        let small = SmallReads {
            payload: frame.payload.to_vec(),
            position: 0,
            step: 0,
        };
        let (again, recorded_again) = run(&frame, caps, small, &mut |_| {});
        assert_eq!(
            recorded, recorded_again,
            "input read sizes changed events for {}",
            FORMAT_NAMES[frame.format]
        );
        assert_eq!(
            observation.result.is_ok(),
            again.result.is_ok(),
            "input read sizes changed the result"
        );
    }
    Some(observation)
}

fn run(
    frame: &Frame<'_>,
    caps: super::campaign_profile::ArchiveProfile,
    input: impl Read + Send + 'static,
    observe: &mut dyn FnMut(&SourceEvent),
) -> (Observation, Vec<Recorded>) {
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
    let mut source =
        ArchiveSource::with_options(input, FORMAT_NAMES[frame.format], file_options, options);
    let cancellation = CancellationToken::new();
    if frame.cancel_before() {
        cancellation.cancel();
    }

    let mut events = 0_usize;
    let mut emitted_bytes = 0_usize;
    let mut recorded = Vec::new();
    let visit = catch_unwind(AssertUnwindSafe(|| {
        source.visit(&cancellation, &mut |event| {
            events += 1;
            match &event {
                SourceEvent::Fragment { fragment, issue } => {
                    emitted_bytes = emitted_bytes
                        .checked_add(fragment.content().len())
                        .expect("bounded event-byte accounting");
                    recorded.push(Recorded::Fragment(
                        fragment.file_path().as_bytes().to_vec(),
                        fragment.start_line(),
                        fragment.content().as_bytes().to_vec(),
                        issue.as_ref().map(|issue| (issue.stage(), issue.kind())),
                    ));
                }
                SourceEvent::Issue(issue) => {
                    black_box(issue.message());
                    recorded.push(Recorded::Issue(issue.stage(), issue.kind()));
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
    (
        Observation {
            result,
            events,
            emitted_bytes,
            input_bytes: frame.payload.len() + HEADER_BYTES,
        },
        recorded,
    )
}
