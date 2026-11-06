//! Shared reader exercise with observable consumed-work accounting.

use std::hint::black_box;
use std::io;

use rustleaks_sources::{
    CallbackError, CancellationToken, FileOptions, FileSource, ReadOutcome, ReadStatus, Source,
    SourceControl, SourceEvent, SourceReader,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::campaign_profile::Profile;
use super::source_frame::ReaderFrame;

const MAX_BYTES_PER_SCHEDULED_READ: usize = 15;

struct ScheduledReader {
    schedule: Vec<u8>,
    payload: Vec<u8>,
    operation: usize,
    payload_offset: usize,
    operations: Arc<AtomicUsize>,
    payload_reads: Arc<AtomicUsize>,
}

impl SourceReader for ScheduledReader {
    fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
        let Some(&instruction) = self.schedule.get(self.operation) else {
            return ReadOutcome::new(0, ReadStatus::Eof);
        };
        self.operation += 1;
        self.operations.fetch_add(1, Ordering::Relaxed);

        if instruction & 0x80 != 0 {
            return ReadOutcome::new(buffer.len().saturating_add(1), ReadStatus::Continue);
        }
        let count = usize::from(instruction & 0x0f).min(buffer.len());
        for slot in &mut buffer[..count] {
            *slot = if self.payload.is_empty() {
                instruction
            } else {
                let byte = self.payload[self.payload_offset % self.payload.len()];
                self.payload_offset += 1;
                self.payload_reads.fetch_add(1, Ordering::Relaxed);
                byte
            };
        }
        let status = match (instruction >> 4) & 0x03 {
            0 | 1 => ReadStatus::Continue,
            2 => ReadStatus::Eof,
            _ => ReadStatus::Error {
                kind: io::ErrorKind::InvalidData,
                message: "scheduled reader failure".to_owned(),
            },
        };
        ReadOutcome::new(count, status)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Observation {
    pub result: Result<SourceControl, rustleaks_sources::SourceError>,
    pub schedule_operations: usize,
    pub payload_reads: usize,
    pub emitted_bytes: usize,
    pub events: usize,
}

pub fn exercise(data: &[u8], profile: Profile) -> Observation {
    exercise_with(data, profile, |_| {})
}

/// Observe emitted events before applying the independently selected controls.
pub fn exercise_with(
    data: &[u8],
    profile: Profile,
    mut observe: impl FnMut(&SourceEvent),
) -> Observation {
    let frame = ReaderFrame::decode(data, profile);
    let control = frame.controls;
    let schedule = frame.schedule;
    let payload = frame.payload;
    let operations = Arc::new(AtomicUsize::new(0));
    let payload_reads = Arc::new(AtomicUsize::new(0));
    let reader = ScheduledReader {
        schedule: schedule.to_vec(),
        payload: payload.to_vec(),
        operation: 0,
        payload_offset: 0,
        operations: Arc::clone(&operations),
        payload_reads: Arc::clone(&payload_reads),
    };
    let chunk_size = control.chunk_bytes;
    let read_ahead = control.read_ahead_bytes;
    let options = FileOptions::new(chunk_size)
        .expect("the derived chunk size is positive")
        .max_boundary_read_ahead(read_ahead);
    let mut source = FileSource::from_source_reader(Box::new(reader), "fuzz/input", options);
    let cancellation = CancellationToken::new();
    if control.cancel_before {
        cancellation.cancel();
    }

    let mut events = 0_usize;
    let mut emitted_bytes = 0_usize;
    let result = source.visit(&cancellation, &mut |event| {
        events += 1;
        observe(&event);
        if let SourceEvent::Fragment { fragment, issue } = &event {
            assert!(fragment.content().len() <= chunk_size.saturating_add(read_ahead));
            emitted_bytes += fragment.content().len();
            black_box(issue);
        }
        if control.cancel_in_callback {
            cancellation.cancel();
        }
        if control.callback_error {
            return Err(CallbackError::new("scheduled callback failure"));
        }
        Ok(if control.callback_stop {
            SourceControl::Stop
        } else {
            SourceControl::Continue
        })
    });
    // A valid scheduled read can be buffered and split into one event per
    // byte, followed by one zero-byte error event for a pending error status.
    let maximum_events = schedule
        .len()
        .saturating_mul(MAX_BYTES_PER_SCHEDULED_READ.saturating_add(1));
    assert!(events <= maximum_events);
    Observation {
        result,
        schedule_operations: operations.load(Ordering::Relaxed),
        payload_reads: payload_reads.load(Ordering::Relaxed),
        emitted_bytes,
        events,
    }
}
