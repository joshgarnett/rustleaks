#![forbid(unsafe_code)]
#![no_main]

use std::hint::black_box;
use std::io;

use rustleaks_sources::{
    CallbackError, CancellationToken, FileOptions, FileSource, ReadOutcome, ReadStatus, Source,
    SourceControl, SourceEvent, SourceReader,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4 * 1024;

struct ScheduledReader {
    schedule: Vec<u8>,
    payload: Vec<u8>,
    operation: usize,
    payload_offset: usize,
}

impl SourceReader for ScheduledReader {
    fn read_source(&mut self, buffer: &mut [u8]) -> ReadOutcome {
        let Some(&instruction) = self.schedule.get(self.operation) else {
            return ReadOutcome::new(0, ReadStatus::Eof);
        };
        self.operation += 1;

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

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let control = data.first().copied().unwrap_or_default();
    let rest = &data[data.len().min(1)..];
    let schedule_len = rest
        .first()
        .map_or(0, |value| usize::from(*value) % (rest.len() + 1));
    let (schedule, payload) = rest.split_at(schedule_len);
    let reader = ScheduledReader {
        schedule: schedule.to_vec(),
        payload: payload.to_vec(),
        operation: 0,
        payload_offset: 0,
    };
    let chunk_size = usize::from(control & 0x3f) + 1;
    let read_ahead = usize::from(control >> 2) & 0x3f;
    let options = FileOptions::new(chunk_size)
        .expect("the derived chunk size is positive")
        .max_boundary_read_ahead(read_ahead);
    let mut source = FileSource::from_source_reader(Box::new(reader), "fuzz/input", options);
    let cancellation = CancellationToken::new();
    if control & 0x40 != 0 {
        cancellation.cancel();
    }

    let mut events = 0_usize;
    let result = source.visit(&cancellation, &mut |event| {
        events += 1;
        if let SourceEvent::Fragment { fragment, issue } = &event {
            assert!(fragment.content().len() <= chunk_size.saturating_add(read_ahead));
            black_box(issue);
        }
        if control & 0x20 != 0 {
            cancellation.cancel();
        }
        if control & 0x10 != 0 {
            return Err(CallbackError::new("scheduled callback failure"));
        }
        Ok(if control & 0x08 != 0 {
            SourceControl::Stop
        } else {
            SourceControl::Continue
        })
    });
    assert!(events <= schedule.len().saturating_add(2));
    let _ = black_box(result);
});
