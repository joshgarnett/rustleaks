#![forbid(unsafe_code)]
#![no_main]

#[cfg(not(panic = "unwind"))]
compile_error!(
    "archive fuzzing requires panic=unwind; panic=abort dependency containment is unsupported"
);

use std::hint::black_box;
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CancellationToken, FileOptions, Source,
    SourceControl, SourceError, SourceEvent,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_ENTRIES: usize = 8;
const MAX_MEMBER_BYTES: usize = 4 * 1024;
const MAX_TOTAL_BYTES: usize = 8 * 1024;
const FORMAT_NAMES: &[&str] = &[
    "input.tar",
    "input.zip",
    "input.7z",
    "input.rar",
    "input.tar.gz",
    "input.gz",
    "input.tar.xz",
    "input.xz",
    "input.bz2",
    "input.br",
    "input.lz4",
    "input.sz",
    "input.mz",
    "input.zst",
    "input.zz",
    "input.lz",
];

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let control = data.first().copied().unwrap_or_default();
    let payload = &data[data.len().min(1)..];
    let name = FORMAT_NAMES[usize::from(control) % FORMAT_NAMES.len()];
    let limits = ArchiveLimits::new(
        2,
        MAX_ENTRIES,
        MAX_MEMBER_BYTES,
        MAX_TOTAL_BYTES,
        MAX_INPUT_BYTES,
    )
    .expect("fixed fuzz limits are positive");
    let file_options = FileOptions::new(512)
        .expect("fixed chunk size is positive")
        .max_boundary_read_ahead(128);
    let options = ArchiveOptions::new(limits).emit_limit_issues(true);
    let mut source =
        ArchiveSource::with_options(Cursor::new(payload.to_vec()), name, file_options, options);
    let cancellation = CancellationToken::new();
    if control & 1 != 0 {
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
            if control & 2 != 0 {
                cancellation.cancel();
            }
            Ok(if control & 4 != 0 {
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

    assert!(events <= 64, "strict entry/byte limits bound event growth");
    assert!(emitted_bytes <= MAX_TOTAL_BYTES);
    if control & 1 != 0 {
        assert!(matches!(result, Err(SourceError::Cancelled)));
    }
    let _ = black_box(result);
});
