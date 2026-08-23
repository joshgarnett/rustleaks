#![forbid(unsafe_code)]
#![no_main]

use rustleaks_sources::{CancellationToken, GitLimits, fuzz_parse_patch};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let control = data.first().copied().unwrap_or_default();
    let patch = &data[data.len().min(1)..];
    let limits = GitLimits::new(MAX_INPUT_BYTES, 2_048, 4_096, MAX_INPUT_BYTES)
        .expect("fixed fuzz limits are positive")
        .with_parser_limits(
            4 * 1024,
            4 * 1024,
            usize::from(control & 0x1f) + 1,
            usize::from(control) + 1,
        )
        .expect("derived parser limits are positive");

    let parse = || {
        let cancellation = CancellationToken::new();
        if control & 0x80 != 0 {
            cancellation.cancel();
        }
        fuzz_parse_patch(patch, limits, &cancellation)
    };
    assert_eq!(parse(), parse(), "Git patch parsing must be deterministic");
});
