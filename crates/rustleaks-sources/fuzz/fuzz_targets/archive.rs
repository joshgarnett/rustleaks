#![forbid(unsafe_code)]
#![no_main]

#[cfg(not(panic = "unwind"))]
compile_error!(
    "archive fuzzing requires panic=unwind; panic=abort dependency containment is unsupported"
);

#[allow(dead_code)] // Seed encoding and observations are consumed by deterministic tests.
#[path = "../support/archive_frame.rs"]
mod archive_frame;
#[allow(dead_code)]
#[path = "../support/archive_harness.rs"]
mod archive_harness;
#[allow(dead_code)]
#[path = "../../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;

use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    black_box(archive_harness::exercise_with_profile(
        data,
        campaign_profile::Profile::current(),
        |_| {},
    ));
});
