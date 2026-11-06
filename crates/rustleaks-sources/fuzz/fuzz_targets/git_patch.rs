#![forbid(unsafe_code)]
#![no_main]

#[allow(dead_code)]
#[path = "../../../rustleaks-core/tests/support/campaign_profile.rs"]
mod campaign_profile;
#[allow(dead_code)]
#[path = "../support/git_harness.rs"]
mod git_harness;
#[allow(dead_code)]
#[path = "../support/source_frame.rs"]
mod source_frame;

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

fuzz_target!(|data: &[u8]| {
    black_box(git_harness::exercise(
        data,
        campaign_profile::Profile::current(),
    ));
});
