#![forbid(unsafe_code)]
#![no_main]

#[allow(dead_code)]
#[path = "../../tests/support/campaign_profile.rs"]
mod campaign_profile;

use campaign_profile::Profile;

use std::borrow::Cow;
use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

#[path = "../../src/regex/mod.rs"]
mod regex;

use regex::GoRegex;

fn framed_input(data: &[u8]) -> Option<(Cow<'_, str>, &[u8])> {
    let (pattern, haystack) = campaign_profile::regex_parts(data, Profile::current())?;
    Some((String::from_utf8_lossy(pattern), haystack))
}

fuzz_target!(|data: &[u8]| {
    let Some((pattern, haystack)) = framed_input(data) else {
        return;
    };
    let Ok(compiled) = GoRegex::compile(pattern.as_ref()) else {
        return;
    };

    black_box(compiled.source());
    black_box(regex::backend_version());
    black_box(compiled.capture_count());
    black_box(compiled.capture_names());
    black_box(compiled.is_match(haystack));
    black_box(compiled.find_all(haystack));
    black_box(compiled.captures_all(haystack));
});
