#![forbid(unsafe_code)]
#![no_main]

use std::borrow::Cow;
use std::hint::black_box;

use libfuzzer_sys::fuzz_target;

#[path = "../../src/regex/mod.rs"]
mod regex;

use regex::GoRegex;

fn framed_input(data: &[u8]) -> Option<(Cow<'_, str>, &[u8])> {
    let (&low, rest) = data.split_first()?;
    let (&high, payload) = rest.split_first()?;
    let declared_pattern_len = usize::from(u16::from_le_bytes([low, high]));
    let pattern_len = declared_pattern_len % (payload.len() + 1);
    let (pattern, haystack) = payload.split_at(pattern_len);
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
