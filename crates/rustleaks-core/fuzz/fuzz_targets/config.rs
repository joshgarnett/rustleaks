#![forbid(unsafe_code)]
#![no_main]

use std::hint::black_box;

use rustleaks_core::config::{ConfigLoader, ConfigOrigin};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let text = String::from_utf8_lossy(data);
    let loader = ConfigLoader::new()
        .with_default_config("")
        .with_current_version("0.0.0")
        .expect("the fixed fuzz version is valid");
    let origin = ConfigOrigin::virtual_path("fuzz/config.toml");

    let parsed = loader.parse_toml(&text, Some(&origin));
    let _ = black_box(parsed.as_ref().map(|raw| raw.rules.len()));
    if let Ok(raw) = parsed {
        let _ = black_box(loader.compile_at(raw, Some(origin)));
    }

    // Exercise the combined parse/compile entry point independently so a
    // future divergence between the two public paths remains fuzz-visible.
    let _ = black_box(loader.load_toml(&text));
});
