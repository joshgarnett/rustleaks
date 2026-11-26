#![forbid(unsafe_code)]
#![no_main]

#[cfg(not(panic = "unwind"))]
compile_error!("the exports fuzz target requires panic=unwind; the exports catch panics");

use libfuzzer_sys::fuzz_target;

// The harness calls the exported C functions with valid pointers and the
// fuzz input as configuration, option keys and values, rule IDs, scan
// arguments and scanned bytes. Its unsafe calls live in rustleaks-ffi.
fuzz_target!(|data: &[u8]| {
    rustleaks_ffi::harness::exercise(data);
});
