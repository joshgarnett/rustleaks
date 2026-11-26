//! A second, unrelated Rust static library for the link test.
//!
//! It uses the parts of the standard library that every Rust static library
//! carries (formatting, allocation and panic unwinding), so a Go program that
//! links it next to the Rustleaks library sees the same standard library
//! symbols twice.

use std::panic;

/// Returns the length of a formatted string after catching a panic, or 0
/// when the panic was not caught.
#[unsafe(no_mangle)]
pub extern "C" fn other_rust_answer() -> u64 {
    let caught = panic::catch_unwind(|| {
        panic!("expected panic from the second library");
    });
    if caught.is_ok() {
        return 0;
    }
    let text = format!("{:>42}", "x");
    text.len() as u64
}
