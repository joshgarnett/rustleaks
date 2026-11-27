//! A second, unrelated Rust static library for the link test.
//!
//! It uses the parts of the standard library that every Rust static library
//! carries (formatting, allocation and panic unwinding), so a Go program that
//! links it next to the Rustleaks library sees the same standard library
//! symbols twice. Its only unsafe Rust is `#[unsafe(no_mangle)]`, which the
//! xtask security check enforces.
#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]

use std::panic;

/// Returns the length of a formatted string after catching a panic, or 0
/// when the panic was not caught.
// SAFETY: no other symbol in a program that links the link test is named
// other_rust_answer, so the unmangled name cannot clash.
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
