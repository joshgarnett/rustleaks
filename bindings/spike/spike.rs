//! Temporary smoke library for the Go and Python binding build spike.
//!
//! This file is not part of the Cargo workspace and is not owned engine code.
//! It is replaced by `crates/rustleaks-ffi` and must be deleted before the
//! bindings pull request merges.

use std::hint::black_box;

/// Returns `a + b`, wrapping on overflow.
#[unsafe(no_mangle)]
pub extern "C" fn spike_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Returns the sum of `len` bytes at `ptr`. A null pointer is valid only with
/// a length of 0.
///
/// # Safety
///
/// When `len` is not 0, `ptr` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spike_sum(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: the caller guarantees `len` readable bytes at a non-null `ptr`.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    bytes.iter().map(|&byte| u64::from(byte)).sum()
}

/// Uses about `kib` KiB of stack in one frame and returns a value that
/// depends on every touched page, so the compiler keeps the frame.
#[unsafe(no_mangle)]
pub extern "C" fn spike_stack(kib: u32) -> u64 {
    match kib {
        0..=64 => touch::<{ 64 * 1024 }>(),
        65..=256 => touch::<{ 256 * 1024 }>(),
        _ => touch::<{ 1024 * 1024 }>(),
    }
}

#[inline(never)]
fn touch<const N: usize>() -> u64 {
    let mut buffer = [0_u8; N];
    let buffer = black_box(&mut buffer);
    let mut index = 0;
    while index < N {
        buffer[index] = (index / 4096) as u8;
        index += 4096;
    }
    black_box(&*buffer).iter().step_by(4096).map(|&byte| u64::from(byte)).sum()
}
