//! A small, private C ABI over `rustleaks-core` for the Go and Python
//! bindings in this repository.
//!
//! The ABI is not a public interface. A wrapper always ships with a library
//! of the same version and checks the exact ABI number. The functions and
//! types are declared in `include/rustleaks.h`, and a unit test checks that
//! the header matches the exports. [`exports`] states the pointer rules.
//!
//! This is the only crate in the repository that allows unsafe Rust. Every
//! unsafe block has a `SAFETY:` comment. The exports only check and read the
//! pointers that a C caller passes, write out parameters and turn handles
//! into boxes and back; the hidden `harness` module is a safe Rust client of
//! the exports for the tests and the fuzz target. Detection runs in safe
//! `rustleaks-core` code.
//!
//! The library builds each engine on its own thread and, by default, runs
//! scans on threads that the engine owns, each with an 8 MiB stack, because
//! callers can have much smaller stacks than pattern compilation needs.
#![deny(
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]
#![warn(missing_docs)]

// The exports catch panics so that a bug cannot unwind into a C caller or
// abort the host process. That needs unwinding.
#[cfg(not(panic = "unwind"))]
compile_error!("rustleaks-ffi requires panic=unwind; it catches panics at the C boundary");

pub mod abi;
pub mod cancel;
pub mod exports;
pub mod handles;
#[doc(hidden)]
pub mod harness;
mod threads;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod header_tests;
