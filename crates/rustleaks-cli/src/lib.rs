#![forbid(unsafe_code)]
//! Synchronous Rustleaks CLI orchestration with pinned backward compatibility.

mod args;
mod complete_profile;
mod config;
mod output;
mod run;
mod source;

pub use run::{RunEnvironment, run_from};
