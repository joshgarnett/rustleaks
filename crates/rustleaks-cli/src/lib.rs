#![forbid(unsafe_code)]
//! Synchronous Rustleaks CLI orchestration with pinned backward compatibility.

mod args;
mod cli_spec;
mod complete_profile;
mod completion;
mod config;
mod help;
mod output;
mod run;
mod source;

pub use run::{RunEnvironment, run_from};
