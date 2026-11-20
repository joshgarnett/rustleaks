#![forbid(unsafe_code)]
//! The Rustleaks command line: argument parsing, configuration, scans and output.

mod args;
mod cli_spec;
mod complete_profile;
mod completion;
mod config;
mod help;
mod limits;
mod output;
mod run;
mod source;

pub use run::{RunEnvironment, run_from};
