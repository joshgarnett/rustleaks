//! Rust-first repository generation and compatibility verification.

mod artifacts;
mod fixtures;
mod fuzz_seeds;
mod go_lowercase;
mod oracle;
mod report;
mod support;

pub(crate) use fixtures::verify_fixtures;
pub(crate) use fuzz_seeds::generate_regex_fuzz_seeds;
pub(crate) use go_lowercase::generate_go_lowercase;
pub(crate) use oracle::{Corpus, replay_corpus};
pub(crate) use report::{check_report_corpus, write_report_corpus};
#[cfg(test)]
pub(crate) use support::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};
pub(crate) use support::{command_output, command_status_with_timeout, sha256_file};
