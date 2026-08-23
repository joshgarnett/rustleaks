//! Rust-first repository generation and compatibility verification.

mod artifacts;
mod config;
mod fixtures;
mod fuzz_seeds;
mod generate;
mod git_corpus;
mod go_lowercase;
mod oracle;
mod report;
mod session;
mod source;
mod support;
mod traceability;

pub(crate) use config::{check_config_corpus, write_config_corpus};
pub(crate) use fixtures::verify_fixtures;
pub(crate) use fuzz_seeds::generate_regex_fuzz_seeds;
pub(crate) use generate::run as run_generate;
pub(crate) use git_corpus::{check_git_corpus, write_git_corpus};
pub(crate) use go_lowercase::generate_go_lowercase;
pub(crate) use oracle::{Corpus, generate_corpus, replay_corpus};
pub(crate) use report::{check_report_corpus, write_report_corpus};
pub(crate) use session::{check_session_corpus, write_session_corpus};
pub(crate) use source::{check_source_corpus, write_source_corpus};
#[cfg(test)]
pub(crate) use support::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};
pub(crate) use support::{command_output, command_status_with_timeout, sha256_file};
pub(crate) use traceability::api::{
    check_api_dispositions, self_test_api_dispositions, summarize_api_dispositions,
    write_api_dispositions,
};
pub(crate) use traceability::assertions::{
    check_assertions, validate_final_traceability, write_assertions,
};
