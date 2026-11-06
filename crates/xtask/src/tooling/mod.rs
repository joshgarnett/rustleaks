//! Rust-owned maintenance and frozen historical evidence verification.

mod archive_fuzz_seeds;
mod artifacts;
#[cfg(test)]
mod cli_corpus;
mod composite;
mod config;
mod fixtures;
mod frozen;
mod fuzz_seeds;
mod generate;
mod git_corpus;
mod inventory;
mod native_assets;
mod report;
mod session;
mod source;
mod support;
mod traceability;
mod vet_inventory;

pub(crate) use archive_fuzz_seeds::generate_archive_fuzz_seeds;
pub(crate) use frozen::check_frozen_evidence;
pub(crate) use fuzz_seeds::generate_regex_fuzz_seeds;
pub(crate) use generate::run as run_generate;
pub(crate) use native_assets::generate as generate_native_pack_identity;
#[cfg(test)]
pub(crate) use support::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};
pub(crate) use support::{command_output, command_status_with_timeout, sha256_file};
pub(crate) use support::{sha256_bytes, terminate_process_tree};
pub(crate) use traceability::api::{
    check_api_dispositions, self_test_api_dispositions, summarize_api_dispositions,
    write_api_dispositions,
};
pub(crate) use vet_inventory::{check_vet_inventory, write_vet_inventory};
