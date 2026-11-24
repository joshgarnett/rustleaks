//! Repository generators and shared helpers.

mod archive_fuzz_seeds;
mod artifacts;
#[cfg(test)]
mod cli_corpus;
mod fuzz_seeds;
mod generate;
mod native_assets;
mod native_coverage_assets;
mod support;
mod tokenizer_assets;
mod vet_inventory;

pub(crate) use archive_fuzz_seeds::generate_archive_fuzz_seeds;
pub(crate) use fuzz_seeds::generate_regex_fuzz_seeds;
pub(crate) use generate::{GENERATE_TARGETS, run as run_generate};
pub(crate) use native_assets::generate as generate_native_pack_identity;
pub(crate) use support::{
    ScopedTempDir, hex_lower, sha256_bytes, terminate_process_tree, wait_with_deadline,
};
#[cfg(test)]
pub(crate) use support::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};
pub(crate) use support::{command_output, command_status_with_timeout, sha256_file};
pub(crate) use vet_inventory::{check_vet_inventory, write_vet_inventory};
