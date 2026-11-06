//! Dispatch for maintained Rust-owned repository generators.
use std::path::Path;

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    match args {
        [target] if target == "native-pack-identity" => super::generate_native_pack_identity(root, false),
        [target, flag] if target == "native-pack-identity" && flag == "--check" => super::generate_native_pack_identity(root, true),
        [target, output] if target == "archive-fuzz-seeds" => super::generate_archive_fuzz_seeds(root, Path::new(output), false).map(|_| ()),
        [target, output, flag] if target == "archive-fuzz-seeds" && flag == "--check" => super::generate_archive_fuzz_seeds(root, Path::new(output), true).map(|_| ()),
        [target, requests, output] if target == "regex-fuzz-seeds" => super::generate_regex_fuzz_seeds(Path::new(requests), Path::new(output)).map(|_| ()),
        [target] if target == "vet-inventory" => super::write_vet_inventory(root, &root.join("supply-chain/inventory-v1.json")),
        [target, flag] if target == "vet-inventory" && flag == "--check" => super::check_vet_inventory(root, &root.join("supply-chain/inventory-v1.json")),
        [target, flag, output] if target == "vet-inventory" && flag == "--output" => super::write_vet_inventory(root, Path::new(output)),
        [target] if target == "api-dispositions" => super::write_api_dispositions(root, &root.join("compat/api-dispositions-v1.jsonl")).map(|summary| print!("{summary}")),
        [target, flag] if target == "api-dispositions" && flag == "--check" => super::check_api_dispositions(root, &root.join("compat/api-dispositions-v1.jsonl")).map(|summary| print!("{summary}")),
        [target, flag] if target == "api-dispositions" && flag == "--self-test" => super::self_test_api_dispositions(root, &root.join("compat/api-dispositions-v1.jsonl")).map(|summary| print!("{summary}")),
        [target, flag] if target == "api-dispositions" && flag == "--summary" => super::summarize_api_dispositions(root, &root.join("compat/api-dispositions-v1.jsonl")).map(|summary| print!("{summary}")),
        [target, flag, output] if target == "api-dispositions" && flag == "--output" => super::write_api_dispositions(root, Path::new(output)).map(|summary| print!("{summary}")),
        _ => Err("usage: cargo xtask generate <api-dispositions [--check|--self-test|--summary|--output PATH]|native-pack-identity [--check]|archive-fuzz-seeds OUTPUT [--check]|regex-fuzz-seeds REQUESTS OUTPUT|vet-inventory [--check|--output PATH]>; live Go generation is retired; use regression-check for frozen evidence".into()),
    }
}
