//! Dispatch for `cargo xtask generate`.
use std::path::Path;

/// Generator targets accepted by [`run`]. The documentation command check
/// reads this list, and a unit test keeps it in step with the dispatch.
pub(crate) const GENERATE_TARGETS: &[&str] = &[
    "native-pack-identity",
    "archive-fuzz-seeds",
    "regex-fuzz-seeds",
    "vet-inventory",
];

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
        _ => Err("usage: cargo xtask generate <native-pack-identity [--check]|archive-fuzz-seeds OUTPUT [--check]|regex-fuzz-seeds REQUESTS OUTPUT|vet-inventory [--check|--output PATH]>".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn listed_targets_match_dispatch() {
        let source = include_str!("generate.rs");
        let start = source.find("pub(crate) fn run(").unwrap();
        let dispatch = &source[start..];
        let pattern = "target == \"";
        let dispatched = dispatch
            .match_indices(pattern)
            .filter_map(|(index, _)| dispatch[index + pattern.len()..].split_once('"'))
            .map(|(name, _)| name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            dispatched,
            super::GENERATE_TARGETS.iter().copied().collect()
        );
    }
}
