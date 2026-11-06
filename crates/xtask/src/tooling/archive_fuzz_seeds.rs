//! Reproducible archive fuzz frames derived from reviewed fixture inputs.

use std::fs;
use std::path::Path;

use serde_json::json;

use super::artifacts::GeneratedTree;
use super::support::{sha256_bytes, sha256_file};

#[allow(dead_code)] // Parsing and controls are used by the fuzz target and source tests.
#[path = "../../../rustleaks-sources/fuzz/support/archive_frame.rs"]
mod archive_frame;
#[path = "../../../rustleaks-sources/fuzz/support/archive_seeds.rs"]
mod archive_seeds;

pub(crate) fn generate_archive_fuzz_seeds(
    root: &Path,
    output: &Path,
    check: bool,
) -> Result<usize, String> {
    let mut tree = GeneratedTree::default();
    let mut records = Vec::new();
    for seed in archive_seeds::cases(root)? {
        for (mode, control) in [("normal", 0), ("pre-cancel", 1), ("cancel", 2), ("stop", 4)] {
            let frame = archive_frame::encode(seed.format, control, &seed.payload);
            let name = format!("corpus/{}-{mode}.bin", seed.id);
            records.push(json!({
                "file": name,
                "frame_version": 1,
                "format": archive_frame::FORMAT_NAMES[usize::from(seed.format)],
                "control": control,
                "bytes": frame.len(),
                "sha256": sha256_bytes(&frame),
                "payload_sha256": sha256_bytes(&seed.payload),
                "origin": seed.origin,
                "expected_fragment_sha256": seed.expected.iter().map(|bytes| sha256_bytes(bytes)).collect::<Vec<_>>(),
            }));
            tree.insert(name, frame)?;
        }
    }
    for name in ["tar-header.txt", "zip-header.txt"] {
        let relative = format!("crates/rustleaks-sources/fuzz/seeds/archive/{name}");
        let legacy = fs::read(root.join(&relative))
            .map_err(|error| format!("cannot read legacy archive seed {name}: {error}"))?;
        let migrated = archive_frame::migrate_legacy(&legacy)
            .ok_or_else(|| format!("legacy archive seed {name} exceeds framed capacity"))?;
        let output_name = format!("corpus/legacy-{name}.bin");
        records.push(json!({
            "file": output_name,
            "frame_version": 1,
            "origin": relative,
            "source_sha256": sha256_bytes(&legacy),
            "sha256": sha256_bytes(&migrated),
            "bytes": migrated.len(),
            "migration": "legacy selector and callback bits preserved; input bytes unchanged",
        }));
        tree.insert(output_name, migrated)?;
    }
    let count = records.len();
    let mut input_hashes = serde_json::Map::new();
    for input in [
        "crates/rustleaks-sources/fuzz/support/archive_frame.rs",
        "crates/rustleaks-sources/fuzz/support/archive_seeds.rs",
        "crates/rustleaks-sources/fuzz/support/sevenz_seeds.rs",
        "crates/xtask/src/tooling/archive_fuzz_seeds.rs",
        "compat/source-corpus/requests-v1.jsonl",
        "compat/upstream-revision.txt",
    ] {
        input_hashes.insert(input.to_owned(), json!(sha256_file(&root.join(input))?));
    }
    let manifest = json!({
        "schema_version": 1,
        "frame_version": 1,
        "seed_count": count,
        "maximum_input_bytes": archive_frame::MAX_INPUT_BYTES,
        "inputs": input_hashes,
        "seeds": records,
        "scope": "synthetic and reviewed fixtures; 7z COPY, single-coder Deflate and LZ4; other coder graphs require separate evidence",
    });
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("cannot encode archive seed manifest: {error}"))?;
    manifest_bytes.push(b'\n');
    tree.insert("manifest.json", manifest_bytes)?;
    for (input, output) in [
        ("NOTICE", "licenses/NOTICE"),
        ("LICENSE", "licenses/LICENSE"),
        (
            "compat/fixtures/oracle/rar-test-files-16b785c/LICENSE.cc0",
            "licenses/LICENSE.rar-test-files.cc0",
        ),
    ] {
        tree.insert(
            output,
            fs::read(root.join(input))
                .map_err(|error| format!("cannot retain archive seed license {input}: {error}"))?,
        )?;
    }
    tree.write_or_check(output, check)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{archive_frame, generate_archive_fuzz_seeds};
    use crate::tooling::support::TempDir;

    #[test]
    fn generated_seed_tree_is_exact_and_versioned() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary = TempDir::new("archive-seed-generation").unwrap();
        let output = temporary.path.join("output");
        assert_eq!(
            generate_archive_fuzz_seeds(&root, &output, false).unwrap(),
            90
        );
        generate_archive_fuzz_seeds(&root, &output, true).unwrap();
        generate_archive_fuzz_seeds(&root, &output, false).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["seed_count"], 90);
        for entry in fs::read_dir(output.join("corpus")).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(bytes.len() <= archive_frame::MAX_INPUT_BYTES);
            assert!(archive_frame::Frame::decode(&bytes).is_some());
        }
        fs::write(output.join("corpus/tar-two-members-normal.bin"), b"changed").unwrap();
        assert!(generate_archive_fuzz_seeds(&root, &output, true).is_err());
        generate_archive_fuzz_seeds(&root, &output, false).unwrap();
        fs::write(output.join("unexpected"), b"stale").unwrap();
        assert!(generate_archive_fuzz_seeds(&root, &output, false).is_err());
    }
}
