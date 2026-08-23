#![cfg(all(
    feature = "brotli",
    feature = "bzip2",
    feature = "deflate",
    feature = "lz4",
    feature = "zstd"
))]

use std::{fs::File, path::PathBuf};

use rustleaks_sevenz::{ArchiveReader, Password};

const FIXTURES: &[(&str, usize)] = &[
    ("copy.7z", 10),
    ("delta.7z", 10),
    ("lzma.7z", 10),
    ("deflate.7z", 10),
    ("bzip2.7z", 10),
    ("brotli.7z", 10),
    ("lz4.7z", 10),
    ("zstd.7z", 10),
    ("bcj.7z", 1),
    ("bcj2.7z", 10),
    ("arm.7z", 1),
    ("ppc.7z", 1),
    ("sparc.7z", 1),
];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/fixtures/oracle/bodgit-sevenzip-v1.6.1")
        .join(name)
}

#[test]
fn decodes_every_non_encrypted_pinned_go_method_fixture() {
    for &(name, expected_files) in FIXTURES {
        let mut archive = ArchiveReader::new_with_memory_limit_kb(
            File::open(fixture(name)).unwrap(),
            Password::empty(),
            64 * 1024,
        )
        .unwrap_or_else(|error| panic!("failed to open {name}: {error}"));
        archive.set_thread_count(1);
        let mut files = 0;
        let mut bytes = 0_u64;
        let mut read_sizes = Vec::new();
        archive
            .for_each_entries(|entry, reader| {
                let mut sink = Vec::new();
                let mut buffer = [0; 100_000];
                loop {
                    let count = reader.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    read_sizes.push(count);
                    sink.extend_from_slice(&buffer[..count]);
                }
                if entry.has_stream {
                    files += 1;
                    bytes += sink.len() as u64;
                }
                Ok(true)
            })
            .unwrap_or_else(|error| panic!("failed to decode {name}: {error}"));
        assert_eq!(files, expected_files, "unexpected member count for {name}");
        assert!(bytes > 0, "empty decoded archive {name}");
        if name == "deflate.7z" {
            assert_eq!(&read_sizes[read_sizes.len() - 2..], &[701, 3_286]);
        }
    }
}
