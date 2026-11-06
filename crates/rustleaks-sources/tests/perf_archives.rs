//! Opt-in archive expansion driver. Normal test runs exercise only its verifier.
#![cfg(feature = "archives")]

#[allow(
    dead_code,
    reason = "shared fuzz framing has entry points unused by this driver"
)]
#[path = "../fuzz/support/archive_frame.rs"]
mod archive_frame;
#[path = "../fuzz/support/archive_seeds.rs"]
mod archive_seeds;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustleaks_core::model::Fragment;
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, ArchiveSource, CallbackError, CancellationToken, FileOptions,
    Source, SourceControl, SourceEvent,
};
use serde_json::json;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const MEMBER_BYTES: usize = 4 * 1024 * 1024;
const TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 32;
const CHUNK_BYTES: usize = MEMBER_BYTES;
const CONFIG: &str = "archive-source-v1;depth=2;entries=32;member=4194304;total=16777216;spool=4194304;chunk=4194304;limit-issues=true";
// Keep the representative matrix stable when the shared fuzz corpus expands.
const FUZZ_FIXTURE_IDS: &[&str] = &[
    "tar-two-members",
    "zip",
    "7z-stored",
    "rar5-stored",
    "tar-gzip-two-members",
    "gzip",
    "tar-xz-two-members",
    "xz",
    "bzip2",
    "brotli",
    "lz4",
    "snappy",
    "minlz",
    "zstd",
    "zlib",
    "lzip",
    "s2",
    "rar5-compressed",
    "rar2-compressed",
    "rar3-compressed",
];

fn root() -> PathBuf {
    std::env::var_os("RUSTLEAKS_PERF_ROOT").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        PathBuf::from,
    )
}

fn fingerprint(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{hash:016x}")
}

fn select_fuzz_seeds(candidates: Vec<archive_seeds::Seed>) -> Result<Vec<archive_seeds::Seed>> {
    let mut by_id = BTreeMap::new();
    for seed in candidates {
        let id = seed.id;
        if by_id.insert(id, seed).is_some() {
            return Err(format!("duplicate archive fixture: {id}").into());
        }
    }
    FUZZ_FIXTURE_IDS
        .iter()
        .map(|id| {
            by_id
                .remove(id)
                .ok_or_else(|| format!("missing representative archive fixture: {id}").into())
        })
        .collect()
}

fn seeds(root: &Path) -> Result<Vec<archive_seeds::Seed>> {
    let mut seeds = select_fuzz_seeds(archive_seeds::cases(root)?)?;
    let archives = root.join("compat/fixtures/upstream/testdata/archives");
    let expected = [".env.prod", ".gitleaksignore", "api.go", "main.go"]
        .into_iter()
        .map(|name| fs::read(archives.join("files").join(name)))
        .collect::<std::io::Result<Vec<_>>>()?;
    seeds.push(archive_seeds::Seed {
        id: "7z-compressed",
        format: 2,
        payload: fs::read(archives.join("files.7z"))?,
        expected,
        origin: "compat/fixtures/upstream/testdata/archives/files.7z",
    });
    seeds.push(archive_seeds::Seed {
        id: "gzip-compressed",
        format: 5,
        payload: fs::read(archives.join("files/main.go.gz"))?,
        expected: vec![fs::read(archives.join("files/main.go"))?],
        origin: "compat/fixtures/upstream/testdata/archives/files/main.go.gz",
    });
    seeds.push(archive_seeds::Seed {
        id: "zlib-compressed",
        format: 14,
        payload: miniz_oxide::deflate::compress_to_vec_zlib(archive_seeds::CODEC_PAYLOAD, 6),
        expected: vec![archive_seeds::CODEC_PAYLOAD.to_vec()],
        origin: "synthetic:zlib-miniz-level6-v1",
    });
    Ok(seeds)
}

fn expected(seed: &archive_seeds::Seed) -> Result<Vec<Fragment>> {
    let outer = archive_frame::FORMAT_NAMES[usize::from(seed.format)];
    let paths = match seed.id {
        "tar-two-members" | "tar-gzip-two-members" | "tar-xz-two-members" => {
            vec![format!("{outer}!first.txt"), format!("{outer}!second.txt")]
        }
        "zip" | "7z-compressed" => [".env.prod", ".gitleaksignore", "api.go", "main.go"]
            .map(|name| format!("{outer}!files/{name}"))
            .to_vec(),
        "7z-stored" | "rar5-stored" => vec![format!("{outer}!value.txt")],
        "rar5-compressed" => vec![format!("{outer}!compressed.txt")],
        "rar2-compressed" => vec![format!("{outer}!hello.txt")],
        "rar3-compressed" => vec![format!("{outer}!testfile.txt")],
        _ => vec![outer.to_owned()],
    };
    if paths.len() != seed.expected.len() {
        return Err("archive expected member count mismatch".into());
    }
    let mut fragments = paths
        .into_iter()
        .zip(&seed.expected)
        .map(|(path, content)| {
            let mut builder = Fragment::builder(content.clone())
                .file_path(path.clone())
                .start_line(1);
            if cfg!(windows) {
                // Completed outer segments stay normalized; the current member
                // retains its native spelling in the Windows metadata field.
                let native_path = path.rsplit_once('!').map_or_else(
                    || path.clone(),
                    |(outer, member)| format!("{outer}!{}", member.replace('/', "\\")),
                );
                builder = builder.windows_file_path(native_path);
            }
            builder.build()
        })
        .collect::<Vec<_>>();
    fragments.sort_by(|left, right| left.file_path().cmp(right.file_path()));
    Ok(fragments)
}

fn source(seed: &archive_seeds::Seed) -> Result<ArchiveSource> {
    Ok(ArchiveSource::with_options(
        Cursor::new(seed.payload.clone()),
        archive_frame::FORMAT_NAMES[usize::from(seed.format)],
        FileOptions::new(CHUNK_BYTES)?,
        ArchiveOptions::new(ArchiveLimits::new(
            2,
            MAX_ENTRIES,
            MEMBER_BYTES,
            TOTAL_BYTES,
            MEMBER_BYTES,
        )?)
        .emit_limit_issues(true),
    ))
}

fn collect(source: &mut ArchiveSource) -> Result<Vec<Fragment>> {
    let mut fragments = Vec::new();
    let control = source.visit(&CancellationToken::new(), &mut |event| {
        match event {
            SourceEvent::Fragment {
                fragment,
                issue: None,
            } => fragments.push(*fragment),
            _ => return Err(CallbackError::new("archive phase emitted an issue")),
        }
        Ok(SourceControl::Continue)
    })?;
    if control != SourceControl::Continue {
        return Err("archive phase stopped".into());
    }
    Ok(fragments)
}

fn verify(actual: &mut [Fragment], expected: &[Fragment]) -> Result<()> {
    actual.sort_by(|left, right| left.file_path().cmp(right.file_path()));
    if actual != expected {
        return Err("archive phase exact member content, location, or metadata mismatch".into());
    }
    Ok(())
}

#[test]
fn representative_archive_fixtures_match_exact_expected_outcomes() -> Result<()> {
    let seeds = seeds(&root())?;
    assert_eq!(seeds.len(), 23);
    for seed in seeds {
        let expected = expected(&seed)?;
        let mut source = source(&seed)?;
        let mut actual = collect(&mut source)?;
        verify(&mut actual, &expected).map_err(|error| format!("{}: {error}", seed.id))?;
        assert!(!seed.payload.is_empty(), "empty compressed fixture");
        assert!(!actual.is_empty(), "fixture emitted no members");
    }
    Ok(())
}

#[test]
fn archive_fixture_selection_preserves_order_and_rejects_missing_or_duplicate_ids() -> Result<()> {
    let seed = |id| archive_seeds::Seed {
        id,
        format: 0,
        payload: Vec::new(),
        expected: Vec::new(),
        origin: "synthetic:selection-control",
    };
    let candidates = || {
        FUZZ_FIXTURE_IDS
            .iter()
            .copied()
            .map(seed)
            .collect::<Vec<_>>()
    };
    let mut extended = candidates();
    extended.push(seed("additional-fuzz-only-case"));
    extended.reverse();
    let selected = select_fuzz_seeds(extended)?;
    assert_eq!(
        selected.iter().map(|seed| seed.id).collect::<Vec<_>>(),
        FUZZ_FIXTURE_IDS
    );
    let mut missing = candidates();
    missing.pop();
    assert!(select_fuzz_seeds(missing).is_err());
    let mut duplicate = candidates();
    duplicate.push(seed(FUZZ_FIXTURE_IDS[0]));
    assert!(select_fuzz_seeds(duplicate).is_err());
    Ok(())
}

#[test]
#[ignore = "on-demand performance driver; invoke through just perf-representative"]
fn representative_archive_driver() -> Result<()> {
    let iterations: usize = std::env::var("RUSTLEAKS_PERF_ITERATIONS")?.parse()?;
    if !(1..=1_000).contains(&iterations) {
        return Err("archive iterations outside 1..=1000".into());
    }
    for seed in seeds(&root())? {
        let expected = expected(&seed)?;
        let expanded: usize = expected
            .iter()
            .map(|fragment| fragment.content().len())
            .sum();
        if expanded == 0 || expected.is_empty() {
            return Err("empty archive benchmark fixture".into());
        }
        let serialized = serde_json::to_vec(&expected)?;
        let mut elapsed = Duration::ZERO;
        for _ in 0..iterations {
            // Copying compressed fixture bytes and constructing options are setup.
            let mut source = source(&seed)?;
            let start = Instant::now();
            let outcome = black_box(collect(&mut source));
            elapsed += start.elapsed();
            let mut actual = outcome?;
            verify(&mut actual, &expected).map_err(|error| format!("{}: {error}", seed.id))?;
            // The one iteration's result and archive state drop outside timing.
        }
        let row = json!({
            "phase": format!("archive-expand/{}", seed.id), "iterations": iterations,
            "elapsed_ns": u64::try_from(elapsed.as_nanos())?, "logical_unit": "expanded-bytes",
            "logical_units_per_iteration": expanded, "input_fnv1a64": fingerprint(&seed.payload),
            "config_fnv1a64": fingerprint(CONFIG.as_bytes()), "outcome_fnv1a64": fingerprint(&serialized),
            "findings": 0, "errors": 0, "complete": true, "scope": "representative-v1-operation-only",
            "counts": {"compressed_bytes": seed.payload.len(), "expanded_bytes": expanded, "members": expected.len(), "fragments": expected.len(), "origin": seed.origin,
                "maximum_entries": MAX_ENTRIES, "maximum_member_bytes": MEMBER_BYTES, "maximum_total_bytes": TOTAL_BYTES, "chunk_bytes": CHUNK_BYTES,
                "scope": "in-memory archive identification, expansion, fragment emission; no detection or process startup", "method_coverage": "one selected fixture; not every method", "returned_result_destruction": "outside-timer", "internal_temporary_destruction": "inside-timer", "comparison": "exact path-content multiset; member emission order is not a public contract"}
        });
        println!("RUSTLEAKS_PERF_ARCHIVE_PHASE={row}");
    }
    Ok(())
}

#[test]
fn archive_verifier_rejects_skipped_clean_members() -> Result<()> {
    let expected = vec![
        Fragment::builder(b"clean input\n")
            .file_path("input.tar!clean.txt")
            .start_line(1)
            .build(),
    ];
    assert!(verify(&mut [], &expected).is_err());
    let mut wrong = vec![
        Fragment::builder(b"clean input\n")
            .file_path("wrong.txt")
            .start_line(1)
            .build(),
    ];
    assert!(verify(&mut wrong, &expected).is_err());
    verify(&mut expected.clone(), &expected)?;
    Ok(())
}
