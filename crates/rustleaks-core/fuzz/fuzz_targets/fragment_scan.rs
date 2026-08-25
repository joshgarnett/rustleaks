#![forbid(unsafe_code)]
#![no_main]

use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::session::sort_findings_canonical;
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanOutcome};
use libfuzzer_sys::fuzz_target;

const MAX_ARBITRARY_BYTES: usize = 8 * 1024;
const DECODE_SUFFIX: &[u8] =
    b"\n7365637265743d46555a5a544f4b454e\nc2VjcmV0PUZVWlpUT0tFTg==\nsecret%3DFUZZTOKEN\n";

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let config = ConfigLoader::new()
            .load_toml(
                r#"
                [[rules]]
                id = "fuzz-decoded-token"
                description = "bounded decoder and location fuzz rule"
                regex = '''secret=([A-Z0-9]{4,32})'''
                keywords = ["secret"]

                [[rules]]
                id = "fuzz-path"
                description = "bounded path fuzz rule"
                path = '''(?i)fuzz[\\/]input'''
                "#,
            )
            .expect("the fixed fuzz configuration is valid");
        Engine::builder(config)
            .build()
            .expect("the fixed fuzz engine builds")
    })
}

fuzz_target!(|data: &[u8]| {
    let arbitrary = &data[..data.len().min(MAX_ARBITRARY_BYTES)];
    let control = arbitrary.first().copied().unwrap_or_default();
    let mut content = Vec::with_capacity(arbitrary.len() + DECODE_SUFFIX.len());
    content.extend_from_slice(arbitrary);
    content.extend_from_slice(DECODE_SUFFIX);

    let path = if control & 1 == 0 {
        b"fuzz/input.bin".as_slice()
    } else {
        b"nested/fuzz\\input.bin".as_slice()
    };
    let start_line = usize::from(control >> 1);
    let fragment = Fragment::builder(content)
        .file_path(path)
        .windows_file_path(b"C:\\fuzz\\input.bin".as_slice())
        .start_line(start_line)
        .build();
    let options = ScanOptions::builder()
        .max_decode_depth(2)
        .max_target_bytes(Some(MAX_ARBITRARY_BYTES + DECODE_SUFFIX.len()))
        .redaction_percent(usize::from(control % 101))
        .honor_gitleaks_allow(control & 2 == 0)
        .build();

    let scan = || -> ScanOutcome {
        let polls = AtomicUsize::new(0);
        let cancel_after = usize::from(control >> 2).saturating_add(1);
        let cancellation = || polls.fetch_add(1, Ordering::Relaxed) >= cancel_after;
        let control = ScanControl::cancellable(&cancellation).with_budget(
            ScanBudget::unlimited()
                .max_decoded_bytes(32 * 1024)
                .max_work_units(4 * 1024)
                .max_finding_records(64),
        );
        engine().scan_fragment_controlled(&fragment, &options, &control)
    };

    let first = scan();
    let second = scan();
    assert_eq!(first, second, "the immutable engine must be deterministic");
    let mut canonical = first.findings().to_vec();
    sort_findings_canonical(&mut canonical);

    for finding in &canonical {
        let location = finding.location();
        assert!(location.end_line() >= location.start_line());
        if location.end_line() == location.start_line() {
            assert!(location.end_column() >= location.start_column());
        }
        if let Some(match_range) = finding.match_range().exact() {
            assert!(match_range.end() <= fragment.content().len());
        }
        if let Some(secret_range) = finding.secret_range().exact() {
            let match_range = finding
                .match_range()
                .exact()
                .expect("an exact secret range requires an exact match range");
            assert!(secret_range.start() >= match_range.start());
            assert!(secret_range.end() <= match_range.end());
        }
    }
});
