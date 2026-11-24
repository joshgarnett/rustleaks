//! Truncated and corrupted archives and compressed streams, and directory
//! walks that meet unreadable, vanishing or broken entries. None of these may
//! panic or end the scan, and later inputs are still scanned.
#![cfg(feature = "archives")]
#![forbid(unsafe_code)]

// The shared fuzz support also serves the fuzz targets; this file uses part of it.
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../fuzz/support/archive_frame.rs"]
mod archive_frame;
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../fuzz/support/archive_harness.rs"]
mod archive_harness;
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../fuzz/support/archive_seeds.rs"]
mod archive_seeds;
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
#[path = "../../rustleaks-core/tests/support/fuzz_profile.rs"]
mod fuzz_profile;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use archive_frame::{FORMAT_NAMES, encode};
use archive_harness::exercise;
use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Finding, Fragment, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_sources::{
    ArchiveOptions, CancellationToken, DirectoryOptions, DirectorySource, Source, SourceControl,
    SourceEvent, SourceIssueKind, SourceRunner, SourceTermination,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustleaks-resilience-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temporary tree");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        #[cfg(unix)]
        restore_permissions(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn restore_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && !metadata.file_type().is_symlink()
    {
        let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        if metadata.is_dir()
            && let Ok(entries) = fs::read_dir(path)
        {
            for entry in entries.flatten() {
                restore_permissions(&entry.path());
            }
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs one archive input through the shared fuzz harness and returns
/// whether the visit finished normally and how many issues it reported.
fn visit_archive(format: u8, payload: &[u8]) -> (bool, usize) {
    let mut issues = 0;
    let observation = exercise(&encode(format, 0, payload), |event| match event {
        SourceEvent::Fragment { issue, .. } => issues += usize::from(issue.is_some()),
        SourceEvent::Issue(_) => issues += 1,
        _ => {}
    })
    .expect("valid frame");
    (
        matches!(observation.result, Ok(SourceControl::Continue)),
        issues,
    )
}

/// Formats whose end carries a trailer, an end mark, a last-block flag or a
/// central index, so that every proper prefix of a valid input is detectably
/// incomplete. TAR (block-aligned prefixes are valid), RAR (the end block is
/// optional) and Snappy and `MinLZ` framing (no end marker) are excluded.
const INTEGRITY_FORMATS: &[&str] = &[
    "input.lz4",
    "input.zip",
    "input.7z",
    "input.tar.gz",
    "input.gz",
    "input.tar.xz",
    "input.xz",
    "input.bz2",
    "input.br",
    "input.zst",
    "input.zz",
    "input.lz",
];

#[test]
fn every_prefix_and_bit_flip_of_every_archive_seed_is_recoverable() {
    let seeds = archive_seeds::cases(&root()).expect("reviewed seeds");
    let mut formats = Vec::new();
    for seed in &seeds {
        let name = FORMAT_NAMES[usize::from(seed.format)];
        formats.push(name);
        let length = seed.payload.len();
        for cut in 0..length {
            let (finished, issues) = visit_archive(seed.format, &seed.payload[..cut]);
            assert!(finished, "{} cut at {cut}", seed.id);
            if cut > 0 && INTEGRITY_FORMATS.contains(&name) {
                assert!(issues > 0, "{} cut at {cut} has no issue", seed.id);
            }
        }
        for index in 0..length {
            let mut payload = seed.payload.clone();
            payload[index] ^= 1 << (index % 8);
            let (finished, _) = visit_archive(seed.format, &payload);
            assert!(finished, "{} flip at {index}", seed.id);
        }
    }
    formats.sort_unstable();
    formats.dedup();
    assert_eq!(formats.len(), FORMAT_NAMES.len());
}

fn engine() -> Engine {
    Engine::builder(
        ConfigLoader::new()
            .load_toml("[[rules]]\nid = 'planted'\nregex = '''PLANTED_[A-Z0-9]{20}'''\n")
            .unwrap(),
    )
    .build()
    .unwrap()
}

const SECRET: &str = "PLANTED_Q7M2Z9V4L1C8R5S0N6B3";

fn run(source: &mut dyn Source) -> (Vec<Finding>, Vec<SourceIssueKind>) {
    let outcome = SourceRunner::new(1, 1).unwrap().run(
        source,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &CancellationToken::new(),
    );
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    (
        outcome.findings().to_vec(),
        outcome
            .issues()
            .iter()
            .map(rustleaks_sources::SourceIssue::kind)
            .collect(),
    )
}

fn found_paths(findings: &[Finding]) -> Vec<String> {
    let mut paths = findings
        .iter()
        .map(|finding| {
            assert_eq!(finding.secret().as_bytes(), SECRET.as_bytes());
            let path = String::from_utf8_lossy(finding.file().as_bytes()).into_owned();
            path.rsplit(['/', '\\']).next().unwrap().to_owned()
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

#[test]
fn a_directory_of_broken_archives_still_scans_the_files_after_them() {
    let tree = TempTree::new("broken-archives");
    let seeds = archive_seeds::cases(&root()).expect("reviewed seeds");
    let mut detectable = 0;
    for (index, seed) in seeds.iter().enumerate() {
        let name = FORMAT_NAMES[usize::from(seed.format)];
        let extension = name.strip_prefix("input").unwrap();
        let half = &seed.payload[..seed.payload.len() / 2];
        fs::write(tree.path().join(format!("a{index:02}{extension}")), half).unwrap();
        detectable += usize::from(INTEGRITY_FORMATS.contains(&name));
    }
    fs::write(tree.path().join("z.txt"), format!("value = {SECRET}\n")).unwrap();
    let options = DirectoryOptions::default().archives(ArchiveOptions::default());
    let (findings, issues) = run(&mut DirectorySource::with_options(tree.path(), options));
    assert_eq!(found_paths(&findings), ["z.txt"]);
    assert!(issues.len() >= detectable, "{issues:?}");
}

fn collect(source: &mut dyn Source) -> (Vec<Fragment>, Vec<SourceIssueKind>) {
    let mut fragments = Vec::new();
    let mut issues = Vec::new();
    source
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Fragment { fragment, issue } => {
                    fragments.push(*fragment);
                    issues.extend(issue.map(|issue| issue.kind()));
                }
                SourceEvent::Issue(issue) => issues.push(issue.kind()),
                _ => panic!("unexpected source event"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("the walk finishes");
    (fragments, issues)
}

fn file_names(fragments: &[Fragment]) -> Vec<String> {
    fragments
        .iter()
        .map(|fragment| {
            let path = String::from_utf8_lossy(fragment.file_path().as_bytes()).into_owned();
            path.rsplit(['/', '\\']).next().unwrap().to_owned()
        })
        .collect()
}

#[test]
fn entries_that_vanish_during_the_walk_are_reported_and_skipped() {
    let tree = TempTree::new("vanishing");
    fs::write(tree.path().join("a.txt"), "first\n").unwrap();
    fs::create_dir(tree.path().join("b")).unwrap();
    fs::write(tree.path().join("b").join("inner.txt"), "inner\n").unwrap();
    fs::write(tree.path().join("c.txt"), "third\n").unwrap();
    fs::write(tree.path().join("d.txt"), "fourth\n").unwrap();
    let directory = tree.path().join("b");
    let file = tree.path().join("c.txt");
    let mut fragments = Vec::new();
    let mut issues = Vec::new();
    // The walk is lexical. Remove `b` and `c.txt` once `a.txt` is emitted.
    DirectorySource::new(tree.path())
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Fragment { fragment, issue } => {
                    if fragment.file_path().as_bytes().ends_with(b"a.txt") {
                        fs::remove_dir_all(&directory).unwrap();
                        fs::remove_file(&file).unwrap();
                    }
                    fragments.push(*fragment);
                    issues.extend(issue.map(|issue| issue.kind()));
                }
                SourceEvent::Issue(issue) => issues.push(issue.kind()),
                _ => panic!("unexpected source event"),
            }
            Ok(SourceControl::Continue)
        })
        .expect("the walk finishes");
    assert_eq!(file_names(&fragments), ["a.txt", "d.txt"]);
    assert_eq!(
        issues,
        [SourceIssueKind::NotFound, SourceIssueKind::NotFound]
    );
}

#[cfg(unix)]
fn symlink(target: &Path, alias: &Path) {
    std::os::unix::fs::symlink(target, alias).unwrap();
}

#[cfg(unix)]
#[test]
fn a_broken_link_inside_the_walk_does_not_stop_later_files() {
    let tree = TempTree::new("broken-link");
    fs::write(tree.path().join("a.txt"), format!("{SECRET}\n")).unwrap();
    symlink(&tree.path().join("missing"), &tree.path().join("b-link"));
    let outside = TempTree::new("broken-link-loop");
    symlink(&outside.path().join("c-loop"), &tree.path().join("c-loop"));
    symlink(&tree.path().join("c-loop"), &outside.path().join("c-loop"));
    fs::write(tree.path().join("d.txt"), format!("{SECRET}\n")).unwrap();

    // Without following links, links are skipped without an issue.
    let (fragments, issues) = collect(&mut DirectorySource::new(tree.path()));
    assert_eq!(file_names(&fragments), ["a.txt", "d.txt"]);
    assert!(issues.is_empty(), "{issues:?}");

    // When following links, each broken link is one issue, in walk order.
    let options = DirectoryOptions::default().follow_symlinks(true);
    let (findings, issues) = run(&mut DirectorySource::with_options(tree.path(), options));
    assert_eq!(found_paths(&findings), ["a.txt", "d.txt"]);
    assert_eq!(
        issues,
        [
            SourceIssueKind::DanglingSymlink,
            SourceIssueKind::SymlinkLoop
        ]
    );
}

#[cfg(unix)]
fn privileged(path: &Path) -> bool {
    // A privileged user can read a mode 000 entry; the test then only
    // checks that the scan finishes.
    fs::read_dir(path).is_ok() || fs::read(path).is_ok()
}

#[cfg(unix)]
#[test]
fn unreadable_folders_and_files_are_reported_and_skipped() {
    use std::os::unix::fs::PermissionsExt as _;
    let tree = TempTree::new("unreadable");
    fs::write(tree.path().join("a.txt"), format!("{SECRET}\n")).unwrap();
    fs::create_dir(tree.path().join("b-locked")).unwrap();
    fs::write(
        tree.path().join("b-locked").join("inner.txt"),
        format!("{SECRET}\n"),
    )
    .unwrap();
    fs::write(tree.path().join("c-locked.txt"), format!("{SECRET}\n")).unwrap();
    fs::write(tree.path().join("d.txt"), format!("{SECRET}\n")).unwrap();
    for locked in ["b-locked", "c-locked.txt"] {
        fs::set_permissions(tree.path().join(locked), fs::Permissions::from_mode(0o000)).unwrap();
    }
    let (findings, issues) = run(&mut DirectorySource::new(tree.path()));
    if privileged(&tree.path().join("b-locked")) {
        assert_eq!(findings.len(), 4);
        return;
    }
    assert_eq!(found_paths(&findings), ["a.txt", "d.txt"]);
    assert_eq!(
        issues,
        [
            SourceIssueKind::PermissionDenied,
            SourceIssueKind::PermissionDenied
        ]
    );
}
