//! Directory scans that read files on several threads give the same events,
//! in the same order, as scans that read every file on the walking thread.
//! The trees mix many tiny files, nested folders, large files, skipped and
//! unreadable files, symbolic links and archives. Expected findings come from
//! the planting plan, not from a scan.
#![cfg(feature = "archives")]
#![forbid(unsafe_code)]

#[path = "../fuzz/support/archive_frame.rs"]
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
mod archive_frame;
#[path = "../fuzz/support/archive_seeds.rs"]
#[allow(dead_code, reason = "shared fuzz support; this binary uses part of it")]
mod archive_seeds;

use std::fmt::Write as _;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use archive_seeds::synthetic_tar as tar;
use rustleaks_core::Engine;
use rustleaks_core::config::{CompiledConfig, ConfigLoader};
use rustleaks_core::model::{Finding, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, CallbackError, CancellationToken, DirectoryOptions,
    DirectorySource, FileOptions, Source, SourceControl, SourceError, SourceEvent, SourceIssue,
    SourceRunner, SourceTermination,
};

/// Reader thread counts compared with the serial walk, which uses 1.
const THREADS: &[usize] = &[1, 2, 3, 4, 8];

const CONFIG: &str = "[[rules]]\nid = 'planted'\nregex = '''PLANTED_[A-Z0-9]{20}'''\nkeywords = ['planted_']\n\n[allowlist]\npaths = ['''(^|/)skipped/''']\n";

/// Padding line of 60 bytes plus a newline, with no blank lines, so large
/// files split at the read-ahead limit.
const FILLER: &str = "filler text that holds no secret and only pads the file 0000";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustleaks-readers-{label}-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
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
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let mode = if metadata.is_dir() { 0o755 } else { 0o644 };
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    if metadata.is_dir()
        && let Ok(entries) = fs::read_dir(path)
    {
        for entry in entries.flatten() {
            restore_permissions(&entry.path());
        }
    }
}

/// A secret that the `planted` rule finds.
fn secret(number: usize) -> String {
    format!("PLANTED_{number:020}")
}

/// One expected finding: logical file path, start line and secret.
type Row = (String, usize, String);

/// Text of `lines` lines with a planted secret on each listed line.
fn planted(lines: usize, plants: &[(usize, String)]) -> String {
    let mut text = String::new();
    for line in 1..=lines {
        match plants.iter().find(|(planted, _)| *planted == line) {
            Some((_, value)) => {
                let _ = writeln!(text, "value = {value}");
            }
            None => {
                let _ = writeln!(text, "{FILLER}");
            }
        }
    }
    text
}

/// Builds the mixed tree under `scan/` and returns the findings that a
/// complete scan must report, before symbolic links.
fn plant(tree: &TempTree) -> Vec<Row> {
    let mut expected = Vec::new();
    let mut number = 0;
    for outer in 0..4 {
        for inner in 0..5 {
            for file in 0..30 {
                number += 1;
                let path = format!("scan/n{outer}/m{inner}/f{file:02}.txt");
                if number % 41 == 0 {
                    // About 330 KB, so three pieces. The secrets sit away from
                    // the piece boundaries near bytes 125,000 and 250,000.
                    let plants = [800, 3_000, 5_000]
                        .iter()
                        .enumerate()
                        .map(|(index, line)| (*line, secret(number * 10 + index)))
                        .collect::<Vec<_>>();
                    for (line, value) in &plants {
                        expected.push((path.clone(), *line, value.clone()));
                    }
                    tree.write(&path, planted(5_400, &plants));
                } else if number % 13 == 0 {
                    // Empty files are skipped without an event.
                    tree.write(&path, "");
                } else if number % 3 == 0 {
                    let line = number % 5 + 1;
                    let value = secret(number * 10);
                    expected.push((path.clone(), line, value.clone()));
                    tree.write(&path, planted(line, &[(line, value)]));
                } else {
                    tree.write(&path, format!("plain text {number}\n"));
                }
            }
        }
    }

    // Skipped by the path allowlist before any read.
    tree.write("scan/skipped/hidden.txt", format!("{}\n", secret(1)));
    // A binary file is skipped after its first read.
    tree.write(
        "scan/binary.wasm",
        [b"\0asm\x01\0\0\0".as_slice(), secret(2).as_bytes()].concat(),
    );
    // Above the size limit, so it gives a limit issue and is not read.
    tree.write("scan/oversize.txt", planted(17_000, &[(1, secret(3))]));

    tree.write(
        "scan/bundle.tar",
        tar(&[
            ("a.txt", format!("{}\n", secret(4)).as_bytes()),
            ("sub/b.txt", format!("x\nx\n{}\n", secret(5)).as_bytes()),
        ]),
    );
    expected.push(("scan/bundle.tar!a.txt".to_owned(), 1, secret(4)));
    expected.push(("scan/bundle.tar!sub/b.txt".to_owned(), 3, secret(5)));
    let inner = tar(&[("c.txt", format!("x\n{}\n", secret(6)).as_bytes())]);
    tree.write("scan/nested.tar", tar(&[("inner.tar", &inner)]));
    expected.push(("scan/nested.tar!inner.tar!c.txt".to_owned(), 2, secret(6)));
    // Deeper than the archive depth limit, and a damaged gzip stream. Each
    // gives an issue.
    let deeper = tar(&[("deeper.tar", &tar(&[("d.txt", b"x\n")]))]);
    tree.write("scan/deep.tar", tar(&[("inner.tar", &deeper)]));
    tree.write("scan/broken.gz", b"\x1f\x8bbad");
    tree.write("scan/zz-last.txt", format!("{}\n", secret(7)));
    expected.push(("scan/zz-last.txt".to_owned(), 1, secret(7)));
    expected
}

/// Adds symbolic links and unreadable entries. Returns whether the
/// unreadable entries are really unreadable, which is false for a
/// privileged user.
#[cfg(unix)]
fn plant_unix(tree: &TempTree) -> bool {
    use std::os::unix::fs::{PermissionsExt, symlink};
    tree.write("outside/target.txt", format!("{}\n", secret(8)));
    let scan = tree.path().join("scan");
    symlink("../../outside/target.txt", scan.join("n1/link.txt")).unwrap();
    symlink("missing.txt", scan.join("n2/dangling.txt")).unwrap();
    symlink("loop-b.txt", scan.join("n2/loop-a.txt")).unwrap();
    symlink("loop-a.txt", scan.join("n2/loop-b.txt")).unwrap();
    symlink("../n0", scan.join("n3/folder-link")).unwrap();
    tree.write("scan/n1/locked.txt", format!("{}\n", secret(9)));
    tree.write(
        "scan/n2/locked-folder/inside.txt",
        format!("{}\n", secret(10)),
    );
    fs::set_permissions(
        scan.join("n1/locked.txt"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    fs::set_permissions(
        scan.join("n2/locked-folder"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    fs::File::open(scan.join("n1/locked.txt")).is_err()
}

fn config() -> CompiledConfig {
    ConfigLoader::new().load_toml(CONFIG).unwrap()
}

/// Options as the command sets them: early path pruning, a logical root,
/// a size limit with issues, and archives two levels deep.
fn options(follow_symlinks: bool) -> DirectoryOptions {
    DirectoryOptions::default()
        .path_config(Arc::new(config()))
        .logical_root("scan")
        .follow_symlinks(follow_symlinks)
        .max_file_size(Some(1_000_000))
        .emit_limit_issues(true)
        .archives(
            ArchiveOptions::new(ArchiveLimits::new(2, 1_000, 1 << 20, 1 << 24, 1 << 24).unwrap())
                .emit_limit_issues(true),
        )
}

fn source(tree: &TempTree, options: DirectoryOptions, threads: usize) -> DirectorySource {
    DirectorySource::with_options(
        tree.path().join("scan"),
        options.read_threads(NonZeroUsize::new(threads).unwrap()),
    )
}

/// Visits the source and returns every event and the result. `control`
/// answers each event by its zero-based position.
fn visit(
    source: &mut DirectorySource,
    cancellation: &CancellationToken,
    mut control: impl FnMut(usize) -> Result<SourceControl, CallbackError>,
) -> (Vec<SourceEvent>, Result<SourceControl, SourceError>) {
    let mut events = Vec::new();
    let result = source.visit(cancellation, &mut |event| {
        events.push(event);
        control(events.len() - 1)
    });
    (events, result)
}

fn engine() -> Engine {
    Engine::builder(config()).build().unwrap()
}

struct Scan {
    findings: Vec<Finding>,
    issues: Vec<SourceIssue>,
    termination: SourceTermination,
    scanned_bytes: u64,
}

fn run(source: &mut DirectorySource, workers: usize) -> Scan {
    let outcome = SourceRunner::new(workers, workers).unwrap().run(
        source,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &CancellationToken::new(),
    );
    Scan {
        findings: outcome.findings().to_vec(),
        issues: outcome.issues().to_vec(),
        termination: outcome.termination().clone(),
        scanned_bytes: outcome.scanned_bytes(),
    }
}

fn rows(findings: &[Finding]) -> Vec<Row> {
    let mut rows = findings
        .iter()
        .map(|finding| {
            assert_eq!(finding.rule_id().as_bytes(), b"planted");
            (
                finding.file().to_string_lossy().into_owned(),
                finding.location().start_line(),
                finding.secret().to_string_lossy().into_owned(),
            )
        })
        .collect::<Vec<_>>();
    rows.sort();
    rows
}

fn issue_paths(issues: &[SourceIssue]) -> Vec<String> {
    issues
        .iter()
        .map(|issue| {
            issue
                .path()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect()
}

#[test]
fn events_do_not_depend_on_reader_threads() {
    let tree = TempTree::new("events");
    plant(&tree);
    #[cfg(unix)]
    plant_unix(&tree);
    for follow_symlinks in [false, true] {
        let mut serial = source(&tree, options(follow_symlinks), 1);
        let (expected, result) = visit(&mut serial, &CancellationToken::new(), |_| {
            Ok(SourceControl::Continue)
        });
        assert_eq!(result, Ok(SourceControl::Continue));
        let fragments = expected
            .iter()
            .filter(|event| matches!(event, SourceEvent::Fragment { .. }))
            .count();
        // 600 files, of which 45 are empty and 14 are read in three pieces.
        assert!(fragments > 600 - 45 + 14 * 2, "{fragments}");
        for &threads in &THREADS[1..] {
            let mut parallel = source(&tree, options(follow_symlinks), threads);
            let (events, result) = visit(&mut parallel, &CancellationToken::new(), |_| {
                Ok(SourceControl::Continue)
            });
            assert_eq!(result, Ok(SourceControl::Continue), "{threads} threads");
            assert!(
                events == expected,
                "events differ with {threads} threads and follow_symlinks={follow_symlinks}"
            );
        }
    }
}

#[test]
fn findings_issues_and_order_do_not_depend_on_reader_threads() {
    let tree = TempTree::new("findings");
    let mut expected = plant(&tree);
    #[cfg(unix)]
    let locked = plant_unix(&tree);
    let mut first: Option<Scan> = None;
    for workers in [1, 3] {
        for &threads in THREADS {
            let scan = run(&mut source(&tree, options(true), threads), workers);
            assert_eq!(scan.termination, SourceTermination::Completed);
            match &first {
                None => first = Some(scan),
                Some(first) => {
                    assert!(
                        scan.findings == first.findings,
                        "findings or their order differ with {threads} threads and {workers} workers"
                    );
                    assert_eq!(scan.issues, first.issues, "{threads} threads");
                    assert_eq!(scan.scanned_bytes, first.scanned_bytes);
                }
            }
        }
    }
    let scan = first.unwrap();
    let mut found = rows(&scan.findings);
    #[cfg(unix)]
    {
        let link = found
            .iter()
            .position(|row| row.2 == secret(8))
            .expect("the linked file is scanned");
        let link = found.remove(link);
        assert_eq!(link.1, 1);
        assert!(link.0.ends_with("outside/target.txt"), "{}", link.0);
        if !locked {
            expected.push(("scan/n1/locked.txt".to_owned(), 1, secret(9)));
            expected.push(("scan/n2/locked-folder/inside.txt".to_owned(), 1, secret(10)));
        }
    }
    expected.sort();
    assert_eq!(found, expected);

    let issues = issue_paths(&scan.issues);
    let reported = |name: &str| issues.iter().any(|issue| issue.contains(name));
    for name in ["oversize.txt", "deep.tar", "broken.gz"] {
        assert!(reported(name), "{name}: {issues:?}");
    }
    #[cfg(unix)]
    {
        for name in ["dangling.txt", "loop-a.txt", "loop-b.txt", "folder-link"] {
            assert!(reported(name), "{name}: {issues:?}");
        }
        if locked {
            for name in ["locked.txt", "locked-folder"] {
                assert!(reported(name), "{name}: {issues:?}");
            }
        }
    }
}

#[test]
fn a_stop_or_error_at_any_event_gives_the_same_prefix_and_result() {
    let tree = TempTree::new("stops");
    // A smaller tree, so that every position can be tried.
    for file in 0..24 {
        let body = if file % 5 == 0 {
            planted(5_400, &[(3_000, secret(file))])
        } else {
            format!("{}\n", secret(file))
        };
        tree.write(&format!("scan/d{}/f{file:02}.txt", file % 3), body);
    }
    tree.write("scan/d1/oversize.txt", planted(17_000, &[]));
    tree.write(
        "scan/d2/bundle.tar",
        tar(&[("a.txt", b"x\n"), ("b.txt", b"y\n")]),
    );
    tree.write("scan/d2/broken.gz", b"\x1f\x8bbad");
    let mut serial = source(&tree, options(false), 1);
    let (all, _) = visit(&mut serial, &CancellationToken::new(), |_| {
        Ok(SourceControl::Continue)
    });
    assert!(all.len() > 30, "{}", all.len());
    for position in 0..all.len() {
        for stop in [true, false] {
            let answer = |index: usize| {
                if index < position {
                    Ok(SourceControl::Continue)
                } else if stop {
                    Ok(SourceControl::Stop)
                } else {
                    Err(CallbackError::new("synthetic rejection"))
                }
            };
            let mut serial = source(&tree, options(false), 1);
            let expected = visit(&mut serial, &CancellationToken::new(), answer);
            assert_eq!(expected.0.len(), position + 1);
            assert!(expected.0[..] == all[..=position]);
            if stop {
                assert_eq!(expected.1, Ok(SourceControl::Stop));
            } else {
                assert!(expected.1.is_err(), "{:?}", expected.1);
            }
            for threads in [2, 4] {
                let mut parallel = source(&tree, options(false), threads);
                let observed = visit(&mut parallel, &CancellationToken::new(), answer);
                assert!(
                    observed.0 == expected.0,
                    "events differ at {position} with {threads} threads, stop={stop}"
                );
                assert_eq!(observed.1, expected.1, "{position} {threads} {stop}");
            }
        }
    }
}

#[test]
fn complete_scans_fail_at_the_same_target_for_every_reader_count() {
    let tree = TempTree::new("complete");
    for file in 0..40 {
        tree.write(
            &format!("scan/d{}/f{file:02}.txt", file % 4),
            format!("{}\n", secret(file)),
        );
    }
    // Larger than the complete-target limit, so the scan fails here.
    tree.write("scan/d2/f50-large.txt", planted(400, &[]));
    tree.write("scan/d3/f99-after.txt", format!("{}\n", secret(99)));
    let complete = || {
        options(false)
            .max_file_size(None)
            .file_options(FileOptions::complete(4_096).unwrap())
    };
    let mut serial = source(&tree, complete(), 1);
    let (expected, result) = visit(&mut serial, &CancellationToken::new(), |_| {
        Ok(SourceControl::Continue)
    });
    let Err(SourceError::Terminal { path, .. }) = &result else {
        panic!("the large target must fail the scan: {result:?}");
    };
    assert!(
        path.as_ref().unwrap().ends_with("d2/f50-large.txt"),
        "{path:?}"
    );
    // Folders d0 and d1 and the earlier files of d2 come first.
    assert_eq!(expected.len(), 10 + 10 + 10);
    for &threads in &THREADS[1..] {
        let mut parallel = source(&tree, complete(), threads);
        let observed = visit(&mut parallel, &CancellationToken::new(), |_| {
            Ok(SourceControl::Continue)
        });
        assert!(observed.0 == expected, "{threads} threads");
        assert_eq!(observed.1, result, "{threads} threads");
    }
}

#[test]
fn cancellation_stops_every_reader_count_with_a_prefix_of_the_events() {
    let tree = TempTree::new("cancel");
    for file in 0..200 {
        tree.write(
            &format!("scan/d{}/f{file:03}.txt", file % 5),
            format!("{}\n", secret(file)),
        );
    }
    let mut serial = source(&tree, options(false), 1);
    let (all, _) = visit(&mut serial, &CancellationToken::new(), |_| {
        Ok(SourceControl::Continue)
    });
    assert_eq!(all.len(), 200);
    for &threads in THREADS {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let (events, result) = visit(
            &mut source(&tree, options(false), threads),
            &cancelled,
            |_| Ok(SourceControl::Continue),
        );
        assert!(events.is_empty(), "{threads} threads");
        assert_eq!(result, Err(SourceError::Cancelled));

        for position in [0, 7, 120] {
            let token = CancellationToken::new();
            let (events, result) = visit(
                &mut source(&tree, options(false), threads),
                &token,
                |index| {
                    if index == position {
                        token.cancel();
                    }
                    Ok(SourceControl::Continue)
                },
            );
            assert_eq!(result, Err(SourceError::Cancelled), "{threads} threads");
            // No event reaches the callback after it cancels.
            assert_eq!(events.len(), position + 1, "{threads} threads");
            assert!(events[..] == all[..=position], "{threads} threads");
        }
    }
}
