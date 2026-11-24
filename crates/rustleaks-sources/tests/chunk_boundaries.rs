//! Secrets near the file part boundaries of the default reader, compared with
//! whole-file reading in complete-target mode.
//!
//! Expected values follow the documented reader rule (docs/user/reports.md and
//! docs/dev/performance.md): the default reader takes a 100,000-byte part,
//! then reads ahead through a 4,096-byte buffer until a blank line (two LF
//! bytes with only spaces, tabs, CR or LF between them) or 25,000 extra bytes.
//! The next part starts with the bytes left in that buffer, so a file without
//! a blank line gives parts of 125,000 bytes and then 28,672 bytes. Parts are
//! scanned on their own. The first line of a part counts columns from 1; later
//! lines count from the preceding LF, so their columns are one higher.

#![forbid(unsafe_code)]

use std::io::Cursor;

use rustleaks_core::Engine;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Finding, Location, ScanOptions};
use rustleaks_core::session::SessionPolicy;
use rustleaks_sources::{
    CancellationToken, FileOptions, FileSource, Source, SourceControl, SourceEvent, SourceRunner,
    SourceTermination,
};

const PART: usize = 100_000;
const READ_AHEAD: usize = 25_000;
const BUFFER: usize = 4_096;
// The read-ahead fills the buffer 7 times for 25,000 bytes and leaves
// 7 * 4,096 - 25,000 = 3,672 bytes. The next part is those bytes plus a new
// read-ahead of 25,000 bytes.
const LEFTOVER: usize = 7 * BUFFER - READ_AHEAD;
const LATER_PART: usize = LEFTOVER + READ_AHEAD;

fn engine() -> Engine {
    Engine::builder(
        ConfigLoader::new()
            .load_toml("[[rules]]\nid = 'planted'\nregex = '''PLANTED_[A-Z0-9]{20}'''\n")
            .unwrap(),
    )
    .build()
    .unwrap()
}

fn secret() -> Vec<u8> {
    b"PLANTED_Q7M2Z9V4L1C8R5S0N6B3".to_vec()
}

/// A file of `length` bytes with an LF at every index in `newlines`, the
/// secret at `at`, and `.` everywhere else.
fn file(length: usize, newlines: impl IntoIterator<Item = usize>, at: usize) -> Vec<u8> {
    let mut bytes = vec![b'.'; length];
    for index in newlines {
        bytes[index] = b'\n';
    }
    let secret = secret();
    assert!(
        !bytes[at..at + secret.len()].contains(&b'\n'),
        "construction keeps the secret on one line"
    );
    bytes[at..at + secret.len()].copy_from_slice(&secret);
    bytes
}

fn part_lengths(bytes: &[u8], options: FileOptions) -> Vec<usize> {
    let mut source = FileSource::with_options(Cursor::new(bytes.to_vec()), "parts.txt", options);
    let mut lengths = Vec::new();
    source
        .visit(&CancellationToken::new(), &mut |event| {
            match event {
                SourceEvent::Fragment {
                    fragment,
                    issue: None,
                } => lengths.push(fragment.content().as_bytes().len()),
                _ => panic!("unexpected source event"),
            }
            Ok(SourceControl::Continue)
        })
        .unwrap();
    lengths
}

fn scan(bytes: &[u8], options: FileOptions) -> Vec<Finding> {
    let mut source = FileSource::with_options(Cursor::new(bytes.to_vec()), "parts.txt", options);
    let outcome = SourceRunner::new(1, 1).unwrap().run(
        &mut source,
        &engine(),
        ScanOptions::default(),
        &SessionPolicy::default(),
        &CancellationToken::new(),
    );
    assert_eq!(outcome.termination(), &SourceTermination::Completed);
    assert!(outcome.issues().is_empty());
    outcome.findings().to_vec()
}

fn count_lf(bytes: &[u8]) -> usize {
    bytes.iter().map(|byte| usize::from(*byte == b'\n')).sum()
}

fn complete(bytes: &[u8]) -> FileOptions {
    FileOptions::complete(bytes.len()).unwrap()
}

/// Location of the secret at `at` in a part that starts at `part_start` on
/// line `part_line`, from the column rule in the module comment.
fn location(bytes: &[u8], part_start: usize, part_line: usize, at: usize) -> Location {
    let part = &bytes[part_start..at];
    let lf = part.iter().rposition(|byte| *byte == b'\n');
    let line = part_line + count_lf(part);
    let column = match lf {
        None => at - part_start + 1,
        Some(index) => at - part_start - index + 1,
    };
    Location::new(line, line, column, column + secret().len() - 1).unwrap()
}

fn assert_one(findings: &[Finding], expected: Location) {
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret().as_bytes(), secret().as_slice());
    assert_eq!(findings[0].location(), expected);
}

#[test]
fn a_blank_line_inside_the_read_ahead_keeps_a_straddling_secret_in_the_first_part() {
    // Lines of 100 bytes. The secret crosses byte 100,000 and is followed by
    // a blank line, so the first part ends after the second LF.
    let at = PART - 10;
    let after = at + secret().len();
    let length = 160_000;
    let newlines = (99..at)
        .step_by(100)
        .chain([after, after + 1])
        .chain((after + 101..length).step_by(100));
    let bytes = file(length, newlines, at);
    let first = after + 2;
    assert_eq!(part_lengths(&bytes, FileOptions::default())[0], first);
    assert_one(
        &scan(&bytes, FileOptions::default()),
        location(&bytes, 0, 1, at),
    );
    assert_one(&scan(&bytes, complete(&bytes)), location(&bytes, 0, 1, at));
}

#[test]
fn a_secret_across_the_read_ahead_limit_is_missed_by_parts_and_found_whole() {
    // Single LF bytes are not part boundaries, so the read-ahead stops at its
    // limit and the first part ends at byte 125,000, inside the secret.
    let length = 200_000;
    let at = PART + READ_AHEAD - 10;
    let newlines = (499..length).step_by(1_000);
    let bytes = file(length, newlines, at);
    assert_eq!(
        part_lengths(&bytes, FileOptions::default())[..2],
        [PART + READ_AHEAD, LATER_PART]
    );
    assert!(scan(&bytes, FileOptions::default()).is_empty());
    assert_eq!(part_lengths(&bytes, complete(&bytes)), [length]);
    assert_one(&scan(&bytes, complete(&bytes)), location(&bytes, 0, 1, at));
}

#[test]
fn later_parts_of_a_file_without_line_breaks_follow_the_short_read_rule() {
    let length = 250_000;
    let first = PART + READ_AHEAD;
    let second = first + LATER_PART;
    let third = second + LATER_PART;
    let bytes = vec![b'.'; length];
    assert_eq!(
        part_lengths(&bytes, FileOptions::default())[..4],
        [first, LATER_PART, LATER_PART, LATER_PART]
    );
    for boundary in [first, second, third] {
        // Across the boundary: missed by parts, found whole.
        let at = boundary - 10;
        let bytes = file(length, [], at);
        assert!(
            scan(&bytes, FileOptions::default()).is_empty(),
            "{boundary}"
        );
        assert_one(&scan(&bytes, complete(&bytes)), location(&bytes, 0, 1, at));
        // Just after the boundary: found, with columns from the part start.
        let at = boundary + 10;
        let bytes = file(length, [], at);
        assert_one(
            &scan(&bytes, FileOptions::default()),
            location(&bytes, boundary, 1, at),
        );
        assert_one(&scan(&bytes, complete(&bytes)), location(&bytes, 0, 1, at));
        // Just before the boundary, ending on its last byte: found.
        let at = boundary - secret().len();
        let bytes = file(length, [], at);
        let part_start = if boundary == first {
            0
        } else {
            boundary - LATER_PART
        };
        assert_one(
            &scan(&bytes, FileOptions::default()),
            location(&bytes, part_start, 1, at),
        );
    }
}

#[test]
fn a_secret_right_after_a_blank_line_boundary_starts_the_next_part() {
    // The first 100,000 bytes end in a blank line, so no read-ahead happens.
    // The secret opens the second part: column 1 there, but column 2 in the
    // whole file, where the preceding byte is an LF on an earlier line.
    let length = 150_000;
    let newlines = (99..PART - 2)
        .step_by(100)
        .chain([PART - 2, PART - 1])
        .chain((PART + 99..length).step_by(100));
    let bytes = file(length, newlines, PART);
    assert_eq!(part_lengths(&bytes, FileOptions::default())[0], PART);
    let lines_before = count_lf(&bytes[..PART]);
    let parts = scan(&bytes, FileOptions::default());
    assert_one(&parts, location(&bytes, PART, 1 + lines_before, PART));
    assert_eq!(parts[0].location().start_column(), 1);
    let whole = scan(&bytes, complete(&bytes));
    assert_one(&whole, location(&bytes, 0, 1, PART));
    assert_eq!(whole[0].location().start_column(), 2);
    assert_eq!(
        whole[0].location().start_line(),
        parts[0].location().start_line()
    );
}

#[test]
fn whitespace_between_the_two_line_feeds_still_ends_the_part() {
    // A blank line may hold spaces, tabs and CR. Any other byte resets it.
    for (gap, ends) in [
        (&b" \t\r"[..], true),
        (&b"\r"[..], true),
        (&b" x "[..], false),
    ] {
        let at = PART - 10;
        let after = at + secret().len();
        let mut bytes = file(140_000, (99..at).step_by(100), at);
        bytes[after] = b'\n';
        bytes[after + 1..after + 1 + gap.len()].copy_from_slice(gap);
        bytes[after + 1 + gap.len()] = b'\n';
        let lengths = part_lengths(&bytes, FileOptions::default());
        if ends {
            assert_eq!(lengths[0], after + 2 + gap.len(), "{gap:?}");
        } else {
            assert_eq!(lengths[0], PART + READ_AHEAD, "{gap:?}");
        }
        assert_one(
            &scan(&bytes, FileOptions::default()),
            location(&bytes, 0, 1, at),
        );
    }
}
