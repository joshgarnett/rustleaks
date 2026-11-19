//! Git history read by several `git log` processes must give the same
//! fragments, issues, errors and order as one process.
//!
//! Each test builds a synthetic repository with `git fast-import`, scans it
//! with one process, and scans it again with several processes and small
//! batches. `GIT_TRACE` records which Git commands ran, so each test also
//! checks whether batches were used.

mod support;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};

use rustleaks_sources::{
    ArchiveLimits, ArchiveOptions, CancellationToken, GitLimits, GitMode, GitSource, Source,
    SourceControl, SourceError, SourceEvent, SourceIssueKind, SourceStage,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Process counts and batch sizes compared with one process.
const SPLITS: &[(usize, usize)] = &[(2, 1), (3, 2), (4, 3), (8, 5)];

struct Sandbox(PathBuf);

impl Sandbox {
    fn new(label: &str) -> Self {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rustleaks-git-history-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create sandbox");
        fs::write(root.join("empty-gitconfig"), []).expect("write empty Git config");
        Self(root)
    }

    fn repository(&self) -> PathBuf {
        self.0.join("repository")
    }

    fn trace(&self) -> PathBuf {
        self.0.join("trace")
    }

    /// Git configuration, locale and time zone isolated from the host.
    fn environment(&self) -> Vec<(OsString, OsString)> {
        vec![
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                self.0.join("empty-gitconfig").into_os_string(),
            ),
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("TZ"), OsString::from("UTC")),
        ]
    }

    fn git(&self, directory: &Path, arguments: &[&str], input: Option<&[u8]>) -> Vec<u8> {
        let mut child = support::command()
            .arg("-C")
            .arg(directory)
            .args(arguments)
            .envs(self.environment())
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start isolated Git");
        if let Some(input) = input {
            child
                .stdin
                .take()
                .expect("Git stdin")
                .write_all(input)
                .expect("write Git stdin");
        }
        let output = child.wait_with_output().expect("run isolated Git");
        assert!(
            output.status.success(),
            "Git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Creates the repository from a `git fast-import` stream. Automatic
    /// maintenance is off, so no repack runs while a scan reads objects.
    fn import(&self, history: &History) -> PathBuf {
        let repository = self.repository();
        fs::create_dir(&repository).expect("create repository");
        self.git(&repository, &["init", "--quiet"], None);
        for (key, value) in [
            ("gc.auto", "0"),
            ("maintenance.auto", "false"),
            ("core.autocrlf", "false"),
        ] {
            self.git(&repository, &["config", key, value], None);
        }
        self.git(
            &repository,
            &["fast-import", "--quiet"],
            Some(&history.stream),
        );
        repository
    }

    fn source(&self, repository: &Path) -> GitSource {
        let mut environment = self.environment();
        environment.push((OsString::from("GIT_TRACE"), self.trace().into_os_string()));
        support::git_source(repository).command_environment(environment)
    }

    fn commits(&self, repository: &Path) -> usize {
        self.git(repository, &["rev-list", "--full-history", "--all"], None)
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count()
    }

    /// Counts the `git rev-list` and batch `git log` processes since the
    /// last call.
    fn traced(&self) -> (usize, usize) {
        let trace = fs::read(self.trace()).unwrap_or_default();
        let _ = fs::remove_file(self.trace());
        let text = String::from_utf8_lossy(&trace);
        let count = |needle: &str| text.lines().filter(|line| line.contains(needle)).count();
        (
            count("built-in: git rev-list --full-history --all"),
            count("--no-walk=unsorted --stdin"),
        )
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A `git fast-import` stream.
struct History {
    stream: Vec<u8>,
    marks: usize,
}

enum Change {
    Write(Vec<u8>, Vec<u8>),
    Mode(&'static str, Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    Rename(Vec<u8>, Vec<u8>),
    Copy(Vec<u8>, Vec<u8>),
}

fn write(path: impl AsRef<[u8]>, bytes: impl AsRef<[u8]>) -> Change {
    Change::Write(path.as_ref().to_vec(), bytes.as_ref().to_vec())
}

/// C-style quoting, which `git fast-import` accepts for every path.
fn quote(path: &[u8]) -> String {
    let mut quoted = String::from("\"");
    for byte in path {
        match byte {
            b'"' => quoted.push_str("\\\""),
            b'\\' => quoted.push_str("\\\\"),
            b'\n' => quoted.push_str("\\n"),
            b'\t' => quoted.push_str("\\t"),
            0x20..=0x7e => quoted.push(char::from(*byte)),
            _ => {
                let _ = write!(quoted, "\\{byte:03o}");
            }
        }
    }
    quoted.push('"');
    quoted
}

impl History {
    const fn new() -> Self {
        Self {
            stream: Vec::new(),
            marks: 0,
        }
    }

    fn data(&mut self, bytes: &[u8]) {
        self.stream
            .extend_from_slice(format!("data {}\n", bytes.len()).as_bytes());
        self.stream.extend_from_slice(bytes);
        self.stream.push(b'\n');
    }

    /// Adds a commit and returns its mark. The first parent continues the
    /// branch; no parent starts a new root.
    fn commit(
        &mut self,
        branch: &str,
        parents: &[usize],
        time: i64,
        message: &str,
        changes: &[Change],
    ) -> usize {
        self.marks += 1;
        let mark = self.marks;
        let header = format!(
            "commit refs/heads/{branch}\nmark :{mark}\n\
             author Synthetic Author <author@example.invalid> {time} +0000\n\
             committer Synthetic Committer <committer@example.invalid> {time} +0000\n"
        );
        self.stream.extend_from_slice(header.as_bytes());
        self.data(message.as_bytes());
        for (index, parent) in parents.iter().enumerate() {
            let kind = if index == 0 { "from" } else { "merge" };
            self.stream
                .extend_from_slice(format!("{kind} :{parent}\n").as_bytes());
        }
        for change in changes {
            match change {
                Change::Write(path, bytes) => self.modify("100644", path, bytes),
                Change::Mode(mode, path, bytes) => self.modify(mode, path, bytes),
                Change::Delete(path) => self
                    .stream
                    .extend_from_slice(format!("D {}\n", quote(path)).as_bytes()),
                Change::Rename(from, to) => self
                    .stream
                    .extend_from_slice(format!("R {} {}\n", quote(from), quote(to)).as_bytes()),
                Change::Copy(from, to) => self
                    .stream
                    .extend_from_slice(format!("C {} {}\n", quote(from), quote(to)).as_bytes()),
            }
        }
        self.stream.push(b'\n');
        mark
    }

    fn modify(&mut self, mode: &str, path: &[u8], bytes: &[u8]) {
        self.stream
            .extend_from_slice(format!("M {mode} inline {}\n", quote(path)).as_bytes());
        self.data(bytes);
    }

    fn tag(&mut self, name: &str, mark: usize) {
        self.stream
            .extend_from_slice(format!("reset refs/tags/{name}\nfrom :{mark}\n\n").as_bytes());
    }
}

/// Text of numbered synthetic lines, one of them a token-like value.
fn lines(label: &str, count: usize) -> Vec<u8> {
    let mut text = String::new();
    for line in 0..count {
        let _ = writeln!(text, "{label} line {line} value=SYNTHETIC{label}{line:04}");
    }
    text.into_bytes()
}

/// A TAR archive with one member.
fn tar(name: &[u8], body: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    header[100..107].copy_from_slice(b"0000644");
    header[108..115].copy_from_slice(b"0000000");
    header[116..123].copy_from_slice(b"0000000");
    header[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
    header[136..147].copy_from_slice(b"00000000000");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut archive = header.to_vec();
    archive.extend_from_slice(body);
    archive.resize(archive.len().next_multiple_of(512) + 1024, 0);
    archive
}

/// A history with merges, renames, copies, binary files, CRLF, quoted paths,
/// a symbolic link, mode and delete-only commits, an empty commit, two roots,
/// several branches, a tag that only `--all` reaches, and commit dates out of
/// order.
#[allow(
    clippy::too_many_lines,
    reason = "one table of commits keeps the planted shapes in history order"
)]
fn rich_history() -> History {
    let mut history = History::new();
    let base = 1_600_000_000_i64;
    let mut main = history.commit(
        "main",
        &[],
        base,
        "root",
        &[
            write(b"docs/a.txt", lines("A", 12)),
            write(b"docs/b.txt", lines("B", 8)),
            write(b"src/main.txt", lines("M", 30)),
        ],
    );
    let mut feature = 0;
    for step in 1..=36_i64 {
        let time = base + step * 600;
        let label = format!("S{step}");
        let text = lines(&label, usize::try_from(step % 7 + 1).unwrap());
        let mut grown = lines("M", 30);
        grown.extend_from_slice(&text);
        let changes: Vec<Change> = match step {
            3 => vec![write(b"bin/data.bin", b"\0\x01binary\0payload\xff\n")],
            5 => vec![write(
                b"crlf.txt",
                b"first\r\nsecond value=SYNTHETICCRLF\r\n",
            )],
            7 => vec![
                write(b"quoted/tab\there.txt", &text),
                write("quoted/\u{fc}nicode.txt".as_bytes(), &text),
                write(b"quoted/quote\"d.txt", &text),
                write(b"quoted/new\nline.txt", &text),
                write(b"quoted/back\\slash.txt", &text),
                write(b"quoted/space name.txt", &text),
            ],
            9 => vec![
                Change::Rename(b"docs/a.txt".to_vec(), b"docs/renamed.txt".to_vec()),
                write(b"docs/renamed.txt", [lines("A", 12), text.clone()].concat()),
            ],
            11 => vec![
                Change::Copy(b"docs/b.txt".to_vec(), b"docs/copy.txt".to_vec()),
                write(b"docs/copy.txt", [lines("B", 8), text.clone()].concat()),
            ],
            13 => vec![Change::Delete(b"crlf.txt".to_vec())],
            15 => vec![Change::Mode(
                "100755",
                b"src/main.txt".to_vec(),
                lines("M", 30),
            )],
            17 => vec![Change::Mode(
                "120000",
                b"link".to_vec(),
                b"src/main.txt".to_vec(),
            )],
            19 => Vec::new(),
            21 => vec![write(
                b"pkg/bundle.tar",
                tar(b"inner.txt", b"archived value=SYNTHETICTAR0001\n"),
            )],
            23 => vec![write(b"no-newline.txt", b"last line value=SYNTHETICEOF")],
            _ => vec![write(b"src/main.txt", &grown)],
        };
        // A commit whose date is older than its parent's.
        let time = if step == 27 { base + 300 } else { time };
        main = history.commit("main", &[main], time, &format!("step {step}"), &changes);
        if step == 10 {
            feature = main;
        }
        if (12..=20).contains(&step) {
            let label = format!("F{step}");
            feature = history.commit(
                "feature",
                &[feature],
                time + 300,
                &format!("feature {step}"),
                &[write(
                    format!("feature/{step}.txt").as_bytes(),
                    lines(&label, 3),
                )],
            );
        }
        if step == 25 {
            // A merge with its own change.
            main = history.commit(
                "main",
                &[main, feature],
                time + 60,
                "merge feature",
                &[write(b"merge-only.txt", lines("MERGE", 2))],
            );
        }
    }
    let mut other = 0;
    for step in 0..6_i64 {
        let parents = if step == 0 { Vec::new() } else { vec![other] };
        other = history.commit(
            "other",
            &parents,
            base + step * 1_700 + 100,
            &format!("other root {step}"),
            &[write(
                b"other.txt",
                lines(&format!("O{step}"), usize::try_from(step + 1).unwrap()),
            )],
        );
    }
    // An octopus merge of all three lines of history.
    history.commit(
        "octopus",
        &[main, feature, other],
        base + 40 * 600,
        "octopus",
        &[],
    );
    let lonely = history.commit(
        "lonely",
        &[main],
        base + 41 * 600,
        "only a tag reaches this commit",
        &[write(b"lonely.txt", lines("L", 4))],
    );
    history.tag("lonely-tag", lonely);
    history
}

/// One source event, with every field that reaches findings and reports.
#[derive(Debug, Eq, PartialEq)]
enum Event {
    Fragment {
        content: Vec<u8>,
        path: Vec<u8>,
        commit: Vec<u8>,
        start_line: String,
        metadata: Option<[Vec<u8>; 5]>,
    },
    Issue {
        stage: SourceStage,
        kind: SourceIssueKind,
        path: Option<PathBuf>,
        message: String,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct Outcome {
    events: Vec<Event>,
    result: Result<SourceControl, SourceError>,
}

/// Scans and records every event. `control` decides the reply to the
/// fragment with the given zero-based index.
fn scan_with(
    source: &mut GitSource,
    mut control: impl FnMut(usize, &CancellationToken) -> SourceControl,
) -> Outcome {
    let cancellation = CancellationToken::new();
    let mut events = Vec::new();
    let mut fragments = 0;
    let result = source.visit(&cancellation, &mut |event| {
        match event {
            SourceEvent::Fragment { fragment, issue } => {
                events.push(Event::Fragment {
                    content: fragment.content().as_bytes().to_vec(),
                    path: fragment.file_path().as_bytes().to_vec(),
                    commit: fragment.commit().as_bytes().to_vec(),
                    start_line: format!("{:?}", fragment.start_line()),
                    metadata: fragment.commit_metadata().map(|metadata| {
                        [
                            metadata.sha().as_bytes().to_vec(),
                            metadata.author_name().as_bytes().to_vec(),
                            metadata.author_email().as_bytes().to_vec(),
                            metadata.date().as_bytes().to_vec(),
                            metadata.message().as_bytes().to_vec(),
                        ]
                    }),
                });
                assert!(issue.is_none(), "Git fragments carry no issue");
                fragments += 1;
                return Ok(control(fragments - 1, &cancellation));
            }
            SourceEvent::Issue(issue) => events.push(Event::Issue {
                stage: issue.stage(),
                kind: issue.kind(),
                path: issue.path().map(Path::to_path_buf),
                message: issue.message().to_owned(),
            }),
            _ => panic!("unexpected future Git source event"),
        }
        Ok(SourceControl::Continue)
    });
    Outcome { events, result }
}

fn scan(source: &mut GitSource) -> Outcome {
    scan_with(source, |_, _| SourceControl::Continue)
}

fn processes(count: usize) -> NonZeroUsize {
    NonZeroUsize::new(count).expect("positive process count")
}

/// The Git processes that a scan with several processes must start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Plan {
    /// A commit list and one process for each batch.
    Batches,
    /// A commit list, then one process for the whole history.
    ListOnly,
    /// One process for the whole history.
    Single,
}

/// Scans with one process, then with every split, and checks that each split
/// gives the same outcome and starts the planned processes. Returns the
/// outcome of one process.
fn assert_splits_match(
    sandbox: &Sandbox,
    repository: &Path,
    plan: Plan,
    configure: impl Fn(GitSource) -> GitSource,
) -> Outcome {
    let commits = sandbox.commits(repository);
    let expected = scan(&mut configure(sandbox.source(repository)));
    assert_eq!(sandbox.traced(), (0, 0), "one process lists no commits");
    for &(count, batch) in SPLITS {
        let mut source = configure(sandbox.source(repository))
            .history_processes(processes(count))
            .history_batch_commits(processes(batch));
        let actual = scan(&mut source);
        assert_eq!(
            actual, expected,
            "{count} processes with batches of {batch} commits"
        );
        let context = format!("{plan:?} with {count} processes and batches of {batch} commits");
        let (listed, batches) = sandbox.traced();
        match plan {
            // A scan that ends early does not start the later batches.
            Plan::Batches if actual.result != Ok(SourceControl::Continue) => {
                assert_eq!(listed, 1, "{context}");
                assert!(
                    batches >= 1 && batches <= commits.div_ceil(batch),
                    "{context}: {batches}"
                );
            }
            Plan::Batches => {
                assert_eq!((listed, batches), (1, commits.div_ceil(batch)), "{context}");
            }
            Plan::ListOnly => assert_eq!((listed, batches), (1, 0), "{context}"),
            Plan::Single => assert_eq!((listed, batches), (0, 0), "{context}"),
        }
    }
    expected
}

fn fragment_count(outcome: &Outcome) -> usize {
    outcome
        .events
        .iter()
        .filter(|event| matches!(event, Event::Fragment { .. }))
        .count()
}

#[test]
fn batches_match_one_process_on_a_rich_history() {
    let sandbox = Sandbox::new("rich");
    let repository = sandbox.import(&rich_history());
    assert!(sandbox.commits(&repository) > 50);
    let outcome = assert_splits_match(&sandbox, &repository, Plan::Batches, |source| source);
    assert_eq!(outcome.result, Ok(SourceControl::Continue));
    assert!(fragment_count(&outcome) > 40);
    // The planted shapes reach the scan.
    let paths = outcome
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Fragment { path, .. } => Some(path.as_slice()),
            Event::Issue { .. } => None,
        })
        .collect::<Vec<_>>();
    for expected in [
        b"crlf.txt".as_slice(),
        b"quoted/new\nline.txt",
        b"quoted/tab\there.txt",
        "quoted/\u{fc}nicode.txt".as_bytes(),
        b"docs/renamed.txt",
        b"lonely.txt",
        b"other.txt",
        b"no-newline.txt",
    ] {
        assert!(paths.contains(&expected), "{expected:?}");
    }
    // As in Gitleaks, the default options show no diff for a merge commit,
    // so a change made only in a merge is not scanned.
    assert!(!paths.contains(&b"merge-only.txt".as_slice()));
}

#[test]
fn batches_match_one_process_with_archives_and_rename_warnings() {
    let sandbox = Sandbox::new("archives");
    let repository = sandbox.import(&rich_history());
    // A rename limit of one makes Git warn about skipped rename detection.
    // These warnings are ignored, also when each batch repeats them.
    sandbox.git(&repository, &["config", "diff.renameLimit", "1"], None);
    let limits = ArchiveLimits::new(2, 1_000, 1 << 20, 1 << 22, 1 << 22).expect("archive limits");
    let outcome = assert_splits_match(&sandbox, &repository, Plan::Batches, |source| {
        source.archives(ArchiveOptions::new(limits))
    });
    assert_eq!(outcome.result, Ok(SourceControl::Continue));
    assert!(outcome.events.iter().any(|event| matches!(
        event,
        Event::Fragment { path, .. } if path == b"pkg/bundle.tar!inner.txt"
    )));
}

#[test]
fn shallow_clones_match_one_process() {
    let sandbox = Sandbox::new("shallow");
    let repository = sandbox.import(&rich_history());
    let shallow = sandbox.0.join("shallow");
    let url = format!("file://{}", repository.display());
    sandbox.git(
        &sandbox.0,
        &[
            "clone",
            "--quiet",
            "--bare",
            "--depth",
            "9",
            "--no-single-branch",
            &url,
            shallow.to_str().expect("UTF-8 sandbox path"),
        ],
        None,
    );
    sandbox.git(&shallow, &["config", "gc.auto", "0"], None);
    sandbox.git(&shallow, &["config", "maintenance.auto", "false"], None);
    assert!(shallow.join("shallow").is_file());
    let outcome = assert_splits_match(&sandbox, &shallow, Plan::Batches, |source| source);
    assert_eq!(outcome.result, Ok(SourceControl::Continue));
}

#[test]
fn other_modes_options_and_pretty_formats_use_one_process() {
    let sandbox = Sandbox::new("modes");
    let repository = sandbox.import(&rich_history());
    sandbox.git(&repository, &["reset", "--quiet", "--hard", "main"], None);
    fs::write(repository.join("src/main.txt"), lines("WORKTREE", 3)).expect("edit worktree");
    fs::write(repository.join("staged.txt"), lines("STAGED", 2)).expect("write staged file");
    sandbox.git(&repository, &["add", "staged.txt"], None);
    for mode in [
        GitMode::Log {
            options: Some("--all".to_owned()),
        },
        GitMode::Log {
            options: Some("--full-history --all --diff-filter=tuxdb".to_owned()),
        },
        GitMode::Log {
            options: Some("-n 7 --all".to_owned()),
        },
        GitMode::LogArguments(vec!["--all".into(), "--reverse".into()]),
        GitMode::Diff { staged: true },
        GitMode::Diff { staged: false },
    ] {
        let outcome = assert_splits_match(&sandbox, &repository, Plan::Single, |source| {
            source.mode(mode.clone())
        });
        assert_eq!(outcome.result, Ok(SourceControl::Continue), "{mode:?}");
        assert!(fragment_count(&outcome) > 0, "{mode:?}");
    }

    // A configured pretty format can end each commit instead of separating
    // commits, so the commit list is made but no batch runs.
    sandbox.git(&repository, &["config", "format.pretty", "fuller"], None);
    assert_splits_match(&sandbox, &repository, Plan::ListOnly, |source| source);
}

#[test]
fn startup_warnings_use_one_process_and_keep_their_issue() {
    let sandbox = Sandbox::new("grafts");
    let repository = sandbox.import(&rich_history());
    // A graft file makes every Git process write a deprecation hint.
    let commit = String::from_utf8(sandbox.git(&repository, &["rev-parse", "main~3"], None))
        .expect("object name");
    let root =
        String::from_utf8(sandbox.git(&repository, &["rev-list", "--max-parents=0", "main"], None))
            .expect("object name");
    fs::create_dir_all(repository.join(".git/info")).expect("create info folder");
    fs::write(
        repository.join(".git/info/grafts"),
        format!("{} {}\n", commit.trim(), root.trim()),
    )
    .expect("write grafts");
    let outcome = assert_splits_match(&sandbox, &repository, Plan::ListOnly, |source| source);
    assert_eq!(outcome.result, Ok(SourceControl::Continue));
    assert!(outcome.events.iter().any(|event| matches!(
        event,
        Event::Issue {
            kind: SourceIssueKind::GitStderr,
            ..
        }
    )));
}

/// The bytes and lines of each commit in default `git log` output, in output
/// order, from one `commit ` line to the next. The blank line that separates
/// two commits counts toward the first.
fn commit_sizes(sandbox: &Sandbox, repository: &Path) -> Vec<(usize, usize)> {
    let output = sandbox.git(
        repository,
        &[
            "log",
            "-p",
            "-U0",
            "--full-history",
            "--all",
            "--diff-filter=tuxdb",
        ],
        None,
    );
    let mut sizes: Vec<(usize, usize)> = Vec::new();
    for line in output.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"commit ") {
            sizes.push((0, 0));
        }
        let (bytes, lines) = sizes.last_mut().expect("output starts with a commit");
        *bytes += line.len();
        *lines += 1;
    }
    sizes
}

/// The most bytes and lines of one commit.
fn largest_commit(sandbox: &Sandbox, repository: &Path) -> (usize, usize) {
    let sizes = commit_sizes(sandbox, repository);
    (
        sizes
            .iter()
            .map(|(bytes, _)| *bytes)
            .max()
            .expect("commits"),
        sizes
            .iter()
            .map(|(_, lines)| *lines)
            .max()
            .expect("commits"),
    )
}

/// The last commit before the final one that is larger than every commit
/// before it. A limit one below its size stops the scan at this commit.
fn last_record_size(sizes: &[(usize, usize)], size: impl Fn(&(usize, usize)) -> usize) -> usize {
    let mut largest = 0;
    let mut chosen = None;
    for commit in &sizes[..sizes.len() - 1] {
        if size(commit) > largest {
            largest = size(commit);
            chosen = Some(largest);
        }
    }
    chosen.expect("a commit before the final one")
}

#[test]
fn limits_count_the_blank_line_between_commits_of_two_batches() {
    // With batches of one commit, every commit but the last ends a batch. The
    // blank line that one process writes before the next commit still counts
    // toward the commit that it follows.
    let sandbox = Sandbox::new("separator");
    let repository = sandbox.import(&rich_history());
    let sizes = commit_sizes(&sandbox, &repository);
    let (bytes, lines) = largest_commit(&sandbox, &repository);
    let at_bytes = last_record_size(&sizes, |(bytes, _)| *bytes);
    let at_lines = last_record_size(&sizes, |(_, lines)| *lines);
    for (bytes, lines) in [(at_bytes - 1, lines), (bytes, at_lines - 1)] {
        let limits = GitLimits::new(bytes, lines, 1 << 20, 1 << 20).expect("limits");
        let outcome = assert_splits_match(&sandbox, &repository, Plan::Batches, |source| {
            source.limits(limits)
        });
        assert!(
            matches!(
                &outcome.result,
                Err(SourceError::Terminal {
                    stage: SourceStage::Limit,
                    ..
                })
            ),
            "{:?}",
            outcome.result
        );
    }
}

#[test]
fn per_commit_limits_publish_the_same_records_before_the_same_error() {
    let sandbox = Sandbox::new("limits");
    let repository = sandbox.import(&rich_history());
    let (bytes, lines) = largest_commit(&sandbox, &repository);
    let limits = |bytes, lines, files, hunks| {
        GitLimits::new(bytes, lines, 1 << 20, 1 << 20)
            .and_then(|limits| limits.with_parser_limits(1 << 20, 4096, files, hunks))
            .expect("limits")
    };
    // At the largest commit exactly, the whole history is scanned.
    let complete = assert_splits_match(&sandbox, &repository, Plan::Batches, |source| {
        source.limits(limits(bytes, lines, 1000, 1000))
    });
    assert_eq!(complete.result, Ok(SourceControl::Continue));
    for (limits, stage) in [
        (limits(bytes - 1, lines, 1000, 1000), SourceStage::Limit),
        (limits(bytes, lines - 1, 1000, 1000), SourceStage::Limit),
        (limits(bytes, lines, 3, 1000), SourceStage::Limit),
        (limits(bytes, lines, 1000, 2), SourceStage::Limit),
        (limits(64, lines, 1000, 1000), SourceStage::Limit),
    ] {
        let outcome = assert_splits_match(&sandbox, &repository, Plan::Batches, |source| {
            source.limits(limits)
        });
        assert!(
            matches!(&outcome.result, Err(SourceError::Terminal { stage: actual, .. }) if *actual == stage),
            "{:?}",
            outcome.result
        );
        assert!(fragment_count(&outcome) < fragment_count(&complete));
    }
}

/// Makes every object loose, so that one object can be removed.
fn unpack(sandbox: &Sandbox, repository: &Path) {
    let pack_directory = repository.join(".git/objects/pack");
    let moved = sandbox.0.join("packs");
    fs::create_dir(&moved).expect("create pack folder");
    for entry in fs::read_dir(&pack_directory).expect("read packs") {
        let path = entry.expect("pack entry").path();
        fs::rename(&path, moved.join(path.file_name().expect("pack name"))).expect("move pack");
    }
    for entry in fs::read_dir(&moved).expect("read moved packs") {
        let path = entry.expect("moved pack").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "pack")
        {
            let pack = fs::read(&path).expect("read pack");
            sandbox.git(repository, &["unpack-objects", "-q"], Some(&pack));
        }
    }
}

fn remove_object(sandbox: &Sandbox, repository: &Path, name: &str) {
    let object = String::from_utf8(sandbox.git(repository, &["rev-parse", name], None))
        .expect("object name");
    let object = object.trim();
    fs::remove_file(
        repository
            .join(".git/objects")
            .join(&object[..2])
            .join(&object[2..]),
    )
    .expect("remove loose object");
}

#[test]
fn a_git_failure_mid_history_publishes_the_same_records() {
    let sandbox = Sandbox::new("missing-blob");
    let repository = sandbox.import(&rich_history());
    unpack(&sandbox, &repository);
    // `git rev-list` reads commits only, so the list succeeds and the batch
    // that shows this commit fails.
    remove_object(&sandbox, &repository, "main~20:src/main.txt");
    let outcome = assert_splits_match(&sandbox, &repository, Plan::Batches, |source| source);
    assert!(
        matches!(
            &outcome.result,
            Err(SourceError::Terminal {
                stage: SourceStage::GitExit,
                ..
            })
        ),
        "{:?}",
        outcome.result
    );
    assert!(fragment_count(&outcome) > 0);

    // A missing commit fails the commit list, so one process reads the
    // history and reports the failure.
    let sandbox = Sandbox::new("missing-commit");
    let repository = sandbox.import(&rich_history());
    unpack(&sandbox, &repository);
    remove_object(&sandbox, &repository, "main~20");
    let expected = scan(&mut sandbox.source(&repository));
    assert!(
        matches!(
            &expected.result,
            Err(SourceError::Terminal {
                stage: SourceStage::GitExit,
                ..
            })
        ),
        "{:?}",
        expected.result
    );
    assert!(fragment_count(&expected) > 0);
    let _ = sandbox.traced();
    for &(count, batch) in SPLITS {
        let actual = scan(
            &mut sandbox
                .source(&repository)
                .history_processes(processes(count))
                .history_batch_commits(processes(batch)),
        );
        assert_eq!(actual, expected);
        assert_eq!(sandbox.traced(), (1, 0));
    }
}

#[test]
fn stop_and_cancellation_end_at_the_same_record() {
    let sandbox = Sandbox::new("stop");
    let repository = sandbox.import(&rich_history());
    let total = fragment_count(&scan(&mut sandbox.source(&repository)));
    let _ = sandbox.traced();
    for at in [0, 1, total / 2, total - 1] {
        let stop = |index: usize, _: &CancellationToken| {
            if index == at {
                SourceControl::Stop
            } else {
                SourceControl::Continue
            }
        };
        let cancel = |index: usize, cancellation: &CancellationToken| {
            if index == at {
                cancellation.cancel();
            }
            SourceControl::Continue
        };
        let stopped = scan_with(&mut sandbox.source(&repository), stop);
        assert_eq!(stopped.result, Ok(SourceControl::Stop));
        assert_eq!(fragment_count(&stopped), at + 1);
        let cancelled = scan_with(&mut sandbox.source(&repository), cancel);
        if at == 0 {
            assert_eq!(cancelled.result, Err(SourceError::Cancelled));
        }
        let _ = sandbox.traced();
        for &(count, batch) in SPLITS {
            let split = |source: GitSource| {
                source
                    .history_processes(processes(count))
                    .history_batch_commits(processes(batch))
            };
            assert_eq!(
                scan_with(&mut split(sandbox.source(&repository)), stop),
                stopped
            );
            assert_eq!(
                scan_with(&mut split(sandbox.source(&repository)), cancel),
                cancelled
            );
        }
    }
}

#[test]
fn a_history_of_one_batch_uses_one_process() {
    let sandbox = Sandbox::new("small");
    let repository = sandbox.import(&rich_history());
    let commits = sandbox.commits(&repository);
    let expected = scan(&mut sandbox.source(&repository));
    let _ = sandbox.traced();
    let actual = scan(
        &mut sandbox
            .source(&repository)
            .history_processes(processes(4))
            .history_batch_commits(processes(commits)),
    );
    assert_eq!(actual, expected);
    assert_eq!(sandbox.traced(), (1, 0));
    // Without a batch size, a history this small is one batch.
    let actual = scan(&mut sandbox.source(&repository).history_processes(processes(4)));
    assert_eq!(actual, expected);
    assert_eq!(sandbox.traced(), (1, 0));
}
