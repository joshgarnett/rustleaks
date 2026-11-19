//! Reads default Git history with several `git log` processes.
//!
//! `git rev-list` lists the commits in the order that `git log` shows them.
//! The list is split into batches of consecutive commits, and each batch is
//! shown by its own `git log --no-walk=unsorted --stdin` process. One parser
//! reads the output of the batches in list order, with the blank line that
//! one `git log` process writes between two shown commits. So the parser
//! reads the same bytes as from one process, and fragments, their order,
//! issues and errors do not change.
//!
//! Git shows each commit on its own when no pathspec simplifies history, so
//! only the default history options use batches. Everything else, and every
//! case where the plan cannot be made, uses one process.

use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use super::{
    COMMAND_POLL, CommandIo, GitMode, GitSource, OutputBudget, PatchStream, StreamedOutput,
    first_non_ignored_stderr, git_exit_message, patch_error_to_source, stream_command_with,
    terminal,
};
use crate::{
    CallbackError, Cancellation, SourceControl, SourceError, SourceEvent, SourceIssue,
    SourceIssueKind, SourceStage,
};

/// Git output is passed to the parser in pieces of about this size.
const MESSAGE_BYTES: usize = 256 * 1024;
/// Output of the batch that the parser reads that can wait for it.
const HEAD_BUFFER_BYTES: usize = 4 * 1024 * 1024;
/// Output of later batches that can wait for the parser, together. On large
/// public histories, less made batches wait for space, and more gave little.
const REORDER_BUFFER_BYTES: usize = 128 * 1024 * 1024;
/// Batches whose output can wait for the parser, for each Git process.
const QUEUED_BATCHES_PER_PROCESS: usize = 2;
/// Commits in one batch. Each Git process starts by reading the pack
/// indexes, so a batch is large enough for that cost to be small. The memory
/// of one Git process grows as it reads more commits, and later batches wait
/// in the reorder buffer, so a batch is also small. On large public
/// histories, smaller batches were slower and larger ones used more memory.
const DEFAULT_BATCH_COMMITS: usize = 250;
/// Longer lists use one process. The list keeps one line of at most 65
/// bytes for each commit.
const MAX_LISTED_COMMITS: usize = 10_000_000;
const MAX_LISTED_BYTES: usize = MAX_LISTED_COMMITS * 65;

/// Commits to show, split into batches.
pub(super) struct HistoryPlan {
    /// `git rev-list` output: one object name and a newline for each commit.
    commits: Vec<u8>,
    /// Byte ranges of `commits`, one for each batch, in list order.
    batches: Vec<Range<usize>>,
    /// Standard error that the `git log` processes may still keep together.
    stderr: OutputBudget,
}

/// Lists the commits when several processes can read the history.
///
/// Returns `None` when one process must read it: one process is allowed,
/// the history options are not the defaults, the history fits one batch,
/// `git rev-list` fails or writes standard error, or a configured pretty
/// format can change how commits are separated. One process then repeats
/// the work and reports any failure or warning.
///
/// Git writes warnings about the repository, such as about its refs or a
/// graft file, when it starts. Each `git log` process would repeat them, and
/// they count toward the standard error limit, so a repository with them
/// uses one process.
pub(super) fn plan(
    source: &GitSource,
    cancellation: &dyn Cancellation,
) -> Result<Option<HistoryPlan>, SourceError> {
    let processes = source.history_processes.get();
    let default_options = match &source.mode {
        GitMode::Log { options } => options.as_ref().is_none_or(String::is_empty),
        GitMode::LogArguments(_) | GitMode::Diff { .. } => false,
    };
    if processes < 2 || !default_options {
        return Ok(None);
    }
    let Some((commits, line)) = list_commits(source, cancellation)? else {
        return Ok(None);
    };
    let count = commits.len() / line;
    let size = source
        .history_batch_commits
        .map_or(DEFAULT_BATCH_COMMITS, NonZeroUsize::get);
    if count <= size || !pretty_format_is_unset(source, cancellation)? {
        return Ok(None);
    }
    // Every line has the same length, so a batch is a fixed byte range.
    let step = size.saturating_mul(line);
    let batches = (0..commits.len())
        .step_by(step)
        .map(|start| start..commits.len().min(start.saturating_add(step)))
        .collect();
    Ok(Some(HistoryPlan {
        commits,
        batches,
        stderr: OutputBudget::new(source.limits.stderr_bytes()),
    }))
}

/// Runs `git rev-list` with the revision options of the default history.
/// Returns the list and the length of one line, or `None` unless Git
/// succeeds without standard error and lists only object names.
fn list_commits(
    source: &GitSource,
    cancellation: &dyn Cancellation,
) -> Result<Option<(Vec<u8>, usize)>, SourceError> {
    let arguments = [
        OsString::from("-C"),
        source.repository.as_os_str().to_owned(),
        OsString::from("rev-list"),
        OsString::from("--full-history"),
        OsString::from("--all"),
    ];
    let mut commits = Vec::new();
    let mut failed = false;
    let result = stream_command_with(
        &source.executable,
        &arguments,
        CommandIo {
            input: None,
            stderr: &OutputBudget::new(source.limits.stderr_bytes()),
        },
        &source.environment,
        cancellation,
        SourceStage::GitCommand,
        &mut |chunk| {
            if commits.len().saturating_add(chunk.len()) > MAX_LISTED_BYTES
                || commits.try_reserve(chunk.len()).is_err()
            {
                failed = true;
                return Ok(SourceControl::Stop);
            }
            commits.extend_from_slice(&chunk);
            Ok(SourceControl::Continue)
        },
    );
    let listed = match result {
        Ok(listed) => listed,
        Err(SourceError::Cancelled) => return Err(SourceError::Cancelled),
        Err(_) => return Ok(None),
    };
    let succeeded = !failed
        && !listed.stopped
        && listed.stderr.is_empty()
        && !listed.stderr_limited
        && listed.status.is_some_and(|status| status.success());
    let line = lists_object_names(&commits).filter(|_| succeeded);
    Ok(line.map(|line| (commits, line)))
}

/// Checks that the output is lines of hexadecimal SHA-1 or SHA-256 object
/// names of one length, each ended by a newline, and returns the length of
/// one line.
fn lists_object_names(output: &[u8]) -> Option<usize> {
    let first = output.iter().position(|byte| *byte == b'\n')?;
    if first != 40 && first != 64 {
        return None;
    }
    output
        .chunks(first + 1)
        .all(|line| {
            line.len() == first + 1
                && line[first] == b'\n'
                && line[..first]
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        })
        .then_some(first + 1)
}

/// Checks that no `format.pretty` value is configured.
///
/// `git log` writes a blank line between two commits in its default format.
/// Some pretty formats end each commit instead, so batch output could not be
/// joined as one process writes it. Exit status 1 means that the value is
/// not set; anything else uses one process.
fn pretty_format_is_unset(
    source: &GitSource,
    cancellation: &dyn Cancellation,
) -> Result<bool, SourceError> {
    let arguments = [
        OsString::from("-C"),
        source.repository.as_os_str().to_owned(),
        OsString::from("config"),
        OsString::from("--get"),
        OsString::from("format.pretty"),
    ];
    let result = stream_command_with(
        &source.executable,
        &arguments,
        CommandIo {
            input: None,
            stderr: &OutputBudget::new(source.limits.stderr_bytes()),
        },
        &source.environment,
        cancellation,
        SourceStage::GitCommand,
        &mut |_| Ok(SourceControl::Continue),
    );
    match result {
        Ok(output) => Ok(output.status.and_then(|status| status.code()) == Some(1)),
        Err(SourceError::Cancelled) => Err(SourceError::Cancelled),
        Err(_) => Ok(false),
    }
}

/// One batch for a Git process, with the queue for its output.
struct Job {
    batch: usize,
    output: Sender<Message>,
}

enum Message {
    Output(Vec<u8>),
    End(Result<StreamedOutput, SourceError>),
}

/// Cancellation of one Git process: the scan's, or the end of the visit.
struct Abort<'a> {
    scan: &'a dyn Cancellation,
    visit: &'a AtomicBool,
}

impl Cancellation for Abort<'_> {
    fn is_cancelled(&self) -> bool {
        self.visit.load(Ordering::Acquire) || self.scan.is_cancelled()
    }
}

/// Bytes of Git output that wait for the parser.
///
/// The batch that the parser reads, the head, can always keep up to
/// `HEAD_BUFFER_BYTES`, so it never waits for a later batch. Later batches
/// share `REORDER_BUFFER_BYTES`. A Git process whose output does not fit
/// waits, with its output pipe full, until the parser frees space or reaches
/// its batch. Parsed pieces return to a pool for reuse, so the memory of the
/// pieces stays close to the most bytes that waited at one time.
struct ReorderBuffer {
    state: Mutex<BufferState>,
    released: Condvar,
}

struct BufferState {
    head: usize,
    total: usize,
    /// Waiting bytes of each batch that has any.
    batches: HashMap<usize, usize>,
    /// Empty pieces of `MESSAGE_BYTES` capacity.
    spare: Vec<Vec<u8>>,
}

impl ReorderBuffer {
    fn new() -> Self {
        Self {
            state: Mutex::new(BufferState {
                head: 0,
                total: 0,
                batches: HashMap::new(),
                spare: Vec::new(),
            }),
            released: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BufferState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until `bytes` of `batch` fit. Returns `false` when aborted.
    fn reserve(&self, batch: usize, bytes: usize, abort: &Abort<'_>) -> bool {
        let mut state = self.lock();
        loop {
            if abort.is_cancelled() {
                return false;
            }
            let waiting = state.batches.get(&batch).copied().unwrap_or(0);
            let fits = if state.head == batch {
                waiting.saturating_add(bytes) <= HEAD_BUFFER_BYTES
            } else {
                state
                    .total
                    .saturating_sub(state.batches.get(&state.head).copied().unwrap_or(0))
                    .saturating_add(bytes)
                    <= REORDER_BUFFER_BYTES
            };
            if fits {
                state.total = state.total.saturating_add(bytes);
                state.batches.insert(batch, waiting.saturating_add(bytes));
                return true;
            }
            state = self
                .released
                .wait_timeout(state, COMMAND_POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Returns an empty piece from the pool, or a new one.
    fn piece(&self) -> Result<Vec<u8>, SourceError> {
        if let Some(piece) = self.lock().spare.pop() {
            return Ok(piece);
        }
        let mut piece = Vec::new();
        piece.try_reserve_exact(MESSAGE_BYTES).map_err(|error| {
            terminal(
                SourceStage::GitCommand,
                None,
                format!("could not reserve Git history output: {error}"),
            )
        })?;
        Ok(piece)
    }

    /// Frees the space of a parsed piece and keeps the piece for reuse.
    fn release(&self, batch: usize, mut piece: Vec<u8>) {
        let bytes = piece.capacity();
        let mut state = self.lock();
        state.total = state.total.saturating_sub(bytes);
        if let Some(waiting) = state.batches.get_mut(&batch) {
            *waiting = waiting.saturating_sub(bytes);
            if *waiting == 0 {
                state.batches.remove(&batch);
            }
        }
        if bytes == MESSAGE_BYTES && state.spare.try_reserve(1).is_ok() {
            piece.clear();
            state.spare.push(piece);
        }
        drop(state);
        self.released.notify_all();
    }

    fn advance(&self, head: usize) {
        self.lock().head = head;
        self.released.notify_all();
    }
}

/// What the Git processes of one visit share.
struct Shared<'a> {
    executable: &'a OsStr,
    environment: &'a [(OsString, OsString)],
    arguments: [OsString; 8],
    plan: &'a HistoryPlan,
    queue: Mutex<Receiver<Job>>,
    buffer: ReorderBuffer,
    abort: Abort<'a>,
}

/// Reads the planned batches with up to `history_processes` Git processes
/// and parses their output in list order.
pub(super) fn visit(
    source: &GitSource,
    plan: &HistoryPlan,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    let processes = source.history_processes.get().min(plan.batches.len());
    let ended = AtomicBool::new(false);
    let (jobs, queue) = mpsc::channel::<Job>();
    let shared = Shared {
        executable: &source.executable,
        environment: &source.environment,
        arguments: [
            OsString::from("-C"),
            source.repository.as_os_str().to_owned(),
            OsString::from("log"),
            OsString::from("-p"),
            OsString::from("-U0"),
            OsString::from("--diff-filter=tuxdb"),
            OsString::from("--no-walk=unsorted"),
            OsString::from("--stdin"),
        ],
        plan,
        queue: Mutex::new(queue),
        buffer: ReorderBuffer::new(),
        abort: Abort {
            scan: cancellation,
            visit: &ended,
        },
    };
    thread::scope(|scope| {
        let mut workers = Vec::new();
        let mut spawn_error = None;
        for _ in 0..processes {
            match thread::Builder::new()
                .name("rustleaks-git-history".to_owned())
                .spawn_scoped(scope, || run_batches(&shared))
            {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    spawn_error = Some(error);
                    break;
                }
            }
        }
        // Fewer threads only read with fewer Git processes.
        let result = match spawn_error {
            Some(error) if workers.is_empty() => {
                drop(jobs);
                Err(terminal(
                    SourceStage::GitCommand,
                    None,
                    format!("could not start a Git history thread: {error}"),
                ))
            }
            _ => parse_batches(source, &shared, jobs, workers.len(), cancellation, emit),
        };
        // Stop every Git process that still runs. `parse_batches` dropped the
        // job sender and every output queue, so idle workers return.
        ended.store(true, Ordering::Release);
        let mut cleanup = None;
        let mut panicked = false;
        for worker in workers {
            match worker.join() {
                Ok(Some(error)) => {
                    cleanup.get_or_insert(error);
                }
                Ok(None) => {}
                Err(_) => panicked = true,
            }
        }
        if panicked {
            return Err(terminal(
                SourceStage::GitCommand,
                None,
                "a Git history thread panicked",
            ));
        }
        // As with one process, a Git child that could not be stopped and
        // reaped fails a scan that stopped or was cancelled.
        match (result, cleanup) {
            (Ok(SourceControl::Stop) | Err(SourceError::Cancelled), Some(error)) => Err(error),
            (result, _) => result,
        }
    })
}

/// Runs one Git process for each job until the job queue closes. Returns an
/// error that the parser no longer receives, other than cancellation.
fn run_batches(shared: &Shared<'_>) -> Option<SourceError> {
    let mut undelivered = None;
    loop {
        let job = shared
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        let Ok(job) = job else {
            return undelivered;
        };
        let deliver = |bytes: Vec<u8>| {
            let size = bytes.capacity();
            if !shared.buffer.reserve(job.batch, size, &shared.abort) {
                return false;
            }
            if let Err(mpsc::SendError(Message::Output(bytes))) =
                job.output.send(Message::Output(bytes))
            {
                shared.buffer.release(job.batch, bytes);
                return false;
            }
            true
        };
        // Pipe reads are often small. Joining them keeps the memory of a
        // waiting batch close to its output size.
        let mut pending = Vec::new();
        let mut result = stream_command_with(
            shared.executable,
            &shared.arguments,
            CommandIo {
                input: Some(&shared.plan.commits[shared.plan.batches[job.batch].clone()]),
                stderr: &shared.plan.stderr,
            },
            shared.environment,
            &shared.abort,
            SourceStage::GitCommand,
            &mut |chunk| {
                // A chunk is at most 64 KiB, so it fits an empty piece.
                if pending.capacity() - pending.len() < chunk.len() {
                    if !pending.is_empty() && !deliver(std::mem::take(&mut pending)) {
                        // The parser ended; stop this Git.
                        return Ok(SourceControl::Stop);
                    }
                    pending = shared.buffer.piece()?;
                }
                pending.extend_from_slice(&chunk);
                Ok(SourceControl::Continue)
            },
        );
        // Output that the parser did not take ends the batch as stopped.
        if !pending.is_empty()
            && !deliver(pending)
            && let Ok(output) = &mut result
        {
            output.stopped = true;
        }
        if let Err(mpsc::SendError(Message::End(Err(error)))) =
            job.output.send(Message::End(result))
            && !matches!(error, SourceError::Cancelled)
        {
            undelivered.get_or_insert(error);
        }
    }
}

/// Queues batches in list order and parses their output in the same order.
fn parse_batches(
    source: &GitSource,
    shared: &Shared<'_>,
    jobs: Sender<Job>,
    processes: usize,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    let plan = shared.plan;
    let queued = processes.saturating_mul(QUEUED_BATCHES_PER_PROCESS);
    let mut pending = VecDeque::new();
    let mut next = 0;
    let mut stream = PatchStream::new(source.limits);
    let mut shown = false;
    let mut warned = false;
    for batch in 0..plan.batches.len() {
        while next < plan.batches.len() && pending.len() < queued {
            let (output, receiver) = mpsc::channel();
            jobs.send(Job {
                batch: next,
                output,
            })
            .map_err(|_| stopped_thread())?;
            pending.push_back(receiver);
            next += 1;
        }
        shared.buffer.advance(batch);
        let receiver = pending.pop_front().ok_or_else(stopped_thread)?;
        let mut first = true;
        let output = loop {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            if plan.stderr.is_exceeded() {
                return Err(stderr_exceeded(source));
            }
            match receiver.recv_timeout(COMMAND_POLL) {
                Ok(Message::Output(chunk)) => {
                    // One process writes a blank line before every shown
                    // commit after the first. A batch that shows no commit
                    // writes nothing.
                    if first && shown {
                        stream
                            .push(b"\n")
                            .map_err(|error| patch_error_to_source(error, &source.repository))?;
                    }
                    first = false;
                    shown = true;
                    let pushed = stream.push(&chunk);
                    shared.buffer.release(batch, chunk);
                    pushed.map_err(|error| patch_error_to_source(error, &source.repository))?;
                    if source.emit_ready_files(&mut stream, cancellation, emit)?
                        == SourceControl::Stop
                    {
                        return Ok(SourceControl::Stop);
                    }
                }
                Ok(Message::End(output)) => break output?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(stopped_thread()),
            }
        };
        // The final record of a batch waits like the final record of one
        // process: a later failure ends the scan before it is published.
        if output.stderr_limited || plan.stderr.is_exceeded() {
            return Err(stderr_exceeded(source));
        }
        if output.stopped || !output.status.is_some_and(|status| status.success()) {
            return Err(terminal(
                SourceStage::GitExit,
                Some(source.repository.clone()),
                git_exit_message(output.status, &output.stderr),
            ));
        }
        warned |= first_non_ignored_stderr(&output.stderr).is_some();
    }
    drop(jobs);
    if warned {
        let control = emit(SourceEvent::Issue(SourceIssue::new(
            SourceStage::GitCommand,
            SourceIssueKind::GitStderr,
            Some(source.repository.clone()),
            "stderr is not empty",
        )))
        .map_err(SourceError::Callback)?;
        if control == SourceControl::Stop {
            return Ok(control);
        }
    }
    stream.finish();
    source.emit_ready_files(&mut stream, cancellation, emit)
}

fn stderr_exceeded(source: &GitSource) -> SourceError {
    terminal(
        SourceStage::Limit,
        Some(source.repository.clone()),
        "Git standard error exceeded its configured byte ceiling",
    )
}

fn stopped_thread() -> SourceError {
    terminal(
        SourceStage::GitCommand,
        None,
        "a Git history thread stopped without a result",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Duration;

    use super::{
        Abort, HEAD_BUFFER_BYTES, MESSAGE_BYTES, REORDER_BUFFER_BYTES, ReorderBuffer,
        lists_object_names,
    };
    use crate::CancellationToken;

    /// Reserves one piece, or reports after 50 ms that it still waits.
    fn fits(buffer: &ReorderBuffer, batch: usize) -> bool {
        let scan = CancellationToken::new();
        let ended = AtomicBool::new(false);
        let abort = Abort {
            scan: &scan,
            visit: &ended,
        };
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(50));
                ended.store(true, std::sync::atomic::Ordering::Release);
            });
            buffer.reserve(batch, MESSAGE_BYTES, &abort)
        })
    }

    #[test]
    fn later_batches_share_the_buffer_and_the_head_never_waits_for_them() {
        let buffer = ReorderBuffer::new();
        let later = REORDER_BUFFER_BYTES / MESSAGE_BYTES;
        for piece in 0..later {
            assert!(fits(&buffer, 1 + piece % 3), "piece {piece}");
        }
        // Later batches wait when the shared space is full.
        assert!(!fits(&buffer, 2));
        // The head has its own space, up to its limit.
        for piece in 0..HEAD_BUFFER_BYTES / MESSAGE_BYTES {
            assert!(fits(&buffer, 0), "head piece {piece}");
        }
        assert!(!fits(&buffer, 0));
        // A parsed piece frees space for a later batch.
        buffer.release(1, Vec::with_capacity(MESSAGE_BYTES));
        assert!(fits(&buffer, 3));
        assert!(!fits(&buffer, 3));
        // When the parser reaches batch 2, its waiting output no longer
        // counts against the later batches. Batch 2 itself waits until the
        // parser takes its output below the head limit.
        buffer.advance(2);
        assert!(fits(&buffer, 4));
        assert!(!fits(&buffer, 2));
        for _ in 0..later / 3 {
            buffer.release(2, Vec::with_capacity(MESSAGE_BYTES));
        }
        assert!(fits(&buffer, 2));
        // A parsed piece is kept for reuse.
        let piece = buffer.piece().expect("piece");
        assert_eq!((piece.len(), piece.capacity()), (0, MESSAGE_BYTES));
    }

    #[test]
    fn only_lines_of_one_object_name_length_are_a_commit_list() {
        let sha1 = "0123456789abcdef0123456789abcdef01234567\n";
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
        assert_eq!(lists_object_names(sha1.as_bytes()), Some(41));
        assert_eq!(lists_object_names(sha1.repeat(3).as_bytes()), Some(41));
        assert_eq!(lists_object_names(sha256.repeat(2).as_bytes()), Some(65));
        for invalid in [
            String::new(),
            sha1.trim_end().to_owned(),
            format!("{sha1}{sha256}"),
            sha1.to_uppercase(),
            sha1.replace('0', "g"),
            format!("{sha1}\n"),
            format!("-{}", &sha1[1..]),
            "commit 0123\n".to_owned(),
        ] {
            assert_eq!(lists_object_names(invalid.as_bytes()), None, "{invalid:?}");
        }
    }
}
