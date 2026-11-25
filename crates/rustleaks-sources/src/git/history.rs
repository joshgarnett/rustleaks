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
//! case where the list cannot be used, uses one process.
//!
//! Batches start while `git rev-list` still runs. Their events wait until the
//! list has succeeded, so a list that fails late still leaves one process to
//! read the history with nothing published.

use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use super::{
    CommandIo, GitMode, GitSource, OutputBudget, PatchStream, StreamedOutput,
    first_non_ignored_stderr, patch_error_to_source, stream_command_with,
};
use crate::process::CHILD_POLL;
use crate::{CallbackError, Cancellation, SourceControl, SourceError, SourceEvent, SourceStage};

/// Git output is passed to the parser in pieces of about this size.
const MESSAGE_BYTES: usize = 256 * 1024;
/// Output of the batch that the parser reads that can wait for it.
const HEAD_BUFFER_BYTES: usize = 4 * 1024 * 1024;
/// Output of later batches that can wait for the parser, together. On large
/// public histories, a smaller buffer made batches wait for space, and a
/// larger one gave little.
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

/// Bytes of parsed events that can wait until `git rev-list` has finished.
///
/// Batches start while the list still runs, and their events wait until the
/// list has passed every check, so that a list that fails late can still
/// fall back to one process with nothing published. Past this size, the
/// parser waits for the list instead.
const HELD_EVENT_BYTES: usize = 32 * 1024 * 1024;

/// What the list thread sends while `git rev-list` runs.
enum Listed {
    /// The next batch of commits: object names, each ended by a newline.
    Batch(Vec<u8>),
    /// The list ended. `true` when Git succeeded without standard error and
    /// listed only object names of one length, within the size limit.
    End(bool),
}

/// Whether several processes may read the history: more than one is allowed,
/// the history options are the defaults, and no configured pretty format can
/// change how commits are separated.
///
/// Git writes warnings about the repository, such as about its refs or a
/// graft file, when it starts. Each `git log` process would repeat them, and
/// they count toward the standard error limit, so a list with standard error
/// uses one process.
fn batches_allowed(
    source: &GitSource,
    cancellation: &dyn Cancellation,
) -> Result<bool, SourceError> {
    let default_options = match &source.mode {
        GitMode::Log { options } => options.as_ref().is_none_or(String::is_empty),
        GitMode::LogArguments(_) | GitMode::Diff { .. } => false,
    };
    if source.history_processes.get() < 2 || !default_options {
        return Ok(false);
    }
    pretty_format_is_unset(source, cancellation)
}

/// Runs `git rev-list` with the revision options of the default history and
/// sends its commits in batches of `size` while it runs. Ends with
/// [`Listed::End`] unless the receiver went away.
fn list_batches(
    source: &GitSource,
    size: usize,
    abort: &Abort<'_>,
    batches: &mpsc::SyncSender<Listed>,
) {
    let arguments = [
        OsString::from("-C"),
        source.repository.as_os_str().to_owned(),
        OsString::from("rev-list"),
        OsString::from("--full-history"),
        OsString::from("--all"),
    ];
    let mut pending = Vec::new();
    let mut line = None;
    let mut listed = 0_usize;
    let mut failed = false;
    let mut gone = false;
    let result = stream_command_with(
        &source.executable,
        &arguments,
        CommandIo {
            input: None,
            stderr: &OutputBudget::new(source.limits.stderr_bytes()),
            clear_attribute_source: false,
            buffers: None,
        },
        &source.environment,
        abort,
        SourceStage::GitCommand,
        &mut |chunk| {
            listed = listed.saturating_add(chunk.len());
            if listed > MAX_LISTED_BYTES || pending.try_reserve(chunk.len()).is_err() {
                failed = true;
                return Ok(SourceControl::Stop);
            }
            pending.extend_from_slice(&chunk);
            if line.is_none() {
                match pending.iter().position(|byte| *byte == b'\n') {
                    Some(end @ (40 | 64)) => line = Some(end + 1),
                    Some(_) => {
                        failed = true;
                        return Ok(SourceControl::Stop);
                    }
                    None if pending.len() > 64 => {
                        failed = true;
                        return Ok(SourceControl::Stop);
                    }
                    None => return Ok(SourceControl::Continue),
                }
            }
            let Some(line) = line else {
                return Ok(SourceControl::Continue);
            };
            let step = size.saturating_mul(line);
            while pending.len() >= step {
                let rest = pending.split_off(step);
                let batch = std::mem::replace(&mut pending, rest);
                if lists_object_names(&batch) != Some(line) {
                    failed = true;
                    return Ok(SourceControl::Stop);
                }
                if batches.send(Listed::Batch(batch)).is_err() {
                    gone = true;
                    return Ok(SourceControl::Stop);
                }
            }
            Ok(SourceControl::Continue)
        },
    );
    if gone {
        return;
    }
    let succeeded = match result {
        Ok(output) => {
            !failed
                && !output.stopped
                && output.stderr.is_empty()
                && !output.stderr_limited
                && output.status.is_some_and(|status| status.success())
        }
        Err(_) => false,
    };
    let rest_valid =
        pending.is_empty() || line.is_some_and(|line| lists_object_names(&pending) == Some(line));
    let succeeded = succeeded && line.is_some() && rest_valid;
    if succeeded && !pending.is_empty() && batches.send(Listed::Batch(pending)).is_err() {
        return;
    }
    let _ = batches.send(Listed::End(succeeded));
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
            clear_attribute_source: false,
            buffers: None,
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
    /// The commits of the batch, as `git rev-list` listed them.
    input: Vec<u8>,
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
                .wait_timeout(state, CHILD_POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Returns an empty piece from the pool, or a new one.
    fn piece(&self) -> io::Result<Vec<u8>> {
        if let Some(piece) = self.lock().spare.pop() {
            return Ok(piece);
        }
        let mut piece = Vec::new();
        piece.try_reserve_exact(MESSAGE_BYTES).map_err(|error| {
            io::Error::other(format!("could not reserve Git history output: {error}"))
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
    arguments: [OsString; 16],
    /// Standard error that the `git log` processes may still keep together.
    stderr: OutputBudget,
    queue: Mutex<Receiver<Job>>,
    buffer: ReorderBuffer,
    abort: Abort<'a>,
}

/// Reads the default history with up to `history_processes` Git processes
/// and parses their output in list order. `empty_tree` names the empty tree
/// that the processes read attributes from.
///
/// Returns `Ok(None)`, having published nothing, when one process must read
/// the history: when [`batches_allowed`] says so, when the history fits one
/// batch, or when `git rev-list` fails, writes standard error or lists
/// something other than object names. One process then repeats the work and
/// reports any failure or warning.
pub(super) fn visit(
    source: &GitSource,
    empty_tree: &str,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<Option<SourceControl>, SourceError> {
    if !batches_allowed(source, cancellation)? {
        return Ok(None);
    }
    let size = source
        .history_batch_commits
        .map_or(DEFAULT_BATCH_COMMITS, NonZeroUsize::get);
    let processes = source.history_processes.get();
    let ended = AtomicBool::new(false);
    let (jobs, queue) = mpsc::channel::<Job>();
    // The parser takes listed batches as they arrive; `MAX_LISTED_BYTES`
    // bounds what they can add up to.
    let (list_sender, listed) = mpsc::sync_channel::<Listed>(processes.saturating_mul(4));
    let [attribute_flag, attribute_value] = super::attribute_override(empty_tree);
    let shared = Shared {
        executable: &source.executable,
        environment: &source.environment,
        arguments: [
            OsString::from("-C"),
            source.repository.as_os_str().to_owned(),
            OsString::from(super::CONFIG_OVERRIDES[0]),
            OsString::from(super::CONFIG_OVERRIDES[1]),
            attribute_flag,
            attribute_value,
            OsString::from("log"),
            OsString::from("-p"),
            OsString::from("-U0"),
            OsString::from(super::LOG_OPTIONS[0]),
            OsString::from(super::LOG_OPTIONS[1]),
            OsString::from(super::LOG_OPTIONS[2]),
            OsString::from(super::LOG_OPTIONS[3]),
            OsString::from("--diff-filter=tuxdb"),
            OsString::from("--no-walk=unsorted"),
            OsString::from("--stdin"),
        ],
        stderr: OutputBudget::new(source.limits.stderr_bytes()),
        queue: Mutex::new(queue),
        buffer: ReorderBuffer::new(),
        abort: Abort {
            scan: cancellation,
            visit: &ended,
        },
    };
    thread::scope(|scope| {
        let lister = match thread::Builder::new()
            .name("rustleaks-git-list".to_owned())
            .spawn_scoped(scope, || {
                // The thread owns the sender, so the parser sees the list end
                // even if the thread panics.
                let sender = list_sender;
                list_batches(source, size, &shared.abort, &sender);
            }) {
            Ok(lister) => lister,
            // One process reads the history without a list.
            Err(_) => return Ok(None),
        };
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
                Err(SourceError::terminal(
                    SourceStage::GitCommand,
                    None,
                    format!("could not start a Git history thread: {error}"),
                ))
            }
            _ => parse_batches(
                source,
                &shared,
                jobs,
                &listed,
                workers.len(),
                cancellation,
                emit,
            ),
        };
        // Stop the list and every Git process that still runs.
        // `parse_batches` dropped the job sender and every output queue, so
        // idle workers return, and dropping the list receiver ends the list.
        ended.store(true, Ordering::Release);
        drop(listed);
        let mut cleanup = None;
        let mut panicked = lister.join().is_err();
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
            return Err(SourceError::terminal(
                SourceStage::GitCommand,
                None,
                "a Git history thread panicked",
            ));
        }
        // As with one process, a Git child that could not be stopped and
        // reaped fails a scan that stopped or was cancelled.
        // A batch Git that could not be stopped before one process takes
        // over fails the scan too.
        match (result, cleanup) {
            (Ok(Some(SourceControl::Stop) | None) | Err(SourceError::Cancelled), Some(error)) => {
                Err(error)
            }
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
        // Pipe reads are often small. Filled pieces keep the memory of a
        // waiting batch close to its output size and need fewer handoffs.
        let pieces = || shared.buffer.piece();
        let result = stream_command_with(
            shared.executable,
            &shared.arguments,
            CommandIo {
                input: Some(&job.input),
                stderr: &shared.stderr,
                clear_attribute_source: true,
                buffers: Some(&pieces),
            },
            shared.environment,
            &shared.abort,
            SourceStage::GitCommand,
            &mut |piece| {
                if deliver(piece) {
                    Ok(SourceControl::Continue)
                } else {
                    // The parser ended; stop this Git.
                    Ok(SourceControl::Stop)
                }
            },
        );
        if let Err(mpsc::SendError(Message::End(Err(error)))) =
            job.output.send(Message::End(result))
            && !matches!(error, SourceError::Cancelled)
        {
            undelivered.get_or_insert(error);
        }
    }
}

/// The batches that `git rev-list` has listed so far.
struct ListState<'a> {
    listed: &'a Receiver<Listed>,
    /// Listed batches that no Git process has been given yet.
    ready: VecDeque<Vec<u8>>,
    /// Batches listed so far.
    count: usize,
    /// How the list ended, once it has.
    end: Option<bool>,
}

impl ListState<'_> {
    /// Takes what the list has sent. With `wait`, first waits until it
    /// sends something or the scan is cancelled.
    fn poll(&mut self, wait: bool, cancellation: &dyn Cancellation) -> Result<(), SourceError> {
        let mut wait = wait && self.end.is_none();
        while self.end.is_none() {
            let message = if wait {
                if cancellation.is_cancelled() {
                    return Err(SourceError::Cancelled);
                }
                match self.listed.recv_timeout(CHILD_POLL) {
                    Ok(message) => message,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => return Err(stopped_thread()),
                }
            } else {
                match self.listed.try_recv() {
                    Ok(message) => message,
                    Err(mpsc::TryRecvError::Empty) => return Ok(()),
                    Err(mpsc::TryRecvError::Disconnected) => return Err(stopped_thread()),
                }
            };
            wait = false;
            match message {
                Listed::Batch(batch) => {
                    self.ready.push_back(batch);
                    self.count += 1;
                }
                Listed::End(succeeded) => self.end = Some(succeeded),
            }
        }
        Ok(())
    }

    /// Waits until the list ends and returns whether it succeeded.
    fn wait_for_end(&mut self, cancellation: &dyn Cancellation) -> Result<bool, SourceError> {
        loop {
            if let Some(succeeded) = self.end {
                return Ok(succeeded);
            }
            self.poll(true, cancellation)?;
        }
    }
}

/// One held event, or a cancellation poll that the parser made before it.
enum HeldItem {
    Poll,
    Event(SourceEvent),
}

/// Events that wait until the list has succeeded.
///
/// Publishing them later must stop where publishing them at once would
/// have: a callback that cancels the scan ends it at the next poll. So the
/// parser's polls between held events are kept and repeated in order.
struct Held {
    items: Vec<HeldItem>,
    bytes: usize,
    confirmed: bool,
}

/// The scan's cancellation, which also notes that the parser polled it.
struct Recording<'a> {
    scan: &'a dyn Cancellation,
    polled: &'a AtomicBool,
}

impl Cancellation for Recording<'_> {
    fn is_cancelled(&self) -> bool {
        self.polled.store(true, Ordering::Relaxed);
        self.scan.is_cancelled()
    }
}

impl Held {
    fn emit(
        &mut self,
        event: SourceEvent,
        polled: &AtomicBool,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, CallbackError> {
        if self.confirmed {
            return emit(event);
        }
        if polled.swap(false, Ordering::Relaxed) {
            self.items.push(HeldItem::Poll);
        }
        let bytes = match &event {
            SourceEvent::Fragment { fragment, .. } => fragment.content().as_bytes().len(),
            SourceEvent::Issue(_) => 0,
        };
        self.bytes = self.bytes.saturating_add(bytes.saturating_add(256));
        self.items.push(HeldItem::Event(event));
        Ok(SourceControl::Continue)
    }

    /// Publishes the held events in order, after the list succeeded, with
    /// the parser's polls between them and after the last one.
    fn confirm(
        &mut self,
        cancellation: &dyn Cancellation,
        polled: &AtomicBool,
        emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    ) -> Result<SourceControl, SourceError> {
        self.confirmed = true;
        self.bytes = 0;
        for item in std::mem::take(&mut self.items) {
            match item {
                HeldItem::Poll => {
                    if cancellation.is_cancelled() {
                        return Err(SourceError::Cancelled);
                    }
                }
                HeldItem::Event(event) => {
                    if emit(event).map_err(SourceError::Callback)? == SourceControl::Stop {
                        return Ok(SourceControl::Stop);
                    }
                }
            }
        }
        if polled.swap(false, Ordering::Relaxed) && cancellation.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        Ok(SourceControl::Continue)
    }
}

/// Queues batches in list order as the list grows, and parses their output
/// in the same order. Returns `Ok(None)`, having published nothing, when
/// one process must read the history; see [`visit`].
#[allow(clippy::too_many_arguments)] // The visit state and the list are passed apart.
fn parse_batches(
    source: &GitSource,
    shared: &Shared<'_>,
    jobs: Sender<Job>,
    listed: &Receiver<Listed>,
    processes: usize,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<Option<SourceControl>, SourceError> {
    let mut list = ListState {
        listed,
        ready: VecDeque::new(),
        count: 0,
        end: None,
    };
    // A history of one batch, or a list that fails first, uses one process.
    while list.count < 2 && list.end.is_none() {
        list.poll(true, cancellation)?;
    }
    // Archive members of one file can add up to far more than the events
    // that may wait, so a history that reads archives waits for the list.
    #[cfg(feature = "archives")]
    if source.archives.is_some() {
        list.wait_for_end(cancellation)?;
    }
    if list.end == Some(false) || list.count < 2 {
        return one_process(cancellation);
    }
    let mut held = Held {
        items: Vec::new(),
        bytes: 0,
        confirmed: list.end == Some(true),
    };
    let polled = AtomicBool::new(false);
    let result = parse_listed(
        source,
        shared,
        &jobs,
        &mut list,
        &mut held,
        &polled,
        processes,
        cancellation,
        emit,
    );
    drop(jobs);
    match result {
        Ok(Some(control)) => Ok(Some(control)),
        Ok(None) => one_process(cancellation),
        Err(SourceError::Cancelled) => Err(SourceError::Cancelled),
        // A failure before the list succeeded publishes the held events
        // first, as one process would have published them before failing.
        // A list that fails uses one process, which then fails itself.
        Err(error) if !held.confirmed => match list.wait_for_end(cancellation)? {
            true => match held.confirm(cancellation, &polled, emit)? {
                SourceControl::Stop => Ok(Some(SourceControl::Stop)),
                SourceControl::Continue => Err(error),
            },
            false => one_process(cancellation),
        },
        Err(error) => Err(error),
    }
}

/// Leaves the history to one process, unless the scan was cancelled while
/// the list ran.
fn one_process(cancellation: &dyn Cancellation) -> Result<Option<SourceControl>, SourceError> {
    if cancellation.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One ordered parse loop.
fn parse_listed(
    source: &GitSource,
    shared: &Shared<'_>,
    jobs: &Sender<Job>,
    list: &mut ListState<'_>,
    held: &mut Held,
    polled: &AtomicBool,
    processes: usize,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<Option<SourceControl>, SourceError> {
    let queued = processes.saturating_mul(QUEUED_BATCHES_PER_PROCESS);
    let mut pending = VecDeque::new();
    let mut next = 0;
    let mut stream = PatchStream::new(source.limits);
    let mut shown = false;
    let mut warned = false;
    let recording = Recording {
        scan: cancellation,
        polled,
    };
    // Takes listed batches, gives them to Git processes, and publishes the
    // held events once the list succeeded. `None` means one process.
    let mut feed = |list: &mut ListState<'_>,
                    pending: &mut VecDeque<Receiver<Message>>,
                    held: &mut Held,
                    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>|
     -> Result<Option<SourceControl>, SourceError> {
        list.poll(false, cancellation)?;
        if !held.confirmed && held.bytes > HELD_EVENT_BYTES {
            list.wait_for_end(cancellation)?;
        }
        if !held.confirmed {
            match list.end {
                Some(true) => {
                    let control = held.confirm(cancellation, polled, emit)?;
                    if control == SourceControl::Stop {
                        return Ok(Some(control));
                    }
                }
                Some(false) => return Ok(None),
                None => {}
            }
        }
        while pending.len() < queued
            && let Some(input) = list.ready.pop_front()
        {
            let (output, receiver) = mpsc::channel();
            jobs.send(Job {
                batch: next,
                input,
                output,
            })
            .map_err(|_| stopped_thread())?;
            pending.push_back(receiver);
            next += 1;
        }
        Ok(Some(SourceControl::Continue))
    };
    let mut batch = 0;
    loop {
        match feed(list, &mut pending, held, emit)? {
            Some(SourceControl::Continue) => {}
            other => return Ok(other),
        }
        if pending.is_empty() {
            if list.end.is_some() && list.ready.is_empty() {
                break;
            }
            list.poll(true, cancellation)?;
            continue;
        }
        shared.buffer.advance(batch);
        let receiver = pending.pop_front().ok_or_else(stopped_thread)?;
        let mut first = true;
        let output = loop {
            if cancellation.is_cancelled() {
                return Err(SourceError::Cancelled);
            }
            if shared.stderr.is_exceeded() {
                return Err(source.stderr_exceeded());
            }
            match feed(list, &mut pending, held, emit)? {
                Some(SourceControl::Continue) => {}
                other => return Ok(other),
            }
            match receiver.recv_timeout(CHILD_POLL) {
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
                    if source.emit_ready_files(&mut stream, &recording, &mut |event| {
                        held.emit(event, polled, emit)
                    })? == SourceControl::Stop
                    {
                        return Ok(Some(SourceControl::Stop));
                    }
                }
                Ok(Message::End(output)) => break output?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(stopped_thread()),
            }
        };
        // The final record of a batch waits like the final record of one
        // process: a later failure ends the scan before it is published.
        if output.stderr_limited || shared.stderr.is_exceeded() {
            return Err(source.stderr_exceeded());
        }
        if output.stopped || !output.status.is_some_and(|status| status.success()) {
            return Err(source.exit_error(&output));
        }
        warned |= first_non_ignored_stderr(&output.stderr).is_some();
        batch += 1;
    }
    // Every batch was read, so the list ended and succeeded.
    if !held.confirmed && held.confirm(cancellation, polled, emit)? == SourceControl::Stop {
        return Ok(Some(SourceControl::Stop));
    }
    source
        .finish_history(stream, warned, cancellation, emit)
        .map(Some)
}

fn stopped_thread() -> SourceError {
    SourceError::terminal(
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
        Abort, HEAD_BUFFER_BYTES, Held, MESSAGE_BYTES, REORDER_BUFFER_BYTES, Recording,
        ReorderBuffer, lists_object_names,
    };
    use crate::{Cancellation, CancellationToken, SourceControl, SourceEvent, SourceIssue};
    use crate::{SourceIssueKind, SourceStage};

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

    fn issue(text: &str) -> SourceEvent {
        SourceEvent::Issue(SourceIssue::new(
            SourceStage::GitCommand,
            SourceIssueKind::GitStderr,
            None,
            text.to_owned(),
        ))
    }

    #[test]
    fn held_events_stop_at_the_poll_that_follows_a_cancelling_callback() {
        let scan = CancellationToken::new();
        let polled = AtomicBool::new(false);
        let recording = Recording {
            scan: &scan,
            polled: &polled,
        };
        let mut held = Held {
            items: Vec::new(),
            bytes: 0,
            confirmed: false,
        };
        let mut nothing = |_: SourceEvent| -> Result<SourceControl, crate::CallbackError> {
            unreachable!("held events are not published before confirmation")
        };
        // Two events of one file, then a poll before the next file's event.
        assert!(!recording.is_cancelled());
        for text in ["first", "second"] {
            held.emit(issue(text), &polled, &mut nothing).expect("held");
        }
        assert!(!recording.is_cancelled());
        held.emit(issue("third"), &polled, &mut nothing)
            .expect("held");
        // A callback that cancels on the first event still receives the
        // second, which came before the next poll, and never the third.
        let mut published = Vec::new();
        let mut cancel_first = |event: SourceEvent| {
            published.push(event);
            scan.cancel();
            Ok(SourceControl::Continue)
        };
        assert_eq!(
            held.confirm(&scan, &polled, &mut cancel_first),
            Err(crate::SourceError::Cancelled)
        );
        assert_eq!(published.len(), 2);
        assert!(held.confirmed);
    }

    #[test]
    fn a_poll_after_the_last_held_event_is_repeated() {
        let scan = CancellationToken::new();
        let polled = AtomicBool::new(false);
        let recording = Recording {
            scan: &scan,
            polled: &polled,
        };
        let mut held = Held {
            items: Vec::new(),
            bytes: 0,
            confirmed: false,
        };
        let mut nothing = |_: SourceEvent| -> Result<SourceControl, crate::CallbackError> {
            unreachable!("held events are not published before confirmation")
        };
        held.emit(issue("last"), &polled, &mut nothing)
            .expect("held");
        // The parser polls once more before it reaches a failure or the end.
        assert!(!recording.is_cancelled());
        let mut cancel = |_: SourceEvent| {
            scan.cancel();
            Ok(SourceControl::Continue)
        };
        assert_eq!(
            held.confirm(&scan, &polled, &mut cancel),
            Err(crate::SourceError::Cancelled)
        );
        // Without that poll the callback's cancellation waits for the next.
        let quiet = CancellationToken::new();
        let polled = AtomicBool::new(false);
        let mut held = Held {
            items: Vec::new(),
            bytes: 0,
            confirmed: false,
        };
        held.emit(issue("last"), &polled, &mut nothing)
            .expect("held");
        let mut cancel = |_: SourceEvent| {
            quiet.cancel();
            Ok(SourceControl::Continue)
        };
        assert_eq!(
            held.confirm(&quiet, &polled, &mut cancel),
            Ok(SourceControl::Continue)
        );
    }
}
