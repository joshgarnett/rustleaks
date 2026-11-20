//! Reads the files of a directory walk on several threads, in walk order.
//!
//! The calling thread walks the tree exactly as a serial scan does and makes
//! every decision there: metadata, path allowlists, size limits, symbolic
//! links and exclusions. Each file that passes becomes a job for a reader
//! thread, which opens it and splits it into fragments with the same code as
//! a serial scan. Issues, files and archives wait in one queue in walk order.
//! Only the calling thread calls the consumer callback, and it takes events
//! from the head of that queue. So the callback sees the same events, in the
//! same order, as when the calling thread reads every file itself.
//!
//! Memory stays bounded. The queue holds at most `threads` times
//! [`READ_AHEAD_PER_THREAD`] files and issues, each file holds at most one
//! finished event, and each reader builds at most one more while it waits.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, Scope};

use super::{DirectorySource, READ_AHEAD_PER_THREAD, WalkSink};
use crate::{
    CallbackError, Cancellation, SourceControl, SourceError, SourceEvent, SourceIssue, SourceStage,
};

/// Walks `source` on this thread and reads its files on up to `threads`
/// reader threads.
pub(super) fn walk(
    source: &DirectorySource,
    threads: NonZeroUsize,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    walk_with(source, threads.get(), cancellation, emit)
}

/// Like [`walk`], but `threads` may be 0, as when no reader thread could
/// start, so every file is read on this thread.
fn walk_with(
    source: &DirectorySource,
    threads: usize,
    cancellation: &dyn Cancellation,
    emit: &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
) -> Result<SourceControl, SourceError> {
    let shared = Shared::default();
    thread::scope(|scope| {
        let mut sink = OrderedSink {
            source,
            shared: &shared,
            scope,
            cancellation,
            emit,
            nominal: Vec::new(),
            threads,
            started: 0,
            window: threads.max(1).saturating_mul(READ_AHEAD_PER_THREAD),
            queued: 0,
            next_sequence: 0,
            outcome: None,
        };
        let walked = source.walk(&source.root, None, cancellation, &mut sink);
        sink.finish(walked)
    })
}

/// State shared by the walking thread and the reader threads.
#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    /// Wakes the walking thread when the head of the queue changes.
    head: Condvar,
    /// Wakes reader threads that wait for a job.
    jobs: Condvar,
    /// Wakes reader threads that wait to hand over an event.
    space: Condvar,
    /// Set when reading ends, so readers stop between bounded steps.
    stopped: AtomicBool,
}

#[derive(Default)]
struct State {
    /// Sequence number of `items[0]`.
    base: u64,
    /// Walk results that have not reached the callback, in walk order.
    items: VecDeque<Item>,
    /// Files that no reader has taken yet, in walk order.
    jobs: VecDeque<Job>,
    idle_readers: usize,
    space_waiters: usize,
    stopped: bool,
    reader_panicked: bool,
}

/// One walk result in the queue.
enum Item {
    Issue(SourceIssue),
    /// A file read on the walking thread when it reaches the head: an
    /// archive, or any file when no reader thread could start.
    Inline {
        target: PathBuf,
        alias: Option<PathBuf>,
    },
    File(Slot),
}

/// What a reader has produced for one file and the callback has not seen.
#[derive(Default)]
struct Slot {
    event: Option<SourceEvent>,
    done: Option<Result<SourceControl, SourceError>>,
}

struct Job {
    sequence: u64,
    target: PathBuf,
    alias: Option<PathBuf>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends reading. Readers stop at their next check and take no more jobs.
    fn stop(&self) {
        let mut state = self.lock();
        state.stopped = true;
        self.stopped.store(true, Ordering::Release);
        drop(state);
        self.jobs.notify_all();
        self.space.notify_all();
        self.head.notify_all();
    }

    fn next_job(&self) -> Option<Job> {
        let mut state = self.lock();
        loop {
            if state.stopped {
                return None;
            }
            if let Some(job) = state.jobs.pop_front() {
                return Some(job);
            }
            state.idle_readers += 1;
            state = self
                .jobs
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
            state.idle_readers -= 1;
        }
    }

    /// Hands one event of file `sequence` to the walking thread. Waits while
    /// the previous event of that file has not reached the callback.
    fn hand_over(&self, sequence: u64, event: SourceEvent) -> Result<SourceControl, CallbackError> {
        let mut state = self.lock();
        loop {
            let at_head = sequence == state.base;
            let Some(slot) = state.slot(sequence) else {
                return Err(CallbackError::new("directory reading stopped"));
            };
            if slot.event.is_none() {
                slot.event = Some(event);
                drop(state);
                if at_head {
                    self.head.notify_one();
                }
                return Ok(SourceControl::Continue);
            }
            state.space_waiters += 1;
            state = self
                .space
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
            state.space_waiters -= 1;
        }
    }

    fn finish(&self, sequence: u64, result: Result<SourceControl, SourceError>) {
        let mut state = self.lock();
        let at_head = sequence == state.base;
        if let Some(slot) = state.slot(sequence) {
            slot.done = Some(result);
            drop(state);
            if at_head {
                self.head.notify_one();
            }
        }
    }
}

impl State {
    /// Returns the slot of file `sequence`, or `None` once reading stopped.
    /// A file stays in the queue until its reader finishes it.
    fn slot(&mut self, sequence: u64) -> Option<&mut Slot> {
        if self.stopped {
            return None;
        }
        let index = usize::try_from(sequence.checked_sub(self.base)?).ok()?;
        match self.items.get_mut(index) {
            Some(Item::File(slot)) => Some(slot),
            _ => None,
        }
    }
}

/// Cancellation seen by readers: the caller's, or the end of reading.
struct ReaderCancellation<'a> {
    outer: &'a dyn Cancellation,
    stopped: &'a AtomicBool,
}

impl Cancellation for ReaderCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.stopped.load(Ordering::Acquire) || self.outer.is_cancelled()
    }
}

/// Tells the walking thread when a reader thread unwinds, so it never waits
/// for a file that no reader will finish.
struct PanicNotice<'a>(&'a Shared);

impl Drop for PanicNotice<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.lock().reader_panicked = true;
            self.0.head.notify_all();
        }
    }
}

fn read_files(source: &DirectorySource, shared: &Shared, cancellation: &dyn Cancellation) {
    let _notice = PanicNotice(shared);
    let cancellation = ReaderCancellation {
        outer: cancellation,
        stopped: &shared.stopped,
    };
    let mut nominal = Vec::new();
    while let Some(job) = shared.next_job() {
        let sequence = job.sequence;
        let result = source.visit_file(
            job.target,
            job.alias,
            &mut nominal,
            &cancellation,
            &mut |event| shared.hand_over(sequence, event),
        );
        shared.finish(sequence, result);
    }
}

/// What the head of the queue allows the walking thread to do next.
enum Head {
    Empty,
    Event(SourceEvent),
    Pop,
    Pending,
}

/// The walk sink on the calling thread. It queues walk results, starts
/// readers and forwards events to the callback in walk order.
struct OrderedSink<'scope, 'env, 'e> {
    source: &'env DirectorySource,
    shared: &'env Shared,
    scope: &'scope Scope<'scope, 'env>,
    cancellation: &'env dyn Cancellation,
    emit: &'e mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
    /// Read buffer for archives, which this thread reads.
    nominal: Vec<u8>,
    threads: usize,
    started: usize,
    window: usize,
    queued: usize,
    next_sequence: u64,
    /// The first stop or error, in walk order.
    outcome: Option<Result<SourceControl, SourceError>>,
}

impl OrderedSink<'_, '_, '_> {
    fn result(&self) -> Result<SourceControl, SourceError> {
        self.outcome.clone().unwrap_or(Ok(SourceControl::Continue))
    }

    /// Records the first stop or error and ends reading.
    fn end(&mut self, outcome: Result<SourceControl, SourceError>) {
        if outcome == Ok(SourceControl::Continue) || self.outcome.is_some() {
            return;
        }
        self.outcome = Some(outcome);
        self.shared.stop();
    }

    fn deliver(&mut self, event: SourceEvent) {
        let outcome = (self.emit)(event).map_err(SourceError::Callback);
        self.end(outcome);
    }

    /// Starts one more reader thread when every started reader is busy.
    /// Returns whether any reader runs.
    fn ensure_reader(&mut self, waiting_jobs: usize, idle_readers: usize) -> bool {
        if self.started < self.threads && waiting_jobs >= idle_readers {
            let (source, shared, cancellation) = (self.source, self.shared, self.cancellation);
            let spawned = thread::Builder::new()
                .name(format!("rustleaks-reader-{}", self.started))
                .spawn_scoped(self.scope, move || read_files(source, shared, cancellation));
            match spawned {
                Ok(_) => self.started += 1,
                // Reading continues on the threads that did start, or on
                // this thread when none did.
                Err(_) => self.threads = self.started,
            }
        }
        self.started > 0
    }

    fn enqueue(&mut self, item: Item) {
        let mut state = self.shared.lock();
        state.items.push_back(item);
        drop(state);
        self.next_sequence += 1;
        self.queued += 1;
    }

    /// Forwards what is ready at the head of the queue. Waits for the head
    /// only while the queue is full.
    fn progress(&mut self) -> Result<SourceControl, SourceError> {
        while self.outcome.is_none() && self.queued > 0 {
            let wait = self.queued >= self.window;
            if !self.step(wait) {
                break;
            }
        }
        self.result()
    }

    /// Handles the head of the queue. Returns false when the head is not
    /// ready and `wait` is false, or when the queue is empty.
    fn step(&mut self, wait: bool) -> bool {
        let mut state = self.shared.lock();
        loop {
            if state.reader_panicked {
                drop(state);
                self.end(Err(SourceError::terminal(
                    SourceStage::Read,
                    None,
                    "directory reader thread panicked",
                )));
                return true;
            }
            if !state.items.is_empty() && self.cancellation.is_cancelled() {
                // As in a serial walk, no event reaches the callback after
                // cancellation is seen.
                drop(state);
                self.end(Err(SourceError::Cancelled));
                return true;
            }
            let head = match state.items.front_mut() {
                None => Head::Empty,
                Some(Item::File(slot)) => {
                    if let Some(event) = slot.event.take() {
                        Head::Event(event)
                    } else if slot.done.is_some() {
                        Head::Pop
                    } else {
                        Head::Pending
                    }
                }
                Some(Item::Issue(_) | Item::Inline { .. }) => Head::Pop,
            };
            match head {
                Head::Empty => return false,
                Head::Event(event) => {
                    let waiters = state.space_waiters > 0;
                    drop(state);
                    if waiters {
                        self.shared.space.notify_all();
                    }
                    self.deliver(event);
                    return true;
                }
                Head::Pop => {
                    let item = state.items.pop_front();
                    state.base += 1;
                    drop(state);
                    self.queued -= 1;
                    if let Some(item) = item {
                        self.handle(item);
                    }
                    return true;
                }
                Head::Pending if !wait => return false,
                Head::Pending => {
                    state = self
                        .shared
                        .head
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            }
        }
    }

    fn handle(&mut self, item: Item) {
        match item {
            Item::Issue(issue) => self.deliver(SourceEvent::Issue(issue)),
            Item::Inline { target, alias } => {
                let outcome = self.source.visit_file(
                    target,
                    alias,
                    &mut self.nominal,
                    self.cancellation,
                    self.emit,
                );
                self.end(outcome);
            }
            Item::File(slot) => {
                if let Some(outcome) = slot.done {
                    self.end(outcome);
                }
            }
        }
    }

    /// Forwards everything still queued, unless the walk was cancelled, and
    /// returns the first stop or error in walk order.
    fn finish(
        mut self,
        walked: Result<SourceControl, SourceError>,
    ) -> Result<SourceControl, SourceError> {
        if walked != Err(SourceError::Cancelled) {
            while self.outcome.is_none() && self.queued > 0 {
                self.step(true);
            }
        }
        self.shared.stop();
        self.outcome.take().unwrap_or(walked)
    }
}

impl WalkSink for OrderedSink<'_, '_, '_> {
    fn issue(&mut self, issue: SourceIssue) -> Result<SourceControl, SourceError> {
        if self.outcome.is_none() {
            if self.queued == 0 {
                self.deliver(SourceEvent::Issue(issue));
            } else {
                self.enqueue(Item::Issue(issue));
            }
        }
        self.progress()
    }

    fn file(
        &mut self,
        target: PathBuf,
        alias: Option<PathBuf>,
    ) -> Result<SourceControl, SourceError> {
        if self.outcome.is_some() {
            return self.result();
        }
        if self.source.reads_as_archive(&target) {
            self.enqueue(Item::Inline { target, alias });
            return self.progress();
        }
        let (waiting_jobs, idle_readers) = {
            let state = self.shared.lock();
            (state.jobs.len(), state.idle_readers)
        };
        if !self.ensure_reader(waiting_jobs, idle_readers) {
            self.enqueue(Item::Inline { target, alias });
            return self.progress();
        }
        let sequence = self.next_sequence;
        let mut state = self.shared.lock();
        state.items.push_back(Item::File(Slot::default()));
        state.jobs.push_back(Job {
            sequence,
            target,
            alias,
        });
        drop(state);
        self.shared.jobs.notify_one();
        self.next_sequence += 1;
        self.queued += 1;
        self.progress()
    }
}

impl Drop for OrderedSink<'_, '_, '_> {
    fn drop(&mut self) {
        // Also on unwinding, so the scope never waits for a blocked reader.
        self.shared.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::{CancellationToken, DirectoryOptions, Source};

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rustleaks-reader-unit-{label}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            for folder in 0..3 {
                for file in 0..20 {
                    let directory = path.join(format!("d{folder}"));
                    fs::create_dir_all(&directory).unwrap();
                    fs::write(
                        directory.join(format!("f{file:02}.txt")),
                        format!("line {folder} {file}\n"),
                    )
                    .unwrap();
                }
            }
            fs::write(path.join("d1/oversize.txt"), "x".repeat(64)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn source(root: &Path) -> DirectorySource {
        DirectorySource::with_options(
            root,
            DirectoryOptions::default()
                .max_file_size(Some(32))
                .emit_limit_issues(true),
        )
    }

    fn events(
        visit: impl FnOnce(
            &mut dyn FnMut(SourceEvent) -> Result<SourceControl, CallbackError>,
        ) -> Result<SourceControl, SourceError>,
    ) -> Vec<SourceEvent> {
        let mut events = Vec::new();
        let result = visit(&mut |event| {
            events.push(event);
            Ok(SourceControl::Continue)
        });
        assert_eq!(result, Ok(SourceControl::Continue));
        events
    }

    #[test]
    fn files_are_read_on_the_walking_thread_when_no_reader_starts() {
        let tree = TempTree::new("inline");
        let cancellation = CancellationToken::new();
        let expected = events(|emit| source(&tree.0).visit(&cancellation, emit));
        assert_eq!(expected.len(), 61);
        let source = source(&tree.0);
        let observed = events(|emit| walk_with(&source, 0, &cancellation, emit));
        assert!(observed == expected);
    }

    #[test]
    fn a_reader_that_unwinds_marks_the_queue() {
        let shared = Shared::default();
        let unwound = thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _notice = PanicNotice(&shared);
                    panic!("synthetic reader failure");
                })
                .join()
                .is_err()
        });
        assert!(unwound);
        assert!(shared.lock().reader_panicked);
    }
}
