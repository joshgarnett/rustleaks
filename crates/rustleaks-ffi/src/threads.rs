//! Threads with a known stack size for engine construction and scans.
//!
//! Core compiles a pattern with more than 200 groups on its own thread with
//! a 32 MiB stack, and every other pattern on the thread that builds the
//! engine or runs the first search. A Go program on musl calls C on threads
//! with a 128 KiB stack, and other hosts can be as small. A pattern with 200
//! nested groups needs more than that in an unoptimized build. So the
//! library builds each engine on a new thread and, by default, runs scans on
//! threads that the engine owns, all with [`SCAN_STACK_BYTES`] of stack.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;

use crate::abi::{ERROR_ENGINE, ERROR_PANIC};
use crate::handles::{EngineInner, FfiError, ResultHandle, ScanJob};

/// Stack size of the threads that build engines and run scans: the usual
/// main thread stack. Only the pages a thread uses are committed.
pub const SCAN_STACK_BYTES: usize = 8 << 20;

fn thread_error(error: &std::io::Error) -> FfiError {
    FfiError::new(
        ERROR_ENGINE,
        format!("cannot start a rustleaks thread: {error}"),
    )
}

/// Runs `work` on a new thread with [`SCAN_STACK_BYTES`] of stack and waits
/// for it.
///
/// # Errors
///
/// Returns `ERROR_ENGINE` when the thread cannot start and `ERROR_PANIC`
/// when `work` panics.
pub(crate) fn on_scan_stack<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, FfiError> {
    std::thread::Builder::new()
        .name("rustleaks-build".into())
        .stack_size(SCAN_STACK_BYTES)
        .spawn(work)
        .map_err(|error| thread_error(&error))?
        // `join` waits with `pthread_join` on Unix, not with the thread parker.
        .join()
        .map_err(|_| FfiError::panic())
}

type Task = Box<dyn FnOnce() + Send + 'static>;

/// The result of one scan task, which the calling thread waits for.
///
/// The wait uses a `Mutex` and a `Condvar`, which are pthread objects on
/// Apple platforms. It must not use a channel, `thread::park` or a contended
/// `Once`: those park the thread through the standard library's parker,
/// which on Apple creates a libdispatch semaphore for the thread the first
/// time it parks. A child forked from that thread inherits the semaphore
/// but cannot use it, and its first scan on that thread would crash.
#[derive(Default)]
struct Reply {
    slot: Mutex<Option<Result<ResultHandle, FfiError>>>,
    ready: Condvar,
}

impl Reply {
    fn put(&self, outcome: Result<ResultHandle, FfiError>) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
        self.ready.notify_one();
    }

    /// Waits until the task sent its outcome, or was dropped without one.
    fn wait(&self) -> Result<ResultHandle, FfiError> {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(outcome) = slot.take() {
                return outcome;
            }
            slot = self
                .ready
                .wait(slot)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// The scan thread's side of a [`Reply`]. If the task is dropped before it
/// runs, for example because the queue closed, the reply gets an error, so
/// the caller never waits forever.
struct ReplySender {
    reply: Option<Arc<Reply>>,
}

impl ReplySender {
    fn send(&mut self, outcome: Result<ResultHandle, FfiError>) {
        if let Some(reply) = self.reply.take() {
            reply.put(outcome);
        }
    }
}

impl Drop for ReplySender {
    fn drop(&mut self) {
        self.send(Err(FfiError::new(
            ERROR_PANIC,
            "a rustleaks scan thread stopped",
        )));
    }
}

/// The scan threads of one engine. Dropping it closes the queue and joins
/// every thread, which finish the task they run first.
#[derive(Debug)]
pub(crate) struct ScanThreads {
    queue: Option<Sender<Task>>,
    threads: Vec<JoinHandle<()>>,
}

impl ScanThreads {
    /// Starts `count` scan threads, at least one.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_ENGINE` when a thread cannot start. The threads that
    /// started are joined first.
    pub(crate) fn start(count: usize) -> Result<Self, FfiError> {
        Self::start_with(count, |work| {
            std::thread::Builder::new()
                .name("rustleaks-scan".into())
                .stack_size(SCAN_STACK_BYTES)
                .spawn(work)
        })
    }

    /// [`ScanThreads::start`] with the function that starts one thread, so
    /// that a test can make a start fail.
    fn start_with(
        count: usize,
        mut spawn: impl FnMut(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<Self, FfiError> {
        let (sender, receiver) = mpsc::channel::<Task>();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut threads = Self {
            queue: Some(sender),
            threads: Vec::new(),
        };
        for _ in 0..count.max(1) {
            let receiver = Arc::clone(&receiver);
            // On failure `threads` drops, which closes the queue and joins
            // the threads that started.
            let thread =
                spawn(Box::new(move || serve(&receiver))).map_err(|error| thread_error(&error))?;
            threads.threads.push(thread);
        }
        Ok(threads)
    }

    /// Runs `job` on a scan thread and waits for its result on a [`Reply`],
    /// never through the thread parker.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_PANIC` when the scan panics or its thread stopped.
    pub(crate) fn run(
        &self,
        engine: Arc<EngineInner>,
        job: ScanJob,
    ) -> Result<ResultHandle, FfiError> {
        self.call(move || Ok(engine.run(job)))
    }

    /// Runs `work` on a scan thread and waits for its outcome. A panic in
    /// `work` becomes `ERROR_PANIC`, and so does a task that never runs.
    fn call(
        &self,
        work: impl FnOnce() -> Result<ResultHandle, FfiError> + Send + 'static,
    ) -> Result<ResultHandle, FfiError> {
        let reply = Arc::new(Reply::default());
        let mut sender = ReplySender {
            reply: Some(Arc::clone(&reply)),
        };
        let task: Task = Box::new(move || {
            let outcome =
                catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|_| Err(FfiError::panic()));
            sender.send(outcome);
        });
        // A task that cannot be queued is dropped here, and its sender then
        // fills the reply with an error, so the wait below returns.
        if let Some(queue) = self.queue.as_ref() {
            let _ = queue.send(task);
        } else {
            drop(task);
        }
        reply.wait()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.threads.len()
    }
}

impl Drop for ScanThreads {
    fn drop(&mut self) {
        drop(self.queue.take());
        for thread in self.threads.drain(..) {
            // A scan thread catches every task panic, so it cannot fail.
            let _ = thread.join();
        }
    }
}

/// Runs tasks until the queue closes.
fn serve(receiver: &Mutex<Receiver<Task>>) {
    loop {
        let task = receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        match task {
            Ok(task) => task(),
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_runs_on_a_thread_with_the_scan_stack_and_panics_are_errors() {
        assert_eq!(on_scan_stack(|| 7).unwrap(), 7);
        let name = on_scan_stack(|| std::thread::current().name().map(str::to_owned)).unwrap();
        assert_eq!(name.as_deref(), Some("rustleaks-build"));
        let error = on_scan_stack(|| panic!("synthetic")).unwrap_err();
        assert_eq!(error.kind(), ERROR_PANIC);
    }

    #[test]
    fn a_reply_returns_what_was_sent_or_an_error_when_the_task_is_dropped() {
        let reply = Arc::new(Reply::default());
        let mut sender = ReplySender {
            reply: Some(Arc::clone(&reply)),
        };
        let waiter = {
            let reply = Arc::clone(&reply);
            std::thread::spawn(move || reply.wait().unwrap_err())
        };
        sender.send(Err(FfiError::new(ERROR_ENGINE, "sent")));
        drop(sender);
        let error = waiter.join().unwrap();
        assert_eq!((error.kind(), error.message()), (ERROR_ENGINE, "sent"));

        let reply = Arc::new(Reply::default());
        drop(ReplySender {
            reply: Some(Arc::clone(&reply)),
        });
        let error = reply.wait().unwrap_err();
        assert_eq!(error.kind(), ERROR_PANIC);
        assert_eq!(error.message(), "a rustleaks scan thread stopped");
    }

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn scan_threads_start_at_least_one() {
        assert_eq!(ScanThreads::start(0).unwrap().len(), 1);
        assert_eq!(ScanThreads::start(3).unwrap().len(), 3);
    }

    #[test]
    fn drop_waits_for_the_running_task_and_joins_every_thread() {
        let threads = ScanThreads::start(2).unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let started = Arc::new(Reply::default());
        {
            let finished = Arc::clone(&finished);
            let started = Arc::clone(&started);
            let task: Task = Box::new(move || {
                started.put(Err(FfiError::new(ERROR_ENGINE, "started")));
                // The drop below must wait for this task, however long it
                // takes; the pause only makes a missing join visible.
                std::thread::sleep(Duration::from_millis(20));
                finished.store(true, Ordering::SeqCst);
            });
            threads.queue.as_ref().unwrap().send(task).unwrap();
        }
        // The task is running when `wait` returns.
        assert!(started.wait().is_err());
        drop(threads);
        assert!(finished.load(Ordering::SeqCst));
    }

    #[test]
    fn call_returns_the_outcome_a_panic_or_a_stop() {
        let threads = ScanThreads::start(1).unwrap();
        let error = threads
            .call(|| Err(FfiError::new(ERROR_ENGINE, "sent")))
            .unwrap_err();
        assert_eq!((error.kind(), error.message()), (ERROR_ENGINE, "sent"));
        let error = threads.call(|| panic!("synthetic")).unwrap_err();
        assert_eq!(error.kind(), ERROR_PANIC);

        // With the queue closed, the task is dropped unrun and the caller
        // still gets an answer.
        let mut closed = ScanThreads::start(1).unwrap();
        drop(closed.queue.take());
        let error = closed
            .call(|| Err(FfiError::new(ERROR_ENGINE, "never")))
            .unwrap_err();
        assert_eq!(error.message(), "a rustleaks scan thread stopped");
    }

    #[test]
    fn a_failed_thread_start_joins_the_threads_that_started() {
        let started = Arc::new(AtomicUsize::new(0));
        let exited = Arc::new(AtomicUsize::new(0));
        let result = {
            let started = Arc::clone(&started);
            let exited = Arc::clone(&exited);
            ScanThreads::start_with(3, move |work| {
                if started.fetch_add(1, Ordering::SeqCst) == 1 {
                    return Err(std::io::Error::other("synthetic start failure"));
                }
                let exited = Arc::clone(&exited);
                std::thread::Builder::new().spawn(move || {
                    work();
                    exited.fetch_add(1, Ordering::SeqCst);
                })
            })
        };
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ERROR_ENGINE);
        assert_eq!(
            error.message(),
            "cannot start a rustleaks thread: synthetic start failure"
        );
        // The second start failed, so the third was not tried, and the first
        // thread was joined before `start_with` returned.
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(exited.load(Ordering::SeqCst), 1);
    }
}
