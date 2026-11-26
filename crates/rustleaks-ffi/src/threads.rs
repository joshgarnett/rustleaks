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
use std::sync::{Arc, Mutex, PoisonError};
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
        .join()
        .map_err(|_| FfiError::panic())
}

type Task = Box<dyn FnOnce() + Send + 'static>;

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
        let (sender, receiver) = mpsc::channel::<Task>();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut threads = Self {
            queue: Some(sender),
            threads: Vec::new(),
        };
        for _ in 0..count.max(1) {
            let receiver = Arc::clone(&receiver);
            let thread = std::thread::Builder::new()
                .name("rustleaks-scan".into())
                .stack_size(SCAN_STACK_BYTES)
                .spawn(move || serve(&receiver))
                .map_err(|error| thread_error(&error))?;
            threads.threads.push(thread);
        }
        Ok(threads)
    }

    /// Runs `job` on a scan thread and waits for its result.
    ///
    /// # Errors
    ///
    /// Returns `ERROR_PANIC` when the scan panics or its thread stopped.
    pub(crate) fn run(
        &self,
        engine: Arc<EngineInner>,
        job: ScanJob,
    ) -> Result<ResultHandle, FfiError> {
        let stopped = || FfiError::new(ERROR_PANIC, "a rustleaks scan thread stopped");
        let (reply, result) = mpsc::sync_channel(1);
        let task: Task = Box::new(move || {
            let outcome =
                catch_unwind(AssertUnwindSafe(|| engine.run(job))).map_err(|_| FfiError::panic());
            // The caller waits for this reply; it cannot have gone away.
            let _ = reply.send(outcome);
        });
        self.queue
            .as_ref()
            .ok_or_else(stopped)?
            .send(task)
            .map_err(|_| stopped())?;
        result.recv().map_err(|_| stopped())?
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
    fn scan_threads_start_at_least_one_and_join_on_drop() {
        let threads = ScanThreads::start(0).unwrap();
        assert_eq!(threads.len(), 1);
        drop(threads);
        let threads = ScanThreads::start(3).unwrap();
        assert_eq!(threads.len(), 3);
    }
}
