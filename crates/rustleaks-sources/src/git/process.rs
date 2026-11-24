use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread;

use crate::process::CHILD_POLL;
use crate::{Cancellation, SourceControl, SourceError, SourceStage};

pub(super) const STDOUT_CHUNK_BYTES: usize = 64 * 1024;
const STDOUT_QUEUE_CHUNKS: usize = 16;

/// A started Git child with its output pipes, and its input pipe when the
/// command reads standard input.
struct GitChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

fn spawn_git(
    program: &OsStr,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    stage: SourceStage,
    with_input: bool,
    clear_attribute_source: bool,
) -> Result<GitChild, SourceError> {
    let mut command = Command::new(program);
    command.args(arguments).envs(environment.iter().cloned());
    if clear_attribute_source {
        command.env_remove("GIT_ATTR_SOURCE");
    }
    command
        .stdin(if with_input {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = crate::process::spawn(&mut command).map_err(|error| {
        SourceError::terminal(stage, None, format!("could not start Git: {error}"))
    })?;
    let stdin = child.stdin.take();
    if with_input && stdin.is_none() {
        stop_and_reap(&mut child, stage, "after a missing stdin pipe")?;
        return Err(SourceError::terminal(
            stage,
            None,
            "Git standard input pipe was unavailable",
        ));
    }
    let Some(stdout) = child.stdout.take() else {
        stop_and_reap(&mut child, stage, "after a missing stdout pipe")?;
        return Err(SourceError::terminal(
            stage,
            None,
            "Git standard output pipe was unavailable",
        ));
    };
    let Some(stderr) = child.stderr.take() else {
        stop_and_reap(&mut child, stage, "after a missing stderr pipe")?;
        return Err(SourceError::terminal(
            stage,
            None,
            "Git standard error pipe was unavailable",
        ));
    };
    Ok(GitChild {
        child,
        stdin,
        stdout,
        stderr,
    })
}

/// Output of a streamed Git command after its standard output closed.
pub(super) struct StreamedOutput {
    pub(super) stderr: Vec<u8>,
    pub(super) stderr_limited: bool,
    /// The consumer stopped the stream; Git was stopped and reaped.
    pub(super) stopped: bool,
    pub(super) status: Option<ExitStatus>,
}

enum StreamEnd {
    Exited(ExitStatus),
    Stopped,
    Cancelled,
    StderrLimited,
    Failed(SourceError),
}

/// Runs Git and passes its standard output to `on_chunk` while Git runs.
///
/// A reader thread fills a small bounded queue, so Git waits while the
/// consumer is busy. Standard error keeps its own bounded reader. Every
/// early end stops and reaps Git before the reader threads are joined.
#[cfg(any(feature = "archives", test))]
pub(super) fn stream_command(
    program: &OsStr,
    arguments: &[OsString],
    stderr_limit: usize,
    environment: &[(OsString, OsString)],
    cancellation: &dyn Cancellation,
    stage: SourceStage,
    on_chunk: &mut dyn FnMut(&[u8]) -> Result<SourceControl, SourceError>,
) -> Result<StreamedOutput, SourceError> {
    stream_command_with(
        program,
        arguments,
        CommandIo {
            input: None,
            stderr: &OutputBudget::new(stderr_limit),
            clear_attribute_source: false,
        },
        environment,
        cancellation,
        stage,
        &mut |chunk| on_chunk(&chunk),
    )
}

/// Standard input and the standard error budget of one streamed command.
#[derive(Clone, Copy)]
pub(super) struct CommandIo<'a> {
    /// Bytes written to standard input, which is then closed. Without input,
    /// standard input is empty.
    pub(super) input: Option<&'a [u8]>,
    /// Can be shared with other Git processes of the same scan.
    pub(super) stderr: &'a OutputBudget,
    /// Removes `GIT_ATTR_SOURCE` from the environment of a command that sets
    /// `attr.tree`, since the variable takes precedence over the setting.
    pub(super) clear_attribute_source: bool,
}

/// Runs Git like [`stream_command`], with optional standard input and a
/// standard error budget that several commands can share. `on_chunk` owns
/// each chunk.
pub(super) fn stream_command_with(
    program: &OsStr,
    arguments: &[OsString],
    io: CommandIo<'_>,
    environment: &[(OsString, OsString)],
    cancellation: &dyn Cancellation,
    stage: SourceStage,
    on_chunk: &mut dyn FnMut(Vec<u8>) -> Result<SourceControl, SourceError>,
) -> Result<StreamedOutput, SourceError> {
    let GitChild {
        mut child,
        stdin,
        stdout,
        stderr,
    } = spawn_git(
        program,
        arguments,
        environment,
        stage,
        io.input.is_some(),
        io.clear_attribute_source,
    )?;
    let budget = io.stderr;
    thread::scope(|scope| {
        // A separate writer never blocks the stdout reader. Dropping the pipe
        // after the input ends it.
        let writer = io.input.zip(stdin).map(|(input, mut stdin)| {
            scope.spawn(move || stdin.write_all(input).and_then(|()| stdin.flush()))
        });
        let (sender, receiver) = mpsc::sync_channel(STDOUT_QUEUE_CHUNKS);
        let stdout_reader = scope.spawn(move || read_chunks(stdout, &sender));
        let stderr_reader = scope.spawn(move || read_bounded_and_drain(stderr, budget));
        let end = drive_stream(&mut child, &receiver, budget, cancellation, stage, on_chunk);
        // Dropping the receiver wakes a reader that waits on a full queue.
        drop(receiver);
        match &end {
            StreamEnd::Exited(_) => {}
            StreamEnd::Cancelled => stop_and_reap(&mut child, stage, "after cancellation")?,
            StreamEnd::StderrLimited => stop_and_reap(&mut child, stage, "after an output limit")?,
            StreamEnd::Stopped => stop_and_reap(&mut child, stage, "after the consumer stopped")?,
            StreamEnd::Failed(_) => stop_and_reap(&mut child, stage, "after a stream failure")?,
        }
        let written = writer.map(|writer| {
            writer
                .join()
                .map_err(|_| SourceError::terminal(stage, None, "Git stdin writer panicked"))
        });
        stdout_reader
            .join()
            .map_err(|_| SourceError::terminal(stage, None, "Git stdout reader panicked"))?;
        let (stderr, stderr_limited) = stderr_reader
            .join()
            .map_err(|_| SourceError::terminal(stage, None, "Git stderr reader panicked"))?
            .map_err(|error| {
                SourceError::terminal(stage, None, format!("could not read Git stderr: {error}"))
            })?;
        let (status, stopped) = match end {
            StreamEnd::Exited(status) => (Some(status), false),
            StreamEnd::Cancelled => return Err(SourceError::Cancelled),
            StreamEnd::Failed(error) => return Err(error),
            StreamEnd::StderrLimited => (None, false),
            StreamEnd::Stopped => (None, true),
        };
        // A Git that read only part of its input can still exit successfully,
        // so a failed write fails the command.
        if let Some(written) = written
            && status.is_some_and(|status| status.success())
        {
            written?.map_err(|error| {
                SourceError::terminal(stage, None, format!("could not write Git stdin: {error}"))
            })?;
        }
        Ok(StreamedOutput {
            stderr,
            stderr_limited,
            stopped,
            status,
        })
    })
}

fn drive_stream(
    child: &mut Child,
    receiver: &mpsc::Receiver<io::Result<Vec<u8>>>,
    stderr: &OutputBudget,
    cancellation: &dyn Cancellation,
    stage: SourceStage,
    on_chunk: &mut dyn FnMut(Vec<u8>) -> Result<SourceControl, SourceError>,
) -> StreamEnd {
    loop {
        if cancellation.is_cancelled() {
            return StreamEnd::Cancelled;
        }
        if stderr.is_exceeded() {
            return StreamEnd::StderrLimited;
        }
        match receiver.recv_timeout(CHILD_POLL) {
            Ok(Ok(chunk)) => match on_chunk(chunk) {
                Ok(SourceControl::Continue) => {}
                Ok(SourceControl::Stop) => return StreamEnd::Stopped,
                Err(error) => return StreamEnd::Failed(error),
            },
            Ok(Err(error)) => {
                return StreamEnd::Failed(SourceError::terminal(
                    stage,
                    None,
                    format!("could not read Git stdout: {error}"),
                ));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    loop {
        if cancellation.is_cancelled() {
            return StreamEnd::Cancelled;
        }
        if stderr.is_exceeded() {
            return StreamEnd::StderrLimited;
        }
        match child.try_wait() {
            Ok(Some(status)) => return StreamEnd::Exited(status),
            Ok(None) => thread::sleep(CHILD_POLL),
            Err(error) => {
                return StreamEnd::Failed(SourceError::terminal(
                    stage,
                    None,
                    format!("could not wait for Git: {error}"),
                ));
            }
        }
    }
}

/// Sends standard output in chunks until end of file, a read error, or a
/// closed receiver.
fn read_chunks(mut reader: impl Read, sender: &SyncSender<io::Result<Vec<u8>>>) {
    loop {
        let mut chunk = Vec::new();
        if let Err(error) = chunk.try_reserve_exact(STDOUT_CHUNK_BYTES) {
            let _ = sender.send(Err(io::Error::other(format!(
                "could not reserve command output: {error}"
            ))));
            return;
        }
        chunk.resize(STDOUT_CHUNK_BYTES, 0);
        match reader.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => {
                chunk.truncate(read);
                if sender.send(Ok(chunk)).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = sender.send(Err(error));
                return;
            }
        }
    }
}

pub(super) fn stop_and_reap(
    child: &mut impl GitChildLifecycle,
    stage: SourceStage,
    context: &str,
) -> Result<(), SourceError> {
    let kill_error = child.terminate().err().filter(|error| {
        !matches!(
            error.kind(),
            io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
        )
    });
    let wait_error = child.reap().err();
    match (kill_error, wait_error) {
        (None, None) => Ok(()),
        (kill, wait) => Err(SourceError::terminal(
            stage,
            None,
            format!("could not clean up Git {context}: kill={kill:?}; wait={wait:?}"),
        )),
    }
}

pub(super) trait GitChildLifecycle {
    fn terminate(&mut self) -> io::Result<()>;
    fn reap(&mut self) -> io::Result<()>;
}

impl GitChildLifecycle for std::process::Child {
    fn terminate(&mut self) -> io::Result<()> {
        self.kill()
    }

    fn reap(&mut self) -> io::Result<()> {
        self.wait().map(|_| ())
    }
}

pub(super) fn git_exit_message(status: Option<ExitStatus>, stderr: &[u8]) -> String {
    let status = status.map_or_else(|| "terminated".to_owned(), |status| status.to_string());
    if stderr.is_empty() {
        format!("Git exited unsuccessfully ({status}) with empty stderr")
    } else {
        format!(
            "Git exited unsuccessfully ({status}); bounded stderr: {}",
            String::from_utf8_lossy(stderr)
        )
    }
}

/// Output bytes that one or more Git processes may still keep.
///
/// Readers take bytes from the budget as they read. Bytes beyond it are read
/// and dropped, and the budget is marked exceeded.
pub(super) struct OutputBudget {
    remaining: AtomicUsize,
    exceeded: AtomicBool,
}

impl OutputBudget {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(limit),
            exceeded: AtomicBool::new(false),
        }
    }

    /// Takes up to `wanted` bytes and returns how many were taken.
    fn take(&self, wanted: usize) -> usize {
        let previous = self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining - remaining.min(wanted))
            })
            .unwrap_or_else(|remaining| remaining);
        let taken = previous.min(wanted);
        if taken < wanted {
            self.exceeded.store(true, Ordering::Release);
        }
        taken
    }

    fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }

    pub(super) fn is_exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Acquire)
    }
}

pub(super) fn read_bounded_and_drain(
    mut reader: impl Read,
    budget: &OutputBudget,
) -> io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(budget.remaining().min(64 * 1024))
        .map_err(|error| io::Error::other(format!("could not reserve command output: {error}")))?;
    let mut buffer = [0_u8; 8192];
    let mut limited = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let keep = budget.take(read);
        if keep > 0 {
            retained.try_reserve(keep).map_err(|error| {
                io::Error::other(format!("could not grow command output: {error}"))
            })?;
            retained.extend_from_slice(&buffer[..keep]);
        }
        limited |= keep < read;
    }
    Ok((retained, limited))
}

pub(super) fn first_non_ignored_stderr(stderr: &[u8]) -> Option<&[u8]> {
    if stderr.is_empty() {
        return None;
    }
    let mut start = 0;
    loop {
        let end = stderr[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(stderr.len(), |relative| start + relative);
        let line = stderr[start..end]
            .strip_suffix(b"\r")
            .unwrap_or(&stderr[start..end]);
        let ignored = [
            b"exhaustive rename detection was skipped".as_slice(),
            b"inexact rename detection was skipped".as_slice(),
            b"you may want to set your diff.renameLimit".as_slice(),
            b"See \"git help gc\" for manual housekeeping".as_slice(),
            b"Auto packing the repository in background for optimum performance".as_slice(),
        ]
        .iter()
        .any(|needle| line.windows(needle.len()).any(|window| window == *needle));
        if !ignored {
            return Some(line);
        }
        if end == stderr.len() || end + 1 == stderr.len() {
            return None;
        }
        start = end + 1;
    }
}
