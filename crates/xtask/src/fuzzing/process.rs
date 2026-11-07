//! Strictly bounded private pipe capture with process-group cleanup.

use std::fs::File;
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::private;

pub(crate) const LOG_LIMIT: u64 = 4 * 1024 * 1024;

struct ProcessGroup {
    child: Child,
    cleaned: bool,
}

impl Deref for ProcessGroup {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for ProcessGroup {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = crate::tooling::terminate_process_tree(
                &mut self.child,
                "private fuzz child",
                Instant::now() + Duration::from_secs(5),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Success,
    ExitFailure,
    SpawnFailure,
    Timeout,
    OutputLimit,
    OutputFailure,
    PollFailure,
    CleanupFailure,
    CorpusLimit,
}

impl Outcome {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ExitFailure => "exit-failure",
            Self::SpawnFailure => "spawn-failure",
            Self::Timeout => "timeout",
            Self::OutputLimit => "output-limit",
            Self::OutputFailure => "output-failure",
            Self::PollFailure => "poll-failure",
            Self::CleanupFailure => "cleanup-failure",
            Self::CorpusLimit => "corpus-limit",
        }
    }
}

pub(crate) fn command(root: &Path, program: &str, arguments: &[String]) -> Command {
    // Command::pre_exec would require unsafe Rust. A fixed shell wrapper sets
    // umask before exec without interpreting program names or argument bytes.
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "umask 077; exec \"$@\"",
        "rustleaks-private-fuzz",
        program,
    ]);
    command.args(arguments).current_dir(root).env_clear();
    for name in ["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("CARGO_NET_OFFLINE", "true");
    command.env("LC_ALL", "C");
    command
}

fn capture(
    mut input: impl Read + Send + 'static,
    mut output: File,
    remaining: Arc<AtomicU64>,
    sender: mpsc::Sender<Outcome>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0; 8192];
        let outcome = loop {
            let count = match input.read(&mut buffer) {
                Ok(0) => break Outcome::Success,
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break Outcome::OutputFailure,
            };
            let previous = remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    Some(value.saturating_sub(count as u64))
                })
                .expect("capture budget update always succeeds");
            let accepted = count.min(usize::try_from(previous).unwrap_or(usize::MAX));
            if output.write_all(&buffer[..accepted]).is_err() {
                break Outcome::OutputFailure;
            }
            if accepted < count {
                break Outcome::OutputLimit;
            }
        };
        let _ = sender.send(outcome);
    })
}

pub(crate) fn run(
    command: &mut Command,
    directory: &Path,
    timeout: Duration,
    limit: u64,
) -> Result<Outcome, String> {
    run_monitored(command, directory, timeout, limit, || Ok(()))
}

pub(crate) fn run_monitored(
    command: &mut Command,
    directory: &Path,
    timeout: Duration,
    limit: u64,
    monitor: impl FnMut() -> Result<(), String>,
) -> Result<Outcome, String> {
    private::supported()?;
    let stdout = private::file(&directory.join("stdout.log"))?;
    let stderr = private::file(&directory.join("stderr.log"))?;
    run_with_files(command, stdout, stderr, timeout, limit, monitor)
}

fn configure_child(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
}

pub(crate) fn run_with_files(
    command: &mut Command,
    stdout: File,
    stderr: File,
    timeout: Duration,
    limit: u64,
    mut monitor: impl FnMut() -> Result<(), String>,
) -> Result<Outcome, String> {
    private::supported()?;
    configure_child(command);
    let Ok(child) = command.spawn() else {
        return Ok(Outcome::SpawnFailure);
    };
    let mut child = ProcessGroup {
        child,
        cleaned: false,
    };
    let (sender, receiver) = mpsc::channel();
    let remaining = Arc::new(AtomicU64::new(limit));
    let readers = [
        capture(
            child.stdout.take().expect("piped stdout"),
            stdout,
            Arc::clone(&remaining),
            sender.clone(),
        ),
        capture(
            child.stderr.take().expect("piped stderr"),
            stderr,
            remaining,
            sender,
        ),
    ];
    let started = Instant::now();
    let mut completed = 0;
    let mut last_monitor = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut outcome = loop {
        if let Some(error) = drain(&receiver, &mut completed) {
            break error;
        }
        if last_monitor.elapsed() >= Duration::from_millis(100) {
            if monitor().is_err() {
                break Outcome::CorpusLimit;
            }
            last_monitor = Instant::now();
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break if status.success() {
                    Outcome::Success
                } else {
                    Outcome::ExitFailure
                };
            }
            Ok(None) => {}
            Err(_) => break Outcome::PollFailure,
        }
        if started.elapsed() >= timeout {
            break Outcome::Timeout;
        }
        thread::sleep(Duration::from_millis(5));
    };
    // Also kill descendants after a successful parent exit. A remaining pipe
    // writer must not outlive the command or prevent readers from reaching EOF.
    let cleanup_deadline = Instant::now() + Duration::from_secs(5);
    // An attempted bounded cleanup must not gain a second budget in Drop.
    child.cleaned = true;
    let cleanup_failed =
        crate::tooling::terminate_process_tree(&mut child, "private fuzz child", cleanup_deadline)
            .is_err();
    while completed < 2 {
        if let Some(error) = drain(&receiver, &mut completed) {
            outcome = error;
        }
        if completed == 2 {
            break;
        }
        if Instant::now() >= cleanup_deadline {
            // Do not hang on an escaped process holding a pipe. Such a result
            // is a failure, never evidence of complete containment.
            return Ok(Outcome::CleanupFailure);
        }
        thread::sleep(
            cleanup_deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(5)),
        );
    }
    // Receiving a reader's result precedes that thread's final return. Do not
    // let a delayed reader join outlive the same cleanup deadline.
    while readers.iter().any(|reader| !reader.is_finished()) {
        let remaining = cleanup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Outcome::CleanupFailure);
        }
        thread::sleep(remaining.min(Duration::from_millis(5)));
    }
    for reader in readers {
        if reader.join().is_err() {
            outcome = Outcome::OutputFailure;
        }
    }
    if monitor().is_err() && outcome == Outcome::Success {
        outcome = Outcome::CorpusLimit;
    }
    Ok(if cleanup_failed || Instant::now() >= cleanup_deadline {
        Outcome::CleanupFailure
    } else {
        outcome
    })
}

fn drain(receiver: &mpsc::Receiver<Outcome>, completed: &mut usize) -> Option<Outcome> {
    let mut failure = None;
    while let Ok(outcome) = receiver.try_recv() {
        *completed += 1;
        if outcome != Outcome::Success {
            failure = Some(outcome);
        }
    }
    failure
}
