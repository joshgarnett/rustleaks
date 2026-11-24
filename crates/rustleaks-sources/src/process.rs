//! Starting child processes.

use std::io;
use std::process::{Child, Command};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// How long a thread that waits for a child process sleeps between checks of
/// the child and of cancellation.
pub(crate) const CHILD_POLL: Duration = Duration::from_millis(2);

/// Held while this crate starts a child process.
///
/// On targets without `pipe2`, such as macOS, the standard library creates a
/// pipe and marks it close-on-exec in a second step. A child that another
/// thread starts between those steps inherits that pipe. When a Git process
/// holds the write end of another Git's input or output pipe, the other end
/// never sees end of file, and two such Git processes wait for each other
/// forever. Starting children one at a time keeps each child's pipes out of
/// every other child that this crate starts.
static SPAWN: Mutex<()> = Mutex::new(());

/// Starts `command` while no other child of this crate is starting.
pub(crate) fn spawn(command: &mut Command) -> io::Result<Child> {
    let _starting = SPAWN.lock().unwrap_or_else(PoisonError::into_inner);
    command.spawn()
}

/// Makes a Git child print its messages in English.
///
/// The sources tell harmless Git warnings from failures by their English
/// text, such as the rename-limit warning and `No remote configured`.
/// `LC_ALL=C` turns off Git's message translation. `LANGUAGE` is removed
/// because GNU gettext can prefer it to the locale. The Git output that the
/// sources parse (commit headers, patches, quoted paths and dates in Git's
/// default format) is the same in every locale.
pub(crate) fn untranslated_git_messages(command: &mut Command) -> &mut Command {
    command.env("LC_ALL", "C").env_remove("LANGUAGE")
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Stdio;
    use std::thread;

    use super::*;

    /// Counts the open descriptors of a child started with three pipes.
    fn open_descriptors() -> usize {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "for fd in /dev/fd/*; do echo \"$fd\"; done"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = spawn(&mut command)
            .expect("start the shell")
            .wait_with_output()
            .expect("wait for the shell");
        assert!(output.status.success(), "{output:?}");
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count()
    }

    #[test]
    fn children_started_at_once_do_not_inherit_each_others_pipes() {
        let alone = open_descriptors();
        // Without the lock, about 3% of these children held another child's
        // pipe on macOS.
        let counts = thread::scope(|scope| {
            let workers: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| (0..40).map(|_| open_descriptors()).collect::<Vec<_>>()))
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().expect("join the starter"))
                .collect::<Vec<_>>()
        });
        assert_eq!(counts.len(), 640);
        assert!(
            counts.iter().all(|count| *count == alone),
            "a child had more than the {alone} descriptors of a child started alone: {counts:?}"
        );
    }
}
