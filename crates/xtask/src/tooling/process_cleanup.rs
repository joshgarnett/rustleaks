//! Bounded observation of the private runner's inherited Unix process group.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const OBSERVER_LIMIT: usize = 1024 * 1024;
const OBSERVER_REAP_RESERVE: Duration = Duration::from_millis(100);

pub(super) fn group_quiescent(group: u32, deadline: Instant) -> Result<bool, String> {
    let mut command = Command::new("/bin/ps");
    // Avoid platform-specific group-selection flags and never collect command
    // lines, which can contain private input. Both supported Unix hosts expose
    // these numeric group and state fields.
    let fields = if cfg!(target_os = "linux") {
        "pgid=,stat=,nlwp="
    } else {
        "pgid=,stat="
    };
    command.args(["-A", "-o", fields]).env("LC_ALL", "C");
    group_snapshot_quiescent(
        &bounded_output(&mut command, deadline)?,
        group,
        cfg!(target_os = "linux"),
    )
}

fn group_snapshot_quiescent(
    output: &[u8],
    group: u32,
    thread_counts: bool,
) -> Result<bool, String> {
    let output = std::str::from_utf8(output).map_err(|_| "invalid process state encoding")?;
    let mut quiescent = true;
    let mut rows = 0;
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let observed_group = fields
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or("invalid process group observation")?;
        let state = fields.next().ok_or("missing process state observation")?;
        let threads = if thread_counts {
            Some(
                fields
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|count| *count > 0)
                    .ok_or("invalid process thread-count observation")?,
            )
        } else {
            None
        };
        if fields.next().is_some() || state.is_empty() {
            return Err("invalid process state observation".into());
        }
        rows += 1;
        // Only zombies have exited without requiring their adopting parent to
        // reap them. D, T, t, R, S and unknown states remain non-quiescent.
        // Linux retains a zombie leader while sibling threads may still run.
        // That leader remains counted, so only Z with exactly one thread is
        // quiescent. Darwin reports process SZOMB after its last thread exits.
        if observed_group == group
            && (!state.starts_with('Z') || threads.is_some_and(|count| count != 1))
        {
            quiescent = false;
        }
    }
    // A successful all-processes query includes at least its own ps process.
    // Empty or malformed output must never certify cleanup.
    if rows == 0 {
        return Err("empty process group observation".into());
    }
    Ok(quiescent)
}

pub(super) fn bounded_output(command: &mut Command, deadline: Instant) -> Result<Vec<u8>, String> {
    let work_deadline = deadline
        .checked_sub(OBSERVER_REAP_RESERVE)
        .ok_or("process observer cleanup deadline expired")?;
    if Instant::now() >= work_deadline {
        return Err("process observer cleanup deadline expired".into());
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "cannot start process cleanup tool")?;
    let stdout = child.stdout.take().expect("piped process observer output");
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .take((OBSERVER_LIMIT + 1) as u64)
            .read_to_end(&mut output)
            .map_err(|_| "cannot read process cleanup tool output".to_owned())
            .and_then(|_| {
                if output.len() > OBSERVER_LIMIT {
                    Err("process cleanup tool output exceeded its bound".into())
                } else {
                    Ok(output)
                }
            });
        let _ = sender.send(result);
    });
    let mut output = None;
    let failure = loop {
        if Instant::now() >= work_deadline {
            break "process cleanup tool exceeded its deadline".into();
        }
        match receiver.try_recv() {
            Ok(Ok(bytes)) => output = Some(bytes),
            Ok(Err(error)) => break error,
            Err(mpsc::TryRecvError::Disconnected) if output.is_none() => {
                break "process cleanup tool output reader failed".into();
            }
            Err(_) => {}
        }
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => {
                break "process cleanup tool failed".into();
            }
            Ok(Some(_)) if output.is_some() && reader.is_finished() => {
                return reader
                    .join()
                    .map_err(|_| "process cleanup tool output reader failed".into())
                    .and_then(|()| output.ok_or_else(|| "missing process observation".into()));
            }
            Ok(_) => {}
            Err(_) => break "cannot reap process cleanup tool".into(),
        }
        let remaining = work_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break "process cleanup tool exceeded its deadline".into();
        }
        thread::sleep(remaining.min(Duration::from_millis(5)));
    };
    // This is a direct, owned Child, not a numeric group. Cleanup must remain
    // nonrecursive and share the caller's deadline, even if the observer fails.
    let _ = child.kill();
    loop {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("process cleanup tool could not be reaped before its deadline".into());
        }
        thread::sleep(remaining.min(Duration::from_millis(5)));
    }
    // A failed observer cannot hold up the owner indefinitely. Its reader owns
    // at most the fixed output bound; a delayed EOF never establishes success.
    if reader.is_finished() {
        let _ = reader.join();
    }
    Err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_observation_requires_absence_or_only_zombies() {
        for state in ["D", "T", "t", "R", "S", "I", "X", "?"] {
            let observed = format!("7 {state}\n99 S\n");
            assert!(!group_snapshot_quiescent(observed.as_bytes(), 7, false).unwrap());
        }
        assert!(group_snapshot_quiescent(b"7 Z\n7 Z+\n99 S\n", 7, false).unwrap());
        assert!(group_snapshot_quiescent(b"99 S\n", 7, false).unwrap());
        assert!(!group_snapshot_quiescent(b"7 Z\n7 D\n99 S\n", 7, false).unwrap());
        for malformed in [
            b"".as_slice(),
            b"7\n",
            b"invalid S\n",
            b"7 Z extra\n",
            b"\xff",
        ] {
            assert!(group_snapshot_quiescent(malformed, 7, false).is_err());
        }
    }

    #[test]
    fn linux_zombie_leader_with_remaining_threads_is_not_quiescent() {
        assert!(!group_snapshot_quiescent(b"7 Z 2\n99 S 1\n", 7, true).unwrap());
        assert!(!group_snapshot_quiescent(b"7 Z 1\n7 D 1\n", 7, true).unwrap());
        assert!(group_snapshot_quiescent(b"7 Z 1\n7 Z+ 1\n99 S 2\n", 7, true).unwrap());
        assert!(group_snapshot_quiescent(b"99 S 2\n", 7, true).unwrap());
        for malformed in [b"7 Z\n".as_slice(), b"7 Z 0\n", b"7 Z invalid\n"] {
            assert!(group_snapshot_quiescent(malformed, 7, true).is_err());
        }
        let mut observations = [b"7 Z 2\n".as_slice(), b"7 Z 1\n"].into_iter();
        super::super::wait_for_cleanup(
            Instant::now() + Duration::from_secs(5),
            "synthetic threaded group",
            || group_snapshot_quiescent(observations.next().unwrap(), 7, true),
        )
        .unwrap();
        assert!(observations.next().is_none());
    }

    #[test]
    fn observer_failures_never_establish_quiescence() {
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(
            bounded_output(
                &mut Command::new("/nonexistent-rustleaks-observer"),
                deadline
            )
            .is_err()
        );
        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "exit 7"]);
        assert!(bounded_output(&mut failed, deadline).is_err());
        let mut expired = Command::new("/bin/sh");
        expired.args(["-c", "exit 0"]);
        assert!(bounded_output(&mut expired, Instant::now()).is_err());
    }

    #[test]
    fn cleanup_polls_live_states_until_quiescent_and_fails_at_its_deadline() {
        let mut observations = [b"7 D\n".as_slice(), b"7 T\n", b"7 Z\n"].into_iter();
        super::super::wait_for_cleanup(
            Instant::now() + Duration::from_secs(5),
            "synthetic group",
            || group_snapshot_quiescent(observations.next().unwrap(), 7, false),
        )
        .unwrap();
        assert!(observations.next().is_none());
        assert!(
            super::super::wait_for_cleanup(Instant::now(), "live group", || Ok(false)).is_err()
        );
        assert!(super::super::wait_for_cleanup(Instant::now(), "late group", || Ok(true)).is_err());
        assert!(
            super::super::wait_for_cleanup(
                Instant::now() + Duration::from_secs(5),
                "unobservable group",
                || Err("synthetic observer failure".into()),
            )
            .is_err()
        );
    }

    #[test]
    fn observer_output_is_bounded_and_hung_observer_is_reaped() {
        let mut oversized = Command::new("python3");
        oversized.args([
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * (1024 * 1024 + 1))",
        ]);
        assert!(bounded_output(&mut oversized, Instant::now() + Duration::from_secs(5)).is_err());

        let temporary = super::super::TempDir::new("cleanup-observer").unwrap();
        let pid_file = temporary.path.join("observer.pid");
        let mut hung = Command::new("/bin/sh");
        hung.args(["-c", "echo $$ > \"$1\"; exec sleep 30", "cleanup-observer"])
            .arg(&pid_file);
        assert!(bounded_output(&mut hung, Instant::now() + Duration::from_secs(1)).is_err());
        let pid = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD,
        );
    }

    #[test]
    fn stopped_parent_and_descendant_with_closed_output_are_cleaned_up() {
        use std::os::unix::process::CommandExt as _;

        let temporary = super::super::TempDir::new("cleanup-closed-output").unwrap();
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "(while :; do printf x >> heartbeat; sleep 0.01; done) & \
                 while [ ! -s heartbeat ]; do sleep 0.01; done; \
                 printf ready > ready; kill -STOP $$",
            ])
            .current_dir(&temporary.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let ready_by = Instant::now() + Duration::from_secs(30);
        let ready = temporary.path.join("ready");
        while !ready.exists() && Instant::now() < ready_by {
            thread::sleep(Duration::from_millis(10));
        }
        let mut stopped = false;
        while ready.exists() && Instant::now() < ready_by {
            let mut observer = Command::new("/bin/ps");
            observer.args(["-o", "stat=", "-p", &child.id().to_string()]);
            let Ok(state) = bounded_output(&mut observer, ready_by) else {
                break;
            };
            if String::from_utf8_lossy(&state)
                .trim_start()
                .starts_with('T')
            {
                stopped = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        // Clean up even if fixture readiness failed, before making assertions.
        let result = super::super::terminate_process_tree(
            &mut child,
            "synthetic stopped parent",
            Instant::now() + Duration::from_secs(5),
        );
        assert!(ready.exists(), "synthetic descendant never became active");
        assert!(stopped, "synthetic parent never entered its stopped state");
        result.unwrap();
        let heartbeat = temporary.path.join("heartbeat");
        let after = std::fs::read(&heartbeat).unwrap();
        assert!(!after.is_empty());
        thread::sleep(Duration::from_millis(150));
        assert_eq!(std::fs::read(heartbeat).unwrap(), after);
        let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD,
        );
    }
}
