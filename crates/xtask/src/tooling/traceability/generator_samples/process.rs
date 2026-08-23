//! Timeout-bounded child processes with bounded diagnostics.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::tooling::support::{TempDir, command_status_with_output_limits, diagnostic_tail};

const OUTPUT_LIMIT: u64 = 1024 * 1024;

pub(super) fn capture(
    command: &mut Command,
    label: &str,
    timeout: Duration,
) -> Result<String, String> {
    capture_with_limits(command, label, timeout, &[])
}

fn capture_with_limits(
    command: &mut Command,
    label: &str,
    timeout: Duration,
    additional_limits: &[(&Path, &str, u64)],
) -> Result<String, String> {
    let temporary = TempDir::new("generator-command")?;
    let stdout_path = temporary.path.join("stdout");
    let stderr_path = temporary.path.join("stderr");
    let stdout = File::create(&stdout_path)
        .map_err(|error| format!("cannot create command stdout: {error}"))?;
    let stderr = File::create(&stderr_path)
        .map_err(|error| format!("cannot create command stderr: {error}"))?;
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let mut limits = vec![
        (stdout_path.as_path(), "stdout", OUTPUT_LIMIT),
        (stderr_path.as_path(), "stderr", OUTPUT_LIMIT),
    ];
    limits.extend_from_slice(additional_limits);
    if let Err(error) = command_status_with_output_limits(command, timeout, label, &limits) {
        let diagnostic = read_diagnostic(&stderr_path);
        return Err(format!("{error}; stderr: {diagnostic}"));
    }
    let bytes =
        fs::read(&stdout_path).map_err(|error| format!("cannot read {label} stdout: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > OUTPUT_LIMIT {
        return Err(format!("{label} stdout exceeded 1 MiB"));
    }
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{label} returned non-UTF-8 stdout: {error}"))
}

pub(super) fn status(command: &mut Command, label: &str, timeout: Duration) -> Result<(), String> {
    capture(command, label, timeout).map(|_| ())
}

pub(super) fn status_with_limits(
    command: &mut Command,
    label: &str,
    timeout: Duration,
    limits: &[(&Path, &str, u64)],
) -> Result<(), String> {
    capture_with_limits(command, label, timeout, limits).map(|_| ())
}

fn read_diagnostic(path: &Path) -> String {
    fs::read(path).map_or_else(
        |error| format!("<cannot read: {error}>"),
        |bytes| diagnostic_tail(&bytes, 16 * 1024),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{capture, capture_with_limits};
    use crate::tooling::support::TempDir;

    const PROBE: &str = "RUSTLEAKS_GENERATOR_PROCESS_PROBE";
    const PROBE_ROOT: &str = "RUSTLEAKS_GENERATOR_PROCESS_PROBE_ROOT";
    const PROBE_TEST: &str =
        "tooling::traceability::generator_samples::process::tests::bounded_process_probe_child";

    #[test]
    fn bounded_process_probe_child() {
        let Ok(mode) = std::env::var(PROBE) else {
            return;
        };
        match mode.as_str() {
            "overflow" => {
                let bytes = vec![b'x'; 2 * 1024 * 1024];
                std::io::stdout().write_all(&bytes).unwrap();
                std::io::stdout().flush().unwrap();
                thread::sleep(Duration::from_secs(10));
            }
            "fast-stdout-overflow" => {
                std::io::stdout()
                    .write_all(&vec![b'x'; 2 * 1024 * 1024])
                    .unwrap();
            }
            "stderr-overflow" => {
                let bytes = vec![b'x'; 2 * 1024 * 1024];
                std::io::stderr().write_all(&bytes).unwrap();
                std::io::stderr().flush().unwrap();
                thread::sleep(Duration::from_secs(10));
            }
            "fast-stderr-overflow" => {
                std::io::stderr()
                    .write_all(&vec![b'x'; 2 * 1024 * 1024])
                    .unwrap();
            }
            "file-overflow" => {
                let root = std::path::PathBuf::from(std::env::var_os(PROBE_ROOT).unwrap());
                std::fs::write(root.join("journal"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
                thread::sleep(Duration::from_secs(10));
            }
            "fast-file-overflow" => {
                let root = std::path::PathBuf::from(std::env::var_os(PROBE_ROOT).unwrap());
                std::fs::write(root.join("journal"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
            }
            "parent" => {
                let root = std::path::PathBuf::from(std::env::var_os(PROBE_ROOT).unwrap());
                let mut descendant = Command::new(std::env::current_exe().unwrap())
                    .args([PROBE_TEST, "--exact", "--nocapture"])
                    .env(PROBE, "descendant")
                    .env(PROBE_ROOT, &root)
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                while !root.join("heartbeat").is_file() {
                    assert!(Instant::now() < deadline, "descendant did not start");
                    thread::sleep(Duration::from_millis(10));
                }
                descendant.wait().unwrap();
            }
            "descendant" => {
                let root = std::path::PathBuf::from(std::env::var_os(PROBE_ROOT).unwrap());
                let mut counter = 0_u64;
                loop {
                    std::fs::write(root.join("heartbeat"), counter.to_string()).unwrap();
                    counter += 1;
                    thread::sleep(Duration::from_millis(10));
                }
            }
            other => panic!("unknown process probe {other}"),
        }
    }

    #[test]
    fn live_output_limit_terminates_the_process() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([PROBE_TEST, "--exact", "--nocapture"])
            .env(PROBE, "overflow");
        let error =
            capture(&mut command, "output-limit probe", Duration::from_secs(5)).unwrap_err();
        assert!(error.contains("stdout exceeded 1048576 bytes"), "{error}");
    }

    #[test]
    fn live_stderr_limit_terminates_the_process() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([PROBE_TEST, "--exact", "--nocapture"])
            .env(PROBE, "stderr-overflow");
        let error =
            capture(&mut command, "stderr-limit probe", Duration::from_secs(5)).unwrap_err();
        assert!(error.contains("stderr exceeded 1048576 bytes"), "{error}");
    }

    #[test]
    fn live_declared_file_limit_terminates_the_process() {
        let temporary = TempDir::new("generator-file-probe").unwrap();
        let journal = temporary.path.join("journal");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([PROBE_TEST, "--exact", "--nocapture"])
            .env(PROBE, "file-overflow")
            .env(PROBE_ROOT, &temporary.path);
        let error = capture_with_limits(
            &mut command,
            "file-limit probe",
            Duration::from_secs(5),
            &[(journal.as_path(), "journal", 1024)],
        )
        .unwrap_err();
        assert!(error.contains("journal exceeded 1024 bytes"), "{error}");
    }

    #[test]
    fn fast_exit_cannot_bypass_stdout_or_stderr_limits() {
        for (mode, stream) in [
            ("fast-stdout-overflow", "stdout"),
            ("fast-stderr-overflow", "stderr"),
        ] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([PROBE_TEST, "--exact", "--nocapture"])
                .env(PROBE, mode);
            let error =
                capture(&mut command, "fast-exit probe", Duration::from_secs(5)).unwrap_err();
            assert!(error.contains(&format!("{stream} exceeded")), "{error}");
        }
    }

    #[test]
    fn fast_exit_cannot_bypass_a_declared_file_limit() {
        let temporary = TempDir::new("generator-fast-file-probe").unwrap();
        let journal = temporary.path.join("journal");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([PROBE_TEST, "--exact", "--nocapture"])
            .env(PROBE, "fast-file-overflow")
            .env(PROBE_ROOT, &temporary.path);
        let error = capture_with_limits(
            &mut command,
            "fast-file probe",
            Duration::from_secs(5),
            &[(journal.as_path(), "journal", 1024)],
        )
        .unwrap_err();
        assert!(error.contains("journal exceeded 1024 bytes"), "{error}");
    }

    #[test]
    fn timeout_terminates_the_descendant_tree() {
        let temporary = TempDir::new("generator-tree-probe").unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([PROBE_TEST, "--exact", "--nocapture"])
            .env(PROBE, "parent")
            .env(PROBE_ROOT, &temporary.path);
        let error = capture(&mut command, "tree probe", Duration::from_secs(2)).unwrap_err();
        assert!(error.contains("external 2 second deadline"), "{error}");
        let before = std::fs::read(temporary.path.join("heartbeat")).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            std::fs::read(temporary.path.join("heartbeat")).unwrap(),
            before,
            "timed-out descendant continued running"
        );
    }
}
