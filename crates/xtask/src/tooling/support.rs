//! Shared filesystem support for repository tooling.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {} for SHA-256: {error}", path.display()))?;
    Ok(sha256_bytes(&bytes))
}

pub(crate) fn go_module_cache(revision: &str) -> PathBuf {
    std::env::var_os("GOMODCACHE").map_or_else(
        || std::env::temp_dir().join(format!("rustleaks-go-mod-cache-{revision}")),
        PathBuf::from,
    )
}

/// Hashes a sorted Rust source tree as portable `path\0content-hash\n` records.
pub(crate) fn source_tree_sha256(root: &Path, directory: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_rust_sources(directory, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "generator source tree {} contains no Rust files",
            directory.display()
        ));
    }
    let mut records = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|error| format!("{} is outside {}: {error}", path.display(), root.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        records.extend_from_slice(relative.as_bytes());
        records.push(0);
        records.extend_from_slice(sha256_file(&path)?.as_bytes());
        records.push(b'\n');
    }
    Ok(sha256_bytes(&records))
}

fn collect_rust_sources(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry = entry
            .map_err(|error| format!("cannot read entry in {}: {error}", directory.display()))?;
        let path = entry.path();
        if entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
            .is_dir()
        {
            collect_rust_sources(&path, output)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            output.push(path);
        }
    }
    Ok(())
}

pub(crate) fn command_output(command: &mut Command) -> Result<String, String> {
    const DIAGNOSTIC_LIMIT: usize = 16 * 1024;

    let display = format!("{command:?}");
    let output = command
        .output()
        .map_err(|error| format!("failed to run {display}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{display} exited {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            diagnostic_tail(&output.stdout, DIAGNOSTIC_LIMIT),
            diagnostic_tail(&output.stderr, DIAGNOSTIC_LIMIT),
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{display} returned non-UTF-8 output: {error}"))
}

pub(crate) fn diagnostic_tail(output: &[u8], limit: usize) -> String {
    if output.is_empty() {
        return "<empty>".into();
    }
    if output.len() <= limit {
        return String::from_utf8_lossy(output).trim().to_owned();
    }

    let omitted = output.len() - limit;
    format!(
        "... {omitted} bytes omitted ...\n{}",
        String::from_utf8_lossy(&output[omitted..]).trim()
    )
}

pub(crate) fn command_status_with_timeout(
    command: &mut Command,
    timeout: Duration,
    label: &str,
) -> Result<(), String> {
    let display = format!("{command:?}");
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run {label} ({display}): {error}"))?;
    wait_for_child_with_timeout(&mut child, timeout, label, &display)
}

/// Runs one command in an isolated process tree while enforcing live file-size
/// limits on redirected output. Descendants are terminated when the direct
/// child exits, fails, exceeds a limit, or reaches its deadline.
pub(crate) fn command_status_with_output_limits(
    command: &mut Command,
    timeout: Duration,
    label: &str,
    limits: &[(&Path, &str, u64)],
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let display = format!("{command:?}");
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run {label} ({display}): {error}"))?;
    let started = Instant::now();
    loop {
        match output_limit_violation(limits, label) {
            Ok(None) => {}
            Ok(Some(error)) | Err(error) => return fail_after_cleanup(&mut child, label, error),
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                return fail_after_cleanup(
                    &mut child,
                    label,
                    format!("failed to poll {label} ({display}): {error}"),
                );
            }
        };
        if let Some(status) = status {
            match output_limit_violation(limits, label) {
                Ok(None) => {}
                Ok(Some(error)) | Err(error) => {
                    return fail_after_cleanup(&mut child, label, error);
                }
            }
            terminate_process_tree(&mut child, label)?;
            return if status.success() {
                Ok(())
            } else {
                Err(format!("{label} ({display}) exited {status}"))
            };
        }
        if started.elapsed() >= timeout {
            return fail_after_cleanup(
                &mut child,
                label,
                format!(
                    "{label} exceeded its external {} second deadline",
                    timeout.as_secs()
                ),
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn output_limit_violation(
    limits: &[(&Path, &str, u64)],
    label: &str,
) -> Result<Option<String>, String> {
    for (path, stream, limit) in limits {
        let length = match fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(format!("cannot inspect {label} {stream}: {error}")),
        };
        if length > *limit {
            return Ok(Some(format!("{label} {stream} exceeded {limit} bytes")));
        }
    }
    Ok(None)
}

fn fail_after_cleanup(child: &mut Child, label: &str, error: String) -> Result<(), String> {
    match terminate_process_tree(child, label) {
        Ok(()) => Err(error),
        Err(cleanup) => Err(format!("{error}; cleanup failed: {cleanup}")),
    }
}

fn terminate_process_tree(child: &mut Child, label: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        let group = format!("-{}", child.id());
        let _ = Command::new("kill")
            .args(["-KILL", "--", &group])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("failed to reap {label}: {error}"))?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("failed to reap {label} after bounded cleanup"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) trait TimeoutChild {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>>;
    fn kill(&mut self) -> std::io::Result<()>;
    fn reap(&mut self) -> std::io::Result<()>;
}

impl TimeoutChild for Child {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }

    fn kill(&mut self) -> std::io::Result<()> {
        Child::kill(self)
    }

    fn reap(&mut self) -> std::io::Result<()> {
        Child::wait(self).map(|_| ())
    }
}

pub(crate) fn wait_for_child_with_timeout(
    child: &mut impl TimeoutChild,
    timeout: Duration,
    label: &str,
    display: &str,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match child
            .try_wait()
            .map_err(|error| format!("failed to poll {label} ({display}): {error}"))?
        {
            Some(status) if status.success() => return Ok(()),
            Some(status) => return Err(format!("{label} ({display}) exited {status}")),
            None if started.elapsed() >= timeout => {
                child
                    .kill()
                    .map_err(|error| format!("failed to terminate timed-out {label}: {error}"))?;
                child
                    .reap()
                    .map_err(|error| format!("failed to reap timed-out {label}: {error}"))?;
                return Err(format!(
                    "{label} exceeded its external {} second deadline",
                    timeout.as_secs()
                ));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

pub(super) struct TempDir {
    pub(super) path: PathBuf,
}

impl TempDir {
    pub(super) fn new(label: &str) -> Result<Self, String> {
        static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
            .as_nanos();
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustleaks-{label}-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).map_err(|error| {
            format!(
                "cannot create temporary directory {}: {error}",
                path.display()
            )
        })?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let is_scoped = self.path.parent() == Some(std::env::temp_dir().as_path())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rustleaks-"));
        if is_scoped {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
