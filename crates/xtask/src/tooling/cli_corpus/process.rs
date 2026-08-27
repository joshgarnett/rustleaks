//! Bounded CLI execution with process-tree cleanup.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::TempDir;
use super::spec::REVISION;
use crate::tooling::support::{diagnostic_tail, go_module_cache};

pub(super) const CASE_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

pub(super) struct ResultData {
    pub(super) exit: i64,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run<S: AsRef<std::ffi::OsStr>>(
    program: &Path,
    args: &[S],
    directory: &Path,
    env: &BTreeMap<String, Vec<u8>>,
    stdin_bytes: &[u8],
    temporary: &TempDir,
    label: &str,
    timeout: Duration,
    limit: usize,
) -> Result<ResultData, String> {
    let safe = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    let stdin_path = temporary.path.join(format!("{safe}.stdin"));
    let stdout_path = temporary.path.join(format!("{safe}.stdout"));
    let stderr_path = temporary.path.join(format!("{safe}.stderr"));
    fs::write(&stdin_path, stdin_bytes)
        .map_err(|error| format!("cannot write {}: {error}", stdin_path.display()))?;
    let stdin = File::open(&stdin_path)
        .map_err(|error| format!("cannot open {}: {error}", stdin_path.display()))?;
    let stdout = File::create(&stdout_path)
        .map_err(|error| format!("cannot create {}: {error}", stdout_path.display()))?;
    let stderr = File::create(&stderr_path)
        .map_err(|error| format!("cannot create {}: {error}", stderr_path.display()))?;
    let mut command = Command::new(program);
    command
        .current_dir(directory)
        .args(args)
        .env_remove("GITLEAKS_CONFIG")
        .env_remove("GITLEAKS_CONFIG_TOML")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("PWD", directory)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (key, value) in env {
        command.env(key, bytes_os(value)?);
    }
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
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to poll {label}: {error}"))?
        {
            break status;
        }
        let stdout_len = file_len(&stdout_path)?;
        let stderr_len = file_len(&stderr_path)?;
        if stdout_len > limit as u64 || stderr_len > limit as u64 {
            cleanup_tree(&mut child, label)?;
            return Err(format!("{label}: output exceeded {limit} bytes"));
        }
        if started.elapsed() > timeout {
            cleanup_tree(&mut child, label)?;
            return Err(format!("{label}: exceeded {}s", timeout.as_secs()));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = fs::read(&stdout_path)
        .map_err(|error| format!("cannot read {}: {error}", stdout_path.display()))?;
    let stderr = fs::read(&stderr_path)
        .map_err(|error| format!("cannot read {}: {error}", stderr_path.display()))?;
    if stdout.len() > limit || stderr.len() > limit {
        return Err(format!("{label}: output bound bypassed"));
    }
    Ok(ResultData {
        exit: exit_value(status),
        stdout,
        stderr,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn command<S: AsRef<std::ffi::OsStr>>(
    program: &Path,
    args: &[S],
    directory: &Path,
    env: &BTreeMap<String, Vec<u8>>,
    temporary: &TempDir,
    label: &str,
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let result = run(
        program, args, directory, env, b"", temporary, label, timeout, limit,
    )?;
    if result.exit != 0 {
        return Err(format!(
            "{label} exited {}\nstdout:\n{}\nstderr:\n{}",
            result.exit,
            diagnostic_tail(&result.stdout, 16 * 1024),
            diagnostic_tail(&result.stderr, 16 * 1024)
        ));
    }
    Ok(result.stdout)
}

fn cleanup_tree(child: &mut std::process::Child, label: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        let group = format!("-{}", child.id());
        let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
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
        thread::sleep(Duration::from_millis(20));
    }
}

fn file_len(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))
}

fn exit_value(status: ExitStatus) -> i64 {
    if let Some(code) = status.code() {
        return i64::from(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        -i64::from(status.signal().unwrap_or_default())
    }
    #[cfg(not(unix))]
    -1
}

#[allow(clippy::unnecessary_wraps)] // Non-Unix targets reject non-UTF-8 environment values.
fn bytes_os(bytes: &[u8]) -> Result<std::ffi::OsString, String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Ok(std::ffi::OsString::from_vec(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes.to_vec())
            .map(Into::into)
            .map_err(|_| "environment value is not UTF-8 on this platform".into())
    }
}

pub(super) fn default_go_env(temporary: &TempDir) -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "GOCACHE".into(),
            temporary
                .path
                .join("go-cache")
                .to_string_lossy()
                .into_owned()
                .into_bytes(),
        ),
        (
            "GOMODCACHE".into(),
            go_module_cache(REVISION)
                .to_string_lossy()
                .into_owned()
                .into_bytes(),
        ),
        ("GOMEMLIMIT".into(), b"768MiB".to_vec()),
        ("GOMAXPROCS".into(), b"2".to_vec()),
    ])
}

#[cfg(test)]
mod tests {
    use super::exit_value;

    #[test]
    fn successful_status_maps_to_zero() {
        let status = std::process::Command::new("true").status().unwrap();
        assert_eq!(exit_value(status), 0);
    }
}
