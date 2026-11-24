//! Release checks that only `cargo xtask qualify` runs.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::tooling::{ScopedTempDir, command_output, command_status_with_timeout};
use crate::{require_exact_tool_version, workspace_root};

const CARGO_PUBLIC_API_VERSION: &str = "cargo-public-api 0.52.0";
const PUBLIC_API_TOOLCHAIN: &str = "nightly-2026-08-21";
const PUBLIC_API_SNAPSHOT: &str = "testdata/public-api/rustleaks-core.txt";

fn composite_test_executable_from_messages(messages: &str) -> Result<PathBuf, String> {
    let mut executables = Vec::new();
    for (index, line) in messages.lines().enumerate() {
        let message: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "cargo emitted invalid JSON on line {} while locating the composite test: {error}",
                index + 1
            )
        })?;
        let is_composite_test = message.get("reason").and_then(serde_json::Value::as_str)
            == Some("compiler-artifact")
            && message
                .pointer("/target/name")
                .and_then(serde_json::Value::as_str)
                == Some("composite_corpus")
            && message
                .pointer("/target/kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("test")));
        if !is_composite_test {
            continue;
        }
        let executable = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "composite_corpus compiler artifact did not include an executable".to_owned()
            })?;
        executables.push(PathBuf::from(executable));
    }
    executables.sort();
    executables.dedup();
    match executables.as_slice() {
        [executable] => Ok(executable.clone()),
        [] => Err("cargo did not report a composite_corpus test executable".into()),
        _ => Err(format!(
            "cargo reported multiple composite_corpus test executables: {executables:?}"
        )),
    }
}

fn composite_test_executable(root: &Path) -> Result<PathBuf, String> {
    let messages = command_output(
        Command::new("cargo")
            .args([
                "test",
                "-p",
                "rustleaks-core",
                "--test",
                "composite_corpus",
                "--no-run",
                "--message-format=json",
            ])
            .current_dir(root),
    )?;
    composite_test_executable_from_messages(&messages)
}

fn resource_test_command(executable: &Path, test: &str, root: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .args([test, "--exact"])
        .env("RUSTLEAKS_BOUNDED_RESOURCE_TEST", test)
        .current_dir(root);
    command
}

fn run_resource_test(
    executable: &Path,
    test: &str,
    root: &Path,
    timeout: Duration,
) -> Result<(), String> {
    command_status_with_timeout(
        &mut resource_test_command(executable, test, root),
        timeout,
        test,
    )
}

pub(crate) fn public_api_check() -> Result<(), String> {
    let root = workspace_root()?;
    let mut version_command = public_api_command();
    version_command.arg("--version");
    require_exact_tool_version(
        &mut version_command,
        CARGO_PUBLIC_API_VERSION,
        "cargo-public-api",
    )?;
    let mut command = public_api_command();
    command
        .args(["-p", "rustleaks-core", "-sss", "--color", "never"])
        .current_dir(&root);
    let actual = command_output(&mut command)?;
    let expected = std::fs::read_to_string(root.join(PUBLIC_API_SNAPSHOT))
        .map_err(|error| format!("cannot read public API snapshot: {error}"))?;
    if actual.trim_end() != expected.trim_end() {
        return Err(format!(
            "rustleaks-core public API differs from {PUBLIC_API_SNAPSHOT}"
        ));
    }
    println!("rustleaks-core public API matches {PUBLIC_API_SNAPSHOT}");
    Ok(())
}

fn public_api_command() -> Command {
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{PUBLIC_API_TOOLCHAIN}"))
        .arg("public-api");
    command
}

fn msrv_check() -> Result<(), String> {
    let root = workspace_root()?;
    let target = ScopedTempDir::new("msrv")?;
    command_status_with_timeout(
        Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target.path)
            .args([
                "+1.95.0",
                "check",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--offline",
            ]),
        Duration::from_mins(20),
        "Rust 1.95 MSRV check",
    )?;
    println!("Rust 1.95 MSRV check passed");
    Ok(())
}

fn clean_worktree_check() -> Result<(), String> {
    let root = workspace_root()?;
    let status = command_output(Command::new("git").current_dir(&root).args([
        "status",
        "--porcelain",
        "--untracked-files=all",
    ]))?;
    if !status.is_empty() {
        return Err(format!(
            "release proof requires a clean worktree:\n{status}"
        ));
    }
    Ok(())
}

fn bounded_composite_resources() -> Result<(), String> {
    let root = workspace_root()?;
    let test_executable = composite_test_executable(&root)?;
    for test in [
        "resource_primary_aux_duplicate_cartesian_is_bounded",
        "resource_many_generics_is_bounded",
        "resource_empty_full_long_malformed_is_bounded",
        "resource_deep_required_graph_is_bounded",
    ] {
        run_resource_test(&test_executable, test, &root, Duration::from_secs(30))?;
    }
    println!("bounded composite resource controls passed");
    Ok(())
}

/// Runs the release checks that no other release dry-run job runs.
pub(crate) fn qualify() -> Result<(), String> {
    clean_worktree_check()?;
    bounded_composite_resources()?;
    public_api_check()?;
    msrv_check()?;
    clean_worktree_check()?;
    println!("clean worktree, bounded composite resources, public API and MSRV checks passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        PUBLIC_API_TOOLCHAIN, composite_test_executable_from_messages, public_api_command,
        resource_test_command, run_resource_test,
    };

    const TIMEOUT_PROBE_TEST: &str = "qualify::tests::resource_launcher_timeout_probe_child";

    const RESOURCE_SELECTOR: &str = "RUSTLEAKS_BOUNDED_RESOURCE_TEST";

    #[test]
    fn public_api_uses_the_pinned_nightly_toolchain() {
        let command = public_api_command();
        assert_eq!(command.get_program(), "cargo");
        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [format!("+{PUBLIC_API_TOOLCHAIN}"), "public-api".to_owned()]
        );
    }

    #[test]
    fn resource_launcher_timeout_probe_child() {
        if std::env::var(RESOURCE_SELECTOR).as_deref() != Ok(TIMEOUT_PROBE_TEST) {
            return;
        }
        let root = std::env::current_dir().unwrap();
        fs::write(root.join("pid"), std::process::id().to_string()).unwrap();
        let path = root.join("heartbeat");
        let mut heartbeat = 0_u64;
        loop {
            fs::write(&path, format!("{heartbeat}\n")).unwrap();
            heartbeat = heartbeat.wrapping_add(1);
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    fn assert_process_was_reaped(pid: &[u8]) {
        let raw_pid = std::str::from_utf8(pid)
            .expect("probe PID was not UTF-8")
            .parse()
            .expect("probe PID was not an integer");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("probe PID was zero");
        match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
            Err(error) if error == rustix::io::Errno::CHILD => {}
            Ok(Some((unreaped, status))) => panic!(
                "timed-out direct child PID {unreaped} remained waitable after launcher return: {status:?}"
            ),
            Ok(None) => {
                panic!("timed-out direct child PID {pid} was still running after launcher return")
            }
            Err(error) => panic!("failed to verify timed-out child PID {pid}: {error}"),
        }
    }

    #[test]
    fn resource_launcher_kills_and_reaps_its_selected_test_body() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rustleaks-xtask-timeout-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let heartbeat = root.join("heartbeat");
        let result = run_resource_test(
            &std::env::current_exe().unwrap(),
            TIMEOUT_PROBE_TEST,
            &root,
            Duration::from_secs(5),
        );
        assert!(
            result
                .unwrap_err()
                .contains("exceeded its external 5 second deadline")
        );
        let stopped = fs::read(&heartbeat).expect("probe body did not start before its deadline");
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            fs::read(&heartbeat).unwrap(),
            stopped,
            "timed-out direct test body continued writing after kill and reap"
        );
        #[cfg(unix)]
        assert_process_was_reaped(&fs::read(root.join("pid")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resource_launcher_command_contract_is_exact() {
        let executable = std::path::Path::new("/tmp/composite-corpus-test");
        let root = std::path::Path::new("/tmp/composite-root");
        let command = resource_test_command(executable, "resource-case", root);
        assert_eq!(command.get_program(), executable.as_os_str());
        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["resource-case", "--exact"]
        );
        assert_eq!(command.get_current_dir(), Some(root));
        assert!(command.get_envs().any(|(key, value)| {
            key == RESOURCE_SELECTOR
                && value.and_then(std::ffi::OsStr::to_str) == Some("resource-case")
        }));
    }

    #[test]
    fn composite_test_executable_is_selected_from_cargo_json() {
        let messages = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"dependency","kind":["lib"]},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"composite_corpus","kind":["test"]},"executable":"/tmp/composite-corpus-test"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        assert_eq!(
            composite_test_executable_from_messages(messages).unwrap(),
            std::path::PathBuf::from("/tmp/composite-corpus-test")
        );
        let missing = r#"{"reason":"build-finished","success":true}"#;
        assert!(composite_test_executable_from_messages(missing).is_err());
    }
}
