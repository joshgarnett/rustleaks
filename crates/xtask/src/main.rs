#![forbid(unsafe_code)]
//! Stable repository validation commands.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod build_system;
mod comparison;
mod comparison_quality;
mod comparison_workloads;
mod docs_check;
mod embedded_python;
mod fuzzing;
mod package;
mod performance;
mod qualify;
mod release_artifact;
mod security;
mod security_deep;
mod tooling;
mod workflows;

use tooling::command_output;

/// Gitleaks commit that `NOTICE` names for attribution.
const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
/// SHA-256 of the shipped default rules, `crates/rustleaks-core/default/gitleaks.toml`.
/// It equals `rustleaks_core::config::DEFAULT_CONFIG_SHA256`.
const DEFAULT_RULES_SHA256: &str =
    "35c17b31383953534b7e5769082564aab30a52606f32a310a217e99b341280b8";
const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
const CARGO_FUZZ_VERSION: &str = "cargo-fuzz 0.13.2";
/// The eight required targets. See `docs/dev/testing.md#platforms`.
pub(crate) const REQUIRED_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];
const FUZZ_TOOLCHAIN: &str = "nightly-2026-08-21";
fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command] if command == "qualify" => qualify::qualify(),
        [command, arguments @ ..] if command == "generate" => {
            tooling::run_generate(&workspace_root()?, arguments)
        }
        [command] if command == "public-api-check" => qualify::public_api_check(),
        [command] if command == "build-system-check" => build_system::check(&workspace_root()?),
        [command] if command == "package-check" => package::package_check(),
        [command] if command == "release-dry-run" => package::release_dry_run(),
        [command, arguments @ ..] if command == "release-artifact" => {
            release_artifact::run(&workspace_root()?, arguments)
        }
        [command] if command == "security-check" => security::security_check(),
        [command, arguments @ ..] if command == "security-deep" => {
            security_deep::run(&workspace_root()?, arguments)
        }
        [command] if command == "docs-check" => docs_check::run(&workspace_root()?),
        [command, arguments @ ..] if command == "compare-quality" => {
            comparison_quality::run(&workspace_root()?, arguments)
        }
        [command, arguments @ ..] if command == "fuzz" => {
            fuzzing::run(&workspace_root()?, arguments)
        }
        [command] if command == "fuzz-build" => fuzz_build(),
        [command] if command == "fuzz-smoke" => fuzz_smoke(),
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "run" => {
            performance::run(arguments)
        }
        [command, subcommand] if command == "perf" && subcommand == "check" => performance::check(),
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "fixtures" => {
            performance::fixtures(arguments)
        }
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "report" => {
            performance::report(arguments)
        }
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "profile" => {
            performance::profile(arguments)
        }
        [command, subcommand, arguments @ ..] if command == "perf" && subcommand == "calibrate" => {
            performance::calibrate(arguments)
        }
        [command, subcommand, arguments @ ..]
            if command == "perf" && subcommand == "representative" =>
        {
            performance::representative(arguments)
        }
        [command, arguments @ ..] if command == "compare" => {
            comparison::run(&workspace_root()?, arguments)
        }
        [command, arguments @ ..] if command == "compare-workloads" => {
            comparison_workloads::run(&workspace_root()?, arguments)
        }
        _ => Err(usage()),
    }
}

/// Top-level subcommands accepted by `run`. The usage text and the
/// documentation command check read this list, and a unit test keeps it in
/// step with the dispatch.
const XTASK_COMMANDS: &[&str] = &[
    "qualify",
    "public-api-check",
    "build-system-check",
    "package-check",
    "release-dry-run",
    "release-artifact",
    "security-check",
    "security-deep",
    "docs-check",
    "fuzz-build",
    "fuzz-smoke",
    "fuzz",
    "generate",
    "perf",
    "compare",
    "compare-quality",
    "compare-workloads",
];

/// Subcommands accepted after `perf`.
const PERF_SUBCOMMANDS: &[&str] = &[
    "run",
    "check",
    "fixtures",
    "representative",
    "profile",
    "calibrate",
    "report",
];

fn usage() -> String {
    let commands = XTASK_COMMANDS
        .iter()
        .map(|command| match *command {
            "release-artifact" | "security-deep" | "fuzz" | "generate" | "compare-quality"
            | "compare-workloads" => {
                format!("{command} [ARGS]")
            }
            "perf" => format!("perf <{}> [ARGS]", PERF_SUBCOMMANDS.join("|")),
            "compare" => format!(
                "compare <{}> [ARGS]",
                comparison::COMPARE_SUBCOMMANDS.join("|")
            ),
            _ => (*command).to_owned(),
        })
        .collect::<Vec<_>>();
    format!("usage: cargo xtask {{{}}}", commands.join("|"))
}

fn workspace_root() -> Result<PathBuf, String> {
    if let Some(root) = env::var_os("BUILD_WORKSPACE_DIRECTORY").filter(|root| !root.is_empty()) {
        return Ok(PathBuf::from(root));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot locate workspace root".to_owned())?;
    if root.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(root)
    }
}

fn require_exact_tool_version(
    command: &mut Command,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let actual = command_output(command)?;
    if actual != expected {
        return Err(format!(
            "{label} version mismatch: expected `{expected}`, got `{actual}`"
        ));
    }
    Ok(())
}

fn fuzz_build() -> Result<(), String> {
    let root = workspace_root()?;
    let toolchain = format!("+{FUZZ_TOOLCHAIN}");
    require_exact_tool_version(
        Command::new("cargo").args(["fuzz", "--version"]),
        CARGO_FUZZ_VERSION,
        "cargo-fuzz",
    )?;
    for workspace in fuzzing::workspaces() {
        let manifest = format!("crates/{workspace}/fuzz/Cargo.toml");
        command_output(Command::new("cargo").current_dir(&root).args([
            toolchain.as_str(),
            "check",
            "--locked",
            "--offline",
            "--all-targets",
            "--manifest-path",
            manifest.as_str(),
        ]))?;
    }
    println!(
        "all {} fuzz targets compile with their locked standalone manifests",
        fuzzing::TARGETS.len()
    );
    Ok(())
}

fn fuzz_smoke() -> Result<(), String> {
    fuzzing::smoke(&workspace_root()?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use super::{build_system, workspace_root};
    use crate::tooling::{TimeoutChild, diagnostic_tail, wait_for_child_with_timeout};

    #[test]
    fn subprocess_diagnostics_preserve_bounded_output_tails() {
        assert_eq!(diagnostic_tail(b"", 4), "<empty>");
        assert_eq!(diagnostic_tail(b" full output \n", 32), "full output");
        assert_eq!(
            diagnostic_tail(b"prefix-failure detail\n", 15),
            "... 7 bytes omitted ...\nfailure detail"
        );
    }

    #[derive(Default)]
    struct TimeoutLifecycleProbe {
        killed: bool,
        reaped: bool,
        fail_reap: bool,
    }

    impl TimeoutChild for TimeoutLifecycleProbe {
        fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
            Ok(None)
        }

        fn kill(&mut self) -> std::io::Result<()> {
            self.killed = true;
            Ok(())
        }

        fn reap(&mut self) -> std::io::Result<()> {
            assert!(self.killed, "child must be killed before it is reaped");
            self.reaped = true;
            if self.fail_reap {
                Err(std::io::Error::other("injected reap failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn timeout_lifecycle_requires_kill_and_reap() {
        let mut child = TimeoutLifecycleProbe::default();
        let error = wait_for_child_with_timeout(
            &mut child,
            Duration::ZERO,
            "lifecycle probe",
            "injected child",
        )
        .unwrap_err();
        assert!(error.contains("exceeded its external 0 second deadline"));
        assert!(child.killed, "timeout did not terminate the child");
        assert!(child.reaped, "timeout did not reap the terminated child");
    }

    #[test]
    fn timeout_lifecycle_fails_closed_when_reap_fails() {
        let mut child = TimeoutLifecycleProbe {
            fail_reap: true,
            ..TimeoutLifecycleProbe::default()
        };
        let error = wait_for_child_with_timeout(
            &mut child,
            Duration::ZERO,
            "lifecycle probe",
            "injected child",
        )
        .unwrap_err();
        assert!(error.contains("failed to reap timed-out lifecycle probe"));
        assert!(child.killed);
        assert!(child.reaped);
    }

    #[test]
    fn cargo_and_bazel_build_contracts_match() {
        build_system::check(&workspace_root().unwrap()).unwrap();
    }

    /// Returns the quoted names compared with `variable` in `source`.
    fn compared_names<'a>(source: &'a str, variable: &str) -> BTreeSet<&'a str> {
        let pattern = format!(" {variable} == \"");
        source
            .match_indices(&pattern)
            .filter_map(|(index, _)| source[index + pattern.len()..].split_once('"'))
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn listed_commands_match_dispatch() {
        let source = include_str!("main.rs");
        let start = source.find("fn run(args: &[String])").unwrap();
        let end = start + source[start..].find("\nfn usage()").unwrap();
        let dispatch = &source[start..end];
        assert_eq!(
            compared_names(dispatch, "command"),
            super::XTASK_COMMANDS.iter().copied().collect()
        );
        assert_eq!(
            compared_names(dispatch, "subcommand"),
            super::PERF_SUBCOMMANDS.iter().copied().collect()
        );
        let usage = super::usage();
        for command in super::XTASK_COMMANDS.iter().chain(super::PERF_SUBCOMMANDS) {
            assert!(usage.contains(command), "usage omits {command}");
        }
    }
}
