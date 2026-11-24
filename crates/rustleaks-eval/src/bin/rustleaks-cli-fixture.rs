//! Native process fixtures for CLI timeout, output-bound and cleanup regressions.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("CLI process fixture failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> io::Result<ExitCode> {
    let mut pid = std::fs::OpenOptions::new();
    pid.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        pid.mode(0o600);
    }
    write!(pid.open("fake-git.pid")?, "{}", std::process::id())?;
    let mode = std::env::var("RUSTLEAKS_CLI_FAKE_GIT_MODE").unwrap_or_default();
    if mode == "malformed" {
        println!("malformed patch bytes");
        return Ok(ExitCode::SUCCESS);
    }
    if mode == "output-limit" {
        let line = "x".repeat(32_767);
        let mut stderr = io::stderr().lock();
        for _ in 0..33 {
            writeln!(stderr, "{line}")?;
        }
        std::thread::sleep(Duration::from_secs(2));
        return Ok(ExitCode::SUCCESS);
    }
    let remote = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .join(" ")
        .contains("ls-remote");
    if mode == "timeout-remote" && remote || mode == "timeout-source" && !remote {
        std::thread::sleep(Duration::from_secs(30));
    } else if remote {
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}
