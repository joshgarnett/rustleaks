//! Bounded execution of declarative compatibility requests against pinned Go.

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::support::TempDir;
use crate::command_status_with_timeout;

#[derive(Clone, Copy)]
pub(crate) enum Corpus {
    Regex,
    Detect,
    Allowlist,
    Decoder,
}

impl Corpus {
    const fn name(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Detect => "detect",
            Self::Allowlist => "allowlist",
            Self::Decoder => "decoder",
        }
    }

    const fn fresh_process_per_request(self) -> bool {
        matches!(self, Self::Allowlist)
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::Regex => Duration::from_secs(180),
            Self::Detect | Self::Allowlist => Duration::from_secs(60),
            Self::Decoder => Duration::from_secs(120),
        }
    }
}

pub(crate) fn replay_corpus(root: &Path, corpus: Corpus) -> Result<(), String> {
    let temporary = TempDir::new(&format!("{}-oracle", corpus.name()))?;
    let oracle_root = root.join("crates/rustleaks-compat/oracle");
    let binary = temporary.path.join(if cfg!(windows) {
        "rustleaks-oracle.exe"
    } else {
        "rustleaks-oracle"
    });
    run_bounded(
        Command::new("go")
            .current_dir(&oracle_root)
            .args(["test", "./..."])
            .env("GOCACHE", temporary.path.join("go-cache")),
        &temporary,
        "go-test",
        Duration::from_secs(180),
    )?;
    run_bounded(
        Command::new("go")
            .current_dir(&oracle_root)
            .args(["build", "-o"])
            .arg(&binary)
            .arg(".")
            .env("GOCACHE", temporary.path.join("go-cache")),
        &temporary,
        "go-build",
        Duration::from_secs(180),
    )?;

    let corpus_root = root
        .join("compat")
        .join(format!("{}-corpus", corpus.name()));
    let requests_path = corpus_root.join("requests-v1.jsonl");
    let outcomes_path = corpus_root.join("outcomes-v1.jsonl");
    let requests = fs::read(&requests_path)
        .map_err(|error| format!("cannot read {}: {error}", requests_path.display()))?;
    let expected = fs::read(&outcomes_path)
        .map_err(|error| format!("cannot read {}: {error}", outcomes_path.display()))?;
    if corpus.fresh_process_per_request() {
        replay_isolated(
            corpus,
            &binary,
            &oracle_root,
            &temporary,
            &requests,
            &expected,
        )?;
    } else {
        let fresh = temporary.path.join("fresh-outcomes.jsonl");
        let mut command = Command::new(&binary);
        command
            .current_dir(&oracle_root)
            .arg(format!("--{}", corpus.name()))
            .arg("-input")
            .arg(&requests_path)
            .arg("-output")
            .arg(&fresh)
            .env("GOMEMLIMIT", "512MiB")
            .env("GOMAXPROCS", "2");
        run_bounded(&mut command, &temporary, corpus.name(), corpus.timeout())?;
        let actual = fs::read(&fresh)
            .map_err(|error| format!("cannot read {}: {error}", fresh.display()))?;
        compare_bytes(corpus.name(), &expected, &actual)?;
    }
    println!(
        "{} corpus matches fresh pinned-Go oracle outcomes",
        corpus.name()
    );
    Ok(())
}

fn replay_isolated(
    corpus: Corpus,
    binary: &Path,
    oracle_root: &Path,
    temporary: &TempDir,
    requests: &[u8],
    expected: &[u8],
) -> Result<(), String> {
    let request_lines = newline_records(requests, "requests")?;
    let expected_lines = newline_records(expected, "outcomes")?;
    if request_lines.len() != expected_lines.len() {
        return Err(format!(
            "{} request/outcome count mismatch: {} versus {}",
            corpus.name(),
            request_lines.len(),
            expected_lines.len()
        ));
    }
    let request_path = temporary.path.join("request.jsonl");
    let outcome_path = temporary.path.join("outcome.jsonl");
    for (index, (request, wanted)) in request_lines.iter().zip(&expected_lines).enumerate() {
        fs::write(&request_path, request)
            .map_err(|error| format!("cannot write {}: {error}", request_path.display()))?;
        let mut command = Command::new(binary);
        command
            .current_dir(oracle_root)
            .arg(format!("--{}", corpus.name()))
            .arg("-input")
            .arg(&request_path)
            .arg("-output")
            .arg(&outcome_path)
            .env("GOMEMLIMIT", "512MiB")
            .env("GOMAXPROCS", "2");
        run_bounded(
            &mut command,
            temporary,
            &format!("{} request {}", corpus.name(), index + 1),
            corpus.timeout(),
        )?;
        let actual = fs::read(&outcome_path)
            .map_err(|error| format!("cannot read {}: {error}", outcome_path.display()))?;
        compare_bytes(
            &format!("{} outcome line {}", corpus.name(), index + 1),
            wanted,
            &actual,
        )?;
    }
    Ok(())
}

fn newline_records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} JSONL lacks a final newline"));
    }
    let mut records = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            if index == start {
                return Err(format!("{label} JSONL contains a blank line"));
            }
            records.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    Ok(records)
}

fn compare_bytes(label: &str, expected: &[u8], actual: &[u8]) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    let offset = expected
        .iter()
        .zip(actual)
        .position(|(left, right)| left != right)
        .unwrap_or(expected.len().min(actual.len()));
    Err(format!(
        "{label} differs at byte {offset}: expected {} bytes, got {}",
        expected.len(),
        actual.len()
    ))
}

fn run_bounded(
    command: &mut Command,
    temporary: &TempDir,
    label: &str,
    timeout: Duration,
) -> Result<(), String> {
    let safe_label = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let stdout_path = temporary.path.join(format!("{safe_label}.stdout"));
    let stderr_path = temporary.path.join(format!("{safe_label}.stderr"));
    let stdout = File::create(&stdout_path)
        .map_err(|error| format!("cannot create {}: {error}", stdout_path.display()))?;
    let stderr = File::create(&stderr_path)
        .map_err(|error| format!("cannot create {}: {error}", stderr_path.display()))?;
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Err(error) = command_status_with_timeout(command, timeout, label) {
        let stdout = fs::read_to_string(&stdout_path).unwrap_or_default();
        let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
        return Err(format!(
            "{error}\nstdout:\n{}\nstderr:\n{}",
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{compare_bytes, newline_records};

    #[test]
    fn jsonl_records_preserve_exact_line_bytes() {
        assert_eq!(
            newline_records(b"{\"a\":1}\n{\"b\":2}\n", "test").unwrap(),
            [b"{\"a\":1}\n".as_slice(), b"{\"b\":2}\n".as_slice()]
        );
        assert!(newline_records(b"{}", "test").is_err());
        assert!(newline_records(b"{}\n\n", "test").is_err());
    }

    #[test]
    fn byte_comparison_reports_the_first_offset() {
        assert!(compare_bytes("same", b"abc", b"abc").is_ok());
        let error = compare_bytes("different", b"abc", b"axc").unwrap_err();
        assert!(error.contains("byte 1"));
    }
}
