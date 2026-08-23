//! Bounded, isolated execution of configuration requests against pinned Go.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::spec::{Canonical, REVISION};
use crate::tooling::support::{TempDir, command_status_with_timeout, diagnostic_tail};

const BUILD_TIMEOUT: Duration = Duration::from_secs(180);
const CASE_TIMEOUT: Duration = Duration::from_secs(60);
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CAPTURE_BYTES: u64 = 8 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 16 * 1024;

pub(super) struct Observed {
    pub(super) default_config: Vec<u8>,
    pub(super) outcomes: Vec<u8>,
}

pub(super) fn observe(
    root: &Path,
    upstream: &Path,
    canonical: &Canonical,
    temporary: &TempDir,
) -> Result<Observed, String> {
    if !upstream.is_dir() {
        return Err(format!(
            "missing pinned upstream checkout: {}",
            upstream.display()
        ));
    }
    let workspace = temporary.path.join("config corpus workspace ü");
    fs::create_dir_all(&workspace).map_err(|error| {
        format!(
            "cannot create temporary workspace {}: {error}",
            workspace.display()
        )
    })?;
    let before_revision = git_text(
        upstream,
        &workspace,
        "revision-before",
        &["rev-parse", "HEAD"],
    )?;
    if before_revision.trim() != REVISION {
        return Err(format!(
            "upstream revision differs: expected {REVISION}, got {}",
            before_revision.trim()
        ));
    }
    let before_status = git_text(
        upstream,
        &workspace,
        "status-before",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    let default_config = git_bytes(
        upstream,
        &workspace,
        "default-config",
        &["show", &format!("{REVISION}:config/gitleaks.toml")],
    )?;
    let binary = build_oracle(root, temporary, &workspace)?;
    let outcomes = observe_cases(&binary, canonical, &workspace)?;

    let after_revision = git_text(
        upstream,
        &workspace,
        "revision-after",
        &["rev-parse", "HEAD"],
    )?;
    let after_status = git_text(
        upstream,
        &workspace,
        "status-after",
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if after_revision != before_revision || after_status != before_status {
        return Err("pinned upstream checkout changed while generating config corpus".into());
    }
    Ok(Observed {
        default_config,
        outcomes,
    })
}

fn build_oracle(root: &Path, temporary: &TempDir, workspace: &Path) -> Result<PathBuf, String> {
    let oracle = root.join("crates/rustleaks-compat/oracle");
    let binary = workspace.join(if cfg!(windows) {
        "config oracle ü.exe"
    } else {
        "config oracle ü"
    });
    let stdout = workspace.join("go-build.stdout");
    let stderr = workspace.join("go-build.stderr");
    let mut command = Command::new("go");
    command
        .current_dir(&oracle)
        .args(["build", "-trimpath", "-o"])
        .arg(&binary)
        .arg(".")
        .env("GOCACHE", temporary.path.join("go cache ü"))
        .env(
            "GOMODCACHE",
            std::env::var_os("GOMODCACHE").map_or_else(
                || std::env::temp_dir().join("rustleaks-go-mod-cache"),
                PathBuf::from,
            ),
        )
        .env("GOMEMLIMIT", "768MiB")
        .env("GOMAXPROCS", "2")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdout(Stdio::from(create(&stdout)?))
        .stderr(Stdio::from(create(&stderr)?));
    run(
        &mut command,
        BUILD_TIMEOUT,
        "build config oracle",
        &stdout,
        &stderr,
    )?;
    Ok(binary)
}

fn observe_cases(
    binary: &Path,
    canonical: &Canonical,
    workspace: &Path,
) -> Result<Vec<u8>, String> {
    let request_lines = records(&canonical.requests, "config requests")?;
    if request_lines.len() != canonical.request_values.len() {
        return Err("parsed config request count differs from canonical lines".into());
    }
    let mut outcomes = Vec::new();
    for (index, request) in request_lines.iter().enumerate() {
        let case_root = workspace.join(format!("case {index:03} ü"));
        let cwd = case_root.join("config");
        let fixture_root = case_root.join("testdata/config");
        fs::create_dir_all(&cwd)
            .map_err(|error| format!("cannot create {}: {error}", cwd.display()))?;
        for fixture in &canonical.fixtures {
            let destination = fixture_root.join(&fixture.path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
            }
            fs::write(&destination, &fixture.bytes)
                .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
        }
        let input = case_root.join("request ü.jsonl");
        let stdout = case_root.join("outcome ü.jsonl");
        let stderr = case_root.join("stderr ü.log");
        fs::write(&input, request)
            .map_err(|error| format!("cannot write {}: {error}", input.display()))?;
        let mut command = Command::new(binary);
        command
            .current_dir(&cwd)
            .arg("--config-one")
            .env("GOMEMLIMIT", "768MiB")
            .env("GOMAXPROCS", "2")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .stdin(Stdio::from(File::open(&input).map_err(|error| {
                format!("cannot open {}: {error}", input.display())
            })?))
            .stdout(Stdio::from(create(&stdout)?))
            .stderr(Stdio::from(create(&stderr)?));
        run(
            &mut command,
            CASE_TIMEOUT,
            &format!("config oracle case {index}"),
            &stdout,
            &stderr,
        )?;
        let output = read_bounded(&stdout)?;
        let output_records = records(&output, &format!("config outcome {index}"))?;
        if output_records.len() != 1 {
            return Err(format!(
                "config oracle case {index} returned {} records instead of one",
                output_records.len()
            ));
        }
        outcomes.extend_from_slice(&ruby_json_number_format(output_records[0])?);
        fs::remove_dir_all(&case_root)
            .map_err(|error| format!("cannot remove {}: {error}", case_root.display()))?;
    }
    Ok(outcomes)
}

/// Ruby's JSON round trip preserves Go's object order but renders exponent
/// numbers with a decimal mantissa and at least two exponent digits.
fn ruby_json_number_format(line: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(line.len() + 8);
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < line.len() {
        let byte = line[index];
        if in_string {
            output.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            output.push(byte);
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < line.len()
                && matches!(line[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                index += 1;
            }
            let number = &line[start..index];
            if let Some(exponent) = number.iter().position(|byte| matches!(byte, b'e' | b'E')) {
                let mantissa = &number[..exponent];
                output.extend_from_slice(mantissa);
                if !mantissa.contains(&b'.') {
                    output.extend_from_slice(b".0");
                }
                output.push(b'e');
                let exponent = &number[exponent + 1..];
                let (sign, digits) = exponent
                    .first()
                    .filter(|byte| matches!(byte, b'+' | b'-'))
                    .map_or((b'+', exponent), |sign| (*sign, &exponent[1..]));
                output.push(sign);
                if digits.len() < 2 {
                    output.push(b'0');
                }
                output.extend_from_slice(digits);
            } else {
                output.extend_from_slice(number);
            }
            continue;
        }
        output.push(byte);
        index += 1;
    }
    if in_string || escaped {
        return Err("config oracle returned an unterminated JSON string".into());
    }
    Ok(output)
}

fn git_text(
    upstream: &Path,
    workspace: &Path,
    label: &str,
    args: &[&str],
) -> Result<String, String> {
    let bytes = git_bytes(upstream, workspace, label, args)?;
    String::from_utf8(bytes).map_err(|error| format!("git {label} returned non-UTF-8: {error}"))
}

fn git_bytes(
    upstream: &Path,
    workspace: &Path,
    label: &str,
    args: &[&str],
) -> Result<Vec<u8>, String> {
    let stdout = workspace.join(format!("git-{label}.stdout"));
    let stderr = workspace.join(format!("git-{label}.stderr"));
    let mut command = Command::new("git");
    command
        .current_dir(upstream)
        .args(args)
        .stdout(Stdio::from(create(&stdout)?))
        .stderr(Stdio::from(create(&stderr)?));
    run(
        &mut command,
        GIT_TIMEOUT,
        &format!("git {label}"),
        &stdout,
        &stderr,
    )?;
    read_bounded(&stdout)
}

fn run(
    command: &mut Command,
    timeout: Duration,
    label: &str,
    stdout: &Path,
    stderr: &Path,
) -> Result<(), String> {
    command_status_with_timeout(command, timeout, label).map_err(|error| {
        let out = fs::read(stdout).unwrap_or_default();
        let err = fs::read(stderr).unwrap_or_default();
        format!(
            "{error}\nstdout:\n{}\nstderr:\n{}",
            diagnostic_tail(&out, DIAGNOSTIC_LIMIT),
            diagnostic_tail(&err, DIAGNOSTIC_LIMIT)
        )
    })
}

fn records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} lacks a final newline"));
    }
    let records = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    if records.iter().any(|line| *line == b"\n") {
        return Err(format!("{label} contains a blank record"));
    }
    Ok(records)
}

fn create(path: &Path) -> Result<File, String> {
    File::create(path).map_err(|error| format!("cannot create {}: {error}", path.display()))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.len() > MAX_CAPTURE_BYTES {
        return Err(format!(
            "{} exceeded the {} byte output limit",
            path.display(),
            MAX_CAPTURE_BYTES
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|error| format!("{} output size does not fit usize: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{records, ruby_json_number_format};

    #[test]
    fn records_require_final_newline_and_reject_blanks() {
        assert_eq!(records(b"one\ntwo\n", "test").unwrap().len(), 2);
        assert!(records(b"one", "test").is_err());
        assert!(records(b"one\n\ntwo\n", "test").is_err());
    }

    #[test]
    fn ruby_json_number_format_changes_only_exponent_tokens() {
        let input = br#"{"tiny":5e-324,"small":1.25e-6,"text":"5e-324","whole":1}
"#;
        let expected = br#"{"tiny":5.0e-324,"small":1.25e-06,"text":"5e-324","whole":1}
"#;
        assert_eq!(ruby_json_number_format(input).unwrap(), expected);
    }
}
