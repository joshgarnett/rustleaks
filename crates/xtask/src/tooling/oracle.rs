//! Bounded execution of declarative compatibility requests against pinned Go.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::artifacts::GeneratedTree;
use super::support::TempDir;
use crate::command_status_with_timeout;

const REVISION: &str = "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b";
const CONFIG_SHA256: &str = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
const MAX_OUTCOME_BYTES: u64 = 64 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 16 * 1024;

const REGEX_ARTIFACTS: &[&str] = &[
    "README.md",
    "expressions-v1.jsonl",
    "manifest-v1.json",
    "outcomes-v1.jsonl",
    "request-metadata-v1.jsonl",
    "requests-v1.jsonl",
];
const DETECT_ARTIFACTS: &[&str] = &[
    "README.md",
    "manifest-v1.json",
    "matrix-coverage-v1.json",
    "outcomes-v1.jsonl",
    "request-metadata-v1.jsonl",
    "requests-v1.jsonl",
];
const ALLOWLIST_ARTIFACTS: &[&str] = &[
    "README.md",
    "coverage-v1.json",
    "manifest-v1.json",
    "outcomes-v1.jsonl",
    "request-metadata-v1.jsonl",
    "requests-v1.jsonl",
];
const DECODER_ARTIFACTS: &[&str] = &[
    "README.md",
    "coverage-v1.json",
    "manifest-v1.json",
    "negative-controls-v1.json",
    "outcomes-v1.jsonl",
    "request-metadata-v1.jsonl",
    "requests-v1.jsonl",
];

#[derive(Clone, Copy)]
pub(crate) enum Corpus {
    Regex,
    Detect,
    Allowlist,
    Decoder,
}

impl Corpus {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Detect => "detect",
            Self::Allowlist => "allowlist",
            Self::Decoder => "decoder",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "regex" => Some(Self::Regex),
            "detect" => Some(Self::Detect),
            "allowlist" => Some(Self::Allowlist),
            "decoder" => Some(Self::Decoder),
            _ => None,
        }
    }

    const fn fresh_process_per_request(self) -> bool {
        matches!(self, Self::Allowlist | Self::Decoder)
    }

    const fn timeout(self) -> Duration {
        match self {
            Self::Regex => Duration::from_secs(180),
            Self::Detect | Self::Allowlist => Duration::from_secs(60),
            Self::Decoder => Duration::from_secs(120),
        }
    }

    const fn artifacts(self) -> &'static [&'static str] {
        match self {
            Self::Regex => REGEX_ARTIFACTS,
            Self::Detect => DETECT_ARTIFACTS,
            Self::Allowlist => ALLOWLIST_ARTIFACTS,
            Self::Decoder => DECODER_ARTIFACTS,
        }
    }
}

pub(crate) fn replay_corpus(root: &Path, corpus: Corpus) -> Result<(), String> {
    let corpus_root = root
        .join("compat")
        .join(format!("{}-corpus", corpus.name()));
    generate_corpus(root, corpus, &corpus_root, true)
}

/// Regenerates one direct-oracle corpus or checks an existing output tree.
///
/// The committed request, metadata, coverage, control, manifest, and README
/// files are canonical inputs. Only `outcomes-v1.jsonl` is observed afresh
/// from the pinned Go oracle. The explicit output root is always handled as an
/// exact tree, including missing and unexpected files.
pub(crate) fn generate_corpus(
    root: &Path,
    corpus: Corpus,
    output_root: &Path,
    check: bool,
) -> Result<(), String> {
    let corpus_root = root
        .join("compat")
        .join(format!("{}-corpus", corpus.name()));
    validate_canonical_file_set(&corpus_root, corpus.artifacts())?;
    let requests_path = corpus_root.join("requests-v1.jsonl");
    let requests = fs::read(&requests_path)
        .map_err(|error| format!("cannot read {}: {error}", requests_path.display()))?;

    let temporary = TempDir::new(&format!("{}-oracle", corpus.name()))?;
    let oracle_root = root.join("crates/rustleaks-compat/oracle");
    let binary = build_oracle(&oracle_root, &temporary)?;
    let outcomes = generate_outcomes(
        corpus,
        &binary,
        &oracle_root,
        &temporary,
        &requests_path,
        &requests,
    )?;
    validate_outcomes(corpus, &requests, &outcomes)?;
    let tree = generated_tree(&corpus_root, corpus.artifacts(), &outcomes)?;
    tree.write_or_check(output_root, check)?;
    println!(
        "{} corpus {} from fresh pinned-Go oracle outcomes",
        corpus.name(),
        if check { "verified" } else { "generated" }
    );
    Ok(())
}

fn build_oracle(oracle_root: &Path, temporary: &TempDir) -> Result<PathBuf, String> {
    let binary = temporary.path.join(if cfg!(windows) {
        "rustleaks-oracle.exe"
    } else {
        "rustleaks-oracle"
    });
    run_bounded(
        Command::new("go")
            .current_dir(oracle_root)
            .args(["test", "./..."])
            .env("GOCACHE", temporary.path.join("go-cache")),
        temporary,
        "go-test",
        Duration::from_secs(180),
    )?;
    run_bounded(
        Command::new("go")
            .current_dir(oracle_root)
            .args(["build", "-o"])
            .arg(&binary)
            .arg(".")
            .env("GOCACHE", temporary.path.join("go-cache")),
        temporary,
        "go-build",
        Duration::from_secs(180),
    )?;
    Ok(binary)
}

fn generate_outcomes(
    corpus: Corpus,
    binary: &Path,
    oracle_root: &Path,
    temporary: &TempDir,
    requests_path: &Path,
    requests: &[u8],
) -> Result<Vec<u8>, String> {
    if corpus.fresh_process_per_request() {
        return generate_isolated(corpus, binary, oracle_root, temporary, requests);
    }

    let fresh = temporary.path.join("fresh-outcomes.jsonl");
    let mut command = Command::new(binary);
    command
        .current_dir(oracle_root)
        .arg(format!("--{}", corpus.name()))
        .arg("-input")
        .arg(requests_path)
        .arg("-output")
        .arg(&fresh)
        .env("GOMEMLIMIT", "512MiB")
        .env("GOMAXPROCS", "2");
    run_bounded(&mut command, temporary, corpus.name(), corpus.timeout())?;
    read_bounded(&fresh, MAX_OUTCOME_BYTES)
}

fn generate_isolated(
    corpus: Corpus,
    binary: &Path,
    oracle_root: &Path,
    temporary: &TempDir,
    requests: &[u8],
) -> Result<Vec<u8>, String> {
    let request_lines = newline_records(requests, "requests")?;
    let request_path = temporary.path.join("request.jsonl");
    let outcome_path = temporary.path.join("outcome.jsonl");
    let mut outcomes = Vec::new();
    for (index, request) in request_lines.iter().enumerate() {
        fs::write(&request_path, request)
            .map_err(|error| format!("cannot write {}: {error}", request_path.display()))?;
        match fs::remove_file(&outcome_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot remove stale {}: {error}",
                    outcome_path.display()
                ));
            }
        }
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
        let actual = read_bounded(&outcome_path, MAX_OUTCOME_BYTES)?;
        let lines = newline_records(&actual, "isolated outcome")?;
        if lines.len() != 1 {
            return Err(format!(
                "{} request {} produced {} outcomes instead of one",
                corpus.name(),
                index + 1,
                lines.len()
            ));
        }
        outcomes.extend_from_slice(&actual);
        if u64::try_from(outcomes.len()).unwrap_or(u64::MAX) > MAX_OUTCOME_BYTES {
            return Err(format!(
                "{} outcomes exceed the {MAX_OUTCOME_BYTES}-byte limit",
                corpus.name()
            ));
        }
    }
    Ok(outcomes)
}

fn generated_tree(
    corpus_root: &Path,
    artifacts: &[&str],
    outcomes: &[u8],
) -> Result<GeneratedTree, String> {
    let mut tree = GeneratedTree::default();
    for name in artifacts {
        let bytes = if *name == "outcomes-v1.jsonl" {
            outcomes.to_owned()
        } else {
            let path = corpus_root.join(name);
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?
        };
        tree.insert(name, bytes)?;
    }
    Ok(tree)
}

fn validate_canonical_file_set(root: &Path, artifacts: &[&str]) -> Result<(), String> {
    let expected = artifacts.iter().map(PathBuf::from).collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("cannot read canonical corpus {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read canonical corpus entry in {}: {error}",
                root.display()
            )
        })?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if !kind.is_file() {
            return Err(format!(
                "canonical corpus contains a non-file artifact: {}",
                entry.path().display()
            ));
        }
        actual.insert(PathBuf::from(entry.file_name()));
    }
    if let Some(missing) = expected.difference(&actual).next() {
        return Err(format!(
            "canonical corpus is missing expected artifact: {}",
            root.join(missing).display()
        ));
    }
    if let Some(extra) = actual.difference(&expected).next() {
        return Err(format!(
            "canonical corpus contains unexpected artifact: {}",
            root.join(extra).display()
        ));
    }
    Ok(())
}

fn validate_outcomes(corpus: Corpus, requests: &[u8], outcomes: &[u8]) -> Result<(), String> {
    let request_lines = newline_records(requests, "requests")?;
    let outcome_lines = newline_records(outcomes, "outcomes")?;
    if request_lines.len() != outcome_lines.len() {
        return Err(format!(
            "{} request/outcome count mismatch: {} versus {}",
            corpus.name(),
            request_lines.len(),
            outcome_lines.len()
        ));
    }
    for (index, (request, outcome)) in request_lines.iter().zip(outcome_lines).enumerate() {
        let request: serde_json::Value = serde_json::from_slice(request).map_err(|error| {
            format!(
                "{} request {} is invalid JSON: {error}",
                corpus.name(),
                index + 1
            )
        })?;
        let outcome: serde_json::Value = serde_json::from_slice(outcome).map_err(|error| {
            format!(
                "{} outcome {} is invalid JSON: {error}",
                corpus.name(),
                index + 1
            )
        })?;
        let request_id = request["id"]
            .as_str()
            .ok_or_else(|| format!("{} request {} has no string ID", corpus.name(), index + 1))?;
        if outcome["id"].as_str() != Some(request_id) {
            return Err(format!(
                "{} outcome {} ID does not match request {request_id}",
                corpus.name(),
                index + 1
            ));
        }
        if outcome["oracle_mode"].as_str() != Some(corpus.name()) {
            return Err(format!(
                "{} outcome {} has the wrong oracle mode",
                corpus.name(),
                index + 1
            ));
        }
        if outcome["upstream_revision"].as_str() != Some(REVISION)
            || outcome["default_config_sha256"].as_str() != Some(CONFIG_SHA256)
        {
            return Err(format!(
                "{} outcome {} does not identify the pinned Go oracle",
                corpus.name(),
                index + 1
            ));
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let size = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
        .len();
    if size > limit {
        return Err(format!(
            "{} is {size} bytes, exceeding the {limit}-byte limit",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
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
        let stdout = diagnostic_tail(&stdout_path);
        let stderr = diagnostic_tail(&stderr_path);
        return Err(format!(
            "{error}\nstdout:\n{}\nstderr:\n{}",
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
}

fn diagnostic_tail(path: &Path) -> String {
    let result = (|| -> Result<Vec<u8>, std::io::Error> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let start = length.saturating_sub(DIAGNOSTIC_LIMIT as u64);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::with_capacity(usize::try_from(length - start).unwrap_or(0));
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    result
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        ALLOWLIST_ARTIFACTS, Corpus, REVISION, generated_tree, newline_records,
        validate_canonical_file_set, validate_outcomes,
    };
    use crate::tooling::support::TempDir;

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
    fn outcome_validation_requires_matching_identity_mode_and_pin() {
        let requests = br#"{"id":"case"}
"#;
        let outcomes = br#"{"id":"case","oracle_mode":"allowlist","upstream_revision":"b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b","default_config_sha256":"e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"}
"#;
        assert!(validate_outcomes(Corpus::Allowlist, requests, outcomes).is_ok());
        assert!(validate_outcomes(Corpus::Decoder, requests, outcomes).is_err());
        let outcome_text = std::str::from_utf8(outcomes).unwrap();
        assert!(
            validate_outcomes(
                Corpus::Allowlist,
                requests,
                outcome_text.replacen("\"case\"", "\"wrong\"", 1).as_bytes()
            )
            .is_err()
        );
        assert!(
            validate_outcomes(
                Corpus::Allowlist,
                requests,
                outcome_text.replacen(REVISION, "wrong", 1).as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn generated_corpus_tree_replaces_only_outcomes_and_checks_exact_files() {
        let temporary = TempDir::new("oracle-tree").unwrap();
        let canonical = temporary.path.join("canonical");
        let output = temporary.path.join("output");
        fs::create_dir(&canonical).unwrap();
        for artifact in ALLOWLIST_ARTIFACTS {
            fs::write(canonical.join(artifact), format!("committed {artifact}\n")).unwrap();
        }
        validate_canonical_file_set(&canonical, ALLOWLIST_ARTIFACTS).unwrap();
        let tree = generated_tree(&canonical, ALLOWLIST_ARTIFACTS, b"fresh outcome\n").unwrap();
        tree.write_or_check(&output, false).unwrap();
        tree.write_or_check(&output, true).unwrap();
        assert_eq!(
            fs::read(output.join("outcomes-v1.jsonl")).unwrap(),
            b"fresh outcome\n"
        );
        assert_eq!(
            fs::read(output.join("requests-v1.jsonl")).unwrap(),
            b"committed requests-v1.jsonl\n"
        );
        fs::write(output.join("outcomes-v1.jsonl"), b"stale\n").unwrap();
        assert!(tree.write_or_check(&output, true).is_err());
        fs::write(output.join("outcomes-v1.jsonl"), b"fresh outcome\n").unwrap();
        fs::remove_file(output.join("README.md")).unwrap();
        assert!(tree.write_or_check(&output, true).is_err());
        fs::write(output.join("README.md"), b"committed README.md\n").unwrap();
        fs::write(output.join("extra"), b"stale").unwrap();
        assert!(tree.write_or_check(&output, true).is_err());
    }

    #[test]
    fn canonical_file_set_rejects_missing_and_extra_artifacts() {
        let temporary = TempDir::new("oracle-canonical").unwrap();
        let canonical = temporary.path.join("canonical");
        fs::create_dir(&canonical).unwrap();
        for artifact in ALLOWLIST_ARTIFACTS {
            fs::write(canonical.join(artifact), b"canonical").unwrap();
        }
        fs::remove_file(canonical.join("manifest-v1.json")).unwrap();
        assert!(validate_canonical_file_set(&canonical, ALLOWLIST_ARTIFACTS).is_err());
        fs::write(canonical.join("manifest-v1.json"), b"canonical").unwrap();
        fs::write(canonical.join("unexpected"), b"unexpected").unwrap();
        assert!(validate_canonical_file_set(&canonical, ALLOWLIST_ARTIFACTS).is_err());
    }

    #[test]
    fn isolation_policy_preserves_state_sensitive_corpora() {
        assert!(Corpus::Allowlist.fresh_process_per_request());
        assert!(Corpus::Decoder.fresh_process_per_request());
        assert!(!Corpus::Regex.fresh_process_per_request());
        assert!(!Corpus::Detect.fresh_process_per_request());
    }
}
