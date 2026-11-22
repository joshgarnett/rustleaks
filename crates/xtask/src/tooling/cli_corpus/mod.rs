//! Rust CLI replay of the recorded CLI corpus in `testdata/cli-corpus`.
//!
//! The replay checks behavior: exit status, findings, report state and bytes,
//! stdout bytes except help output, stderr event severity, class and fields,
//! whether a usage block was printed, child cleanup, and that stderr never
//! discloses the inline configuration marker. Help, usage and message
//! wording are not compared; the CLI help tests own them.

mod fixture;
mod normalize;
mod observe;
mod process;
mod spec;
mod validation;

use std::fs;
use std::path::{Path, PathBuf};

use super::support::ScopedTempDir;

/// Number of cases in `requests-v1.jsonl`. Update it with the corpus.
const CASE_COUNT: usize = 34;
/// Number of variants across all cases. Update it with the corpus.
const VARIANT_COUNT: usize = 119;

pub(crate) fn check_cli_corpus(
    root: &Path,
    rust_binary: &Path,
    fake_git_binary: &Path,
) -> Result<(), String> {
    let rust_binary = executable_path(rust_binary, "Rust CLI")?;
    let fake_git_binary = executable_path(fake_git_binary, "CLI fixture helper")?;
    let corpus = root.join("testdata/cli-corpus");
    let rows = spec::validate_requests(&read(&corpus.join("requests-v1.jsonl"))?)?;
    let variants = validation::bind_expected(
        &rows,
        &read(&corpus.join("outcomes-v1.jsonl"))?,
        cfg!(windows),
    )?;
    // Catches a case or variant removed from both files together.
    if rows.len() != CASE_COUNT || variants.len() != VARIANT_COUNT {
        return Err(format!(
            "CLI corpus has {} cases and {} variants, expected {CASE_COUNT} and {VARIANT_COUNT}",
            rows.len(),
            variants.len()
        ));
    }
    let mut executed = 0;
    let mut inapplicable = 0;
    for variant in &variants {
        if validation::inapplicable(&variant.request, cfg!(windows), cfg!(target_os = "linux"))
            .is_some()
        {
            inapplicable += 1;
            continue;
        }
        let actual = observe::observe(
            &rust_binary,
            &variant.case_id,
            &variant.request,
            &fake_git_binary,
        )?;
        validation::compare(&variant.id, &actual, &variant.expected)?;
        executed += 1;
    }
    println!(
        "CLI corpus: {} variants, {executed} executed, {inapplicable} not applicable on this platform",
        variants.len()
    );
    Ok(())
}

fn executable_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = std::path::absolute(path)
        .map_err(|error| format!("cannot resolve {label} executable: {error}"))?;
    if !path.is_file() {
        return Err(format!("{label} is not a file"));
    }
    Ok(path)
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn newline_records<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a [u8]>, String> {
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} JSONL lacks final newline"));
    }
    let mut records = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            if index == start {
                return Err(format!("{label} contains blank line"));
            }
            records.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    Ok(records)
}

fn git_executable() -> Result<PathBuf, String> {
    runfile("RUSTLEAKS_CLI_GIT_RUNFILE")
}

fn runfile(name: &str) -> Result<PathBuf, String> {
    let key = std::env::var_os(name).ok_or_else(|| format!("missing required {name}"))?;
    if Path::new(&key).is_absolute() {
        return executable_path(Path::new(&key), name);
    }
    for root in ["RUNFILES_DIR", "TEST_SRCDIR"] {
        if let Some(root) = std::env::var_os(root) {
            for path in [
                PathBuf::from(&root).join(&key),
                PathBuf::from(root).join("_main").join(&key),
            ] {
                if path.is_file() {
                    return executable_path(&path, name);
                }
            }
        }
    }
    if let Some(manifest) = std::env::var_os("RUNFILES_MANIFEST_FILE") {
        for line in fs::read_to_string(manifest)
            .map_err(|error| format!("cannot read runfile manifest: {error}"))?
            .lines()
        {
            if let Some((candidate, path)) = line.split_once(' ')
                && (candidate == key.to_string_lossy()
                    || candidate == format!("_main/{}", key.to_string_lossy())
                    || key.to_string_lossy().strip_prefix("../") == Some(candidate))
            {
                return executable_path(Path::new(path), name);
            }
        }
    }
    if cfg!(windows) && key == "git" {
        for parent in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let path = parent.join("git.exe");
            if path.is_file() {
                return executable_path(&path, name);
            }
        }
    }
    Err(format!("cannot resolve required runfile {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "runs in the dedicated Bazel cli_regression_test with native binary runfiles"]
    fn cli_corpus_replays_with_native_binaries() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let cli = runfile("RUSTLEAKS_CLI_RUNFILE").expect("Bazel Rust CLI runfile");
        let helper =
            runfile("RUSTLEAKS_CLI_FIXTURE_RUNFILE").expect("Bazel native fixture runfile");
        check_cli_corpus(&root, &cli, &helper).expect("Rust CLI corpus replay");
    }

    #[test]
    fn jsonl_boundaries_fail_closed() {
        assert!(newline_records(b"{}", "test").is_err());
        assert!(newline_records(b"{}\n\n", "test").is_err());
        assert_eq!(newline_records(b"{}\n[]\n", "test").unwrap().len(), 2);
    }
}
