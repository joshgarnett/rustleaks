//! Material Git behavior and negative controls retained from the previous generator.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::read;
use super::validation::{
    decode, decode_str, fragment_bytes, outcome_for, required_array, required_str,
};

const NEW_COMMIT: &[u8] = b"53cd7a3c6eb4937f413e3c25e4a9f39289afa69e";

pub(super) fn validate(
    root: &Path,
    requests: &[Value],
    outcomes: &BTreeMap<&str, &Value>,
    _coverage: &Value,
    _negative: &Value,
) -> Result<(), String> {
    validate_argv(outcomes)?;
    validate_fragments(root, outcomes)?;
    validate_results(outcomes)?;
    validate_remotes(requests, outcomes)?;
    Ok(())
}

fn validate_argv(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    assert_args(
        outcomes,
        "int-default-log",
        &[
            "git",
            "-C",
            "<repo>",
            "log",
            "-p",
            "-U0",
            "--full-history",
            "--all",
            "--diff-filter=tuxdb",
        ],
    )?;
    assert_args(
        outcomes,
        "int-working-tree-diff",
        &["git", "-C", "<repo>", "diff", "-U0", "--no-ext-diff", "."],
    )?;
    assert_args(
        outcomes,
        "int-staged-findings",
        &[
            "git",
            "-C",
            "<repo>",
            "diff",
            "-U0",
            "--no-ext-diff",
            "--staged",
            ".",
        ],
    )?;
    let cases: &[(&str, &[&[u8]])] = &[
        ("log-options-double-space", &[b"--all", b"", b"foo..."]),
        ("log-options-leading-trailing-space", &[b"", b"--all", b""]),
    ];
    for (id, suffix) in cases {
        let arguments = arguments(outcomes, id)?;
        if arguments.len() < suffix.len() || &arguments[arguments.len() - suffix.len()..] != *suffix
        {
            return Err(format!("{id}: literal ASCII-space tokenization changed"));
        }
    }
    let tab = arguments(outcomes, "log-options-tab-not-split")?;
    if tab.last().map(Vec::as_slice) != Some(b"--all\tfoo...") {
        return Err("tab log option unexpectedly split".into());
    }
    let shell = arguments(outcomes, "log-options-shell-metacharacters-literal")?;
    let suffix = shell
        .iter()
        .rev()
        .take(2)
        .rev()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    if suffix != [b"$(touch".as_slice(), b"proof)".as_slice()] {
        return Err("shell metacharacters were transformed or executed".into());
    }
    Ok(())
}

fn validate_fragments(root: &Path, outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    let default = fragment_bytes(outcomes, "int-default-log")?;
    let observed_default = concat(&default);
    if observed_default.len() != 1_477 {
        return Err("pinned default Git additions changed".into());
    }
    let legacy_default = without_commit(outcomes, "int-default-log", NEW_COMMIT)?;
    let expected_default =
        read(&root.join("compat/fixtures/upstream/testdata/expected/git/small.txt"))?;
    if legacy_default != expected_default {
        return Err("legacy default Git golden relation changed".into());
    }
    let observed_foo = fragment_bytes(outcomes, "int-all-foo-log")?;
    if concat(&observed_foo).len() != 786 {
        return Err("pinned foo Git additions changed".into());
    }
    let legacy_foo = without_commit(outcomes, "int-all-foo-log", NEW_COMMIT)?;
    let expected_foo =
        read(&root.join("compat/fixtures/upstream/testdata/expected/git/small-branch-foo.txt"))?;
    if legacy_foo != expected_foo {
        return Err("legacy foo Git golden relation changed".into());
    }
    if concat(&fragment_bytes(outcomes, "int-working-tree-diff")?)
        != b"this line is added\nand another one"
    {
        return Err("working-tree diff additions changed".into());
    }
    for id in ["delete-skip", "binary-skip", "pure-rename-skip"] {
        if !fragment_bytes(outcomes, id)?.is_empty() {
            return Err(format!("{id}: deletion/binary/rename emitted fragments"));
        }
    }
    Ok(())
}

fn validate_results(outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    for (id, findings) in [
        ("int-default-findings", 2),
        ("int-all-foo-findings", 1),
        ("int-archive-findings", 16),
        ("int-staged-findings", 1),
    ] {
        if len(outcomes, id, "findings")? != findings {
            return Err(format!("{id}: finding multiset changed"));
        }
    }
    if len(outcomes, "ineffective-commit-allowlist", "fragments")? != 1 {
        return Err("source commit allowlist unexpectedly pruned".into());
    }
    let bad_archive = outcome_for(outcomes, "staged-malformed-archive-worker-error")?;
    if !bad_archive["error"].is_null()
        || len(
            outcomes,
            "staged-malformed-archive-worker-error",
            "fragments",
        )? != 0
        || len(outcomes, "staged-malformed-archive-worker-error", "issues")? != 0
    {
        return Err("archive worker error became observable".into());
    }
    if len(outcomes, "unstaged-archive-reads-index", "findings")? != 1 {
        return Err("unstaged archive did not read the index blob".into());
    }
    let malformed = required_array(
        outcome_for(outcomes, "malformed-not-a-repository")?,
        "issues",
        "malformed-not-a-repository",
    )?;
    if malformed.len() != 1 || required_str(&malformed[0], "class", "Git issue")? != "stderr" {
        return Err("Git stderr classification changed".into());
    }
    if outcome_for(outcomes, "cancel-after-start")?
        .pointer("/error/class")
        .and_then(Value::as_str)
        != Some("canceled")
    {
        return Err("Git cancellation classification changed".into());
    }
    Ok(())
}

fn validate_remotes(requests: &[Value], outcomes: &BTreeMap<&str, &Value>) -> Result<(), String> {
    assert_remote(outcomes, "remote-explicit-none", "none", b"")?;
    assert_remote(
        outcomes,
        "remote-ssh-port-github",
        "github",
        b"https://github.com/org/repo",
    )?;
    assert_remote(
        outcomes,
        "remote-userinfo-gitlab",
        "gitlab",
        b"https://gitlab.com/org/repo",
    )?;
    if remote_platform(outcomes, "remote-unknown-host")? != "unknown" {
        return Err("unknown remote mapping changed".into());
    }
    assert_remote(outcomes, "remote-malformed-url", "unknown", b"")?;
    for request in requests
        .iter()
        .filter(|request| request.get("expected_platform").is_some())
    {
        let id = required_str(request, "id", "request")?;
        let expected = required_str(request, "expected_platform", id)?;
        if remote_platform(outcomes, id)? != expected {
            return Err(format!("{id}: inferred remote platform changed"));
        }
    }
    Ok(())
}

fn without_commit(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    rejected: &[u8],
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for fragment in required_array(outcome_for(outcomes, id)?, "fragments", id)? {
        if decode(fragment, "commit_base64", id)? != rejected {
            bytes.extend(decode(fragment, "raw_base64", id)?);
        }
    }
    Ok(bytes)
}

fn arguments(outcomes: &BTreeMap<&str, &Value>, id: &str) -> Result<Vec<Vec<u8>>, String> {
    required_array(outcome_for(outcomes, id)?, "arguments_base64", id)?
        .iter()
        .map(|value| {
            decode_str(
                value
                    .as_str()
                    .ok_or_else(|| format!("{id}: invalid argument"))?,
                id,
            )
        })
        .collect()
}

fn assert_args(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    expected: &[&str],
) -> Result<(), String> {
    let actual = arguments(outcomes, id)?;
    let expected = expected
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(format!("{id}: exact Git argv changed"));
    }
    Ok(())
}

fn assert_remote(
    outcomes: &BTreeMap<&str, &Value>,
    id: &str,
    platform: &str,
    url: &[u8],
) -> Result<(), String> {
    let remote = outcome_for(outcomes, id)?
        .get("remote")
        .ok_or_else(|| format!("{id}: remote missing"))?;
    if required_str(remote, "platform", id)? != platform || decode(remote, "url_base64", id)? != url
    {
        return Err(format!("{id}: remote normalization changed"));
    }
    Ok(())
}

fn remote_platform<'a>(outcomes: &'a BTreeMap<&str, &Value>, id: &str) -> Result<&'a str, String> {
    outcome_for(outcomes, id)?
        .pointer("/remote/platform")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{id}: remote platform missing"))
}

fn len(outcomes: &BTreeMap<&str, &Value>, id: &str, field: &str) -> Result<usize, String> {
    Ok(required_array(outcome_for(outcomes, id)?, field, id)?.len())
}

fn concat(chunks: &[Vec<u8>]) -> Vec<u8> {
    chunks.iter().flatten().copied().collect()
}
