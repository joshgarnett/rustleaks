//! GitHub workflow policy validation.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let directory = root.join(".github/workflows");
    let mut files = fs::read_dir(&directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
    files.retain(|path| {
        path.extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "yml" | "yaml"))
    });
    files.sort();
    if files.is_empty() {
        return Err("repository contains no GitHub workflows".into());
    }

    let mut names = BTreeSet::new();
    for path in &files {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        validate_workflow(path, &source, &mut names)?;
    }
    let ci = fs::read_to_string(directory.join("ci.yml"))
        .map_err(|error| format!("cannot read CI workflow: {error}"))?;
    let weekly = fs::read_to_string(directory.join("weekly.yml"))
        .map_err(|error| format!("cannot read weekly workflow: {error}"))?;
    validate_ci_matrix(&ci)?;
    validate_workflow_efficiency(&ci, &weekly)?;
    validate_dependabot(root)?;
    println!(
        "checked {} least-privilege workflows with immutable action pins and exact runners",
        files.len()
    );
    Ok(())
}

fn validate_workflow(
    path: &Path,
    source: &str,
    names: &mut BTreeSet<String>,
) -> Result<(), String> {
    let name = source
        .lines()
        .find_map(|line| line.strip_prefix("name: "))
        .ok_or_else(|| format!("{} omits a workflow name", path.display()))?;
    if !names.insert(name.to_owned()) {
        return Err(format!("duplicate workflow name {name:?}"));
    }
    for forbidden in [
        "pull_request_target:",
        "workflow_run:",
        "permissions: write-all",
        "persist-credentials: true",
        "${{ secrets.",
        "-latest",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "{} contains forbidden workflow text {forbidden:?}",
                path.display()
            ));
        }
    }
    let permissions = source
        .find("permissions:\n  contents: read")
        .ok_or_else(|| format!("{} omits top-level read-only permissions", path.display()))?;
    let jobs = source
        .find("\njobs:\n")
        .ok_or_else(|| format!("{} omits jobs", path.display()))?;
    if permissions > jobs {
        return Err(format!(
            "{} declares read-only permissions only after jobs",
            path.display()
        ));
    }
    for (index, line) in source.lines().enumerate() {
        let Some(value) = line.trim().strip_prefix("uses: ") else {
            continue;
        };
        if value.starts_with("./") {
            continue;
        }
        let (reference, comment) = value.split_once(" # ").ok_or_else(|| {
            format!(
                "{}:{} external action omits a same-line release comment",
                path.display(),
                index + 1
            )
        })?;
        let revision = reference
            .rsplit_once('@')
            .map(|(_, revision)| revision)
            .ok_or_else(|| format!("{}:{} action omits a revision", path.display(), index + 1))?;
        if revision.len() != 40
            || !revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "{}:{} action is not pinned to a full lowercase commit SHA",
                path.display(),
                index + 1
            ));
        }
        if !comment.starts_with('v') {
            return Err(format!(
                "{}:{} action comment does not name its release tag",
                path.display(),
                index + 1
            ));
        }
    }
    Ok(())
}

fn validate_ci_matrix(source: &str) -> Result<(), String> {
    for (runner, target) in [
        ("ubuntu-24.04", "x86_64-unknown-linux-gnu"),
        ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu"),
        ("ubuntu-24.04", "x86_64-unknown-linux-musl"),
        ("ubuntu-24.04-arm", "aarch64-unknown-linux-musl"),
        ("macos-15-intel", "x86_64-apple-darwin"),
        ("macos-15", "aarch64-apple-darwin"),
        ("windows-2025", "x86_64-pc-windows-msvc"),
        ("windows-11-arm", "aarch64-pc-windows-msvc"),
    ] {
        if !source.contains(runner) || !source.contains(target) {
            return Err(format!("CI omits native target {target} on {runner}"));
        }
    }
    for required in [
        "run: just ci",
        "run: just security",
        "run: just fuzz-smoke",
        "run: just release-dry-run",
        "just parity",
        "name: Required",
    ] {
        if !source.contains(required) {
            return Err(format!("CI omits required boundary {required:?}"));
        }
    }
    Ok(())
}

fn validate_workflow_efficiency(ci: &str, weekly: &str) -> Result<(), String> {
    if weekly.contains("run: just security") {
        return Err("weekly workflow duplicates the scheduled CI security boundary".into());
    }
    if ci.contains("//:build //:docs") {
        return Err("native CI duplicates the acceptance gate's API documentation build".into());
    }
    Ok(())
}

fn validate_dependabot(root: &Path) -> Result<(), String> {
    let source = fs::read_to_string(root.join(".github/dependabot.yml"))
        .map_err(|error| format!("cannot read Dependabot configuration: {error}"))?;
    for ecosystem in ["cargo", "gomod", "rust-toolchain", "github-actions"] {
        if !source.contains(&format!("package-ecosystem: {ecosystem}")) {
            return Err(format!("Dependabot omits {ecosystem}"));
        }
    }
    for group in ["rust-dependencies", "rust-security-fixes", "github-actions"] {
        if !source.contains(&format!("{group}:")) {
            return Err(format!("Dependabot omits grouped updates for {group}"));
        }
    }
    if source.contains("automerge") {
        return Err("Dependabot configuration must not enable automatic merges".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::{validate_workflow, validate_workflow_efficiency};

    const PIN: &str = "d23441a48e516b6c34aea4fa41551a30e30af803";

    #[test]
    fn accepts_local_actions_and_immutable_external_actions() {
        let source = format!(
            "name: Test\non:\n  push:\npermissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: ./local\n      - uses: actions/checkout@{PIN} # v6\n"
        );
        validate_workflow(Path::new("test.yml"), &source, &mut BTreeSet::new()).unwrap();
    }

    #[test]
    fn rejects_moving_action_tags_and_latest_runners() {
        let source = "name: Test\non:\n  push:\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v6\n";
        let error =
            validate_workflow(Path::new("test.yml"), source, &mut BTreeSet::new()).unwrap_err();
        assert!(error.contains("-latest"));
    }

    #[test]
    fn rejects_privileged_untrusted_triggers() {
        let source = format!(
            "name: Test\non:\n  pull_request_target:\npermissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{PIN} # v6\n"
        );
        let error =
            validate_workflow(Path::new("test.yml"), &source, &mut BTreeSet::new()).unwrap_err();
        assert!(error.contains("pull_request_target"));
    }

    #[test]
    fn rejects_duplicate_scheduled_security_work() {
        let error = validate_workflow_efficiency("run: just security\n", "run: just security\n")
            .unwrap_err();
        assert!(error.contains("duplicates the scheduled CI security boundary"));
    }

    #[test]
    fn rejects_duplicate_native_documentation_builds() {
        let error =
            validate_workflow_efficiency("run: bazelisk build //:build //:docs\n", "").unwrap_err();
        assert!(error.contains("duplicates the acceptance gate's API documentation build"));
    }
}
