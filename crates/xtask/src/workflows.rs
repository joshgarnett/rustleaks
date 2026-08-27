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
    let dry_run = fs::read_to_string(directory.join("release-dry-run.yml"))
        .map_err(|error| format!("cannot read release dry-run workflow: {error}"))?;
    let release = fs::read_to_string(directory.join("release.yml"))
        .map_err(|error| format!("cannot read GitHub release workflow: {error}"))?;
    let publish = fs::read_to_string(directory.join("publish.yml"))
        .map_err(|error| format!("cannot read publication workflow: {error}"))?;
    let scorecard = fs::read_to_string(directory.join("scorecard.yml"))
        .map_err(|error| format!("cannot read Scorecard workflow: {error}"))?;
    validate_ci_matrix(&ci)?;
    validate_release_workflow(&dry_run)?;
    validate_github_release_workflow(&release)?;
    validate_publish_workflow(&publish)?;
    validate_scorecard_workflow(&scorecard)?;
    validate_workflow_efficiency(&ci, &weekly)?;
    validate_dependabot(root)?;
    println!(
        "checked {} least-privilege workflows with immutable action pins and exact runners",
        files.len()
    );
    Ok(())
}

fn validate_publish_workflow(source: &str) -> Result<(), String> {
    for forbidden in [
        "pull_request:",
        "pull_request_target:",
        "push:",
        "schedule:",
        "workflow_run:",
        "cargo publish --token",
        "CRATES_IO_TOKEN: ${{",
        "${{ secrets.",
        "uses: ./.github/actions/setup",
        "bazelisk",
        "actions/setup-go@",
        "run: just ",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "publication workflow contains forbidden trigger or credential {forbidden:?}"
            ));
        }
    }
    for required in [
        "candidate:",
        "dry_run_id:",
        "version:",
        "environment: release",
        "actions: read",
        "id-token: write",
        "rustup toolchain install 1.88.0 --profile minimal",
        "rustup default 1.88.0",
        "test \"${TRIGGER_COMMIT}\" = \"${CANDIDATE}\"",
        "test \"${TRIGGER_REF}\" = refs/heads/main",
        "test \"$(git rev-parse origin/main)\" = \"${CANDIDATE}\"",
        ".github/workflows/release-dry-run.yml",
        "rustleaks-core-${EXPECTED_VERSION}-package",
        "cmp \"${approved_crate}\" \"${current_crate}\"",
        "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18 # v1.0.5",
        "CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}",
        "run: cargo publish --locked -p rustleaks-core",
        "https://crates.io/api/v1/crates/rustleaks-core/${EXPECTED_VERSION}",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "publication workflow omits required boundary {required:?}"
            ));
        }
    }
    for (required, expected) in [
        ("rust-lang/crates-io-auth-action@", 1),
        ("cargo publish", 1),
        ("CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}", 1),
        ("id-token: write", 1),
    ] {
        let actual = source.matches(required).count();
        if actual != expected {
            return Err(format!(
                "publication workflow contains {actual} instances of {required:?}; expected {expected}"
            ));
        }
    }
    Ok(())
}

fn validate_github_release_workflow(source: &str) -> Result<(), String> {
    for forbidden in [
        "pull_request:",
        "pull_request_target:",
        "push:",
        "schedule:",
        "workflow_run:",
        "cargo publish",
        "CRATES_IO_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "${{ secrets.",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "GitHub release workflow contains forbidden trigger or credential {forbidden:?}"
            ));
        }
    }
    for required in [
        "candidate:",
        "dry_run_id:",
        "version:",
        "environment: release",
        "actions: read",
        "contents: write",
        "rustup toolchain install 1.88.0 --profile minimal",
        "test \"${TRIGGER_COMMIT}\" = \"${CANDIDATE}\"",
        "test \"${TRIGGER_REF}\" = refs/heads/main",
        "test \"$(git rev-parse origin/main)\" = \"${CANDIDATE}\"",
        ".github/workflows/release-dry-run.yml",
        "rustleaks-core-${EXPECTED_VERSION}-package",
        "cargo xtask release-artifact verify",
        "gh attestation verify",
        "--signer-workflow",
        "--source-digest",
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "gh release create \"${tag}\"",
        "--target \"${CANDIDATE}\"",
        "--prerelease",
        "test \"$(jq '.assets | length' <<<\"${release_json}\")\" = 60",
        "test \"$(jq -r '.object.sha' <<<\"${ref_json}\")\" = \"${CANDIDATE}\"",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "GitHub release workflow omits required boundary {required:?}"
            ));
        }
    }
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ] {
        if !source.contains(target) {
            return Err(format!(
                "GitHub release workflow omits artifact target {target}"
            ));
        }
    }
    for (required, expected) in [
        ("environment: release", 1),
        ("contents: write", 1),
        ("gh release create", 1),
    ] {
        let actual = source.matches(required).count();
        if actual != expected {
            return Err(format!(
                "GitHub release workflow contains {actual} instances of {required:?}; expected {expected}"
            ));
        }
    }
    Ok(())
}

fn validate_scorecard_workflow(source: &str) -> Result<(), String> {
    if source.contains("${{ secrets.") {
        return Err("Scorecard workflow must not use repository secrets".into());
    }
    for required in [
        "push:",
        "schedule:",
        "runs-on: ubuntu-24.04",
        "actions: read",
        "contents: read",
        "id-token: write",
        "security-events: write",
        "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc # v2.4.4",
        "publish_results: true",
        "github/codeql-action/upload-sarif@4c0873ef8656cb3c50b3f42fb63bc1ade0cfa827 # v4",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "Scorecard workflow omits required boundary {required:?}"
            ));
        }
    }
    Ok(())
}

fn validate_release_workflow(source: &str) -> Result<(), String> {
    for required in [
        "candidate:",
        "version:",
        "test \"${TRIGGER_COMMIT}\" = \"${CANDIDATE}\"",
        "test \"${TRIGGER_REF}\" = refs/heads/main",
        "test \"$(git rev-parse origin/main)\" = \"${CANDIDATE}\"",
        "run: just release-dry-run",
        "cmp \"${first}\" \"${second}\"",
        "cargo install cargo-public-api --locked --version 0.52.0",
        "rustup toolchain install nightly-2026-08-21 --profile minimal --component miri",
        "cargo xtask parity --all",
        "run: just security",
        "run: just fuzz-smoke",
        "release-artifact compare",
        "release-artifact compare-bundles",
        "release-artifact prepare",
        "rustleaks-${EXPECTED_VERSION}-${RELEASE_TARGET}/rustleaks",
        "rustleaks-$env:EXPECTED_VERSION-$env:RELEASE_TARGET/rustleaks.exe",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
        "id-token: write",
        "attestations: write",
        "gh attestation verify",
        "--signer-workflow",
        "--source-digest",
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "name: Release candidate required",
        "  acceptance:",
        "  differential:",
        "  security:",
        "  fuzz:",
        "  self-scan:",
        "      - acceptance",
        "      - differential",
        "      - security",
        "      - fuzz",
        "      - self-scan",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "release workflow omits required boundary {required:?}"
            ));
        }
    }
    for (required, expected) in [
        (
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2",
            4,
        ),
        ("id-token: write", 4),
        ("attestations: write", 4),
        ("gh attestation verify", 4),
        ("steps.attest.outputs.bundle-path", 4),
        ("release-artifact compare-bundles", 3),
        ("cargo xtask release-artifact verify", 3),
        ("packaged-smoke.json", 3),
    ] {
        let actual = source.matches(required).count();
        if actual != expected {
            return Err(format!(
                "release workflow contains {actual} instances of {required:?}; expected {expected}"
            ));
        }
    }
    validate_release_evidence_boundaries(source)?;
    Ok(())
}

fn validate_release_evidence_boundaries(source: &str) -> Result<(), String> {
    validate_release_differential_setup(source)?;
    let native_attestation_steps = source
        .split("- name: Verify and retain the release archive attestation")
        .skip(1)
        .filter_map(|tail| tail.split("\n      - name:").next())
        .collect::<Vec<_>>();
    if native_attestation_steps.len() != 3
        || native_attestation_steps
            .iter()
            .any(|step| !step.contains("working-directory: rustleaks"))
    {
        return Err("each native release attestation verifier must run from the checkout".into());
    }
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ] {
        if !source.contains(target) {
            return Err(format!("release workflow omits artifact target {target}"));
        }
    }
    for forbidden in [
        "environment: release",
        "cargo publish --execute",
        "cargo publish --token",
        "gh release create",
        "--report-path=- | grep -q REDACTED",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "release dry run contains live publication command {forbidden:?}"
            ));
        }
    }
    Ok(())
}

fn validate_release_differential_setup(source: &str) -> Result<(), String> {
    let differential = source
        .split("\n  differential:\n")
        .nth(1)
        .and_then(|tail| tail.split("\n  security:\n").next())
        .ok_or("release workflow omits the differential job")?;
    for required in [
        "rustup toolchain install nightly-2026-08-21 --profile minimal --component miri",
        "cargo +nightly-2026-08-21 miri setup",
        "cargo xtask parity --all",
    ] {
        if !differential.contains(required) {
            return Err(format!(
                "release differential job omits required setup {required:?}"
            ));
        }
    }
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
    if source.contains("actions/setup-go@") {
        if source.contains("go-version:") {
            return Err(format!(
                "{} hard-codes Go instead of using .go-version",
                path.display()
            ));
        }
        if !source.contains("go-version-file: rustleaks/.go-version") {
            return Err(format!(
                "{} sets up Go without the repository version file",
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
    for (target, execution_platform) in [
        ("x86_64-unknown-linux-musl", "//platforms:linux_x86_64_gnu"),
        (
            "aarch64-unknown-linux-musl",
            "//platforms:linux_aarch64_gnu",
        ),
    ] {
        validate_target_execution_platform(source, target, execution_platform)?;
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

fn validate_target_execution_platform(
    source: &str,
    target: &str,
    execution_platform: &str,
) -> Result<(), String> {
    let entry = source
        .split("          - runner: ")
        .find(|entry| entry.contains(&format!("target: {target}\n")))
        .ok_or_else(|| format!("CI omits native target {target}"))?;
    let expected = format!("execution_platform: {execution_platform}\n");
    if !entry.contains(&expected) {
        return Err(format!(
            "CI native target {target} does not use required execution platform {execution_platform}"
        ));
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
    for ecosystem in [
        "cargo",
        "gomod",
        "rust-toolchain",
        "bazel",
        "github-actions",
    ] {
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

    use super::{
        validate_github_release_workflow, validate_publish_workflow,
        validate_release_differential_setup, validate_scorecard_workflow,
        validate_target_execution_platform, validate_workflow, validate_workflow_efficiency,
    };

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
    fn requires_the_repository_go_version_file() {
        let source = format!(
            "name: Test\non:\n  push:\npermissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/setup-go@{PIN} # v6\n        with:\n          go-version: 1.26.7\n"
        );
        let error =
            validate_workflow(Path::new("test.yml"), &source, &mut BTreeSet::new()).unwrap_err();
        assert!(error.contains("hard-codes Go"));

        let source = source.replace(
            "go-version: 1.26.7",
            "go-version-file: rustleaks/.go-version",
        );
        validate_workflow(Path::new("test.yml"), &source, &mut BTreeSet::new()).unwrap();
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

    #[test]
    fn requires_miri_setup_in_the_release_differential_job() {
        let source = "\n  differential:\n    steps:\n      - run: cargo xtask parity --all\n  security:\n    steps:\n      - run: rustup toolchain install nightly-2026-08-21 --profile minimal --component miri\n      - run: cargo +nightly-2026-08-21 miri setup\n";
        let error = validate_release_differential_setup(source).unwrap_err();
        assert!(error.contains("release differential job"));

        let source = source.replace(
            "      - run: cargo xtask parity --all",
            "      - run: rustup toolchain install nightly-2026-08-21 --profile minimal --component miri\n      - run: cargo +nightly-2026-08-21 miri setup\n      - run: cargo xtask parity --all",
        );
        validate_release_differential_setup(&source).unwrap();
    }

    #[test]
    fn rejects_musl_execution_platform_for_host_tools() {
        let source = "          - runner: ubuntu-24.04-arm\n            target: aarch64-unknown-linux-musl\n            host_platform: //platforms:linux_aarch64_gnu\n            execution_platform: //platforms:linux_aarch64_musl\n";
        let error = validate_target_execution_platform(
            source,
            "aarch64-unknown-linux-musl",
            "//platforms:linux_aarch64_gnu",
        )
        .unwrap_err();
        assert!(error.contains("aarch64-unknown-linux-musl"));
        assert!(error.contains("linux_aarch64_gnu"));
    }

    #[test]
    fn rejects_token_fallback_in_publication_workflow() {
        let error = validate_publish_workflow("cargo publish --token").unwrap_err();
        assert!(error.contains("forbidden trigger or credential"));
    }

    #[test]
    fn rejects_full_build_setup_in_publication_workflow() {
        let error = validate_publish_workflow("uses: ./.github/actions/setup").unwrap_err();
        assert!(error.contains("forbidden trigger or credential"));
    }

    #[test]
    fn rejects_crate_publication_in_github_release_workflow() {
        let error = validate_github_release_workflow("cargo publish").unwrap_err();
        assert!(error.contains("forbidden trigger or credential"));
    }

    #[test]
    fn rejects_secret_backed_scorecard_workflow() {
        let error = validate_scorecard_workflow("${{ secrets.SCORECARD_TOKEN }}").unwrap_err();
        assert!(error.contains("must not use repository secrets"));
    }
}
