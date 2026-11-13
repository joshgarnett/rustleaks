//! GitHub workflow policy validation.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const CODEQL_ACTION_PIN: &str = "1fc58d04a4d4374f921bdac573c3811c240f9c26";
const SECRET_SCANNING_CONFIG: &str = r#"paths-ignore:
  - "compat/allowlist-corpus/**"
  - "compat/assertion-corpus/**"
  - "compat/cli-corpus/**"
  - "compat/composite-corpus/**"
  - "compat/config-corpus/**"
  - "compat/decoder-corpus/**"
  - "compat/detect-corpus/**"
  - "compat/generator-corpus/**"
  - "compat/git-corpus/**"
  - "compat/regex-corpus/**"
  - "compat/report-corpus/**"
  - "compat/session-corpus/**"
  - "compat/source-corpus/**"
  - "compat/api-dispositions-v1.jsonl"
  - "compat/api-inventory-v1.json"
  - "compat/fixtures/**"
  - "crates/rustleaks-core/default/gitleaks.toml"
"#;

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
    let codeql = fs::read_to_string(directory.join("codeql.yml"))
        .map_err(|error| format!("cannot read CodeQL workflow: {error}"))?;
    let secret_scanning = fs::read_to_string(root.join(".github/secret_scanning.yml"))
        .map_err(|error| format!("cannot read secret-scanning configuration: {error}"))?;
    validate_ci_matrix(&ci)?;
    validate_notice_catalog_gate(&ci, "bazel-acceptance")?;
    validate_release_workflow(&dry_run)?;
    validate_github_release_workflow(&release)?;
    validate_publish_workflow(&publish)?;
    validate_scorecard_workflow(&scorecard)?;
    validate_codeql_workflow(&codeql)?;
    validate_secret_scanning_config(&secret_scanning)?;
    validate_workflow_efficiency(&ci, &weekly)?;
    validate_dependabot(root)?;
    let setup = fs::read_to_string(root.join(".github/actions/setup/action.yml"))
        .map_err(|error| format!("cannot read setup action: {error}"))?;
    validate_tool_setup(&setup)?;
    let nightly = fs::read_to_string(directory.join("nightly.yml"))
        .map_err(|error| format!("cannot read nightly workflow: {error}"))?;
    if !nightly.contains("run: cargo xtask regression-check") {
        return Err("nightly workflow omits Rust regression replay".into());
    }
    println!(
        "checked {} least-privilege workflows with immutable action pins and exact runners",
        files.len()
    );
    Ok(())
}

fn validate_codeql_workflow(source: &str) -> Result<(), String> {
    for action in ["init", "analyze"] {
        let required = format!("github/codeql-action/{action}@{CODEQL_ACTION_PIN} # v4.39.2");
        if !source.contains(&required) {
            return Err(format!(
                "CodeQL workflow omits reviewed action pin {required:?}"
            ));
        }
    }
    Ok(())
}

fn validate_secret_scanning_config(source: &str) -> Result<(), String> {
    if source != SECRET_SCANNING_CONFIG {
        return Err(
            "secret-scanning exclusions must match the reviewed generated-data paths exactly"
                .into(),
        );
    }
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
        "rustup toolchain install 1.95.0 --profile minimal",
        "rustup default 1.95.0",
        "test \"${TRIGGER_COMMIT}\" = \"${CANDIDATE}\"",
        "test \"${TRIGGER_REF}\" = refs/heads/main",
        "test \"$(git rev-parse origin/main)\" = \"${CANDIDATE}\"",
        ".github/workflows/release-dry-run.yml",
        "rustleaks-core-${EXPECTED_VERSION}-package",
        "cmp \"${approved_crate}\" \"${current_crate}\"",
        "rust-lang/crates-io-auth-action@3268eb413133e2960fa4ae0e963ca76380c54cd9 # v1.0.6",
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
        "rustup toolchain install 1.95.0 --profile minimal",
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
        "test \"$(jq '.assets | length' <<<\"${release_json}\")\" = 63",
        "source_name=\"rustleaks-${EXPECTED_VERSION}-corresponding-source.tar.gz\"",
        "cmp \"${bundle}/${source_name}\" \"${assets}/${source_name}\"",
        "install -m 0644 \"${bundle}/source-relink.json\" \"${assets}/${stem}.source-relink.json\"",
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
    validate_published_native_verification(source)
}

fn validate_published_native_verification(source: &str) -> Result<(), String> {
    let job = workflow_job(source, "verify-native")?;
    for forbidden in [
        ": write",
        "id-token:",
        "environment:",
        "continue-on-error:",
        "if: always()",
        "gh run download",
        "gh release create",
        "gh release upload",
        "gh release delete",
        "release-artifact prepare",
        "bazelisk",
    ] {
        if job.contains(forbidden) {
            return Err(format!(
                "published native verifier contains forbidden boundary {forbidden:?}"
            ));
        }
    }
    for required in [
        "    needs: release\n",
        "      fail-fast: false\n",
        "    permissions:\n      contents: read\n",
        "          ref: ${{ inputs.candidate }}\n",
        "          persist-credentials: false\n",
        "      CANDIDATE: ${{ inputs.candidate }}\n",
        "      EXPECTED_VERSION: ${{ inputs.version }}\n",
        "      RELEASE_TARGET: ${{ matrix.target }}\n",
        "      EXPECTED_ARCHITECTURE: ${{ matrix.architecture }}\n",
        "rustup toolchain install 1.95.0 --profile minimal",
        "cargo fetch --locked",
    ] {
        if !job.contains(required) {
            return Err(format!(
                "published native verifier omits required boundary {required:?}"
            ));
        }
    }
    validate_published_native_matrix(job)?;
    validate_published_native_steps(job)
}

fn workflow_job<'a>(source: &'a str, name: &str) -> Result<&'a str, String> {
    let marker = format!("\n  {name}:\n");
    if source.matches(&marker).count() != 1 {
        return Err(format!("workflow must contain exactly one {name} job"));
    }
    let (_, tail) = source
        .split_once(&marker)
        .ok_or_else(|| format!("workflow omits {name} job"))?;
    // A next job has exactly two leading spaces; nested YAML keys have more.
    let end = tail
        .match_indices("\n  ")
        .find(|(index, _)| {
            tail.as_bytes()
                .get(index + 3)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
        })
        .map_or(tail.len(), |(index, _)| index);
    Ok(&tail[..end])
}

fn validate_published_native_matrix(job: &str) -> Result<(), String> {
    let matrix = job
        .split_once("        include:\n")
        .and_then(|(_, tail)| tail.split_once("    runs-on: ${{ matrix.runner }}\n"))
        .map(|(matrix, _)| matrix)
        .ok_or("published native verifier omits its explicit runner matrix")?;
    let targets = [
        ("ubuntu-24.04", "x86_64", "x86_64-unknown-linux-gnu"),
        ("ubuntu-24.04-arm", "aarch64", "aarch64-unknown-linux-gnu"),
        ("ubuntu-24.04", "x86_64", "x86_64-unknown-linux-musl"),
        ("ubuntu-24.04-arm", "aarch64", "aarch64-unknown-linux-musl"),
        ("macos-15-intel", "x86_64", "x86_64-apple-darwin"),
        ("macos-15", "arm64", "aarch64-apple-darwin"),
        ("windows-2025", "X64", "x86_64-pc-windows-msvc"),
        ("windows-11-arm", "Arm64", "aarch64-pc-windows-msvc"),
    ];
    if matrix.matches("          - runner:").count() != targets.len() {
        return Err("published native verifier must contain exactly eight targets".into());
    }
    for (runner, architecture, target) in targets {
        let entry = format!(
            "          - runner: {runner}\n            architecture: {architecture}\n            target: {target}\n"
        );
        if matrix.matches(&entry).count() != 1 {
            return Err(format!(
                "published native verifier omits exact native mapping for {target}"
            ));
        }
    }
    Ok(())
}

fn workflow_step<'a>(job: &'a str, name: &str) -> Result<&'a str, String> {
    let marker = format!("      - name: {name}\n");
    if job.matches(&marker).count() != 1 {
        return Err(format!(
            "published native verifier must contain one {name} step"
        ));
    }
    let (_, tail) = job
        .split_once(&marker)
        .ok_or_else(|| format!("published native verifier omits {name} step"))?;
    Ok(tail.split("\n      - name:").next().unwrap_or(tail))
}

fn validate_published_native_steps(job: &str) -> Result<(), String> {
    for platform in ["Linux and macOS", "Windows"] {
        let verify_name = format!("Verify public bundle on {platform}");
        let smoke_name = format!("Smoke public executable on {platform}");
        let verify = workflow_step(job, &verify_name)?;
        let smoke = workflow_step(job, &smoke_name)?;
        if job.find(&verify_name) >= job.find(&smoke_name) {
            return Err(format!("{platform} public smoke precedes verification"));
        }
        let primary_download = if platform == "Windows" {
            "          gh release download \"v$env:EXPECTED_VERSION\" --repo $env:GITHUB_REPOSITORY --dir $bundle --pattern \"$stem.tar.gz\""
        } else {
            "          gh release download \"v${EXPECTED_VERSION}\" --repo \"${GITHUB_REPOSITORY}\" --dir \"${bundle}\" \\"
        };
        if !verify
            .lines()
            .any(|line| line.starts_with(primary_download))
        {
            return Err(format!(
                "{platform} public verifier omits its bound primary native bundle download"
            ));
        }
        for required in [
            ".tar.gz",
            ".cdx.json",
            ".provenance.json",
            ".attestation.jsonl",
            ".SHA256SUMS",
            ".reproducibility.json",
            ".manifest.json",
            "cargo xtask release-artifact verify",
            "gh attestation verify",
            "--signer-workflow",
            "/.github/workflows/release-dry-run.yml",
            "--source-digest",
            "--source-ref refs/heads/main",
            "--deny-self-hosted-runners",
        ] {
            if !verify.contains(required) {
                return Err(format!("{platform} public verifier omits {required:?}"));
            }
        }
        let condition = if platform == "Windows" {
            "if: runner.os == 'Windows'"
        } else {
            "if: runner.os != 'Windows'"
        };
        if !verify.contains(condition) || !smoke.contains(condition) {
            return Err(format!(
                "{platform} public verifier has an incorrect platform guard"
            ));
        }
        for required in published_native_bindings(platform) {
            if !verify.contains(required) {
                return Err(format!(
                    "{platform} public verifier omits binding {required:?}"
                ));
            }
        }
        if platform == "Linux and macOS" {
            for required in [
                "if [[ \"${RELEASE_TARGET}\" = *-linux-gnu ]]; then",
                "\n            gh release download \"v${EXPECTED_VERSION}\" --repo \"${GITHUB_REPOSITORY}\" --dir \"${bundle}\" \\\n",
                "--pattern \"rustleaks-${EXPECTED_VERSION}-corresponding-source.tar.gz\"",
                "--pattern \"${stem}.source-relink.json\"",
                "mv \"${bundle}/${stem}.source-relink.json\" \"${bundle}/source-relink.json\"",
            ] {
                if !verify.contains(required) {
                    return Err(format!(
                        "public GNU verifier omits corresponding-source boundary {required:?}"
                    ));
                }
            }
        }
        if verify.contains("tar -xzf") || verify.contains("--help") || smoke.contains("GH_TOKEN") {
            return Err(format!(
                "{platform} public verification and execution boundaries overlap"
            ));
        }
        for required in [
            "tar -xzf",
            "--help",
            "stdin --redact",
            "published-smoke.json",
            "REDACTED",
        ] {
            if !smoke.contains(required) {
                return Err(format!("{platform} public smoke omits {required:?}"));
            }
        }
    }
    Ok(())
}

fn published_native_bindings(platform: &str) -> &'static [&'static str] {
    if platform == "Windows" {
        &[
            "if ($actual -ne $env:EXPECTED_ARCHITECTURE)",
            "if ($manifest.release.version -cne $env:EXPECTED_VERSION)",
            "if ($manifest.release.sourceCommit -cne $env:CANDIDATE)",
            "if ($manifest.build.target -cne $env:RELEASE_TARGET)",
            "--source-digest $env:CANDIDATE",
        ]
    } else {
        &[
            "test \"$(uname -m)\" = \"${EXPECTED_ARCHITECTURE}\"",
            "test \"$(jq -r '.release.version' \"${bundle}/manifest.json\")\" = \"${EXPECTED_VERSION}\"",
            "test \"$(jq -r '.release.sourceCommit' \"${bundle}/manifest.json\")\" = \"${CANDIDATE}\"",
            "test \"$(jq -r '.build.target' \"${bundle}/manifest.json\")\" = \"${RELEASE_TARGET}\"",
            "--source-digest \"${CANDIDATE}\"",
        ]
    }
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
        "ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e # v2.5.0",
        "publish_results: true",
        "github/codeql-action/upload-sarif@1fc58d04a4d4374f921bdac573c3811c240f9c26 # v4.39.2",
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
    validate_notice_catalog_gate(source, "acceptance")?;
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
        "cargo xtask qualify",
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
        "  qualification:",
        "  security:",
        "  fuzz:",
        "  self-scan:",
        "      - acceptance",
        "      - qualification",
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

fn validate_notice_catalog_gate(source: &str, job_name: &str) -> Result<(), String> {
    let job = workflow_job(source, job_name)?;
    let step = workflow_step(job, "Check native notice source completeness")?;
    for required in [
        "working-directory: rustleaks",
        "cargo xtask release-artifact notices --check",
    ] {
        if !step.contains(required) {
            return Err(format!(
                "{job_name} notice completeness gate omits {required:?}"
            ));
        }
    }
    if step.contains("continue-on-error") || step.contains("        if:") || step.contains("||") {
        return Err(format!(
            "{job_name} notice completeness gate must run unconditionally and fail closed"
        ));
    }
    let hydrate = job.find("cargo fetch --locked").ok_or_else(|| {
        format!("{job_name} notice completeness gate omits locked archive hydration")
    })?;
    let check = job
        .find("cargo xtask release-artifact notices --check")
        .ok_or("notice completeness command disappeared")?;
    if hydrate >= check {
        return Err(format!(
            "{job_name} must hydrate locked archives before checking notice completeness"
        ));
    }
    Ok(())
}

fn validate_release_evidence_boundaries(source: &str) -> Result<(), String> {
    validate_release_qualification_setup(source)?;
    validate_corresponding_source_workflow(source)?;
    validate_windows_runtime_evidence(source)?;
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

fn validate_windows_runtime_evidence(source: &str) -> Result<(), String> {
    let windows = workflow_job(source, "native-windows")?;
    for required in [
        "if ((Test-Path $firstRoot) -or (Test-Path $secondRoot))",
        "if ((Test-Path $firstMap) -or (Test-Path $secondMap))",
        "crates/rustleaks-cli/src/main.rs@-Wlinker-messages",
        "crates/rustleaks-cli/src/main.rs@-Clink-arg=/VERBOSE:LIB",
        "crates/rustleaks-cli/src/main.rs@-Clink-arg=/MAP:rustleaks-runtime.map",
        "Copy-Item $firstMap (Join-Path $firstEvidence link.map)",
        "Copy-Item $secondMap (Join-Path $secondEvidence link.map)",
        "Tee-Object -FilePath $firstTrace",
        "Tee-Object -FilePath $secondTrace",
        "cargo xtask release-artifact prepare-windows $first $firstRoot $env:RELEASE_TARGET $env:CANDIDATE (Join-Path $work reproducibility.json) (Join-Path $work bundle) $firstMap $firstTrace",
        "cargo xtask release-artifact prepare-windows $second $secondRoot $env:RELEASE_TARGET $env:CANDIDATE (Join-Path $work reproducibility.json) (Join-Path $work bundle-repeat) $secondMap $secondTrace",
    ] {
        if !windows.contains(required) {
            return Err(format!("Windows runtime identity gate omits {required:?}"));
        }
    }
    if windows
        .lines()
        .filter(|line| line.contains(" build ") && line.contains("@runtimeFlags"))
        .count()
        != 2
        || windows.find("if ((Test-Path $firstMap)")
            >= windows.find("--windows_enable_symlinks build")
    {
        return Err("both fresh Windows builds must capture native runtime evidence".into());
    }
    for output in ["execution_root", "bazel-bin"] {
        let suffix = format!("@runtimeFlags {output}");
        if windows
            .lines()
            .filter(|line| line.contains(" info ") && line.trim_end().ends_with(&suffix))
            .count()
            != 2
        {
            return Err(format!(
                "both Windows {output} queries must use the native runtime build flags"
            ));
        }
    }
    let retained = workflow_step(windows, "Retain Windows runtime provider evidence")?;
    for required in [
        "if: always()",
        "name: runtime-provider-evidence-${{ matrix.target }}-${{ inputs.candidate }}",
        "path: ${{ runner.temp }}/release-work/runtime-evidence",
    ] {
        if !retained.contains(required) {
            return Err(format!(
                "separate Windows diagnostic artifact omits {required:?}"
            ));
        }
    }
    Ok(())
}

fn validate_corresponding_source_workflow(source: &str) -> Result<(), String> {
    let linux = workflow_job(source, "native-linux")?;
    for required in [
        "if [[ \"${RELEASE_LIBC}\" = gnu ]]; then",
        "cargo xtask release-artifact fetch-source \"${first_cache}\"",
        "cargo xtask release-artifact fetch-source \"${second_cache}\"",
        "cargo xtask release-artifact prepare-source \"${first_cache}\" \"${CANDIDATE}\" \"${work}/source\"",
        "cargo xtask release-artifact relink-source \"${source_archive}\" \"${CANDIDATE}\" \"${RELEASE_TARGET}\" \"${work}/source-relink-work\" \"${work}/source-relink.json\"",
        "source_args=(\"${work}/source-relink.json\")",
    ] {
        if !linux.contains(required) {
            return Err(format!(
                "GNU corresponding-source workflow omits {required:?}"
            ));
        }
    }
    if linux.matches("\"${glibc}\" \"${source_args[@]}\"").count() != 2 {
        return Err("both GNU bundle preparations must bind the native source relink proof".into());
    }
    if linux.find("cargo xtask release-artifact relink-source")
        >= linux.find("cargo xtask release-artifact prepare \"")
    {
        return Err(
            "GNU corresponding-source relink proof must precede native bundle preparation".into(),
        );
    }
    Ok(())
}

fn validate_release_qualification_setup(source: &str) -> Result<(), String> {
    let qualification = source
        .split("\n  qualification:\n")
        .nth(1)
        .and_then(|tail| tail.split("\n  security:\n").next())
        .ok_or("release workflow omits the qualification job")?;
    for required in [
        "cargo install cargo-public-api --locked --version 0.52.0",
        "cargo install cargo-deny --locked --version 0.19.9",
        "rustup toolchain install nightly-2026-08-21 --profile minimal --component llvm-tools-preview",
        "cargo +nightly-2026-08-21 install cargo-fuzz --locked --version 0.13.2",
        "rustup toolchain install nightly-2026-08-21 --profile minimal --component miri",
        "cargo +nightly-2026-08-21 miri setup",
        "cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-core/fuzz/Cargo.toml",
        "cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml",
        "cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-report/fuzz/Cargo.toml",
        "cargo xtask qualify",
    ] {
        if !qualification.contains(required) {
            return Err(format!(
                "release qualification job omits required setup {required:?}"
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
    validate_no_live_go(source)?;
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

fn validate_no_live_go(source: &str) -> Result<(), String> {
    for forbidden in [
        "actions/setup-go@",
        "repository: gitleaks/gitleaks",
        ".go-version",
        "cargo xtask verify-upstream",
        "cargo xtask oracle",
        "cargo xtask parity --all",
        "cargo xtask generate source",
        "cargo xtask generate git",
        "cargo xtask generate report",
        "cargo xtask generate cli",
    ] {
        if source.contains(forbidden) {
            return Err(format!(
                "automation restores retired Go execution {forbidden:?}"
            ));
        }
    }
    let words = source.split_whitespace().collect::<Vec<_>>();
    if words.windows(2).any(|pair| {
        pair[0] == "go"
            && matches!(
                pair[1],
                "install" | "env" | "run" | "build" | "test" | "version"
            )
    }) {
        return Err("automation restores a host Go command".into());
    }
    Ok(())
}

fn validate_tool_setup(source: &str) -> Result<(), String> {
    validate_no_live_go(source)?;
    for (runner, asset, sha256) in [
        (
            "Linux:X64",
            "bazelisk-linux-amd64",
            "5a408715e932c0250d28bd84555f12edbf70117de42f9181691c736eacc4a992",
        ),
        (
            "Linux:ARM64",
            "bazelisk-linux-arm64",
            "e20e8b0f4f240091b7a55bf17b9398bd4f40ee70ae0208dff95dd4c445fb4010",
        ),
        (
            "macOS:X64",
            "bazelisk-darwin-amd64",
            "16c3d7aa15323a9fb69f56c7ec5733ed18bedb786680d0ba13bb12a3c8083007",
        ),
        (
            "macOS:ARM64",
            "bazelisk-darwin-arm64",
            "cee851f726789227d5561004e9904a52be45c3efb56f8b38b6993d6adbaa0409",
        ),
        (
            "Windows:X64",
            "bazelisk-windows-amd64.exe",
            "092a8738d5b41aae7a85c42cc961b1034e3389aba43ffc20c0fabda7b43e095b",
        ),
        (
            "Windows:ARM64",
            "bazelisk-windows-arm64.exe",
            "8bc42bd5d7857f18a21440b906469bb6c7cf91a7c72364d4b1e5ec56a76fe94f",
        ),
    ] {
        let binding = format!("{runner})\n            asset={asset}\n            sha256={sha256}");
        if !source.contains(&binding) {
            return Err(format!(
                "setup action omits the verified Bazelisk asset for {runner}"
            ));
        }
    }
    let mut remaining = source;
    for required in [
        "https://github.com/bazelbuild/bazelisk/releases/download/v1.29.0/${asset}",
        "test \"${actual_sha256}\" = \"${sha256}\"",
        "chmod +x \"${destination}\"",
        "bazeliskVersion",
        "Bazelisk version: v1.29.0",
    ] {
        remaining = remaining
            .split_once(required)
            .map(|(_, remaining)| remaining)
            .ok_or_else(|| format!("setup action omits ordered verification {required:?}"))?;
    }
    Ok(())
}

fn validate_ci_matrix(source: &str) -> Result<(), String> {
    for job in ["native-linux", "native-macos", "native-windows"] {
        let header = format!("\n  {job}:\n");
        let lane = source
            .split_once(&header)
            .map(|(_, tail)| {
                tail.split("\n  native-")
                    .next()
                    .unwrap_or(tail)
                    .split("\n  required:")
                    .next()
                    .unwrap_or(tail)
            })
            .ok_or_else(|| format!("CI omits native lane {job}"))?;
        for required in [
            "//:test",
            "rust-cli-regression-${{ matrix.target }}",
            "rustleaks/bazel-testlogs/crates/xtask/cli_regression_test/test.outputs/cli-regression-ledger.json",
            "--nozip_undeclared_test_outputs",
            "if-no-files-found: error",
        ] {
            if !lane.contains(required) {
                return Err(format!(
                    "native lane {job} omits Rust evidence {required:?}"
                ));
            }
        }
    }
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
        "cargo xtask regression-check",
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
    for ecosystem in ["cargo", "rust-toolchain", "bazel", "github-actions"] {
        if !source.contains(&format!("package-ecosystem: {ecosystem}")) {
            return Err(format!("Dependabot omits {ecosystem}"));
        }
    }
    if source.contains("package-ecosystem: gomod") {
        return Err("Dependabot must not restore the retired oracle module".into());
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
        CODEQL_ACTION_PIN, SECRET_SCANNING_CONFIG, validate_codeql_workflow,
        validate_github_release_workflow, validate_publish_workflow,
        validate_release_qualification_setup, validate_scorecard_workflow,
        validate_secret_scanning_config, validate_target_execution_platform, validate_workflow,
        validate_workflow_efficiency,
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
    fn rejects_retired_go_execution_and_sibling_checkouts() {
        for forbidden in [
            "uses: actions/setup-go@reviewed-pin",
            "repository: gitleaks/gitleaks",
            "run: cargo xtask oracle-vulnerability-check",
            "run: cargo xtask generate cli --check",
            "go install github.com/bazelbuild/bazelisk@v1.29.0",
        ] {
            assert!(super::validate_no_live_go(forbidden).is_err());
        }
        super::validate_no_live_go("run: cargo xtask regression-check").unwrap();
        super::validate_no_live_go("run: cargo install just --locked --version 1.53.0").unwrap();
    }

    #[test]
    fn rejects_changed_bazelisk_hash_or_unverified_execution() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = std::fs::read_to_string(root.join(".github/actions/setup/action.yml"))
            .expect("read setup action");
        super::validate_tool_setup(&source).unwrap();
        let changed = source.replace(
            "5a408715e932c0250d28bd84555f12edbf70117de42f9181691c736eacc4a992",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(super::validate_tool_setup(&changed).is_err());
        let unchecked = source.replace("test \"${actual_sha256}\" = \"${sha256}\"", "true");
        assert!(super::validate_tool_setup(&unchecked).is_err());
    }

    #[test]
    fn native_ledgers_require_exact_json_and_unzipped_outputs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = std::fs::read_to_string(root.join(".github/workflows/ci.yml"))
            .expect("read CI workflow");
        super::validate_ci_matrix(&source).unwrap();
        let zipped = source.replace("--nozip_undeclared_test_outputs", "");
        assert!(super::validate_ci_matrix(&zipped).is_err());
        let broad = source.replace("test.outputs/cli-regression-ledger.json", "test.outputs/**");
        assert!(super::validate_ci_matrix(&broad).is_err());
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
    fn requires_qualification_tools_in_the_release_qualification_job() {
        let source = "\n  qualification:\n    steps:\n      - run: cargo xtask qualify\n  security:\n    steps:\n      - run: cargo install cargo-public-api --locked --version 0.52.0\n      - run: cargo install cargo-deny --locked --version 0.19.9\n      - run: rustup toolchain install nightly-2026-08-21 --profile minimal --component llvm-tools-preview\n      - run: cargo +nightly-2026-08-21 install cargo-fuzz --locked --version 0.13.2\n      - run: rustup toolchain install nightly-2026-08-21 --profile minimal --component miri\n      - run: cargo +nightly-2026-08-21 miri setup\n      - run: cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-core/fuzz/Cargo.toml\n      - run: cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml\n      - run: cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-report/fuzz/Cargo.toml\n";
        let error = validate_release_qualification_setup(source).unwrap_err();
        assert!(error.contains("release qualification job"));

        let source = source.replace(
            "      - run: cargo xtask qualify",
            "      - run: cargo install cargo-public-api --locked --version 0.52.0\n      - run: cargo install cargo-deny --locked --version 0.19.9\n      - run: rustup toolchain install nightly-2026-08-21 --profile minimal --component llvm-tools-preview\n      - run: cargo +nightly-2026-08-21 install cargo-fuzz --locked --version 0.13.2\n      - run: rustup toolchain install nightly-2026-08-21 --profile minimal --component miri\n      - run: cargo +nightly-2026-08-21 miri setup\n      - run: cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-core/fuzz/Cargo.toml\n      - run: cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml\n      - run: cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-report/fuzz/Cargo.toml\n      - run: cargo xtask qualify",
        );
        validate_release_qualification_setup(&source).unwrap();
        for required in [
            "cargo +nightly-2026-08-21 install cargo-fuzz --locked --version 0.13.2",
            "cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-core/fuzz/Cargo.toml",
            "cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml",
            "cargo +nightly-2026-08-21 fetch --locked --manifest-path crates/rustleaks-report/fuzz/Cargo.toml",
        ] {
            let error = validate_release_qualification_setup(&source.replace(required, "missing"))
                .unwrap_err();
            assert!(error.contains(required));
        }
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
    fn gnu_source_delivery_requires_native_relink_before_both_bundle_preparations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source =
            std::fs::read_to_string(root.join(".github/workflows/release-dry-run.yml")).unwrap();
        super::validate_corresponding_source_workflow(&source).unwrap();
        for removed in [
            "cargo xtask release-artifact fetch-source \"${first_cache}\"",
            "cargo xtask release-artifact prepare-source",
            "cargo xtask release-artifact relink-source",
            "source_args=(\"${work}/source-relink.json\")",
            "\"${source_args[@]}\"",
        ] {
            let changed = source.replacen(removed, "missing", 1);
            assert!(
                super::validate_corresponding_source_workflow(&changed).is_err(),
                "accepted omission of {removed}"
            );
        }
    }

    #[test]
    fn windows_runtime_gate_requires_actual_fresh_maps_traces_and_separate_retention() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source =
            std::fs::read_to_string(root.join(".github/workflows/release-dry-run.yml")).unwrap();
        super::validate_windows_runtime_evidence(&source).unwrap();
        for removed in [
            "if ((Test-Path $firstRoot) -or (Test-Path $secondRoot))",
            "if ((Test-Path $firstMap) -or (Test-Path $secondMap))",
            "crates/rustleaks-cli/src/main.rs@-Wlinker-messages",
            "crates/rustleaks-cli/src/main.rs@-Clink-arg=/MAP:rustleaks-runtime.map",
            "@runtimeFlags //crates/rustleaks-cli:rustleaks",
            "@runtimeFlags execution_root",
            "@runtimeFlags bazel-bin",
            "cargo xtask release-artifact prepare-windows $first",
            "$firstMap $firstTrace",
            "path: ${{ runner.temp }}/release-work/runtime-evidence",
        ] {
            assert!(
                super::validate_windows_runtime_evidence(&source.replacen(removed, "missing", 1))
                    .is_err(),
                "accepted missing Windows runtime boundary {removed}"
            );
        }
    }

    #[test]
    fn ci_and_release_require_source_recomputed_notice_catalog_checks() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for (file, job) in [
            ("ci.yml", "bazel-acceptance"),
            ("release-dry-run.yml", "acceptance"),
        ] {
            let source =
                std::fs::read_to_string(root.join(".github/workflows").join(file)).unwrap();
            super::validate_notice_catalog_gate(&source, job).unwrap();
            for (before, after) in [
                (
                    "cargo xtask release-artifact notices --check",
                    "cargo xtask release-artifact notices",
                ),
                (
                    "Check native notice source completeness\n",
                    "Check native notice source completeness\n        continue-on-error: true\n",
                ),
                (
                    "Check native notice source completeness\n",
                    "Check native notice source completeness\n        if: false\n",
                ),
                ("cargo fetch --locked", "echo omitted archive hydration"),
            ] {
                assert!(
                    super::validate_notice_catalog_gate(&source.replace(before, after), job)
                        .is_err(),
                    "accepted weakened {job} gate: {after}"
                );
            }
        }
    }

    #[test]
    fn published_source_assets_require_deduplication_and_native_downloads() {
        let source = github_release_fixture();
        validate_github_release_workflow(&source).unwrap();
        for removed in [
            "cmp \"${bundle}/${source_name}\" \"${assets}/${source_name}\"",
            "install -m 0644 \"${bundle}/source-relink.json\"",
            "\n            gh release download",
            "--pattern \"rustleaks-${EXPECTED_VERSION}-corresponding-source.tar.gz\"",
            "--pattern \"${stem}.source-relink.json\"",
        ] {
            let changed = source.replacen(removed, "missing", 1);
            assert!(
                validate_github_release_workflow(&changed).is_err(),
                "accepted omission of {removed}"
            );
        }
    }

    fn github_release_fixture() -> String {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        std::fs::read_to_string(root.join(".github/workflows/release.yml"))
            .expect("read GitHub release workflow")
    }

    fn mutate_native_verifier(source: &str, before: &str, after: &str) -> String {
        let marker = "\n  verify-native:\n";
        let (publication, verification) = source.split_once(marker).unwrap();
        assert!(
            verification.contains(before),
            "missing mutation input {before:?}"
        );
        format!(
            "{publication}{marker}{}",
            verification.replacen(before, after, 1)
        )
    }

    #[test]
    fn published_smoke_requires_every_native_mapping_inside_its_job() {
        let source = github_release_fixture();
        validate_github_release_workflow(&source).unwrap();
        for before in [
            "          - runner: windows-11-arm\n            architecture: Arm64\n            target: aarch64-pc-windows-msvc\n",
            "            target: aarch64-unknown-linux-musl\n",
            "            architecture: arm64\n",
        ] {
            let changed = mutate_native_verifier(&source, before, "");
            assert!(validate_github_release_workflow(&changed).is_err());
        }
        let changed =
            mutate_native_verifier(&source, "runner: windows-11-arm", "runner: windows-2025");
        assert!(validate_github_release_workflow(&changed).is_err());
    }

    #[test]
    fn published_smoke_requires_read_only_post_publication_execution() {
        let source = github_release_fixture();
        for (before, after) in [
            ("    needs: release\n", ""),
            ("contents: read", "contents: write"),
            ("contents: read", "contents: read\n      id-token: write"),
            (
                "    needs: release\n",
                "    needs: release\n    environment: release\n",
            ),
            (
                "    needs: release\n",
                "    needs: release\n    continue-on-error: true\n",
            ),
            ("gh release download", "gh run download"),
        ] {
            let changed = mutate_native_verifier(&source, before, after);
            assert!(
                validate_github_release_workflow(&changed).is_err(),
                "{before}"
            );
        }
        let changed = mutate_native_verifier(&source, "    needs: release\n", "");
        let unrelated = format!("{changed}\n  unrelated:\n    needs: release\n");
        assert!(validate_github_release_workflow(&unrelated).is_err());
    }

    #[test]
    fn published_smoke_requires_each_platform_identity_and_attestation() {
        let source = github_release_fixture();
        for platform in ["Linux and macOS", "Windows"] {
            for binding in super::published_native_bindings(platform) {
                let changed = mutate_native_verifier(&source, binding, "missing-binding");
                assert!(
                    validate_github_release_workflow(&changed).is_err(),
                    "{binding}"
                );
            }
            let name = format!("Verify public bundle on {platform}");
            let job = super::workflow_job(&source, "verify-native").unwrap();
            let step = super::workflow_step(job, &name).unwrap();
            for boundary in [
                "gh release download",
                "cargo xtask release-artifact verify",
                "gh attestation verify",
                "--signer-workflow",
                "--source-ref refs/heads/main",
                "--deny-self-hosted-runners",
            ] {
                let changed = source.replace(step, &step.replacen(boundary, "missing-boundary", 1));
                assert!(
                    validate_github_release_workflow(&changed).is_err(),
                    "{name}: {boundary}"
                );
            }
        }
    }

    #[test]
    fn published_smoke_cannot_run_before_verification_or_with_its_token() {
        let source = github_release_fixture();
        for platform in ["Linux and macOS", "Windows"] {
            let verify_name = format!("      - name: Verify public bundle on {platform}\n");
            let smoke_name = format!("      - name: Smoke public executable on {platform}\n");
            let verify_start = source.find(&verify_name).unwrap();
            let smoke_start = source.find(&smoke_name).unwrap();
            let smoke_end = source[smoke_start + smoke_name.len()..]
                .find("\n      - name:")
                .map_or(source.len(), |offset| {
                    smoke_start + smoke_name.len() + offset + 1
                });
            let changed = format!(
                "{}{}{}{}",
                &source[..verify_start],
                &source[smoke_start..smoke_end],
                &source[verify_start..smoke_start],
                &source[smoke_end..],
            );
            assert!(validate_github_release_workflow(&changed).is_err());
            let changed = source.replace(
                &smoke_name,
                &format!("{smoke_name}        env:\n          GH_TOKEN: ${{{{ github.token }}}}\n"),
            );
            assert!(validate_github_release_workflow(&changed).is_err());
        }
        let changed = mutate_native_verifier(
            &source,
            "          cargo xtask release-artifact verify \"${bundle}\"",
            "          tar -xzf unverified.tar.gz\n          cargo xtask release-artifact verify \"${bundle}\"",
        );
        assert!(validate_github_release_workflow(&changed).is_err());
    }

    #[test]
    fn rejects_secret_backed_scorecard_workflow() {
        let error = validate_scorecard_workflow("${{ secrets.SCORECARD_TOKEN }}").unwrap_err();
        assert!(error.contains("must not use repository secrets"));
    }

    #[test]
    fn rejects_broadened_secret_scanning_exclusions() {
        validate_secret_scanning_config(SECRET_SCANNING_CONFIG).unwrap();
        let broadened = format!("{SECRET_SCANNING_CONFIG}  - \"docs/**\"\n");
        let error = validate_secret_scanning_config(&broadened).unwrap_err();
        assert!(error.contains("match the reviewed generated-data paths exactly"));
    }

    #[test]
    fn requires_reviewed_codeql_commit_pins() {
        let source = format!(
            "github/codeql-action/init@{CODEQL_ACTION_PIN} # v4.39.2\n\
             github/codeql-action/analyze@{CODEQL_ACTION_PIN} # v4.39.2\n"
        );
        validate_codeql_workflow(&source).unwrap();
        assert!(validate_codeql_workflow(&source.replace(CODEQL_ACTION_PIN, PIN)).is_err());
    }
}
