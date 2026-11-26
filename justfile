set default-list
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# Report required tools without changing the workspace.
doctor:
    just --version
    bazelisk version
    cargo --version
    rustc --version

# Check Rust formatting through Bazel.
format:
    bazelisk test //:format

# Build first-party libraries and binaries for the host platform.
build:
    bazelisk build //:build

# Run every first-party test represented in Bazel.
test:
    bazelisk test //:test

# Run the Go binding tests through Bazel.
test-go:
    bazelisk test //bindings/go:all_tests

# Run the Python binding tests through Bazel.
test-python:
    bazelisk test //bindings/python:all_tests

# Run every first-party test ten uncached times to expose nondeterminism.
flake-check:
    bazelisk test --nocache_test_results --runs_per_test=10 //:test

# Build warning-denied API documentation through Bazel.
docs:
    bazelisk build //:docs

# Check prose, templates, skills, local links, and workflow and automation commands.
docs-check:
    bazelisk run //crates/xtask:xtask -- docs-check

# Evaluate the synthetic detection-quality corpus.
quality-eval:
    bazelisk run //crates/rustleaks-eval:rustleaks_quality -- evaluate

# Run optimized benchmark workloads with their Bazel build identity.
perf-run:
    bazelisk run //crates/xtask:xtask -- perf run

# Check benchmark outcomes and build identity.
perf-check:
    bazelisk run //crates/xtask:xtask -- perf check

# Generate or verify independently specified development benchmark fixtures.
[positional-arguments]
perf-fixtures *arguments:
    bazelisk run //crates/xtask:xtask -- perf fixtures "$@"

# Measure time per scan phase on larger inputs.
perf-representative:
    bazelisk run //crates/xtask:xtask -- perf representative

# Record a CPU profile. Output stays local.
[unix]
[positional-arguments]
perf-profile *arguments:
    bazelisk run //crates/xtask:xtask -- perf profile "$@"

# Measure local unchanged-code noise and a deliberate slowdown control.
[unix]
[positional-arguments]
perf-calibrate *arguments:
    bazelisk run //crates/xtask:xtask -- perf calibrate "$@"

# Collect or check a local performance report.
[positional-arguments]
perf-report *arguments:
    bazelisk run //crates/xtask:xtask -- perf report "$@"

# Compare Rustleaks with other scanners. Output stays local.
[unix]
[positional-arguments]
compare *arguments:
    bazelisk run //crates/xtask:xtask -- compare "$@"

# Generate or check the labeled quality corpus for the scanner comparison.
[unix]
[positional-arguments]
compare-quality *arguments:
    bazelisk run //crates/xtask:xtask -- compare-quality "$@"

# Fetch, generate or check the workload sets for the scanner comparison.
[unix]
[positional-arguments]
compare-workloads *arguments:
    bazelisk run //crates/xtask:xtask -- compare-workloads "$@"

# Run formatting, lint, documentation, build, and eight-target compile gates.
check: docs-check
    bazelisk test //:check

# Run the complete local Bazel acceptance suite.
ci: docs-check
    bazelisk build --build_tests_only //:test
    bazelisk test --jobs=1 //:ci

# Build every fuzz target without running a campaign.
fuzz-build:
    bazelisk run //crates/xtask:xtask -- fuzz-build

# Replay fuzz corpora and run bounded smoke campaigns.
fuzz-smoke:
    bazelisk run //crates/xtask:xtask -- fuzz-smoke

# Run local fuzz campaigns and manage fuzz corpora.
[unix]
[positional-arguments]
fuzz *arguments:
    bazelisk run //crates/xtask:xtask -- fuzz "$@"

# Check advisories, dependency policy, and owned-code safety.
security:
    bazelisk run //crates/xtask:xtask -- security-check

# Run the bounded local deep security checks.
[unix]
[positional-arguments]
security-deep *arguments:
    bazelisk run //crates/xtask:xtask -- security-deep "$@"

# Package the engine and run clean external Cargo and Bazel consumers.
package-check:
    bazelisk run //crates/xtask:xtask -- package-check

# Run package checks and Cargo's locked no-upload publish dry run.
release-dry-run:
    bazelisk run //crates/xtask:xtask -- release-dry-run

# Regenerate Cargo, crate-universe, and Bazel module lockfiles together.
[unix]
deps-repin:
    cargo update --workspace
    cargo update --workspace --manifest-path crates/rustleaks-core/fuzz/Cargo.toml
    cargo update --workspace --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml
    cargo update --workspace --manifest-path crates/rustleaks-report/fuzz/Cargo.toml
    CARGO_BAZEL_REPIN=1 bazelisk query @crates//:srcs --lockfile_mode=update
    bazelisk mod deps --lockfile_mode=update
    git diff -- Cargo.lock cargo-bazel-lock.json MODULE.bazel.lock

# Regenerate Cargo, crate-universe, and Bazel module lockfiles together.
[windows]
deps-repin:
    cargo update --workspace
    cargo update --workspace --manifest-path crates/rustleaks-core/fuzz/Cargo.toml
    cargo update --workspace --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml
    cargo update --workspace --manifest-path crates/rustleaks-report/fuzz/Cargo.toml
    $env:CARGO_BAZEL_REPIN = "1"; bazelisk query @crates//:srcs --lockfile_mode=update; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    bazelisk mod deps --lockfile_mode=update
    git diff -- Cargo.lock cargo-bazel-lock.json MODULE.bazel.lock
