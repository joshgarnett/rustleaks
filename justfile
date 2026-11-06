set default-list
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# Report required tools without changing the workspace.
[unix]
doctor:
    just --version
    bazelisk version
    cargo --version
    rustc --version

# Report required tools without changing the workspace.
[windows]
doctor:
    just --version
    bazelisk version
    cargo --version
    rustc --version

# Check Rust formatting through the authoritative Bazel graph.
format:
    bazelisk test //:format

# Build first-party libraries and binaries for the host platform.
build:
    bazelisk build //:build

# Run every first-party test represented in Bazel.
test:
    bazelisk test //:test

# Run every first-party test ten uncached times to expose nondeterminism.
flake-check:
    bazelisk test --nocache_test_results --runs_per_test=10 //:test

# Build warning-denied API documentation through Bazel.
docs:
    bazelisk build //:docs

# Check maintained prose, templates, skills, and local links.
docs-check:
    bazelisk run //crates/xtask:xtask -- docs-check

# Run the committed compatibility replay through Bazel.
parity:
    bazelisk test //:parity

# Evaluate the maintained synthetic detection-quality corpus.
quality-eval:
    bazelisk run //crates/rustleaks-compat:rustleaks_quality -- evaluate

# Run optimized benchmark workloads with their Bazel build identity.
perf-run:
    bazelisk run //crates/xtask:xtask -- perf run

# Check benchmark outcomes, build identity, and applicable host budgets.
perf-check:
    bazelisk run //crates/xtask:xtask -- perf check

# Collect representative phase measurements on demand.
perf-representative:
    bazelisk run //crates/xtask:xtask -- perf representative

# Capture an optional native profile with private output.
[unix]
[positional-arguments]
perf-profile *arguments:
    bazelisk run //crates/xtask:xtask -- perf profile "$@"

# Measure local unchanged-code noise and a deliberate slowdown control.
[unix]
[positional-arguments]
perf-calibrate *arguments:
    bazelisk run //crates/xtask:xtask -- perf calibrate "$@"

# Collect or validate an optional private performance report.
[positional-arguments]
perf-report *arguments:
    bazelisk run //crates/xtask:xtask -- perf report "$@"

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

# Run private local fuzz evidence and reviewed-corpus operations.
[unix]
[positional-arguments]
fuzz *arguments:
    bazelisk run //crates/xtask:xtask -- fuzz "$@"

# Check advisories, dependency policy, and owned-code safety.
security:
    bazelisk run //crates/xtask:xtask -- security-check

# Run the optional bounded local deep-security profile.
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
    cargo generate-lockfile
    cargo generate-lockfile --manifest-path crates/rustleaks-core/fuzz/Cargo.toml
    cargo generate-lockfile --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml
    cargo generate-lockfile --manifest-path crates/rustleaks-report/fuzz/Cargo.toml
    CARGO_BAZEL_REPIN=1 bazelisk query @crates//:srcs --lockfile_mode=update
    bazelisk mod deps --lockfile_mode=update
    git diff -- Cargo.lock cargo-bazel-lock.json MODULE.bazel.lock

# Regenerate Cargo, crate-universe, and Bazel module lockfiles together.
[windows]
deps-repin:
    cargo generate-lockfile
    cargo generate-lockfile --manifest-path crates/rustleaks-core/fuzz/Cargo.toml
    cargo generate-lockfile --manifest-path crates/rustleaks-sources/fuzz/Cargo.toml
    cargo generate-lockfile --manifest-path crates/rustleaks-report/fuzz/Cargo.toml
    $env:CARGO_BAZEL_REPIN = "1"; bazelisk query @crates//:srcs --lockfile_mode=update; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    bazelisk mod deps --lockfile_mode=update
    git diff -- Cargo.lock cargo-bazel-lock.json MODULE.bazel.lock
