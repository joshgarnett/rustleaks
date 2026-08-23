set default-list
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# Report required tools and their selected versions without changing the workspace.
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

# Build warning-denied API documentation through Bazel.
docs:
    bazelisk build //:docs

# Check maintained prose, templates, skills, and local links.
docs-check:
    bazelisk run //crates/xtask:xtask -- docs-check

# Run the committed compatibility replay through Bazel.
parity:
    bazelisk test //:parity

# Run formatting, lint, documentation, build, and eight-target compile gates.
check: docs-check
    bazelisk test //:check

# Run the complete local Bazel acceptance suite.
ci: docs-check
    bazelisk test //:ci

# Build every fuzz target without running a campaign.
fuzz-build:
    bazelisk run //crates/xtask:xtask -- fuzz-build

# Replay fuzz corpora and run bounded smoke campaigns.
fuzz-smoke:
    bazelisk run //crates/xtask:xtask -- fuzz-smoke

# Check advisories, dependency policy, and owned-code safety.
security:
    bazelisk run //crates/xtask:xtask -- security-check

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
    CARGO_BAZEL_REPIN=1 bazelisk query @crates//:srcs --lockfile_mode=update
    bazelisk mod deps --lockfile_mode=update
    git diff -- Cargo.lock cargo-bazel-lock.json MODULE.bazel.lock

# Regenerate Cargo, crate-universe, and Bazel module lockfiles together.
[windows]
deps-repin:
    cargo generate-lockfile
    $env:CARGO_BAZEL_REPIN = "1"; bazelisk query @crates//:srcs --lockfile_mode=update; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    bazelisk mod deps --lockfile_mode=update
    git diff -- Cargo.lock cargo-bazel-lock.json MODULE.bazel.lock
