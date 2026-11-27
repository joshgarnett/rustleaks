# Testing

This page is for contributors. It explains how to run the tests, how to add
a test, and how the test data under `testdata/` is used.

## Rules for tests

- Ordinary tests are small and fast. A test that needs a large input, a long
  run or a lot of memory is an opt-in check: an ignored driver, a fuzz
  campaign or a performance workload. It is not part of `just test`.
- Write expected values by hand, from the specification of the behavior. For
  findings, spans, fingerprints, report fields, exit codes and error classes,
  never copy the current Rust output into the expected value.
- Include positive cases, negative cases and near misses. A negative case
  must fail if the rule or check becomes too broad.
- Every intended functional change has a test that fails when the behavior
  breaks.
- Use synthetic values or reviewed copied fixtures. Never use a live
  credential. Never edit a copied fixture: keep its bytes, modes, symbolic
  links, provenance, hashes, licenses and attribution.
- Keep suspected findings and fuzz crash artifacts private until their
  contents are reviewed.
- Give each case a stable name.
- Keep functional assertions apart from timing. Timing measurements belong to
  the performance tools. See [Performance](performance.md).
- Do not add a second test for something that a maintained test already
  covers.

Help, usage, error wording, log lines and the banner are presentation. A
change to them updates the test expectation, and a reviewer checks the new
text against the intent of the change.

## Running tests

Run all commands from the repository root.

| Need | Command |
| --- | --- |
| One test target | `bazelisk test //crates/rustleaks-core:engine_test` |
| One test function | `bazelisk test //crates/rustleaks-core:engine_test --test_arg=NAME` |
| All tests of one crate | `bazelisk test //crates/rustleaks-sources:all_tests` |
| The CLI corpus replay | `bazelisk test //crates/xtask:cli_regression_test` |
| Every first-party test | `just test` |
| Every test ten times, without the cache | `just flake-check` |
| Test files registered in Bazel | `cargo xtask build-system-check` |
| Quality corpus report | `just quality-eval` |
| Labeled inputs for scanner comparisons | `just compare-quality generate --out CACHE` (on Windows, `cargo xtask compare-quality`), see [Comparison quality inputs](comparison-quality.md) |

[Local workflow](../../CONTRIBUTING.md#local-workflow) says which broader
command each kind of change needs, including `just flake-check`, `just ci`
and `cargo xtask qualify`.

## Adding a test

Integration tests live in `crates/<crate>/tests/<name>.rs`. Unit tests live
next to the code in `src/` and run in the crate's unit test target, for
example `//crates/rustleaks-core:rustleaks_core_unit_test`. They need no
registration.

To add an integration test file:

1. Register it in the crate's `BUILD.bazel` with
   `rustleaks_integration_test`. Most crates use a list of test names; add
   the name there. Give the test its own call when it needs extra
   `compile_data`, `srcs` or `data`. A file read with `include_str!` or
   `include_bytes!` must be listed in `compile_data`. A test that reads files
   under `testdata/` needs `//testdata:all` in `data`.
2. Add the target to the crate's `all_tests` suite. `just test` runs
   `//:test`, which lists every crate's `all_tests` suite, or its unit and
   doc test targets for crates without one.
3. Add the target to `_RUST_TARGETS` in the root `BUILD.bazel`, so that the
   format and Clippy checks cover it.

`cargo xtask build-system-check` fails when a file in `tests/` has no
`<name>_test` target in the crate's `all_tests` suite or in `_RUST_TARGETS`.
In `rustleaks-core`, `all_tests` is built from the grouped test lists in
`BUILD.bazel`, so add a new test to one list.

## Test data

The [`testdata/` README](../../testdata/README.md) lists what each folder
holds, which tests read it, and how to regenerate the generated files.

Most corpora under `testdata/` hold cases that were recorded from Gitleaks
when Rustleaks started, with their expected outcomes. They are Rustleaks
test data: the expected outcomes are the expected Rustleaks behavior. A case
changes only with a reviewed change to the behavior it covers. Write the new
expected value from the intended behavior, never from the current output, and
add a [changelog entry](../../CONTRIBUTING.md#changelog) when the change
needs one.

The tests that read a corpus compare these fields exactly: rule IDs,
matches, secrets, locations, source and commit metadata, entropy, tags,
required findings, fingerprints, duplicates, ordering where specified,
suppression results, report fields and values, exit status and error
classes. The only normalization is ordering that the cases do not specify.

Report corpus tests compare exact report bytes. So they fix JSON key order
and CSV column order, even though that order is presentation. To change the
order, first change those tests to compare parsed fields.

### CLI corpus replay

`//crates/xtask:cli_regression_test` runs the Rustleaks binary on the
recorded CLI cases in `testdata/cli-corpus/`. Each case sets up a temporary
folder, runs one command line, and compares the exit status, findings,
reports, the severity, class and fields of each stderr event, whether a
usage block was printed, child process cleanup and the disclosure check. It
does not compare help, usage or message wording, which the tests in
`crates/rustleaks-cli/tests/` check.

## Platforms

The CI workflow (`.github/workflows/ci.yml`) has one native lane for each of
the eight required targets. It runs on every pull request, on every push to
`main`, and weekly. Each lane uses a GitHub-hosted runner with the target's
operating system and architecture:

| Targets | Runner |
| --- | --- |
| `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `aarch64-apple-darwin` | `macos-15` |
| `x86_64-pc-windows-msvc` | `windows-2025` |
| `aarch64-pc-windows-msvc` | `windows-11-arm` |

Each lane checks the host architecture, builds `//:build` for the target
(including the feature-profile library targets), and runs `//:test`, which
contains every first-party test. The musl lanes run musl binaries on the
Ubuntu host. Bazel doc tests are marked incompatible on Windows and musl;
the Linux GNU and macOS lanes run them. The workflow's `Required` job fails
unless every lane passes.

`//:test` includes the Go and Python binding tests, so every lane runs them
natively:

- Go uses the Go SDK that `MODULE.bazel` pins. On Linux and macOS the tests
  link the FFI static library through cgo. On Windows they build without cgo
  and load the FFI DLL.
- Python uses the CPython builds that `MODULE.bazel` pins: 3.12 and 3.15 on
  every lane. The release dry run also installs the wheels on 3.13 and 3.14. The tests load the FFI shared library with `ctypes`.
- On musl, the binding tests build for `//platforms:linux_<cpu>_musl_c`,
  which selects the LLVM toolchain's musl C library (see
  `bazel/musl_c.bzl`). The Go test programs are static musl executables.
  The Python tests run a dynamic musl CPython, so the musl lanes install the
  Ubuntu `musl` package, which provides the musl loader.
- `//crates/rustleaks-ffi:linktest_test` links the FFI static library and a
  second Rust static library into one cgo program, on every lane but
  Windows.
- Differential tests compare the bindings with `rustleaks-core` at run
  time and store no expected values.
  `//crates/rustleaks-ffi:differential_test` scans the detection cases of
  the detect, allowlist, composite and decoder corpora and every generator
  sample with core and through the C ABI, and requires the same findings,
  completion and usage. `//crates/rustleaks-eval:binding_reference` runs a
  test-only tool that scans the fixture files, a few other `testdata` files
  and a file of all generator samples with every built-in rule through core.
  It also scans each text file with CRLF line breaks and without its final
  line break, and writes the findings as JSON. The Go `TestReferenceFindings` and the Python
  `reference_test` scan the same inputs and require the same findings in
  the same order.

The release dry run also runs `Binding Packages` on all eight lanes: it builds
a Go program from the packed `rustleaks-go` modules with the host C compiler
and installs each wheel into a new virtual environment without network
access. See [Binding packages](releasing.md#binding-packages).

Other CI jobs, such as `just ci` and the Cargo stable and MSRV checks, run
on `ubuntu-24.04` (`x86_64`) only.

Cross-compilation of the eight targets proves only that the code compiles. It
is not used to claim runtime support. The native lanes run the tests; they do
not measure performance or memory on each platform.

A support claim for a target needs native build, test, feature, example and
CLI evidence for that exact target.
