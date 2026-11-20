# Testing and parity

This page is for contributors. It explains how to run the tests, how to add
a test, and how the compatibility evidence under `compat/` is checked. The
rules for what may change are in the
[compatibility policy](../user/gitleaks-differences.md#compatibility-policy).

## Rules for tests

- Ordinary tests are small and fast. A test that needs a large input, a long
  run or a lot of memory is an opt-in check: an ignored driver, a fuzz
  campaign or a performance workload. It is not part of `just test`.
- Write expected values by hand, from the specification of the behavior. For
  findings, spans, fingerprints, report fields, exit codes and error classes,
  never copy the current Rust output into the expected value.
- Include positive cases, negative cases and near misses. A negative case
  must fail if the rule or check becomes too broad.
- Use synthetic values or reviewed upstream fixtures. Never use a live
  credential.
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
| Replay tests of one crate | `bazelisk test //crates/rustleaks-report:parity_tests` |
| Every first-party test | `just test` |
| Every test ten times, without the cache | `just flake-check` |
| All replay tests | `just parity` |
| Frozen evidence check and replay | `cargo xtask regression-check` |
| Frozen evidence check only | `cargo xtask frozen-evidence-check` |
| Test files registered in Bazel | `cargo xtask build-system-check` |
| Quality corpus report | `just quality-eval` |
| Labeled inputs for scanner comparisons | `cargo xtask compare-quality generate --out CACHE`, see [Comparison quality inputs](comparison-quality.md) |
| The full local gate | `just ci` |

Run `just flake-check` after a change to timers, cancellation, subprocesses,
directory traversal, temporary paths or concurrency. Every run must pass.

Run `cargo xtask regression-check` when supported compatibility behavior or
its evidence changes. `cargo xtask qualify` is a release candidate check; see
[Releasing](releasing.md).

Neither Go nor a Gitleaks checkout is needed for any of these commands.

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
   `include_bytes!` must be listed in `compile_data`.
2. Add the target to the crate's `all_tests` suite. `just test` runs
   `//:test`, which lists every crate's `all_tests` suite, or its unit and
   doc test targets for crates without one.
3. If the test replays frozen evidence, also add it to the crate's
   `parity_tests` suite. `just parity` runs `//:parity`.
4. Add the target to `_RUST_TARGETS` in the root `BUILD.bazel`, so that the
   format and Clippy checks cover it.

`cargo xtask build-system-check` fails when a file in `tests/` has no
`<name>_test` target in the crate's `all_tests` suite or in `_RUST_TARGETS`.
In `rustleaks-core`, `all_tests` is built from the grouped test lists in
`BUILD.bazel`, so add a new test to one list.

## Compatibility evidence

The [`compat/` README](../../compat/README.md) lists every file in
`compat/`, says which files are frozen and how to regenerate the others.

Frozen files record what Gitleaks did at the pinned revision and never
change. The [`compat/` README](../../compat/README.md#frozen-evidence)
explains how they are checked and which commands named in them no longer
run.

The committed evidence includes:

- 6,770 default-rule helper samples, covering 220 rules, with negative
  samples for 82 rules;
- 3,618 regular-expression requests;
- 112 configuration cases;
- 124 source cases, 34 Git cases, 49 report cases and 119 CLI variants;
- 283 semantic assertions: 115 with direct Rust tests and 168 with a stated
  reason why they do not apply;
- six benchmark assertion links and two platform branches with Rust
  evidence;
- 607 upstream API identities, 275 upstream test identities, 225 rule
  constructors and copied fixture manifests; and
- mutation checks that reject pending traceability, missing evidence, stale
  revisions, changed defaults and swapped identities.

The two Dropbox default constructors have no helper samples. Source replay
accounts for all 124 cases with explicit safe and platform dispositions. Git
replay delegates 13 remote cases to SCM tests. Report replay delegates 15
template cases to template tests. CLI replay accounts for all 119 variants and
reports executed, platform-inapplicable and native-disposition counts
separately. Archived observations used in place of unavailable host behavior
are not counted as executions. The three valid bootstrap records have Rust
regressions. The wrong-protocol record is retired adapter behavior, and the
malformed-regex panic maps to a structured Rust configuration error.

### What the replay compares

Replay compares these functional fields exactly: rule IDs, matches, secrets,
locations, source and commit metadata, entropy, tags, required findings,
fingerprints, duplicates, ordering where specified, suppression results,
report fields and values, exit status and error classes. The only
normalization is ordering that was already nondeterministic upstream.

Presentation text, such as help, usage and error wording, must also match its
expected text. A reviewed presentation disposition can replace it.

Report corpus tests compare exact report bytes, and CLI replay compares
findings as compact JSON text. So these tests still fix JSON key order and
CSV column order, even though the policy treats that order as presentation.
To change the order, first change the report and findings comparisons to
compare parsed fields. A presentation disposition cannot cover it.

Where the Go behavior used host features or could panic, such as template
helpers that reach the host, Rustleaks uses a named, bounded behavior instead.
These cases have their own dispositions; they are not normalized away.

### Version output in the CLI replay

For the three `CLI-BB-001` version outputs, the replay first checks the
historical fields exactly, then expects the current build version from
package metadata.

Rustleaks compares the configuration `minVersion` with the implemented
Gitleaks version, 8.30.0 (`IMPLEMENTED_GITLEAKS_VERSION` in
`crates/rustleaks-cli/src/config.rs`). So the minimum version warning
recorded as event 0 of the two `CLI-BB-007` embedded configuration variants
is not printed. The replay checks the historical warning and then expects it
to be absent.

All other fields stay exact unless a presentation disposition replaces them.
The execution ledger names the historical and current build versions and
marks these five expectations.

## Presentation dispositions

`compat/presentation-dispositions.toml` holds reviewed presentation changes
for the frozen CLI corpus. Each entry names:

- an `id` for the entry;
- a corpus variant, written as `<case id>/<variant id>`, for example
  `CLI-BB-018/following-positional`;
- one presentation field: `stdout`, `stderr_usage`, or the message of one
  stderr event (`stderr_event_message` with an `event` index). A `stdout`
  entry is allowed only for help output;
- the SHA-256 of the frozen value that it replaces;
- the exact new expected text; and
- the reason for the change.

Expected text is normalized in the same way as the replay output for that
field:

- stderr event message: the log level and timestamp prefix are removed, the
  text is trimmed, the temporary root becomes `<TMP>`, durations become
  `<DURATION>`, operating system not-found errors become `<os:not-found>`,
  and `exit code:` is written as `exit status:`;
- `stderr_usage`: the block from the `Usage:` line up to the first log line,
  with trailing whitespace trimmed and one final line feed. Lines with
  versions are kept; and
- `stdout`: ANSI color codes are removed, and the temporary root becomes
  `<TMP>`.

All fields use the name `rustleaks`. On Windows, only the first path
separator after `<TMP>` is normalized, so avoid nested paths in message
dispositions.

The CLI replay requires the new text exactly. A `stderr_usage` entry replaces
the whole usage block, including the stderr events that the block's lines
produce, so the new block may have a different number of lines. Events before
and after the block stay fixed.

The replay still compares exit status, findings, reports, error class,
severity, child process cleanup and disclosure checks with the frozen
evidence. A disposition for any of these functional fields is rejected. A
disposition that no replay uses also fails the check.

Message dispositions on the two `CLI-BB-007` embedded configuration variants
use the frozen event indices. Event 0 of those variants is the removed
warning and takes no disposition.

The replay computes the error class of an event from its message text with a
keyword classifier, and its severity from the log level token. New wording
must still produce the same class. Log lines keep their level token, and the
usage block keeps its `Usage:` header. A change to the classifier is reviewed
as a functional change.

The same file holds `behavior_supersession` rows for behavior records that no
longer apply as written. `CLI-DEFER-001`, which kept help and parser usage
bytes exact, is superseded. `CLI-009` is narrowed: stream routing, error
class and non-disclosure still apply, and message wording is presentation.
The frozen corpora, `compat/behavior-matrix.toml` and
`compat/test-manifest.toml` do not change.

Before the replay compares output with a frozen value, it rewrites the
executable name `rustleaks` to `gitleaks` and the name `Rustleaks` to
`Gitleaks`. Expected text from a disposition is compared without that
rewrite, so it uses the Rustleaks name.

## What the evidence covers

| Area | Covers |
| --- | --- |
| Core | Configuration, regular expressions, detection, allowlists, decoding, composite rules, redaction, fingerprints, baselines, ignores and sessions |
| Sources | Readers, files, directories, symbolic links, archives, Git and links to findings |
| CLI and reports | Commands and flags, precedence, exit codes, error classes, output streams, JSON, CSV, JUnit, SARIF and safe templates |

All three areas have Rust regression tests and historical Go evidence. Only
`rustleaks-core` is a published package. The evidence for sources, reports
and the CLI does not make those crates public.

The replay keeps the selected regression contracts. It runs no new Go
comparison and makes no claim about inputs it has not seen.

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
(including the feature-profile library targets), and runs `//:test`. The
`//:test` suite contains every `//:parity` replay target and the CLI tests.
The musl lanes run musl binaries on the Ubuntu host. Bazel doc tests are
marked incompatible on Windows and musl; the Linux GNU and macOS lanes run
them. Each lane keeps its CLI regression ledger, which holds no finding
values, as a workflow artifact. The workflow's `Required` job fails unless
every lane passes.

Other CI jobs run on one host only. `just ci`, the Cargo stable and MSRV
checks and `cargo xtask frozen-evidence-check` run on `ubuntu-24.04`
(`x86_64`). The native lanes replay `//:parity` as part of `//:test`. The Git
adversarial check is an xtask unit test.

Cross-compilation of the eight targets proves only that the code compiles. It
is not used to claim runtime support. The native lanes run the tests; they do
not measure performance or memory on each platform. Missing native evidence
does not create an exception to the compatibility policy.

A support claim for a target needs native build, test, feature, parity,
example and CLI evidence for that exact target.
