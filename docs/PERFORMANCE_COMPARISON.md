# Released CLI performance comparison

The optional `just perf-compare` command compares explicitly supplied scanner
executables on deterministic synthetic inputs. It is separate from the Rust
compatibility oracle, inherited performance budgets, and release qualification.
It does not change the accepted Gitleaks revision or packaged default rules.

The [2026-11-11 measurement report](validation/cross-scanner-2026-11-11.md)
contains all workload results and links to the numeric evidence.

The [version manifest](validation/cross-scanner-versions.json) identifies the
published macOS arm64 executables selected for this comparison:

| Executable | Release | Default rule definitions |
| --- | --- | ---: |
| Rustleaks | 0.1.0-alpha.6 | 222 |
| Rustleaks | 0.1.0-alpha.8 | 222 |
| Gitleaks | 8.30.1 | 222 |
| Betterleaks | 1.10.0 | 466 |

Rule counts describe configuration entries, not detection quality. The first
three releases have byte-identical packaged default TOML. Betterleaks has a
different default configuration. Its stable v1 release is used; moving v2
development code is outside this comparison.

The manifest records release commits, archive and executable hashes, published
checksum evidence, configuration hashes, and inspected build metadata. These
are released binaries with their respective build choices. Gitleaks and
Betterleaks both use their packaged RE2 implementations; this is not a
comparison against Go's standard regular-expression implementation.

## Measurement profiles

`shared-rules` uses a small explicitly specified common rule set, fixed task
depths, and `GOMAXPROCS=1` for the Go executables. Expected findings are derived
from fixture construction. This profile tests those rules and inputs; it does
not establish general equivalence between all supported configurations.

`shipped-rules` retains each executable's built-in rules, filters, and default
concurrency. A depth is increased only when the named task requires a feature
that is disabled by default. Every effective setting and override is recorded.
Differences in expected, missing, or additional findings remain visible beside
timings. A finding difference is not silently normalized into agreement.

Actual executable help, flag initialization, and positive probes establish
decode depth 5 for all four selected releases. Archive traversal defaults to
0 for Rustleaks and Gitleaks, and 8 for Betterleaks. The Gitleaks 8.30.1 README
still describes decode depth 0; the executable and its flag initialization
take precedence in this protocol.

Rustleaks' CLI uses one detection worker and one queue slot. The Go tools have
different source concurrency, and Betterleaks also uses a parallel filesystem
walker. A Go scheduler cap is neither an operating-system CPU quota nor equal
worker or OS-thread counts. The report states these differences and includes
CPU consumption as well as elapsed time.

Betterleaks validation is explicitly disabled. The suite uses local files,
standard input, and local Git repositories. It does not contact credential
providers or use live credentials.

## Workload scope

The original Rustleaks phase benchmarks remain documented in
[Performance measurement](PERFORMANCE.md). Their operation-only timings are
not mixed with whole-command results from this suite.

| Earlier operation | CLI counterpart |
| --- | --- |
| 4 MiB JSON scan | Scan a 4 MiB JSON input and emit JSON findings |
| 20,000 base64 lines | Scan 20,000 encoded synthetic records with decoding enabled |
| 100,000 small fragments | Traverse 100,000 files of 64 bytes each |
| JSON report with 10,000 findings | Scan and report 10,000 distinct synthetic findings |
| 500 small Zstandard files | Traverse 500 named streams with archive scanning enabled |
| 20,000-commit Git history | Scan a deterministic linear patch history |
| 12 MiB JSON in 16 KiB fragments | Traverse 768 JSON files of 16 KiB each |
| 4 MiB invalid UTF-8 | Scan malformed bytes with known ASCII plants |
| 256 KiB multi-language source | Traverse a synthetic source tree totaling 256 KiB |

The filesystem cases include traversal and file I/O. They do not reproduce
in-memory fragment dispatch. The report case includes detection and JSON
writing, not serialization alone. Archive inputs are named files: the selected
tools do not detect the tested compressed streams through anonymous stdin.

Small and empty inputs expose startup costs. Clean, mixed application, and
independently seeded held-out inputs complement the inherited stress shapes.
All values are generated offline. Synthetic injection recovery and unexpected
findings do not establish deployment precision or real-world recall.

## Isolation and coverage

The collector starts children with an allowlisted environment and an isolated
working directory. Scanner configuration and ignore environment variables,
ambient Git settings, credentials, and Go runtime overrides are not inherited.
Input trees exclude scanner configuration and ignore control files. Reports,
diagnostics, and tool binaries remain outside the scanned inputs.

Git identity, revision boundaries, input paths and byte counts are fixed before
sampling. Git history means patches over the declared reachable revisions,
not every stored object or every merge-resolution blob. Fixture creation and
Git preparation occur outside the timed region.

Expected findings are independently constructed multisets. The comparison
covers nine benchmark fields: rule, path, secret hash, start and end lines,
start and end columns, commit, and decoded status. This is not complete JSON
report equivalence. Identity recovery and physical-coordinate agreement are
reported separately, preserving duplicates and additional findings.

Separate untimed scope witnesses check exact marker identity, path, commit,
decoded status, and multiplicity. Witness coordinate differences remain
visible but do not imply a file or commit was skipped. Available scan counters
must agree with independently prescribed scope; missing counters are explicitly
unavailable. Exact per-commit witnesses can establish the selected fixture
scope without a printed commit-count counter. A witness pass is not proof that
every byte was inspected in every subsequent run. Unestablished coverage is
marked indeterminate and cannot support a favorable comparable-work speedup.

The shared-rule eligibility gate still requires agreement on all nine finding
fields. Timings with position differences remain descriptive observations,
not equivalent-result speedups. In particular, the pinned Gitleaks column
calculation is deliberately preserved by Rustleaks; its differences from
physical byte columns are not silently corrected by this harness.

The frozen `location-second-line-includes-boundary-newline` case in the
[location evidence](../compat/detect-corpus/outcomes-v1.jsonl) records this
legacy behavior. The report therefore distinguishes physical-coordinate
agreement from preservation of Rustleaks' accepted compatibility profile.

Shipped detection scope can also differ. Betterleaks 1.10.0's
[AWS access-key rule](https://github.com/betterleaks/betterleaks/blob/8d77e1712fb06fd14444cc648686f1d5655e28a8/config/betterleaks.toml#L845)
requires a nearby secret-access-key component. A standalone synthetic access
ID can match the common rule while being intentionally excluded by that
shipped policy. Such a difference does not establish live credential validity
or a real-world false-negative rate.

## Timing and resource accounting

The timer covers process creation, configuration, reading, decoding or archive
work, Git subprocesses, scanning, JSON output, and exit. Fixture generation,
hashing, outcome parsing, and validation are outside the timer.

Each cell has one untimed warmup and eight measured fresh processes. Four-tool
orders are `A B D C`, `B C A D`, `C D B A`, and `D A C B`, repeated twice.
The complete schedule is retained. Measurements are serial, after builds and
fuzzing stop. Filesystem caches are warm or uncontrolled; these are not
cold-disk measurements.

Reports retain all samples and arithmetic medians, minima, maxima, and median
absolute deviations. Eight samples do not establish a p95 or statistical
significance. Incomplete runs and failed repetitions remain explicit; the
collector does not rank only the successful subset of a failed cell.

Per-child `wait4` accounting records user CPU, system CPU, and the
OS-reported maximum resident set. Darwin reports RSS in bytes; Linux reports
KiB. This metric is not simultaneous aggregate process-tree peak memory,
allocation volume, or retained engine memory. The aggregate process-tree peak
field remains unavailable. CPU and RSS scope limitations apply particularly
to commands that invoke Git.

External deadlines and output bounds apply to each invocation. Process groups
are cleaned up on failure. A completed collection requires the planned matrix,
explicit cell dispositions, and unchanged executable, configuration, fixture,
and collector identities at the end.

## Reproduction and evidence

Use Python 3.9 or later on a supported Unix host. Download the release archives
listed in the version manifest, verify their checksums, and place the extracted
executables under a private tool directory using the manifest's relative paths.
The collector verifies executable hashes before use. No tool download or build
occurs inside a measured invocation.

With the recorded collector revision checked out at the example path below,
a full collection uses a new output directory. The explicit Git path is the
Command Line Tools executable used on the measured macOS host; another host
must record its own actual Git executable and identity.

```sh
cd /private/tmp/rustleaks-comparison-checkout
just perf-compare --tools /private/tmp/rustleaks-comparison-checkout/docs/validation/cross-scanner-versions.json --tool-root /private/tmp/rustleaks-cross-scanner-tools --git /Library/Developer/CommandLineTools/usr/bin/git --output /private/tmp/rustleaks-cross-scanner-results --samples 8
```

Raw reports and diagnostics stay private. Public evidence contains reviewed
version and input identities, settings, numeric samples, quality dispositions,
and summaries. It excludes raw findings, arbitrary environment values, private
absolute paths, and unrestricted diagnostic text. Public conclusions remain
specific to the measured host, releases, inputs, and timing scope.
