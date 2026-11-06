# Larger structured test cases

The optional deep-security operator combines bounded fuzz campaigns with
deterministic larger-input cases. These are different forms of evidence.
Passing a structured case does not measure fuzz source coverage or certify a
decoder that the case does not exercise.

The test-only helper in
`crates/rustleaks-core/tests/support/campaign_profile.rs` defines the shared
limits and larger synthetic seeds. It is outside the production library.
`RUSTLEAKS_FUZZ_PROFILE=deep` selects the explicit deep harness profile; the
private runner sets and records it. Smoke and extended profiles retain the
existing 4–16 KiB input caps. Deep permits 64 KiB per input and raises the
corresponding internal harness limits. Unknown profiles fail at initialization.

## Boundary traceability

| Boundary | Entry point and synthetic case | Asserted evidence | Limit of the claim |
| --- | --- | --- | --- |
| Regex and fragment input | `go_regex` and `fragment_scan`; match suffix beyond the old input cap | Full-input exact end span; truncated smoke input has no match | No new Go parity claim |
| Configuration | `config`; rule after 8 KiB comment, selected-rule and source-byte boundary cases | Rule retained; inclusive selection limits accepted and one more rejected | Selection limits do not bound every configuration allocation |
| Nested decoding | Controlled fragment scan of three encoded layers | Complete result at measured decoded-byte budget; one less returns structured partial termination | Deterministic budget evidence, not exhaustive decoder coverage |
| Many findings | Controlled scan producing 8,192 occurrences | Exact count at the finding limit; one less rolls back the partial top-level rule | Operation-wide multi-fragment budgets remain outside this case |
| Session metadata | Large synthetic finding and baseline classification | Retained metadata length and baseline suppression | Does not enumerate all session state transitions |
| Archive input | Shared archive fuzz exercise with a 32 KiB stored member | Entire member emitted and compared; smoke truncation cannot emit it all | Stored TAR input reachability only |
| Archive expansion and nesting | Zlib member, nested TAR, many entries and aggregate member cases | Inclusive member/depth/entry/total boundaries and structured limit issues | Larger structured cases cover these formats; they do not imply other codec coverage |
| Reader scheduling | Shared scheduled-reader exercise with 8,192 instructions | Actual read-operation, payload-byte and emitted-byte counts | Existing chunk/callback correlations remain; arbitrary chunk equivalence is not assumed |
| Git parser | Deep seed containing 512 added lines beyond 16 KiB | Larger campaign input and deterministic parser outcome | Parser limits remain; no per-line consumption counter or source-coverage claim |
| Templates | Larger literal source, 16 findings, repeated literal actions | Exact source/action/output boundaries and structured errors | Safe-template profile only |

All inputs are generated from fixed nonfunctional values. Structured source
cases stay below 6 MiB of original data, with at most 4 MiB aggregate emitted
archive bytes. The optional operator provides the external deadline; controlled
scan cancellation remains cooperative. The deep member cap is 1 MiB, depth 4
and entry count 256. Production defaults remain unchanged.

## Execution and interpretation

Each core, sources and report `security_stress_test` target has small ordinary
contract tests and an ignored `security_stress_driver`. The optional operator
selects that driver explicitly, captures its output privately, and reports its
status. Ordinary release tests do not run the larger drivers. Successful driver
rows contain case identifiers, measured counts and classifications, without raw
findings. A failed driver is a failed stage, never a successful coverage result.

The same harness profiles are exercised by the existing eight ASan fuzz targets.
LibFuzzer edge/feature counters are feedback metrics. Source/line/region
coverage requires matching LLVM tools and an actual coverage replay; a missing
tool is recorded as skipped. Ordinary Bazel tests and the traceability table
must not be substituted for that coverage.

See [security controls](SECURITY_CONTROLS.md) for private evidence retention and
the optional operator, and [resource limits](RESOURCE_LIMITS.md) for the
production contract. Native/platform claims require executed evidence on that
platform; compilation alone is insufficient.
