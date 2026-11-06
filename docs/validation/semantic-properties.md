# Semantic properties and source harness validation

Validation date: 2026-11-05. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

This bounded S3 increment adds semantic properties and repairs reader/Git fuzz
control correlations. It demonstrated no additional production scanner defect.
It did expose and correct a Bazel/Cargo output-directory race. The previous
[four production corrections](semantics-and-matching.md) remain intact. Broader
S3 and further P3 work remain open in the [roadmap](../ROADMAP.md).

The baseline inventory contained 783 entries with verified bytes, modes and
symlink targets. Independent validation used exact candidate source and
separate build output. Its dirty source status does not establish a clean
release baseline.

## Independent properties

| Boundary | Added evidence | Failure control |
| --- | --- | --- |
| Decoders and locations | Three tests cover 424 constructed cases: 84 encoding chains through depth three at three placements, 16 nested sibling combinations, and 156 raw byte/span cases. Expected positions are recorded during input construction. | Removing nested predecessor mapping breaks the nested tests; truncating normalized end offsets breaks the malformed-byte span test. |
| Engine budgets and partial outcomes | Six tests include 42 work-budget, 26 finding-record and 24 nested decoded-byte boundary cases, complete/cancelled distinction and reused-control isolation. Unfinished-rule findings roll back while incurred charges remain. | Tests reject strict rather than inclusive bounds, unfinished-rule publication, reset decoded-byte charges, termination-insensitive equality and latched cancellation. |
| Session isolation | The same six-test suite checks ignore/baseline classification, session ownership, clone isolation, duplicate handling and atomic rejection of a foreign-policy merge. | Mutating state before rejecting the foreign policy fails the test. |
| Files and Git metadata | Eleven ordinary tests check actual reader consumption, emitted bytes, callback outcomes, parser counts, independent ceilings/cancellation and preserved legacy mappings. | The framed 129-hunk case succeeds; the former coupled control pre-cancels the same patch. Individual callback and ceiling changes produce the expected finite outcomes. |
| Campaign initialization | One test calls the actual initializer under smoke and deep profiles, checking twelve generated frame seeds, legacy seeds and private file permissions. | Omitting generated frame seeds from initialization fails the test; restored code passes. |

Eight isolated deliberate production mutations demonstrate test sensitivity,
not discovered production bugs. They are absent from the validated source.
An additional isolated mutation checks campaign initialization.
All three new integration targets belong to the ordinary test, formatting and
Clippy gates; they do not expand the pinned parity manifest.

Decoded reporting locations identify enclosing encoded source candidates.
Exact decoded match/secret rewrite ranges remain `Unavailable`; raw ranges must
slice the original bytes exactly. The budget matrices establish their stated
finite boundaries, not general monotonicity of finding sets. Cancellation tests
do not promise a public poll count. Reader tests do not assume arbitrary chunk
partitioning preserves every match. The Git fuzz hook exposes optional file/hunk
counts, so these tests do not classify internal rejection errors.

## Source frames and campaigns

Reader frames independently select chunk size, read-ahead, stop, callback error,
pre-cancellation, callback cancellation and schedule length. Git frames separate
file/hunk ceilings from pre-cancellation. The maintained runner adds eight
reader and four Git synthetic seeds to both profiles. Actual retained initial
corpora contained all twelve framed seeds.

The [source fuzz contract](../../crates/rustleaks-sources/fuzz/README.md) defines
the versioned headers and unchanged caps. Complete recognized prefixes reserve
part of the old arbitrary-input space. Committed and generated deep seeds have
no prefix collisions and retain their original interpretation; arbitrary old
artifacts require review. Short headers and unknown versions use legacy parsing.
All 256 legacy control values are checked under both profiles.

Two serial ASan campaigns used deep 64 KiB inputs, seed 1, a 60-second budget
per target, at most one million executions, a five-second input timeout and
2 GiB RSS limit, within a 600-second whole-run deadline. Both completed with
zero crash artifacts and successful final identity checks.

| Target | Executions | Covered edges | Features | Final corpus files |
| --- | --- | --- | --- | --- |
| Reader schedule | 7,137 | 365 | 1,739 | 194 |
| Git patch | 830,360 | 898 | 3,509 | 974 |

These are libFuzzer feedback counters, not unique cases or source coverage.
Raw inputs, logs, source inventories and manifests remain private. The retained
campaigns precede the two-file build-exclusion amendment below. Both compiled
target hashes still match after that amendment, and all eight smoke targets
passed on the amended source. This does not rewrite the retained manifests or
make their earlier whole-source identity identical to the final source; strict
replay may require the recorded source snapshot.

## Build integration correction

A package check overlapped a Cargo fuzz build. Bazel's recursive contract glob
entered a standalone fuzz `target/debug/incremental` directory while Cargo
removed it, causing an inconsistent-filesystem error before package checking.
The prior `.bazelignore` excluded only the root `target` directory.

The ignore list now also excludes the three standalone fuzz `target`
directories. An exact-list contract test rejects missing entries, broad source
exclusions, wildcards and duplicates. A before/after query proved that the
temporary output sentinel disappeared from the contract glob while real source
remained. The package check passed after the correction. This is a build
integration defect, not a scanner defect or a new scan exclusion.

## Validation

| Check | Result and scope |
| --- | --- |
| Integrated `just ci` | Pass: 53 targets, formatting, Clippy, documentation, host builds, eight-target compilation and committed parity |
| `just security` | Pass: dependency policy, vetting, advisory, owned safety, Miri and panic-policy checks |
| `just fuzz-smoke` | Pass: all eight targets on final code, with no crash artifacts |
| `just package-check` | Pass: packaged core and clean external Cargo/Bazel consumers |
| Independent checkout | Pass: three new integration targets, xtask unit tests, formatting and Clippy; initial run passed, final build-only rerun reused five cached test results |
| Local package publication dry run | Pass: locked validation of added packaged tests against a local no-upload registry |
| Redacted repository self-scans | Pass: working tree and all 276 commits, with no findings |
| Documentation and links | Pass: maintained prose and Rust documentation surfaces |
| Independent acceptance review | No unresolved material findings in implementation, evidence or documentation |

The added core tests are included by the existing package include rules.
No runtime source file changed in this increment: all 81 runtime source entries
match the accepted baseline. All 24 checked manifests, locks, toolchain/module
inputs, pinned revision and default-configuration entries are unchanged.
Public signatures, unsafe policy, dependency versions and release requirements
are unchanged. No fresh full Go differential was required for these test,
harness and build-only changes; committed parity passed, and the previous
production corrections retain their separately recorded full differential.

All native execution here is aarch64-apple-darwin. Eight-target compilation
does not establish native runtime support elsewhere. No TSan, MSan, source
coverage, universal OOM bound or exhaustive semantic-safety claim is made.
Additional decode overlap and budget combinations, deeper Git/archive semantics
and any comparison-tracing experiment remain separately scoped work.
