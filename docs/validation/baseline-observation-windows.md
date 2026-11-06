# Baseline observation-window validation

Validation date: 2026-11-06. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

The fixed baseline matrix completed, but the longer observation length did not
qualify across all guards. Three of eight K=10 cells failed the predeclared
calibration conditions. No optimization candidate was timed, no production
optimization was accepted, and no candidate or release threshold was created.
P3 is blocked on qualified measurement in the [roadmap](../ROADMAP.md).

## Retained tooling

Optional window calibration reuses the original scan and sample timing methods
byte for byte. It adds indexed worker components, checked totals, exact integer
ratio decisions, retained partial transcripts and strict termination checks.
A prepared matrix path binds one optimized Bazel build before all 16 cells;
it does not build between cells. Omission of the new options preserves the
legacy calibration protocol and its historical results.

The worker emits each component outside its scan timers, then immediately
continues. Collector parsing, validation and transcript writing can overlap
later scans and perturb their elapsed times. This limitation was explicitly
frozen before invocation. K=1/K=10 differences therefore do not isolate a
causal effect of observation length. All sides and both runs use the same
versioned protocol.

The new policy applies no invented physical timer-error allowance. Each window
is an exact integer sum of separately timed scans. Its band is twice the largest
absolute training ratio deviation; held-out deviations must fit and every
deliberate extra-work deviation must exceed it. Decisions use checked integer
cross multiplication. Zero training variation remains unqualified. The
[packet](../plans/baseline-observation-windows.md) preserves the complete rule,
schedule, resource limits and stopping conditions.

Independent controls reject missing, duplicated or reordered components,
changed identities/work counts, invalid numeric types, overflow, incorrect
classification boundaries and zero-band qualification. Actual synthetic child
processes exercise absent/contradictory completion, failed exit, trailing bytes,
output ceilings, timeout, inherited descendants and cleanup. Separate controls
reject source/executable mutation and forged bindings. Synthetic clocks test
the fixed schedule, idle-inclusive cell deadlines, late returns/checkpoints and
retention of partial/uncollected states. These are finite controls, not a proof
of universal containment or clock accuracy.

## Frozen source and provenance

The accepted baseline contained 797 entries. The clean measurement snapshot has
800 entries at local commit `1b0930b6a52b702731a3c872cb633e199723554d`, tree
`a34c6eb85d01292ff4d7ba008ec2a461352c6fe6`. The source inventory, protocol,
schedule, worker/controller binaries and completed-check hashes were frozen
before invocation. This identity excludes the subsequent documentation and
generated evidence projection.

Independent post-collection verification reconciled every frozen source entry,
the compiler/version/options, 131 Rust action identities, 45 generated argument
files, executable hashes, full arguments/action graph, default configuration,
protected inputs and workload-definition digest. All 864 worker executable
fingerprints agree with that build. All 81 runtime source entries and 24
protected manifest, lock, toolchain, pin and copied-default entries match the
accepted baseline. The production engine and all earlier accepted fixes remain
unchanged by this packet.

The host default Go 1.27.1 failed the pinned-version check. Validation with
the already installed Go 1.26.10 passed. No toolchain or dependency was
installed or changed.

## Native observations

Collection used Apple M1 Max, macOS 26.5.2, aarch64-apple-darwin and Rust 1.95.0.
All 16 cells completed in 657.797 seconds. The retained matrix contains 864
fresh workers, 4,752 components, 554,400 timed scans and 864 warm scans. Its
1,728 commands and 7,344 responses reconcile exactly. No retry, additional cell
or discarded observation occurred. All process exits, EOF markers, cleanup and
deadline records passed; the largest collector duration was approximately
3.246 seconds.

The table shows diagnostic bands, not accepted regression thresholds. H denotes
a failed held-out check; S denotes a failed extra-work sensitivity check.

| Workload | K=1 run 1 | K=1 run 2 | K=10 run 1 | K=10 run 2 |
| --- | ---: | ---: | ---: | ---: |
| Dense 16 KiB | 8.2405%, pass | 12.5348%, pass | 5.0924%, pass | 28.6167%, pass |
| Mixed 16 KiB | 4.0357%, H | 11.8249%, pass | 6.8020%, H | 9.9385%, pass |
| Default no-hit 16 KiB | 8.2927%, pass | 11.2039%, pass | 107.3469%, S | 5.5029%, pass |
| Decode depth five | 4.9699%, H | 4.0408%, pass | 28.8313%, pass | 2.8052%, H |

Only the predeclared K=10 length could qualify a later comparison. Its failures
were:

- Mixed run 1: held-out pair 1 deviated by -8.4243%, outside its 6.8020% band.
- No-hit run 1: a 53.6735% training deviation produced the 107.3469% band.
  All nine extra-work deviations, from 73.8676% to 101.4544%, fell below it.
- Depth-five run 2: held-out pair 7 deviated by 47.6160%, outside its 2.8052% band.

Pair indices are zero-based. Two descriptive K=1 cells also failed held-out
checks. In total, 11 of 16 cells passed; five of eight K=10 cells passed. Neither
dense success nor K=1 observations can rescue failed K=10 guards. The cause of
the variation remains unknown. No competing builds, tests, fuzzing or profiling
ran during collection; unrelated host activity and thermal state were not
controlled.

Two independent audits recomputed all exact classifications and reconciled
ordered components, totals, raw transcripts, termination records and frozen
identities. The generated [projection](observation-windows-2026-11-06.json)
retains all ordered component durations, exact fractions, classifications,
work counts and hashes for 6,981 native artifacts. Raw commands, absolute paths
and compile-action keys remain private; the complete private build is bound by
its digest.

## Validation and disposition

| Check | Result and scope |
| --- | --- |
| Integrated `just ci` | Pass: 55 targets, format, lint, documentation, host builds, declared target compilation and committed parity |
| `just security` | Pass: dependency/advisory/vetting, Miri, owned-safety and panic-policy checks |
| `just fuzz-smoke` | Pass: all eight targets, zero crash artifacts |
| Clean optimized checkout | Pass: worker/controller builds and focused worker, transcript, matrix and process tests |
| Native matrix and independent audits | Complete and internally consistent; baseline qualification fails |
| Documentation and redacted self-scans | Pass: maintained prose/links, complete working tree and all 276 history commits; no scan findings |

Supervision has separate five-second reaping and pipe-cleanup deadlines and
may retry reaping after cleanup failure; this is not a strict total cleanup
wall-time guarantee. Absolute acceptance
checks reject late results. The shared process supervisor and production
scanner are unchanged.

This tooling-only packet changes no supported detection/configuration behavior,
public API, packaged defaults, dependency graph or release obligation. A fresh
full Go differential and package/consumer run were outside its required scope.
Native results apply only to the executed target. No physical clock precision,
confidence interval, allocation improvement, production speedup or absence of
defects is established.

The bounded investigation is complete. Further P3 work requires a separately
justified measurement change and reviewed protocol; repeating this matrix or
increasing its size is not an automatic next step. Unrelated security and
feature packets retain their own prerequisites and completion boundaries.
