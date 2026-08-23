# rustleaks-core

`rustleaks-core` is the byte-first synchronous configuration and detection
engine for the independent `rustleaks` port.

The compatibility profile targets one pinned Gitleaks revision. References to
Gitleaks in config fields, `.gitleaksignore`, and copied assets are retained
only for backward compatibility and attribution. Rustleaks is independent and
is not affiliated with or endorsed by the upstream project.

The initial supported package is `0.1.0-alpha.1`. Its public API is guarded by
an exact first-release snapshot; changes remain possible during the alpha
series but require an explicit reviewed baseline update.

Regular-expression execution is hidden behind a private Go-compatible
frontend and an exact-pinned Unicode-15 direct PikeVM. No backend type is part
of the public API. Validated allowlists retain private combined path/content
matchers and immutable normalized commit/stopword state; scanning preserves
upstream's separate early-fragment and finding-level evaluation stages.

The session layer assigns global or commit-qualified fingerprints, parses
native `.rustleaksignore` plus backward-compatible `.gitleaksignore` data and
baseline bytes with pinned Go-compatible semantics, and
collects accepted findings through immutable policy plus owned mergeable
batches. It is safe Rust, uses host-independent byte path rules, and does not
create a scheduler or require an async/runtime dependency on macOS, Linux, or
Windows.

`Engine::scan_fragment_controlled` adds cooperative cancellation and aggregate
decoded-byte, work-unit, and finding-record budgets. The ordinary
`scan_fragment` method remains the unlimited, never-cancelled compatibility
wrapper. Partial outcomes carry structured termination and usage, and never
include candidates from an unfinished top-level rule.

## Licensing and attribution

The independent Rust implementation is MIT licensed. Copied or adapted
Gitleaks compatibility configuration and test-derived material retains the
upstream project's MIT terms.
The safe Rust Eisel-Lemire conversion routine, its detailed powers-of-ten
table, and the generated Go Unicode 15.0.0 simple-lowercase ranges retain the
Go Authors' BSD terms. See `LICENSE` and `NOTICE`, both included in the crate
package.
