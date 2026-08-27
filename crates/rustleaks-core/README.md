# rustleaks-core

`rustleaks-core` is the byte-first synchronous configuration and detection
engine for the independent `rustleaks` port.

The compatibility profile targets one pinned Gitleaks revision. References to
Gitleaks in config fields, `.gitleaksignore`, and copied assets are retained
only for backward compatibility and attribution. Rustleaks is independent and
is not affiliated with or endorsed by the upstream project.

The crate is on an alpha development line. Its public API is guarded by an
exact snapshot; changes remain possible during the alpha series but require an
explicit reviewed baseline update.

Regular-expression execution is hidden behind a private Go-compatible
frontend and a direct PikeVM with downstream-compatible `regex-automata`
`^0.4.12` and `regex-syntax` `^0.8.5` requirements. Unicode properties and
case folding can therefore include additions after the pinned Go Unicode 15
baseline. No backend type is part of the public API. Validated allowlists
retain private combined path/content matchers and immutable normalized
commit/stopword state; scanning preserves upstream's separate early-fragment
and finding-level evaluation stages.

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

Finding match and secret mappings are exact half-open ranges into the original
fragment when no transform intervenes. Decoded, path-only, nonparticipating,
and otherwise inexact mappings are explicitly unavailable and must not be
approximated for rewriting.

Budgets cover one fragment scan. A caller scanning multiple fields or leaves
owns aggregate input-byte, finding, work, cancellation, and elapsed-time
limits for the complete operation. Findings and fragments retain ordinary
owned byte buffers, may be cloned, and are not zeroized on drop. Compatibility
serialization intentionally preserves raw fields. `Debug` output omits their
contents, while `Finding::without_detected_secrets` removes detected secret
byte sequences recursively and drops a retained fragment. Neither mechanism
proves that unrelated or undetected source-derived metadata is safe to
disclose; use a narrow caller-owned projection across trust boundaries.

## Licensing and attribution

The independent Rust implementation is MIT licensed. Copied or adapted
Gitleaks compatibility configuration and test-derived material retains the
upstream project's MIT terms.
The safe Rust Eisel-Lemire conversion routine, its detailed powers-of-ten
table, and the generated Go Unicode 15.0.0 simple-lowercase ranges retain the
Go Authors' BSD terms. See `LICENSE` and `NOTICE`, both included in the crate
package.
