# Native detection policy

The native policy requires explicit opt-in. Existing `Engine` callers
retain their configuration and detection behavior. This contract introduces no
compatibility exception, copied-default change, or provider network operation.
Local integration, public API, package/consumer and compatibility checks have
passed. Qualified delivery is recorded in the [roadmap](ROADMAP.md) and
[completion record](validation/process-cpu-and-completion.md).

## Profiles and selection

The pinned Gitleaks profile remains the default. Its upstream identity, copied
configuration, byte findings, serialized output, and mapped evidence remain
subject to [COMPATIBILITY.md](COMPATIBILITY.md).

`native::NativePolicy::builder()` explicitly selects `rustleaks-native-v1`.
The builder starts with the embedded default. `with_pack(id, toml)` appends an
in-memory TOML pack through the existing loader, and `build()` creates an
immutable `NativeEngine`. `native::EXTRA_RULES_V1` exposes the separately
maintained pilot asset. Nothing downloads or selects it automatically.

The wrapper returns a `NativeScanOutcome` containing the unchanged `ScanOutcome`,
exact policy identity, and bounded explanation metadata. `scan()` preserves
legacy finding serialization and termination. `engine()` exposes the effective
engine for existing sessions and rule projections; calls through that accessor
omit the native metadata envelope. Detection stays synchronous, byte-oriented,
`Send + Sync`, and caller-scheduled.

## Identities and composition

Each native rule ID begins with `rustleaks.`. Pack IDs and rule IDs use a bounded
ASCII grammar. Native-only validation rejects unknown TOML fields and
case-colliding field spellings at every supported table level before the legacy
loader runs. Known case-insensitive aliases and named-table shorthand remain
supported; positional table sequences are rejected. Fixed validation errors omit
unknown field names and values. The standalone compatibility loader remains
permissive. Duplicate pack IDs and all rule collisions fail with structured
errors. No override mechanism exists. Existing rules cannot be replaced or
silently disabled by load order. Pack extension directives, global allowlists,
and minimum-version directives are rejected. Rule-local allowlists and
composite dependencies use existing loader semantics.

Composition permits at most 32 packs, 1 MiB of aggregate pack TOML, and 1,024
native rules. Each pack is supplied wholly in memory. These bounds supplement
the existing per-expression compilation limits; they do not promise a fixed
aggregate regex compilation allocation.

`NativePolicyIdentity` compares exact length-framed bytes for the native policy
version, crate version, pinned upstream/configuration identities, enabled
annotation extensions, and ordered pack IDs and TOML sources. Whitespace and
comment edits conservatively change identity. The framing is an exact equality
contract, not a digest or authentication mechanism. Behavior changes require a
policy or package version change. Source content, scan options, budgets,
fragment metadata, and review decisions are outside configuration identity and
must be accounted for by consumers that cache results.

`builtin_review_reference()` returns a source-omitting persistent reference
only for the pinned base alone or the exact packaged pilot bytes under their
fixed pack ID. It includes checked content hashes, versions and extensions.
Custom compositions return no builtin reference and require a caller-owned
fingerprint bound to exact identity. Review records never need raw TOML.

Identity debug output omits configuration. `sensitive_exact_bytes()` is the
explicit export for access-controlled persistence or hashing with a caller's
established cryptographic implementation. It contains complete pack sources,
which can include sensitive literals. It must not be presented as a safe public
identifier. The type deliberately has no automatic serialization.

Pin third-party source revisions and hashes. Record per-file license and
attribution, source tests, transformations, unsupported semantics, and refresh
procedure. Reject imports that cannot represent relevant behavior without
omission. Copied default changes still require the upstream-sync workflow.

## Ordering and partial results

Composition retains the existing engine's lexicographic effective-rule order,
match order, generic/provider overlap filtering, redaction, exact raw spans,
and decoded-source mapping. Native IDs cannot collide, but independent rules
may report the same occurrence. No wrapper grouping or deduplication removes
occurrences. Decoded findings retain the existing distinction between upstream
location and an unavailable exact raw secret range.

`ScanControl` and `ScanOptions` retain their meanings. The native envelope
retains the actual options and aggregate budget. Review consumers must bind
options as well as configuration identity and inspect completion. A terminated
scan remains partial; the wrapper exposes only findings from the existing committed rule
prefix. An explanation may describe a candidate later filtered out or a rule
that did not finish. It is execution evidence, not a second finding inventory.
The compatibility per-target byte gate remains a rule skip rather than an
aggregate-budget termination.

## Explanations and offline annotations

`ExplanationOptions::disabled()` stores no events and runs no offline checks.
The log's `is_enabled()` and envelope's `offline_annotations_enabled()` expose
selection explicitly; neither claims a candidate was checked.
`bounded(n)` retains at most `min(n, 65_536)` records. Exhaustion or allocation
failure marks the log truncated and stops retention. It does not stop detection
or change findings. Records contain scan-local numeric rule/pass/candidate
ordinals and finite decision codes for selection, keywords, paths, patterns,
entropy, allowlists, composites, target limits, validators, and termination.
They contain no rule text, source bytes, tokens, paths, snippets, or arbitrary
provider responses. The log alone is a narrow serializable projection.

Ordinals identify evaluations within one scan, not stable review keys. A rule
ordinal indexes the effective configuration's lexicographically ordered rule
map; decoded pass zero denotes raw input. Auxiliary evaluations can repeat a
rule and candidate ordinal. Counts and decisions still reveal scan activity,
so consumers must choose where diagnostics may be disclosed.

The first extension is the historical GitHub classic PAT format pilot.
[Issuer-source review](validation/offline-validation.md) records its exact
scope and specification gap. Historical layout and checksum are distinct
checks. The layout can be valid, invalid, or unknown; the incompletely specified
checksum remains unknown. No inference about activation, expiry, revocation,
or safety is made. Validators are annotations only. Findings remain
visible under every validator result. No network, plugin interpreter, or
credential use enters core.

## Evidence and migration

The independent quality evaluator supplies the baseline. New rules require
positive, negative, boundary, invalid-byte, allowlist and exact-span evidence,
including full-ruleset overlap. The initial pilot remains limited to Azure
Service Bus/Event Hub, Azure App Configuration and MongoDB credential URIs.
Existing behavior uses Rust regression replay of frozen historical evidence
and independently specified Rust contracts.

The native API includes executable documentation examples and focused tests
for composition, identity changes, unchanged legacy outcomes, partial outcomes,
bounded diagnostics, decoding, redaction, and uncertainty. Source-bound local
results include exact generated API validation, packaging, external Cargo/Bazel
consumers and the historical full pinned-Go differential. Current Rust-owned
qualification and hosted delivery are identified separately in the
[local validation record](ROADMAP.md#current-local-validation).
Consumers must reject stale review or cache decisions on identity mismatch;
matching an identity alone does not establish matching input or scan options.
