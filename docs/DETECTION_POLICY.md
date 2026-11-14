# Native detection policy

The native policy requires explicit opt-in. Existing `Engine` callers
retain their configuration and detection behavior. This contract introduces no
compatibility exception, copied-default change, or provider network operation.
Version-specific qualification is recorded in the [roadmap](ROADMAP.md) and
[completion record](validation/process-cpu-and-completion.md).

## Profiles and selection

The pinned Gitleaks profile remains the default. Its upstream identity, copied
configuration, byte findings, serialized output, and mapped evidence remain
subject to [COMPATIBILITY.md](COMPATIBILITY.md).

`native::NativePolicy::builder()` explicitly selects `rustleaks-native-v1`.
The builder starts with the embedded default. `with_pack(id, toml)` appends an
in-memory TOML pack through the existing loader, and `build()` creates an
immutable `NativeEngine`. `native::EXTRA_RULES_V1` exposes the separately
maintained pilot asset; `native::PROVIDER_RULES_V1` exposes the provider pack.
`native::CONNECTION_RULES_V1` exposes the focused connection-password pack.
Nothing downloads or selects these packs automatically.

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
for the pinned base alone or compositions of the exact packaged packs under
their fixed IDs. It includes checked content hashes, versions and
extensions, preserving composition order.
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
The optional `rustleaks-providers-v1` pack adds reviewed Groq, Cerebras,
Replicate and NVIDIA detector shapes, plus five companions for selected
Anthropic, DigitalOcean, OpenAI and Fly.io format or delimiter gaps.
Six further rules cover Cloudsmith, MiniMax, PostHog personal, Figma personal,
Together and Google Gemini candidate formats. Nine contextual provider rules,
two Slack session rules and four finite Veles rules are also included. Six Docker
Hub, Neon, Render, Deno user and Apify rules use explicit
`byte-shannon-f64-v1` strict-less-than entropy rejection. Twenty-four shared-prefix
companions add escaped-quote and vertical-tab endings with explicit less-or-equal
byte entropy and independently scoped source exclusions. The pack contains
104 rules and requires native loading; ordinary configuration loading
rejects its structured entropy values. Forty contextual and four residual
companions preserve source context, capture and path requirements while adding
reviewed VT and escaped-quote occurrences. Public Lob and Mailgun roles remain
excluded. The xAI rule selects the Apache
80-byte body expression, not
the broader overlapping MIT rule. Slack cookies have an unbounded body and
remain subject to caller-selected input and finding-payload limits.
Its [pack contract and provenance](../crates/rustleaks-core/default/rustleaks-providers-v1.md)
record the source scopes, ASCII translation, entropy rules and policy
differences. Provider attribution can replace a generic finding for the same
occurrence through existing overlap filtering; this is not an extra recovered
secret. The separate `rustleaks-connections-v1` pack provides five ASCII JDBC
and semicolon password rules and one ASCII database-URI password rule. Its
[contract](../crates/rustleaks-core/default/rustleaks-connections-v1.md)
records source predicates, extraction, byte limits and enumeration gaps;
general URI, libpq and Unicode-equivalent detection are outside that pack.
Native composition retains the default global exclusions, including the
documented URI placeholder differences from isolated pack loading.
None of these packs is selected automatically.
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

## Explicit native CLI composition

`--native-pack <pack-id>` appends a builtin pack to the pinned embedded default.
Repeat the flag to compose `rustleaks-extra-v1`, `rustleaks-providers-v1` and
`rustleaks-connections-v1` in the supplied order. Unknown or repeated IDs fail.
No pack is active unless explicitly selected. Legacy help bytes remain frozen;
this document describes the additive option.

The CLI first applies its normal configuration precedence and discovery.
Native selection requires that the resulting source is the embedded default.
A selected `--config`, nonempty native or legacy configuration environment
variable, or source-local configuration produces a conflict error. The CLI
never drops that configuration's allowlists or disabled rules to use a pack.
Empty variables, source discovery errors and all invocations without native
flags retain their previous behavior. Custom-base native composition and
arbitrary pack paths are outside this option.

`--enable-rule` selects rules from the full native composition without removing
native predicates. Baselines, ignore files, allow markers, redaction, global
path exclusions, reports and source modes use the normal scan pipeline.
`--complete-profile` remains a separate opt-in selection and can be combined
with native packs. Native pack selection alone does not change source framing,
completion reporting or exit semantics.

Debug diagnostics retain only `builtin_review_reference()`, which contains
versions, ordered builtin IDs and checked content hashes. This reference binds
the full composition, not an `--enable-rule` projection. Reproducible scan
records must also bind the binary, selected rule IDs, scan options and finite
profile. Exact policy bytes and inline configuration do not enter this channel.

## Native byte entropy

A pack loaded through `NativePolicy` can declare:

```toml
entropy = { algorithm = "byte-shannon-f64-v1", reject = "lt", threshold = 3.5 }
```

The table requires exactly `algorithm`, `reject` and `threshold` with these
literal key spellings. Unknown fields, case-colliding aliases, malformed values,
unknown algorithms or comparators, and non-finite or out-of-range thresholds
are rejected. Thresholds are numeric values in `0..=8`. `lt` rejects entropy
below the threshold; `le` also rejects equality. Zero is an active native
threshold. A native predicate requires a content pattern.

`byte-shannon-f64-v1` counts all 256 byte values, including UTF-8 encoding bytes
and invalid UTF-8. It visits nonzero counts in ascending byte order, converts
each count and the total byte length to binary64, divides each count by the
length, and accumulates `entropy - frequency * frequency.log2()` from positive
zero. Empty input has entropy zero. This is a specified floating-point
algorithm, not exact real-number arithmetic. Target-specific `log2` behavior
still requires native validation before claiming cross-platform bit equality.

The predicate runs inside candidate acceptance before finding admission,
materialization and generic suppression. Reports retain the existing explicit
binary64-to-binary32 conversion and contain the entropy used by the predicate.
The fixed histogram occupies `256 * size_of::<usize>()` bytes and adds no
allocation, dependency, I/O or runtime. Cancellation remains cooperative at the
existing candidate boundaries; one entropy calculation is indivisible.

Scalar entropy retains the legacy character-count, reciprocal multiplication,
`<=` rejection and zero-disable behavior. The copied default is unchanged.
A structured entropy table passed to ordinary `ConfigLoader`, `--config`, an
inline configuration variable or an extension fails to decode. Concatenating
native-only TOML into an ordinary configuration is not a supported conversion.

`NativePolicy::compile()` returns the compiled config and exact identity without
building an engine. Typed predicates remain on compiled rules through clones,
selection and engine rebuilding. `CompiledRule::native_entropy()` returns the
algorithm, comparator and threshold; the older scalar `entropy()` accessor is
zero for these rules and is insufficient to describe their policy. Compiling
or using `NativeEngine::engine()` retains detection policy, while native
annotation envelopes remain the responsibility of `NativeEngine`.
