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
`native::CONNECTION_RULES_V1` exposes the focused connection-credential pack.
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

## Buffer-local required relations

Native packs can explicitly select a separate required-rule contract:

```toml
[[rules]]
id = "rustleaks.example-parent"
regex = 'pair=([A-Z]{4})'
[rules.required]
contract = "buffer-v1"
edges = [
  { id = "rustleaks.example-predicate", relation = "same-candidate" },
  { id = "rustleaks.example-context", relation = "full-match-window", window = "5L" },
]
```

The referenced helper rules must also exist in the compiled selection. This
form requires a content regex, at least one edge, unique helper IDs, and exact
contract and relation tags. Unknown fields, duplicate case-insensitive field
spellings, and malformed windows fail native validation. `same-candidate`
forbids a window. `full-match-window` requires either `"0"` for unlimited or a
positive decimal integer followed by `L`, without leading zeros. The native
loader validates and transforms this table before attaching private metadata.
The ordinary loader's permissive raw parser may accept the table, but ordinary
compilation rejects its missing legacy required-rule ID. Native metadata
survives cloning, rule selection, and rebuilding an `Engine`; exact original
pack bytes remain in policy identity.

The raw fragment is one input buffer. At each decode pass, each newly accepted
decoded segment is a distinct buffer, including nested siblings whose public
source locations cover the same outer carrier. Rules and their helpers search
that buffer independently, preserving anchors, word boundaries, nonoverlapping
match enumeration, and buffer-local keyword admission. Matches cannot combine
separate decoded carriers, raw and decoded text, or a newly decoded leaf with
unchanged outer text. An occurrence already present in an earlier outer buffer
remains eligible at that earlier pass.

`same-candidate` requires identical input identity and both endpoints of the
untrimmed whole regex match. Helpers may select different captures from that
same whole occurrence. `full-match-window` also requires the same input. For
`NL`, let the primary full match start on line S and its exclusive end lie on
line E. A helper qualifies when its full-match start line is between
`S - (N - 1)` and `E + (N - 1)`, inclusive, with saturating bounds. A trailing
LF therefore advances E. Lines count LF bytes, so CRLF has one line break.
Capture locations and reported original-source locations do not define this
relation. `"0"` removes the line bound while retaining input isolation.

This association formula targets Kingfisher's no-options context API contract.
It does not claim equivalence to its CLI or ordinary SDK association routes.
Rustleaks applies the same buffer isolation to its accepted percent, hex, and
Unicode segments as well as Base64; those extra transforms and Rustleaks decoder
discovery and depth behavior are separate from the inspected Kingfisher context
implementation's standalone ASCII Base64 buffers.

Native captures come from the actual match in the full input buffer, including
leading or trailing newlines in a selected capture. An explicit nonparticipating
capture rejects the candidate; a participating zero-width capture is retained.
This avoids the legacy trimmed-match capture fallback. Public match text still
trims surrounding newlines. Raw match and secret ranges independently identify
the bytes actually reported; decoded exact source ranges remain unavailable.
Existing source locations, tags, original source line, allowlist ordering,
redaction and nested-report projection retain their existing representation.
The compatibility allowlist line target still uses the existing source/decoded
line projection. Its scope is distinct from the association coordinate buffer.

The enclosing contract applies to the primary and its helper evaluations.
Helpers obey their own keyword, path, entropy and allowlist predicates, and may
use `skipReport = true`. Helper dependencies are not recursively evaluated.
A caller's public inherited-fragment flag cannot bypass the primary's declared
relations. Legacy string patterns and required arrays without this table continue
using the existing detector, proximity semantics and accounting. A `bytes-v1`
rule also uses owning input buffers without requiring a relation table.

## Native byte regex and keyword semantics

Native packs may use an explicit content dialect:

```toml
regex = { dialect = "bytes-v1", pattern = 'a(?s:.{0,2})(X)' }
```

The table requires string `dialect` and `pattern` fields. Unknown dialects,
unknown fields, case-colliding field aliases, positional arrays, malformed
patterns and invalid capture indices fail compilation. Ordinary `ConfigLoader`
rejects the table, including through extensions. A string `regex` keeps its Go
dialect. The original typed TOML remains in policy identity; the inspectable
`CompiledRule::regex()` accessor returns pattern source, not a complete dialect
or policy description.

The byte dialect uses the existing backend with Unicode disabled by default,
UTF-8 validity disabled, leftmost-first alternatives and byte-position empty
matches. Inline flags retain their byte-regex meanings, including explicit
Unicode scopes. Dots, negated classes and quantifiers consume bytes unless a
source Unicode scope changes them. Matches and captures search the original
owning buffer, including malformed UTF-8, with full anchor and boundary context.
No rune approximation, ASCII-only bridge or post-match byte filter is used.
Compilation shares the existing source, nesting, NFA, working-set and cache
ceilings. Go's separate repetition cap does not apply to this dialect.

Rules with `bytes-v1`, and all roots and helpers participating in `buffer-v1`,
retain keyword classification from the original configuration before Go
normalization. Empty keyword lists and empty keywords open the gate. An original
ASCII keyword compares raw byte windows with ASCII case insensitivity. An
original non-ASCII keyword compares Rust whole-string lowercase after lossy
UTF-8 decoding, even if its lowercase spelling is ASCII. This distinction keeps
ASCII `accesskey` from matching `accessKey`, while original `Key` can match `KEY`.
Each gate reads only the same owning buffer as its expression and helpers.
The shared compatibility prefilter still includes native rule keywords and may
allocate a full lowercase input view before native dispatch, including in a
byte-only selection. Native keyword decisions do not use that prefilter's
matches; an ASCII native gate itself borrows raw bytes.
The compatibility-normalized `keywords()` accessor remains unchanged; it does
not describe this private native classification. Metadata survives cloning,
selection and direct compiled-engine construction. Old native packs without
these explicit contracts and the pinned default retain their existing gates.

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
300 rule definitions, including hidden association helpers, and requires native
loading; ordinary configuration loading rejects its structured entropy values.
Forty contextual and four residual companions preserve source context, capture
and path requirements while adding reviewed VT and escaped-quote occurrences.
Public Lob and Mailgun roles remain
excluded. The xAI rule selects the Apache
80-byte body expression, not
the broader overlapping MIT rule. Slack cookies have an unbounded body and
remain subject to caller-selected input and finding-payload limits.
Its [pack contract and provenance](../crates/rustleaks-core/default/rustleaks-providers-v1.md)
record the source scopes, ASCII translation, entropy rules and policy
differences. Provider attribution can replace a generic finding for the same
occurrence through existing overlap filtering; this is not an extra recovered
secret. The separate `rustleaks-connections-v1` pack contains 14 rule
definitions: ten password rules, three complete Git credential URL rules and
one hidden tuple-predicate helper. Its
[contract](../crates/rustleaks-core/default/rustleaks-connections-v1.md)
records source predicates, extraction, byte limits and enumeration gaps;
general URI and Unicode-equivalent detection are outside that pack. Libpq
keyword passwords have a bounded ASCII subset with host context.
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

## Bounded native secret predicates

A native rule can add one `predicate` table alongside its typed `bytes-v1`
regex. The ordinary loader rejects the typed regex; it cannot silently discard
the predicate from a valid native configuration. Unknown fields, case-colliding
aliases, wrong types, unsupported algorithms, empty outer patterns, invalid
bounds and invalid decoded patterns fail native configuration loading. Exact
descriptor bytes participate in policy identity. Compiled metadata survives
cloning, selection and engine rebuilding; `native_predicate_algorithm()`
identifies the active algorithm. Existing scalar and byte entropy run first,
followed by the predicate and existing finding allowlists.

The bounded segment decoder has this source-specific Mapbox configuration:

```toml
predicate = { algorithm = "base64url-segment-go-regex-v1", parts = 3, separator = ".", segment = 1, encodedMin = 23, encodedMax = 308, decodedMax = 231, regex = '''^\{"u":"[^"\\\x00-\x1f]+"\s*,\s*"a"\s*:\s*"[A-Za-z0-9]+"\s*\}$''' }
```

Version one requires exactly three parts separated by ASCII dot and selects
zero-based segment one. Bounds are positive integers with
`encodedMin <= encodedMax <= 308` and `decodedMax <= 231`. The full selected
secret is capped at 926 bytes to bound structural scanning in custom packs.
The Mapbox source's maximum secret fits this cap. Only unpadded base64url
alphabet bytes are accepted, with modulo-four length one rejected. Translation
and canonical padding use a fixed 308-byte buffer; decode uses a fixed
231-byte buffer and accepts nonzero unused pad bits as the source does.

Decoded bytes must be valid UTF-8 and match the entire configured Go pattern.
The matcher adds absolute whole-payload anchors and uses existing regex caps
and controlled normalization. The displayed source pattern preserves field
order, nonempty user and authorization fields, the prohibition on escaped or
control bytes in the user, and Go ASCII whitespace excluding vertical tab.
Malformed encoding, invalid UTF-8 or bound violations reject that candidate
and scanning continues. Pinned Kingfisher propagates invalid decoded UTF-8 as
an error; local reject-and-continue is an explicit native error-handling
difference. It does not claim source error parity or relax accepted payloads.

The fixed Vercel predicate has no configurable thresholds or vocabulary:

```toml
predicate = { algorithm = "vercel-cl100k-ratio-v1" }
```

It accepts only the complete 60-byte ASCII capture language
`[vV][cC][kK]_[A-Za-z0-9_-]{56}`, counts ordinary cl100k tokens, and accepts
counts above 24. This is exactly the source's `60 / token_count < 2.5`
condition; entropy and inherited source filters remain separate. The complete
bounded lookup data, source identities, license chain, reduction and generator
are documented with the [tokenizer assets](../crates/rustleaks-core/data/README.md).
It performs no special-token or dictionary processing.

Predicate transforms never change finding bytes, spans, tags, decoder depth
or decoded-byte usage. Work and cancellation checkpoints precede bounded
decode and decoded matching, and Vercel domain, piece and merge work. A stopped
predicate propagates the existing typed partial outcome and does not admit
unfinished-rule findings. Explanation reasons distinguish predicate acceptance
and rejection without retaining source or decoded bytes.
