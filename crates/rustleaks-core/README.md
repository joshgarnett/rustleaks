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
frontend and a private pooled meta engine with downstream-compatible `regex-automata`
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
decoded-byte, work-unit, finding-record, finding-payload, collected-span and
normalization budgets. These are logical counters, not a process heap quota.
The ordinary
`scan_fragment` method remains the unlimited, never-cancelled compatibility
wrapper. Partial outcomes carry structured termination and usage, and never
include candidates from an unfinished top-level rule.

Finding match and secret mappings are exact half-open ranges into the original
fragment when no transform intervenes. Decoded, path-only, nonparticipating,
and otherwise inexact mappings are explicitly unavailable and must not be
approximated for rewriting.

The packaged default configuration and the optional native rule packs are in
`default/`. Counts are `[[rules]]` definitions, including hidden helpers, not
distinct secret families. The native packs are opt-in and add to the default
configuration.

| Pack | Constant | Rules | Contract |
| --- | --- | ---: | --- |
| Pinned Gitleaks default (`gitleaks.toml`) | `config::DEFAULT_CONFIG` | 222 | [`COMPATIBILITY.md`](https://github.com/joshgarnett/rustleaks/blob/main/docs/COMPATIBILITY.md) |
| `rustleaks-extra-v1` | `native::EXTRA_RULES_V1` | 3 | [`default/rustleaks-extra-v1.md`](default/rustleaks-extra-v1.md) |
| `rustleaks-providers-v1` | `native::PROVIDER_RULES_V1` | 300 | [`default/rustleaks-providers-v1.md`](default/rustleaks-providers-v1.md) |
| `rustleaks-connections-v1` | `native::CONNECTION_RULES_V1` | 14 | [`default/rustleaks-connections-v1.md`](default/rustleaks-connections-v1.md) |

`rustleaks-extra-v1` adds Azure Service Bus or Event Hubs, Azure App
Configuration and MongoDB URI password rules.

Optional provider rules are selected through
`NativePolicy::builder().with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)`.
The namespaced pack adds Groq, Cerebras, Replicate and NVIDIA detector shapes,
plus selected Anthropic, DigitalOcean, OpenAI and Fly.io format or delimiter
coverage, and Cloudsmith, MiniMax, PostHog personal, Figma, Together and Google
Gemini candidate formats. Nine contextual provider formats, two Slack session
formats and four finite Veles formats are also included. Six additional Docker
Hub, Neon, Render, Deno user and Apify rules use explicit native byte entropy.
Twenty-four shared-prefix companions add escaped-quote and vertical-tab
endings with explicit byte entropy and independently scoped source exclusions.
Forty contextual companions cover terminal and assignment-VT gaps, and four
residual companions cover Anthropic, DigitalOcean refresh and old OpenAI endings.
The complete pack requires `NativePolicy` or the CLI selector
`--native-pack rustleaks-providers-v1`; ordinary config loading rejects its
structured entropy values. It can be composed with `rustleaks-extra-v1`; exact
pack bytes and order participate in policy identity. See
[`default/rustleaks-providers-v1.md`](default/rustleaks-providers-v1.md) for
format limits, source-policy differences and the absence of live validation.

`CONNECTION_RULES_V1` exposes the separate `rustleaks-connections-v1` pack with
14 rule definitions: ten password rules, three complete Git credential URL
rules and one hidden tuple-predicate helper. Its
[contract](default/rustleaks-connections-v1.md) specifies capture, placeholder,
byte-bound and enumeration behavior. It does not add a general connection
parser or Unicode-equivalent Kingfisher policy.

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
The optional provider pack retains pinned Betterleaks MIT and Veles Apache-2.0
source terms. The optional connection pack retains Kingfisher Apache-2.0 and
Betterleaks MIT terms. Their exact licenses, [additional notice](default/NOTICE), and
transformation provenance are included in `default/`.
The safe Rust Eisel-Lemire conversion routine, its detailed powers-of-ten
table, and the generated Go Unicode 15.0.0 simple-lowercase ranges retain the
Go Authors' BSD terms. See `LICENSE` and `NOTICE`, both included in the crate
package.
