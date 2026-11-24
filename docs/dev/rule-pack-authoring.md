# Rule pack authoring

This page is for contributors who add or change rules in the native rule
packs, the rule files that hold the Rustleaks rules. Every scan without a
configuration, and every configuration with `[extend] useDefault = true`,
uses all of them. The page covers the pack files, the rules the native loader
enforces, the native-only rule features, and the steps for a change. For what
users see, see [Built-in rules](../user/built-in-rules.md).

## Packs and their files

The packs live in `crates/rustleaks-core/default/` and are built into
`rustleaks-core` as constants in `native.rs`.

| Pack | Rules | Files |
| --- | ---: | --- |
| `rustleaks-extra-v1` | 3 | `.toml`, `.md`, `.sha256` |
| `rustleaks-providers-v1` | 303 | `.toml`, `.md`, `.sha256`, `.provenance.json` |
| `rustleaks-connections-v1` | 19 | `.toml`, `.md`, `.sha256`, `.provenance.json` |

- `<pack>.toml` holds the rules.
- `<pack>.md` describes the pack for users: selection, rules, shared
  boundaries, provenance and license. It ships in the crate package, so a
  link that leaves the crate uses an absolute
  `https://github.com/joshgarnett/rustleaks/blob/main/...` URL. Maintenance
  notes for each pack are in [Notes for each pack](#notes-for-each-pack).
- `<pack>.sha256` is the SHA-256 of the TOML file. It is generated. Never
  edit it by hand.
- `<pack>.provenance.json` records, for each imported rule, the source,
  revision, file hash, original pattern and the changes made.
- `LICENSE.betterleaks`, `LICENSE.kingfisher`, `LICENSE.veles` and `NOTICE`
  keep the license and attribution of imported rules.

Rule counts include hidden helper rules that other rules depend on.

`ConfigLoader` adds every pack to the default rules in `gitleaks.toml`. The
packs do not change that file.

## What the native loader enforces

`native::NativePolicy::builder()` starts from the packaged default rules.
`with_pack(id, toml)` adds one pack, and `build()` creates an immutable
`NativeEngine`. The native loader adds these checks before the normal
configuration loader runs:

- Every rule ID starts with `rustleaks.`. Pack IDs and rule IDs use a
  bounded ASCII grammar.
- Unknown TOML fields are rejected at every table level. Two spellings of one
  field that differ only in case are rejected. Known case-insensitive aliases
  and named-table shorthand still work. Positional table sequences are
  rejected. Error messages do not repeat unknown field names or values.
- A repeated pack ID or any rule ID collision fails with a structured error.
  There is no override: a pack cannot replace or turn off an existing rule.
  A reviewed overlap (see [Same secret from two rules](#same-secret-from-two-rules))
  drops one finding only where another rule reports the same secret.
- `extend`, global allowlists and `minVersion` are rejected inside a pack.
  Rule allowlists and required rules use the normal loader rules.
- A composition holds at most 32 packs, 1 MiB of pack TOML and 1,024 pack
  rules. These limits add to the per-expression compile limits. They are not
  a limit on total compile memory.

The normal loader (`ConfigLoader`, `--config`, configuration variables and
`extend`) rejects the native-only tables described below. It ignores a
top-level `overlaps` key, as it ignores any unknown top-level key, so a
configuration file cannot declare overlaps. Joining native TOML into an
ordinary configuration file is not supported.

## Identity

`NativePolicyIdentity` compares exact, length-framed bytes of the native
policy version, crate version, default rules identity,
enabled annotation extensions, and the ordered pack IDs and TOML sources.
Any byte change, including whitespace or a comment, changes the identity. The
framing is an equality check, not a digest and not authentication.

- A rule file changes in place: edit it, keep its ID and add a changelog
  entry. A change that makes Rustleaks miss a secret it found before needs
  maintainer approval.
- `builtin_review_reference()` returns a reference without the TOML source
  for the default rules alone or for the packaged packs under their fixed IDs.
  It holds versions, the ordered pack IDs and checked content hashes. A
  custom composition returns no builtin reference; the caller must bind its
  own fingerprint to the exact identity.
- `Debug` output of the identity leaves out the configuration.
  `sensitive_exact_bytes()` returns the full pack sources for storage or
  hashing by the caller. Pack sources can contain sensitive literals, so do
  not show these bytes as a public identifier. The type has no automatic
  serialization.
- Source bytes, scan options, budgets, fragment metadata and review decisions
  are not part of the identity. Consumers that cache results must bind them
  separately.

The CLI debug log prints only `builtin_review_reference()`. That reference
covers the full composition, not an `--enable-rule` selection.

## Native-only rule features

These features work only in packs loaded through `NativePolicy`. Rules that
do not use them keep the normal Gitleaks behavior.

### Byte regex dialect

```toml
regex = { dialect = "bytes-v1", pattern = 'a(?s:.{0,2})(X)' }
```

The table needs string `dialect` and `pattern` fields. Unknown dialects or
fields, case-colliding aliases, positional arrays, bad patterns and bad
capture indices fail to compile. A plain string `regex` keeps the Go dialect.

The byte dialect turns off Unicode by default and does not require valid
UTF-8. Alternation is leftmost-first, and empty matches are at byte
positions. Inline flags keep their byte-regex meaning, including explicit
Unicode scopes. Dots, negated classes and repeats consume bytes unless a
Unicode scope changes them. Matching runs on the original buffer, including
malformed UTF-8, with the full anchor and word-boundary context. The source,
nesting, NFA, working-set and cache limits still apply. The Go limit on
nested repeat counts does not apply.

`CompiledRule::regex()` returns the pattern source only. It does not
describe the dialect.

### Keywords in native rules

Rules that use `bytes-v1`, and every root and helper in a `buffer-v1`
relation, keep their keywords as written in the TOML, before Go
normalization:

- An empty keyword list, or an empty keyword, always lets the rule run.
- An ASCII keyword matches raw bytes with ASCII case folding.
- A non-ASCII keyword matches after Rust lowercasing of the whole buffer,
  decoded as lossy UTF-8.

So the ASCII keyword `accesskey` does not match `accessKey` through Unicode
folding, while `Key` matches `KEY`. Keywords that an extending configuration
adds to such a rule follow the same checks, after Go lowercasing. Each
keyword check reads only the buffer that its rule searches. The shared
prefilter still includes these keywords, but native rules do not use its
result. `keywords()` returns the normalized keywords and does not describe
this native behavior.

### Required relations in one buffer

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

- The helper rules must exist in the composition. A rule selection or
  `disabledRules` that leaves out a helper of a reporting rule keeps the
  helper as a rule that does not report. The table needs a content regex,
  at least one edge, unique helper IDs, and exact contract and relation
  names.
- An extending configuration that sets `regex` on the rule removes the
  relation, so the rule becomes a plain rule with the merged keywords.
- `same-candidate` takes no window. The helper must match the same input
  buffer with the same start and end of the whole, untrimmed match. Helpers
  may use different captures of that match.
- `full-match-window` needs `window = "0"` (no line limit) or a positive
  number followed by `L`, without leading zeros. For `NL`, let the primary
  match start on line S and end on line E. A helper qualifies when its match
  starts on a line from `S - (N - 1)` to `E + (N - 1)`. Lines count LF bytes,
  so CRLF is one line break, and a trailing LF moves E.

Each input is its own buffer: the raw fragment, and each decoded segment at
each decode pass. A match cannot combine two decoded carriers, raw and
decoded text, or a decoded value with outer text. An occurrence that is
already in an outer buffer stays eligible at that earlier pass.

Captures come from the real match in the full buffer, including selected
leading or trailing newlines. A capture that does not take part rejects the
candidate; an empty capture that takes part is kept. Public match text still
trims surrounding newlines.

Helpers apply their own keyword, path, entropy and allowlist checks, and may
use `skipReport = true`. Helper dependencies are not evaluated recursively.
The public inherited-fragment flag cannot skip the declared relations.

The window formula follows the Kingfisher context API without options. It
does not claim to match Kingfisher's CLI or SDK association.

### Byte entropy

```toml
entropy = { algorithm = "byte-shannon-f64-v1", reject = "lt", threshold = 3.5 }
```

- The table needs exactly `algorithm`, `reject` and `threshold`, spelled this
  way. Thresholds are numbers from 0 to 8. `lt` rejects entropy below the
  threshold; `le` also rejects equality. Zero is an active threshold. The
  rule needs a content pattern.
- `byte-shannon-f64-v1` counts all 256 byte values, including UTF-8 and
  invalid bytes. It visits nonzero counts in ascending byte order, converts
  each count and the total length to binary64, and adds
  `-frequency * frequency.log2()` starting from positive zero. Empty input
  has entropy zero. Bit equality across platforms needs native evidence for
  each target, because `log2` can differ.
- The check runs before a finding is admitted. Reports keep the existing
  conversion to binary32.
- `CompiledRule::native_entropy()` returns the table. The older `entropy()`
  accessor returns zero for these rules.

Scalar `entropy = 3.5` keeps the Gitleaks behavior: character counts and `<=`
rejection, with zero meaning off.

### Secret predicates

A rule with a `bytes-v1` regex can add one `predicate` table. Predicates run
after entropy and before finding allowlists. They never change finding bytes,
spans, tags or decode depth. The exact table bytes are part of the identity,
and `native_predicate_algorithm()` names the active algorithm.

The Mapbox segment predicate:

```toml
predicate = { algorithm = "base64url-segment-go-regex-v1", parts = 3, separator = ".", segment = 1, encodedMin = 23, encodedMax = 308, decodedMax = 231, regex = '''^\{"u":"[^"\\\x00-\x1f]+"\s*,\s*"a"\s*:\s*"[A-Za-z0-9]+"\s*\}$''' }
```

- Version one needs exactly three parts split by an ASCII dot and selects
  segment one (counting from zero). Bounds are positive with
  `encodedMin <= encodedMax <= 308` and `decodedMax <= 231`. The whole secret
  is limited to 926 bytes.
- The segment must be unpadded base64url; a length that leaves a remainder
  of one when divided by four is rejected. Nonzero unused pad bits are
  accepted, as in the source.
- The decoded bytes must be valid UTF-8 and match the whole Go pattern.
- Bad encoding, invalid UTF-8 or a bound violation rejects the candidate, and
  scanning continues. Kingfisher returns an error for invalid decoded UTF-8;
  this is a documented difference in error handling.

The Vercel predicate has no settings:

```toml
predicate = { algorithm = "vercel-cl100k-ratio-v1" }
```

It accepts only a 60-byte ASCII capture of the form
`[vV][cC][kK]_[A-Za-z0-9_-]{56}`, counts cl100k tokens, and accepts counts
above 24. This is the source condition `60 / token_count < 2.5`. The token
data, its sources, licenses and generator are described in the
[tokenizer data README](../../crates/rustleaks-core/data/README.md).

### Same secret from two rules

A pack can list rule pairs that report the same secret:

```toml
[[overlaps]]
description = "A WorkOS key also fits the Stripe pattern"
keep = "rustleaks.workos-production-api-key"
drop = "stripe-access-token"
```

When both rules report the same file, commit, secret and exact secret range,
the `drop` finding is removed and the `keep` finding is reported. The filter
runs on the findings of one scanned fragment, after allowlists and before
redaction, with the generic filter. A finding without an exact secret range,
such as one from decoded text, is never removed.

- `keep` and `drop` are rule IDs, and `description` is optional. Other fields
  are rejected. A rule with `generic` in its ID (ASCII case-insensitive)
  cannot be in an overlap, because the generic filter could remove the kept
  finding.
- At least one of the two rules is in the same pack. The other can be a
  default rule or a rule of another pack.
- At build time both rules must exist and report findings (no
  `skipReport`). A pair is listed once in a composition, and no rule is both
  a `keep` and a `drop`, so every removed finding has a reported finding with
  the same secret.
- A rule selection keeps an overlap only when both rules are selected.
  `disabledRules` removes the rule and its overlaps, also when the extending
  configuration defines a rule with the same ID.
- A cancelled scan returns only the findings decided so far. A removed
  finding whose kept finding is not among them stays in the result.

Add a pair only when both rules can report the same credential and one of
them names it better, or both name the same provider. When both name the same
provider, keep the default rule, so its ID and fingerprints stay. Do not add
a pair when the secrets differ, such as a prefix of a longer token. Keep
`INTENDED_REPLACEMENTS` in `tests/rule_precedence.rs` and the table in
[Built-in rules](../user/built-in-rules.md#findings-from-two-rules) equal to
the pack entries, and add a case to `tests/rule_overlaps.rs`.

## Ordering and partial results

A composition keeps the engine's rule order (sorted by rule ID), match order,
generic and overlap filtering, redaction, exact raw spans and decoded-source
mapping. Pack IDs cannot collide, but two rules can report the same
occurrence. Only the generic filter and the reviewed overlaps above remove
such findings.

`scan()` on `NativeEngine` returns a `NativeScanOutcome` with the normal
`ScanOutcome`, the policy identity and optional explanation records. The
envelope keeps the actual options and budget. A stopped scan stays partial
and returns only findings from rules that finished. The per-target byte limit
skips a rule; it does not end the scan.

## Explanations and annotations

`ExplanationOptions::disabled()` stores nothing and runs no offline checks.
`bounded(n)` keeps at most `min(n, 65_536)` records. When that is full, or
an allocation fails, the log is marked truncated and stops growing; detection
continues. Records hold only numeric ordinals and fixed decision codes, never
rule text, source bytes, paths or provider responses. Ordinals are local to
one scan and are not stable review keys. Counts still reveal scan activity.

The only annotation is the GitHub classic token (`ghp_`) layout check. It
only annotates; it never removes a finding.

- Layout: a 40-byte value with the `ghp_` prefix and 36 ASCII alphanumeric
  bytes is `Valid`. The same prefix and length with another byte is
  `Invalid`. Other lengths and prefixes, including `github_pat_`, are
  `Unknown`. A prefix captured from a longer token is `Unknown` with
  `AmbiguousBoundary`.
- Checksum: GitHub states that `ghp_` tokens end with a CRC32 checksum in six
  Base62 characters. It does not publish the checksum input, the CRC32
  variant or the Base62 alphabet order. A guess could mark real tokens
  invalid, so the engine computes no checksum. The result is `Unknown` with
  `UnspecifiedChecksumContract`, or `UnsupportedFormat` for other values.
  Adding a checksum needs an issuer specification or reviewed issuer test
  vectors that settle all three parameters.

Rustleaks does not check whether a credential is live, does not revoke
credentials, loads no runtime plugins and uses no learned filters. Adding
any of these needs a concrete user need and a reviewed safety design.

## Changing a pack

### Choose where the rule goes

- Use `rustleaks-providers-v1` for provider API keys and tokens,
  `rustleaks-connections-v1` for passwords in connection strings and URLs,
  and `rustleaks-extra-v1` for the small first-party set.
- Changes to the shipped default rules
  (`crates/rustleaks-core/default/gitleaks.toml`) follow [A detection
  rule](architecture.md#a-detection-rule). Do not edit
  `testdata/config-corpus/default-gitleaks.toml`, which is test input for the
  configuration cases.

### Imported rules

Rules adapted from another scanner must:

- pin the source revision and the SHA-256 of the source file;
- record the license and attribution for each file, and keep the license text
  next to the pack;
- record the original pattern, the source tests, every change made, and any
  source behavior that the rule does not support; and
- be rejected when Rustleaks cannot express the relevant behavior without
  leaving something out.

### Generated parts of the provider and connection packs

The provider and connection TOML files have two parts:

1. The rules before the line
   `# Maintained additional coverage; generated by xtask generate native-pack-identity.`
   Their bytes and provenance are bound by hash in
   `crates/xtask/src/tooling/native_coverage/reviewed.json`. Do not edit them.
2. The rules after that line. They are copied from
   `crates/xtask/src/tooling/native_coverage/providers.toml` or
   `connections.toml`.

To add or change a rule in the generated part:

1. Edit the rule in `native_coverage/providers.toml` or `connections.toml`.
2. Add or update its record in `native_coverage/reviewed.json`. The `native`
   object must equal the TOML rule, and `origin` holds the source details.
3. Regenerate the pack, its provenance and the identity:

   ```sh
   cargo xtask generate native-pack-identity
   ```

4. Check that the committed files match:

   ```sh
   cargo xtask generate native-pack-identity --check
   ```

The generator also checks the tokenizer data, the provider provenance
against the source revision and `LICENSE.betterleaks`, and the connection
inventory. It never downloads or runs upstream code.

For `rustleaks-extra-v1`, edit the TOML file and then run the same generator
to update `rustleaks-extra-v1.sha256`.

### Tests

Write synthetic positive cases, near misses, entropy boundaries, exact
locations, ASCII and Unicode differences, invalid bytes, allowlist cases and
overlap with the default rules. Write the expected findings by hand.

| Test file in `crates/rustleaks-core/tests/` | Covers |
| --- | --- |
| `native_rules.rs` | `rustleaks-extra-v1` |
| `provider_rules.rs` | `rustleaks-providers-v1` |
| `connection_rules.rs` | `rustleaks-connections-v1` |
| `additional_coverage.rs`, `format_coverage.rs`, `special_coverage.rs`, `association_coverage.rs`, `remaining_verified_rules.rs` | The generated provider and connection additions, with expectations in `tests/support/*.json` |
| `shared_rule_deltas.rs`, `contextual_rule_deltas.rs` | Delimiter companion rules in the provider pack |
| `native_policy.rs`, `native_predicates.rs` | The native loader, identity, entropy and predicates |
| `rule_overlaps.rs` | `[[overlaps]]` checks, the overlap filter and each reviewed pair |

Run the narrow target first:

```sh
bazelisk test //crates/rustleaks-core:provider_rules_test
bazelisk test //crates/rustleaks-core:connection_rules_test
```

A new test file must be registered. See
[Testing](testing.md#adding-a-test).

### Quality corpus

The synthetic quality corpus in `testdata/quality-corpus/` compares the
default rules with `rustleaks-extra-v1`. Its labels are written
independently of detector output. Regenerate and check it with:

```sh
bazelisk run //crates/rustleaks-compat:rustleaks_quality -- generate
bazelisk run //crates/rustleaks-compat:rustleaks_quality -- baseline
just quality-eval
```

Never change a label to improve a detector result. See the
[quality corpus README](../../testdata/quality-corpus/README.md).

### Notes for each pack

These notes add to the steps above.

#### rustleaks-extra-v1

- Tests: `native_rules.rs`, with the native loader and identity in
  `native_policy.rs`.
- Edit `rustleaks-extra-v1.toml` by hand, then regenerate the `.sha256`
  identity with the generator. Never edit the digest by hand. The build
  checks that it matches the TOML bytes.
- A refresh needs a review of provider format changes, new independent test
  cases and a new run of the quality comparison. Nothing is downloaded.
- Quality evaluation: the [quality
  corpus](../../testdata/quality-corpus/README.md) compares the default rules
  with and without this pack on the same inputs. It has Azure field orders,
  repeats, invalid bytes, percent-encoded wrappers, MongoDB percent-encoded
  user information, short passwords, templates and near misses. Sovereign
  Azure endpoints and MongoDB IPv6 inputs are positive gap cases, not
  negative examples.
- The pack is accepted only when the comparison shows no lost held-out
  positives, no new alerts on reviewed negatives and no unreviewed duplicate
  alerts. The one reviewed duplicate is the `mongodb-provider-overlap` case,
  where a synthetic MongoDB password has the shape of a GitHub token. These
  cases are small structural controls, not a measure of accuracy on real
  data.
- Run `just quality-eval` for the current counts. A change must cite that
  report and its source and configuration identity. A report that runs
  successfully is not by itself an acceptance decision.

#### rustleaks-providers-v1

- Tests: `provider_rules.rs` covers the rules before the generated part, and
  the Alibaba, Slack access and xAI supplements. The other files are in the
  table under [Tests](#tests).
- The tests use synthetic positives, near misses, entropy boundaries, exact
  locations, ASCII and Unicode differences, invalid bytes, allowlists, old
  and new format unions, generic overlap, identity and scan budgets. Some
  tests compare with fixed smaller rule compositions and check that existing
  specific findings stay. Fixtures are written by hand and never sent to a
  provider. The tests are a regression contract, not a measure of accuracy
  on real data.
- All 3 packs with the default rules give 547 rules, including 32 hidden
  helpers.
- The build checks both pack digests and that the provider provenance is
  consistent. Nothing is downloaded at build or run time.
- A refresh needs a review of source changes, exact provenance and license
  bytes, and an evaluation of changed predicates and overlaps.

#### rustleaks-connections-v1

- Tests: `connection_rules.rs` covers the 6 connection string forms, the
  libpq forms, the password-first, Oracle, SQLite and added URI scheme
  forms, and quoted and braced controls. It also checks exact
  locations, bounds, ASCII and Unicode differences, stopwords and findings
  on the same line. Other cases cover adjacent connections, host-key
  boundaries, allowlists, generic and provider overlap, composition
  identity, decoding and scan budgets. The generated rules are also covered
  by the coverage tests in the table under [Tests](#tests). These synthetic
  tests are a regression contract, not a measure of accuracy on real data.
- The generator checks the reviewed inventory and provenance before it
  writes the hash. Check mode rejects changed patterns, missing predicates,
  added rule fields, changed identities and license changes.
- A change needs a source review, new independent expected results and a
  versioned policy decision.

### Documentation and review

- Update the pack's `.md` file, the rule counts in this page and the user
  [built-in rules guide](../user/built-in-rules.md) when its description
  changes.
- Run `just ci`. Run `just fuzz-smoke` when you change regex, decoder or
  predicate code.
- In the pull request, list the rule IDs, the source and license, the
  positive and negative cases, the overlap with existing rules, and the
  commands you ran.
