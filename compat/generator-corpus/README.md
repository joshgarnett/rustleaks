# Pinned generator validation corpus

This directory freezes the sample validations embedded in the Gitleaks default
rule constructors at upstream commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. The upstream project is MIT
licensed. These files are compatibility evidence for the Rust port; they are
not production secrets.

## Files

- `constructors-v1.jsonl` contains all 225 exported zero-argument rule
  constructors. It distinguishes the 222 selected defaults, the 220 selected
  constructors with helper validation, the two selected Dropbox validation
  gaps, and the three upstream default exclusions.
- `samples-v1.jsonl` contains exactly 6,770 helper cases from one reviewed
  concrete run: 6,368 ordinary positives, 342 ordinary negatives, 28 path
  positives, and 32 path negatives. Duplicate cases remain separate rows.
- `cargo xtask generate generator-samples` verifies or deliberately
  regenerates the files without writing to the sibling Go checkout.

Frozen SHA-256 digests:

```text
b7f69ca6317157c7ca8015ec897ec82371e6e362067c6c799c61f0c4819cd7c1  constructors-v1.jsonl
b0d1e24c04f88ec3c875bcbd08a6e0cafbabd7f7cf8757af5e385eb83259b750  samples-v1.jsonl
```

## Provenance and extraction

The extractor first verifies the sibling `../gitleaks` HEAD and the pinned
`config/gitleaks.toml` digest. It rejects tracked changes under
`cmd/generate` or to that config. It then uses `git archive` to create a
temporary copy. Only the temporary copy is instrumented.

The observer calls the original single-rule detector and records each helper
result immediately before the original assertion. It makes the two otherwise
nondeterministic source containers deterministic for identity assignment:

- the 26 `GenerateSampleSecrets` map templates are traversed by sorted template
  key; and
- path maps are traversed by sorted raw path string.

This changes ordering only. The generated default config must still have the
pinned SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`,
and all original helper assertions must pass.

Upstream `secrets.NewSecret` is intentionally random. The extractor replaces
its private temporary-archive copy with a stable regex-derived FNV-1a reggen
seed before executing helper assertions. It evaluates a fixed 128-candidate
sequence and selects the least concentrated byte distribution, with lexical
tie-breaking. This keeps fresh release checks reproducible and prevents a rare
low-entropy random positive from failing its own upstream threshold. The
generated default config must remain byte-identical and every original helper
assertion still runs. The checked-in sample file was frozen from an earlier
random run; its observation bytes may differ from the deterministic replay
while stable recipe identities must match exactly.

## Schema and identity

Every byte-bearing input, path, match, secret, and keyword is standard base64.
`path_present` plus nullable `path_base64` distinguishes an absent path from a
present empty path. Empty content remains an empty base64 string.

A sample identity is derived from constructor, polarity, and a deterministic
ordinal within the helper source occurrence. It does not contain random secret
bytes or Go map iteration order. Each row also records:

- constructor/RuleID/helper and source file, constructor line, helper line,
  source occurrence, and constructor source digest;
- origin kind, origin call site, and template key when a shared sample template
  generated the case;
- duplicate ordinal for the frozen observed `(RuleID, polarity, path, input)`
  tuple;
- entropy, normalized keyword bytes, rule allowlist count, path presence,
  secret group, and global-allowlist dependency; and
- the upstream helper contract separately from the Go oracle observation.

Ordinary positives have the upstream contract `at_least_one`; path positives
have `exactly_one`; all negatives have `zero`. `oracle_observed_count` and the
base64 finding fields are observations from the frozen run, not stronger
claims about the ordinary helper.

The two Dropbox gaps and three exclusions are records in
`constructors-v1.jsonl`, not synthetic passing sample cases:

- `DropBoxLongLivedAPIToken` and `DropBoxShortLivedAPIToken` are selected but
  return without a validation helper.
- `GCPServiceAccount`, `SquareSecret`, and `TrelloAccessToken` are omitted from
  the default generator. The first has a known failing helper; the latter two
  pass when invoked independently at the pin.

## Verification and regeneration

From the `rustleaks` root:

```sh
cargo xtask generate generator-samples --check
```

`--check` validates the frozen file digests, JSONL schema, canonical base64,
identity uniqueness/digests, contiguous source ordinals, helper contracts,
finding counts, duplicate ordinals, exact totals, the 225/222/220 constructor
reconciliation, and the explicit gaps/exclusions. It performs a fresh
temporary extraction with deterministic private secret generation and compares
only stable recipe identities to the frozen rows. A built-in same-count
identity-substitution negative self-test must fail for the check to pass.

`cargo xtask generator-check` also runs
`crates/rustleaks-core/tests/default_rule_corpus.rs`. That test loads the
packaged default configuration, projects each of the 220 helper-covered rules,
and compares all 6,770 Rust outcomes with the pinned oracle observations. It
checks rule IDs, matched bytes, secret bytes, path behavior, duplicates, and
the positive or negative count contract.

Deliberate regeneration is:

```sh
cargo xtask generate generator-samples
```

This overwrites the two versioned JSONL files with a newly observed run and
prints their new digests. Fresh secret and finding bytes may vary, as they did
under the legacy generator; the ordered stable recipe identities must remain
exact. Review the observation diff and update the two digest constants in the
Rust generator and this README. Until that review step, `--check` fails closed.
