# Go allowlist corpus

This directory freezes compiled allowlist methods and direct raw-fragment
allowlist behavior from pinned Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`, default-config SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`,
and the ordinary Go standard-regexp build. Generate or verify it with:

```sh
ruby compat/generate_allowlist_corpus.rb
ruby compat/generate_allowlist_corpus.rb --check
```

The generator verifies both pins and the expected read-only sibling status,
runs the Go oracle tests, builds one temporary oracle executable, and launches
a fresh executable process for every request. It then enforces independent
semantic invariants before writing or byte-comparing the artifacts: direct
method decisions and returned match text, validation errors/idempotence and
normalization, all 92 extracted base-allowlist assertions, exact detector
finding counts and selected rule IDs, complete finding schema, all 18 AL IDs,
all nine assigned assertion leaves, all 31 assigned nested detector leaves,
the exact rule IDs/regexes/OR-vs-AND behavior links for the 22 programmatic
detector leaves, and the absence of aggregator IDs from request leaf links.

`--allowlist` protocol inputs use base64 for every arbitrary string/byte field.
Method rows exercise validated and unvalidated `CommitAllowed`, `PathAllowed`,
`RegexAllowed`, and `ContainsStopWord` behavior, including their observable
matched-value returns. Detector rows use ordinary translated configs: inline,
pinned upstream fixtures, or request-contained temporary extension bundles.
They run with decoding and redaction disabled and compare complete canonical
finding multisets while retaining multiplicity.

The corpus covers validation and combined regex construction, empty/nil and
malformed-byte boundaries, Go Unicode lowercase, stopword first-match
selection, OR early versus finding phases, AND over only present categories,
independent table aggregation, global/targeted-global/rule scope, every
normalized/Windows path leaf, secret/match/raw-line targets, path-only bypass,
marker/capture/entropy order, extension append order and targeted-base discard,
upstream allowlist fixtures, and duplicate match preservation.

AL-014 and AL-015 are split across focused evidence: primary/auxiliary
suppression plus the inherited pre-projection bypass are frozen in the
composite corpus, while raw-line and decoded-current-line targeting are
covered by their respective detection corpora. The manifest
excludes positive composite projection,
decoded targeting, and session/source filters.

Files:

- `requests-v1.jsonl`: byte-safe protocol inputs and leaf links;
- `outcomes-v1.jsonl`: canonical pinned-Go observations;
- `request-metadata-v1.jsonl`: hashes, IDs, and finding counts per request;
- `coverage-v1.json`: AL status plus assigned/related leaf and aggregator
  dispositions;
- `manifest-v1.json`: scope, exclusions, totals, and whole-file hashes.
