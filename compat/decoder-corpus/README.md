# Decoder oracle corpus v1

This directory freezes ordinary-Go observations from the pinned Gitleaks
decoder and direct detector at
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. The generator builds the oracle
once and executes one new OS process for every request. `--check` regenerates
all outcomes and byte-compares them with these files.

The corpus contains 263 requests: 204 codec observations and 59 detector
observations. `coverage-v1.json` additionally maps every mandatory audit case
1 through 31 from `M6-DECODER-SEMANTICS-001` to explicit request IDs. The
generator rejects a missing/substituted ID and asserts the important outcome
of every branch matrix before either writing or checking artifacts.

The 54 `TestDecode` nested identities are exactly `TM-0187..TM-0240`.
`TM-0186` is retained in `coverage-v1.json` as their top-level aggregator and
is deliberately not attached to a direct request. Each nested row carries the
original table input plus the exact transformation used by upstream:
`direct`, Go `url.PathEscape`, or Go `hex.EncodeToString`. The oracle verifies
the supplied transformed input itself before decoding it, and the generator
checks the final bytes against that table row's expected value.

`TM-0078` is represented once by `detect-encoded-depth-8`. Its input is
extracted byte-for-byte from the pinned `encodedTestValues` constant, its
configuration is the pinned `testdata/config/encoded.toml`, and the result is a
complete canonical projection of all 20 findings. Separate requests record
the MaxDecodeDepth 0 through 8 boundary counts:
`2, 9, 15, 16, 18, 19, 19, 20, 20`.

## Files

- `requests-v1.jsonl`: versioned codec and detector requests.
- `outcomes-v1.jsonl`: exact pass outputs, complete accepted-segment metadata,
  public range/tag/current-line observations, and canonical findings.
- `request-metadata-v1.jsonl`: identity, behavior, input/config hashes, and
  per-request counts.
- `coverage-v1.json`: authoritative DEC behavior mapping, exact test
  identities, mandatory cases 1..31, aggregator disposition, and decode-depth
  counts.
- `negative-controls-v1.json`: same-count field substitutions whose hashes
  must differ from the originals.
- `manifest-v1.json`: pins, scope exclusions, totals, and file hashes.

Every codec pass records input/output bytes; accepted segment original,
encoded, and decoded half-open ranges; decoded bytes; encoding bitset and
ordered names; depth; all predecessor indexes; aggregate public tags; public
`CurrentLine`; and public `AdjustMatchIndex`/decoded-overlap results for
explicit and automatically generated boundary probes. Per-run and per-pass
cache snapshots expose successful and empty cached values without timing.
A terminal zero-segment pass is retained, so stopping behavior is independently
replayable.

## Behavior categories

- `DEC-001`: iterative passes, termination, and cache reuse/empty caching.
- `DEC-002`: percent candidate grammar and decoding.
- `DEC-003`: Unicode code-point and slash-escape forms.
- `DEC-004`: hex grammar, minimum length, digit heuristic, and decoding.
- `DEC-005`: standard/raw-URL base64 grammar, heuristic, and decoding.
- `DEC-006`: combined-regex precedence and inclusive overlap/touch behavior.
- `DEC-007`: segment shifts, ranges, predecessor chains, and original mapping.
- `DEC-008`: overlap selection, tags, current line, and index adjustment.
- `DEC-009`: malformed, nonprintable, non-ASCII, and arbitrary-byte cases.
- `DEC-010`: detector raw/decode pass scheduling and MaxDecodeDepth boundaries.
- `DEC-011`: decoded finding pipeline: keywords, markers, capture/entropy,
  coordinates, tags, required context, state reuse, and multiplicity.
- `DEC-012`: decoded-pass suppression gates and allowlist targets, including
  current-line positive/negative behavior.
- `DEC-013`: bounded greedy/candidate resource envelopes.

This 13-ID map is authoritative for the decoder corpus. The broader semantics
packet may use finer-grained global rows, but it must map those rows back to
these exact categories and request IDs rather than redefining their meaning.

`DEC-005` includes paired canonical and noncanonical final quanta for both
unused-bit widths (`=` and `==`) and for padded standard and unpadded raw-URL
encodings. The pinned Go decoder accepts non-zero trailing pad bits and returns
the same bytes as the canonical spelling; the generator asserts all four
pairs.

Focused precedence cases also pin three consecutively touching candidates
against the original-neighbor filter, a rejected greedy percent span that
swallows a lower-precedence base64 candidate, and the distinction between
percent-decoded bytes (printability checked) and arbitrary bytes copied inside
that same successful span (unchecked). Base64 controls separately reject
unpadded standard input containing `+`, padded URL-safe input, and mixed
alphabets. A detector row freezes the inclusive-touch repeat guard that emits
both a raw finding and a decoded-tagged finding even though the regex match
itself is unchanged.

The detector matrix separately freezes keywords, original/decoded allow
markers, capture/strict-entropy behavior, secret/match/line allowlist targets,
global and per-pass early gates, rule-tag state reuse, malformed UTF-8 around
all four codecs, and the required-rule context boundary. After M7 integration,
the positive composite and mapped-proximity rows retain exact required vectors
and all 59 detector rows replay in Rust with no deferred exclusions. The
opposite-pass zeros plus inherited decoded `skipReport` and allowlisted controls
continue to guard the decoder/composite boundary.

## Regeneration

From the Rust repository root:

```sh
env GOCACHE=/private/tmp/rustleaks-m7-oracle-gocache \
  GOMODCACHE=/private/tmp/rustleaks-go-mod-cache \
  ruby compat/generate_decoder_corpus.rb --check
```

The generator refuses changed upstream revision, default-config hash, or
sibling status. It excludes Rust implementation claims, session/baseline and
ignore filtering, source adapters, and CLI behavior.
