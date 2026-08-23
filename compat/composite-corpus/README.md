# Composite oracle corpus v1

This directory freezes ordinary-Go observations from Gitleaks
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` for required/composite evaluation, generic suppression, and
redaction. The generator invokes a fresh pinned-Go process
for each request, verifies exact request identities and semantic branch
outcomes before writing, and byte-compares fresh results in `--check` mode.

The corpus contains 182 requests, 275
canonical findings, and 1623 required-finding
attachments. `coverage-v1.json` maps all 58 mandatory semantic groups to
exact request IDs and records the material assertion executed for each
reviewed group. Group 12's otherwise unobservable internal stage order is
explicitly classified as source-order-only against the pinned source hash
and lines. Group 22's negative `Fragment.StartLine` is an exact Go-only
domain observation.

## Files

- `requests-v1.jsonl`: versioned detector, redaction, missing-reference, and
  private final-filter probe requests.
- `outcomes-v1.jsonl`: complete canonical findings, ordered required vectors,
  full locations/byte fields, fragments, and redacted outcomes.
- `coverage-v1.json`: behavior IDs, exact upstream identities, mandatory
  groups, material assertions, source/domain classifications, and resource
  contracts.
- `negative-controls-v1.json`: paired same-count substitutions.
- `manifest-v1.json`: pins, counts, and artifact SHA-256 hashes.

Group 58 has three separately bounded requests: the all-present 64-node
chain, a missing-tail counterfactual that still returns `graph-0` with one
`graph-1` attachment, and a closed 64-node cycle. Each pinned-Go child has a
10-second deadline, 4 MiB combined per-stream ceiling, and 1 GiB
`GOMEMLIMIT`; any timeout, overflow, or nonzero exit fails with the request
ID.

## Regeneration

From the Rust repository root:

```sh
cargo xtask generate composite
cargo xtask generate composite --check
```

The generator refuses a changed upstream revision, default-config hash, or
sibling status. Ignore/baseline behavior and report/CLI presentation are
out of scope; the corpus makes no Rust implementation claim.
