# Session oracle corpus v1

This corpus freezes pinned Gitleaks `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` session behavior. The generator
runs every one of its 45 requests in a fresh Go child with a
10-second deadline, 4 MiB per-stream output ceiling, 512 MiB Go memory limit,
and explicit input bytes for cross-platform path cases.

`outcomes-v1.jsonl` preserves every Finding field, duplicates, original collection
order, fingerprint mutation, and a separate stable canonical-sort view. Baseline
comparisons mutate each compared and ignored field individually; ignore cases
cover global and commit forms, slash normalization, comments, blanks, malformed
entries, duplicate collapse, and precedence.

Regenerate or verify from the repository root:

```sh
cargo xtask generate session
cargo xtask generate session --check
```

Production safety/unsafe design and Rust implementation claims are outside this packet.
