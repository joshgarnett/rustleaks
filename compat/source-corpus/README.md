# Source oracle corpus v1

This corpus freezes reader, file, directory, symlink, and archive behavior from
pinned Gitleaks `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. Each of its 124 requests runs in a
fresh Go child with a 15-second deadline, an 8 MiB per-stream ceiling, a 512 MiB
Go memory limit, and at most two Go scheduler threads.

Byte-bearing fragment and finding fields are base64 encoded. Both emission-order
and canonical fragment views preserve duplicates; `bytes_nil` distinguishes nil
from empty byte slices. Archive requests use provenance-tracked copies under
`compat/fixtures/upstream`, whose hashes are frozen in `coverage-v1.json`.
`coverage-v1.json` embeds the authoritative definition for every `SRC-001`
through `SRC-030`, material assertions aligned to those definitions, and an
explicit per-ID gap list for unresolved behavior that still needs separately
controlled evidence.

Regenerate or verify from the repository root:

```sh
cargo xtask generate source
cargo xtask generate source --check
```

Outcomes record the generating GOOS/GOARCH. Native Linux and Windows workflows
replay the pinned source oracle and target-specific Bazel tests; the Windows
suite directly checks raw and slash-normalized path matching. The payload-free
`native-windows-v1.json` ledger binds complete x64 and ARM64 observations by
raw and platform-neutral SHA-256 values while listing every semantic and
structural difference from the committed Darwin baseline. The pinned Go oracle
cannot produce Unix-equivalent followed-symlink observations on Windows, so
the ledger records target-only or empty results as an unavailable dimension,
not as fabricated equality. Each successful Windows replay also publishes a
payload-free per-record hash ledger for review.
