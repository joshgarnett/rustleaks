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
explicit per-ID gap list where native or Rust implementation evidence is still
mandatory.

Regenerate or verify from the repository root:

```sh
ruby compat/generate_source_corpus.rb
ruby compat/generate_source_corpus.rb --check
```

Outcomes record the generating GOOS/GOARCH. Windows symlink behavior and native
separator metadata require native Windows CI confirmation rather than emulation.
