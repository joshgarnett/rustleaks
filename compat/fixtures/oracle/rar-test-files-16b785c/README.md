# RAR compatibility fixtures

These files are copied byte-for-byte from `ssokolow/rar-test-files` commit
`16b785c2b1b504e99fc307676e5369a26d3ce060`. The archive contents were made
from scratch specifically to be legally redistributable. The upstream CC0
dedication is retained as `LICENSE.cc0`.

The selected matrix distinguishes RAR3 from RAR5, a single member from two
members, and ordinary compression from solid compression:

- `testfile.rar3.rar`
- `testfile.rar3.solid.rar`
- `testfile.rar3.cbr`
- `testfile.rar3.solid.cbr`
- `testfile.rar5.rar`
- `testfile.rar5.solid.rar`
- `testfile.rar5.cbr`
- `testfile.rar5.solid.cbr`

The three files under `expected/` are the exact uncompressed inputs used by
the upstream reproducible build. Archive and expected-content hashes are
frozen by `compat/generate_source_corpus.rb`.
