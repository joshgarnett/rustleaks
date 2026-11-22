# RAR fixtures

These files are byte-for-byte copies from `ssokolow/rar-test-files` commit
`16b785c2b1b504e99fc307676e5369a26d3ce060`. The archive contents were made
from scratch so that they can be shared freely. The upstream CC0 dedication
is kept as `LICENSE.cc0`.

The archives cover RAR3 and RAR5, one member and two members, and ordinary
and solid compression:

- `testfile.rar3.rar`
- `testfile.rar3.solid.rar`
- `testfile.rar3.cbr`
- `testfile.rar3.solid.cbr`
- `testfile.rar5.rar`
- `testfile.rar5.solid.rar`
- `testfile.rar5.cbr`
- `testfile.rar5.solid.cbr`

The three files under `expected/` are the uncompressed inputs that the
upstream project used to build the archives.

`//crates/rustleaks-sources:rustleaks_sources_archives_unit_test` extracts
each archive and compares the result with `expected/`. The source corpus
(`../../../source-corpus/requests-v1.jsonl`) holds copies of the archives in
its `archive-rar-*` cases, and the archive fuzz seeds use
`testfile.rar3.rar`.
