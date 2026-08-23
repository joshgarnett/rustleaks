# Pinned upstream fixtures

`upstream/testdata/` is an independent copy of the Gitleaks test fixtures at
commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. The files retain their MIT
provenance, paths, bytes, executable modes, and the repository's one symlink.

Run `cargo xtask fixture-check` with the pinned sibling Go checkout present to
verify the complete path set, all 214 regular-file hashes and sizes, executable
modes, the symlink target, and the aggregate record digest. Mutable source and
Git tests must work on temporary copies of these fixtures.

`oracle/bodgit-sevenzip-v1.6.1/` contains the additional 7z method fixtures
from the exact `github.com/bodgit/sevenzip` version selected by that pinned Go
checkout. Their hashes are frozen in the source corpus and their separate
BSD-3-Clause license is retained beside them.

The synthetic RAR2 corpus archive embeds the exact compressed payload from
the MIT `compcol 0.3.0` `rar2` decoder test. That test records that the payload
was produced by the historical `rar 2.60` binary; the generator adds only the
checked RAR2 container header needed to exercise the production source path.

`oracle/rar-test-files-16b785c/` contains a CC0 matrix of RAR3/RAR5,
single-member/multi-member, and ordinary/solid archives copied byte-for-byte
from `ssokolow/rar-test-files` commit
`16b785c2b1b504e99fc307676e5369a26d3ce060`. Its hashes, exact decompressed
inputs, provenance, and license are retained beside the fixtures.

`oracle/mholt-archives-v0.1.5/` contains the two-part RAR fixture from the
exact `github.com/mholt/archives` version selected by the pinned Go checkout.
The corpus intentionally supplies only part one to the unnamed stream API and
freezes its missing-volume outcome. Its MIT license is retained beside it.
