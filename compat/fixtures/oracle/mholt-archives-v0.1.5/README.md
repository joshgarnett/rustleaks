# Multi-volume RAR compatibility fixture

`test.part01.rar` and `test.part02.rar` are copied byte-for-byte from the
`testdata` directory of `github.com/mholt/archives` version 0.1.5, the exact
archive frontend selected by the pinned Go checkout. The upstream MIT license
is retained beside them.

The source oracle receives only the first part because Gitleaks constructs the
RAR extractor from an unnamed stream and provides neither a filesystem nor a
volume resolver. This freezes the resulting missing-volume behavior; the
second part is retained to prove the fixture is intentionally split rather
than truncated accidentally.
