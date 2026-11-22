# Multi-volume RAR fixture

`test.part01.rar` and `test.part02.rar` are byte-for-byte copies from the
`testdata` folder of `github.com/mholt/archives` v0.1.5, the version that
Gitleaks used at commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. They
remain under the MIT license in `LICENSE`.

The source corpus case `archive-rar5-multivolume`
(`../../../source-corpus/requests-v1.jsonl`) holds a copy of the first part
only, read from a stream with no file name, so the second volume cannot be
found. The recorded Gitleaks outcome is a panic. Rustleaks reports a source
issue, and `//crates/rustleaks-sources:source_corpus_test` checks that. The
second part is kept to show that the archive is split on purpose, not cut
short by mistake.
