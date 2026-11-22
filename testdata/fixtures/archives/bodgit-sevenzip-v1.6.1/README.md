# 7z decoder fixtures

These archives are byte-for-byte copies of the decoder fixtures in
`github.com/bodgit/sevenzip` v1.6.1, the version that Gitleaks used at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. They cover the COPY, DELTA,
LZMA, Deflate, bzip2, Brotli, LZ4 and Zstandard methods, BCJ2, and the x86,
ARM, PPC and SPARC branch converters.

`//crates/rustleaks-sevenz:oracle_codecs_test` decodes each archive. The
source corpus (`../../../source-corpus/requests-v1.jsonl`) holds copies of
them in its `archive-7z-*` cases.

The fixtures remain under the BSD-3-Clause license in `LICENSE`.
