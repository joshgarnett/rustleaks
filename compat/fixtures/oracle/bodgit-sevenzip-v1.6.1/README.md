# Pinned sevenzip decoder fixtures

These archives are byte-for-byte copies of the decoder fixtures in
`github.com/bodgit/sevenzip` v1.6.1, the exact module selected by the pinned
Go behavioral oracle. Together they cover COPY, DELTA, LZMA, Deflate, bzip2,
Brotli, LZ4, Zstandard, BCJ2, and the x86/ARM/PPC/SPARC branch converters.

The upstream archive hashes are frozen by `compat/generate_source_corpus.rb`.
The fixtures remain under the adjacent BSD-3-Clause license.
