# Bounded cl100k tokenizer data

`cl100k-vercel60-v1.bin` contains only lookup records reachable when counting
ordinary cl100k tokens in `[vV][cC][kK]_[A-Za-z0-9_-]{56}`. It is immutable
compile-time data. The runtime never reads a file, initializes a vocabulary,
allocates tokenizer storage, or downloads data.

The original `cl100k_base.tiktoken` is retained byte-for-byte for reproducible
generation and tests against the full vocabulary. It comes from
[tiktoken-rs 0.12.1](https://static.crates.io/crates/tiktoken-rs/tiktoken-rs-0.12.1.crate),
archive SHA-256 `2aeff724640cfe13037336ddf35befdffd2909cbdb65cf041cc8a4cf8c584cfa`,
repository revision `72a5a800651a1cea1ad609292446ba02c80e3bcd`.
The pinned repository's
[asset script](https://github.com/zurawiki/tiktoken-rs/blob/72a5a800651a1cea1ad609292446ba02c80e3bcd/scripts/download_assets.sh)
names OpenAI's cl100k asset and the source hash below. Its OpenAI submodule is
revision `4e71bbe0c078468e00fefbf94b39849389f346e5`; that revision's
[encoding definition](https://github.com/openai/tiktoken/blob/4e71bbe0c078468e00fefbf94b39849389f346e5/tiktoken_ext/openai_public.py)
names the same hash, URL and splitting pattern.

Both adjacent MIT licenses apply: OpenAI and Shantanu Jain, 2022, and Roger
Zurawicki, 2023. The tiktoken-rs archive omitted its license file, so the
adjacent notice is copied from its exact repository revision. No tiktoken-rs
runtime dependency, thread-local machinery or unsafe code is imported.

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| `cl100k_base.tiktoken` | 1,681,126 | `223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7` |
| `cl100k-vercel60-v1.bin` | 470,103 | `ad1a8cb135ace0e3dd9507246248658d2d99761353d96e31b1f33626d677ab28` |

`xtask generate native-pack-identity` regenerates the derived table;
`xtask generate native-pack-identity --check` verifies it. The build-contract
gate also runs this verification. The maintained generator verifies original
source size and hash, both license hashes, 100,256 unique tokens and ranks,
all 256 singleton tokens, and every one-to-three-digit token. It derives all
records and compares every output byte, not just an output digest.

For this capture language the ordered splitter reduces exactly to
`[-_]?[A-Za-z]+|[0-9]{1,3}|[-_]+`. Consecutive punctuation stays one piece;
only a single punctuation byte immediately followed by letters joins their
piece. No merge crosses a piece boundary. All possible lookup keys belong to:

```text
[A-Za-z]{1,56}
_[A-Za-z]{1,56}
-[A-Za-z]{1,54}
[0-9]{1,3}
[-_]{1,56}
_[-_]{56}
```

This retains 35,635 source records. The count-only implementation omits 64
singletons and 1,100 multi-byte numeric tokens: singleton counts are one, and
every numeric pretoken is a verified direct vocabulary hit. The remaining
34,471 records retain original merge ranks and use 194,315 token bytes; their
maximum key length is 48. Whole-piece hits, adjacent-pair lookups and later
merged lookups therefore keep the same ranks or absence as the full source.
Strict minimum-rank comparison keeps the earliest equal-rank pair.

The binary starts with `RLVCBPE1`, then little-endian u32 record and pool
counts, `N+1` little-endian u32 offsets, `N` original little-endian u32 ranks,
and the concatenated token bytes. Keys are sorted lexicographically by raw
bytes. The runtime uses ordinary checked byte indexing without aligned casts.
Only the derived table is used by production code; the original asset is used
by the maintenance gate and tests.
