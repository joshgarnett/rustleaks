# Runtime dependency audit: const-oid batch 27

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`a5aa908a30a04e6ac6d5f37beb2d6e74386d36b5`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`const-oid 0.10.2` is a normal dependency of `digest 0.11.3`. The locked graph
reaches it through `sha2`, including the `lzma-rust2`, `rustleaks-sources`, and
`xtask` paths. The generated inventory records `rustleaks-cli` and `xtask` as
workspace consumers. No package feature is selected, and the package has no
build script, `links` value, or core normal or build graph path.

The configured peer projects did not provide version-specific coverage for
the exact locked package. The local review covered all 22 packaged files and
8,385 packaged lines, including 7,255 lines of Rust source and tests. The
optional database consists of generated OID constants and linear lookup code;
it is not selected by Rustleaks but was included in the source review and
all-feature tests. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability warning in
the exact Rustleaks lockfile. An exact-package GitHub Advisory Database query
returned no advisory for `const-oid`. Apache-2.0 OR MIT matches `deny.toml`,
both license texts are packaged, and there is no `NOTICE` file. No wildcard
trust, criteria change, or exception was used.

## `const-oid 0.10.2`

- Archive: `const-oid-0.10.2.crate`; SHA-256
  `a6ef517f0926dd24a1582492c791b6a4818a4d94e789a334894aa15b0d12f55c`.
  All 22 archive members are regular files with mode `0644`. Cargo's registry
  source matches a fresh archive extraction byte for byte apart from Cargo's
  `.cargo-ok` marker. The packaged VCS record identifies upstream commit
  `385ef739bcec785472c7c971c57f26f87caca3b8` and path `const-oid`. Release tag
  `const-oid/v0.10.2` points at follow-up commit
  `e5c7e4c110cfeec8cd17802f11ead7eac700c8a8`; the `const-oid` tree is
  unchanged between those commits. Production source, tests, documentation,
  changelog, licenses, and `Cargo.toml.orig` match the exact VCS tree. The
  normalized manifest, package lockfile, and VCS record are Cargo packaging
  metadata. `LICENSE-APACHE` and `LICENSE-MIT` have respective SHA-256 values
  `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`
  and
  `73b9dc2e79c7308998dd30296e073aefaefb944a68fb89aa412c23c0edcabcaa`.
- Rustleaks use: `digest` uses the crate's associated-OID trait for fixed
  algorithm identifiers exposed by `sha2`. Rustleaks does not parse
  caller-provided OID text or bytes and does not select the optional OID name
  database or arbitrary-value generator.
- Parser and encoder behavior: fallible constructors validate the constrained
  first and second arcs, use checked arithmetic for decimal and base-128
  conversion, reject unterminated or oversized arcs, and encode into a fixed
  array. Owned values use the default 39-byte capacity in the locked graph.
  The internal length is an eight-bit value, so callers choosing a public
  const-generic capacity above 255 bytes must stay within that representable
  length. The recursive text parser can exhaust stack on an adversarially long
  string before reaching the encoded-size check. Neither limitation is
  reachable through Rustleaks' fixed compile-time algorithm identifiers.
- Unsafe inventory: the package has one unsafe block. It casts `&[u8]` to
  `&ObjectIdentifierRef`, a `repr(transparent)` dynamically sized newtype over
  `[u8]`. The cast preserves the slice data pointer, length metadata, lifetime,
  alignment, and representation. Its private unchecked entry point is reached
  either after byte validation or from an owned identifier constructed through
  the encoder. Miri exercised construction, byte validation, conversion,
  lookup, formatting, iteration, and property-test round trips without an
  invalid-access report. There is no external declaration, native binding,
  generated-at-build source, or other unsafe block.
- Authority and resource boundary: the crate is `no_std`, has no selected
  normal dependency, and performs no heap allocation, file or socket access,
  environment read, process or thread creation, logging, or global mutation.
  Parsing and iteration are linear in input length. The optional database uses
  compile-time static constants and linear scans; it performs no I/O and is not
  selected. Panic APIs are explicit const-construction conveniences, while the
  runtime constructors used for untrusted bytes return structured errors.
- Published-source evidence: package unit, integration, property, and
  documentation tests passed on Rust 1.88.0 and pinned nightly with all
  features. The selected no-feature profile passed the same suite on the
  declared Rust 1.85.0 MSRV. Pinned Miri passed the complete all-feature suite
  on AArch64 macOS after filesystem isolation was disabled for proptest's
  failure-persistence `getcwd` call; the deterministic tests also passed under
  normal Miri isolation before that development-only helper stopped the run.
- Target evidence: pinned-nightly `build-std` checks compiled the selected
  no-feature library for the seven non-native required targets. Native AArch64
  macOS behavior was exercised by the multi-toolchain and Miri test runs. The
  package has no target-specific production branch.
- Conclusion: complete source review, exact archive and VCS provenance, the
  transparent-newtype unsafe proof, selected and all-feature tests, property
  tests, all-required-target compilation, Miri execution, license evidence,
  and advisory results support `safe-to-deploy` for the locked Rustleaks graph.
