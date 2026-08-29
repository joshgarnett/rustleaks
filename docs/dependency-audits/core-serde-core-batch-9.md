# Core dependency audit: Serde core batch 9

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`b67147ca08c005bd64c904686cd7aea54b353fb4`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from the publishable core and
five other workspace consumers. Its exact workspace consumers, selected
features, target expressions, build-script status, `links` value, checksum,
and cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies
to every declared target, has a build script and no `links` value, and selects
the `alloc`, `result`, and `std` features. The active normal and build graph has
no dependency below `serde_core`. The package manifest names
`serde_derive 1.0.229` only under the deliberately impossible `cfg(any())`
target expression, so that edge is resolved but never compiled. Development
tests name `serde` and `serde_derive`; those edges do not enter Rustleaks
artifacts. The source archive came from the crates.io registry source recorded
in `Cargo.lock`.

The review covered all 12,150 lines of packaged Rust source, including every
selected and unselected feature branch, target-specific module, build script,
manifest, package lockfile, README, and license file. Cargo-vet estimated
12,534 lines for the complete audit. `cargo audit --deny warnings --color
never` refreshed the RustSec database and found no warning in the exact locked
graph. An exact-package GitHub Advisory Database query returned no record. MIT
OR Apache-2.0 matched `deny.toml`; both license texts are packaged, match the
already reviewed Serde 1.0.229 license texts, and there is no `NOTICE` file.
No peer audits, wildcard trust, criteria changes, or exceptions were used.

## `serde_core 1.0.229`

- Archive: `serde_core-1.0.229.crate`; SHA-256
  `67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48`.
  The packaged VCS identity is commit
  `7fc3b4c30c94f73a96ebd1553f2b090d928fc3a8`, under path `serde_core`.
  Every archive member is a regular file with mode `0644`. A fresh extraction
  matched the cargo-vet review tree byte for byte apart from Cargo's
  `.cargo-ok` extraction marker.
- Rustleaks use: the package supplies Serde's core `Serialize`, `Serializer`,
  `Deserialize`, `Deserializer`, visitor, access, error, and value interfaces.
  `serde`, `serde_json`, `serde_spanned`, `toml`, and `toml_datetime` use it in
  the locked graph. Rustleaks reaches those paths while parsing configuration
  and baselines and while serializing compatibility and report structures.
- Data-model boundary: serialization implementations forward primitives,
  collections, options, results, ranges, time values, network-address values,
  strings, paths, and operating-system strings through fallible serializer
  methods. Deserialization implementations obtain those values through
  fallible visitors and access protocols. Numeric conversions are range
  checked or intentionally saturating. Duration and system-time arithmetic is
  checked, sequence and map protocol lengths return errors on mismatches, and
  invalid UTF-8, invalid interior NUL bytes, and wrong-host operating-system
  string variants return Serde errors.
- Unsafe code: the package contains two runtime unsafe blocks and no unsafe
  function. `src/format.rs` converts a private fixed formatting buffer with
  `str::from_utf8_unchecked`; the writer accepts only valid UTF-8 `&str`,
  bounds-checks every copy, and is reached only by fixed numeric and IP
  formatting. The IPv4 serializer writes only ASCII digits and dots derived
  from four `u8` values into a 15-byte buffer before the same unchecked UTF-8
  conversion. The reviewed invariants establish valid initialized UTF-8 and
  an in-bounds length at both call sites. There is no external function,
  native compilation step, C or C++ code, or mutable global state.
- Build script: `build.rs` reads Cargo-provided `OUT_DIR`, package-version,
  target, and selected-compiler variables, invokes the selected Rust compiler
  only with `--version`, writes one fixed private module to `OUT_DIR`, and
  emits Cargo configuration declarations. It does not access the network,
  inspect arbitrary files, write outside `OUT_DIR`, spawn threads, or load a
  native library. Environment or file-operation unwraps turn an invalid build
  environment into a build failure rather than a runtime input path.
- Ambient authority: runtime code performs no file, environment, network, or
  process access, creates no thread, emits no log, and retains no mutable
  process-global state. Implementations for `std::net` types only convert
  address values and never open a socket. Mutex and read-write-lock
  serialization can wait on a caller-owned lock and translate poisoning into a
  Serde error. Atomic values use relaxed loads during serialization and create
  new atomics during deserialization.
- Resource behavior: allocation and iteration scale with the value or input
  supplied by the selected serializer or deserializer. Collection
  preallocation uses a cautious size hint capped at 1 MiB; further growth
  remains proportional to values actually received. The package adds no
  independent recursion or depth limit and relies on the selected format and
  destination type for traversal. Rustleaks' configuration, decoded-byte,
  work, finding, and process-allocation boundaries continue to govern hostile
  input. Ordinary allocation failure can still abort as documented in
  `docs/RESOURCE_LIMITS.md`.
- Failure behavior: malformed values and unsupported representations normally
  return serializer or deserializer errors. Fixed-buffer formatting unwraps
  are protected by the reviewed maximum encoded lengths. The zero-length
  `OneOf` panic is excluded by its callers' empty-list cases. The map-value
  `expect` enforces a programmer violation of the `MapAccess` call protocol and
  cannot be reached from serialized input alone. Pair-visitor size-hint
  unwrapping observes its own implementation, which always returns a value.
  No unexplained hostile-input panic or memory-safety path was found.
- Selected-feature evidence: warning-denied locked offline library checks
  passed for `alloc`, for the `no_std` `alloc,result` combination, and for the
  unselected `rc` branch. The exact packaged `--all-targets --features alloc`
  test passed its one unit test after retrieving only the development-only
  `serde 1.0.185` named by the package lockfile. The package's original locked
  documentation test ran 68 cases, with 47 passing and 21 failing because its
  development lock pairs `serde 1.0.185` with the versioned private
  `serde_core 1.0.229` interface. In an isolated reconstruction of the
  authoritative upstream path layout using the exact `serde_core`, `serde`,
  and `serde_derive 1.0.229` source archives, the graph resolved one
  `serde_core` identity and all 68 warning-denied offline documentation tests
  passed. Rustleaks' exact locked uses remain covered by the repository
  acceptance suite.
- Conclusion: the complete reviewed source and selected-feature evidence
  support `safe-to-deploy` for the locked Rustleaks graph.
