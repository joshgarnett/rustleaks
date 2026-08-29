# Core dependency audit: Serde batch 10

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`e2982548226a2ca69f5856f7ff1f231b8c70fb8c`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from the publishable core and
five other workspace consumers. Its exact workspace consumers, selected
features, target expressions, build-script status, `links` value, checksum,
and cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies
to every declared target and to the deliberately impossible `cfg(any())`
resolution edge, has a build script and no `links` value, and selects the
`default`, `derive`, `serde_derive`, and `std` features. The facade depends on
exactly `serde_core 1.0.229` with its `result` feature and on the selected
`serde_derive 1.0.229` proc macro. Both dependencies already have local
`safe-to-deploy` audits. The source archive came from the crates.io registry
source recorded in `Cargo.lock`.

The review covered all 17,306 lines of packaged Rust source, including every
selected and unselected feature branch, target-specific module, build script,
manifest, package lockfile, README, crates.io readme, and license file.
Cargo-vet estimated 17,830 lines for the complete audit. The 12,037-line
`src/core` subtree is byte-identical to the complete source subtree already
reviewed in `serde_core 1.0.229`; the remaining 5,269 lines were reviewed as
the Serde facade, build glue, generated-module template, and private derive
support. `cargo audit --deny warnings --color never` refreshed the RustSec
database and found no warning in the exact locked graph. An exact-package
GitHub Advisory Database query returned no record. MIT OR Apache-2.0 matched
`deny.toml`; both license texts are packaged, match the already reviewed Serde
core license texts, and there is no `NOTICE` file. No peer audits, wildcard
trust, criteria changes, or exceptions were used.

## `serde 1.0.229`

- Archive: `serde-1.0.229.crate`; SHA-256
  `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba`.
  The packaged VCS identity is commit
  `7fc3b4c30c94f73a96ebd1553f2b090d928fc3a8`, under path `serde`. All 33
  archive members are regular files with mode `0644`. A fresh extraction
  matched the cargo-vet review tree byte for byte apart from Cargo's
  `.cargo-ok` extraction marker.
- Rustleaks use: the package is the public Serde facade and derive-macro
  re-export used by core configuration, baseline, finding, compatibility, and
  reporting structures. The selected `derive` feature runs the separately
  audited proc macro at build time. Runtime serialization and deserialization
  call the separately audited `serde_core` traits through safe interfaces.
  Rustleaks directly exercises Serde's private flattening path for the raw
  global allowlist representation.
- Data-model boundary: the facade forwards public traits and macros from
  `serde_core`, then supplies private support for tagged, untagged, adjacent,
  and flattened derive representations. Deserialization buffers typed
  `Content` values, validates string and byte conversions, rejects duplicate
  or missing tags, rejects malformed enum shapes, and reports sequence or map
  elements left unconsumed. Serialization either delegates supported map and
  struct representations or returns a serializer error for unsupported tagged
  newtype shapes. No dependency implementation type enters a Rustleaks public
  API.
- Unsafe code: the package's only two runtime unsafe blocks are inside its
  byte-identical copy of the audited `serde_core` source. They are the reviewed
  fixed-buffer UTF-8 conversion and IPv4 ASCII-formatting paths. The Serde
  facade, private derive machinery, generated module, and build script contain
  no additional unsafe code. There is no external function, native
  compilation step, C or C++ code, or native library.
- Build script: `build.rs` reads Cargo-provided `OUT_DIR`, package-version, and
  selected-compiler variables. It writes one fixed versioned private module to
  `OUT_DIR`, invokes the selected Rust compiler only with `--version`, and
  emits Cargo configuration declarations. It does not access the network,
  inspect arbitrary files, write outside `OUT_DIR`, spawn threads, or load a
  native library. Environment and output-file unwraps turn an invalid build
  environment into a build failure rather than a runtime input path.
- Ambient authority: unique runtime code performs no file, environment,
  network, or process access, creates no thread, emits no log, and retains no
  mutable process-global state. The only process and filesystem authority is
  the reviewed build script. Network-address code occurs only in the
  byte-identical core subtree and converts values without opening sockets.
- Resource behavior: private deserialization recursively buffers content for
  derive representations. Sequence and map preallocation uses the audited
  cautious size-hint helper, then grows in proportion to values actually
  received. Private serialization buffers flattened and tagged values and
  accepts capacity hints from trusted `Serialize` implementations. The crate
  has no independent recursion, depth, or total-allocation limit. Rustleaks'
  raw configuration limits, selected-rule limits, controlled scan budgets,
  and caller-owned outer input limits remain the applicable boundary.
  Ordinary allocation failure and sufficiently deep caller-created values can
  still abort as documented in `docs/RESOURCE_LIMITS.md`.
- Failure behavior: malformed data and representation mismatches return
  serializer or deserializer errors. Two map-value `expect` calls enforce the
  documented `MapAccess` protocol, and the serializer map-value `expect`
  enforces the matching `SerializeMap` protocol. They require a faulty
  visitor or `Serialize` implementation and are not selected by input bytes
  alone. Pair-visitor size-hint unwraps call the local implementation, which
  always returns `Some`. Build-script unwraps require a broken Cargo build
  environment. No unexplained hostile-input panic or memory-safety path was
  found.
- Selected-feature evidence: warning-denied locked offline library checks
  passed with no default features, with `alloc` only, and with the selected
  default `std` plus `derive` path while also compiling the unselected `rc`
  branch. The exact packaged warning-denied `--all-targets --features derive`
  test and `--doc --features derive` test both passed; the registry package
  intentionally contains no unit or documentation test cases. The complete
  Rustleaks acceptance and security suites exercise the selected facade,
  derive, configuration, baseline, compatibility, and reporting paths.
- Conclusion: the complete reviewed source, previously audited exact
  dependencies, selected-feature evidence, and Rustleaks boundary support
  `safe-to-deploy` for the locked graph.
