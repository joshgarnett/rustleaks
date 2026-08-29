# Core dependency audit: Serde derive batch 8

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`770d53868dc013703e39749d9acf8a3bdfccbc9c`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from the publishable core and
five other workspace consumers. Its exact workspace consumers, selected
features, target expressions, build-script status, `links` value, checksum,
and cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies
to every declared target, has no build script or `links` value, and has the
selected feature `default`. Its exact normal dependencies are
`proc-macro2 1.0.107`, `quote 1.0.47`, and `syn 3.0.4`. The first two have
local `safe-to-deploy` audits; `syn` retains its reviewed temporary exemption.
The source archive came from the crates.io registry source recorded in
`Cargo.lock`.

The review covered all 8,975 lines of packaged Rust source, generated-code
branches, manifests, lockfile, license files, READMEs, and the selected feature.
The unselected `deserialize_in_place` branch was also reviewed and compiled.
`cargo audit --deny warnings --color never` refreshed the RustSec database and
found no warning in the exact locked graph. An exact-package GitHub Advisory
Database query returned no record. MIT OR Apache-2.0 matched `deny.toml`; both
license texts are packaged and there is no `NOTICE` file. No peer audits,
wildcard trust, criteria changes, or exceptions were used.

## `serde_derive 1.0.229`

- Archive: `serde_derive-1.0.229.crate`; SHA-256
  `e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348`.
  The packaged VCS identity is commit
  `7fc3b4c30c94f73a96ebd1553f2b090d928fc3a8`, under path `serde_derive`.
  Every archive member is a regular file with mode `0644`. A fresh extraction
  matched the cargo-vet review tree byte for byte apart from Cargo's
  `.cargo-ok` extraction marker.
- Rustleaks use: the macro generates `Serialize` and `Deserialize`
  implementations for production configuration types and for compatibility,
  source, decoder, regex, and corpus types. The repository contains 78 derive
  sites across 11 source files. The procedural macro executes only while
  compiling; the emitted implementations process runtime configuration and
  corpus input through Serde traits.
- Parsing and validation: macro input is parsed as `syn::DeriveInput`.
  Container, variant, and field attributes are parsed into Rust paths, types,
  expressions, lifetimes, and predicates before generation. Duplicate,
  malformed, conflicting-tag, invalid-transparent, unsupported tuple-tag,
  flatten, skip, borrow, getter, and custom-handler combinations produce
  spanned compiler errors before guarded generation branches run.
- Generated serialization: implementations borrow or copy fields according to
  packed and remote-type constraints, call the selected Serde data-model
  methods, propagate serializer errors, and invoke only developer-selected
  custom hooks. Flattened values use Serde's flat-map serializer. Packed-field
  liveness code uses `addr_of!` without dereferencing a raw pointer and the
  reviewed package contains no unsafe block or unsafe function.
- Generated deserialization: visitors consume caller-provided map, sequence,
  enum, and identifier access through fallible Serde interfaces. Missing,
  duplicate, unknown, invalid-length, and unmatched-variant cases return Serde
  errors according to the declared attributes. Unknown fields are either
  rejected or consumed as `IgnoredAny`; flatten buffers key-value content for
  the declared flattened fields. Untagged variants buffer one Serde content
  value and retry the declared variants in order, intentionally discarding
  intermediate mismatch errors before returning the configured final error.
- Type and lifetime generation: inferred bounds traverse field syntax and add
  only relevant generic or associated-type predicates. Borrowed lifetimes are
  collected into the generated deserializer lifetime. Remote types, custom
  Serde paths, defaults, conversions, packed types, and custom handlers are
  represented in generated typed code. Internally constructed syntax is
  reparsed only after being produced by `syn` and `quote`.
- Resource behavior: compile-time parsing, validation, allocation, and emitted
  token size scale with the developer-provided item, its fields, variants,
  aliases, generic syntax, and attributes. Runtime map and sequence visitors
  scale with the supplied input. Flattened input buffers map entries, and
  untagged enums can retry buffered content once per declared variant. The
  macro introduces no independent input limit, thread, or cache. Rustleaks'
  documented parser, decoded-size, and process-allocation boundaries continue
  to govern hostile runtime input.
- Ambient authority: the package does not read or write files, access the
  network, inspect runtime environment variables, spawn threads or processes,
  emit logs, load native libraries, or maintain mutable global state. Its sole
  `env!` use reads Cargo's package patch version at compile time to select the
  matching private Serde module. The `std::thread` reference only suppresses an
  internal diagnostic-context drop panic while the compiler thread is already
  panicking; it does not create a thread.
- Failure behavior: ordinary invalid derive input becomes `compile_error!`
  output. Guarded unwraps, assertions, and unreachable branches enforce states
  established by prior syntax validation. Two developer-source edge cases can
  panic during macro expansion: a container-level default bound on a
  const-generic item reaches an explicit unsupported-const-generic panic, and
  camel-case conversion slices the first byte of an identifier, which is not a
  character boundary for some Unicode identifiers. These are compile-time
  availability limitations for developer-controlled Rust source, not runtime
  hostile-input or memory-safety paths. Generated runtime implementations
  propagate Serde and custom-hook errors instead of panicking.
- Package evidence: both selected-feature unit tests passed with warnings
  denied. Both also passed while compiling the unselected
  `deserialize_in_place` feature. The package's committed development lockfile
  pins `serde 1.0.228`, so its locked documentation test cannot resolve the
  versioned private module emitted by `serde_derive 1.0.229` and failed with
  that version mismatch. In an isolated source copy whose development-only
  Serde packages were aligned to `1.0.229`, the one runnable documentation test
  passed with warnings denied; four illustrative enum snippets remained
  intentionally ignored. Rustleaks' exact locked generated implementations are
  covered by the repository acceptance suite.
- Conclusion: the reviewed source and completed evidence support
  `safe-to-deploy` for the locked Rustleaks graph.
