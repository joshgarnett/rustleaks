# Core dependency audits: TOML batch 4

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`48fb280488c9e62a1bc656c3717239dd3fdcf599`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

Both packages are normal dependencies reachable from the publishable core.
Their exact workspace consumers, enabled features, target expressions,
build-script status, `links` value, checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. Both apply to every declared target, have no
build script, and have no `links` value. The source archives came from the
crates.io registry source recorded in `Cargo.lock`.

The review covered every packaged production source file, manifest, license,
README, included test, example, and selected-feature branch. `cargo audit
--deny warnings --color never` found no RustSec warning in the exact locked
graph. Exact-package GitHub Advisory Database queries returned no record for
either package. MIT OR Apache-2.0 matched `deny.toml`. No peer audits, wildcard
trust, criteria changes, or exceptions were used.

## `toml 1.1.4+spec-1.1.0`

- Archive: `toml-1.1.4+spec-1.1.0.crate`; SHA-256
  `3aace63f4bbcdfc2c965b059de67119c89c4017a70d633be6c104910f67056f5`.
- Graph: normal dependency through every publishable crate, `rustleaks-compat`,
  and `xtask`; selected features `default`, `display`, `parse`, `serde`, and
  `std`. Optional `debug`, `fast_hash`, `preserve_order`, and `unbounded`
  features are not selected.
- Code: the crate forbids unsafe code. Its parser facade lexes borrowed UTF-8,
  emits checked spans and events, builds owned or borrowed TOML values, and
  implements Serde conversion. Serialization writes only to caller-owned
  in-memory buffers. Production code performs no file, environment, network,
  process, thread, logging, native-code, or mutable-global operation.
- Hostile input and limits: the selected parser wraps nested arrays and inline
  tables in a recursion guard with a maximum depth of 80 and separately rejects
  dotted-key paths at that limit. Lexing, decoding, event collection, map
  construction, and error collection are bounded by the input and reported
  errors. The unselected `unbounded` feature explicitly removes these stack
  protections.
- Failure behavior: span unwraps consume events emitted from the same checked
  lexer. Table and array unwraps follow variants constructed immediately in
  the same branch. Serde map ordering panics require a caller implementation to
  violate the Serde access contract. Public indexing intentionally panics for
  a missing key or index and is documented as such.
- Evidence: all 8 packaged unit tests, 3 packaged examples, and 9 doc tests
  passed with default selected features, a locked archive graph, and warnings
  denied. The original manifest names decoder and encoder compliance targets,
  but their source is omitted from the published archive, so they were not
  claimed as archive evidence. Rustleaks' checked default-config corpus and
  parity replay provide integration evidence for the selected parser path.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `toml_parser 1.1.3+spec-1.1.0`

- Archive: `toml_parser-1.1.3+spec-1.1.0.crate`; SHA-256
  `1d38ac1cf9b95face32296c0a3ede1fdc270627c9d9c02a7274dd6d960dc4d56`.
- Graph: normal dependency through the TOML parser stack; selected features
  `alloc` and `std`. Optional `debug`, `simd`, and `unsafe` features are not
  selected. Its only normal dependency is `winnow` with default features
  disabled.
- Code: the selected configuration forbids unsafe code. The lexer advances on
  checked UTF-8 boundaries, the push parser consumes a finite token slice, and
  decoders validate strings, escapes, Unicode scalar values, numbers, and
  dates while streaming into caller-provided builders. Production code has no
  ambient file, environment, network, process, thread, logging, native-code,
  or mutable-global behavior.
- Hostile input and limits: lexing and decoding advance monotonically through
  the input. Parser recovery tracks nested delimiters iteratively with
  saturating decrements. Nested value parsing is recursive, but the selected
  `toml` facade wraps its event receiver in the depth guard before this code is
  reached. The low-level public parser also exposes an unguarded receiver API,
  which Rustleaks does not use.
- Failure behavior: unchecked-looking span constructors store offsets only;
  safe source lookup validates range and UTF-8 boundaries. The selected
  whitespace validator expects token spans produced by the crate lexer, which
  is the facade invariant. Remaining unreachable branches cover exhaustive
  token states. The optional unsafe source and slicing fast paths are excluded
  from the selected graph.
- Evidence: all 20 packaged tests passed with default selected features, a
  locked archive graph, and warnings denied. The archive has no doc tests.
  Tests cover lexer recovery, strings, escapes, scalars, redundant numeric
  signs, dates, tokens, and decoder output.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.
