# Core dependency audits: leaf batch 1

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`be95dacb18edc31a66fbdb0fad5c8371f2faa9de`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The four packages are normal dependencies reachable from the publishable
core. Their exact workspace consumers, enabled features, target expressions,
build-script status, `links` value, checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. All four apply to every declared target and
have no build script or `links` value. The source archives came from the
crates.io registry source recorded in `Cargo.lock`.

The review covered every packaged production source file, manifest, license,
README, included test or benchmark, and target or feature branch. `cargo audit
--deny warnings --color never` found no RustSec warning in the exact locked
graph. Exact-version GitHub Advisory Database queries returned no record for
each package. MIT OR Apache-2.0 matched `deny.toml`. No peer audits, wildcard
trust, criteria changes, or exceptions were used.

## `serde_spanned 1.1.1`

- Archive: `serde_spanned-1.1.1.crate`; SHA-256
  `6662b5879511e06e8999a8a235d848113e942c9124f211511b16466ee2995f26`.
- Graph: normal dependency through `toml`; selected features `alloc`, `serde`,
  and `std`; dependency `serde_core 1.0.229`.
- Code: a generic span wrapper and serde map adapter. The crate forbids unsafe
  code. It performs no file, environment, network, process, thread, logging,
  or global-state operation. It has no native or generated source.
- Hostile input and limits: deserialization has fixed field state. The panic in
  `next_value_seed` requires a `MapAccess` caller to request a value without a
  preceding key. Normal serde protocol use cannot reach it. Allocation and
  value behavior are delegated to the caller's generic type and `serde_core`.
- Evidence: the all-feature library target built successfully. The packaged
  doctest cannot resolve its omitted monorepo-only `toml` path dependency, so
  it was recorded as a packaging-test limitation rather than a source failure.
  Rustleaks configuration tests exercise the selected integration.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `itoa 1.0.18`

- Archive: `itoa-1.0.18.crate`; SHA-256
  `8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682`.
- Graph: normal dependency through `serde_json`; no selected features or
  dependencies.
- Code: fixed-stack integer formatting for sealed primitive implementations.
  It performs no allocation or ambient operation. Every unsafe site was
  reviewed. The sealed trait fixes the cast buffer type and maximum length,
  lookup indices are reduced below 100, offsets remain within the exact
  primitive buffer, and only initialized ASCII bytes reach unchecked UTF-8
  conversion.
- Hostile input and limits: input is a primitive integer and work is bounded by
  its bit width. The unchecked-unreachable branch depends on the sealed output
  length invariant. There is no recursion, external input parser, global state,
  or integer growth beyond fixed-width arithmetic reviewed in `u128_ext.rs`.
- Evidence: all 11 packaged boundary tests passed, including signed minima,
  unsigned maxima, 128-bit values, zero, and maximum string lengths.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `toml_writer 1.1.2+spec-1.1.0`

- Archive: `toml_writer-1.1.2+spec-1.1.0.crate`; SHA-256
  `7d56353a2a665ad0f41a421187180aab746c8c325620617ad883a99a1cbe66d2`.
- Graph: normal dependency through `toml`; selected features `alloc` and
  `std`; no dependencies.
- Code: low-level TOML key and value formatting. The crate forbids unsafe code
  and performs no ambient operation. The only unwrap follows an explicit
  nonempty-stream check. UTF-8 slicing stops only at ASCII delimiters or
  controls, which preserves character boundaries.
- Hostile input and limits: string scanning and escaping are linear in the
  input. Collection serialization is linear in caller-provided elements.
  Allocation and output capacity are caller-owned, matching the documented
  streaming report boundary. There is no recursion or native code.
- Evidence: the all-feature build and all four packaged doctests passed.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `toml_datetime 1.1.1+spec-1.1.0`

- Archive: `toml_datetime-1.1.1+spec-1.1.0.crate`; SHA-256
  `3165f65f62e28e0115a00b2ebdd37eb6f3b641855f9d636d3cd4103767159ad7`.
- Graph: normal dependency through `toml`; selected features `alloc`, `serde`,
  and `std`; dependency `serde_core 1.0.229`.
- Code: TOML datetime parsing, display, and serde adapters. The crate forbids
  unsafe code and performs no ambient operation. The nanosecond panic follows
  a digit-token check. The serde map panic requires protocol misuse. Parsed
  custom offsets are bounded before display can negate them.
- Hostile input and limits: lexing and fractional-second conversion are linear
  in input length. Fraction arithmetic uses only the first nine digits, so a
  long fractional field does not overflow. Parsing has no recursion. The
  enclosing Rustleaks configuration input limit bounds total work and
  allocation.
- Evidence: the complete all-feature crate built successfully. The package
  contains no unit tests or doctests; Rustleaks configuration corpus and parity
  tests exercise accepted and rejected datetime forms through the selected
  TOML stack.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.
