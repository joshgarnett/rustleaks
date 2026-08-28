# Core dependency audits: leaf batch 2

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`5df09b4a719530010eaa3129d8b2c45f3df838af`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The four packages are normal dependencies reachable from the publishable
core. Their exact workspace consumers, enabled features, target expressions,
build-script status, `links` value, checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. All four apply to every declared target and
have no `links` value. Only `zmij` has a build script. The source archives came
from the crates.io registry source recorded in `Cargo.lock`.

The review covered every packaged production source file, manifest, license,
README, included test or benchmark, and target or selected-feature branch.
`cargo audit --deny warnings --color never` found no RustSec warning in the
exact locked graph. Exact-version GitHub Advisory Database queries returned no
record for each package. The declared licenses matched `deny.toml`. No peer
audits, wildcard trust, criteria changes, or exceptions were used.

## `thiserror-impl 2.0.20`

- Archive: `thiserror-impl-2.0.20.crate`; SHA-256
  `bc04cd3e1236dd4a98afca4569f2deb3f120e5422a4023be2cb683f8486292af`.
- Graph: normal procedural-macro dependency through `thiserror`; no selected
  features or build script. Its dependencies are `proc-macro2`, `quote`, and
  `syn`.
- Code: the macro parses derive input and emits error trait implementations.
  It contains no unsafe code and performs no file, network, process, thread,
  logging, mutable-global, or runtime environment operation. Its only
  environment access is the compile-time package-version constant supplied by
  Cargo.
- Hostile input and limits: parsing, validation, expression scanning, and token
  generation are bounded by the input token stream. Expression nesting follows
  the input syntax. Unwraps follow checked syntax or attribute invariants, and
  transparent-field access follows the preceding exactly-one-field validation.
- Evidence: the exact packaged procedural macro compiled with warnings denied.
  The package contains no tests. Rustleaks builds and tests exercise generated
  error implementations through the selected `thiserror` graph.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `unicode-ident 1.0.24`

- Archive: `unicode-ident-1.0.24.crate`; SHA-256
  `e6e4313cd5fcd3dad5cafa179702e2b244f760991f45397d14d4ebf38247da75`.
- Graph: normal dependency through the procedural-macro stack; no selected
  features, dependencies, build script, or allocation support.
- Code: two constant-time character predicates over generated Unicode 17.0.0
  tables. The crate is `no_std` and performs no allocation or ambient
  operation. Both unsafe leaf-table lookups were reviewed. The two trie index
  arrays have maximum chunk value 242, so the maximum computed leaf offset is
  `242 * 32 + 63 = 7807`, within the 7,808-byte leaf table.
- Hostile input and limits: input is one Rust `char`; lookup work and memory are
  fixed. Characters beyond a trie level use a checked zero chunk. The ASCII
  bit shift is limited to values from 0 through 127. There is no recursion,
  mutable state, native code, or parser.
- Evidence: the library and all five packaged static-size tests passed with
  warnings denied. The packaged cross-implementation test cannot reproduce its
  intended Unicode 17 oracle because crates.io packaging omits the workspace
  Git patch for `unicode-xid`; it stops on the first known Unicode-version
  difference. The generated trie, FST, and roaring fixtures were reviewed, and
  the unsafe index bounds were checked independently.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `semver 1.0.28`

- Archive: `semver-1.0.28.crate`; SHA-256
  `8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd`.
- Graph: normal dependency of `rustleaks-core` and `xtask`; selected features
  `default` and `std`; no selected dependencies, build script, or native code.
- Code: semantic-version parsing, comparison, matching, and display. Its
  identifier type stores up to eight ASCII bytes inline and longer identifiers
  in an owned allocation. Every pointer-tagging, allocation, clone, drop,
  unchecked UTF-8, and `Send + Sync` site was reviewed for the declared 64-bit
  targets. Parser validation guarantees nonzero ASCII identifier bytes and
  valid UTF-8 boundaries before the unsafe constructor is used.
- Hostile input and limits: number parsing uses checked arithmetic. Identifier
  allocation is linear in input length. Version requirements reject more than
  32 comparators, which bounds recursive parsing. The spare-capacity writes
  occur only after the deepest parse succeeds and reserves the complete vector;
  unwind initializes each element once before `set_len` exposes them.
- Evidence: all 34 packaged tests and the all-feature benchmark target passed
  with warnings denied after declaring the package's documented
  `test_node_semver` check-cfg name. Tests cover long heap identifiers, parser
  errors, the comparator limit, comparisons, formatting, and `Send + Sync`.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `zmij 1.0.23`

- Archive: `zmij-1.0.23.crate`; SHA-256
  `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b`.
- Graph: normal dependency through `serde_json`; no selected features or
  dependencies. Its build script reads Cargo's `RUSTC` and `OPT_LEVEL`, invokes
  `rustc --version`, and emits only compilation configuration. It has no
  `links` value or native compilation.
- Code: allocation-free `f32` and `f64` formatting into a 24-byte owned buffer.
  Every unsafe table access, pointer write, unchecked UTF-8 conversion, vector
  transmute, intrinsic, and inline-assembly compiler barrier was reviewed.
  Power-of-ten indices remain in the 618-entry table, exponent-string and shift
  indices follow finite float exponent ranges, and the two-digit lookup is
  called below 100. SIMD paths write at most 16 bytes at once into the buffer.
- Hostile input and limits: input is one fixed-width float and execution is
  constant space with bounded loops. The longest fixed or exponential result,
  including a sign, fits the 24-byte buffer. Every initialized output byte is
  ASCII before unchecked UTF-8 conversion. Static data is immutable, and the
  safe public trait is sealed to `f32` and `f64`.
- Evidence: both unit tests, all 17 boundary and exponent tests, the benchmark
  target, and the default one-million-value Ryu comparison passed with warnings
  denied. The exhaustive all-`f32` test is packaged but requires an explicit
  `exhaustive` configuration and was not run in this bounded audit.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.
