# Core dependency audit: regex-syntax batch 13

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`760d7ba9d9c51980eab85cc19b9994395a284592`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable directly and through
`regex-automata` from the publishable core. The CLI, compatibility, report,
and sources crates inherit it through `rustleaks-core`. Its exact consumers,
selected features, target expressions, build-script status, `links` value,
checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. It applies to every declared target, has no
build script or `links` value, and selects `default`, `std`, `unicode`, and all
seven Unicode data features. Its only declared dependency is the unselected
optional `arbitrary` feature dependency. The source archive came from the
crates.io registry source recorded in `Cargo.lock`.

The review covered all 58,465 lines of packaged Rust source, including 33,933
lines of generated Unicode 16.0 tables, the 63-line nightly benchmark,
manifests, package lockfile, README, VCS metadata, licenses, embedded tests,
and every selected and unselected feature branch. Cargo-vet estimated 59,067
lines for the complete audit. A fresh RustSec check at advisory database
commit `6420e39260b3d771b049954cf5d52b57e2118da4` found no vulnerability or
warning in the exact 71-package Rustleaks lockfile. An exact-package GitHub
Advisory Database query returned no record. The upstream repository publishes
one historical advisory for `regex <=1.5.4`, not `regex-syntax 0.8.11`; its
empty-subexpression repetition issue is also addressed by the reviewed HIR
constructor described below. MIT OR Apache-2.0 and the bundled Unicode-3.0
data license match `deny.toml`; all three license texts are packaged and there
is no `NOTICE` file. No peer audits, wildcard trust, criteria changes, or
exceptions were used.

## `regex-syntax 0.8.11`

- Archive: `regex-syntax-0.8.11.crate`; SHA-256
  `d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4`.
  The packaged VCS identity is verified upstream commit
  `140167995737fa11dfe11b8af8b9aa143b790b4e`, at path `regex-syntax`. All 42
  archive members are regular files with mode `0644`. Cargo-vet's source and
  Cargo's registry extraction match byte for byte apart from Cargo's
  `.cargo-ok` marker and local test output. `LICENSE-MIT`, `LICENSE-APACHE`,
  and `src/unicode_tables/LICENSE-UNICODE` have respective SHA-256 values
  `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb`,
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`,
  and `74db5baf44a41b1000312c673544b3374e4198af5605c7f9080a402cec42cfa3`.
- Rustleaks use: the private Go-compatible frontend calls
  `regex_syntax::escape_into` while the direct PikeVM builder asks
  `regex-automata` to parse translated patterns through this crate. Rustleaks
  enables Unicode and UTF-8 syntax, caps source patterns at 1 MiB, caps AST
  nesting at 4,096, caps compiled NFAs at 256 MiB, limits Go repetition to
  1,000, and moves deeply nested compilation to a 32 MiB stack. It does not
  call public AST mutation, HIR construction, printing, UTF-8 range iteration,
  or literal extraction directly.
- Memory-safety boundary: the crate is `no_std` plus `alloc` and applies
  `forbid(unsafe_code)` at its root. The complete archive contains no unsafe
  block, external function, native library, C or C++ source, generated
  production source path, or `links` declaration. No memory-safety invariant
  depends on caller input or an unaudited selected dependency.
- Parser behavior: parsing advances only at UTF-8 character boundaries and
  constructs AST nodes, comments, capture names, group frames, and character
  class frames on heap vectors. Capture index and position arithmetic checks
  overflow; a position overflow would require an input approaching the
  address-space limit and is unreachable behind Rustleaks' 1 MiB cap. Group,
  alternation, and class stacks are explicit rather than recursive. A second
  heap visitor enforces the caller-selected nesting limit after parsing.
  Malformed escapes, repetitions, ranges, flags, groups, classes, properties,
  and UTF-8 modes return structured errors.
- HIR behavior: AST translation uses explicit visitor and HIR-frame stacks.
  Smart constructors flatten adjacent literals and nested concatenations or
  alternations while preserving canonical invariants. Repetition remains a
  compact node; if its child can match only the empty string, the constructor
  caps the effective repetition at one. This prevents the historical
  empty-subexpression expansion pattern. Length and capture properties use
  checked or saturating arithmetic so an unrepresentable bound becomes
  unknown or conservatively saturated rather than wrapping.
- Class and Unicode behavior: interval sets canonicalize sorted disjoint
  ranges and implement union, intersection, difference, symmetric difference,
  negation, and simple case folding with boundary-aware checked operations.
  UTF-8 sequence generation splits around surrogate code points and encoding
  widths before constructing one-to-four-byte ranges. Unicode property and
  value lookup normalizes input to ASCII and performs binary searches over
  generated sorted tables. Unicode classes can allocate ranges proportional
  to the selected fixed tables and requested class expression, but cannot
  fetch data or mutate global state.
- Recursion and destruction: AST and HIR visitors use constant call-stack
  space with heap stacks proportional to input structure. Custom AST, class,
  and HIR destructors iteratively detach children so deeply nested parsed
  values do not recursively drop. Literal extraction is the documented
  exception that recursively traverses HIR; its defaults cap class expansion
  at 10, repetition expansion at 10, each literal at 100 bytes, and the total
  sequence at 250. Rustleaks' direct PikeVM construction does not invoke this
  public extraction API.
- Panic boundary: production panics and unwraps enforce internal stack-shape,
  canonical-range, UTF-8 encoding, and generated-table invariants, or document
  public preconditions such as strictly increasing case-fold lookups. The
  parser owns the AST passed to its translator and maintains these invariants.
  Checked parser errors cover hostile concrete syntax. No ordinary untrusted
  Rustleaks pattern reaches an unexplained panic path. Allocation failure can
  still abort, as for ordinary Rust allocation.
- Ambient authority: selected production code opens no file or socket, reads
  no environment variable, starts no process or thread, writes no log, and
  retains no mutable process-global state. The selected `std` feature adds
  error-trait implementations. Two explicit stack-size thread spawns exist
  only in destructor tests. The packaged benchmark uses nightly's in-process
  test harness and is not library behavior.
- Time and allocation: AST construction and translation use space
  proportional to pattern structure plus fixed Unicode table expansions.
  Duplicate named captures and range-set algebra can perform repeated vector
  insertion or merging, and alternation simplification may revisit adjacent
  structures. Literal cross products are capped before continued extraction.
  Rustleaks' source, nesting, repetition, compiled-size, and stack limits bound
  the selected hostile-pattern path. These controls do not promise a strict
  wall-clock or total-process-memory limit.
- Upstream evidence: default-feature library tests passed 147 tests,
  featureless library tests passed 144 tests, and all-feature library tests
  passed 147 tests. All-feature doctests passed 48 tests with compiler warnings
  denied. These cover malformed-input regressions, nesting enforcement,
  constant-stack destruction, class algebra, Unicode lookup and case folding,
  UTF-8 range construction, smart HIR simplification, literal-extraction caps,
  and previously fuzzed parser inputs.
- Upstream evidence limits: the packaged benchmark requires nightly and was
  inspected but not executed. A supplemental current-Clippy run with all
  features was not clean because generated tables and documentation trigger
  711 style lints, including redundant static lifetimes and documentation
  formatting. No passing Clippy result is claimed, and those lints do not
  change the compiled behavior or the safety conclusion.
- Conclusion: the complete reviewed source, unsafe-free and ambient-authority-
  free implementation, bounded Rustleaks call path, parser and HIR resource
  controls, upstream tests, advisory results, and license evidence support
  `safe-to-deploy` for the locked Rustleaks graph. The documented public
  preconditions and resource limitations do not require an exception and
  remain part of the dependency boundary.
