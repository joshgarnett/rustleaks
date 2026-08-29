# Core dependency audit: regex-automata batch 14

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`57d9341b02d8d69143be39ca631c6a5d77fd8b4c`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency of the publishable core. The CLI,
compatibility, report, and sources crates inherit it through
`rustleaks-core`. Its exact consumers, selected features, target expressions,
build-script status, `links` value, checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. It applies to every declared target, has no
build script or `links` value, and selects `alloc`, `std`, `syntax`,
`nfa-thompson`, `nfa-pikevm`, `unicode`, and all eight Unicode feature flags.
Its only selected dependency is the separately audited `regex-syntax`; the
optional Aho-Corasick, memchr, and logging edges are not selected. The source
archive came from the crates.io registry source recorded in `Cargo.lock`.

The review covered all 68,447 lines of packaged Rust source, including 65,894
lines under `src`, manifests, package lockfile, README, VCS metadata, licenses,
tests, test data, benchmarks, and every selected and unselected feature branch.
A fresh RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact 71-package Rustleaks
lockfile. An exact-package GitHub Advisory Database query returned no record.
The upstream repository publishes one historical advisory for `regex <=1.5.4`,
not `regex-automata 0.4.18`; its empty-subexpression repetition issue is also
bounded by the reviewed parser and Rustleaks repetition controls described
below. MIT OR Apache-2.0 matches `deny.toml`; both license texts are packaged
and there is no `NOTICE` file. The archive also contains an unselected
Unicode-derived fallback table. Its exact provenance and license disposition
are recorded below. No peer audits, wildcard trust, criteria changes, or
exceptions were used.

## `regex-automata 0.4.18`

- Archive: `regex-automata-0.4.18.crate`; SHA-256
  `ad8553b9b26413251cbf30e620595c7a41b3887f03da04579c0e6b0d6a06b4b2`.
  The packaged VCS identity is verified upstream commit
  `e6ad938198e68339a593f85d228f2d44cb54718f`, at path `regex-automata`. All
  107 archive members are regular files with mode `0644`. A fresh extraction
  matched cargo-vet's source byte for byte apart from Cargo's `.cargo-ok`
  marker. `LICENSE-MIT` and `LICENSE-APACHE` have respective SHA-256 values
  `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb`
  and `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`.
- Unicode data license: `src/util/unicode_data/perl_word.rs` identifies its
  `ucd-generate 0.3.1` command and Unicode 16.0.0 input. Its SHA-256 is
  `30f073baae28ea34c373c7778c00f20c1621c3e644404eff031f7d1cc8e9c9e2`,
  exactly matching the separately audited `regex-syntax 0.8.11` table. The
  upstream repository places that copy under the Unicode data license whose
  SHA-256 is
  `74db5baf44a41b1000312c673544b3374e4198af5605c7f9080a402cec42cfa3`.
  The normalized `regex-automata` manifest names `LICENSE-UNICODE`, but the
  archive does not contain that file. Rustleaks selects both `syntax` and
  `unicode-perl`, so conditional compilation excludes this fallback and uses
  the licensed `regex-syntax` copy, whose package includes the license. This
  establishes the selected data's exact provenance and license without
  treating the upstream archive omission as a passing packaged-license claim.
- Rustleaks use: the private Go-compatible regex frontend builds a Thompson
  NFA and executes it directly through the PikeVM with leftmost-first,
  Unicode, UTF-8, and full-capture behavior. Rustleaks supplies a fresh cache
  and checked search span for each operation. It does not expose dependency
  types publicly or select the meta engine, backtracker, dense or sparse DFA,
  one-pass DFA, hybrid DFA, literal acceleration, logging, or PikeVM
  instrumentation.
- Unsafe inventory: the complete selected and unselected source has unsafe
  code in ten files. The selected utility surface contains the lazy-value
  and thread-aware pool implementations. The remaining unsafe code implements
  serialized dense and sparse DFA access, accelerator casts, automaton search,
  hybrid DFA cache access, and wire-format slice casts in unselected feature
  branches. The PikeVM, Thompson NFA builder and compiler, capture tables,
  syntax integration, and search state sets use safe Rust.
- Lazy initialization safety: the allocation-enabled lazy value publishes a
  boxed pointer with release semantics and reads it with acquire semantics. A
  losing initializer reconstructs and drops only its own box; exclusive drop
  reclaims the published box once. Its `Sync` implementation requires both
  the value and initializer to be `Send + Sync`. The unselected allocation-free
  variant uses atomic `INIT`, `BUSY`, and `DONE` states around `Cell` storage,
  publishes initialized data with release semantics, reads it with acquire
  semantics, and resets to the poisoned path if initialization unwinds.
- Pool safety: monotonic thread-local IDs and reserved sentinel values make
  the owner identity unique; counter wrap panics before an ID can be reused.
  An atomic compare-and-exchange grants the owner slot to one thread, and the
  slot is initialized before its guard is returned. Non-owner values remain
  behind mutex-sharded stacks. The guard retains the original owner ID, so a
  guard dropped on a different thread restores the correct owner. Its
  `ManuallyDrop` and dropped sentinel prevent a value from being returned
  twice. These invariants support `Sync` for a pool whose stored value is
  `Send` but need not itself be `Sync`.
- Serialized automata safety: wire casts convert aligned `u32` slices to
  representation-transparent state or pattern identifiers of the same size
  and alignment. Accelerator casts check byte length and alignment, and their
  safe constructor restricts accelerator lengths to one through three. Safe
  dense and sparse deserializers validate state classes, transition and start
  tables, special-state ranges, accelerators, and referenced state IDs before
  returning an automaton. Their public unchecked alternatives and the unsafe
  `Automaton` trait state the caller's validity contract explicitly. Dense
  unchecked indexing relies on validated or builder-created tables; sparse
  lookup remains checked. Search loops check haystack bounds and propagate
  only valid state IDs.
- Hybrid safety: unchecked cached transitions require an untagged state from
  the same current cache, as the public unsafe contract states. Safe search
  code checks input bounds and tagged cache states, and recomputes unknown
  transitions through the cache before using them. Rustleaks does not select
  or construct the hybrid engine.
- Parser and NFA behavior: `regex-syntax` returns structured syntax errors.
  Thompson compilation uses explicit heap stacks for HIR traversal and UTF-8
  range construction, validates capture and state identifier limits, and
  returns build errors for configured NFA-size exhaustion. Builder panics
  document low-level sequencing preconditions such as pairing
  `start_pattern` with `finish_pattern`; the high-level compiler maintains
  them. Range-trie and UTF-8 node unwraps enforce non-empty and bounded
  internal structures constructed by the compiler.
- PikeVM behavior: matching maintains two sparse active-state sets, two
  capture-slot tables, an epsilon-closure stack, and caller-visible capture
  slots. State-set insertion prevents duplicate epsilon traversal. Search
  advances within checked input spans, state IDs originate in the compiled
  NFA, and capture slot IDs originate in validated group metadata. Public APIs
  can panic if a caller mixes caches between PikeVM instances or supplies an
  invalid span; Rustleaks creates the cache from the same instance and builds
  spans from checked byte positions. The PikeVM search implementation itself
  has no fallible match path for Rustleaks to unwrap.
- Resource boundary: Rustleaks caps each source pattern at 1 MiB, syntax
  nesting at 4,096, nested repetition products at 1,000, and the compiled NFA
  at 256 MiB. Compilation above 200 opening parentheses runs on a named 32 MiB
  stack and converts a thread panic into a structured error. Before any PikeVM
  cache allocation, Rustleaks conservatively estimates both capture-slot
  tables, caller capture slots, both sparse state sets, and the epsilon stack.
  It rejects overflow or an estimate above 256 MiB. The merged regression at
  baseline commit `57d9341b02d8d69143be39ca631c6a5d77fd8b4c` proves the
  estimate covers dependency-reported cache memory for an accepted pattern
  and rejects a 4,096-capture pattern before cache creation.
- Time and allocation: PikeVM matching is linear in the haystack for a fixed
  NFA and can perform work proportional to the product of haystack length and
  active NFA states. Captures and result collection allocate according to the
  bounded compiled expression and matches in caller-owned input. The stated
  compile and working-set controls do not include allocator overhead, result
  vectors, or ordinary allocation failure, and do not promise a strict
  wall-clock or total-process-memory limit.
- Panic boundary: selected production unwraps enforce identifier widths,
  compiler stack shape, capture metadata, valid UTF-8 range construction, and
  checked index progression. Rustleaks' source, nesting, repetition, NFA, and
  pre-cache working-set checks prevent hostile configuration from reaching
  the dependency's documented slot-table overflow concern. No ordinary
  untrusted Rustleaks pattern or haystack reaches an unexplained panic or
  memory-safety path. Allocation failure can still abort, as for ordinary Rust
  allocation.
- Native and authority boundary: the archive has no build script, external
  function, native library, C or C++ source, generated production source, or
  `links` declaration. Selected production code opens no file or socket,
  reads no environment variable, starts no process, and writes no log. The
  utility pool uses thread-local identity and exposes an available-parallelism
  capacity helper; the direct PikeVM path does not call that helper. Logging,
  thread-local PikeVM instrumentation counters, meta-engine pools, and their
  available-parallelism query are unselected. Thread spawns elsewhere in the
  archive are tests.
- Published-source evidence: locked default and all-feature library suites
  each passed 204 tests, the locked featureless library suite passed 20 tests,
  and the exact locked Rustleaks feature set passed 111 tests. Locked
  all-feature doctests passed 459 tests with 2 ignored. These cover NFA
  building, parsing, captures, PikeVM matching, look assertions, state sets,
  lazy initialization, thread-aware pool ownership, wire formats, dense and
  sparse DFAs, hybrid caches, and malformed-state regressions.
- Upstream workspace evidence: at the exact packaged VCS commit, the selected
  feature set passed 111 library tests and 3 PikeVM integration tests. The
  all-feature integration target passed 60 tests, including serialized DFA,
  hybrid cache, fuzz regression, capture-slot, and regex corpus cases. These
  runs used an offline temporary resolution of current compatible development
  dependencies because the historical workspace lockfile is not accepted by
  current Cargo.
- Upstream evidence limits: the published integration target cannot compile
  outside its workspace because it references test data two directories above
  the crate. Its all-feature target also references a deliberately excluded
  fuzz module and generated DFA binary fixtures that are absent from the
  archive. No passing published-archive integration result is claimed; the
  exact-commit workspace runs above supply that evidence without changing
  production source.
- Conclusion: the complete source review, unsafe invariant analysis, bounded
  direct PikeVM path, parser and search resource controls, upstream and
  Rustleaks tests, advisory results, and license evidence support
  `safe-to-deploy` for the locked Rustleaks graph. The documented low-level
  caller contracts and resource limitations do not require an exception and
  remain part of the dependency boundary.
