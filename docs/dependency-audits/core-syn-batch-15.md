# Core dependency audit: syn batch 15

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`ac9d6ddfcbc0c553066ea697c87fcb347c4a607c`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency of the `serde_derive` and
`thiserror-impl` procedural macros. It is therefore reachable from the
publishable core and five other workspace consumers, but executes while those
crates are compiled rather than in a deployed Rustleaks process. Its exact
consumers, selected features, target expressions, build-script status,
`links` value, checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. It applies to every declared target, has no
packaged build script or `links` value, and selects `clone-impls`, `derive`,
`parsing`, `printing`, and `proc-macro` through the default feature. Its exact
normal dependencies are the separately audited `proc-macro2 1.0.107`,
`quote 1.0.47`, and `unicode-ident 1.0.24`.

The review covered all 66,921 lines of packaged Rust source, including 51,754
lines under `src`, manifests, package lockfile, licenses, README, benchmarks,
tests, generated modules, and every selected and unselected production
feature. A fresh RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact 71-package Rustleaks
lockfile. Exact-package GitHub Advisory Database and upstream repository
security-advisory queries returned no record. MIT OR Apache-2.0 matches
`deny.toml`; both license texts are packaged and there is no `NOTICE` file. No
peer audits, wildcard trust, criteria changes, or exceptions were used.

## `syn 3.0.4`

- Archive: `syn-3.0.4.crate`; SHA-256
  `e6275cddf4610d1775e6d1fe9469b2e77d0f39fd98fb7450901b821e0c53649f`.
  The packaged VCS identity is verified upstream commit
  `b5d62a6e43a29418e118b7bcb48e211cefc0154f` at the repository root. All 104
  archive members are regular files with mode `0644`. A fresh extraction
  matched cargo-vet's source byte for byte apart from Cargo's `.cargo-ok`
  marker. `LICENSE-MIT` and `LICENSE-APACHE` have respective SHA-256 values
  `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`
  and `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`.
- Rustleaks use: `serde_derive` parses derive inputs, attributes, generics,
  paths, types, expressions, and literals before emitting Serde
  implementations. `thiserror-impl` parses error enums, structs, attributes,
  formats, types, and generics before emitting error implementations. Those
  two generators have separate local audits of their parsing, validation,
  generated code, and failure behavior. Rustleaks does not expose a `syn`
  type in a public API or parse runtime configuration, findings, files, or
  archives with this package.
- Unsafe inventory: actual unsafe code is confined to five production files.
  `buffer.rs` implements the flattened token buffer and cursors. `parse.rs`
  and `discouraged.rs` erase and restore cursor lifetimes inside sealed parse
  buffers. `thread.rs` guards compiler spans by their creating thread.
  `token.rs` exposes the single span of one-character punctuation through a
  transparent layout. Selected and unselected syntax-tree, printer, clone,
  equality, hash, fold, and visitor implementations otherwise use safe Rust.
- Token buffer safety: construction flattens each token tree into an immutable
  boxed slice. Every group entry receives a forward offset to its matching end
  entry, every end entry receives a backward offset to the buffer start and
  group start, and one final end sentinel terminates the outer scope. Cursors
  borrow the buffer through `PhantomData`, expose no pointer fields, and move
  only by those recorded offsets or by one checked token position. Group and
  lifetime operations always retain an in-slice scope sentinel. None-delimited
  groups may be skipped transparently, but their end entries are traversed
  only while another live scope entry follows. The static empty cursor contains
  only an end entry, so its narrow manual `Sync` implementation cannot expose
  a thread-bound identifier or span.
- Cursor and parser lifetime safety: `ParseBuffer` stores a cursor with an
  erased static lifetime solely to preserve covariance, while its private
  lifetime marker ties every returned cursor to the token buffer. The sealed
  higher-ranked `step` closure cannot return a cursor unrelated to its input
  except a static empty cursor. Its invariant `StepCursor` proves that the
  closure cursor outlives the parse buffer before the lifetime is shortened.
  Speculative `advance_to` accepts only a fork with the same scope pointer and
  panics before assigning a cursor from another live buffer. Nested group
  construction uses the same proof and retains the parent buffer. No safe API
  can construct an arbitrary cursor or extend a buffer borrow.
- Thread-bound safety: compiler `Span` values are stored in a private
  `ThreadBound<SpanRange>`. Shared access compares the current thread ID and
  returns no reference on a different thread. The manual `Send` and `Copy`
  implementations require `T: Copy`; such a value cannot contain
  `UnsafeCell` or a destructor under current Rust rules. Cross-thread error
  formatting falls back to call-site spans. The package queries the current
  thread ID but does not create or manage threads.
- Token layout safety: one-character punctuation structs contain exactly
  `[Span; 1]` and are representation-transparent in production builds. Their
  dereference casts target the separately representation-transparent
  single-`Span` helper. Multi-character punctuation does not receive this
  implementation. The cast therefore preserves size, alignment, validity,
  provenance, and exclusive-borrow rules.
- Parsing and generation behavior: parser entry points first obtain a
  `proc_macro2` token stream, build the token buffer, and require complete
  consumption unless a nested parser deliberately owns a delimited scope.
  Invalid syntax returns spanned errors. Lookahead is limited to three tokens
  unless a macro author explicitly forks a stream. `parse_quote!` intentionally
  panics when developer-generated quoted tokens do not match the requested
  syntax-tree type. Public literal, lifetime, punctuation, range, and
  punctuated constructors also document or enforce developer-facing validity
  preconditions. Internal unwraps and unreachable branches follow token-kind,
  nonempty-path, punctuation-state, or previously validated grammar checks.
- Resource behavior: token-buffer storage and syntax trees allocate in
  proportion to compiler input, and speculative parsing can repeat work if a
  macro author parses an unbounded fork. Token groups, nested syntax trees,
  printing, cloning, and optional visitors contain recursive paths; sufficiently
  deep developer source can exhaust the compiler thread stack. The crate
  imposes no independent token, allocation, recursion, or wall-clock limit.
  These are compile-time availability properties of developer-controlled Rust
  source. They are not reachable from runtime hostile Rustleaks input. Ordinary
  allocation failure can abort compilation.
- Generated source: `src/gen/clone.rs` is selected. The unselected generated
  debug, equality, hash, fold, visit, and visit-mut modules are also packaged
  and were reviewed. Running the exact-commit upstream generator reproduced
  every file under `src/gen` without a diff. The upstream-only `build.rs`
  probes whether development tests can use compiler-private APIs, but the
  package include list omits it and the normalized registry manifest sets
  `build = false`; no build script executes for the audited package.
- Native and authority boundary: the archive has no native source, external
  function, native library, or generated-at-build production source. Library
  code opens no file or socket, reads no environment variable, starts no
  process, and writes no log. File and process examples are documentation
  only. Its compiler capability is limited to consuming and constructing
  token streams and spans supplied through `proc_macro` and `proc_macro2`.
- Published-source evidence: the exact selected feature set, the featureless
  library, and every production feature together compiled from the archive.
  The published test target cannot compile because crates.io replaces the
  workspace-only `syn-test-suite` development dependency with an intentional
  one-token invalid placeholder. No passing published-archive test result is
  claimed.
- Upstream evidence: the packaged `src` and licenses match the exact VCS
  commit byte for byte. Using a temporary current-compatible development
  resolution, the all-feature release library and 22 stable-compatible
  integration targets passed 138 tests with 5 size checks ignored. All 109
  all-feature documentation tests passed. Strict-provenance Miri passed 23
  targeted token-buffer, parsing, grouping, token, and literal tests with one
  unwind-safety test intentionally ignored under Miri. The complete upstream
  compiler-comparison suite additionally requires a nightly `rustc-dev`
  component that was not installed or added for this audit. No passing result
  for that suite is claimed.
- Conclusion: the complete source and unsafe-invariant review, exact-commit
  provenance, generated-source reproduction, selected-feature compilation,
  targeted Miri evidence, tests, advisory results, and separate audits of the
  consuming code generators support `safe-to-deploy` for the locked
  Rustleaks graph. The documented compile-time recursion and developer-misuse
  panic boundaries do not require an exception.
