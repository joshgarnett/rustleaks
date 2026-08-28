# Core dependency audits: procedural macro batch 3

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`943c28d203de4edab824097dc2bc00f612616e6d`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The three packages are normal dependencies reachable from the publishable
core. Their exact workspace consumers, enabled features, target expressions,
build-script status, `links` value, checksum, and cargo-vet disposition are in
`supply-chain/inventory-v1.json`. All three apply to every declared target,
have build scripts, and have no `links` value. The source archives came from
the crates.io registry source recorded in `Cargo.lock`.

The review covered every packaged production source file, manifest, license,
README, included test, and selected-feature branch. `cargo audit --deny
warnings --color never` found no RustSec warning in the exact locked graph.
Exact-version GitHub Advisory Database queries returned no record for each
package. MIT OR Apache-2.0 matched `deny.toml`. No peer audits, wildcard trust,
criteria changes, or exceptions were used.

## `thiserror 2.0.20`

- Archive: `thiserror-2.0.20.crate`; SHA-256
  `ec86235f5fcc2a73650310756d2ac5b138a5780bbbdfae3eeccec992c435ba4f`.
- Graph: normal dependency through `rustleaks-cli`, `rustleaks-compat`,
  `rustleaks-core`, `rustleaks-report`, and `rustleaks-sources`; selected
  features `default` and `std`. Its only normal dependency is the separately
  audited exact version `thiserror-impl 2.0.20`.
- Code: the runtime crate contains sealed helpers for error sources, display,
  formatting, and generic member provision. It contains no unsafe code and
  performs no file, environment, network, process, thread, logging, or mutable
  global operation at runtime.
- Build: the script writes a deterministic private module under Cargo's
  `OUT_DIR`. It invokes Cargo's configured compiler and wrappers on one fixed,
  packaged probe to detect error generic-member support. The probe has no
  source input, network access, or output outside `OUT_DIR`. Cleanup accepts
  only absence and the documented Linux NFS directory-not-empty race.
- Hostile input and limits: runtime helpers operate on caller-owned values and
  formatting sinks. The derive implementation performs the input-dependent
  parsing and generation and has its own full local audit. The uninhabited
  display placeholder cannot be constructed.
- Evidence: 52 stable packaged tests passed with all features, all targets, and
  warnings denied. The compile-fail suite and two backtrace or option tests
  are explicitly nightly-only and were not run on stable. Rustleaks tests
  exercise the selected stable derive path.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `quote 1.0.47`

- Archive: `quote-1.0.47.crate`; SHA-256
  `1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001`.
- Graph: normal dependency through the procedural-macro stack; selected
  features `default` and `proc-macro`. Its only normal dependency is
  `proc-macro2` with default features disabled and its `proc-macro` feature
  selected through the feature mapping.
- Code: declarative macros and sealed runtime adapters construct token streams,
  interpolate caller-provided token values, and format identifiers. The crate
  contains no unsafe code. Iteration and allocation are bounded by quoted input
  and interpolated iterators. Nested group generation follows macro input
  nesting.
- Invariants: parsing helpers consume only stringified tokens accepted by
  Rust's macro parser. The documented identifier panic validates an explicitly
  constructed name. Lifetime slicing receives stringified lifetime tokens, and
  internal unreachable fallbacks participate only in method resolution for
  supported span types.
- Build: the script invokes Cargo's configured compiler with `--version` and
  emits only compilation configuration. It has no file, network, native-code,
  or generated-source operation.
- Evidence: all 41 stable packaged tests passed with all features, all targets,
  and warnings denied. The compile-fail suite is explicitly nightly-only.
  Tests cover interpolation, repetition, spans, identifiers, literals,
  comments, and type inference.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

## `proc-macro2 1.0.107`

- Archive: `proc-macro2-1.0.107.crate`; SHA-256
  `985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9`.
- Graph: normal dependency through the procedural-macro stack; selected
  features `default` and `proc-macro`. Its only normal dependency is the
  separately audited `unicode-ident 1.0.24`.
- Code: the crate wraps the compiler token API when available and otherwise
  uses an owned parser and token representation. Parsing uses an explicit
  delimiter stack, token-stream destruction is nonrecursive, and work and
  allocation are linear in input size except source-map lookups. Span source
  storage is thread-local and has a documented 4 GiB per-thread location limit
  with explicit invalidation.
- Unsafe invariants: `TokenStream::take_inner` wraps the sole field in
  `ManuallyDrop`, reads that field exactly once, and transfers ownership without
  a duplicate drop. Unchecked literal construction receives only literal
  tokens already validated by Rust's macro parser or strings built by reviewed
  escaping routines. Unchecked UTF-8 is not used on unvalidated bytes in the
  selected source.
- Build and ambient state: the build script compiles fixed packaged probes with
  Cargo's configured compiler and wrappers under `OUT_DIR`, then removes the
  probe output. It emits feature-detection configuration only. The selected
  Rust 1.71-or-newer path uses `proc_macro::is_available`; the legacy global
  panic-hook probe is unreachable for the package's declared Rust version.
- Failure behavior: public constructors intentionally panic on invalid
  identifiers, unsupported punctuation, nonfinite floats, or invalid access to
  compiler-only spans. Compiler/fallback mismatch panics guard internal mode
  invariants. Checked parsing returns `LexError` and validates input with the
  fallback parser before invoking compiler parsing.
- Evidence: 73 active packaged tests passed with all features, all targets, and
  warnings denied. Four size or feature tests were ignored because their
  configuration did not match the all-feature wrapper build. Tests cover token
  parsing and round trips, comments, invalid identifiers and lifetimes,
  literals, spans, invalidation, marker traits, formatting, and size bounds.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.
