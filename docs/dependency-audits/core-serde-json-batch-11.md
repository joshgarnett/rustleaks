# Core dependency audit: Serde JSON batch 11

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`bf85a7b1ee35021be8da8ba93fcbf5e1f08c0c00`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from the publishable core and
five other workspace consumers. Its exact consumers, selected features,
target expressions, build-script status, `links` value, checksum, and
cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies to
every declared target, has a build script and no `links` value, and selects
only the `default` and `std` features. The locked direct dependencies are
`itoa 1.0.18`, `memchr 2.8.3`, `serde_core 1.0.229`, and `zmij 1.0.23`, plus a
deliberately impossible `cfg(any())` edge to `serde 1.0.229`. Every exact
dependency already has a local `safe-to-deploy` audit. The source archive came
from the crates.io registry source recorded in `Cargo.lock`.

The review covered all 18,329 lines of packaged library source, 4,850 lines of
packaged tests, the 30-line build script, manifests, package lockfile, workflow,
README, contribution guide, VCS metadata, licenses, and every selected and
unselected feature branch. Cargo-vet estimated 24,344 lines for the complete
audit. A fresh RustSec check at advisory database commit
`6420e39260b3d771b049954cf5d52b57e2118da4` found no vulnerability or warning
in the exact Rustleaks lockfile. Exact-version GitHub Advisory Database and
upstream repository advisory queries returned no published record. MIT OR
Apache-2.0 matches `deny.toml`; both license texts are packaged and there is no
`NOTICE` file. No peer audits, wildcard trust, criteria changes, or exceptions
were used.

## `serde_json 1.0.151`

- Archive: `serde_json-1.0.151.crate`; SHA-256
  `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14`.
  The packaged VCS identity is commit
  `de8500740cdcabffb9734f503e4889def823cf10`, at the repository root. All 89
  archive members are regular files with mode `0644`. A fresh extraction
  matched the Cargo registry extraction byte for byte apart from Cargo's
  `.cargo-ok` marker.
- Rustleaks use: core parses caller-provided Gitleaks baseline report bytes
  through `serde_json::from_str` into a private compatibility visitor. The
  visitor handles Go field matching, null and duplicate values, invalid UTF-8,
  and lone surrogate replacement before parsing. Report, source,
  compatibility, CLI, and maintenance components also serialize or parse
  owned data and committed corpora. No `serde_json` type enters the public
  session API.
- Parser boundary: the selected deserializer accepts strings, byte slices, or
  caller-provided readers and returns structured syntax, data, EOF, or I/O
  errors. Parsed arrays and maps retain the default recursion limit of 128.
  Ignored nested values use an explicit byte stack rather than Rust call-stack
  recursion. The unselected `unbounded_depth` feature permits an explicit
  caller opt-out and documents the resulting stack risk. Rustleaks does not
  enable it.
- Serializer boundary: serializers write to caller-provided writers or owned
  vectors and strings. They escape control characters, reject unsupported map
  keys, serialize nonfinite floats as `null`, and propagate writer and custom
  `Serialize` failures. Serialization depth and work are controlled by the
  caller's data and `Serialize` implementation rather than by an independent
  crate limit. Rustleaks serializes owned findings, configuration evidence,
  and reports whose outer limits are maintained by their owning component.
- Selected unsafe code: nine executable unsafe sites are reachable with
  `default,std`. A slice-pointer subtraction uses a chunk derived from the
  same input slice. A string reader skips UTF-8 validation only after starting
  from `str` and validating escapes. WTF-8 scratch writes reserve four bytes,
  write at most four encoded bytes, and set the length to the exact initialized
  extent. Two serializer fragments convert bytes split only at ASCII
  boundaries. One unreachable hint is selected only from the fixed escape
  table. Two owned-string constructors skip validation after the serializer
  has emitted valid UTF-8. `Value` display performs the same conversion for
  output from the default formatter. The focused tests cover control-byte
  search alignment, malformed UTF-8, escapes, strings, and serialization, and
  no violated unsafe invariant was found.
- Unselected unsafe code: `raw_value` contains three transparent conversions
  between `str` and `RawValue` and a public unsafe constructor whose documented
  precondition requires one complete JSON value without surrounding
  whitespace. The representation is `repr(transparent)`, the conversions
  preserve ownership and layout, and all-feature tests cover borrowed and
  owned values, malformed UTF-8, valid input, and debug checks for violated
  constructor preconditions. Rustleaks does not enable `raw_value`.
- Native and build boundary: there is no external function, native library,
  C or C++ compilation, generated Rust source, or `links` declaration. The
  build script reads only Cargo-provided target architecture and pointer width,
  emits checked `fast_arithmetic` configuration, and selects 32-bit or 64-bit
  numeric limbs. Missing Cargo variables fail the build. Both limb
  implementations, their constant tables, and their checked or saturating
  exponent paths were reviewed.
- Ambient authority: production code opens no file or socket, reads no runtime
  environment variable, starts no process or thread, emits no log, and retains
  no mutable process-global state. Reader and writer APIs operate only on
  caller-provided standard I/O traits. Documentation and one test demonstrate
  file, loopback socket, and thread usage, but the package does not acquire
  those capabilities itself.
- Allocation and availability: string scratch buffers, parsed values, and
  output grow in proportion to caller input or values. The float parser's slow
  path retains at most the significant digits needed for the target float;
  `arbitrary_precision`, which retains complete numeric text, is not selected.
  Ordinary allocation failure can abort. `from_reader` reads until EOF and can
  wait indefinitely on a persistent caller-controlled stream. Display, debug,
  clone, drop, and serialization of deeply caller-constructed value trees are
  recursive and have no separate depth cap. `Baseline::from_go_json` receives
  a caller-owned slice, while the existing `Baseline::load_go_json` helper
  reads its named file without a size cap. These caller-owned outer limits and
  allocation-failure behavior remain documented Rustleaks limitations.
- Integer behavior: length-derived exponent calculations in the precise
  lexical parser saturate before narrowing. The selected best-effort float
  path increments an `i32` once per digit after a `u64` significand overflows;
  the source notes that this can overflow only for a multi-gigabyte integer.
  Such input already requires proportional read and normalization memory. It
  can panic in a debug dependency build or wrap in a release build, so callers
  must retain an outer input bound. No ordinary-size integer wrap or
  hostile-input memory-safety path was found.
- Panic and protocol behavior: public mutable indexing panics for a missing key,
  wrong value type, or out-of-range array index as documented. The `json!`
  macro unwraps conversion of interpolated `Serialize` values and can panic if
  a custom implementation fails. Serializer and deserializer `expect` or
  unreachable sites enforce private state transitions or the Serde map access
  protocol and require a faulty caller implementation or an internal defect,
  not JSON bytes alone. A formatting adapter expects `fmt::Error` to accompany
  its stored writer error; a faulty `Display` implementation can violate that
  assumption. Build-script unwraps require an invalid Cargo environment. No
  unexplained panic selected by ordinary hostile JSON was found.
- Selected-feature evidence: warning-denied `cargo check --locked` and
  `cargo check --locked --no-default-features --features alloc` passed. The
  warning-denied default `--all-targets` suite passed 138 tests with one
  nightly-only UI suite ignored. The warning-denied all-feature suite passed
  153 tests with the same UI suite ignored, exercising every optional feature
  reviewed above. The UI harness then passed all 10 compile-fail cases under
  the repository's pinned nightly. Default and all-feature doctests passed 97
  and 106 tests. The Rustleaks core unit and session-corpus Bazel targets then
  passed with test-result caching disabled. These tests cover numeric
  boundaries, recursion rejection and opt-out, malformed strings and numbers,
  UTF-8 and surrogate handling, stream offsets and errors, raw-value
  invariants, serializer protocol errors, and the pinned baseline
  compatibility visitor.
- Conclusion: the complete reviewed source, locally audited exact
  dependencies, selected-feature and all-feature evidence, advisory and
  license results, and Rustleaks reachability support `safe-to-deploy` for the
  locked graph. The resource and caller-protocol limitations above do not
  require an exception and remain part of the documented boundary.
