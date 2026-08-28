# Core dependency audit: Base64 batch 5

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`88649fcbe3ba3bd3d10904fe019ff1906908d49d`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from every publishable crate,
`rustleaks-compat`, and `xtask`. Its exact workspace consumers, selected
features, target expressions, build-script status, `links` value, checksum,
and cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies
to every declared target, has no build script or `links` value, and has no
normal dependencies. The source archive came from the crates.io registry
source recorded in `Cargo.lock`.

The review covered every packaged production source file, manifest, license,
README, included test, example, benchmark, and selected-feature branch.
`cargo audit --deny warnings --color never` found no RustSec warning in the
exact locked graph. An exact-package GitHub Advisory Database query returned
no record. MIT OR Apache-2.0 matched `deny.toml`. No peer audits, wildcard
trust, criteria changes, or exceptions were used.

## `base64 0.23.1`

- Archive: `base64-0.23.1.crate`; SHA-256
  `ac07cdecf99051d9a5238b80f35af32cdeba5b336e55d957b318b50137e18da5`.
- Graph: selected features `alloc` and `std`, with default features disabled.
  The default `simd-unsafe` feature is not selected. Its 807-line SIMD module,
  runtime CPU detection, and unsafe AVX2 and NEON implementations are outside
  this audit and the locked Rustleaks graph.
- Code: the selected configuration forbids unsafe code. The scalar encoder and
  decoder use fixed lookup tables, checked slice boundaries, and caller-owned
  memory. Custom alphabets reject invalid length, duplicate or non-printable
  bytes, and the selected padding symbol. Production code has no implicit
  file, environment, network, process, thread, logging, native-code, or
  mutable-global behavior.
- Hostile input and limits: scalar decoding advances linearly and rejects
  invalid bytes, lengths, padding, and non-canonical trailing bits. Conservative
  decode sizing cannot overflow `usize`; encode sizing uses checked arithmetic
  and documents that allocating APIs panic when a length is unrepresentable.
  Work and allocation are bounded by input and output length, with no recursive
  parser or input-controlled stack growth.
- Streaming adapters: the selected `std` feature includes bounded-stack
  adapters for caller-provided `Read` and `Write` values. The decoder uses a
  1,024-byte encoded buffer and preserves exact error offsets across reads. The
  encoder uses fixed buffers, preserves unwritten output across partial writes,
  retries interrupted writes, and documents its unusual `Ok(0)` behavior. Its
  finalization loop can keep retrying a delegate that persistently returns
  `Ok(0)`. Rustleaks uses only the in-memory engine APIs, not these adapters.
- Failure behavior: slice APIs return size errors except for the explicitly
  named and documented `decode_slice_unchecked` variant. Remaining panics cover
  documented size overflow, caller misuse after writer finalization, or
  internal UTF-8 and buffer-size invariants established by the reviewed scalar
  engine. The scalar decoder is documented as not constant-time; Rustleaks does
  not use it for authentication or cryptographic key processing.
- Evidence: all 204 packaged unit tests and 13 integration tests passed with
  default features disabled, selected features `alloc,std`, the archive's
  locked graph, and warnings denied. The packaged example and benchmark target
  completed in test mode, and all 26 doc tests passed. Tests cover random and
  exhaustive round trips, malformed bytes and padding, trailing-bit
  malleability, exact output bounds, custom alphabets, short reads, partial
  writes, interrupts, and writer retry state. Optional SIMD tests were excluded.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.
