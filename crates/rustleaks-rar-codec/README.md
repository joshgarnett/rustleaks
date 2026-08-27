# rustleaks-rar-codec

This is a private, dependency-free extraction of the RAR3 and RAR5 codec
implementation from `bitplane/rars` commit
`1f4f885577485d954c5e9a470a728d0111dc6f11` (upstream version 0.9.3).
The explicit upstream `COPYING` file is retained verbatim.

The package is isolated because the upstream crate requires Rust 1.87 and
also brings archive writing, encryption, recovery, parallelism, and filesystem
features that the source library does not need. This fork targets Rust 1.88,
forbids unsafe code, and has no dependencies. The codec files retain upstream
encoder helpers so the fork remains mechanically comparable, but
`rustleaks-sources` calls only the RAR3 and RAR5 decoder state machines. The
caller remains responsible for checked container parsing, CRC validation,
resource ceilings, cancellation, and error classification.
