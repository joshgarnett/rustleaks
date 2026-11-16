# rustleaks-rar-codec

This is a private, dependency-free extraction of the RAR3 and RAR5 codec
implementation from `bitplane/rars` commit
`1f4f885577485d954c5e9a470a728d0111dc6f11` (upstream version 0.9.3).
The explicit upstream `COPYING` file is retained verbatim.

The package is separate because the upstream crate has no decoder-only
feature. It also brings archive writing, encryption, recovery, parallelism
and file system code that the source library does not need. This fork
requires Rust 1.95, the workspace MSRV. It forbids unsafe code and has no
dependencies. The codec files keep upstream encoder helpers so that the fork
stays easy to compare with upstream, but `rustleaks-sources` calls only the
RAR3 and RAR5 decoders. The caller is responsible for checked container
parsing, CRC checks, resource limits, cancellation and error classification.

The crate is not published. See
[Dependencies](../../docs/dev/dependencies.md#archive-codec-decision) for the
decision and the conditions for replacing the fork.
