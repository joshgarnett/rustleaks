# rustleaks-rar-codec

Safe RAR3 and RAR5 decoders and the RAR CRC-32 for the Rustleaks archive
sources. The crate has no dependencies. The caller parses the container,
checks CRCs, sets resource limits, handles cancellation and classifies
errors.

The crate is internal to Rustleaks and is not published. Only
`rustleaks-sources` uses it, behind its `archives` feature. It calls the RAR3
and RAR5 decoders and the CRC-32. The RAR3 and RAR5 encoders are compiled only
for this crate's tests, which encode data and decode it back.

- Upstream: [`bitplane/rars`](https://github.com/bitplane/rars) 0.9.3.
- License: the upstream `COPYING` file, kept unchanged. It states the WTFPL
  with one extra clause ("don't blame me"). `deny.toml` records it as
  `LicenseRef-Rustleaks-Rar-Codec`.

See [Dependencies](../../docs/dev/dependencies.md#archive-codec-decision) for
the upstream commit and archive SHA-256, the changes from upstream, the reason
for the fork and the conditions for replacing it.
