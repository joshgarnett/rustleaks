# `rustleaks-report` fuzz targets

The limits below describe smoke and extended campaigns. The optional deep
profile admits 64 KiB inputs, 32 KiB template source, 512 actions, 128 KiB
output and 16 findings. The runner records the profile and a synthetic large
literal seed. Separate structured cases check exact source, action and output
boundaries; see the [structured-case contract](../../../docs/SECURITY_STRESS.md).

This is a standalone `cargo-fuzz` package and does not participate in the root
workspace or lockfile.

## `template`

The target frames at most 8 KiB into no more than 4 KiB of arbitrary
byte-preserving safe-template source and up to four bounded findings. Parsing
and rendering use 128 actions and an 8 KiB output ceiling. Parsed arbitrary
templates render both to memory and to a writer that rejects bytes after a
fuzz-selected prefix. A fixed valid template and immediately rejecting writer
prove destination errors propagate on every execution, even when the arbitrary
template is invalid or empty.

Use the maintained private runner from the repository root:

```sh
just fuzz-smoke
just fuzz run --output /private/tmp/rustleaks-report-fuzz-run
```

The output path must be new and outside the checkout; this example uses
macOS's non-symlink temporary directory. Failed runs preserve private evidence;
explicit-output successful runs retain corpus progress. The
[private fuzz workflow](../../../docs/SECURITY_CONTROLS.md#private-local-fuzz-evidence)
describes replay, crash minimization, bounded successful corpus merging and
reviewed local promotion. Direct cargo-fuzz commands can print raw crash
bytes and do not provide the private retention policy.

The target is a bounded panic/hang/resource-pathology check. It does not imply
a universal OOM guarantee or native Linux/Windows runtime execution.
