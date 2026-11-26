# Using the Go package

This guide is for Go developers who want to scan bytes for secrets inside
their own program. The package `github.com/joshgarnett/rustleaks-go` runs the
same engine as the `rustleaks` command, through a small C library written in
Rust. It covers installing the package, scanning, rules, options and
defaults, errors, concurrency, deadlines, findings and safe logging.

The package scans bytes that you give it. It does not read files, archives or
Git history, and it has no baselines, ignore files or fingerprints. For
those, use the [`rustleaks` command](getting-started.md) or [the Rust
library](library.md).

These guides describe the current source. The Go package is listed under
Unreleased in the [changelog](../../CHANGELOG.md) and is not in a release yet.

## Install

The package is not published yet. Its code is in `bindings/go/` of this
repository, where Bazel builds the Rust library and links it into the
package tests:

```sh
just test-go
```

A later release is planned to publish the module
`github.com/joshgarnett/rustleaks-go` with prebuilt libraries for each
system. Until then there is no `go get` command for it.

The package needs Go 1.27 or later.

| System | What the package needs |
| --- | --- |
| Linux and macOS | cgo: a C compiler and `CGO_ENABLED=1`. The package links the Rust static library. |
| Windows x86_64 and ARM64 | No cgo and no C compiler. The package loads the Rust DLL with the `syscall` package, so it builds with or without cgo. See [Windows library](#windows-library). |

On Linux and macOS a build with `CGO_ENABLED=0` fails at compile time with
the error `undefined: rustleaks_needs_cgo_on_linux_and_macos_set_CGO_ENABLED_1`.
The package never builds a detector that finds nothing.

CI runs the package tests on Linux x86_64 and ARM64 with glibc and with
musl, macOS x86_64 and Apple silicon, and Windows x86_64 and ARM64.

## A first scan

The key in this example is synthetic test data, built from two parts so that
the source holds no complete key.

```go
package main

import (
	"context"
	"fmt"
	"log"

	rustleaks "github.com/joshgarnett/rustleaks-go"
)

func main() {
	engine, err := rustleaks.New()
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	input := "string AWSToken = \"" + "AKIA" + "LALEMEL33243OLIB" + "\";\n"
	findings, err := engine.ScanString(context.Background(), input,
		rustleaks.WithPath("src/app.go"))
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range findings {
		fmt.Println(f) // {RuleID:aws-access-token Path:src/app.go StartLine:1 ...}
	}
}
```

Build an `Engine` once and reuse it, because `New` compiles every rule.
`ScanString` takes a `string`
and `ScanBytes` takes a `[]byte`. Both return the findings in report order,
and `nil` when there are none.

## Rules

`New()` with no options uses every [built-in rule](built-in-rules.md), the
same rules as the `rustleaks` command.

| Option | Result |
| --- | --- |
| `WithRules(ids...)` | Keeps only the named rules for findings, like `--enable-rule`. A rule that a kept rule needs through `[[rules.required]]` stays, but does not report findings. |
| `WithConfig(toml)` | Uses your configuration, in the Gitleaks format described in [Configuration](configuration.md), instead of the built-in rules. |
| `WithConfig(toml)` with `[extend] useDefault = true` | Keeps every built-in rule and adds yours. |

A configuration with `[extend] path = "..."` fails with a `*ConfigError`,
because the package reads no files. An empty configuration builds an engine
with no rules, which finds nothing. `WithRules` also works with
`WithConfig`. `Engine.Rules()` lists the rules that can report findings, in
report order, with their ID, description, tags and keywords.

```go
config := []byte(`
[extend]
useDefault = true

[[rules]]
id = "example-ticket"
description = "Example ticket token"
regex = '''TICKET-([0-9]{6})'''
secretGroup = 1
keywords = ["ticket-"]
`)
engine, err := rustleaks.New(rustleaks.WithConfig(config))
```

## Options and defaults

`New` takes engine options. `ScanString` and `ScanBytes` take scan options.
The detection options work in both places: on `New` they set the engine
default, and on a scan they change that scan only.

| Option | Where | Default | Meaning |
| --- | --- | --- | --- |
| `WithWorkers(n)` | `New` | One per CPU the process can use, up to 12 | How many scans run at once. At most 256. |
| `WithMaxInputBytes(n)` | `New` | 10,000,000 | The largest input, inclusive. `rustleaks.Unlimited` turns it off. |
| `WithPath(path)` | Scan | None | The path of the content. Findings report it, and rule path patterns test it. |
| `WithDecodeDepth(n)` | Both | 0, no decoding | How many levels of base64, hex, percent-encoded and Unicode-escaped text to decode. |
| `WithBase64Mode(mode)` | Both | `Base64Compatible` | `Base64Extended` also decodes padded URL-safe and unpadded standard base64. See [Decoding](configuration.md#decoding). |
| `WithAllowComments(honor)` | Both | `true` | Whether a `rustleaks:allow` or `gitleaks:allow` comment hides the findings on its line. |
| `WithRedaction(percent)` | Both | 0, no masking | Masks part of each secret in `Secret`, `Match` and `Line`. 100 gives `REDACTED`. |
| `WithBudget(kind, limit)` | Both | Only `BudgetFindingRecords`, 100,000 finding records | Limits one kind of scan work. See [Budgets](#budgets). |

Two defaults differ from the `rustleaks` command:

- The decode depth is 0. The command decodes 5 levels. Use
  `WithDecodeDepth(5)` to decode as the command does.
- Allow comments are honored, as in the command. Anyone who can write the
  scanned content can add an allow comment to hide a secret. When you scan
  content that other people write, such as uploads or pull requests, use
  `WithAllowComments(false)`.

A bad option value, such as a negative decode depth, makes `New` or the scan
return an error before the library runs.

### Budgets

| Kind | Limits |
| --- | --- |
| `BudgetDecodedBytes` | Bytes that the decoder produces. |
| `BudgetWorkUnits` | Detection steps. A work unit has no fixed time cost, and the count for one input can change between releases. |
| `BudgetFindingRecords` | Finding records. The engine counts a record for each candidate finding before its final filters, so a scan can stop with fewer findings than the limit. The default is 100,000. |
| `BudgetFindingPayloadBytes` | Bytes that findings hold. |
| `BudgetCollectedSpans` | Candidate matches collected. A finite limit turns off a faster search path for some rules. |
| `BudgetNormalizationBytes` | Bytes produced when text is normalized for matching. |

Each limit includes its value. `rustleaks.Unlimited` turns a budget off. A
scan that runs out returns an `*IncompleteError` and no findings. A budget
applies to one scan; if you split one file into many scans, add your own
total limits. See [Resource limits](resource-limits.md) for how budgets
behave in the engine.

## Errors

| Error | When |
| --- | --- |
| `*ConfigError` | `New` could not load the configuration (`KindConfig`), or a rule ID does not exist (`KindRuleSelection`). `Message` is the full message from the engine and can quote configuration text. |
| `*IncompleteError` | A scan stopped early. `Termination` says why: `TerminationCancelled`, `TerminationDeadline`, `TerminationBudget` or `TerminationOther`. For a budget, `Budget`, `Limit`, `Consumed` and `Requested` say which budget ran out, its limit, what the scan used and what the next step asked for. `Usage` is what the scan used. |
| `ErrInputTooLarge` | The input is longer than the input limit. The error wraps it with the sizes. |
| `ErrClosed` | The engine is closed. |
| `*LibraryError` | The native library failed. `Kind` says how: `LibraryLoad` (it could not be found, extracted or loaded, or lacks an export), `LibraryVersion` (its version or ABI number differs from the package), `LibraryEngine` (it could not build or use an engine, for example because a thread could not start) or `LibraryPanic` (it caught an internal panic). |

A scan stopped by its context gives an error where
`errors.Is(err, context.Canceled)` or
`errors.Is(err, context.DeadlineExceeded)` is true. A `nil` context is an
error.

A scan that returns an error returns no findings. Partial findings are not a
full result.

## Concurrency and Close

An `Engine` is safe for concurrent use. Up to `Workers()` scans run at once;
other callers wait for a free worker, and the wait ends when their context
ends.

`Close` stops new scans and frees the engine after the running scans return.
It does not cancel them. Scans that wait for a worker when `Close` starts
return `ErrClosed`. You can call `Close` many times and from many
goroutines, and every call returns after the engine is freed. `Rules` keeps
working after `Close`. If you drop an engine without closing it, the garbage
collector frees it eventually, but call `Close` to free it at a known time.

The library builds each engine on a thread of its own and runs scans on one
thread per worker, each with an 8 MiB stack, so goroutines with small stacks
can call it. In a process that limits threads, starting them can fail, and
`New` returns a `*LibraryError` of kind `LibraryEngine`.

## Deadlines and cancellation

Pass a context with a deadline for untrusted input:

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()
findings, err := engine.ScanBytes(ctx, data)
if errors.Is(err, context.DeadlineExceeded) {
	// The scan ran out of time. There are no findings to use.
}
```

The package passes the deadline to the library, and cancelling the context
sets a flag that the library checks between steps. Cancellation is not
immediate: one pattern search cannot be interrupted. A scan never returns
while the library still reads the input. If the library finishes the scan,
the findings are returned even if the deadline passed after its last check.
A context that can never end, such as `context.Background()`, never stops a
scan.

## Findings

| Field | Meaning |
| --- | --- |
| `RuleID`, `Description`, `Tags` | The rule that matched. Tags include decoding tags, such as `decoded:base64`, for findings in decoded text. |
| `Secret`, `Match` | The secret, and the full text the rule matched. |
| `Line` | The source line that holds the match. |
| `StartLine`, `EndLine`, `StartColumn`, `EndColumn` | The position of the match, with the same values as the `rustleaks` report fields. |
| `SecretRange`, `MatchRange` | Byte offsets into the input, from `Start` up to `End`. `OK` is false when no exact range exists, for example for decoded text. |
| `Entropy` | Shannon entropy of the secret. |
| `Path` | The path given with `WithPath`. |

Lines and columns follow [Line and column
numbers](reports.md#line-and-column-numbers): lines count from 1, and columns
count bytes from 1 on the first line and from 2 on every later line. A rule
that matches only a path, such as `pkcs12-file`, reports line and column 0,
and reports a finding even for empty content. On every line after the
first, `Line` starts with the line break that ends the line before it.

Use `SecretRange` and `MatchRange`, not lines and columns, if you change the
scanned bytes. Do not guess a range whose `OK` is false.

Findings of one scan whose lines are equal share one `Line` string, so many
findings on one long line do not copy it many times.

## Safe logging

Findings hold secret bytes. The `String`, `GoString`, `Format`, `LogValue`
and `MarshalJSON` methods of `Finding` leave out `Secret`, `Match` and
`Line`. So `fmt` (`%v`, `%+v`, `%#v`, `%s`), `slog` with the text or JSON
handler, and `json.Marshal` never write the secret. That holds for one
finding, a pointer to one, the `[]Finding` that a scan returns, and
findings in maps and in exported struct fields. Error messages do not
include the scanned input.

The JSON form has every other field, under the Go field names. To store or
send the secret, match or line, copy them into a type of your own.

`fmt` cannot call the methods of a `Finding` stored in an unexported field
of your own struct, and prints its fields, including the secret.

`f.Redacted(percent)` returns a copy with the secret masked in `Secret`,
`Match` and `Line`, the same way as `WithRedaction`. The package does not
erase inputs or findings from memory.

## Windows library

On Windows the package needs the Rust DLL. It looks for it in this order:

1. The absolute path given to `rustleaks.SetLibraryPath`, called before the
   first `New`.
2. The absolute path in the `RUSTLEAKS_LIBRARY_PATH` environment variable.
3. A DLL embedded in the program. The planned published module embeds one
   for each Windows platform; this repository does not.

The package writes an embedded DLL once to
`<user cache folder>/rustleaks/<version>-<hash>/rustleaks_ffi.dll`, where the
user cache folder is the one `os.UserCacheDir` returns, `%LocalAppData%`.
The new folder inherits the access rules of that folder, which by default
only the user and administrators can change. The file is read-only. The
package checks the SHA-256 of the compressed bytes before it writes them,
and of the written file. A lock that the system releases when its process
ends keeps two processes from writing the file at once.

Before it loads the DLL, the package opens the file so that other handles
can only read it, checks the SHA-256 of an embedded DLL again, and keeps
the file open until the load returns. No other process can change the file
between the check and the load.

The DLL is loaded by absolute path, with only System32 searched for the
DLLs it needs, and is never unloaded. Load failures, including a DLL of
another version, return a `*LibraryError`.

On Linux and macOS the library is linked into the program, and
`SetLibraryPath` and `RUSTLEAKS_LIBRARY_PATH` are not used.
