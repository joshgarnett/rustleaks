# Using Rustleaks from Python

This guide is for Python developers who want to scan bytes or text for
secrets inside their own program. The `rustleaks` package runs the same
engine as the `rustleaks` command, in your process. It scans data that you
give it; it does not read files, run Git or write reports.

The package is listed under Unreleased in the [changelog](../../CHANGELOG.md)
and is not in a release yet.

## Requirements

- CPython 3.12, 3.13, 3.14 or 3.15, in the standard build with the GIL.
- One of the eight supported targets: Linux x86_64 or ARM64 with glibc or
  musl, macOS on Intel or Apple silicon, or Windows x86_64 or ARM64.

The package uses only the Python standard library. It loads the native
library from the `_native` folder inside the package, by absolute path. It
never searches the current folder or `PATH` for it.

Free-threaded CPython, PyPy and subinterpreters are not tested. The package
does not refuse them, but nothing checks that it works there.

The package version and the native library version are the same. If the
library is missing, is built for another architecture or has another
version, creating an engine raises `LibraryError`.

## Install

The package is not published yet. To try it from a checkout of this
repository, build the wheel for your platform with Bazel and install it
with pip. Pick the `release-bindings-*` configuration in `.bazelrc` that
matches your platform, for example on Linux x86_64 with glibc:

```sh
bazelisk build --config=release-bindings-linux-x86_64-gnu //release/python:wheel
python -m pip install bazel-bin/release/python/rustleaks-*.whl
```

## A first scan

`Engine()` with no arguments loads every [built-in rule](built-in-rules.md).
Building an engine compiles every rule, so build it once and reuse it.

```python
import rustleaks

data = b'aws_key = "AKIALALEMEL33243OLIB"\n'  # rustleaks:allow
with rustleaks.Engine() as engine:
    findings = engine.scan(data, path="config/app.env")

finding = findings[0]
assert finding.rule_id == "aws-access-token"
assert finding.secret == data[11:31]
assert finding.start_line == 1
assert finding.path == "config/app.env"
print(finding)  # The repr leaves out the secret.
```

The value in the example is synthetic test data. The `rustleaks:allow`
comment is outside the scanned bytes and does not change the result.

`scan` returns a list of `Finding` values in report order. An empty list
means that the whole input was scanned and nothing was found. A scan that
stops early raises an error instead; see [Errors](#errors).

## Choosing rules

| Argument | Rules |
| --- | --- |
| Nothing | Every built-in rule. |
| `rules=["aws-access-token", "github-pat"]` | Only the named rules, like `--enable-rule`. An unknown ID raises `ConfigError` with `kind == "rule_selection"`. |
| `config=toml` | The rules in your TOML configuration, in the format described in [Configuration](configuration.md). They replace the built-in rules. |
| `config=toml` with `[extend] useDefault = true` | The built-in rules and your rules. |

`config` takes a `str` or UTF-8 `bytes`. A configuration with
`[extend] path = "..."` raises `ConfigError`, because the package reads no
files. Read the base file yourself and pass its text, or use
`useDefault = true`.

```python
import rustleaks

config = """
[extend]
useDefault = true

[[rules]]
id = "example-marker"
description = "An example rule"
regex = '''MARK-([A-Z]{4})'''
secretGroup = 1
keywords = ["mark-"]
"""

with rustleaks.Engine(config=config, rules=["example-marker"]) as engine:
    print([rule.id for rule in engine.rules()])
    findings = engine.scan(b"token: MARK-ABCD\n")
    assert [finding.secret for finding in findings] == [b"ABCD"]
```

`Engine.rules()` returns the rules that can report findings, in report
order, as `Rule` values with `id`, `description`, `tags` and `keywords`.

## Options and defaults

Every option is a keyword argument of `Engine`. `None`, the default, keeps
the value of the native library.

| Option | Default | Meaning |
| --- | --- | --- |
| `workers` | One per CPU, up to 12 | How many scans the engine runs at once, from 1 to 256. |
| `max_input_bytes` | 10,000,000 | The largest input, in bytes. A longer input raises `InputTooLargeError`; it is never skipped. `rustleaks.UNLIMITED` turns the limit off. |
| `budget` | 100,000 finding records | A `Budget` with limits for each scan. See [Budgets, timeouts and cancellation](#budgets-timeouts-and-cancellation). |
| `allow_comments` | `True` | Whether a `rustleaks:allow` or `gitleaks:allow` comment on a line hides its findings. |
| `decode_depth` | 0 | How many levels of base64, hex, percent and Unicode escapes to decode. 0 does not decode. |
| `base64_mode` | `"compatible"` | `"compatible"` or `"extended"`, as `--base64-mode` in the [command reference](cli-reference.md). |
| `redaction` | 0 | The percent of each secret to hide, from 0 to 100. See [Logging findings safely](#logging-findings-safely). |

Three defaults differ from the `rustleaks` command:

- The command decodes 5 levels. The package decodes none unless you set
  `decode_depth=5`.
- An input longer than 10,000,000 bytes raises `InputTooLargeError`. The
  command reads large files in parts and has no such limit.
- A scan stops with `BudgetExceededError` after 100,000 finding records.
  The command sets no finding record limit.

Allow comments are honored, as in the command. Anyone who can write the
scanned content can hide a secret with one. When you scan content that
other people write, such as uploads or messages, set
`allow_comments=False`.

`scan` and `scan_text` take `allow_comments`, `decode_depth`,
`base64_mode`, `redaction` and `budget` too. A value there applies to that
scan only.

```python
import rustleaks

config = """
[[rules]]
id = "example-marker"
regex = '''MARK-([A-Z]{4})'''
secretGroup = 1
keywords = ["mark-"]
"""

with rustleaks.Engine(config=config, allow_comments=False) as engine:
    line = b"token: MARK-ABCD  # rustleaks:allow\n"
    assert len(engine.scan(line)) == 1
    assert engine.scan(line, allow_comments=True) == []
    (finding,) = engine.scan(b"token: MARK-ABCD\n", redaction=100)
    assert finding.secret == b"REDACTED"
```

## Bytes, text and offsets

`scan` takes any bytes-like object: `bytes`, `bytearray`, `memoryview`,
`array.array` or any other object with the buffer protocol. A `bytes`
object is passed to the native library without a copy. Any other object is
copied once, before the scan, so changing it during the scan does not change
the result.

`scan_text` takes a `str` and encodes it as strict UTF-8. Text with a lone
surrogate, such as `"\ud800"`, raises `TextEncodingError`. The error holds
the index of the character, not the text.

Every offset and column counts bytes of the scanned input. For text, that is
UTF-8 bytes, not characters:

```python
import rustleaks

config = """
[[rules]]
id = "example-marker"
regex = '''MARK-([A-Z]{4})'''
secretGroup = 1
keywords = ["mark-"]
"""

with rustleaks.Engine(config=config) as engine:
    text = "é MARK-ABCD"
    (finding,) = engine.scan_text(text)
    # "é" takes two bytes in UTF-8.
    assert finding.secret_range == range(8, 12)
    assert text.encode()[finding.secret_range.start:finding.secret_range.stop] == b"ABCD"
```

The input limit applies to the encoded bytes. `scan_text` rejects a `str`
with more characters than the limit before it encodes it.
`engine.max_input_bytes` gives the engine's limit.

`path` is the path that path rules and path allowlists test, as a `str` or
an `os.PathLike` value. Findings report it unchanged. An empty path is the
same as no path. On Windows, rule path patterns test a path with `\`
separators both as given and with `/` separators.

## Findings

A `Finding` is a frozen dataclass:

| Field | Meaning |
| --- | --- |
| `rule_id`, `description`, `tags` | The rule that matched. Findings in decoded text also have `decoded:NAME` and `decode-depth:N` tags. |
| `secret`, `match`, `line` | `bytes`: the secret, the text that the rule matched, and the line that holds the match. |
| `start_line`, `end_line`, `start_column`, `end_column` | The same values as the report fields of the command. See [Line and column numbers](reports.md#line-and-column-numbers). |
| `secret_range`, `match_range` | `range` of byte offsets into the input, or `None` when no exact range exists, as for decoded text. |
| `entropy` | The Shannon entropy of the secret. |
| `path` | The `path` given to the scan, or `None`. |

Lines count from 1. Columns count bytes from 1 on the first line of the
input, and are 1 higher on every later line, as in the command's reports. A
finding of a rule that has only a `path` pattern, such as `pkcs12-file`, has
line and column 0 and no ranges. Use the ranges, not the columns, to find
the secret in the input. On every line after the first, `line` starts with
the line break that ends the line before it, as in `b"\nsecond = ..."`.

Findings with the same long line share one `bytes` object for `line`, so
many findings on one large line do not copy it many times.

## Errors

Every error of the package is a subclass of `rustleaks.Error`. Wrong
argument types raise `TypeError` and bad values raise `ValueError`. A
`bool` is not accepted where a number is expected.

| Error | When |
| --- | --- |
| `ConfigError` | The configuration does not load (`kind == "config"`) or a selected rule does not exist (`kind == "rule_selection"`). The message can quote configuration text. |
| `InputTooLargeError` | The input is longer than `max_input_bytes`. It has `size` and `limit`. |
| `IncompleteScanError` | The scan stopped early. Its subclasses are `ScanCancelledError`, `ScanTimeoutError` and `BudgetExceededError`. |
| `ClosedError` | The engine is closed, or was created before the process forked. |
| `LibraryError` | The native library cannot be used, or failed inside. `kind` is `"load"` (missing, cannot load or lacks an export), `"version"` (another ABI number or version), `"engine"` (a failure outside the configuration, such as a thread that cannot start in a restricted process) or `"panic"` (the library caught an internal error). |
| `TextEncodingError` | Text that UTF-8 cannot encode, such as a lone surrogate: the text given to `scan_text`, a `path`, a `config` string or a rule ID. A path from `os.listdir` or `os.walk` with a name that is not valid in the file system encoding holds such surrogates. |

A status that this version of the package does not name raises
`rustleaks.Error` itself.

An `IncompleteScanError` has `termination` (`"cancelled"`, `"timeout"`,
`"budget"` or `"other"`) and `usage`, a `Usage` value with what the scan
used. For a budget, `budget` names the budget that ran out, and `limit`,
`consumed` and `requested` give its limit, the amount used and the amount
asked for. A scan that stops early returns no findings, because they would
not be a full result.

## Budgets, timeouts and cancellation

A `Budget` limits one scan. Each field is a number, `rustleaks.UNLIMITED`,
or `None` to keep the value that applies already:

- `decoded_bytes`: bytes produced by decoding.
- `work_units`: an internal count of detection steps. It has no fixed time
  cost, and the count for the same input can change between releases.
- `finding_records`: finding records, 100,000 by default. The engine counts
  a record before its last filters, so a scan can stop at this limit with
  fewer findings than the limit.
- `finding_payload_bytes`: bytes held by findings.
- `collected_spans`: candidate matches. Any limit here, even a large one,
  turns off the literal-anchored search that the engine uses for some rules
  with keywords, so those rules search more of the input and scans can take
  longer.
- `normalization_bytes`: bytes produced by text normalization.

A budget on the engine applies to every scan, and a budget given to `scan`
overrides it field by field. See [Budgets and
cancellation](library.md#budgets-and-cancellation) for what the engine
counts.

`timeout` is a number of seconds. It covers the wait for a free worker and
the scan itself. When it passes, the scan raises `ScanTimeoutError`. A scan
that completes returns its findings, even if the timeout passed after the
engine's last check. Set a timeout or a budget when you scan input that
other people control.

A `CancelToken` stops the scans that it is passed to. Call `cancel()` from
any thread. A cancelled token stays cancelled.

```python
import threading

import rustleaks

with rustleaks.Engine() as engine:
    token = rustleaks.CancelToken()
    threading.Timer(0.01, token.cancel).start()
    try:
        engine.scan(b"password = 'x'\n" * 100_000, cancel=token, timeout=30)
    except rustleaks.IncompleteScanError as error:
        print("stopped:", error.termination)
```

Cancellation is not immediate. The engine checks the token and the timeout
between steps, and one pattern search cannot be interrupted.

Python runs signal handlers, and raises `KeyboardInterrupt` for Ctrl-C, only
between native calls, so an interrupt during a scan waits until the scan
returns. To stop long scans on Ctrl-C, give them a `timeout`, or set their
`CancelToken` from the signal handler.

## Threads and closing

An `Engine` can be used from many threads at once. Native calls release the
GIL, so scans on different threads run in parallel. The engine runs at most
`engine.workers` scans at a time; other scans wait for a free worker, and
the wait counts against their timeout.

Detection is synchronous. To scan from `asyncio` code, run the scan on a
thread, for example with `asyncio.to_thread(engine.scan, data)`.

`close()` stops new scans, waits for the scans that are running, and frees
the engine. It does not cancel them. Later scans raise `ClosedError`.
Calling `close()` again does nothing. A `with` block calls `close()` at the
end. An engine that is not closed is freed when it is garbage collected.

Do not call `close()` from a signal handler or from another place that can
run in the middle of a scan on the same thread. It would wait for that scan,
which cannot finish. When the scan is already running in the library,
`close()` sees this and raises `RuntimeError`. When the signal arrives while
the thread is still starting or ending a scan, `close()` can wait forever.
In a signal handler, set a `CancelToken` or a flag, and close the engine
after the scan returns.

Engines, tokens and findings cannot be pickled. Engines and tokens cannot be
copied.

## Fork

After `os.fork()`, engines created before the fork are closed in the child,
and their scans raise `ClosedError`. The child can create new engines. This
keeps servers that fork worker processes working: create the engines in the
workers, or create new ones there. Python warns about `fork` in a process
with threads, and every engine has native threads. Prefer the `spawn` or
`forkserver` start methods of `multiprocessing` when you can.

## Logging findings safely

Findings hold secret bytes in memory, and they are not erased when they are
freed. The same is true of your input.

- `repr(finding)` and `str(finding)` show the rule and the position, never
  `secret`, `match` or `line`. Log the finding itself, or the fields you
  need, not those three fields.
- Error messages never hold scanned bytes. A `ConfigError` message can
  quote configuration text.
- The traceback of an error from `scan` or `scan_text` holds the frames of
  the package, and their local variables hold the input. An error reporter
  that records local variables, as some crash reporting services do, sends
  the scanned bytes with the error. Turn that option off, or catch the
  error and report a new one.
- `redaction=100` replaces each secret with `REDACTED` in `secret`,
  `match` and `line`. A lower percent keeps the start of the secret and
  replaces the rest with `...`. For a finding in decoded text, the whole
  `line` becomes the replacement, because the line holds the secret in
  encoded form.
- `dataclasses.asdict(finding)` and similar helpers copy every field,
  including the secret.
