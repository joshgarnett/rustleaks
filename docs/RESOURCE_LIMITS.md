# Resource and cancellation contract

`rustleaks-core` is synchronous. `Engine::scan_fragment` is the compatibility
wrapper and uses an unlimited, never-cancelled control. Callers handling
untrusted or open-ended work should use `scan_fragment_controlled` with a
`ScanControl` and explicit `ScanBudget`.

Budgets are inclusive and aggregate across one fragment scan:

- decoded bytes count every successful decoded pass before it is scanned;
- work units count documented rule, decoder, keyword, match, required-rule,
  and proximity checkpoints; and
- finding records count materialized primary, auxiliary, and projected
  required findings.

Cancellation is cooperative. It is polled between bounded owned work units,
including between decoder candidates and encoding transforms; one regex
backend evaluation or individual transform remains indivisible. A partial
outcome contains findings only from completed top-level rules and carries
structured termination plus measured usage. Callers must not treat partial
findings as a complete fragment result. The bounded source runner discards a
partially scanned fragment rather than merging its prefix into a session batch.

| Surface | Bound or ownership |
| --- | --- |
| Regex compile | 1 MiB source, nesting 4,096, compiled NFA 256 MiB; limits are per expression |
| Configuration selection | Extension depth 2, 4,096 selected rules or rule-linked entries, 8 MiB selected rule source |
| Controlled fragment | Optional aggregate decoded-byte, work-unit, and finding-record budgets |
| Scan options | Caller-selected decode depth and optional per-target byte limit |
| Ignore input | Individual scanner token limited to 64 KiB; aggregate collection is caller-owned |
| Files | Bounded chunks, optional per-file maximum, symlink hop limit 64 |
| Archives | Default depth 8, entries 10,000, member 64 MiB, total 256 MiB, spool 64 MiB |
| Git | Patch/blob 256 MiB, stderr 1 MiB, metadata 16 MiB, path 1 MiB, files 1,000,000, hunks 2,000,000 |
| Source runner | Bounded workers/queue and 1,000,000 unique commits; workers and child processes are joined/reaped |
| Templates | Source 1 MiB, actions 1,000,000, output 64 MiB, nesting 128 |
| CLI | 4,096 arguments; individual text and path values 1 MiB; normalized paths 4,096 components |
| Streaming reports | Writer capacity, cancellation, and final I/O errors are caller-owned |

Many ordinary Rust allocations remain infallible; out-of-memory may abort.
The CLI timeout is cooperative, not a hard wall-clock deadline. Streaming
sources and reports are intentionally open-ended unless their caller installs
the relevant outer policy.

Compressed RAR3/RAR5 and 7z dependency calls rely on unwind containment for
malformed-input panics. The 7z boundary contains both reader construction and
entry iteration. When the final binary uses `panic=abort`, those paths are
rejected as structured unsupported-archive issues before entering the
dependency; stored RAR members and other owned/safe decoders remain available.

Owned code forbids unsafe. Feature-selected dependencies can contain reviewed
unsafe internals and are documented separately. Native Linux/Windows runtime
measurement remains a nonblocking follow-up; no limit or portability claim is
derived solely from cross-compilation.
