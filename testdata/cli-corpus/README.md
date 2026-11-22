# CLI corpus

These cases run the `rustleaks` binary with one command line each and check
what it does. `//crates/xtask:cli_regression_test` replays them; the code is
in `crates/xtask/src/tooling/cli_corpus/`.

The cases were recorded from Gitleaks at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and from Rustleaks, and are MIT
licensed (see the repository [NOTICE](../../NOTICE)). The expected values are
the expected Rustleaks behavior.

## Files

| File | Contents |
| --- | --- |
| `requests-v1.jsonl` | One line per case, `CLI-BB-001` onward, each with its variants |
| `outcomes-v1.jsonl` | The expected observation of each variant, in the same order |
| `negative-controls-v1.json` | Changes to an observation that the comparison must reject |

A request variant names a fixture `setup`, the `args`, `stdin_base64`, `env`,
an optional `report_path`, where findings are read from (`finding_source`),
an optional `prepare` step and an `expectation` hint. The fixtures are built
in `fixture.rs`.

An outcome variant has `expected` and, where Windows behaves differently,
`expected_windows` (a list of accepted observations). An observation holds:

- `exit`: the exit status;
- `stdout_base64`, `stdout_bytes` and `stdout_sha256`, except for help
  requests, whose stdout is not compared;
- `stderr_events`: the severity, class and structured fields of each log
  line, without its message text;
- `stderr_usage_printed`: whether a usage block was printed. Its lines are
  not events;
- `report`: the report file state and bytes, when the case asks for a
  report;
- `findings` and `finding_count`: the findings, in a fixed order;
- `child_reaped`: whether timed-out child processes were cleaned up; and
- `stderr_contains_disclosure_marker`: whether stderr printed a marker that
  must stay hidden.

Byte fields are standard base64. Stdout and report bytes use `<VERSION>` for
the Rustleaks version and `<TMP>` for the temporary folder.

## Changing a case

Help, usage and message wording are not compared here; the tests in
`crates/rustleaks-cli/tests/` check them. The replay still finds each event's
class from keywords in its line (see `normalize.rs`), and banner lines are
events, so a wording change can change a class and fail the replay. Then
check that the new class is right and update the case. Change an outcome only with a
reviewed change to the behavior it covers, and write the new value from the
intended behavior, not from the current output. Update `*_bytes` and
`*_sha256` when the bytes change.
