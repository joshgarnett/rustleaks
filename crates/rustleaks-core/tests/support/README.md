# Test support files

The integration tests in `crates/rustleaks-core/tests/` include these files.
`BUILD.bazel` lists which test gets which file.

## Shared Rust modules

| File | Used by | Contents |
| --- | --- | --- |
| `native_harness.rs` | The five coverage tests below | All built-in rules, and scan, range and entropy helpers |
| `corpus.rs` | `allowlist.rs`, `composite_corpus.rs`, `detect_corpus.rs`, `session_corpus.rs` | The finding record of the corpora under `testdata/`, and JSON Lines and base64 helpers |
| `fuzz_profile.rs` | The core, sources and report fuzz targets, their `security_stress.rs` tests, some `rustleaks-sources` tests, and `xtask` fuzzing | Smoke and deep fuzz limits and the larger synthetic seeds |
| `*_cases.rs` | The rule file tests and `rule_precedence.rs` | Hand-written cases for each rule file |

## Coverage data

Each JSON file holds hand-written cases for rules in the Rustleaks rule files. No
generator writes them. Change a file by hand, in the same change as the rule
it covers, and write each expected value from the rule source, not from
scanner output.

| File | Read by |
| --- | --- |
| `additional_coverage.json` | `additional_coverage.rs`, `rule_precedence.rs` |
| `format_coverage.json` | `format_coverage.rs`, `rule_precedence.rs` |
| `special_coverage.json` | `special_coverage.rs`, `rule_precedence.rs` |
| `association_coverage.json` | `association_coverage.rs`, `format_coverage.rs`, `special_coverage.rs`, `rule_precedence.rs` |
| `remaining_verified_rules.json` | `remaining_verified_rules.rs`, `association_coverage.rs`, `rule_precedence.rs` |

`crates/xtask/src/comparison_workloads/matrix.py` also reads the `cases` array
of all five files for the scanner comparison. Update it when you rename or move
one of them.

`baseline_rule_ids` in each file is a fixed list of rule IDs. The lists do not
follow rule file changes.

- `additional_coverage.rs` scans with the rules in its own list, which includes
  the file's primary rules. It compares that with the same list without the
  primary rules.
- `format_coverage.rs`, `special_coverage.rs` and `association_coverage.rs`
  scan with the rules in another file's list: `association_coverage.json` for
  the first two and `remaining_verified_rules.json` for the third. They compare
  that with the rules in their own list.
- `remaining_verified_rules.rs` scans with all built-in rules and compares that
  with the rules in its own list.

`additional_coverage.json` and `format_coverage.json` carry the same list.
