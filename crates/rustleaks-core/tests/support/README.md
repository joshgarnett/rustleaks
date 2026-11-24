# Test support files

The integration tests in `crates/rustleaks-core/tests/` include these files.
`BUILD.bazel` lists which test gets which file.

## Shared Rust modules

| File | Used by | Contents |
| --- | --- | --- |
| `native_harness.rs` | The five coverage tests below | The shipped rules, the shipped rules without some rules, and scan, range and entropy helpers |
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
| `association_coverage.json` | `association_coverage.rs`, `rule_precedence.rs` |
| `remaining_verified_rules.json` | `remaining_verified_rules.rs`, `rule_precedence.rs` |

`crates/xtask/src/comparison_workloads/matrix.py` also reads the `cases` array
of all five files for the scanner comparison. Update it when you rename or move
one of them.

Each coverage test scans with the rules Rustleaks ships, in the order it loads
them (`ConfigLoader::new().load_default()`). To check what the other rules
find, it also scans with the shipped rules without the rules of its own file:
the rules of the `primary` cases in `additional_coverage.json` and
`format_coverage.json`, and the `selected_rule_ids` in the other three files.
The `before_*` fields of a case give what those other rules find.
