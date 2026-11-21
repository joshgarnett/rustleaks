# Test support files

The integration tests in `crates/rustleaks-core/tests/` include these files.
`BUILD.bazel` lists which test gets which file.

## Shared Rust modules

| File | Used by | Contents |
| --- | --- | --- |
| `native_harness.rs` | The five coverage tests below | The composition of all three rule packs, scan, range and entropy helpers |
| `corpus.rs` | `allowlist.rs`, `composite_corpus.rs`, `detect_corpus.rs`, `session_corpus.rs` | The finding record of the frozen corpora under `compat/`, JSON Lines and base64 helpers |
| `fuzz_profile.rs` | Fuzz targets, `security_stress.rs` tests and `xtask` in several crates | Smoke and deep fuzz limits and the larger synthetic seeds |
| `*_cases.rs` | The rule-pack tests and `rule_precedence.rs` | Hand-written cases for each rule pack |

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

`baseline_rule_ids` in each file is a frozen comparison set: the rule IDs
before that file's rules were added. The tests compare what that set finds
with what the full composition finds. The lists do not follow later rule
changes. `format_coverage.rs` and `special_coverage.rs` read their rule set
from `association_coverage.json`, and `association_coverage.rs` reads its rule
set from `remaining_verified_rules.json`, so those lists have one copy each.
`additional_coverage.json` and `format_coverage.json` carry the same list.
