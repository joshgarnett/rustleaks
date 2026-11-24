---
name: rustleaks-rule-maintenance
description: Maintain Rustleaks default-rule, custom-rule or Rustleaks rule file behavior with grounded positive and negative cases, exact source spans, keyword and entropy behavior, and allowlist coverage. Use for rule semantics, built-in rules and rule tests.
---

# Rustleaks rule maintenance

Read `docs/dev/rule-authoring.md`, `docs/dev/testing.md`, the
[repository contract](../../../AGENTS.md#repository-contract) and the
applicable config and detection corpus READMEs under `testdata/`. Decide
whether the request changes the shipped default rules, supported TOML
semantics, a Rustleaks rule file, or only Rustleaks test coverage.

## Default rules and Rustleaks rule files

Follow [Changing the default
rules](../../../docs/dev/rule-authoring.md#changing-the-default-rules)
or [Changing a pack](../../../docs/dev/rule-authoring.md#changing-a-pack).
The `NativePolicy` API calls a Rustleaks rule file a pack. Never edit rules
above the generated marker line, a `.sha256` file or a `.provenance.json`
file by hand. A change that makes Rustleaks miss secrets it found before
needs maintainer approval.

## Build evidence

For each rule behavior, add or identify:

- a grounded positive case that should produce the exact rule, match, secret,
  byte span, line, and column;
- a near-miss negative case that would fail if the regex, keyword filter,
  entropy threshold, secret group, predicate or path condition were
  broadened;
- invalid UTF-8, overlapping, boundary, or multiline coverage when relevant;
- global and rule allowlist coverage for the affected condition, including
  stop-word, regex, path, commit, and target-rule behavior where applicable;
- extension and composite behavior when the rule participates in either;
- for a Rustleaks rule file, overlap with the default rules and the other
  rule files, with an `[[overlaps]]` entry and a case in
  `tests/rule_overlaps.rs` when two rules report the same secret; and
- a synthetic value or reviewed upstream fixture, never a live credential.

Keep Go regex translation and dependency types private. Do not alter matching
bytes or offsets in a corpus normalizer.

The quality corpus in `testdata/quality-corpus/` has labels written
independently of detector output. Never change a label to improve a result.
See `testdata/quality-corpus/README.md` for how to regenerate it, and run
`just quality-eval` to print the report.

## Validate

Run the narrow targets that the procedure lists first. Then run the commands
that the [local workflow](../../../CONTRIBUTING.md#local-workflow) table names
for the change, at least `just ci`. Run `just fuzz-smoke` for a parser, regex,
decoder, predicate or hostile-input change. Follow [Rules for
tests](../../../docs/dev/testing.md#rules-for-tests) for expected values and
cases under `testdata/`.

Report the rule identifiers, intended behavior, positive and negative cases,
exact span evidence, allowlist effect, overlap, whether any secret is lost,
commands and results, and any approval required.
