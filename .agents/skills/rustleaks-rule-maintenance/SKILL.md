---
name: rustleaks-rule-maintenance
description: Maintain Rustleaks built-in rule, custom-rule or Rustleaks rule file behavior with real positive and negative cases, exact source spans, keyword and entropy behavior, and allowlist coverage. Use for rule semantics, built-in rules and rule tests.
---

# Rustleaks rule maintenance

Read `docs/dev/rule-authoring.md`, `docs/dev/testing.md`, the
[repository contract](../../../AGENTS.md#repository-contract) and the config
and detection corpus READMEs under `testdata/` that apply. Decide whether the
request changes the Gitleaks-based rules in `gitleaks.toml`, supported TOML
semantics, a Rustleaks rule file, or only Rustleaks test coverage.

## Gitleaks-based rules and Rustleaks rule files

Follow [Changing the Gitleaks-based
rules](../../../docs/dev/rule-authoring.md#changing-the-gitleaks-based-rules)
or [Changing a rule
file](../../../docs/dev/rule-authoring.md#changing-a-rule-file). Never edit
rules above the generated marker line, a `.sha256` file or a
`.provenance.json` file by hand. See [Approval
boundaries](../../../AGENTS.md#approval-boundaries) for a change that makes
Rustleaks miss a secret.

## Build evidence

For each rule behavior, add or find:

- a real positive case that should produce the exact rule, match, secret,
  byte span, line, and column;
- a near-miss negative case that would fail if the regex, keyword filter,
  entropy threshold, secret group, predicate or path condition were
  broadened;
- invalid UTF-8, overlapping, boundary, or multiline coverage when relevant;
- global and rule allowlist coverage for the affected condition, including
  stop-word, regex, path, commit, and target-rule behavior where it applies;
- extension and composite behavior when the rule participates in either;
- for a Rustleaks rule file, overlap with the Gitleaks-based rules and the other
  rule files, with an `[[overlaps]]` entry and a case in
  `tests/rule_overlaps.rs` when two rules report the same secret; and
- a synthetic value or reviewed upstream fixture, never a live credential.

Keep Go regex translation and dependency types private. Do not alter matching
bytes or offsets in a corpus normalizer.

Any edit to a rule file changes the quality baseline and the performance
values. Follow [Quality
corpus](../../../docs/dev/rule-authoring.md#quality-corpus) and [Performance
values](../../../docs/dev/rule-authoring.md#performance-values). Never change
a quality label to improve a result.

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
