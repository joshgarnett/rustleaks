---
name: rustleaks-rule-maintenance
description: Maintain Rustleaks default-rule, custom-rule or native rule pack behavior with grounded positive and negative cases, exact source spans, keyword and entropy behavior, and allowlist coverage. Use for rule semantics, native pack rules and rule tests.
---

# Rustleaks rule maintenance

Read `docs/dev/rule-pack-authoring.md`, `docs/dev/testing.md`, the
[repository contract](../../../AGENTS.md#repository-contract) and the
applicable config and detection corpus READMEs under `testdata/`. Decide
whether the request changes the
shipped default rules, supported TOML semantics, a native rule pack, or only
Rustleaks test coverage.

## Default rules

The shipped default rules, `crates/rustleaks-core/default/gitleaks.toml`,
started from the Gitleaks default configuration and are maintained in place.
`testdata/config-corpus/default-gitleaks.toml` is test input for the
configuration cases; never edit it to match the shipped rules.

A change to the shipped default rules needs normal review, and:

- tests with expectations from the change's definition, including near
  misses that must stay findings;
- for an added allowlist, an update to
  `crates/rustleaks-core/tests/default_rules.rs`, which names the allowlists
  that Rustleaks adds;
- an update to [Default rules](../../../docs/user/built-in-rules.md#default-rules)
  when users see the change, and a changelog entry;
- updates of `DEFAULT_CONFIG_SHA256` in `rustleaks-core` and
  `DEFAULT_RULES_SHA256` in `xtask`, and of generated baselines with their
  generator commands; and
- a measurement on a held-out set that was not used to design the change.

A change that makes Rustleaks miss secrets it found before needs maintainer
approval.

## Native rule packs

New Rustleaks rules go into a native pack in `crates/rustleaks-core/default/`:
`rustleaks-providers-v1` for provider keys and tokens,
`rustleaks-connections-v1` for passwords in connection strings and URLs, and
`rustleaks-extra-v1` for the small first-party set. Every default scan uses
all of them. A pack changes in place: it keeps its ID and the change gets a
changelog entry. A change that makes Rustleaks miss secrets it found before
needs maintainer approval.

For the provider and connection packs:

1. Edit the rule in `crates/xtask/src/tooling/native_coverage/providers.toml`
   or `connections.toml`. Do not edit the rules above the generated marker
   line in the pack TOML.
2. Add or update its record in
   `crates/xtask/src/tooling/native_coverage/reviewed.json`. The `native`
   object must equal the TOML rule, and `origin` holds the source, revision,
   file hash, license and changes made.
3. Regenerate the pack TOML, its `.provenance.json` and the `.sha256`
   identity, then check them:

   ```sh
   cargo xtask generate native-pack-identity
   cargo xtask generate native-pack-identity --check
   ```

   Rule counts come from these files, so no count needs a manual edit.

For `rustleaks-extra-v1`, edit the TOML and run the same generator to update
its `.sha256`. Never edit a `.sha256` or `.provenance.json` file by hand.

Imported rules keep the pinned source revision, file SHA-256, license text
next to the pack and `NOTICE` attribution. Reject a rule when Rustleaks cannot
express the relevant source behavior without leaving something out.

Update the pack's `.md` file and the rule counts in
`docs/dev/rule-pack-authoring.md`.

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
- for a native pack rule, overlap with the default rules and the other packs;
  and
- a synthetic value or reviewed upstream fixture, never a live credential.

Keep Go regex translation and dependency types private. Do not alter matching
bytes or offsets in a corpus normalizer.

The quality corpus in `testdata/quality-corpus/` has labels written
independently of detector output. Never change a label to improve a result.
See `testdata/quality-corpus/README.md` for how to regenerate it, and run
`just quality-eval` to print the report.

## Validate

Run the narrowest applicable targets first. For default rules:

```sh
bazelisk test //crates/rustleaks-core:default_rule_corpus_test
bazelisk test //crates/rustleaks-core:detect_corpus_test
bazelisk test //crates/rustleaks-core:allowlist_test
```

For native packs:

```sh
bazelisk test //crates/rustleaks-core:native_rules_test
bazelisk test //crates/rustleaks-core:provider_rules_test
bazelisk test //crates/rustleaks-core:connection_rules_test
bazelisk test //crates/rustleaks-core:native_policy_test
```

`docs/dev/rule-pack-authoring.md` lists the other native test files. Add
`bazelisk test //crates/rustleaks-core:config_test` for TOML, extension, or
config-loading changes. Then run the commands that the [local
workflow](../../../CONTRIBUTING.md#local-workflow) table names for the
change, at least `just ci`. Run `just fuzz-smoke` for a parser, regex,
decoder, predicate or hostile-input change. New expectations must be
specified independently of current Rust output. A case under `testdata/`
changes only when the reviewed behavior change requires it.

Report the rule identifiers, intended behavior, positive and negative cases,
exact span evidence, allowlist effect, overlap, whether any secret is lost,
commands and results, and any approval required.
