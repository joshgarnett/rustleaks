---
name: rustleaks-compatibility
description: Check Rustleaks behavior against the compatibility policy and the committed Gitleaks evidence, classify each difference, and, with maintainer approval, move the Gitleaks pin or the upstream copy of the default configuration. Use for parity replay failures, compatibility reviews and upstream updates, not ordinary rule edits.
---

# Rustleaks compatibility

Read the [compatibility
policy](../../../docs/user/gitleaks-differences.md#compatibility-policy),
[Testing and parity](../../../docs/dev/testing-and-parity.md) and, for a pin
change, [Updating upstream](../../../docs/dev/updating-upstream.md). Those
documents hold the procedure. This skill lists what agents get wrong.

Rustleaks has no Go oracle and does not track Gitleaks automatically. Do not
install Go or check out Gitleaks to create expected values. Frozen files under
`compat/` record Gitleaks behavior at the pin and never change. Commands named
inside them do not run.

## Check the evidence

Find the failing replay target and its corpus README, and reproduce the
difference with a focused target first, for example:

```sh
bazelisk test //crates/rustleaks-core:detect_corpus_test
```

Then run `cargo xtask regression-check`, which includes `just parity`. Never
edit an accepted outcome to make a replay pass.

## Classify each difference

Give each difference exactly one class:

- a defect in Rustleaks or in the test harness, fixed so the behavior matches;
- a documented finding difference that loses no secret: Rustleaks finds more,
  or gives a clearer result. List it in `docs/user/gitleaks-differences.md`
  and add a Rust test;
- a presentation change, handled as in [Presentation
  dispositions](../../../docs/dev/testing-and-parity.md#presentation-dispositions);
  or
- a change that needs maintainer approval: it changes the meaning of a
  configuration, report field, error class or exit code, or makes Rustleaks
  miss a secret it found before.

Write expected values from the intended behavior, never from current output.
Never normalize findings, spans, fingerprints, report fields, error classes,
suppression or exit status.

## Move the pin

Moving the pin or the upstream copy of the default configuration needs
maintainer approval for the exact commit. Follow the steps in Updating
upstream. Update the pin, the upstream copy, new evidence, hashes and
attribution in one change. `crates/rustleaks-core/tests/default_rules.rs`
must still name every difference in the shipped default rules. Rustleaks
does not have to adopt upstream presentation changes. From a clean,
committed tree, finish with:

```sh
just ci
just security
cargo xtask regression-check
cargo xtask qualify
```

Report the commit and hashes, each difference and its class, the commands
and results, and any approval still needed.
