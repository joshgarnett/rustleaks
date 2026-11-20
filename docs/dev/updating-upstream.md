# Updating upstream

This page is for maintainers. It explains how to move Rustleaks to a newer
Gitleaks revision. Changing the pin needs maintainer approval.

Rustleaks is pinned to one Gitleaks revision. `compat/upstream-revision.txt`
records the commit and the SHA-256 of the upstream default configuration. The
unchanged upstream copy is `compat/config-corpus/default-gitleaks.toml`. The
shipped default rules in `crates/rustleaks-core/default/gitleaks.toml` are
based on it and may differ by the reviewed changes listed in
[Default rules](../user/gitleaks-differences.md#default-rules).

Rustleaks has no Go oracle. Commands named in frozen `compat/` files do not
run. See the [`compat/` README](../../compat/README.md#frozen-evidence).

## Before you start

- Get approval for the candidate revision.
- Write a plan for how you will import and qualify it.
- Do not overwrite the frozen evidence. A passing Rust replay does not show
  that Rustleaks matches a different upstream revision.

## Steps

1. **Record the candidate.** Note the commit and the default configuration
   hash. Read the upstream changes since the current pin: rules,
   configuration, regex, detectors, sources, reports, CLI, tests, fixtures
   and licenses.
2. **Decide what to adopt.** For each behavior you adopt, write expected
   results that a reviewer can check without running Rustleaks. Decide how
   you will get and keep the evidence before you edit any accepted input.
   Adding external tools or dependencies needs its own review and approval.
3. **Keep the old evidence.** Do not change existing historical observations.
   Store new evidence in new versioned files, with the exact source and
   generator provenance. Never derive expected results only from the current
   Rust code.
4. **Update the pin in one change.** Update `compat/upstream-revision.txt`,
   the upstream copy of the default configuration and the new evidence
   together. Apply the new upstream rules to the shipped default rules and
   keep or rework each listed Rustleaks change, so that
   `crates/rustleaks-core/tests/default_rules.rs` still names every
   difference.
   Keep copied bytes, file modes, symbolic link targets, hashes, licenses and
   `NOTICE` attribution. Use reviewed, deterministic tools for generated
   files. Never edit historical outcomes or inventories by hand.
5. **Classify every difference.** Each behavior difference is one of:
   - supported behavior that now matches exactly;
   - an intended Rustleaks difference;
   - a documented finding difference that loses no secret: list it in
     [Differences from Gitleaks](../user/gitleaks-differences.md) and add a
     Rust test;
   - a presentation change; or
   - a defect to fix.

   A difference that makes Rustleaks miss a secret it found before, or that
   changes the meaning of a configuration, report field or exit code, needs
   maintainer approval.

   A presentation change affects only help, usage, error wording, log,
   banner or summary text, or JSON key or CSV column order. It needs a
   reviewed test expectation and, for frozen CLI evidence, a
   [presentation disposition](testing-and-parity.md#presentation-dispositions).
   It does not need maintainer approval. Rustleaks does not have to adopt
   upstream presentation changes. A key or column order change first needs a
   change to the report and findings comparisons so that they compare parsed
   fields.

   The other classes apply to functional behavior. Keep executable tests and
   negative controls for them. Do not hide a functional difference with
   normalization.
6. **Run the checks.** From a clean, committed candidate:

   ```sh
   just ci
   just security
   cargo xtask regression-check
   cargo xtask qualify
   ```

   `regression-check` checks the frozen evidence and replays it. `qualify`
   checks the public API snapshot and the MSRV build. Refresh the native
   evidence for each target.
   Cross-compilation proves only that the code compiles.
7. **Review and record.** Get an independent review of the finding
   differences and the Rust API.
   Record the final source identities, artifact hashes, case counts,
   commands, results and remaining host limits. A pending native or required
   hosted check is not a pass.

This process does not authorize a release or a change to repository
settings.
