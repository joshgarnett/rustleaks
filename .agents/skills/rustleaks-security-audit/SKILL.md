---
name: rustleaks-security-audit
description: Audit Rustleaks threat boundaries, owned code, dependencies, unsafe inventory, static checks, fuzzing, sensitive findings, and security policy. Use for security reviews, dependency-risk review, hostile-input hardening, or fuzz findings; do not disclose raw findings publicly.
---

# Rustleaks security audit

Read `SECURITY.md`, `docs/dev/threat-model.md`,
`docs/dev/engine-internals.md`, `docs/user/resource-limits.md`,
`docs/dev/dependencies.md`, `docs/dev/security-checks.md`, and
`docs/dev/incident-response.md`. Select the
affected threat-model row and verify its implementation, limits, tests,
remaining limitations, dependency boundary, and public claims against the
current tree.

## Handle sensitive material

Assume findings, crash inputs, reports, Git metadata, paths, and diagnostics
may contain a live credential or private vulnerability detail. Keep raw values
out of issues, commits, chat, and normal logs. Work from a private copy, record
a hash, and reduce it to a synthetic reproducer that does not work as a
credential before adding a test. Do not test a suspected credential by using
it.

Owned crates must continue to forbid unsafe Rust. Treat dependency unsafe
inventory as a change signal, not proof of safety or reachability. Review any
new source, build script, native link, license, advisory, vet exemption,
exception review condition, feature, or target-specific edge. Accepting an
advisory, vetting, unsafe, or native exception, or a change that the
repository contract reserves for the maintainer, needs maintainer approval.
See [Approval boundaries](../../../AGENTS.md#approval-boundaries).

Before keeping an approved cargo-vet exemption, apply the [exemption
policy](../../../docs/dev/security-checks.md#exemptions). Confirm that
configured peer evidence is absent. Record why the required criterion cannot
be certified, and find out whether the concern is reachable in the dependency
graph. Record the scope, resolution condition, owner, and the
review date or approved boundary-change trigger. Never use an exemption for a
known concern reachable in the runtime graph or as a silent criteria
downgrade.
Regenerate the vet inventory after changing an exemption.

Use `rustleaks-build-maintenance` for dependency and lockfile mechanics. This
skill owns the risk assessment, exception decision, and security evidence for
those changes.

## Test the boundary

Add deterministic regressions for the actual failure mode and the
structured error, cancellation, budget, path, redaction, or panic policy.
Use synthetic seeds. Run the affected Bazel test or corpus first, then:

```sh
just security
just ci
```

Run `just fuzz-smoke`, and add `just package-check` when public APIs, default
assets, features, manifests, or dependencies change. Do not run
`just package-check` for an ordinary owned source-code fix; add it only when
one of those package-facing boundaries changes. Follow the incident procedure
for a suspected live finding, compromised dependency, release input, or
unexplained fuzz or sanitizer result.

For a repository self-scan, follow [Repository
self-scan](../../../docs/dev/security-checks.md#repository-self-scan) and keep
all findings redacted.

Report the threat boundary, evidence inspected, exact commands and results,
finding classification, synthetic regression, dependency and unsafe delta,
limits and residual risk, private-handling status, and PASS or FAIL. An
unresolved mandatory finding or unexplained exception is FAIL.
