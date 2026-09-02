---
name: rustleaks-security-audit
description: Audit Rustleaks threat boundaries, owned code, dependencies, unsafe inventory, static checks, fuzzing, sensitive findings, and security policy. Use for security reviews, dependency-risk review, hostile-input hardening, or fuzz findings; do not disclose raw findings publicly.
---

# Rustleaks security audit

Read `SECURITY.md`, `docs/THREAT_MODEL.md`,
`docs/RESOURCE_LIMITS.md`, `docs/DEPENDENCY_SAFETY.md`,
`docs/SECURITY_CONTROLS.md`, and `docs/INCIDENT_RESPONSE.md`. Select the
affected threat-model row and verify its implementation, limits, tests,
remaining limitations, dependency boundary, and public claims against the
current tree.

## Handle sensitive material

Assume findings, crash inputs, reports, Git metadata, paths, and diagnostics
may contain a live credential or private vulnerability detail. Keep raw values
out of issues, commits, chat, and normal logs. Work from a private copy, record
a hash, and reduce it to a nonfunctional synthetic reproducer before adding a
test. Do not test a suspected credential by using it.

Owned crates must continue to forbid unsafe Rust. Treat dependency unsafe
inventory as a change signal, not proof of safety or reachability. Review any
new source, build script, native link, license, advisory, vet exemption,
exception expiry, feature, or target-specific edge. Accepting an advisory,
vetting, unsafe, native, or compatibility exception requires maintainer
approval.

Before retaining an approved cargo-vet exemption, apply the exemption policy
in `docs/SECURITY_CONTROLS.md`. Confirm that configured peer evidence is absent,
record why the required criterion cannot be certified, establish whether the
concern is reachable in the maintained graph, and record the scope, resolution
condition, owner, and review date. Never use an exemption for a known concern
reachable in the maintained runtime graph or as a silent criteria downgrade.
Regenerate the vet inventory after changing an exemption.

Use `rustleaks-build-maintenance` for dependency and lockfile mechanics. This
skill owns the risk assessment, exception decision, and security evidence for
those changes.

## Test the boundary

Add deterministic regressions for the actual failure mode and applicable
structured error, cancellation, budget, path, redaction, or panic policy.
Use synthetic seeds. Run the affected Bazel test or corpus first, then:

```sh
just security
just ci
```

The final `just ci` result includes committed parity. When supported behavior
or fresh Go evidence changes, run `cargo xtask parity --all` against a clean,
committed candidate tree; it includes package and fuzz checks. Otherwise run
`just fuzz-smoke`, and add `just package-check` when public APIs, default
assets, features, manifests, or dependencies change. Do not run
`just package-check` for an ordinary owned source-code fix; add it only when
one of those package-facing boundaries changes. Follow the incident procedure
for a suspected live finding, compromised dependency, release input, or
unexplained fuzz or sanitizer result.

For a repository self-scan, build the maintained CLI and keep all findings
redacted:

```sh
bazelisk build //crates/rustleaks-cli:rustleaks
bazel-bin/crates/rustleaks-cli/rustleaks dir . --redact --no-banner --timeout=300
bazel-bin/crates/rustleaks-cli/rustleaks git . --redact --no-banner --timeout=600
```

Do not broaden `.rustleaks.toml` paths or add a `.rustleaksignore` fingerprint
without privately reviewing the redacted rule, path, line, source context, and
provenance.

Report the threat boundary, evidence inspected, exact commands and results,
finding classification, synthetic regression, dependency and unsafe delta,
limits and residual risk, private-handling status, and PASS or FAIL. An
unresolved mandatory finding or unexplained exception is FAIL.
