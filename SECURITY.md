# Security policy

## Supported versions

Security fixes target the current development line and the latest published
release. Older prereleases and source snapshots are not supported unless a
release advisory states otherwise.

## Reporting

Do not include real credentials, exploit payloads, or non-public vulnerability
details in a public issue. Use [GitHub private vulnerability
reporting](https://github.com/joshgarnett/rustleaks/security/advisories/new).
The route was enabled and verified through the authenticated repository API on
2026-08-24. Setup did not submit a live vulnerability report.

Maintainers should acknowledge a private report within three business days,
provide an initial assessment within seven business days, coordinate
disclosure with the reporter, and avoid publishing details before a fix or
agreed disclosure date.

## Security expectations

The library preserves arbitrary input bytes, returns structured errors for
hostile configuration, and uses cooperative cancellation and explicit resource
budgets for controlled scans. Owned crates forbid unsafe code. Allocation
failure can still abort, cancellation is cooperative rather than a hard
deadline, and dependency code may contain narrowly reviewed unsafe internals;
see `docs/RESOURCE_LIMITS.md` and `docs/DEPENDENCY_SAFETY.md`.

Finding, baseline, and fragment `Debug` output omits retained byte contents.
Compatibility serialization and reporting intentionally preserve raw fields.
Owned buffers are not zeroized, and removing detected secret byte sequences
does not prove that remaining source-derived metadata is safe to disclose.

Dependency advisories, licenses, versions, and source origins are governed by
`deny.toml`. Temporary exceptions must be recorded in
`supply-chain-exceptions.toml` with an owner, rationale, affected package,
policy, and expiry date. Expired or unreferenced exceptions fail the local
release gate.

The maintained boundary map, exact local commands, and response procedure are
documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
[`docs/SECURITY_CONTROLS.md`](docs/SECURITY_CONTROLS.md), and
[`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).
