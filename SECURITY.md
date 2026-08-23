# Security policy

## Supported versions

Security fixes are prepared only for the latest `0.1.0-alpha.x` source while
the project remains unpublished. Older snapshots are not supported.

## Reporting

Do not include real credentials, exploit payloads, or non-public vulnerability
details in a public issue. The intended intake route is GitHub private
vulnerability reporting. It has not been enabled and tested, so this policy
does not yet provide a verified private advisory endpoint. The route must be
enabled, tested, and recorded here before any public package release. Until
then, publication remains blocked.

When a private report route is available, maintainers should acknowledge a
report within three business days, provide an initial assessment within seven
business days, coordinate disclosure with the reporter, and avoid publishing
details before a fix or agreed disclosure date.

## Security expectations

The library preserves arbitrary input bytes, returns structured errors for
hostile configuration, and uses cooperative cancellation and explicit resource
budgets for controlled scans. Owned crates forbid unsafe code. Allocation
failure can still abort, cancellation is cooperative rather than a hard
deadline, and dependency code may contain narrowly reviewed unsafe internals;
see `docs/RESOURCE_LIMITS.md` and `docs/DEPENDENCY_SAFETY.md`.

Dependency advisories, licenses, versions, and source origins are governed by
`deny.toml`. Temporary exceptions must be recorded in
`supply-chain-exceptions.toml` with an owner, rationale, affected package,
policy, and expiry date. Expired or unreferenced exceptions fail the local
release gate.

The maintained boundary map, exact local commands, and response procedure are
documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
[`docs/SECURITY_CONTROLS.md`](docs/SECURITY_CONTROLS.md), and
[`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).
