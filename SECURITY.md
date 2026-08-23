# Security policy

## Supported versions

Security fixes are prepared only for the latest `0.1.0-alpha.x` source while
the project remains unpublished. Older snapshots are not supported.

## Reporting

Do not include real credentials, exploit payloads, or non-public vulnerability
details in a public issue. This checkout has no configured repository remote or
private advisory endpoint, so private vulnerability intake is not yet
available. A private reporting route must be configured and recorded here
before any public package release; until then, publication remains an external
release follow-up.

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
