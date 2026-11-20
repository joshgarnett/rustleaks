# Security policy

## Supported versions

Security fixes target the current development line and the latest published
release. Older prereleases and source snapshots are not supported unless a
release advisory states otherwise.

## Reporting

Do not include real credentials, exploit payloads, or non-public vulnerability
details in a public issue. Use [GitHub private vulnerability
reporting](https://github.com/joshgarnett/rustleaks/security/advisories/new).

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
see [Resource limits](docs/user/resource-limits.md), [Engine
internals](docs/dev/engine-internals.md) and
[Dependencies](docs/dev/dependencies.md).

Finding, baseline, and fragment `Debug` output omits retained byte contents.
Compatibility serialization and reporting intentionally preserve raw fields.
Owned buffers are not zeroized, and removing detected secret byte sequences
does not prove that remaining source-derived metadata is safe to disclose.

`deny.toml` sets the policy for dependency advisories, licenses, versions and
sources, and `just security` checks it. `supply-chain-exceptions.toml` has no
active exceptions, and `just security` fails if one is added. Accepting an
exception needs maintainer approval and a change to that check.

The threat boundaries, exact local commands and response procedure are
documented in the [threat model](docs/dev/threat-model.md),
[security checks](docs/dev/security-checks.md) and
[incident response](docs/dev/incident-response.md).
