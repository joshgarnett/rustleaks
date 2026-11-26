# Security policy

This page is for people who want to report a security problem in Rustleaks,
or who want to know what Rustleaks protects.

## Supported versions

Security fixes target the current development line and the latest published
release. Older releases, including the 0.1.0 alpha releases, and source
snapshots are not supported unless a release advisory says otherwise.

## Reporting

Do not put real credentials, exploit payloads or details of an unfixed problem
in a public issue. Use [GitHub private vulnerability
reporting](https://github.com/joshgarnett/rustleaks/security/advisories/new).

Maintainers should acknowledge a private report within three business days,
give a first assessment within seven business days, agree on disclosure with
the reporter, and not publish details before a fix or the agreed disclosure
date.

## What Rustleaks protects

- The library keeps input bytes as they are and returns errors for bad
  configuration.
- Scans can be stopped and given limits. A stop happens between steps, not
  at once, and running out of memory can still end the process. See
  [Resource limits](docs/user/resource-limits.md).
- Rustleaks code uses no unsafe Rust, except the C ABI crate
  `rustleaks-ffi` that the Go and Python bindings call. Its unsafe code
  reads and writes only through the pointers that callers pass and frees
  the handles it made. Detection stays in safe code. Some dependencies use
  unsafe Rust; see [Dependencies](docs/dev/dependencies.md).

Findings and reports hold secrets:

- Reports and serialized findings keep the `Secret`, `Match` and `Line`
  fields unless you use `--redact`. See [Report
  files](docs/user/reports.md#report-files) for how Rustleaks creates report
  files.
- `Debug` output of findings, baselines and fragments leaves out their bytes.
- Rustleaks does not clear secret bytes from memory after use.
- A redacted report can still hold other text from the scanned files, such as
  file names and commit messages.

## For maintainers

The threat boundaries, the security checks and the response procedure are in
the [threat model](docs/dev/threat-model.md), [Security
checks](docs/dev/security-checks.md) and [Incident
response](docs/dev/incident-response.md).
