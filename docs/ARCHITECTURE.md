# Architecture

Rustleaks keeps detection independent from I/O and process behavior.

## Root CLI generator auxiliary packages

The workspace root owns package policy and validation. The CLI is a thin
consumer. Compatibility generators and the pinned Go oracle are unpublished
test infrastructure.

## Configuration

`rustleaks-core` parses raw TOML into validated immutable configuration. The
packaged default is a build asset. Dependency regular-expression types remain
private.

## Detection and codec

Detection applies keywords, regular expressions, entropy, allowlists,
decoding, composite rules, and location mapping to caller-provided bytes.
Archive codecs are outside the core graph.

## Findings and reports

The core owns byte-oriented finding models and sessions. `rustleaks-report`
formats findings without changing detection state.

## SCM and regexp

The regular-expression compatibility frontend is private to the core. Git
processes and remote-link construction are isolated in `rustleaks-sources`.

## Sources

Source adapters produce fragments and structured issues. A bounded runner may
schedule them, but it submits only complete fragment outcomes to a session.

## Package boundaries

| Package | Responsibility | Publication status |
| --- | --- | --- |
| `rustleaks-core` | Configuration, matching, decoding, findings, and session policy | Initial publishable boundary |
| `rustleaks-sources` | Files, directories, archives, Git, cancellation, and bounded scheduling | Workspace only |
| `rustleaks-report` | JSON, CSV, JUnit, SARIF, and restricted templates | Workspace only |
| `rustleaks-cli` | Argument compatibility, config discovery, orchestration, diagnostics, and exits | Workspace only |
| `rustleaks-compat` | Go oracle integration and performance workloads | Workspace only |
| `xtask` | Repository validation and release-policy checks | Workspace only |
| `rustleaks-bzip2`, `rustleaks-rar-codec`, `rustleaks-sevenz` | Retained internal safe archive decoder forks | Workspace only |

RAR2 decoding uses the upstream `compcol 0.3.1` crate privately through
`rustleaks-sources`. No `compcol` type crosses the source API.

The dependency direction is core to sources and reports, then into the CLI.
The core does not depend on source adapters, report writers, the CLI, archive
codecs, Git, a shell, or an async runtime. Compatibility tools may observe the
pinned Go implementation, but production packages do not load it.

The default core engine owns immutable compiled configuration. A caller passes
one byte-oriented fragment and scan options, then receives a complete or
structured partial outcome. Source adapters may schedule fragments, but the
engine does not create threads or retain process-global state.

Project-native names use `rustleaks`. Upstream names remain only where required
for backward-compatible configuration, CLI behavior, report bytes, oracle
protocols, fixture identity, or attribution. These compatibility names do not
identify the product or imply upstream endorsement.
