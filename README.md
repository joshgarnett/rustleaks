# Rustleaks

Rustleaks is an experimental, engine-first secret scanner written in Rust. The
`rustleaks-core` crate accepts in-memory bytes and returns structured findings.
Source adapters, reports, and the command-line interface are separate workspace
crates.

Rustleaks is backward compatible with Gitleaks at one pinned revision. It
builds on Gitleaks' behavior, default rules, tests, and fixtures, and I am
grateful to its maintainers and contributors for that foundation. Rustleaks is
an independent project and is not affiliated with or endorsed by Gitleaks or
its maintainers.

## Current status

Rustleaks is in alpha development. Only `rustleaks-core` is in the public
package boundary. The source, report, CLI, compatibility, and codec crates are
tested workspace components, not registry promises.

The workspace manifest and changelog identify the current release candidate.
Availability of a version is established by its crates.io entry and matching
GitHub release, not by version text in this README.

Defects, compatibility gaps and feature proposals are tracked in
[GitHub issues](https://github.com/joshgarnett/rustleaks/issues).

Platform evidence and its limitations are summarized below. Rustleaks is not
described as production-ready.

## Why Rustleaks exists

I needed secret scanning inside another Rust project. Gitleaks was the scanner
I already knew and trusted, and I wanted its detection behavior through a
reusable Rust library. The Rust options I evaluated did not match my embedding,
target, and dependency constraints, so I started this experimental port.

Kingfisher is a separate Rust secret scanner with a broader product scope.
Rustleaks instead focuses on a small synchronous engine and a pinned
compatibility profile. This is a difference in project scope, not a performance
or quality comparison.

## Library example

This example loads the packaged default rules and scans one in-memory byte
slice. The value is synthetic compatibility-test data, not a credential.

```rust
use std::sync::atomic::AtomicBool;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

let config = ConfigLoader::new().load_default()?;
let engine = Engine::builder(config).build()?;
let input = b"string AWSToken = \"AKIALALEMEL33243OLIB\";";
let cancelled = AtomicBool::new(false);
let control = ScanControl::cancellable(&cancelled).with_budget(
    ScanBudget::unlimited()
        .max_work_units(10_000)
        .max_finding_records(100),
);
let outcome = engine.scan_fragment_controlled(
    &Fragment::new(input),
    &ScanOptions::default(),
    &control,
);

assert!(outcome.is_complete());
assert_eq!(outcome.findings()[0].rule_id().as_str()?, "aws-access-token");
# Ok::<(), Box<dyn std::error::Error>>(())
```

The engine is synchronous, byte-first, and immutable after construction. It
does not read the environment, log, access the file system, create background
threads, or require an async runtime. `Engine` is `Send + Sync`. Controlled
scans add cooperative cancellation and explicit work, decoded-byte, and
finding-record budgets.

Budgets apply to one fragment scan. Callers that split a structured operation
across multiple fragments must also enforce aggregate byte, finding, work, and
elapsed-time limits. Finding values preserve source bytes and are not
zeroized. Their compatibility serialization is an explicit disclosure
surface; routine diagnostics should use the content-omitting `Debug` output or
a caller-owned metadata projection.

## CLI example

Build and scan a directory with the authoritative Bazel CLI target:

```sh
bazelisk run //crates/rustleaks-cli:rustleaks -- dir ./src --no-banner
```

The built binary is `bazel-bin/crates/rustleaks-cli/rustleaks`.
`rustleaks help` lists the commands and the shared flags. Each command page,
such as `rustleaks help git`, lists the flags of that command too. Print the
help for one command, or a shell completion script:

```sh
rustleaks help git
rustleaks completion bash
```

`rustleaks help completion` shows how to install the script for bash, zsh,
fish and PowerShell.

Rustleaks uses `RUSTLEAKS_CONFIG`, `RUSTLEAKS_CONFIG_TOML`,
`.rustleaks.toml`, `.rustleaksignore`, `rustleaks:allow`,
`--rustleaks-ignore-path`, and `--ignore-rustleaks-allow` as native names.
The corresponding Gitleaks spellings remain accepted only for backward
compatibility with existing configurations and automation. Native config
sources take precedence over legacy aliases.

Base64 decoding defaults to `--base64-mode compatible`. Use
`--base64-mode extended` to scan arbitrary decoded bytes from standard and
URL-safe Base64, with or without padding. Extended mode requires canonical
trailing bits. Both modes use the existing candidate discovery and heuristic;
this is not exhaustive detection of every Base64 carrier. Decode depth remains
controlled by `--max-decode-depth` (default 5; 0 disables decoding). Library
callers select `rustleaks_core::Base64Mode::Extended` with
`ScanOptions::builder().base64_mode(...)`.

## Compatibility target

The profile is pinned to Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. The packaged upstream default
configuration has SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.

Compatibility is functional. Gitleaks configuration files keep their meaning,
the same input produces the same findings and fingerprints, exit codes do not
change, and reports keep their field names, types and meanings. Help, usage,
error wording, log text and the order of JSON keys and CSV columns belong to
Rustleaks and can change. See the [compatibility
policy](docs/COMPATIBILITY.md#compatibility-policy) for the full list.

Compatibility is checked through Rust regression tests against frozen
historical observations and independently specified Rust contracts. The
evidence includes 6,770 default-rule samples, 3,618 regular
expression requests, mapped upstream tests and assertions, copied fixtures,
and focused corpora for configuration, detection, allowlists, decoding,
composite rules, sessions, files, archives, Git, reports, and the CLI. See the
[compatibility profile](docs/COMPATIBILITY.md) for counts, normalization, and
known differences.

Run the committed compatibility replay through its Bazel target:

```sh
just parity
```

`cargo xtask regression-check` verifies the frozen evidence and Rust replay.
`cargo xtask qualify` runs complete local Rust release hardening from a clean,
committed candidate. The live Go oracle and upstream rediscovery are retired;
these commands require no Go installation or sibling Gitleaks checkout.
Historical input and output bytes and attribution remain unchanged as
provenance. Frozen tests establish regression coverage for the functional
results of their cases, not equivalence on unseen input.

## Platform and dependency evidence

The declared MSRV is Rust 1.95. Owned crate roots forbid unsafe code. This does
not mean every dependency is implemented without unsafe code; the reviewed
dependency boundary is documented in
[dependency safety](docs/DEPENDENCY_SAFETY.md). The default core graph has no
native library, C, C++, archive, Git, report, CLI, or async-runtime dependency.

CI builds and runs the platform-compatible first-party tests, including the
parity replay targets, on a native runner for each of the eight required
targets. Cross-compilation remains compilation evidence only. The
[platform section of the compatibility profile](docs/COMPATIBILITY.md#platforms)
lists the runners and limits. See also the [architecture](docs/ARCHITECTURE.md)
and [resource contract](docs/RESOURCE_LIMITS.md).

## AI-assisted development

The initial port was developed with extensive use of OpenAI Codex and
GPT-5.6-Sol under human direction. Codex analyzed the pinned Go implementation
and implemented Rustleaks and its compatibility tooling. Multiple agent roles
performed implementation, oracle work, and independent review. Acceptance
relied on tests, mutation controls, and differential evidence, not an
assumption that generated code was correct.

## Security

Do not report real credentials or non-public vulnerability details in a public
issue. Use [GitHub private vulnerability
reporting](https://github.com/joshgarnett/rustleaks/security/advisories/new) for
private reports. See the [security policy](SECURITY.md), [threat
model](docs/THREAT_MODEL.md), and [local security
controls](docs/SECURITY_CONTROLS.md).

## License and attribution

Independent Rustleaks code is licensed under the MIT License. Copied Gitleaks
configuration, fixtures, and test-derived material retain their applicable MIT
terms. Adapted Go material retains its BSD terms. Codec fixtures and forks keep
their own recorded licenses. Native archives include `licenses/index.json`
and the corresponding exact license and attribution texts. Optional native
rule packs retain their separate MIT or Apache-2.0 source terms. See
[LICENSE](LICENSE), [NOTICE](NOTICE), the [native-pack notice](crates/rustleaks-core/default/NOTICE),
and the license files beside third-party material.
