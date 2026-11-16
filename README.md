# Rustleaks

Rustleaks finds secrets, such as API keys and passwords, in files, Git history
and standard input. It is written in Rust. Rustleaks is compatible with
Gitleaks 8.30.0 configuration, findings and reports. See [Differences from
Gitleaks](docs/user/gitleaks-differences.md) for the exceptions. The detection
engine is also available as the `rustleaks-core` library.

Rustleaks builds on the behavior, default rules, tests and fixtures of
[Gitleaks](https://github.com/gitleaks/gitleaks), and thanks its maintainers
and contributors. Rustleaks is an independent project. It is not affiliated
with or endorsed by Gitleaks.

## Status

Rustleaks is alpha software. Commands, options and the library API can change
between releases.

- The `rustleaks` command is published as pre-release archives on the
  [GitHub releases page](https://github.com/joshgarnett/rustleaks/releases).
  It is not on crates.io.
- The `rustleaks-core` library is published on
  [crates.io](https://crates.io/crates/rustleaks-core).

The documentation describes the current source. Features listed under
Unreleased in the [changelog](CHANGELOG.md) are not in a release yet.

Report bugs and request features in
[GitHub issues](https://github.com/joshgarnett/rustleaks/issues).

## Install

Download the archive for your platform from the releases page, check it, and
extract it. Archives exist for Linux (glibc and musl), macOS and Windows, each
on x86_64 and ARM64. See [Getting started](docs/user/getting-started.md) for
the exact steps, or to build from source with Bazel.

## First scan

```sh
rustleaks dir .                 # files in the current folder
rustleaks git .                 # every commit in the current repository
cat app.log | rustleaks stdin   # standard input
```

The exit code is 0 when nothing is found and 1 when secrets are found. Add
`--report-path findings.json` to save a report. Run `rustleaks --help` to list
the commands and flags.

## Library

```sh
cargo add rustleaks-core
```

```rust
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::Engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::builder(ConfigLoader::new().load_default()?).build()?;
    let outcome = engine.scan_fragment(
        &Fragment::new(b"string AWSToken = \"AKIALALEMEL33243OLIB\";"), // rustleaks:allow
        &ScanOptions::default(),
    );
    assert!(outcome.is_complete());
    assert_eq!(outcome.findings()[0].rule_id().as_str()?, "aws-access-token");
    Ok(())
}
```

The value above is synthetic test data. The `rustleaks:allow` comment stops
Rustleaks from reporting it when it scans this repository. The engine is
synchronous, does no I/O and starts no threads. See [Using
rustleaks-core](docs/user/library.md) and the [API
documentation](https://docs.rs/rustleaks-core).

## Documentation

For people who use Rustleaks:

- [Getting started](docs/user/getting-started.md)
- [Command reference](docs/user/cli-reference.md)
- [Configuration](docs/user/configuration.md)
- [Reports](docs/user/reports.md)
- [Using Rustleaks in CI and Git hooks](docs/user/ci.md)
- [Native rule packs](docs/user/native-rule-packs.md)
- [Complete scanning](docs/user/complete-scanning.md)
- [Resource limits](docs/user/resource-limits.md)
- [Differences from Gitleaks](docs/user/gitleaks-differences.md)
- [Using rustleaks-core](docs/user/library.md)
- [Review records](docs/user/review-records.md)

For people who work on Rustleaks:

- [Contributing](CONTRIBUTING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Compatibility profile](docs/COMPATIBILITY.md)
- [Detection policy](docs/DETECTION_POLICY.md)
- [Complete scanning internals](docs/COMPLETE_SCANNING.md)
- [Resource and cancellation contract](docs/RESOURCE_LIMITS.md)
- [Archive codec strategy](docs/ARCHIVE_CODEC_STRATEGY.md)
- [Performance measurement](docs/PERFORMANCE.md)
- [Performance reporting](docs/PERFORMANCE_REPORTING.md)
- [Dependency policy](docs/DEPENDENCIES.md)
- [Dependency safety](docs/DEPENDENCY_SAFETY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security controls](docs/SECURITY_CONTROLS.md)
- [Security stress tests](docs/SECURITY_STRESS.md)
- [Incident response](docs/INCIDENT_RESPONSE.md)
- [Updating upstream](docs/UPDATING_UPSTREAM.md)
- [Releasing](docs/RELEASING.md)
- [Changelog](CHANGELOG.md)

## AI-assisted development

Much of Rustleaks was written with AI coding agents under human direction.
Every change must pass tests and review.

## Security

Do not put real credentials or private vulnerability details in a public
issue. Use [private vulnerability
reporting](https://github.com/joshgarnett/rustleaks/security/advisories/new).
See the [security policy](SECURITY.md).

## License

Rustleaks code is licensed under the [MIT License](LICENSE). Copied Gitleaks
configuration, fixtures and test material keep their MIT terms. Adapted Go
code keeps its BSD terms. The optional rule packs keep their MIT or Apache-2.0
source terms. Forked codec crates and codec fixtures keep their own licenses,
which are stored next to them. Release archives include every license in a
`licenses` folder.
See [NOTICE](NOTICE) and the [rule pack
notice](crates/rustleaks-core/default/NOTICE).
