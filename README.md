# Rustleaks

Rustleaks finds secrets, such as API keys and passwords, in files, Git history
and standard input. It is written in Rust. The detection engine is also
available as the `rustleaks-core` library.

Rustleaks reads configuration files, ignore files, baselines and allow
comments written for Gitleaks. If you use Gitleaks now, start with
[Moving from Gitleaks](docs/user/moving-from-gitleaks.md).

## Status

The current release is 0.2.0. Rustleaks keeps commands, flags,
configuration files, ignore files, baselines, allow comments, report fields
and exit codes working. A release that removes or changes one of them says
so in the [changelog](CHANGELOG.md). Before 1.0, a minor release, such as
0.3.0, can also change the library API. A patch release, such as 0.2.1, does
not change the library API.

The `rustleaks` command is not on crates.io. The `rustleaks-core` library is,
at [crates.io/crates/rustleaks-core](https://crates.io/crates/rustleaks-core).

The documentation describes the current source. Features listed under
Unreleased in the [changelog](CHANGELOG.md) are not in a release yet.

Report bugs and request features in
[GitHub issues](https://github.com/joshgarnett/rustleaks/issues).

## Install

On macOS and Linux, with Homebrew:

```sh
brew install joshgarnett/tap/rustleaks
```

On Windows, with Scoop:

```powershell
scoop bucket add rustleaks https://github.com/joshgarnett/scoop-bucket
scoop install rustleaks/rustleaks
```

Each release also has `.deb` and `.rpm` packages for Linux with glibc 2.28 or
later, and archives for Linux (glibc and musl), macOS and Windows, each on
x86_64 and ARM64. See [Getting started](docs/user/getting-started.md) for
how to install and check them, or to build from source with Bazel.

## First scan

```sh
rustleaks dir .                 # files in the current folder
rustleaks git .                 # every commit in the current repository
cat app.log | rustleaks stdin   # standard input
```

The exit code is 0 when nothing is found and 1 when secrets are found. Add
`--report-path findings.json` to save a report. Run `rustleaks --help` to list
the commands and flags.

To stop Rustleaks from reporting a value that is not a secret, add an
[allow comment](docs/user/configuration.md#allow-comments), an
[ignore file](docs/user/configuration.md#ignore-files) entry or an
[allowlist](docs/user/configuration.md#allowlist-fields).

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

The value above is synthetic test data. The engine is synchronous and starts a
thread only to compile a pattern with more than 200 groups. It reads files
only through two helpers that you call yourself.
See [Using
rustleaks-core](docs/user/library.md) and the [API
documentation](https://docs.rs/rustleaks-core).

## Documentation

For people who use the `rustleaks` command:

- [Getting started](docs/user/getting-started.md)
- [Command reference](docs/user/cli-reference.md)
- [Configuration](docs/user/configuration.md)
- [Reports](docs/user/reports.md)
- [Using Rustleaks in CI and Git hooks](docs/user/ci.md)
- [Built-in rules](docs/user/built-in-rules.md)
- [Complete scanning](docs/user/complete-scanning.md)
- [Resource limits](docs/user/resource-limits.md)
- [Moving from Gitleaks](docs/user/moving-from-gitleaks.md)

For Rust developers who use the library:

- [Using rustleaks-core](docs/user/library.md)
- [Review records](docs/user/review-records.md)

For people who work on Rustleaks, start with [Contributing](CONTRIBUTING.md)
and the [developer documentation](docs/dev/README.md). Changes are listed in
the [changelog](CHANGELOG.md).

## AI-assisted development

Much of Rustleaks was written with AI coding agents under human direction.
Every change must pass tests and review.

## Security

Do not put real credentials or private vulnerability details in a public
issue. Use [private vulnerability
reporting](https://github.com/joshgarnett/rustleaks/security/advisories/new).
See the [security policy](SECURITY.md).

## Thanks

Rustleaks builds on the behavior, rules, tests and fixtures of
[Gitleaks](https://github.com/gitleaks/gitleaks), and thanks its maintainers
and contributors. Rustleaks is an independent project. It is not affiliated
with or endorsed by Gitleaks.

## License

Rustleaks code is licensed under the [MIT License](LICENSE). Copied Gitleaks
configuration, fixtures and test material keep their MIT terms. Adapted Go
code keeps its BSD terms. The Rustleaks rule files keep their MIT or Apache-2.0
source terms. Forked codec crates and codec fixtures keep their own licenses,
which are stored next to them. Release archives include every license in a
`licenses` folder.
See [NOTICE](NOTICE) and the [rule file
notice](crates/rustleaks-core/default/NOTICE).
