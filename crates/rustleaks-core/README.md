# rustleaks-core

`rustleaks-core` is the detection engine of
[Rustleaks](https://github.com/joshgarnett/rustleaks), a secret scanner. It
reads Gitleaks configuration files and scans bytes that you give it for
secrets, such as API keys and passwords. Rustleaks is compatible with Gitleaks
8.30.0 configuration, findings and reports. See [Differences from
Gitleaks](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/gitleaks-differences.md)
for the exceptions.

The engine is synchronous. It does not read files, run Git, read environment
variables, write logs, start threads or need an async runtime. Only
`Baseline::load_go_json` and `FileSystemResolver` read files, when you call
them. An `Engine` can
be shared between threads.

The crate is alpha software. Its API can change between alpha releases.
Rustleaks is an independent project and is not affiliated with or endorsed by
Gitleaks.

## Example

```rust
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigLoader::new().load_default()?;
    let engine = Engine::builder(config).build()?;
    let input = b"string AWSToken = \"AKIALALEMEL33243OLIB\";"; // rustleaks:allow
    let control = ScanControl::unlimited().with_budget(
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
    Ok(())
}
```

The value is synthetic test data, not a credential. The guide [Using
rustleaks-core](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/library.md)
covers configuration, sessions, ignore files, baselines, rule packs and review
records.

## Rules

The crate includes the Gitleaks default rules and three optional rule packs.
The packs add rules to the default rules and are used only when you add them
with `native::NativePolicy`. Rule counts include helper rules.

| Rule set | Constant | Rules | Details |
| --- | --- | ---: | --- |
| Gitleaks default rules | `config::DEFAULT_CONFIG` | 222 | [Compatibility policy](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/gitleaks-differences.md#compatibility-policy) |
| `rustleaks-extra-v1` | `native::EXTRA_RULES_V1` | 3 | [Pack contract](https://github.com/joshgarnett/rustleaks/blob/main/crates/rustleaks-core/default/rustleaks-extra-v1.md) |
| `rustleaks-providers-v1` | `native::PROVIDER_RULES_V1` | 300 | [Pack contract](https://github.com/joshgarnett/rustleaks/blob/main/crates/rustleaks-core/default/rustleaks-providers-v1.md) |
| `rustleaks-connections-v1` | `native::CONNECTION_RULES_V1` | 14 | [Pack contract](https://github.com/joshgarnett/rustleaks/blob/main/crates/rustleaks-core/default/rustleaks-connections-v1.md) |

## Limits

`Engine::scan_fragment` has no limits. For untrusted input, use
`Engine::scan_fragment_controlled` with a `ScanBudget`, and check
`ScanOutcome::is_complete()` before you treat a result as clean. Budgets apply
to one fragment. Findings keep secret bytes in memory. See [Budgets and
cancellation](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/library.md#budgets-and-cancellation).

## License

The Rustleaks code is licensed under the MIT License. Copied Gitleaks
configuration and test material keep their MIT terms. Adapted Go code keeps
its BSD terms. The optional rule packs keep their MIT or Apache-2.0 source
terms. See `LICENSE`, `NOTICE` and `default/NOTICE` in the crate package.
