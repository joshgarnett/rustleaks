# rustleaks-core

`rustleaks-core` is the detection engine of
[Rustleaks](https://github.com/joshgarnett/rustleaks), a secret scanner. It
scans bytes that you give it for secrets, such as API keys and passwords. It
reads configuration files, ignore files, baselines and allow comments written
for Gitleaks 8.30.0. Its findings can differ from Gitleaks. See [Moving from
Gitleaks](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/moving-from-gitleaks.md).

The engine is synchronous. It does not read files, run Git, read environment
variables, write logs or need an async runtime. It starts a thread only to
compile a pattern with more than 200 groups. Only `Baseline::load_go_json`
and `FileSystemResolver` read files, when you call them. An `Engine` can be
shared between threads.

Before 1.0, a minor release, such as 0.3.0, can change the API. A patch
release, such as 0.2.1, does not.

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
covers configuration, sessions, ignore files, baselines, built-in rules and
review records.

## Rules

The crate includes 547 built-in rules, counting helper rules that do not
report findings by themselves. `ConfigLoader::load_default` gives all of
them, the same rules as the `rustleaks` command. [Built-in
rules](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/built-in-rules.md)
lists what they find.

The rules are kept in four files so that each file keeps its source and
license. You do not need to choose between them. To build an engine from only
some of the files, see [Choosing rule
files](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/library.md#choosing-rule-files).

## Limits

`Engine::scan_fragment` has no limits. For untrusted input, use
`Engine::scan_fragment_controlled` with a `ScanBudget`, and check
`ScanOutcome::is_complete()` before you treat a result as clean. Budgets apply
to one fragment. Findings keep secret bytes in memory. See [Budgets and
cancellation](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/library.md#budgets-and-cancellation).

## License

The Rustleaks code is licensed under the MIT License. Copied Gitleaks
configuration and test material keep their MIT terms. Adapted Go code keeps
its BSD terms. The Rustleaks rule files keep their MIT or Apache-2.0 source
terms. See `LICENSE`, `NOTICE` and `default/NOTICE` in the crate package.
