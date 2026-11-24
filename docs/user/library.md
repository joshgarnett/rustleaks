# Using rustleaks-core

This guide is for Rust developers who want to scan bytes for secrets inside
their own program. It covers the `rustleaks-core` library: building an
engine, scanning, limits, findings, ignore files and baselines, custom rule
compositions and review records.

The full API reference is on [docs.rs](https://docs.rs/rustleaks-core).

This guide describes the current source. See the
[changelog](../../CHANGELOG.md) for what is not released yet.

## Add the library

```sh
cargo add rustleaks-core
```

`rustleaks-core` needs Rust 1.95 or later. It has no optional features. The
library is alpha software, and its API can change between alpha releases. To
pin the exact version, add it with `=`:

```sh
cargo add rustleaks-core@=0.1.0-alpha.12
```

Only `rustleaks-core` is published. The file, archive and Git readers, the
report writers and the command-line program are not published crates.

## What the library does and does not do

The engine takes bytes that you give it and returns findings. It does not read
files, run Git, read environment variables, write logs, start threads or need
an async runtime. Only two helpers read files, and only when you call them:
`Baseline::load_go_json` and `FileSystemResolver`. An `Engine` can be shared
between threads (`Send + Sync`). Build it once and reuse it, because building
it compiles every rule.

## A first scan

This example loads the default rules and scans one byte string. The value is
synthetic test data, not a credential. The `rustleaks:allow` comment is
outside the scanned bytes and does not change the result.

```rust
use std::sync::atomic::AtomicBool;
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigLoader::new().load_default()?;
    let engine = Engine::builder(config).build()?;
    let input = b"string AWSToken = \"AKIALALEMEL33243OLIB\";"; // rustleaks:allow
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
    Ok(())
}
```

## Building an engine

`ConfigLoader` turns TOML into a `CompiledConfig`. `Engine::builder(config)`
then builds the engine.

| Call | Result |
| --- | --- |
| `ConfigLoader::new().load_default()` | Every [built-in rule](built-in-rules.md), the same rules as the CLI: the 222 default rules plus the Rustleaks rules. |
| `ConfigLoader::new().load_toml(text)` | Your own configuration. It uses the Gitleaks format described in [Configuration](configuration.md). |
| `CompiledConfig::select_rules(ids)` | A copy that keeps only the named rules, like `--enable-rule`. Rules they require stay without reporting. |

A configuration can use `[extend] useDefault = true` to build on the
built-in rules. A configuration with `[extend] path = "..."` needs file
access, which the loader does not have by default. Give it a resolver:

```rust
use rustleaks_core::config::{ConfigLoader, FileSystemResolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let loader = ConfigLoader::new()
        .with_resolver(FileSystemResolver::with_base_directory("config"));
    let config = loader.load_toml("[extend]\nuseDefault = true\n")?;
    assert!(config.rule("aws-access-token").is_some());
    Ok(())
}
```

`FileSystemResolver` reads a relative `extend.path` from the folder of the
configuration that names it, when that configuration came from a file. Load a
file with `load_toml_at(text, Some(ConfigOrigin::Path(path)))` to give it that
folder. For text without a file path, the resolver uses the folder set with
`FileSystemResolver::with_base_directory`, or the process working folder when
you use `FileSystemResolver::new()`. It reads files of at most 16 MiB, and
a larger file fails with `ConfigError::Resolve`. `VirtualResolver` serves base
configurations from memory instead.

The CLI is different: it reads a relative `extend.path` from the current
working folder.

The loader ignores `minVersion` unless you set a current version with
`ConfigLoader::new().with_current_version("8.30.0")?`. The call fails if the
version you give is not valid. With a version set, invalid `minVersion`
values are errors and `CompiledConfig::requires_newer_version()` tells you
whether the configuration asks for a newer version.

## Scanning bytes

`Fragment` holds the bytes to scan and optional source details:

```rust
use rustleaks_core::model::{Fragment, ScanOptions};

fn main() {
    let fragment = Fragment::builder(b"token = \"value\"\n")
        .file_path("config/app.env")
        .start_line(1)
        .build();
    let options = ScanOptions::builder().max_decode_depth(5).build();
    let _ = (fragment, options);
}
```

| Builder method | Meaning |
| --- | --- |
| `file_path` | The path reported in `Finding::file`. Path rules and path allowlists test this value. |
| `start_line` | The line number of the first line. The default is 0. Use 1 to number lines like the CLI. |
| `commit`, `commit_metadata` | Git details reported in findings. |
| `symlink_file` | The link path for a file reached through a symbolic link. |
| `windows_file_path` | The original Windows spelling of the path, with `\` separators. Rule `path` patterns also test this value. It is not reported. |

`ScanOptions` controls detection. Build it with `ScanOptions::builder()`:

| Option | Default in the library | Default in the CLI |
| --- | --- | --- |
| `max_decode_depth` | 0, no decoding | 5 |
| `base64_mode` | `Base64Mode::Compatible` | `compatible` |
| `max_target_bytes` | `None`, no limit | No limit |
| `redaction_percent` | 0 | 0, 100 with `--redact`, or N with `--redact=N` |
| `honor_allow_markers` | `true` | `true` |

Set `max_decode_depth(5)` to decode encoded text the way the CLI does.
`max_target_bytes` skips rules for a fragment that is larger than the limit.
It is not a budget, and the outcome is still reported as complete.

## Budgets and cancellation

`Engine::scan_fragment` runs with no limits. For untrusted input, use
`Engine::scan_fragment_controlled` with a `ScanControl`:

- `ScanControl::unlimited()` has no cancellation.
- `ScanControl::cancellable(&flag)` takes an `AtomicBool` or any
  `Fn() -> bool + Send + Sync`. The engine checks it between steps.
- `.with_budget(ScanBudget::unlimited().max_...(n))` adds limits. The
  budgets are `max_decoded_bytes`, `max_work_units`, `max_finding_records`,
  `max_finding_payload_bytes`, `max_collected_spans` and
  `max_normalization_bytes`.

When a budget runs out or the flag is set, the scan stops early:

```rust
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::{Engine, ScanBudget, ScanControl, ScanTermination};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::builder(ConfigLoader::new().load_default()?).build()?;
    let control = ScanControl::unlimited()
        .with_budget(ScanBudget::unlimited().max_work_units(0));
    let outcome = engine.scan_fragment_controlled(
        &Fragment::new(b"string AWSToken = \"AKIALALEMEL33243OLIB\";"), // rustleaks:allow
        &ScanOptions::default(),
        &control,
    );

    assert!(!outcome.is_complete());
    match outcome.termination() {
        Some(ScanTermination::BudgetExceeded { kind, limit, consumed, requested }) => {
            println!("{kind:?}: limit {limit}, used {consumed}, asked for {requested}");
        }
        Some(ScanTermination::Cancelled) => println!("cancelled"),
        _ => {}
    }
    Ok(())
}
```

Every budget is optional and includes its value. When a budget runs out,
`termination()` says which budget ran out, with the limit, the amount used and
the amount asked for. A partial outcome keeps only the findings of rules that
finished. `ScanOutcome::usage()` reports what the scan used.

What your program must do:

- Check `is_complete()` before you treat a result as clean. Partial findings
  are not a full result.
- Budgets apply to one fragment. If you split one file or request into many
  fragments, add your own limits for the total bytes, findings, work and time.
- Cancellation is not immediate. The engine checks your cancellation flag
  between steps, and one pattern search cannot be interrupted. Use the flag
  to build your own time limit.
- Limit the size of each fragment before you scan it.
- A work unit is an internal count of detection steps. It has no fixed time
  cost, and the count for the same input can change between releases.
- Detection is synchronous. If you call it from an async runtime, run it on a
  blocking thread.
- Findings hold secret bytes. See [Reading findings](#reading-findings).

See [Resource limits](resource-limits.md) for the limits of the `rustleaks`
command.

## Reading findings

`ScanOutcome::findings()` returns the findings. Text fields are `ByteText`,
which keeps the original bytes. Use `as_bytes()`, `as_str()` (fails on
invalid UTF-8) or `to_string_lossy()`.

| Method | Meaning |
| --- | --- |
| `rule_id()`, `description()` | The rule that matched. |
| `secret()`, `match_text()` | The secret, and the full text the rule matched. |
| `location()` | `start_line()`, `end_line()`, `start_column()` and `end_column()`, with the same values as the CLI report fields. See [Line and column numbers](reports.md#line-and-column-numbers). |
| `secret_range()`, `match_range()` | `FindingRange::Exact(ByteRange)` with exact byte offsets into the fragment, or `FindingRange::Unavailable` when no exact range exists, for example for decoded text. |
| `line()` | The source line that holds the match. |
| `file()`, `symlink_file()`, `commit()`, `author()`, `email()`, `date()`, `message()` | Values copied from the fragment. |
| `link()` | A web link to the finding. The engine leaves it empty. The CLI adds it for Git history scans. |
| `entropy()`, `tags()` | Shannon entropy of the secret, and rule and decoding tags. |
| `fingerprint()` | Empty until a session assigns it. See below. |
| `required_findings()` | Helper findings for rules with `[[rules.required]]`. |

Use the exact ranges, not line and column numbers, if you need to change the
scanned bytes. Do not guess a range that is `Unavailable`.

Findings keep secret bytes in memory and are not cleared when dropped. Their
`Debug` output leaves the contents out. `Finding::redacted(percent)` masks the
primary secret only; it does not change `required_findings()`.
`Finding::without_detected_secrets()` removes every detected secret,
including the values of required findings. `Finding` also implements `serde::Serialize` with the
JSON report field names. That output includes the secret. Before you log
findings or send them elsewhere, use one of these methods or copy only the
fields you need.

## Sessions, ignore files and baselines

A session gives each finding its fingerprint and drops findings that an
ignore file or a baseline covers, as the CLI does.

```rust
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::session::{IgnoreSet, ScanSession, SessionPolicy};
use rustleaks_core::Engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::builder(ConfigLoader::new().load_default()?).build()?;
    let parsed = IgnoreSet::parse_go_compatible(b"config/old.env:aws-access-token:1\n");
    assert!(parsed.issues.is_empty());
    let policy = SessionPolicy::builder().ignores(parsed.ignores).build();
    let mut session = ScanSession::new(policy);

    let fragment = Fragment::builder(b"string AWSToken = \"AKIALALEMEL33243OLIB\";") // rustleaks:allow
        .file_path("config/app.env")
        .start_line(1)
        .build();
    let outcome = engine.scan_fragment(&fragment, &ScanOptions::default());
    assert!(outcome.is_complete());
    for finding in outcome.into_findings() {
        let added = session.add_finding(finding);
        assert!(added.is_accepted());
    }
    let findings = session.into_findings();
    assert_eq!(
        findings[0].fingerprint().as_str()?,
        "config/app.env:aws-access-token:1"
    );
    Ok(())
}
```

- `IgnoreSet::parse_go_compatible` reads `.rustleaksignore` and
  `.gitleaksignore` content. `IgnoreSet::extend_go_compatible` adds more
  files to the same set. See [Ignore files](configuration.md#ignore-files)
  for the format.
- `Baseline::load_go_json(path)` or `Baseline::from_go_json(bytes)` reads a
  JSON report. Add it with `SessionPolicyBuilder::baseline`.
- If you scan with redaction, also call
  `SessionPolicyBuilder::redaction_percent` with the same value. Baselines then
  skip the match and secret when they compare findings.
- `add_finding` returns `AddOutcome::Accepted` or `AddOutcome::Suppressed`
  with the reason: `GlobalIgnore`, `CommitIgnore` or `Baseline`.
- To collect findings on several threads, create one `SessionBatch` for each
  thread with `ScanSession::new_batch`, and `merge` the batches into the
  session at the end.
- `session::global_fingerprint` and `session::qualified_fingerprint` build
  fingerprints without a session.

## Built-in rules

`ConfigLoader::new().load_default()` and `[extend] useDefault = true` give
every built-in rule, the same rules as the CLI: the default rules plus the
Rustleaks rules. See [Built-in rules](built-in-rules.md) for what they
cover. The Rustleaks rules compile the first time a loader needs them, once
for the loader and its clones, so a configuration that does not extend the
default does not pay for them. Reuse the loader or the `CompiledConfig`
instead of creating a new loader for each scan.

To use the default rules alone, pass `config::DEFAULT_CONFIG` to
`with_default_config`. Any text passed to `with_default_config` replaces the
whole default, without the Rustleaks rules.

```rust
use rustleaks_core::config::ConfigLoader;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::Engine;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigLoader::new().load_default()?;
    assert!(config.rule("rustleaks.groq-api-key").is_some());
    let engine = Engine::builder(config).build()?;
    let outcome = engine.scan_fragment(&Fragment::new(b"no secrets here"), &ScanOptions::default());
    assert!(outcome.findings().is_empty());
    Ok(())
}
```

### Custom compositions

`NativePolicy` starts from the default rules and adds rule files that you
choose, with an identity that records them. `with_pack` adds one rule file.
The built-in rule files can be added in any order. The exact bytes and the
order of the rule files are part of the identity.

```rust
use rustleaks_core::explanation::ExplanationOptions;
use rustleaks_core::model::{Fragment, ScanOptions};
use rustleaks_core::native::{CONNECTION_RULES_V1, NativePolicy, PROVIDER_RULES_V1};
use rustleaks_core::ScanControl;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = NativePolicy::builder()
        .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)?
        .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)?
        .build()?;
    let result = engine.scan_fragment_controlled(
        &Fragment::new(b"no secrets here"),
        &ScanOptions::default(),
        &ScanControl::unlimited(),
        ExplanationOptions::disabled(),
    );
    assert!(result.scan().is_complete());
    assert!(engine.identity().builtin_review_reference().is_some());
    Ok(())
}
```

- Use the rule file IDs shown above, such as `rustleaks-providers-v1`.
  `builtin_review_reference()` returns a value only for the built-in rule
  files under their own IDs.
- `NativeEngine::engine()` returns the plain `Engine`, which works with
  sessions.
- `NativePolicy::compile()` returns the `CompiledConfig` and the
  `NativePolicyIdentity` without building an engine.
- You can also add your own rule files with `with_pack`. Their rule IDs
  must start with `rustleaks.`. A rule file cannot replace or disable an
  existing rule.
- `ExplanationOptions::bounded(n)` records up to `n` numeric diagnostic
  events about the scan. They contain no source bytes.

## Review records

The `triage` module tracks findings that a person has already reviewed. See
[Review records](review-records.md).
