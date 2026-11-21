# Built-in rules

This guide is for people who want to know which rules a Rustleaks scan uses.

## What a scan uses

Without a configuration file, Rustleaks scans with all of its built-in rules:

- the default rules, which are based on the Gitleaks default configuration,
  with 222 rules and the changes in
  [Default rules](gitleaks-differences.md#default-rules); and
- the Rustleaks rules, which add more providers and connection strings.

The Rustleaks rules come from three rule files. They never change or remove a
default rule.

| Rule file | What it adds | Details |
| --- | --- | --- |
| `rustleaks-extra-v1` | Azure Service Bus and Event Hubs keys, Azure App Configuration secrets, and MongoDB URI passwords | [rule file notes](../../crates/rustleaks-core/default/rustleaks-extra-v1.md) |
| `rustleaks-providers-v1` | API keys and tokens for many service providers, such as Groq, NVIDIA, Figma, Slack session tokens, Mapbox and Vercel | [rule file notes](../../crates/rustleaks-core/default/rustleaks-providers-v1.md) |
| `rustleaks-connections-v1` | Passwords in database connection strings, JDBC and ODBC URLs, libpq keyword strings, service URIs and Git URLs with credentials | [rule file notes](../../crates/rustleaks-core/default/rustleaks-connections-v1.md) |

Some Rustleaks rules are helpers that other rules depend on. They do not
report findings by themselves.

All Rustleaks rule IDs start with `rustleaks.`, for example
`rustleaks.groq-api-key`. This keeps them apart from the default rule IDs.
`--enable-rule` can select them by ID.

The rules work only on the bytes they scan. They do not contact a provider,
and they do not check whether a credential is active.

## With a configuration file

A configuration file replaces the built-in rules. To keep them and add your
own rules, extend the default:

```toml
[extend]
useDefault = true

[[rules]]
id = "my-token"
regex = '''my_token_[0-9a-f]{32}'''
```

`useDefault = true` gives the default rules and all Rustleaks rules.
`disabledRules` can turn off any of them by ID. A rule in your file with the
same ID as a built-in rule changes it, as in Gitleaks. If you set `regex` or
`entropy` on a Rustleaks rule, your value replaces the built-in matcher or
entropy check.

To scan with the Gitleaks-derived default rules only, pass a configuration
that does not extend the default, such as a copy of
[`gitleaks.toml`](../../crates/rustleaks-core/default/gitleaks.toml).

See [Configuration](configuration.md) for where Rustleaks looks for a
configuration.

## The rule files and --config

Some Rustleaks rules use fields that only the built-in loader understands,
such as byte-based entropy checks. The providers and connections rule files
fail with an error when you pass them with `--config`, through a
configuration variable, or as an `extend` path. Use `useDefault = true`
instead.

## Built-in rules in the library

`rustleaks-core` keeps its default as the Gitleaks-derived rules alone, so
that library results stay the same unless you ask for more.
`ConfigLoader::with_builtin_rules` makes `load_default` and `useDefault`
include every Rustleaks rule, as the CLI does. `NativePolicy` builds a custom
composition. See [Using rustleaks-core](library.md#built-in-rules).

## Findings from two rules

A Rustleaks rule and a default rule can match the same secret. Rustleaks uses
the same filter as Gitleaks for rules with `generic` in their ID, such as
`generic-api-key`. The filter drops a finding from such a rule only when all
of these are true:

- another rule finds a secret on the same line and in the same commit;
- that rule has no `generic` in its ID; and
- its secret contains the generic secret.

Rustleaks rule IDs do not contain `generic`, so a Rustleaks rule can replace a
`generic-api-key` finding in this way. In all other cases, both findings are
reported.
