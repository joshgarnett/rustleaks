# Native rule packs

This guide is for people who want Rustleaks to look for more kinds of secrets
than the default rules cover. It explains the optional rule packs that ship
with Rustleaks and how to turn them on.

## What a rule pack is

The default rules are based on the Gitleaks default configuration, with 222
rules and the changes in [Default rules](gitleaks-differences.md#default-rules).
Rustleaks also ships three optional rule packs. A pack adds rules to the
default rules. It never changes or removes a default rule. No pack is used
unless you ask for it.

| Pack ID | Rules | What it adds | Details |
| --- | ---: | --- | --- |
| `rustleaks-extra-v1` | 3 | Azure Service Bus and Event Hubs keys, Azure App Configuration secrets, and MongoDB URI passwords | [pack contract](../../crates/rustleaks-core/default/rustleaks-extra-v1.md) |
| `rustleaks-providers-v1` | 303 | API keys and tokens for many service providers, such as Groq, NVIDIA, Figma, Slack session tokens, Mapbox and Vercel | [pack contract](../../crates/rustleaks-core/default/rustleaks-providers-v1.md) |
| `rustleaks-connections-v1` | 14 | Passwords in database connection strings, JDBC and ODBC URLs, libpq keyword strings, and Git URLs with credentials | [pack contract](../../crates/rustleaks-core/default/rustleaks-connections-v1.md) |

The rule counts include helper rules that other rules depend on and that do
not report findings by themselves. With all three packs, a scan uses 542
rules.

All pack rule IDs start with `rustleaks.`, for example
`rustleaks.groq-api-key`. This keeps them apart from the default rule IDs.

Pack rules work only on the bytes they scan. They do not contact a provider,
and they do not check whether a credential is active.

## Turning on a pack

Add `--native-pack ID` to a scan. Repeat the flag to add more packs:

```sh
rustleaks dir . --native-pack rustleaks-providers-v1
rustleaks git . \
  --native-pack rustleaks-extra-v1 \
  --native-pack rustleaks-providers-v1 \
  --native-pack rustleaks-connections-v1
```

An unknown pack ID, or the same ID twice, stops the scan with an error.

Packs build on the default rules only. If the scan would use another
configuration, Rustleaks stops with an error instead of quietly dropping your
rules or allowlists. That includes `--config`, a non-empty
`RUSTLEAKS_CONFIG`, `RUSTLEAKS_CONFIG_TOML`, `GITLEAKS_CONFIG` or
`GITLEAKS_CONFIG_TOML` variable, and a `.rustleaks.toml` or `.gitleaks.toml`
file in the scanned folder. See [Configuration](configuration.md) for the full
search order.

Everything else works as usual with packs: `--enable-rule`, ignore files,
baselines, allow comments, redaction, reports and `--complete-profile`.
`--enable-rule` can select pack rules by their `rustleaks.` IDs.

With `--log-level debug`, Rustleaks logs a line that names the selected packs
in order, with a SHA-256 hash of each pack. Keep this line with your results
if you need to show later which rules a scan used.

That line covers the whole pack composition, not an `--enable-rule`
selection. To make a scan record that someone can reproduce, also record the
Rustleaks binary, the selected rule IDs, the scan options and any complete
scanning profile.

If you keep review or cache decisions next to scan results, store the pack
identity with each decision. Reject a stored decision when the identity does
not match. A matching identity alone does not prove that the input or the
scan options were the same.

## Using a pack file with --config

Pack files use TOML, but some pack rules use fields that only the pack loader
understands, such as byte-based entropy checks. The providers and connections
pack files fail with an error when you pass them with `--config`, through a
configuration variable, or as an `extend` base. The extra pack file loads that
way, but then it is a normal configuration with only its own 3 rules, without
the default rules. Use `--native-pack` instead.

## Packs in the library

Library users add packs with `NativePolicy`. The pack text is built into
`rustleaks-core` as constants:

| Pack ID | Constant |
| --- | --- |
| `rustleaks-extra-v1` | `rustleaks_core::native::EXTRA_RULES_V1` |
| `rustleaks-providers-v1` | `rustleaks_core::native::PROVIDER_RULES_V1` |
| `rustleaks-connections-v1` | `rustleaks_core::native::CONNECTION_RULES_V1` |

See [Using rustleaks-core](library.md#native-rule-packs) for an example.

## Findings from packs and default rules

A pack rule and a default rule can match the same secret. Rustleaks uses the
same filter as Gitleaks for rules with `generic` in their ID, such as
`generic-api-key`. The filter drops a finding from such a rule only when all
of these are true:

- another rule finds a secret on the same line and in the same commit;
- that rule has no `generic` in its ID; and
- its secret contains the generic secret.

Pack rule IDs do not contain `generic`, so a pack rule can replace a
`generic-api-key` finding in this way. In all other cases, both findings are
reported.
