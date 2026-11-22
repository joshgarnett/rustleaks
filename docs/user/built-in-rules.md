# Built-in rules

This guide is for people who want to know which rules a Rustleaks scan uses.

## What a scan uses

Without a configuration file, Rustleaks scans with all of its built-in rules:

- the [default rules](#default-rules), 222 rules that started from the
  Gitleaks default configuration; and
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

## Default rules

The default rules are in
[`gitleaks.toml`](../../crates/rustleaks-core/default/gitleaks.toml). They
started from the Gitleaks default configuration at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (`v8.30.0-27-gb58d3f1`), and
Rustleaks changes them in its own releases. Rustleaks has added these
allowlists:

- `generic-api-key` does not report:
  - hex digests of 32, 40, 64 or 128 characters under a name with md5, sha,
    digest, checksum, fingerprint, hash or etag, such as `token_md5`;
  - 40-character Git object IDs under a name that ends in commit, revision or
    rev, such as `token_commit`;
  - Subresource Integrity values such as `sha384-` and a Base64 digest;
  - Stripe publishable keys (`pk_live_` and `pk_test_`), which Stripe
    documents as safe to expose;
  - UUIDs under identifier names such as `token_id`, `client_id` or
    `keycloak.client-id`. Names that contain `secret`, such as `secret_id`,
    and key names such as `api_key` are not affected.
- A global allowlist hides, from every rule, the exact example values that
  Discord, Azurite, Telegram, Slack and Google publish in their
  documentation.

Known loss: UUIDs under names such as `client_id` or `keycloak.client-id`
are public OAuth and Keycloak identifiers, but some test sets label them as
secrets. `generic-api-key` does not report them.

The global `[allowlist]` table of the Gitleaks file is written as the first
`[[allowlists]]` entry, which has the same meaning.

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

In `rustleaks-core`, `ConfigLoader::load_default` and `useDefault` give
every built-in rule, as the CLI does. `ConfigLoader::with_default_config`
replaces the default, for example with `config::DEFAULT_CONFIG` for the
default rules alone. `NativePolicy` builds a custom composition. See [Using
rustleaks-core](library.md#built-in-rules).

## Findings from two rules

Two built-in rules can match the same secret. Two filters keep some of these
to one finding.

Rustleaks uses the same filter as Gitleaks for rules with `generic` in their
ID, such as `generic-api-key`. The filter drops a finding from such a rule
only when all of these are true:

- another rule finds a secret on the same line and in the same commit;
- that rule has no `generic` in its ID; and
- its secret contains the generic secret.

Rustleaks rule IDs do not contain `generic`, so a Rustleaks rule can replace a
`generic-api-key` finding in this way.

The second filter covers reviewed pairs of built-in rules. When both rules of
a pair report the same secret at the same bytes of the same file and commit,
only one finding is reported:

| Reported | Not reported | Why |
| --- | --- | --- |
| `grafana-api-key` | `rustleaks.grafana-api-key-base64` | Same Grafana key |
| `alibaba-access-key-id` | `rustleaks.alibaba-access-key-id-boundary` | Same Alibaba Cloud AccessKey ID |
| `planetscale-api-token` | `rustleaks.association.planetscale-api-token` | Same PlanetScale token |
| `artifactory-api-key` or `jfrog-api-key` | `rustleaks.association.artifactory-api-key` | Same JFrog API key |
| `artifactory-reference-token` or `jfrog-identity-token` | `rustleaks.association.artifactory-reference-token` | Same JFrog reference token |
| `gitlab-incoming-mail-token` | `rustleaks.gitlab-incoming-mail-address-token` | Same GitLab incoming mail token |
| `slack-config-access-token` | `rustleaks.slack-config-access-token-166` | Same Slack configuration token |
| `rustleaks.xai-api-key-delimiter` | `rustleaks.xai-api-key-80` | Same xAI key |
| `rustleaks.workos-production-api-key` | `stripe-access-token` | A WorkOS key also fits the Stripe pattern |
| `rustleaks.highnote-secret-live-key` | `stripe-access-token` | A Highnote key also fits the Stripe pattern |
| `rustleaks.clerk-secret-key-delimiter` | `rustleaks.stripe-access-token-delimiter` | A Clerk key also fits the Stripe pattern |
| `rustleaks.temporal-cloud-api-key` | `jwt` | A Temporal Cloud key is a JWT |
| `rustleaks.monday-api-token` | `jwt` | A Monday token is a JWT |

The secret is always reported. A rule that is not reported for one secret
still reports every secret that the other rule does not, for example a
Stripe key without a WorkOS name nearby. If an allowlist, an `--enable-rule`
selection or `disabledRules` removes the reported rule's finding, the other
finding stays. Ignore files and baselines apply after this filter, so an
entry for the reported finding also hides the secret. A configuration file
cannot add pairs.

In all other cases, both findings are reported. For example,
`curl-auth-header` reports the token in a curl `Authorization` header next to
the rule for that token. `rustleaks.endorlabs-api-key` and
`rustleaks.endorlabs-api-secret` both report a value whose name says only
`endor`, since either part of the credential can have that name.
