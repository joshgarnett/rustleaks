# Built-in rules

This guide is for people who want to know which rules a Rustleaks scan uses.

## What a scan uses

Rustleaks has 547 built-in rules. Without a configuration file, every scan
uses all of them. The count includes helper rules that other rules depend
on. Helper rules do not report findings by themselves.

The built-in rules are:

- the [Gitleaks-based rules](#gitleaks-based-rules), 222 rules that started
  from the Gitleaks default configuration; and
- the Rustleaks rules, which add more service providers and connection
  strings.

| Rules | What they find |
| --- | --- |
| Gitleaks-based rules | API keys, tokens and private keys for many services, and generic secrets such as `api_key = "..."` |
| Rustleaks extra rules | Azure Service Bus and Event Hubs keys, Azure App Configuration secrets, and MongoDB URI passwords |
| Rustleaks provider rules | API keys and tokens for many more service providers, such as Groq, NVIDIA, Figma, Slack session tokens, Mapbox and Vercel |
| Rustleaks connection rules | Passwords in database connection strings, JDBC and ODBC URLs, libpq keyword strings, service URIs and Git URLs with credentials |

The rules are kept in four files so that each file keeps its source and
license. You do not choose between them: a scan uses all four. Maintainers
can read the reference page of each Rustleaks rule file:
[extra](../../crates/rustleaks-core/default/rustleaks-extra-v1.md),
[providers](../../crates/rustleaks-core/default/rustleaks-providers-v1.md) and
[connections](../../crates/rustleaks-core/default/rustleaks-connections-v1.md).

All Rustleaks rule IDs start with `rustleaks.`, for example
`rustleaks.groq-api-key`. This keeps them apart from the Gitleaks-based rule
IDs. `--enable-rule` can select any built-in rule by ID.

For a few reviewed pairs of rules that find the same secret, Rustleaks
reports only one of the two findings. See [Findings from two
rules](#findings-from-two-rules).

The rules work only on the bytes they scan. They do not contact a provider,
and they do not check whether a credential is active.

## Gitleaks-based rules

The Gitleaks-based rules are in
[`gitleaks.toml`](../../crates/rustleaks-core/default/gitleaks.toml). They
started from the Gitleaks default configuration at the commit named in
[Moving from Gitleaks](moving-from-gitleaks.md), and Rustleaks changes them
in its own releases. Rustleaks has added these allowlists:

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
    and key names such as `api_key` are not affected. Some tools treat these
    identifiers as secrets; Rustleaks does not.
- A global allowlist hides, from every rule, the exact example values that
  Discord, Azurite, Telegram, Slack and Google publish in their
  documentation.

## With a configuration file

A configuration file replaces the built-in rules. To keep them and add your
own rules, extend the built-in rules:

```toml
[extend]
useDefault = true

[[rules]]
id = "my-token"
regex = '''my_token_[0-9a-f]{32}'''
```

`useDefault = true` gives every built-in rule. `disabledRules` can turn off
any of them by ID. A rule in your file with the same ID as a built-in rule
changes it. If you set `entropy` on a Rustleaks rule, your value replaces its
entropy check. If you set `regex` on a Rustleaks rule, your regex replaces the
built-in pattern, and the rule no longer needs its helper rules. It then
reports every match of your regex.

To scan with the Gitleaks-based rules only, pass a configuration that does
not extend the built-in rules, such as a copy of
[`gitleaks.toml`](../../crates/rustleaks-core/default/gitleaks.toml).

See [Configuration](configuration.md) for where Rustleaks looks for a
configuration.

## Copying a Rustleaks rule file

The providers and connections rule files use fields that only the built-in
loader reads, such as byte-based entropy checks. If you pass a copy of one
with `--config`, a configuration variable or an `extend` path, loading fails.
Use `useDefault = true` instead.

## Built-in rules in the library

For the library, see [Using rustleaks-core](library.md#built-in-rules).

## Findings from two rules

Two built-in rules can match the same secret. Two filters keep some of these
to one finding.

For rules with `generic` in their ID, such as `generic-api-key`, a filter
drops a finding only when all of these are true:

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
