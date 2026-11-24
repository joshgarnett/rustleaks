# Rustleaks extra rules v1

This file is the reference for maintainers of the `rustleaks-extra-v1`
rules. For the rules a scan uses, see [Built-in
rules](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/built-in-rules.md).

This rule file adds 3 namespaced rules for Azure Service Bus and Event Hubs
keys, Azure App Configuration keys and MongoDB URI passwords. It has no
hidden helper rules. Every default scan uses these rules. They run locally.
They do not contact a provider or check whether a credential is active. They
use the normal matching, allowlist, overlap filtering and decoding behavior.

## Selection

- The rule file uses no native-only tables. It also loads with `--config` or
  `ConfigLoader`, but then it is a plain configuration with only these 3
  rules and without the default rules.
- In a custom composition, add it with
  `NativePolicy::builder().with_pack("rustleaks-extra-v1", EXTRA_RULES_V1)`.
  `EXTRA_RULES_V1` is in `rustleaks_core::native`.

See [Using
rustleaks-core](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/library.md#built-in-rules)
for the library and [Rule pack
authoring](https://github.com/joshgarnett/rustleaks/blob/main/docs/dev/rule-pack-authoring.md)
for contributors.

## Rules

Rule IDs in the table leave out the `rustleaks.` prefix. Entropy is Shannon
entropy of the secret. "Above N" means that values at or below N are
rejected.

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `azure-servicebus-key` | Public cloud `sb://` endpoint, a nonempty `SharedAccessKeyName` and a `SharedAccessKey` of 43 base64 characters plus padding, in any of the 6 orders of the 3 core fields, with an optional `EntityPath` between fields | Key value, including padding | Shannon entropy above 3.5 |
| `azure-app-configuration-key` | Public cloud `https://` endpoint, a nonempty `Id` and a base64 `Secret`, in any of the 6 field orders | Secret value, including padding | Shannon entropy above 3.5 |
| `mongodb-password` | Standard or SRV URI with a nonempty ASCII or percent-encoded user name and password. Standard URIs take a DNS or IPv4 host list; SRV URIs take one DNS host without a port | Password bytes as written, including percent escapes | None; an allowlist for template values |

Azure notes:

- Field names are case-insensitive. Spaces and tabs around separators are
  accepted. The first `=` separates a field name from its value.
- The first capture that takes part in the match is the secret. This selects
  the secret across the field order alternatives.
- The key name, credential ID and endpoint are never part of the secret
  range.
- Microsoft describes Service Bus signing keys as 256-bit base64 values. App
  Configuration has no published length for secrets, so the rule accepts
  complete base64 groups with 16 to 131 characters before padding. This bound
  is a detection choice, not an issuer rule.
- The entropy floor removes repeated-value placeholders. It is not an issuer
  check and can miss credentials with low entropy.

MongoDB notes:

- Passwords are chosen by users, so the rule has no entropy floor.
- The rule allowlist accepts only these percent-encoded template spellings:
  `<password>`, `<your_password>`, `${PASSWORD}` and `{{password}}`.
- Escaped reserved URI characters stay escaped in raw findings.

## Shared boundaries

- Input byte ranges and the original spelling are kept.
- The optional decoding pass can find a whole encoded URI or connection
  string. The source range of such a finding is unavailable.
- Escaping in source languages needs a decoding pass that the caller selects.
  The rules do not guess unknown escapes or decide validity from a partial
  match.
- The rules are not a complete connection string parser.
- Known gaps for Azure: sovereign cloud endpoints, custom hosts, new fields
  between App Configuration fields, Unicode whitespace around fields and
  strings outside the size bounds.
- Known gaps for MongoDB: IPv6 addresses, Unix sockets, literal non-ASCII user
  information, more than 4 standard hosts and very long credentials.
- Default generic rules can still find key values in these gaps. A missing
  finding never shows that an input has no credentials.
- These rules do not suppress or replace existing provider rules. When a
  MongoDB password also has the shape of a provider token, both rules can
  report the same occurrence.

## Provenance and license

The rules and fixtures were written for Rustleaks from the primary format
references below. No third-party pattern, code or fixture was copied. They
are covered by the repository's MIT license.

References:

- [Service Bus connection string properties](https://learn.microsoft.com/en-us/javascript/api/@azure/service-bus/servicebusconnectionstringproperties?view=azure-node-latest):
  endpoint, policy name and key, and optional entity path.
- [Service Bus shared access signatures](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas):
  the 256-bit base64 key form.
- [Event Hubs connection strings](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string):
  the shared endpoint, policy and key form, and entity path.
- [App Configuration connection setup](https://learn.microsoft.com/en-us/azure/service-connector/how-to-integrate-app-configuration):
  the `Endpoint`, `Id` and `Secret` fields.
- [App Configuration HMAC authentication](https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac):
  base64 decoding of the access key value.
- [Azure SDK connection string parser](https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/src/Shared/ConnectionString.cs):
  any field order, case-insensitive names, trimmed whitespace and the first
  `=` as separator. No parser code was copied.
- [MongoDB connection string formats](https://www.mongodb.com/docs/manual/reference/connection-string-formats/):
  credentials, percent encoding of reserved characters, standard host lists,
  and one SRV host without a port.
