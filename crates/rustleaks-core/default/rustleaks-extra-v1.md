# Rustleaks extra rules v1

This first-party TOML pack is explicitly selected as `rustleaks-extra-v1`.
It adds namespaced rules to the unchanged pinned default configuration. It uses
existing matching, allowlist, overlap filtering and decoding semantics. It does
not contact a provider or establish whether credentials are active.

The definitions and fixtures were independently authored from the primary
format references below, reviewed on 2026-11-06. No third-party pattern, code or
fixture was copied. They are covered by this repository's MIT license. Refresh
requires reviewing provider format changes, updating independent controls and
rerunning the full quality comparison. There are no automatic downloads.

## Formats and extraction

| Rule ID | Bounded recognized form | Extracted secret |
| --- | --- | --- |
| `rustleaks.azure-servicebus-key` | Public-cloud `sb://` endpoint, nonempty `SharedAccessKeyName` and 43 base64 characters plus padding in `SharedAccessKey`; six core-field orders; optional interleaved `EntityPath` | Key value including padding |
| `rustleaks.azure-app-configuration-key` | Public-cloud `https://` endpoint, nonempty `Id` and bounded base64 `Secret`; six field orders | Secret value including padding |
| `rustleaks.mongodb-password` | Standard or SRV URI with nonempty ASCII or percent-encoded username/password; standard DNS/IPv4 host list or SRV DNS host without a port | Password bytes as written, including percent escapes |

Azure field names are case insensitive, horizontal space around separators is
accepted, and the first `=` separates each field name from its value. The
existing loader's first participating capture selects the secret across the
order alternatives. The key name, credential ID, username and endpoint never
form part of the secret range. Input byte ranges and original spelling remain
unchanged.

Microsoft describes Service Bus signing keys as 256-bit base64 values. App
Configuration documents base64 secrets without a universal length contract;
this pilot accepts complete base64 groups bounded to 16 through 131 nonpadding
characters. That bound is a detection scope choice, not issuer validity.
Both Azure rules require Shannon entropy above 3.5 bits per character to avoid
repeated-value placeholders; this precision guard is not an issuer validity
check and can omit low-entropy credentials. MongoDB passwords are user chosen,
so the URI rule has no entropy floor. Its rule-local allowlist recognizes only
the documented conventional percent-encoded password template spellings
`<password>`, `<your_password>`, `${PASSWORD}` and `{{password}}`. Escaped
reserved URI characters remain escaped in raw findings. A whole encoded URI or
connection string can be found by the existing optional decoding pass, whose
source ranges remain explicitly unavailable.

The pack is not a complete connection-string parser. Azure sovereign endpoints,
custom hosts, new fields interleaved between App Configuration fields, Unicode
field whitespace and strings outside the explicit size bounds are outside the
pilot. MongoDB IPv6 addresses, Unix sockets, literal non-ASCII userinfo, more
than four standard hosts and very long credentials are outside it. Source
language escaping requires an applicable caller-selected decoding pass. The
rules do not infer unknown escape semantics or validity from a partial match.
Missing coverage remains visible in the quality corpus; a missing alert never
establishes a credential-free input.

## Primary format references

- [Service Bus connection-string properties](https://learn.microsoft.com/en-us/javascript/api/@azure/service-bus/servicebusconnectionstringproperties?view=azure-node-latest)
  specifies endpoint, policy name/key and optional entity path.
- [Service Bus shared access signatures](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas)
  specifies the 256-bit base64 key representation.
- [Event Hubs connection strings](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string)
  identifies the shared endpoint/policy/key form and entity path.
- [App Configuration connection setup](https://learn.microsoft.com/en-us/azure/service-connector/how-to-integrate-app-configuration)
  identifies `Endpoint`, `Id` and `Secret`.
- [App Configuration HMAC authentication](https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac)
  specifies base64 decoding of the access-key value.
- [Azure SDK connection-string parser](https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/src/Shared/ConnectionString.cs)
  establishes field-order independence, case-insensitive names, whitespace
  trimming and the first `=` delimiter. No parser implementation was copied.
- [MongoDB connection-string formats](https://www.mongodb.com/docs/manual/reference/connection-string-formats/)
  specifies credentials, reserved-character percent encoding, standard host
  lists and the SRV single-host/no-port restriction.

## Evaluation and dispositions

The maintained quality generator adds credential-role labels, all six Azure
field orders, repeats, invalid-byte surroundings, percent envelopes, MongoDB
percent userinfo, short passwords, and negative templates and near misses.
`all-default-rules` and `all-native-rules` assess the identical corpus, with
individual native selections reported separately. This comparison retains
existing generic coverage, attribution differences, duplicates, missed
occurrences, unlocated decoded values and reviewed-negative alerts.

Sovereign Azure endpoints and MongoDB IPv6 inputs are retained as explicit
positive gap cases. They do not qualify as negative examples merely because
this pack omits them. Existing generic rules may still cover their key values.
The pack neither suppresses nor replaces existing specific rules. Its admission
requires no held-out positive loss, no added reviewed-negative alerts, and no
unreviewed duplicate alerts on the fixed synthetic comparison. These controls are
small, related structural cases, not independent deployment accuracy evidence.

The `mongodb-provider-overlap` control deliberately uses a synthetic database
password with a GitHub-token shape. Both specific rules can attribute that one
exact occurrence. One additional contextual alert is retained in this case;
no existing provider alert is suppressed to improve the duplicate metric.
Other added duplicates fail the maintained pilot gate.

The initial 72-case comparison qualifies all three bounded rules:

| Candidate | Measured benefit | Remaining disposition |
| --- | --- | --- |
| Service Bus/Event Hubs | 11 existing occurrences gain provider attribution; no additional exact occurrences claimed | Sovereign endpoint remains generic-only; encoded source range remains unavailable |
| App Configuration | 10 existing occurrences gain provider attribution; no additional exact occurrences claimed | Sovereign endpoint remains generic-only; encoded source range remains unavailable |
| MongoDB | Eight additional exact occurrences and one additional encoded value recognized | IPv6 remains missed; one reviewed provider overlap produces two attributed alerts |

Across the identical corpus, full-default versus full-native exact true
positives are 36 versus 44, false negatives 13 versus 5, and false positives
one versus one. Attribution mismatches decrease from 23 to two. Duplicate
alerts increase from zero to the one reviewed MongoDB/provider overlap.
The preexisting false alert is the deliberately benign `api_key` UUID control;
there are no new reviewed-negative alerts. All scans complete. Four remaining
exact-location misses are decoded findings, and the fifth is the MongoDB IPv6
gap. These are corpus-specific results, not estimated field accuracy.

The generated report is the source of measured counts. Candidate acceptance
must cite that report and its source/configuration identity; successful report
generation by itself is not an acceptance decision.

The packaged `.sha256` identity is generated with
`bazelisk run //crates/xtask:xtask -- generate native-pack-identity`. The normal
build contract checks its exact agreement with the TOML bytes. Regenerate it
after an intentional pack change; never edit the digest by hand.
