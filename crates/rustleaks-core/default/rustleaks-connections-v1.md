# Rustleaks connection rules v1

This optional pack adds six namespaced password rules to the unchanged
pinned defaults. Select it with the existing native composition API:

```rust
use rustleaks_core::native::{CONNECTION_RULES_V1, NativePolicy};

let engine = NativePolicy::builder()
    .with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)?
    .build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

It composes with `rustleaks-extra-v1` and `rustleaks-providers-v1` in either
order. Exact pack bytes and order participate in policy identity. Existing
engine constructors do not enable it. All detection is local. The pack adds
no parser, dependency, expression interpreter, validator, or client connection.

## Scope

Every consumed match byte is ASCII, including permitted ASCII controls.
The surrounding fragment can contain arbitrary bytes; no text normalization
occurs. Unicode or invalid-byte connection values are outside this pack's
scope. Cross-tool comparisons must use entirely ASCII raw inputs and account
for the tools' separate source, finding, and match-enumeration policies.

| Rule ID suffix | Required context | Password source form |
| --- | --- | --- |
| `double-quoted` | Semicolon host property | Double quoted, 4 through 128 bytes |
| `single-quoted` | Semicolon host property | Single quoted, 4 through 128 bytes |
| `odbc-braced` | Semicolon host property or JDBC SQL Server prefix | Braced, 4 through 128 units |
| `unquoted` | Semicolon host property or JDBC SQL Server prefix | Unquoted, 4 through 128 bytes |
| `jdbc-query` | PostgreSQL, MariaDB, or MySQL JDBC URL | Lowercase `password=` query property, 4 through 128 bytes |
| `database-uri` | PostgreSQL, MariaDB, or MySQL URI | Userinfo password, 1 through 256 bytes |

Full IDs start with `rustleaks.connection-string.password.`. Every rule
selects capture 1. Quotes and enclosing braces are excluded from the secret.
A doubled ODBC closing brace counts as one unit and retains both source
bytes, so the braced secret can contain up to 256 source bytes. Percent
escapes, including malformed or placeholder-shaped percent sequences,
remain raw text. The rules do not percent-decode passwords or assess client
validity.

Semicolon forms require a nonempty `Server`, `Host`, `Data Source`, or `DSN`
before `Password` or `Pwd` on the same line. Field names accept ASCII case
variants. The host body is bounded to 128 bytes before optional trailing
horizontal whitespace. Horizontal whitespace around separators has no
separate length cap. An optional intermediate segment permits at most 200
bytes before its terminating semicolon. Quotes and braces in host or
intermediate fields are excluded. Password-first order and space-delimited
libpq properties are outside this scope.

JDBC SQL Server context is accepted only for unquoted and braced passwords.
The JDBC query rule also accepts MySQL `loadbalance` and `replication`
prefixes. Its authority is bounded to 256 bytes and its optional path to 200
bytes. Up to 16 preceding options can have keys of 1 through 64 bytes and
optional values of at most 200 bytes. Bare options and `&amp;` separators are
permitted. The password key is case-sensitive even when the dialect and
preceding option names vary in ASCII case. Oracle and SQLite JDBC dialects
and libpq syntax have no rule in this pack.

The database URI rule accepts `postgres`, `postgresql`, `mysql`, and
`mariadb`, including ASCII case variants. It permits an empty username or up
to 128 username bytes, and requires 1 through 256 raw password bytes. The
first colon separates username and password; subsequent colons belong to the
password. Slash, at-sign, ASCII whitespace, quotes and backtick cannot occur
in either field; username additionally excludes colon. ASCII controls other
than whitespace remain literal bytes. Host labels permit 1 through 253
bytes and optional ports permit 1 through 5 digits. Bracketed hexadecimal
address bodies, comma-separated host lists and optional path/query tails
are unbounded repetitions. This is source pattern coverage, not address,
port, client or URI validity. Other schemes, HTTPS credential URLs and
arbitrary-byte values are outside this rule's declared domain.

Detection uses the generated Kingfisher byte-regex ASCII whitespace dialect:
bytes 09 through 0d and 20, including vertical tab. Rejection predicates use
the generated runtime's Go-compatible whitespace: bytes 09, 0a, 0c, 0d and
20, excluding vertical tab. A synthetic URI ending directly in vertical tab
can therefore remain eligible where one ending in ordinary space is rejected.
This is an explicit generated-detector dialect, not full Betterleaks Go
detection equivalence.

This is a content detector. An allowed punctuation boundary can
expose a JDBC substring inside a larger malformed prefix. Quoted password
escaping by doubled single or double quotes, quoted auxiliary fields,
client duplicate-property precedence, and strings assembled across literals
are not interpreted.

## Suppression and findings

There is no entropy or character-complexity floor. The quoted and braced
rules retain all 27 source `ignore_if_contains` markers as case-insensitive
secret substring stopwords. The unquoted and JDBC query rules retain the
same markers plus 16 environment, configuration, and function markers.
Quoted code-looking literals such as `"process.env.DB_PASSWORD"` remain
eligible. The exact lists are visible in the TOML and provenance JSON.

The database URI rule preserves 13 source-global and 18 URI-local secret
regex exclusions, the two source-global case-insensitive substring markers,
and two full-match exclusions for synthetic tuples on selected example hosts
and ignored example-host lists. Their exact finite OR predicates are in the
TOML and provenance. Every independent predicate is scoped before native
regex-array alternation, preserving its own flags and internal precedence.
For example, loading this pack in isolation retains `%B`, `%D` and `%S`, while
`%b`, `%d` and `%s` match the source's case-sensitive formatting-placeholder
rejection. Native composition and CLI `--native-pack` also apply the pinned
default global allowlist. Its legacy regex flag scope additionally suppresses
these uppercase variants, so isolated acceptance is not composed-policy
coverage. `%Z` and `%B0` remain eligible under both policies. These are raw
detector examples, not claims that a client accepts the URI as written.
Repeated letters and listed placeholders can be suppressed;
weak numeric and ordinary default passwords have no entropy floor. Source
confidence-only examples, low-confidence hosts such as `localhost`, and
paths under tests or documentation do not become unconditional exclusions.
The generated Kingfisher Git-path override requires an HTTPS URI capture;
it cannot match any of this rule's four schemes.

A real password containing a listed marker can be suppressed. Unlisted
markers and percent-encoded forms can remain reportable. The pack has no
switch to disable only these exclusions. Callers constructing changed TOML
create a different policy identity. Composition inherits unchanged global
allowlists, path policy, inline allow markers, decoding, and resource
controls.

Raw findings retain exact half-open secret and match ranges. Consumed
separators and enclosing quotes or braces belong to the full match rather
than the secret. Existing match trimming removes leading or trailing LF
bytes and retains CR. Existing location semantics and decoded-range
availability remain unchanged. These ranges must not be normalized into
another tool's full-match geometry.

The existing generic-suppression rule can replace an overlapping generic
alert with the connection rule's attribution. Independent specific-provider
alerts remain visible alongside connection alerts for the same password.
Count exact occurrences separately from rule attribution and duplicates.

Non-overlapping matching can miss an adjacent connection when the first
match consumes the semicolon needed to start the second. For example,
`Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;` has two password occurrences but the
native unquoted rule reports the first. This is a known coverage gap, not a
one-password truth claim. Separating the connections with another accepted
boundary supports distinct findings, including repeated values. No full
scanner equivalence with Kingfisher is asserted. The URI rule also preserves
greedy path consumption: a semicolon followed by another URI can belong
entirely to the first URI path, retaining only its first password. Whitespace,
quotes or a closing parenthesis separate these URI occurrences.

## Source and maintenance

The semicolon and JDBC rules adapt five first-party Apache-2.0 rules in
Kingfisher commit `01e7b817376fbf2272be8f162bd32309bf97ee1f`. The source path
is `crates/kingfisher-rules/data/kingfisher-rules.yml`;
its SHA-256 is
`12a5b53962fdcb8572a22d9b320531d6b7cec604f9c54cdca5239edcd833d192`.
The adjacent provenance records original patterns, all detection
requirements, source order, source-file hashes, the exact translation, and
license identity. `LICENSE.kingfisher` retains the exact source license.
The adjacent [NOTICE](NOTICE) preserves the relevant MongoDB attribution.

The database URI rule adapts the MIT `generic-credential-uri` rule from
Betterleaks commit `8f376ff9c31ed5309ac448fe601c5dd21b376155`, at
`config/betterleaks.toml`. The source SHA-256 is
`7c305ade42d5dbad4650b97cca0299f9c16d152ec555ae47bd6f321f049f82e5`.
Its source password bound is 256 bytes. The adjacent `LICENSE.betterleaks`
and `NOTICE` retain its license and attribution. Provenance preserves the
original global and local filters, generated overlay, exact source identity,
and explicit disposition of confidence, specificity and source-path policy.
No full-source-rule or Kingfisher scanner equivalence is asserted.

Rustleaks removes reviewed extended-mode formatting, expands ASCII case
alternatives explicitly, and intersects negated source byte classes with
ASCII positive ranges. The capture-free JDBC option repetition is unrolled
into sixteen greedy optional groups, preserving the 0 through 16 bound
without raising the existing nested-repeat product limit. The five original
rules retain empty native keywords because their source has none; the URI
rule keeps its four relevant scheme keywords. Original greedy/lazy choices,
capture selection, delimiter consumption, stopword target, and substring
matching are retained within the documented ASCII translation.

`cargo xtask generate native-pack-identity` checks the fixed reviewed
inventory and provenance before regenerating the packaged hash. Its check
mode rejects changed patterns, missing predicates, added rule fields,
altered identities, and license drift. The generator does not download or
execute upstream code. Updating this pack requires source review, new
independent expectations, and a versioned policy decision.

URI host-list, address-body and path repetitions have no intrinsic length
cap. Callers must bound complete source input and combine collected-span,
finding-payload, work and finding-record budgets with cooperative cancellation.
A controlled-budget failure is explicitly incomplete. `max_target_bytes`
retains its existing target-skip semantics; it is not an incomplete-status
source limit. Individual regex searches are indivisible. The tests exercise
long tails, many hosts, dense matches and negative inputs; they do not prove
a wall-clock or process-memory ceiling.

`tests/connection_rules.rs` covers all six forms, quoted/braced controls,
exact geometry, bounds, ASCII/Unicode distinctions, stopwords, same-line
occurrences, the adjacent-connection gap, allowlists, generic and specific
overlap, composition identity, decoding, and finite scan controls. These
synthetic controls establish a bounded regression contract, not field
accuracy or complete connection-string coverage.

- [Pinned rule definitions](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/kingfisher-rules.yml)
- [Pinned source scope and syntax references](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/kingfisher-rules.md)
- [Pinned source regression tests](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/tests/connection_string_password.rs)

- [Pinned Betterleaks URI source](https://github.com/betterleaks/betterleaks/blob/8f376ff9c31ed5309ac448fe601c5dd21b376155/config/betterleaks.toml#L5521)
- [Pinned generated URI override](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/imported-rules-capabilities.yml#L31)
