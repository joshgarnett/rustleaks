# Rustleaks connection rules v1

This optional pack adds fourteen namespaced rules to the unchanged
pinned defaults: ten password rules, three complete Git credential URLs
and one hidden tuple-predicate helper. Select it with the existing native composition API:

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

The complete pack includes native entropy and association tables. Load it
through `NativePolicy` or CLI `--native-pack rustleaks-connections-v1`.
The ordinary configuration loader rejects these native table values.

## Scope

For the six original password rules, every consumed match byte is ASCII, including permitted ASCII controls.
The surrounding fragment can contain arbitrary bytes; no text normalization
occurs. Unicode or invalid-byte connection values are outside these rules'
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

The six password-rule IDs start with `rustleaks.connection-string.password.`. The six password rules
select capture 1. Quotes and enclosing braces are excluded from the secret.
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
libpq properties are outside these six original rules.

JDBC SQL Server context is accepted only for unquoted and braced passwords.
The JDBC query rule also accepts MySQL `loadbalance` and `replication`
prefixes. Its authority is bounded to 256 bytes and its optional path to 200
bytes. Up to 16 preceding options can have keys of 1 through 64 bytes and
optional values of at most 200 bytes. Bare options and `&amp;` separators are
permitted. The password key is case-sensitive even when the dialect and
preceding option names vary in ASCII case. Oracle and SQLite JDBC dialects
have no rule in this pack. The separate libpq rules below cover a bounded
keyword syntax subset.

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

## Git credential URL subsets

Three additional rules extract complete HTTPS credential URLs for Bitbucket,
CodeCatalyst and CodeCommit. The IDs are `rustleaks.bitbucket-git-credentials`,
`rustleaks.codecatalyst-git-credentials` and
`rustleaks.codecommit-git-credentials`. Their path conditions preserve the
case-sensitive `.git/config`, `.git-credentials` and `_history` suffixes from
the original Veles helper, including filenames with a non-boundary prefix.

Each requires nonempty unescaped ASCII username and password fields, bounded
to 64 and 128 bytes, and a bounded repository path. The selected grammar
guarantees the reviewed source parser predicates without adding a URL parser.
Percent-encoded, Unicode, malformed-percent and longer credentials are outside
this selection. No source keyword gate is invented. The full URL remains the
secret, including username, password, host and repository path.

The consumed terminal is end of input or one ASCII whitespace byte. Bitbucket
admits vertical tab at this boundary; CodeCatalyst and CodeCommit exclude it
to preserve their source URL-parser predicate. A consumed LF is trimmed by
the engine's existing match-location behavior. Two newline-separated commands
retain two exact secret occurrences.

Direct core scans of `repo/.git/config` remain eligible: the unchanged global
path expression matches a path ending in `.git`, not descendants. A directory
source can separately prune the `.git` ancestor. Do not conflate source
traversal policy with direct-core fragment detection.

These adaptations use the pinned Apache-2.0 Veles sources already attributed
in `LICENSE.veles` and `NOTICE`. Exact source URLs, hashes, path predicates,
parser restrictions and selected bounds are recorded in the adjacent
provenance. They provide local credential candidates and do not establish
that a remote service accepts a URL or credential.

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

## MongoDB and service URI subsets

Two reporting rules and one hidden tuple helper extend the connection pack.
`rustleaks.mongodb-password-comma` selects the password from a lowercase,
single-host MongoDB URI ending with comma and horizontal whitespace. It
requires 3 through 50 username bytes and 3 through 88 password bytes from the
ASCII URI-unreserved alphabet. Paths, options, percent escapes and multiple
hosts are outside this companion's scope. The hidden
`rustleaks.mongodb-password-comma-tuple` preserves the original whole-URI
entropy floor and example/interpolation predicates.

Native `buffer-v1` `same-candidate` association requires equal detection-input
identity and both complete-match endpoints. Each raw or decoded input is
separate. Shared reported locations or equal local endpoints in different
inputs cannot supply another tuple's predicate. The helper attaches to its
own parent and does not produce an independent credential finding. Explicit
rule selection must include both parent and helper IDs.

`rustleaks.service-uri-password` covers `redis`, `rediss`, `amqp`, `amqps`,
`ldap`, `ldaps`, `smtp`, `smtps`, `ftp`, `ftps` and `ssh` schemes. It permits an
empty username or up to 128 username bytes, and 1 through 256 password bytes
from the ASCII URI-unreserved alphabet. It preserves the source DNS host,
port, path and suffix grammar. HTTP(S), database/MongoDB schemes, percent
escapes, reserved userinfo, IPv6 and multiple hosts are outside its scope.

The service URI rule selects the original medium-confidence domain. Source
rejection predicates remain local, and the four original confidence-reduction
categories become explicit local exclusions: example values, synthetic tuples,
test/documentation paths and low-confidence hosts. Those categories were not
all source rejections, and this selection adds no global confidence mode.
An ordinary weak password can remain eligible in deployment context.
This differs intentionally from the existing database URI rule's broader
confidence domain. The native inherited global policy remains unchanged.

All three additions derive from the pinned MIT Betterleaks configuration.
Their exact source fields, attribution and selections are in the adjacent
provenance. They make no client-validity or remote-credential claim.

## Libpq keyword passwords

The original Rustleaks rules `rustleaks.connection-string.password.libpq-quoted`
and `rustleaks.connection-string.password.libpq-unquoted` use the
[PostgreSQL keyword/value syntax](https://www.postgresql.org/docs/18/libpq-connect.html#LIBPQ-CONNSTRING).
They are independent implementations, not imported scanner patterns.

Both require lowercase `host` or `hostaddr` before lowercase `password` on the
same line. Host values contain 1 through 128 ASCII letters, digits, or
`._:/-`. Up to seven intervening `user`, `dbname`, `port`, `sslmode`,
`application_name`, or `connect_timeout` assignments accept the same value
alphabet and bound. Spaces and tabs separate assignments and may surround
`=`. Password-first ordering, quoted or escaped host/intermediate values,
unknown intermediate properties, and multiline connections are outside this
subset. These rules detect credential syntax without validating a connection.

Passwords contain 1 through 128 units. A unit is one printable ASCII byte or
backslash followed by one printable ASCII byte, so a raw capture can contain
up to 256 bytes. Single quotes enclose the quoted form and are excluded from
the capture; unquoted values exclude bare spaces and both quote characters.
Bare backslashes are excluded in both forms. Escaped spaces, quotes, and
backslashes retain their exact source spelling, as do percent sequences.
A completed value must end at a space, tab, or line end. Incomplete quotes,
trailing escapes, and overlong uninterrupted values do not produce truncated
password captures. Unicode password bytes are outside this subset.

The rules select secret group 1 and have no entropy floor. Inherited global
allowlists and conventional password placeholder stopwords remain active.
Optional general decoding can emit separate decoded findings; this does not
change libpq's literal percent-containing password semantics or the raw
capture. The rules do not claim complete libpq parsing or catalog precision.

The host key starts at a zero-width ASCII word boundary. A preceding letter,
digit, or underscore excludes it; punctuation and non-ASCII surrounding bytes
can precede a match. The preceding byte is never consumed. Matching consumes
the password's terminating horizontal separator, but adjacent connections
separated by one space or tab retain their next host boundary. This is a
credential-syntax detector, not validation of the surrounding document.
