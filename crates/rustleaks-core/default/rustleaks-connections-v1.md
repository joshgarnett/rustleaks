# Rustleaks connection rules v1

The `rustleaks-connections-v1` pack adds 14 namespaced rules for passwords in
connection strings and credential URLs: 10 password rules, 3 Git credential
URL rules and 1 hidden helper rule. The pack is opt-in and runs locally. It
adds no parser, dependency, expression interpreter, validator or client
connection. It does not check whether a credential is active, and it does not
change the packaged default rules.

## Selection

- CLI: `--native-pack rustleaks-connections-v1`.
- Library: `NativePolicy::builder().with_pack("rustleaks-connections-v1", CONNECTION_RULES_V1)?.build()?`,
  with `CONNECTION_RULES_V1` from `rustleaks_core::native`.
- The pack can be combined with `rustleaks-extra-v1` and
  `rustleaks-providers-v1` in any order. The exact bytes and the order of the
  packs are part of the policy identity. Existing engine constructors do not
  turn it on.
- The pack uses native byte entropy and `buffer-v1` association tables. The
  normal configuration loader (`ConfigLoader`, `--config`, inline
  configuration or joined TOML files) rejects these tables.

See [Native rule packs](../../../docs/user/native-rule-packs.md) for users and
[Rule pack authoring](../../../docs/dev/rule-pack-authoring.md) for
contributors.

## Rules

Rule IDs in the tables leave out the `rustleaks.` prefix. Unless a table
says otherwise, the secret is capture 1. Entropy is Shannon entropy of the
secret. "Above N" means that values at or below N are rejected. "Byte
Shannon entropy" is the native `byte-shannon-f64-v1` table, which counts
bytes.

### Connection string passwords (6 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `connection-string.password.double-quoted` | Semicolon form with a host property | Double-quoted password, 4 to 128 bytes | None; 27 stopwords |
| `connection-string.password.single-quoted` | Semicolon form with a host property | Single-quoted password, 4 to 128 bytes | None; 27 stopwords |
| `connection-string.password.odbc-braced` | Semicolon form with a host property, or a JDBC SQL Server prefix | Braced password, 4 to 128 units | None; 27 stopwords |
| `connection-string.password.unquoted` | Semicolon form with a host property, or a JDBC SQL Server prefix | Unquoted password, 4 to 128 bytes | None; 43 stopwords |
| `connection-string.password.jdbc-query` | PostgreSQL, MariaDB or MySQL JDBC URL | Lowercase `password=` query value, 4 to 128 bytes | None; 43 stopwords |
| `connection-string.password.database-uri` | `postgres`, `postgresql`, `mysql` or `mariadb` URI | User information password, 1 to 256 bytes | None; 31 regex exclusions, 2 stopwords, 2 full-match exclusions |

Semicolon forms:

- A nonempty `Server`, `Host`, `Data Source` or `DSN` must come before
  `Password` or `Pwd` on the same line. Field names accept ASCII case
  variants.
- The host key starts at the start of the input, after one consumed
  semicolon, ASCII whitespace (tab, line feed, vertical tab, form feed,
  carriage return or space), quote, `=` or `(`, or at an ASCII word
  boundary. Other punctuation, other control bytes and non-ASCII bytes
  before the key are not consumed, and the match starts at the key. A
  letter, digit or underscore before the key blocks the match, so
  `ProxyServer=` is not a host key, but `Proxy-Server=` is.
- The host value is at most 128 bytes, before optional trailing spaces or
  tabs. Spaces and tabs around separators have no separate length limit.
- One optional segment between the host and the password is at most 200
  bytes before its closing semicolon.
- Quotes and braces are not allowed in the host or in the middle segment.
- Quotes and braces around the password are not part of the secret. A
  doubled ODBC closing brace counts as one unit and keeps both source bytes,
  so a braced secret can hold up to 256 source bytes.
- Password-first order is not matched.

JDBC forms:

- The SQL Server JDBC prefix is accepted only for unquoted and braced
  passwords.
- The `jdbc-query` rule also accepts the MySQL `loadbalance` and
  `replication` prefixes. The authority is at most 256 bytes and the
  optional path at most 200 bytes.
- Up to 16 options can come before it, with keys of 1 to 64 bytes and
  optional values of at most 200 bytes. Bare options and `&amp;` separators
  are accepted.
- The `password` key is case-sensitive, even when the dialect and the
  option names before it use other ASCII cases.
- Oracle and SQLite JDBC URLs have no rule in this pack.

Database URIs:

- Scheme names accept ASCII case variants.
- The user name is empty or up to 128 bytes. The password is 1 to 256 raw
  bytes. The first colon separates them; later colons belong to the
  password.
- Neither field can contain a slash, at sign, ASCII whitespace, quote or
  backtick. The user name also cannot contain a colon. Other ASCII control
  bytes stay literal.
- Host labels are 1 to 253 bytes and ports are 1 to 5 digits. Bracketed
  hexadecimal address bodies, comma-separated host lists and the optional
  path and query have no length limit.
- Other schemes, HTTPS credential URLs and values outside ASCII are not
  matched.
- Detection uses the generated Kingfisher byte regex whitespace: bytes 09 to
  0d and 20, including vertical tab. Rejection rules use Go whitespace: bytes
  09, 0a, 0c, 0d and 20, without vertical tab. So a synthetic URI that ends
  directly in a vertical tab can be reported where one that ends in a space
  is rejected.

Percent escapes stay raw text in all six rules, including malformed or
placeholder-shaped escapes. The rules do not percent-decode passwords or
check that a client would accept them.

### Libpq keyword passwords (2 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `connection-string.password.libpq-quoted` | [PostgreSQL keyword and value syntax](https://www.postgresql.org/docs/18/libpq-connect.html#LIBPQ-CONNSTRING) with a single-quoted password | Password inside the quotes, 1 to 128 units | None; 27 placeholder stopwords |
| `connection-string.password.libpq-unquoted` | Same syntax with an unquoted password | Password, 1 to 128 units | None; 27 placeholder stopwords |

- These rules were written for Rustleaks. They are not imported from another
  scanner.
- Lowercase `host` or `hostaddr` must come before lowercase `password` on the
  same line. The host value has 1 to 128 ASCII letters, digits or `._:/-`.
- Up to 7 `user`, `dbname`, `port`, `sslmode`, `application_name` or
  `connect_timeout` assignments can appear between them, with the same value
  alphabet and limit. Spaces and tabs separate assignments and can surround
  `=`.
- A password unit is one printable ASCII byte, or a backslash followed by one
  printable ASCII byte. A raw capture can therefore hold up to 256 bytes.
- The quotes are not part of the capture. Unquoted values cannot contain bare
  spaces or quotes. Bare backslashes are not allowed in either form. Escaped
  spaces, quotes and backslashes keep their source spelling, as do percent
  sequences.
- A value must end at a space, tab or line end. Incomplete quotes, trailing
  escapes and values that are too long do not give a shortened capture.
- The `host` key starts at an ASCII word boundary. A letter, digit or
  underscore before it prevents a match; punctuation and non-ASCII bytes do
  not. The byte before it is never consumed. Matching consumes the space or
  tab after the password, but a next connection after one space or tab still
  has its host boundary.
- Not matched: password-first order, quoted or escaped host and middle
  values, unknown middle properties, multiline connections and Unicode
  password bytes. The rules do not parse all of libpq.

### MongoDB and service URIs (3 rules, 1 hidden)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `mongodb-password-comma` | Lowercase single-host `mongodb://` or `mongodb+srv://` URI that ends with a comma and a space or tab | Password, 3 to 88 bytes (capture 2); user name 3 to 50 bytes | `buffer-v1` `same-candidate` relation to the helper |
| `mongodb-password-comma-tuple` | Hidden helper (`skipReport = true`) for the whole URI | None reported | Byte Shannon entropy above 4.0; the source global secret regexes, 2 stopwords, the source path prefilter, and the example and interpolation exclusions |
| `service-uri-password` | `redis`, `rediss`, `amqp`, `amqps`, `ldap`, `ldaps`, `smtp`, `smtps`, `ftp`, `ftps` or `ssh` URI | Password, 1 to 256 bytes; user name empty or up to 128 bytes | Source exclusions and the medium-confidence domain |

- Both reporting rules accept only the ASCII URI unreserved alphabet in user
  names and passwords.
- MongoDB comma: paths, options, percent escapes and multiple hosts are not
  matched. The helper keeps the source's whole-URI entropy floor and its
  example and interpolation exclusions.
- The `same-candidate` relation needs the same detection input and the same
  start and end of the whole match. Each raw or decoded input is separate,
  so a match in one input cannot satisfy the helper in another. The helper
  attaches to its parent and never gives its own finding. An explicit rule
  selection must name both the parent and the helper.
- Service URI: the rule keeps the source DNS host, port, path and suffix
  grammar. HTTP and HTTPS, database and MongoDB schemes, percent escapes,
  reserved characters in user information, IPv6 and multiple hosts are not
  matched.
- Service URI: the source rejection rules stay as local allowlists. The 4
  source confidence-reduction categories become local exclusions too:
  example values, synthetic tuples, test or documentation paths, and
  low-confidence hosts. No global confidence mode is added. An ordinary weak
  password can still be reported. This is narrower than the confidence
  domain of `database-uri`.

### Git credential URLs (3 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `bitbucket-git-credentials` | HTTPS URL with user name and password for `bitbucket.org` | The full URL | Path ends with `.git/config`, `.git-credentials` or `_history` |
| `codecatalyst-git-credentials` | HTTPS URL with user name and password for CodeCatalyst | The full URL | Same path condition |
| `codecommit-git-credentials` | HTTPS URL with user name and password for CodeCommit | The full URL | Same path condition |

- The path suffixes are case-sensitive and come from the source helper. A
  file name with another prefix before the suffix also matches.
- User name and password are nonempty, unescaped ASCII, at most 64 and 128
  bytes. The repository path is bounded. This grammar ensures the source
  parser checks hold without adding a URL parser.
- Percent-encoded, Unicode, malformed-percent and longer credentials are not
  matched. The rules have no keyword gate, because the source has none.
- The match ends at end of input or one ASCII whitespace byte. Bitbucket
  accepts a vertical tab there; CodeCatalyst and CodeCommit do not, to keep
  the source URL parser rule. The engine trims a consumed LF, so two commands
  on separate lines give two exact findings.
- A direct core scan of `repo/.git/config` can match. The default global path
  allowlist matches a path ending in `.git`, not files under it. A directory
  source can still skip the `.git` folder. Source traversal rules and core
  fragment detection are separate.

## Shared boundaries

ASCII scope:

- In the 6 connection string rules, every consumed match byte is ASCII,
  including allowed ASCII control bytes. The surrounding fragment can contain
  any bytes. No text normalization runs.
- Unicode and invalid-byte connection values are out of scope. A comparison
  with another tool must use raw ASCII input and account for each tool's own
  source, finding and match rules.

Exclusions:

- No rule in the pack has an entropy or character complexity floor, except
  the MongoDB comma helper.
- The quoted and braced rules keep all 27 source `ignore_if_contains` markers
  as case-insensitive secret stopwords. The unquoted and `jdbc-query` rules
  keep the same 27 markers and 16 more for environment, configuration and
  function markers. A quoted literal that looks like code, such as
  `"process.env.DB_PASSWORD"`, can still be reported.
- The `database-uri` rule keeps 13 source global and 18 URI-local secret
  regex exclusions and the 2 source global case-insensitive substring
  markers. It also keeps 2 full-match exclusions: one for synthetic tuples on
  example hosts and one for lists of ignored example hosts. Each predicate is scoped before the native
  regex array joins them, so each keeps its own flags and precedence.
- Example: the pack alone keeps `%B`, `%D` and `%S` but rejects `%b`, `%d`
  and `%s` as source formatting placeholders. The CLI and native composition
  also apply the default global allowlist, whose regex flags also reject the
  uppercase forms. `%Z` and `%B0` stay reportable in both cases. These are
  raw detector examples, not claims that a client accepts the URI.
- Repeated letters and listed placeholders can be suppressed. Weak numeric
  and common default passwords are not. Source examples that only lower
  confidence, low-confidence hosts such as `localhost`, and test or
  documentation paths are not hard exclusions in `database-uri`.
- The generated Kingfisher Git path override needs an HTTPS URI capture, so
  it cannot match any of the 4 `database-uri` schemes.
- A real password that contains a listed marker can be suppressed. Unlisted
  markers and percent-encoded forms can still be reported. There is no switch
  to turn off only these exclusions. Changed TOML creates a different policy
  identity.
- Composition keeps the global allowlists, path rules, inline allow
  comments, decoding and resource controls.

Findings and overlap:

- Raw findings keep exact half-open secret and match ranges. Consumed
  separators, quotes and braces are part of the match, not the secret. Match
  trimming removes leading or trailing LF bytes and keeps CR. Do not convert
  these ranges to another tool's match geometry.
- Optional decoding can give separate decoded findings. This does not change
  the literal percent handling of libpq passwords or the raw capture.
- The existing generic suppression can replace an overlapping generic finding
  with the connection rule. Findings from specific provider rules stay next to
  connection findings for the same password. Count exact occurrences apart
  from rule attribution and duplicates.
- Adjacent connections that share one semicolon each give a finding. In
  `Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;` the first match consumes the shared
  semicolon, and the second match starts at the next host key.
- Known gap: the URI rule keeps the greedy path match of the source. A
  semicolon followed by another URI can belong to the first URI's path, so
  only the first password is reported. Whitespace, quotes or a closing
  parenthesis separate the URIs.
- The rules find content only. An allowed punctuation boundary can expose a
  JDBC substring inside a larger malformed prefix. The rules do not interpret
  doubled quotes as escapes, quoted extra fields, duplicate properties or
  strings built from several literals.

Resources:

- URI host lists, address bodies and paths have no length limit of their
  own. Callers must bound the source input, and combine collected-span,
  finding-payload, work and finding-record budgets with cancellation.
- A scan stopped by a budget is reported as incomplete. `max_target_bytes`
  skips a target; it does not mark a result incomplete.
- One regex search cannot be interrupted. The tests cover long tails, many
  hosts, dense matches and negative inputs. They do not prove a time or
  memory limit.

## Provenance and license

| Rules | Source | License |
| --- | --- | --- |
| `connection-string.password.` `double-quoted`, `single-quoted`, `odbc-braced`, `unquoted` and `jdbc-query` | 5 first-party rules in Kingfisher commit `01e7b817376f`, file `crates/kingfisher-rules/data/kingfisher-rules.yml`, SHA-256 `12a5b53962fdcb8572a22d9b320531d6b7cec604f9c54cdca5239edcd833d192` | Apache-2.0, `LICENSE.kingfisher` |
| `connection-string.password.database-uri` | `generic-credential-uri` in Betterleaks commit `8f376ff9c31e`, file `config/betterleaks.toml`, SHA-256 `7c305ade42d5dbad4650b97cca0299f9c16d152ec555ae47bd6f321f049f82e5`, password bound 256 bytes | MIT, `LICENSE.betterleaks` |
| `mongodb-password-comma`, `mongodb-password-comma-tuple`, `service-uri-password` | The same pinned Betterleaks configuration | MIT, `LICENSE.betterleaks` |
| 3 Git credential URL rules | Apache-2.0 Veles (OSV-SCALIBR) sources, as recorded per rule | Apache-2.0, `LICENSE.veles` |
| `connection-string.password.libpq-quoted` and `connection-string.password.libpq-unquoted` | Written for Rustleaks from the PostgreSQL documentation | MIT, repository license |

The table shows 12-character commits. The provenance JSON records the full
commit IDs.

The adjacent [NOTICE](NOTICE) keeps the attribution for each source,
including the MongoDB attribution for Kingfisher.
`rustleaks-connections-v1.provenance.json` records, for each imported rule,
the original patterns, all detection requirements, source order, source file
hashes, path predicates, parser limits, the exact translation and the license
identity. For `database-uri` it also keeps the original global and local
filters, the generated overlay and how confidence, specificity and source path
rules were handled. No downloaded scanner code runs or ships in the pack.

Changes made:

- IDs are namespaced and descriptions are factual.
- Extended-mode formatting is removed after review. ASCII case alternatives
  are written out. Negated source byte classes are limited to ASCII ranges.
- The JDBC option repetition, which has no capture, is unrolled into 16
  greedy optional groups. This keeps the 0 to 16 bound without raising the
  nested repeat limit.
- The 5 Kingfisher rules keep empty keyword lists, because the source has
  none. `database-uri` keeps its 4 scheme keywords.
- Greedy and lazy choices, capture selection, delimiter consumption, the
  stopword target and substring matching are kept within the ASCII
  translation.
- The 4 semicolon forms add an ASCII word boundary as a last way for the host
  key to start. A semicolon consumed by one match then does not hide the next
  connection.

The pack does not claim to match the full source rules or the Kingfisher
scanner. It finds local candidates and does not show that a remote service
accepts a URL or credential.

References:

- [Pinned Kingfisher rule definitions](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/kingfisher-rules.yml)
- [Pinned Kingfisher scope and syntax references](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/kingfisher-rules.md)
- [Pinned Kingfisher regression tests](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/tests/connection_string_password.rs)
- [Pinned Betterleaks URI source](https://github.com/betterleaks/betterleaks/blob/8f376ff9c31ed5309ac448fe601c5dd21b376155/config/betterleaks.toml#L5521)
- [Pinned generated URI override](https://github.com/mongodb/kingfisher/blob/01e7b817376fbf2272be8f162bd32309bf97ee1f/crates/kingfisher-rules/data/imported-rules-capabilities.yml#L31)
- [PostgreSQL connection strings](https://www.postgresql.org/docs/18/libpq-connect.html#LIBPQ-CONNSTRING)

## Maintenance

- Tests: `crates/rustleaks-core/tests/connection_rules.rs` covers the 6
  connection string forms, the libpq forms, and quoted and braced controls.
  It also checks exact geometry, bounds, ASCII and Unicode differences,
  stopwords and findings on the same line. Other cases cover adjacent
  connections, host-key boundaries, allowlists, generic and provider
  overlap, composition identity, decoding and scan budgets. The generated
  rules are also covered by the coverage tests listed in
  [Rule pack authoring](../../../docs/dev/rule-pack-authoring.md). These
  synthetic tests are a regression contract, not a measure of accuracy on
  real data.
- The rules after the line
  `# Maintained additional coverage; generated by xtask generate native-pack-identity.`
  come from `crates/xtask/src/tooling/native_coverage/connections.toml`, with
  their records in `native_coverage/reviewed.json`. Do not edit them in the
  pack file.
- Regenerate and check the pack, its provenance and its identity:

  ```sh
  cargo xtask generate native-pack-identity
  cargo xtask generate native-pack-identity --check
  ```

  The generator checks the reviewed inventory and provenance before it writes
  the hash. Check mode rejects changed patterns, missing predicates, added
  rule fields, changed identities and license changes. It never downloads or
  runs upstream code.
- A change needs a source review, new independent expected results and a
  versioned policy decision. A change in what the pack detects needs a new
  pack ID.
