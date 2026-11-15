# Rustleaks provider rules v1

This optional pack adds 300 namespaced rules to the unchanged pinned defaults.
It includes standalone and contextual provider formats, bounded companions,
Slack session formats, eighteen Apache Veles formats and a native ADC
refresh-token selection. Select it through the native API:

```rust
use rustleaks_core::native::{NativePolicy, PROVIDER_RULES_V1};

let engine = NativePolicy::builder()
    .with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)?
    .build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The provider pack includes native structured entropy, association and predicate tables. Load the
complete pack through `NativePolicy`, or select it in the CLI with
`--native-pack rustleaks-providers-v1`. Passing it through ordinary
`ConfigLoader`, `--config`, inline configuration or TOML concatenation rejects
the structured value before scanning. 211 rules require native byte entropy;
the other 89 use scalar entropy or have no entropy predicate.
Native CLI composition uses the embedded default and rejects conflicting custom
configuration selection. It does not activate complete-target scanning.

The pack can be composed with `rustleaks-extra-v1`. Exact bytes and pack order
participate in policy identity. Existing constructors do not activate it.
Rules detect candidates locally; they do not contact providers or establish
whether a credential is active. This is bounded format coverage, not a claim
of complete provider or scanner coverage.

## Provider formats

| Rule ID | ASCII secret form | Native entropy requirement |
| --- | --- | --- |
| `rustleaks.groq-api-key` | `gsk_` and 52 alphanumeric characters | Greater than 3.5 |
| `rustleaks.cerebras-api-key` | `csk-` and 48 alphanumeric characters | Greater than 3.0 |
| `rustleaks.replicate-api-token` | `r8_` and 37 alphanumeric characters | Greater than 3.0 |
| `rustleaks.nvidia-api-key` | `nvapi-` and 60 through 70 alphanumeric, underscore or hyphen characters | Greater than 3.5 |

These four rules accept ASCII upper/lower prefix variants and exclude
non-ASCII case-fold variants. Replicate documents a 40-character total and
`r8_` prefix. The other references establish credential role and prefix
without guaranteeing the exact detector lengths.

Each requires a leading ASCII word boundary and a following delimiter:
ordinary or backslash-escaped single quote, double quote or backtick; ASCII
whitespace (`09` through `0d` and `20`); semicolon; literal `\n`, `\N`, `\r`
or `\R`; or end of input.

## Additional provider formats

| Rule ID | ASCII secret form | Native entropy requirement |
| --- | --- | --- |
| `rustleaks.cloudsmith-api-key` | `csa_`, 30 lowercase hexadecimal bytes, then 6 alphanumeric bytes | None |
| `rustleaks.minimax-api-key` | `sk-api-` and 119 alphanumeric, underscore or hyphen bytes | Greater than 3.5 |
| `rustleaks.posthog-personal-api-key` | `phx_` and 41 through 49 alphanumeric, underscore or hyphen bytes | Greater than 3.0 |
| `rustleaks.figma-personal-access-token` | `figd_` and 38 through 42 alphanumeric, underscore or hyphen bytes | Greater than 3.5 |
| `rustleaks.togetherai-api-key` | `tgp_v1_` and 43 alphanumeric, underscore or hyphen bytes | Greater than 3.0 |
| `rustleaks.gcp-gemini-api` | `AQ.Ab8RN6` and 44 alphanumeric, underscore or hyphen bytes | Greater than 4.0 |

Cloudsmith and Google/Gemini prefixes are case-sensitive. MiniMax, PostHog,
Figma and Together accept explicit ASCII prefix/body case variants. All six
require a leading ASCII word boundary and the same terminal delimiters as the
first four provider rules. The two case-sensitive rules accept only lowercase
literal `\n` and `\r`, while the other four also accept `\N` and `\R`.
Cloudsmith's final six bytes can be uppercase; its preceding hexadecimal part
must remain lowercase. These bounds describe pinned detector scopes, not an
exhaustive specification of provider-issued keys.

Only PostHog personal `phx_` tokens are included. Public-write project `phc_`
tokens are outside that rule; inherited generic rules remain unchanged.
The `AQ.Ab8RN6` form is a Google/Gemini API-key candidate. Its syntax does not
prove Gemini authorization, key activity or key restrictions. Existing Google
`AIza` detections retain their default rule and behavior.

Bare candidates can add detected occurrences. A candidate already captured
by an assigned generic key is an attribution change under the existing overlap
policy. Regression controls distinguish those cases by exact secret ranges.
No credential is submitted to a provider for validation or analysis.

## Incremental companions

| Rule ID | Added scope | Native entropy requirement |
| --- | --- | --- |
| `rustleaks.anthropic-api-key-escaped` | `sk-ant-api03-`, 93 alphanumeric/underscore/hyphen bytes, `AA`, then a backslash-escaped quote or backtick | None |
| `rustleaks.anthropic-admin-api-key-escaped` | The same body and delimiter with `sk-ant-admin01-` | None |
| `rustleaks.digitalocean-refresh-token-escaped` | `dor_v1_`, 64 hexadecimal bytes, then a backslash-escaped quote or backtick | None |
| `rustleaks.openai-api-key-20-segment` | `sk-`, role `proj`, `svcacct` or `admin`, hyphen, left segment, `T3BlbkFJ`, right segment; at least one segment has 20 bytes | Greater than 3.0 |
| `rustleaks.flyio-flyv1` | `FlyV1`, exactly one ASCII whitespace byte, then at least 100 body bytes | Greater than 4.0 |

The first three retain the leading ASCII word boundary. Anthropic prefixes,
bodies and `AA` endings remain case-sensitive. DigitalOcean accepts ASCII
case variants of the prefix and hexadecimal body. Their ordinary delimiters
remain covered only by the pinned defaults. Three separate `-vt` companions cover the vertical-tab suffix for these families.

The OpenAI companion admits exactly five left/right length pairs:
`(20,20)`, `(20,58)`, `(20,74)`, `(58,20)` and `(74,20)`, for each of the three
roles. Segment bytes are alphanumeric, underscore or hyphen; the prefix,
roles and marker are case-sensitive. Both leading and terminal ASCII word
boundaries remain required. The four existing pairs from `{58,74}` and the
legacy unscoped `sk-` form retain their default ordinary-ending coverage. The
separate `-legacy-delimiter` companion covers their escaped-quote and VT endings.

The Fly.io companion is case-sensitive. Its body alphabet is alphanumeric,
equals, underscore, hyphen, comma, slash and plus. The existing `fo1_`,
`fm1a_`, `fm1r_` and `fm2_` formats remain covered only by the default rule.

The OpenAI and Fly.io companions accept ordinary or backslash-escaped quotes
and backticks, ASCII whitespace, semicolon, literal lowercase `\n` or `\r`,
or end of input as their terminal delimiter. Fly.io also permits LF as its
single separator, making its captured secret potentially multiline.

The two Sonar companions select capture 2 as the secret because capture 1 is
the login/token label. All other rules select capture 1. Consumed terminal delimiters
belong to the match, not the secret. Existing trimming removes trailing LF
from matches and retains CR. Raw-byte and decoded-range contracts are
unchanged. `Fragment::new` starts locations at line zero, and the frozen
location helper includes the preceding LF in its byte-column origin.
Unsupported forms remain coverage gaps; they do not show a value is harmless.

## Providers with explicit byte entropy

Six rules use `entropy = { algorithm = "byte-shannon-f64-v1", reject = "lt",
threshold = 3.5 }`. They reject byte entropy strictly below 3.5, accepting an
exact threshold. This is separate from the unchanged scalar entropy predicates
of the earlier rules.

| Rule ID suffix (under `rustleaks.`) | Case-sensitive ASCII form | Boundaries |
| --- | --- | --- |
| `dockerhub-personal-access-token` | `dckr_pat_` and 27 alphanumeric, underscore or hyphen bytes | Leading word boundary and terminal delimiter |
| `dockerhub-organization-access-token` | `dckr_oat_` and 32 alphanumeric, underscore or hyphen bytes | Leading word boundary and terminal delimiter |
| `neon-api-key` | `napi_` and 64 alphanumeric bytes | Leading word boundary and terminal delimiter |
| `render-api-key` | `rnd_` and 28 alphanumeric bytes | Leading word boundary and terminal delimiter |
| `deno-account-token` | `ddp_` and 36 alphanumeric bytes | Leading word boundary and terminal delimiter |
| `apify-api-token` | `apify_api_` and 34 through 38 alphanumeric bytes | Leading and trailing word boundaries; no consumed delimiter |

For the first five, terminal delimiters are ordinary or backslash-escaped
single quote, double quote or backtick, ASCII whitespace (`09` through `0d`
and `20`), semicolon, literal lowercase `\n` or `\r`, or EOF. Word boundaries
are ASCII. Uppercase prefixes and non-ASCII case-fold variants are excluded.
Deno user `ddp_` tokens remain distinct from the Apache organization `ddo_`
rule. Personal and organization Docker Hub tokens are separately attributed.
The exact lengths are pinned source detector scopes, not an exhaustive issuer
specification or proof of token activity.

The named algorithm builds a 256-byte histogram, divides each nonzero count
by the total byte length in binary64, and accumulates in ascending byte order.
The exact original strict comparison is retained. These six ASCII rule
languages avoid an arbitrary-byte source string-equivalence claim. This
algorithm contract does not claim arbitrary-platform `log2` bit equivalence;
the candidate reports the native predicate's entropy with the existing f32
report conversion. Its metadata survives compiled rule selection.

All six complete generated source predicates contain the same 13 global
secret regexes, two stopwords and strict entropy rejection. There is no omitted
component requirement, tokenizer or precedence overlay. Global secret
exclusions are retained as explicit rule-local predicates and inherited through
the native base. Each of the 13 rule-local regexes has its own noncapturing
scope, preserving source flags and alternatives when the native allowlist joins
them. Predicate whitespace is preserved literally; it is not widened to the
detector delimiter whitespace class. Source-path differences remain documented
below. Whole-pack ordinary loading fails, preventing silent
loss of the native predicate. Exact comparator/histogram controls, source
arithmetic witnesses, native metadata inspection, rule selection, low-entropy
admission accounting and actual provider-format cases are separate tests.

The unchanged inherited base joins its global regexes with legacy flag scope.
For these six captured prefix languages, only the first global true/false/null
expression is reachable. The other twelve require an entire repeated-letter,
star or dot value, or a leading `$`, `{`, `%`, `@` or slash. None intersects a
captured token, so inherited cross-alternative flags cannot change this domain.
Independent predicate probes cover case-sensitive path prefixes and vertical
tab without altering the provider patterns or legacy global policy.

## Contextual provider formats

These nine rules retain assignment context from the pinned MIT source. Context
is part of the match; only the token is the secret. Labels allow zero through
20 ASCII word, space, tab, dot or hyphen bytes before up to three whitespace or
quote bytes, a source assignment separator, and up to five whitespace, quote,
backtick or equals bytes before the token. The separators are `=`, `>`, `:=`,
`::=`, `:::=`, `||`, `:`, `=>`, `?=` and comma. Context has no leading word
boundary, so a matching substring of a longer label remains eligible.

| Rule ID suffix (under `rustleaks.`) | Required context and ASCII secret form | Entropy |
| --- | --- | --- |
| `checkout-secret-key` | `checkout`; `sk_` and hexadecimal groups 8-4-4-4-12 | None |
| `crates-io-api-key` | `crates` with optional `.io`, `_io`, `-io` or `io`; `cio` and 32 alphanumeric bytes | None |
| `cursor-api-key` | `cursor`; `key_` and 64 hexadecimal bytes | Greater than 3.5 |
| `databento-api-key` | `databento`; `db-` and 29 alphanumeric bytes | None |
| `elevenlabs-api-key` | `elevenlabs`; `sk_` and 48 hexadecimal bytes | Greater than 3.5 |
| `figma-personal-access-header-token` | `x-figma-token`, `xfigmatoken` or `x_figma_token`; hexadecimal groups 4-8-4-4-4-12 | None |
| `ollama-api-key` | `ollama`; 32 hexadecimal bytes, dot, then 24 alphanumeric, underscore or hyphen bytes | Greater than 3.5 |
| `polymarket-private-key` | `poly`, up to 20 non-LF runes, `private`, up to 20 non-LF runes, `key`; `0x` and 64 hexadecimal bytes | Greater than 3.5 |
| `stability-ai-api-key` | `stability`; `sk-` and 48 alphanumeric bytes | Greater than 3.5 |

ASCII case variants are explicit. Polymarket's `0x` prefix and escaped `n`/`r`
terminal alternatives stay case-sensitive; its bounded dot context retains
existing rune semantics, including non-ASCII runes. Other contextual rules
accept uppercase escaped `N`/`R`. All nine require the ordinary or escaped
quote, ASCII whitespace, semicolon, escaped newline or EOF terminal delimiter
used above. Non-ASCII case folding and non-ASCII whitespace do not substitute
for their explicit ASCII literal, body and whitespace classes.

These contexts are detection evidence, not issuer or permission validation.
Polymarket's private-key context does not classify bare hexadecimal hashes or
public addresses as private keys. Figma header and private-key assignments can
already produce generic findings; those are attribution changes. Context-only
assignments for other rows can add occurrences. Bare opaque bodies remain
outside these contextual rules.
The Figma header rule has no entropy floor: a value rejected by the generic
rule's entropy threshold can add an occurrence, while a higher-entropy value
under the same label can change only attribution.

## Slack session formats

`rustleaks.slack-session-token` captures case-sensitive `xoxc-`, three digit
groups of 9 through 15 bytes separated by hyphens, another hyphen and 64
lowercase hexadecimal bytes. It requires a trailing ASCII word boundary and
no leading boundary. The complete token is capture 1. The source describes
session use together with a cookie, but does not require a cookie for detection.
No independent full-session access claim follows from a token match.

`rustleaks.slack-session-cookie` captures case-sensitive `xoxd-`, at least 100
ASCII word, slash, backslash, plus or hyphen bytes, then zero through two equals
padding bytes. Its following delimiter is EOF or a character outside ASCII
word, slash, plus, equals and hyphen. A consumed delimiter belongs to the
match. Backslash belongs to both the body and delimiter languages; greedy
matching owns it in the body when possible, while padding can make it the
delimiter. There is no leading boundary. Non-ASCII terminal characters and
invalid source bytes retain the existing rune and exact-range behavior.

Both rules require native entropy greater than 3.5. The cookie has no regex
maximum. Regression controls specify 8 KiB and 256 KiB synthetic bodies,
input admission, finding payload, finding count and work limits. Input and
payload limits must be chosen by the caller; work units are engine checkpoints,
not a time limit or a bound on every internal regex operation. The full secret
is retained when admitted, so a long candidate can have a large sensitive
payload. A finite payload budget rejects it with an incomplete result before
owned finding fields are copied. No resource benchmark or field accuracy
claim is made by these synthetic regression expectations.

## Finite Apache Veles formats

| Rule ID | Case-sensitive source form | Total match bytes |
| --- | --- | --- |
| `rustleaks.circleci-project-token` | `CCIPRJ_`, 22 alphanumeric bytes, underscore, 40 lowercase hexadecimal bytes | 70 |
| `rustleaks.deno-organization-token` | `ddo_` and 36 alphanumeric bytes | 40 |
| `rustleaks.xai-api-key-80` | `xai-` and 80 alphanumeric bytes | 84 |
| `rustleaks.postman-collection-token` | `PMAT-` and 26 alphanumeric bytes | 31 |

These rules preserve the finite source expressions and their unconditional
whole-match extraction. They have no keywords, entropy threshold or leading or
trailing delimiter. A longer surrounding alphanumeric run can contain an
admitted finite prefix match. Low-entropy matches remain eligible in the
isolated pack; composed global allowlists still apply. The finite source
`MaxLen` equals the complete match length. This is a local expression contract,
not equivalence with the source scanner's streaming implementation.

The xAI selection includes only the Apache 80-byte body expression. The MIT
70-through-120-body rule overlaps it and uses entropy and delimiters; that
rule and Kingfisher's suppression overlay are not selected. The optional pack
does not implement their union, and this rule excludes `xai-token-` management
keys. CircleCI personal tokens, Deno user tokens and Postman account API tokens
are distinct roles; these four rules do not broaden into those formats.

## Additional source predicates and provider formats

The pack also contains 101 MIT provider selections and one native ADC
refresh-token selection. The adjacent provenance identifies every rule,
original pattern, capture, keyword, full rejection predicate and adaptation.
These additions retain all 23 source path exclusions in independently scoped
rule allowlists, including root and nested `bun.lock` and `bun.lockb`.
They retain 13 source secret-regex exclusions, two case-insensitive substring
exclusions, local exclusions and the declared byte-entropy comparator.
The native loader preserves these predicates when selecting individual rules.

Source roles are selected explicitly. DevCycle server keys are included;
DevCycle client/mobile and ConfigCat SDK keys are excluded. Midtrans includes
only `Mid-server-`. The two Endor components retain separate rule identities
and thresholds; two attributions for one occurrence are not two credentials.
Ionic, Miro and Resend retain their source keywords even when the token cannot
supply that keyword itself. Original provider assignment context remains
required for contextual rules, including Voyage, DeepSeek, Kimi and Z.ai.

The Clerk and Scalr companions select only their documented delimiter
increments. WorkOS candidates with ordinary alphanumeric unpadded bodies can
already have Stripe attribution. A new provider finding therefore does not
automatically represent a new complete secret occurrence. Independent tests
compare exact secret bytes and byte ranges against the previous composition.

Capella's four proximity gaps use explicit ASCII bytes and preserve the source
32/12/12/32 byte bounds. Fal's wildcard context admits one ASCII byte other
than LF. Asaas and Buildkite service consumed delimiters use explicit ASCII
classes. Scaleway's free context admits up to 20 ASCII non-LF bytes. Non-ASCII
and malformed bytes in those positions remain outside these bounded selections.
The DataStax, Fullstory, Workato and Temporal bodies, and Notify's service name
and whitespace, retain their unbounded source repetitions. Callers must select input, work and finding-payload limits;
synthetic large-payload tests are not performance guarantees.

Supabase, Thunderstore and Val Town retain their two-digit predicates. Unkey
requires a digit, uppercase and lowercase somewhere in the complete captured
secret; its fixed lowercase prefix satisfies that part of the predicate.
Temporal's mandatory marker already supplies its required digit count. These
conditions are anchored secret-target rejection complements, with no added
configuration field or expression interpreter.

The ADC detector captures only a `1//` refresh-token value from the canonical
`application_default_credentials.json` basename and requires the Google
client-ID keyword. Its 20-byte body minimum, 512-byte complete-token maximum
and bounded whitespace are conservative selections. It does not capture the
whole JSON document or implement JSON parsing. Whole service-account document
capture and the lossy generated Bitwarden pair expression are excluded.

The inherited default global filter remains additional policy. In particular,
its existing alternation flag scope can suppress mixed-case letter-only Asaas
values that the independently scoped source filters would retain. Rule-local
copies cannot reverse that global exclusion. These additions do not claim
source-policy equivalence or introduce a switch to disable inherited filtering.

## Credential format and boundary supplements

Twenty-seven rules add selected credential formats and delimiters. Seventeen
are derived from the pinned MIT Betterleaks configuration and ten from the
pinned Apache-2.0 Veles detectors. Each origin records its immutable source
URL, digest, original expression, generated overlay and native selection.

The source predicates remain local to their rules. Betterleaks selections
retain source keywords, all source secret and path exclusions, generated
supersession filters and the exact byte-entropy comparison. GoCardless rejects
entropy strictly below 3.5. Stripe excludes `sk_test_` and WorkOS prefixes.
The Betterleaks Heroku supplement accepts only trailing-hyphen AA bodies;
the Veles Heroku supplement retains the original final word boundary.
Veles selections do not acquire Betterleaks source filters. Inherited native
global filtering remains additional policy for every rule.

The Authress selection retains lowercase credential prefixes, `acc` and
account identifiers. Datadog API and application keys retain distinct 32-byte
and 40-byte hexadecimal bodies. Etsy captures the complete keystring and
shared-secret pair. Grafana accepts the selected standard-Base64 body alphabet.
HCP preserves a secret-only assignment without a client ID. Packagist ORT and
OUT tokens do not require a repository URL. The optional validation components
are neither required rules nor independent secret findings.

Most supplements consume selected punctuation, escaped quotes or vertical tab
after a complete bounded token. HCP, Packagist and Slack refresh instead retain
their source fixed-width prefix extraction above the nominal length. HCP's
original Go whitespace excludes vertical tab; Betterleaks byte whitespace
includes it. All selected token alphabets are explicit ASCII.

The complete versioned GitLab PAT and the 147-byte Slack refresh body can
coexist with shorter findings from retained rules. For Monday before an
escaped quote, the retained JWT finding includes one extra backslash; the
Monday finding extracts the exact credential. These are extraction changes
and additional alerts for already detected credentials. Ordinary Monday JWT
and Grafana forms can also gain provider attribution without a new occurrence.
Independent tests compare against an explicit 440-rule prior composition and
retain existing specific findings. The format and special-case suites retain their historical 476-rule composition.
The complete composition now contains 537 rules, including 32 hidden helpers.
The association suite retains its historical 534-rule composition.

GitLab incoming-mail token length and HCP assignment whitespace retain their
unbounded source repetitions. Callers can set target-size, work and finding
payload limits. Synthetic resource tests do not establish performance or
issuer acceptance. Broader xAI body/prefix variants and presumed multi-digit
Slack segments are outside these selections.

## Connection-key and structured-context supplements

Five reporting rules and one hidden predicate rule add selected credential
contexts. Azure App Configuration and Service Bus extract exact 44-byte keys
before an unquoted comma and horizontal whitespace. Existing ordinary-ending
key rules remain unchanged. The Service Bus parent requires its own complete
tuple through native `buffer-v1` `same-candidate` association. Its hidden helper
preserves source whole-tuple entropy and exclusions; the parent additionally
requires key entropy greater than 3.5. Both detection-input identity and full
match endpoints must agree, including inside decoded inputs. Selecting the
parent explicitly requires selecting its helper ID as well.

The unsigned JWT companion requires `Authorization: Bearer`, one of three
literal `alg:none` header encodings, a base64url-shaped payload, an empty
signature and a backslash-escaped quote or backtick. It excludes the escaped
delimiter from the secret. This is a lexical authentication candidate rule,
not a JSON/JOSE parser or signature validator. Bare unsigned data and signed
JWTs are outside the companion's scope. The retained `jwt` rule can report a
signed escaped token including its trailing backslash.

The Kubernetes companion extracts one data item with 201 through 1000 ASCII
bytes between kind and data/item, in either order. It preserves the source
YAML path, keyword, template and empty-value predicates. It rejects matches
crossing `---` or `...` document-marker lines, conservatively including indented
marker-like lines, and rejects overlaps containing a short-context default
match. Ordinary mapping keys beginning `---suffix` or `...suffix` remain
eligible. This is bounded lexical coverage, not YAML parsing.

The Cloudflare companion requires one of seven credential labels and a
40-byte token before a comma. Public `CF_ACCOUNT_ID` is excluded. Its selected
forward ASCII context does not reproduce the original Veles pair algorithm.
It retains the source terminal word boundary and adds no Betterleaks-only
path or secret predicates. The inherited native global policy still applies.

The Betterleaks selections retain local source filters and paths. Service Bus
filters apply to the complete tuple through its hidden helper. Source URLs,
digests, original detection fields and the selected domains are recorded in
the adjacent provenance. Validators and remote service calls are not included.
Raw findings preserve exact secret and match byte ranges. Existing location
semantics and unavailable decoded ranges remain unchanged.

## Source and modifications

223 patterns are adapted directly from the MIT-licensed Betterleaks source at
`8f376ff9c31ed5309ac448fe601c5dd21b376155`. The original source archived by
Kingfisher was read as data; generated Kingfisher patterns are not the copied
source. The adjacent provenance JSON records the immutable source URL and
SHA-256, original patterns, filters, keywords, and each added rule's selection
and transformations. `LICENSE.betterleaks` and `NOTICE` retain attribution.

Seventeen patterns are adapted directly from Apache-2.0 Veles/OSV-SCALIBR source
at `e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845`, archived as data by the same
pinned Kingfisher revision. Exact detector files, source pattern lines and
SHA-256 values are recorded per rule; the source license and retained Google
copyrights are in `LICENSE.veles` and the adjacent `NOTICE`. The archived source
records no upstream NOTICE. No downloaded scanner implementation is executed
or included in the pack.

Rustleaks namespaces IDs, uses factual descriptions, expands applicable
ASCII-insensitive flags to explicit classes, and spells byte whitespace
explicitly. Companion rules select reviewed format and delimiter increments.
The earlier scalar source entropy rejection predicates use `<=`; those native
rules retain their stated thresholds and existing f64 calculation.
The byte predicates reject below the threshold for 150 rules and at or below
it for 61 rules, including source scanner floors and the existing native floor.
All use their stated byte calculation. Numeric equivalence beyond the stated
algorithm contracts is not asserted.
Thresholds can omit valid low-entropy credentials and do not establish issuer
validity. No expression interpreter, tokenizer, wordlist, dependency or
validator is added.

Composition inherits Rustleaks' unchanged global allowlists. For the MIT
imports, its 13 secret-regex exclusions and two stopwords correspond to the
source's global secret exclusions for the reviewed ASCII domain. The fifteen
Apache formats inherit those exclusions as additional native policy. Source-path exclusions
differ: Rustleaks retains its office/PDF/binary and `.git` exclusions, while
the pinned Betterleaks source additionally excludes Bun lockfiles. This pack
does not claim source-policy equivalence. Native allow markers, decoding,
required-rule behavior and resource controls still apply.

Provider attribution can replace an overlapping generic finding under the
existing native generic-suppression rule. An assigned token already detected
by the generic rule is an attribution improvement, not a newly found secret.
Independent specific-provider findings remain present. Count exact occurrences
and duplicate attribution separately when evaluating the pack.

Each rule enumerates matches independently. A long OpenAI token can contain a
shorter token-shaped suffix, including an old shape inside a new one or the
reverse. Both specific candidates remain visible at their distinct spans.
This differs from enumerating one combined source expression, which can select
only the outer match. Such nested candidates are additional alerts, not proof
of additional credentials or recovered secrets. The pack does not promise
disjoint output across provider rules.

## References and maintenance

- [Pinned Veles source](https://github.com/google/osv-scalibr/tree/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/veles/secrets)
- [Pinned Betterleaks source](https://github.com/betterleaks/betterleaks/blob/8f376ff9c31ed5309ac448fe601c5dd21b376155/config/betterleaks.toml)
- [Groq security onboarding](https://console.groq.com/docs/production-readiness/security-onboarding)
- [Cerebras support source](https://github.com/Cerebras/vscode-cerebras-chat/blob/main/SUPPORT.md)
- [Replicate API tokens](https://replicate.com/docs/topics/security/api-tokens)
- [NVIDIA registry authentication](https://docs.nvidia.com/nvcf/dev/third-party-registries)

`tests/provider_rules.rs`, `tests/additional_coverage.rs` and
`tests/format_coverage.rs` and `tests/special_coverage.rs` specify synthetic positives, near misses, entropy
boundaries, exact locations, ASCII/Unicode distinctions, invalid bytes,
allowlists, old/new format unions, generic overlap, identity and finite scan
controls. Fixtures are independently authored and never submitted to a
provider. Those controls establish a bounded regression contract, not field
accuracy or an exhaustive provider specification.

Refresh requires reviewing source changes, recording exact provenance and
license bytes, and evaluating changed predicates and overlaps. A changed
published pack needs a new versioned identifier. No runtime downloads occur.
The maintained `crates/xtask/src/tooling/native_coverage/` source contracts
generate the additional TOML blocks and provenance. Prior rule bytes and
provenance are hash-bound before append generation. Regenerate assets and
content identities with
`bazelisk run //crates/xtask:xtask -- generate native-pack-identity`; the normal
build contract checks both pack digests and provider provenance consistency.


## Shared-prefix delimiter companions

Twenty-four additional rules ending in `-delimiter` add raw occurrences before
literal backslash-plus-quote (single, double or backtick) and vertical tab. Their
prefixes, token alphabets, bounds, alternatives and exact secret captures follow
the pinned Betterleaks source. Ordinary delimiters and EOF remain covered by the
unchanged default rules, without matching these companions. No decoding pass is
needed to recover the literal escaped endings.

The companions cover Amazon Bedrock long-lived keys, DigitalOcean access tokens,
GCP keys, both Hugging Face token forms, Infracost, Intra42, MaxMind, Notion,
Octopus, both PlanetScale forms, Prefect, Pulumi, ReadMe, RubyGems, Scalingo, all
three Settlemint forms, Shippo, Square, and both Vault forms. Their independently
scoped secret exclusions include the GCP examples and the Vault letter-only
legacy-token exclusion. The legacy `s.` Vault form still needs the source's
`vault` keyword context; the `hvs.` prefix supplies its own keyword.

Each companion uses native `byte-shannon-f64-v1` entropy with `reject = "le"`
and its source threshold. Source secret predicates are copied into each rule,
with every regex scoped independently; native global and path policy also
applies. Case differences caused by the unchanged global regex joining are
unreachable for these fixed-prefix token languages. Detection whitespace and
predicate whitespace retain their separate source meanings. These fields require
`NativePolicy` or the CLI native-pack route; the legacy config loader rejects
structured entropy. Existing scalar entropy behavior is unchanged.

The contextual and residual delimiter companions below cover their separately
reviewed gaps. This pack does not claim complete source-catalog semantics.


## Contextual and residual delimiter companions

Twenty contextual families each have a `-delimiter` rule and a `-context-vt`
rule: Beamer, Defined Networking, Terraform passwords, legacy Heroku UUIDs,
HubSpot, Lob private keys, Mailchimp, Mailgun private/signing keys, Okta, Plaid,
Sidekiq, Snyk, Sonar, Squarespace, Telegram, Typeform and three Yandex formats.
The public Lob publishable and Mailgun validation-key rows remain excluded.

`-delimiter` accepts escaped single/double/backtick quotes or VT after a token
whose assignment whitespace contains no VT. `-context-vt` requires VT within
the source's at-most-three pre-separator or at-most-five post-separator bytes
and retains all source terminal endings. The first-VT alternatives preserve
the total bounds. They do not admit VT into the separate 0..20 label-tail class.
The two classes are disjoint for a given assignment. Optional native ASCII
preambles remain for match geometry, including both Okta preambles. Removing
those preambles alone would not recover a secret occurrence.

Required provider labels and body alternatives are retained. Terraform retains
the `.tf`/`.hcl` path constraint and captures the quotes with the password.
Eight- and nine-character quoted bodies can add occurrences; longer bodies
may already be reported by the generic rule and instead gain attribution or
different capture geometry. Sonar retains capture 2. Okta accepts exactly the
source's `okta`, `Okta` and `OKTA` label forms, and only lowercase escaped `n`/`r`.
Telegram's `A` after the numeric prefix remains case-sensitive. Mailchimp's
source dot wildcard is retained as a rune wildcard. Yandex access tokens retain
the unbounded first segment and require caller input/payload/work limits.

Three `-vt` companions cover the prior Anthropic API/admin and DigitalOcean
refresh token VT gaps. `openai-api-key-legacy-delimiter` covers the old 58/74
role-segment pairs and old bare 20/20 form before escaped quotes or VT. Existing
20-segment role companions continue to own their new forms; ordinary endings
remain covered by the defaults. None of the existing sixty rules is changed.

Every addition carries the complete source secret predicates, with each regex
scoped independently. Go-style predicate whitespace is distinct from detector
VT whitespace. Five additions use byte entropy `reject = "le"`: the two
Terraform rules at 2, the two Okta rules at 4 and the OpenAI residual at 3.
The other 39 additions have no source entropy predicate. Native global/path
policy still applies. Overlapping distinct assignments retain native enumeration;
this is not a claim of cross-engine enumeration or source-policy equivalence.


## Buffer-local associated credentials

Twenty-six reporting rules use thirty hidden helper rules. Each mandatory
source edge is retained through native `required = { contract = "buffer-v1",
edges = [...] }`. Select the complete pack through `NativePolicy`; the legacy
configuration loader rejects these tables. A selected parent without every
required helper fails closed. Existing standalone default rules, including the
AWS access-token rule, keep their visibility.

The associated families are Aikido, Artifactory API and reference tokens,
Auth0, AWS session credentials, Azure storage, BrowserStack, Canva, eBay,
Exoscale, Langfuse, Miro, MongoDB Atlas service accounts, Mux, OVH, PayPal,
PlanetScale, Polymarket, Ramp, Razorpay, Salesforce, Supabase, Tableau,
Upstash, Wiz and Zoho. Source files, source predicates and every edge are
recorded in the adjacent provenance JSON.

The selected source contract is pinned Kingfisher `scan_blob_with_context`
without `DetectionOptions`. A helper must belong to the same raw buffer or
individual decoded buffer as the parent. A window `NL` accepts helper full-match
start lines from the parent's full-match start minus `N-1` through its exclusive
full-match end plus `N-1`, inclusive. The lower bound is one. Window `0` removes
the line limit while retaining buffer identity. Consumed trailing LF affects
that exclusive endpoint even though public match text trims LF. Captures come
from the full logical buffer. Raw, decoded, sibling and nested buffers cannot
supply one another's helpers. Native depth-two isolation does not claim that
the source no-options API recursively decodes.

Each helper evaluates its own keywords, paths, allowlists and byte entropy in
its buffer. Each applicable source global and local secret predicate is retained, and all
23 source path exclusions remain on every node. AWS session tokens and
Polymarket passphrases explicitly reject byte entropy at or below zero,
preserving the source scanner floor that is independent of filter ASTs. Native inherited policy is an additional
layer. Every association node uses
`regex = { dialect = "bytes-v1", pattern = "..." }` with its exact generated
source pattern. This explicit native form matches raw bytes with source ASCII
case folding and original inline flags, repetition bounds, captures and
leftmost-first greedy or lazy selection. String regexes retain their existing
Go-compatible meaning. The AWS session capture directly retains the original
16 through 2048 repetition without Go adaptation.

The nine bounded bridges in seven nodes retain arbitrary source bytes: Azure
key/name, the two Canva ID bridges, the two PlanetScale ID bridges, and three
Polymarket rules. Limits count bytes. Complete UTF-8 scalars and invalid bytes
are accepted within each original byte cap, while one byte over is rejected.
Source dotall and ordinary-dot LF/CR distinctions remain intact. JFrog,
Salesforce and Tableau delimiter guards retain their actual one-byte ownership,
including ranges starting or ending inside a UTF-8 scalar. Adjacent helpers may
consume separate bytes of that scalar. Matching does not normalize malformed
input, expand ranges, or substitute rune counts for source byte limits.

Every qualifying helper occurrence appears once per parent in core
`required_findings`, ordered by required edge and occurrence. Helpers have
`skipReport = true` and never become standalone reports. Parent finding
serialization and ordinary JSON reports omit these records. Explicit support
serialization and the core accessor expose support bytes. Primary-only
redaction preserves supports; `without_detected_secrets` removes their detected
secrets too. Helpers and projected copies consume work, span, finding and payload
budgets. Exhaustion is incomplete and cannot publish a partially satisfied
parent. Support records are not additional source-coverage successes.

## Private Packagist credential roles

`rustleaks.packagist-api-secret` reports `packagist_acs_` followed by 64 through
96 lowercase hexadecimal characters. `rustleaks.packagist-api-key` reports
`packagist_ack_` followed by 28 through 32 lowercase hexadecimal characters.
Both prefixes are case-sensitive. Nonconsuming ASCII word boundaries reject
identifier substrings and overlong token-prefix slices. This is an explicit
precision restriction relative to the source's unguarded expressions.

Each token is an independent finding whose match and secret own only the token.
No counterpart, assignment, path, gap, uniqueness, padding, entropy or checksum
condition is added. Two token roles yield two findings; two retained pairs yield
four. Ordinary configuration values, punctuation, multiline context and long
gaps remain eligible. Existing native allowlists and budgets still apply.

The issuer identifies ACS as an HMAC secret and documents ACK-only GET
authentication. This supports independent credential detection without claiming
ACS-only bearer authentication. ACS follows the pinned visible Kingfisher
selection, whose optional validation dependency does not gate detection. Making
ACK visible is a deliberate selection broader than Kingfisher's hidden helper
and Veles's conditional partial detection. Veles tuple weighting and source
output parity are not implemented or claimed. These are offline format
candidates, with no live-validity or measured false-positive claim. See the
[issuer's authentication documentation](https://packagist.com/docs/api/api-authentication).


## Mapbox secret tokens

`rustleaks.mapbox-secret-token` accepts the complete pinned `sk.` grammar:
23 through 308 base64url payload bytes beginning `eyJ1Ijoi`, a dot, and a
22-byte signature whose final byte is `A`, `Q`, `g` or `w`. The prefix is
case-sensitive. Source ASCII word and right-delimiter guards remain intact.
The full selected secret has 49 through 334 bytes and must have byte entropy
at least 4.0.

The native `base64url-segment-go-regex-v1` predicate decodes only the payload
into at most 231 bytes and applies the exact source Go-compatible expression.
It requires the original ordered `u` and `a` fields, nonempty user and
alphanumeric authorization text, and the source ASCII whitespace positions.
Unicode user text is allowed; arbitrary JSON layouts, escaped user text and
additional fields are outside this expression. Nonzero unused Base64 trailing
bits remain allowed. Malformed encoding or UTF-8 rejects that candidate and
continues; this intentionally differs from source filter-error propagation.
Cancellation and resource exhaustion remain typed incomplete outcomes.

## Vercel AI Gateway keys

`rustleaks.vercel-ai-gateway-key` selects `vck_` followed by exactly 56 ASCII
letters, digits, underscores or hyphens. Prefix case is ASCII-insensitive.
The exact source delimiter alternatives include ordinary or escaped quotes
and backticks, ASCII whitespace, semicolon, literal backslash `n`/`r` in
either case, and end of input. The whole secret capture is always 60 bytes.

The rule separately requires byte entropy at least 3.5 and the native
`vercel-cl100k-ratio-v1` predicate. Pinned cl100k ordinary encoding must produce
at least 25 tokens; 24 tokens gives ratio exactly 2.5 and is rejected. The
predicate covers the complete source capture alphabet and case domain. It
does not use a dictionary, approximate ratio or restricted witness grammar.
The pinned tokenizer data, algorithm version and source chain are recorded
in provenance. Its immutable packaged asset and licenses are maintained by
the native predicate tooling.

Mapbox and Vercel use explicit `bytes-v1` outer regexes and preserve every
source global secret filter, stopword and path prefilter as distinct local
allowlists. Existing native global suppression remains an additional layer.
Paths are never tested as secret regexes. Consumed LF is trimmed from public
match bytes, while CR is retained; neither changes selected secret bytes.

## Bitwarden CLI client secrets

`rustleaks.bitwarden-cli-client-secret` binds the quoted alphanumeric value of
`user_<UUID>_token_apiKeyClientSecret` directly. Values have 10 through 50
bytes and positive byte entropy. The named property may appear at any field
position or nesting depth and may repeat. Source Go ASCII whitespace before
the colon is unbounded; whitespace after it has a 20-byte cap. No outer
object or fragment length limit is added.

The path follows the original lowercase literal suffix `bitwarden cli/data.json`.
The frozen Go lowercase preimages include dotted capital I and exclude long s.
Backslashes, repeated separators and hyphenated directory names do not match.
No path-component boundary is required before the suffix.

This is direct lexical property binding. It deliberately excludes arbitrary
bridges, reversed tuples and binding a nearby unrelated string when the named
property is null. It does not reproduce Veles weighted tuple selection or the
broader generated Kingfisher path expression. It does not validate complete
JSON. The generic rule's entropy threshold is unchanged. Inherited policy
still suppresses its existing alphabet stopword; `placeholder123` remains a
locally accepted value, without an added general placeholder classifier.
