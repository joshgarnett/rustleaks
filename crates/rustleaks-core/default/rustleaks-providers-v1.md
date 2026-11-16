# Rustleaks provider rules v1

The `rustleaks-providers-v1` pack adds 303 namespaced rules for provider API
keys, tokens and related credentials. 31 of them are hidden helper rules: 30
association helpers and 1 Azure Service Bus tuple helper. The other 272 rules
report findings. The pack is opt-in and runs locally. It does not contact a
provider or check whether a credential is active, and it does not change the
packaged default rules. It covers selected formats. It does not claim complete
coverage of any provider or scanner.

## Selection

- CLI: `--native-pack rustleaks-providers-v1`.
- Library: `NativePolicy::builder().with_pack("rustleaks-providers-v1", PROVIDER_RULES_V1)?.build()?`,
  with `PROVIDER_RULES_V1` from `rustleaks_core::native`.
- The pack can be combined with `rustleaks-extra-v1` and
  `rustleaks-connections-v1` in any order. The exact bytes and the order of
  the packs are part of the policy identity. Existing engine constructors do
  not turn it on.
- The CLI native pack route uses the embedded default rules and rejects a
  conflicting custom configuration. It does not turn on complete-target
  scanning.
- The pack uses native-only tables:
  - 213 rules use `byte-shannon-f64-v1` byte entropy: 151 reject values
    below the threshold (`lt`) and 62 reject values at or below it (`le`).
    18 rules use scalar entropy and 72 have no entropy check.
  - 27 rules use `buffer-v1` required relations.
  - 58 rules use the `bytes-v1` regex dialect.
  - 2 rules use secret predicates.
- The normal configuration loader (`ConfigLoader`, `--config`, inline
  configuration or joined TOML files) rejects these tables before scanning.
- An explicit rule selection must include every hidden helper that a selected
  rule needs. A selected parent without its helpers fails to build.

See [Native rule packs](../../../docs/user/native-rule-packs.md) for users and
[Rule pack authoring](../../../docs/dev/rule-pack-authoring.md) for
contributors, including the meaning of the native tables.

## Rules

Rule IDs in the tables leave out the `rustleaks.` prefix. Unless a table
says otherwise, the secret is capture 1. Consumed delimiters belong to the
match, not the secret.

Entropy is Shannon entropy of the secret. "Above N" means that values at or
below N are rejected. "At least N" means that values below N are rejected.
"Byte Shannon entropy" is the native `byte-shannon-f64-v1` table, which
counts bytes. Plain "Shannon entropy" is the normal Gitleaks check, which
counts characters.

### Provider prefixes (10 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `groq-api-key` | `gsk_` and 52 alphanumeric bytes | Token | Shannon entropy above 3.5 |
| `cerebras-api-key` | `csk-` and 48 alphanumeric bytes | Token | Shannon entropy above 3.0 |
| `replicate-api-token` | `r8_` and 37 alphanumeric bytes | Token | Shannon entropy above 3.0 |
| `nvidia-api-key` | `nvapi-` and 60 to 70 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 3.5 |
| `cloudsmith-api-key` | `csa_`, 30 lowercase hexadecimal bytes, then 6 alphanumeric bytes | Token | None |
| `minimax-api-key` | `sk-api-` and 119 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 3.5 |
| `posthog-personal-api-key` | `phx_` and 41 to 49 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 3.0 |
| `figma-personal-access-token` | `figd_` and 38 to 42 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 3.5 |
| `togetherai-api-key` | `tgp_v1_` and 43 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 3.0 |
| `gcp-gemini-api` | `AQ.Ab8RN6` and 44 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 4.0 |

- All 10 rules need a leading ASCII word boundary and a terminal delimiter.
  The delimiter is an ordinary or backslash-escaped single quote, double
  quote or backtick, ASCII whitespace (bytes 09 to 0d and 20), a semicolon, a
  literal `\n` or `\r`, or end of input.
- Groq, Cerebras, Replicate, NVIDIA, MiniMax, PostHog, Figma and Together
  accept ASCII case variants of the prefix and body, and also accept `\N` and
  `\R`. Cloudsmith and `gcp-gemini-api` prefixes are case-sensitive and
  accept only lowercase `\n` and `\r`. Non-ASCII case-fold variants never
  match.
- The last 6 Cloudsmith bytes can be uppercase; the hexadecimal part must be
  lowercase.
- Replicate documents a 40-byte total with the `r8_` prefix. The other
  references give the credential role and prefix but not the exact lengths.
  The lengths are pinned detector scopes, not issuer rules.
- Only PostHog personal `phx_` tokens match. Public project `phc_` tokens do
  not.
- `AQ.Ab8RN6` is a Google or Gemini API key candidate. The syntax does not
  prove Gemini access, key activity or key restrictions. Google `AIza` keys
  stay with the default rule.

### Escaped and segment companions (5 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `anthropic-api-key-escaped` | `sk-ant-api03-`, 93 alphanumeric, underscore or hyphen bytes and `AA`, before a backslash-escaped quote or backtick | Token | None |
| `anthropic-admin-api-key-escaped` | The same body and delimiter with `sk-ant-admin01-` | Token | None |
| `digitalocean-refresh-token-escaped` | `dor_v1_` and 64 hexadecimal bytes, before a backslash-escaped quote or backtick | Token | None |
| `openai-api-key-20-segment` | `sk-`, role `proj`, `svcacct` or `admin`, hyphen, left segment, `T3BlbkFJ`, right segment, where at least one segment has 20 bytes | Token | Shannon entropy above 3.0 |
| `flyio-flyv1` | `FlyV1`, exactly 1 ASCII whitespace byte, then at least 100 body bytes | Token | Shannon entropy above 4.0 |

- The Anthropic and DigitalOcean rules keep the leading word boundary.
  Anthropic prefixes, bodies and `AA` endings are case-sensitive.
  DigitalOcean accepts ASCII case variants of the prefix and hexadecimal
  body. Ordinary endings stay with the default rules.
- OpenAI accepts exactly 5 left and right segment length pairs for each role:
  (20,20), (20,58), (20,74), (58,20) and (74,20). Segment bytes are
  alphanumeric, underscore or hyphen. The prefix, roles and marker are
  case-sensitive. Leading and trailing ASCII word boundaries are required.
  The (58,74) family and the unscoped `sk-` form stay with the default rule.
- Fly.io is case-sensitive. The body alphabet is alphanumeric, `=`, `_`, `-`,
  `,`, `/` and `+`. The `fo1_`, `fm1a_`, `fm1r_` and `fm2_` formats stay with
  the default rule. The separator can be LF, so the secret can span lines.
- OpenAI and Fly.io end at an ordinary or escaped quote or backtick, ASCII
  whitespace, a semicolon, a literal lowercase `\n` or `\r`, or end of input.

### Contextual provider formats (9 rules)

These rules keep the assignment context of the source. The context is part
of the match; only the token is the secret.

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `checkout-secret-key` | Label `checkout`; `sk_` and hexadecimal groups 8-4-4-4-12 | Token | None |
| `crates-io-api-key` | Label `crates` with optional `.io`, `_io`, `-io` or `io`; `cio` and 32 alphanumeric bytes | Token | None |
| `cursor-api-key` | Label `cursor`; `key_` and 64 hexadecimal bytes | Token | Shannon entropy above 3.5 |
| `databento-api-key` | Label `databento`; `db-` and 29 alphanumeric bytes | Token | None |
| `elevenlabs-api-key` | Label `elevenlabs`; `sk_` and 48 hexadecimal bytes | Token | Shannon entropy above 3.5 |
| `figma-personal-access-header-token` | Label `x-figma-token`, `xfigmatoken` or `x_figma_token`; hexadecimal groups 4-8-4-4-4-12 | Token | None |
| `ollama-api-key` | Label `ollama`; 32 hexadecimal bytes, a dot and 24 alphanumeric, underscore or hyphen bytes | Token | Shannon entropy above 3.5 |
| `polymarket-private-key` | Label `poly`, up to 20 non-LF characters, `private`, up to 20 non-LF characters, `key`; `0x` and 64 hexadecimal bytes | Token | Shannon entropy above 3.5 |
| `stability-ai-api-key` | Label `stability`; `sk-` and 48 alphanumeric bytes | Token | Shannon entropy above 3.5 |

- A label allows 0 to 20 ASCII word, space, tab, dot or hyphen bytes. Then
  come up to 3 whitespace or quote bytes and an assignment separator. Up to
  5 whitespace, quote, backtick or `=` bytes can come before the token.
- The separators are `=`, `>`, `:=`, `::=`, `:::=`, `||`, `:`, `=>`, `?=` and
  a comma.
- The context has no leading word boundary, so a matching part of a longer
  label is accepted.
- ASCII case variants are written out. Polymarket's `0x` prefix and escaped
  `n` and `r` endings are case-sensitive, and its dot context keeps character
  meaning, including non-ASCII characters. The other rules also accept `\N`
  and `\R`.
- All 9 rules use the terminal delimiters of the provider prefix rules.
  Non-ASCII case folding and whitespace do not replace the ASCII classes.
- The context is detection evidence, not issuer or permission validation.
  Polymarket's context does not turn bare hexadecimal hashes or public
  addresses into private keys. Bare tokens without context do not match.
- The Figma header rule has no entropy floor. A value that the generic rule
  rejects for low entropy can add an occurrence. A value with higher entropy
  under the same label only changes attribution.

### Slack session formats (2 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `slack-session-token` | `xoxc-`, 3 digit groups of 9 to 15 bytes joined by hyphens, a hyphen and 64 lowercase hexadecimal bytes | Token | Shannon entropy above 3.5 |
| `slack-session-cookie` | `xoxd-`, at least 100 ASCII word, `/`, `\`, `+` or `-` bytes, then 0 to 2 `=` padding bytes | Cookie value | Shannon entropy above 3.5 |

- Both prefixes are case-sensitive and neither rule has a leading boundary.
- The token needs a trailing ASCII word boundary. The source describes use
  together with a cookie, but detection does not need a cookie. A token match
  does not show full session access.
- The cookie ends at end of input or at a byte outside ASCII word, `/`, `+`,
  `=` and `-`. A consumed delimiter belongs to the match. A backslash belongs
  to both the body and the delimiter; greedy matching keeps it in the body
  when it can, while padding can make it the delimiter. Non-ASCII terminal
  characters and invalid bytes keep the normal character and range
  behavior.
- The cookie body has no length limit. See [Shared boundaries](#shared-boundaries).

### Finite Veles formats (4 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `circleci-project-token` | `CCIPRJ_`, 22 alphanumeric bytes, `_`, 40 lowercase hexadecimal bytes (70 bytes) | Whole match | None |
| `deno-organization-token` | `ddo_` and 36 alphanumeric bytes (40 bytes) | Whole match | None |
| `xai-api-key-80` | `xai-` and 80 alphanumeric bytes (84 bytes) | Whole match | None |
| `postman-collection-token` | `PMAT-` and 26 alphanumeric bytes (31 bytes) | Whole match | None |

- The forms are case-sensitive. The rules have no keywords, entropy check or
  delimiters. A longer alphanumeric run can contain a match.
- The source `MaxLen` equals the full match length. This is a rule on the
  expression only, not a claim of equal behavior with the source scanner's
  streaming code.
- Low-entropy matches are reported when the pack runs alone. Global
  allowlists still apply in a composition.
- `xai-api-key-80` uses only the Apache 80-byte body expression, and
  `xai-token-` management keys do not match it. The MIT form for 70 to 120
  byte bodies is the separate `xai-api-key-delimiter` rule in
  [Format and boundary supplements](#format-and-boundary-supplements-30-rules),
  which does match `xai-token-` keys. Neither rule uses the Kingfisher
  overlay that leaves exact 80-byte bodies to one rule.
- CircleCI personal tokens, Deno user tokens and Postman account API tokens
  are different roles. These rules do not match them.

### Byte entropy provider formats (6 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `dockerhub-personal-access-token` | `dckr_pat_` and 27 alphanumeric, underscore or hyphen bytes | Token | Byte Shannon entropy of at least 3.5 |
| `dockerhub-organization-access-token` | `dckr_oat_` and 32 alphanumeric, underscore or hyphen bytes | Token | Byte Shannon entropy of at least 3.5 |
| `neon-api-key` | `napi_` and 64 alphanumeric bytes | Token | Byte Shannon entropy of at least 3.5 |
| `render-api-key` | `rnd_` and 28 alphanumeric bytes | Token | Byte Shannon entropy of at least 3.5 |
| `deno-account-token` | `ddp_` and 36 alphanumeric bytes | Token | Byte Shannon entropy of at least 3.5 |
| `apify-api-token` | `apify_api_` and 34 to 38 alphanumeric bytes | Token | Byte Shannon entropy of at least 3.5 |

- All forms are case-sensitive. Uppercase prefixes and non-ASCII case-fold
  variants do not match.
- The first 5 rules need a leading ASCII word boundary and a terminal
  delimiter. The delimiter is an ordinary or escaped quote or backtick,
  ASCII whitespace, a semicolon, a literal lowercase `\n` or `\r`, or end of
  input. Apify uses leading and trailing word boundaries and consumes no
  delimiter.
- An entropy exactly at 3.5 is accepted.
- Deno account `ddp_` tokens are separate from the `ddo_` organization rule.
  Docker Hub personal and organization tokens are reported under separate
  rules.
- Each rule carries the source predicates as local allowlists: 13 global
  secret regexes, 2 stopwords and the strict entropy rejection. Nothing is
  left out. Predicate whitespace is kept as written; it is not widened to the
  detector whitespace class.
- The default global allowlist joins its regexes with the legacy flag scope.
  For these 6 prefix forms only the first global expression
  (true, false or null) can be reached. The other 12 need a whole value of
  repeated letters, stars or dots, or a leading `$`, `{`, `%`, `@` or slash.
  None of them can match a captured token here.

### Shared-prefix delimiter companions (24 rules)

These rules add occurrences before a literal backslash and quote (single,
double or backtick) or a vertical tab. Ordinary delimiters and end of input
stay with the default rules. No decoding pass is needed. Prefixes, token
alphabets, bounds, alternatives and captures follow the pinned Betterleaks
source. Each rule uses byte entropy with `reject = "le"`.

| Rule ID | Matches | Entropy or predicate |
| --- | --- | --- |
| `aws-amazon-bedrock-api-key-long-lived-delimiter` | Amazon Bedrock long-lived key | Byte Shannon entropy above 3.0 |
| `digitalocean-access-token-delimiter` | DigitalOcean access token | Byte Shannon entropy above 3.0 |
| `gcp-api-key-delimiter` | GCP API key | Byte Shannon entropy above 4.0 |
| `huggingface-access-token-delimiter` | Hugging Face access token | Byte Shannon entropy above 2.0 |
| `huggingface-organization-api-token-delimiter` | Hugging Face organization token | Byte Shannon entropy above 2.0 |
| `infracost-api-token-delimiter` | Infracost | Byte Shannon entropy above 3.0 |
| `intra42-client-secret-delimiter` | Intra42 | Byte Shannon entropy above 3.0 |
| `maxmind-license-key-delimiter` | MaxMind | Byte Shannon entropy above 4.0 |
| `notion-api-token-delimiter` | Notion | Byte Shannon entropy above 4.0 |
| `octopus-deploy-api-key-delimiter` | Octopus Deploy | Byte Shannon entropy above 3.0 |
| `planetscale-oauth-token-delimiter` | PlanetScale OAuth token | Byte Shannon entropy above 3.0 |
| `planetscale-password-delimiter` | PlanetScale password | Byte Shannon entropy above 3.0 |
| `prefect-api-token-delimiter` | Prefect | Byte Shannon entropy above 2.0 |
| `pulumi-api-token-delimiter` | Pulumi | Byte Shannon entropy above 2.0 |
| `readme-api-token-delimiter` | ReadMe | Byte Shannon entropy above 2.0 |
| `rubygems-api-token-delimiter` | RubyGems | Byte Shannon entropy above 2.0 |
| `scalingo-api-token-delimiter` | Scalingo | Byte Shannon entropy above 2.0 |
| `settlemint-application-access-token-delimiter` | Settlemint application token | Byte Shannon entropy above 3.0 |
| `settlemint-personal-access-token-delimiter` | Settlemint personal token | Byte Shannon entropy above 3.0 |
| `settlemint-service-access-token-delimiter` | Settlemint service token | Byte Shannon entropy above 3.0 |
| `shippo-api-token-delimiter` | Shippo | Byte Shannon entropy above 2.0 |
| `square-access-token-delimiter` | Square | Byte Shannon entropy above 2.0 |
| `vault-batch-token-delimiter` | Vault batch token | Byte Shannon entropy above 4.0 |
| `vault-service-token-delimiter` | Vault service token | Byte Shannon entropy above 3.5 |

- Source secret exclusions are copied into each rule, each regex scoped on
  its own. They include the GCP examples and the Vault letter-only legacy
  token exclusion.
- The legacy Vault `s.` form still needs the source `vault` keyword context.
  The `hvs.` prefix supplies its own keyword.
- Case changes caused by the global regex joining cannot be reached for these
  fixed-prefix forms. Detection whitespace and predicate whitespace keep
  their separate source meanings.

### Contextual and residual delimiter companions (44 rules)

20 contextual families each have 2 rules: a `-delimiter` rule and a
`-context-vt` rule. That gives 40 rules. 4 residual rules cover other
vertical tab and escaped quote gaps.

| Family | Rule IDs | Entropy or predicate |
| --- | --- | --- |
| Beamer | `beamer-api-token-delimiter`, `beamer-api-token-context-vt` | None |
| Defined Networking | `defined-networking-api-token-delimiter`, `defined-networking-api-token-context-vt` | None |
| Terraform password | `hashicorp-tf-password-delimiter`, `hashicorp-tf-password-context-vt` | Byte Shannon entropy above 2.0 |
| Heroku legacy UUID | `heroku-api-key-delimiter`, `heroku-api-key-context-vt` | None |
| HubSpot | `hubspot-api-key-delimiter`, `hubspot-api-key-context-vt` | None |
| Lob private key | `lob-api-key-delimiter`, `lob-api-key-context-vt` | None |
| Mailchimp | `mailchimp-api-key-delimiter`, `mailchimp-api-key-context-vt` | None |
| Mailgun private key | `mailgun-private-api-token-delimiter`, `mailgun-private-api-token-context-vt` | None |
| Mailgun signing key | `mailgun-signing-key-delimiter`, `mailgun-signing-key-context-vt` | None |
| Okta | `okta-access-token-delimiter`, `okta-access-token-context-vt` | Byte Shannon entropy above 4.0 |
| Plaid | `plaid-api-token-delimiter`, `plaid-api-token-context-vt` | None |
| Sidekiq | `sidekiq-secret-delimiter`, `sidekiq-secret-context-vt` | None |
| Snyk | `snyk-api-token-delimiter`, `snyk-api-token-context-vt` | None |
| Sonar | `sonar-api-token-delimiter`, `sonar-api-token-context-vt` (secret is capture 2) | None |
| Squarespace | `squarespace-access-token-delimiter`, `squarespace-access-token-context-vt` | None |
| Telegram | `telegram-bot-api-token-delimiter`, `telegram-bot-api-token-context-vt` | None |
| Typeform | `typeform-api-token-delimiter`, `typeform-api-token-context-vt` | None |
| Yandex access token | `yandex-access-token-delimiter`, `yandex-access-token-context-vt` | None |
| Yandex API key | `yandex-api-key-delimiter`, `yandex-api-key-context-vt` | None |
| Yandex AWS access token | `yandex-aws-access-token-delimiter`, `yandex-aws-access-token-context-vt` | None |
| Residual: Anthropic | `anthropic-api-key-vt`, `anthropic-admin-api-key-vt` | None |
| Residual: DigitalOcean | `digitalocean-refresh-token-vt` | None |
| Residual: OpenAI | `openai-api-key-legacy-delimiter` | Byte Shannon entropy above 3.0 |

- A `-delimiter` rule matches an escaped single, double or backtick quote, or
  a vertical tab, after a token whose assignment whitespace has no vertical
  tab.
- A `-context-vt` rule needs a vertical tab near the separator. It must be in
  the 3 bytes before the separator or the 5 bytes after it. The rule keeps
  all source endings.
  The first-VT alternatives keep the total bounds. They do not add a vertical
  tab to the separate label tail class of 0 to 20 bytes. For one assignment,
  only one of the two rules can match.
- Optional native ASCII preambles stay for match geometry, including both
  Okta preambles. Removing a preamble alone would not recover an occurrence.
- Provider labels and body alternatives are kept. The public Lob publishable
  key and Mailgun validation key roles are not included.
- Terraform keeps the `.tf` and `.hcl` path condition and captures the quotes
  with the password. Quoted bodies of 8 or 9 characters can add occurrences;
  the generic rule can already report longer bodies, which then only gain
  attribution or a different capture.
- Sonar rules report capture 2, because capture 1 is the login or token label.
- Okta accepts only the source label forms `okta`, `Okta` and `OKTA`, and only
  lowercase escaped `n` and `r`.
- Telegram's `A` after the numeric prefix is case-sensitive. Mailchimp keeps
  the source dot wildcard as a character wildcard.
- The Anthropic and DigitalOcean `-vt` rules cover the vertical tab ending of
  those families. `openai-api-key-legacy-delimiter` covers the (58,74) role
  segment pairs and the bare (20,20) form before escaped quotes or a vertical
  tab. The 20-segment role companion covers the new forms. Ordinary endings
  stay with the default rules.
- Every rule carries the full source secret predicates, each regex scoped on
  its own. Go predicate whitespace is separate from detector whitespace,
  which includes vertical tab. Overlapping assignments keep native match
  enumeration.

### Source-predicate provider formats (102 rules)

101 rules come from the pinned MIT Betterleaks configuration, and 1 rule is a
native Google ADC refresh token rule. Each rule keeps the source keywords,
capture, full rejection predicate and byte entropy comparison. The
provenance JSON records the original pattern and every change for each rule.

| Rule ID | Matches | Entropy or predicate |
| --- | --- | --- |
| `abuseipdb-api-key` | AbuseIPDB account API key | Byte Shannon entropy of at least 3.5 |
| `aikido-ci-token` | Aikido CI scan token | Byte Shannon entropy of at least 3.0 |
| `asaas-api-token` | Asaas payment API token, including sandbox `hmlg` | Byte Shannon entropy of at least 3.5 |
| `brave-search-api-key` | Brave Search API key | Byte Shannon entropy of at least 3.2 |
| `buildkite-service-token` | Buildkite agent, job, package or portal token | Byte Shannon entropy of at least 3.5 |
| `buildkite-user-access-token` | Buildkite user access token | Byte Shannon entropy of at least 3.5 |
| `canadian-digital-service-notify-api-key` | GC Notify API key | Byte Shannon entropy of at least 3.5 |
| `cartesia-api-key` | Cartesia voice API key | Byte Shannon entropy of at least 3.5 |
| `clerk-secret-key-delimiter` | Clerk backend secret key, including test keys | Byte Shannon entropy of at least 3.3 |
| `clickup-personal-api-token` | ClickUp personal API token (`pk_` is not a publishable key here) | Byte Shannon entropy of at least 3.5 |
| `cockroachlabs-cloud-api-key` | CockroachDB Cloud service account key | Byte Shannon entropy of at least 3.5 |
| `couchbase-capella-api-key` | Couchbase Capella management API secret | Byte Shannon entropy of at least 4.0 |
| `datastax-astra-application-token` | DataStax Astra application token | Byte Shannon entropy of at least 4.0 |
| `devcycle-server-sdk-key` | DevCycle server SDK key | Byte Shannon entropy of at least 3.0 |
| `devin-personal-api-key` | Devin personal API key | Byte Shannon entropy of at least 3.5 |
| `devin-service-api-key` | Devin organization service API key | Byte Shannon entropy of at least 3.5 |
| `devin-service-user-token` | Devin service user token | Byte Shannon entropy of at least 3.5 |
| `docker-swarm-join-token` | Docker Swarm join token | Byte Shannon entropy of at least 3.5 |
| `docker-swarm-unlock-key` | Docker Swarm unlock key | Byte Shannon entropy of at least 3.5 |
| `elastic-cloud-api-key` | Elastic Cloud API key | Byte Shannon entropy of at least 3.5 |
| `endorlabs-api-key` | Endor Labs API key part | Byte Shannon entropy of at least 3.0 |
| `endorlabs-api-secret` | Endor Labs API secret part | Byte Shannon entropy of at least 3.5 |
| `fal-api-key` | fal API key with key ID and secret | Byte Shannon entropy of at least 3.5 |
| `fullstory-api-key` | Fullstory server API key | Byte Shannon entropy of at least 3.3 |
| `highnote-secret-live-key` | Highnote live secret key | Byte Shannon entropy of at least 3.5 |
| `hunter-api-key` | Hunter API key | Byte Shannon entropy of at least 3.5 |
| `ibm-cloud-user-api-key` | IBM Cloud user API key | Byte Shannon entropy of at least 3.5 |
| `instantly-api-key` | Instantly API key | Byte Shannon entropy of at least 3.3 |
| `ionic-personal-access-token` | Ionic Appflow personal token | Byte Shannon entropy of at least 3.5 |
| `kagi-api-key` | Kagi API key | Byte Shannon entropy of at least 3.5 |
| `klaviyo-api-key` | Klaviyo private API key (`pk_` prefix) | Byte Shannon entropy of at least 3.5 |
| `labelbox-api-key` | Labelbox API key | Byte Shannon entropy of at least 3.5 |
| `labelbox-recursion-api-key` | Labelbox Recursion key | Byte Shannon entropy of at least 3.5 |
| `langchain-langsmith-personal-access-token` | LangSmith personal key | Byte Shannon entropy of at least 4.0 |
| `langchain-langsmith-service-key` | LangSmith service key | Byte Shannon entropy of at least 4.0 |
| `lichess-personal-access-token` | Lichess personal token | Byte Shannon entropy of at least 3.5 |
| `llama-cloud-api-key` | LlamaCloud API key | Byte Shannon entropy of at least 3.5 |
| `mailersend-api-token` | MailerSend API token | Byte Shannon entropy of at least 3.5 |
| `mem0-api-key` | Mem0 API key | Byte Shannon entropy of at least 3.0 |
| `mercury-production-api-token` | Mercury production API token | Byte Shannon entropy of at least 3.5 |
| `mergify-application-key` | Mergify application key | Byte Shannon entropy of at least 3.2 |
| `midtrans-production-server-key` | Midtrans production server key (`Mid-server-` only) | Byte Shannon entropy of at least 2.8 |
| `miro-access-token` | Miro OAuth access token | Byte Shannon entropy of at least 3.5 |
| `ngrok-api-key` | ngrok API key or agent authtoken | Byte Shannon entropy of at least 3.5 |
| `nuget-api-key` | NuGet API key | Byte Shannon entropy of at least 3.5 |
| `nylas-api-key` | Nylas API key | Byte Shannon entropy of at least 3.5 |
| `onesignal-rich-authentication-token` | OneSignal rich authentication token | Byte Shannon entropy of at least 3.5 |
| `onfido-live-api-token-ca` | Onfido live API token, Canada | Byte Shannon entropy of at least 3.5 |
| `onfido-live-api-token-eu` | Onfido live API token, EU | Byte Shannon entropy of at least 3.5 |
| `onfido-live-api-token-us` | Onfido live API token, US | Byte Shannon entropy of at least 3.5 |
| `opsgenie-api-key` | Opsgenie API key | Byte Shannon entropy of at least 3.0 |
| `paddle-live-api-key` | Paddle live API key | Byte Shannon entropy of at least 3.5 |
| `pagerduty-authorization-token` | PagerDuty authorization token | Byte Shannon entropy of at least 3.5 |
| `persona-production-api-key` | Persona production API key | Byte Shannon entropy of at least 3.5 |
| `pinecone-api-key-uuid` | Pinecone API key, UUID form | Byte Shannon entropy of at least 3.0 |
| `pinecone-api-key-pcsk` | Pinecone API key, `pcsk` form | Byte Shannon entropy of at least 3.5 |
| `pinterest-access-token` | Pinterest access token | Byte Shannon entropy of at least 3.5 |
| `polar-oauth-access-token` | Polar OAuth access token | Byte Shannon entropy of at least 3.5 |
| `polar-organization-access-token` | Polar organization token | Byte Shannon entropy of at least 3.5 |
| `polar-personal-access-token` | Polar personal token | Byte Shannon entropy of at least 3.5 |
| `postmark-api-token` | Postmark server or account token | Byte Shannon entropy of at least 3.0 |
| `proof-full-access-api-key` | Proof production full-access key | Byte Shannon entropy of at least 3.5 |
| `rainforest-pay-production-api-key` | Rainforest Pay production key | Byte Shannon entropy of at least 3.5 |
| `redirect-pizza-api-token` | redirect.pizza API token | Byte Shannon entropy of at least 3.5 |
| `resend-api-key` | Resend API key | Byte Shannon entropy of at least 3.5 |
| `retell-api-key` | Retell AI API key | Byte Shannon entropy of at least 3.0 |
| `rootly-api-key` | Rootly API key | Byte Shannon entropy of at least 3.5 |
| `runpod-api-key` | RunPod API key | Byte Shannon entropy of at least 3.5 |
| `samsara-api-token` | Samsara API token | Byte Shannon entropy of at least 3.0 |
| `scaleway-secret-key` | Scaleway secret key | Byte Shannon entropy of at least 3.0 |
| `scalr-api-access-token-delimiter` | Scalr API access token | Byte Shannon entropy of at least 3.5 |
| `segment-public-api-token` | Segment Public API token | Byte Shannon entropy of at least 3.3 |
| `tailscale-api-key` | Tailscale API access token | Byte Shannon entropy of at least 3.5 |
| `tailscale-auth-key` | Tailscale device enrollment key | Byte Shannon entropy of at least 3.5 |
| `tailscale-key` | Tailscale legacy untyped key | Byte Shannon entropy of at least 3.5 |
| `tailscale-oauth-client-secret` | Tailscale OAuth client secret | Byte Shannon entropy of at least 3.5 |
| `tailscale-scim-key` | Tailscale SCIM key | Byte Shannon entropy of at least 3.5 |
| `tailscale-webhook-secret` | Tailscale webhook signing secret | Byte Shannon entropy of at least 3.5 |
| `telnyx-api-v2-key` | Telnyx API v2 key | Byte Shannon entropy of at least 3.5 |
| `upcloud-api-token` | UpCloud API token | Byte Shannon entropy of at least 3.0 |
| `virustotal-api-key` | VirusTotal API key | Byte Shannon entropy of at least 3.5 |
| `voyageai-api-key` | Voyage AI API key | Byte Shannon entropy of at least 4.0 |
| `vultr-api-key` | Vultr API key | Byte Shannon entropy of at least 3.4 |
| `wakatime-api-key-uuid` | WakaTime API key, UUID form | Byte Shannon entropy of at least 3.0 |
| `wakatime-api-key-prefixed` | WakaTime API key, `waka_` form | Byte Shannon entropy of at least 3.0 |
| `woocommerce-consumer-secret` | WooCommerce consumer secret | Byte Shannon entropy of at least 3.5 |
| `workato-developer-api-token` | Workato developer API token | Byte Shannon entropy of at least 4.0 |
| `workos-production-api-key` | WorkOS production API key | Byte Shannon entropy of at least 3.5 |
| `xendit-production-api-key` | Xendit production API key | Byte Shannon entropy of at least 3.0 |
| `zoho-oauth-token` | Zoho OAuth access or refresh token | Byte Shannon entropy of at least 3.5 |
| `zoho-zapi-key` | Zoho ZAPI key | Byte Shannon entropy of at least 3.5 |
| `zuplo-consumer-api-key` | Zuplo consumer API key | Byte Shannon entropy of at least 3.3 |
| `supabase-management-token` | Supabase management token | Byte Shannon entropy above 3.5 |
| `thunderstore-api-token` | Thunderstore API token | Byte Shannon entropy of at least 3.5 |
| `unkey-root-key` | Unkey root key | Byte Shannon entropy of at least 3.5 |
| `val-town-api-token` | Val Town API token | Byte Shannon entropy of at least 3.5 |
| `temporal-cloud-api-key` | Temporal Cloud API key | Byte Shannon entropy of at least 3.2 |
| `openrouter-api-key` | OpenRouter API key | Byte Shannon entropy above 3.5 |
| `deepseek-api-key` | DeepSeek API key | Byte Shannon entropy above 3.5 |
| `kimi-api-key` | Kimi API key | Byte Shannon entropy above 3.5 |
| `zai-api-key` | Z.ai API key | Byte Shannon entropy above 3.5 |
| `gcp-adc-refresh-token` | Google OAuth refresh token in an ADC file | None |

- All 23 source path exclusions stay as rule allowlists, including root and
  nested `bun.lock` and `bun.lockb`. The rules also keep 13 source secret
  regex exclusions, 2 case-insensitive substring exclusions and local
  exclusions. The native loader keeps these predicates when single rules are
  selected.
- Source roles are chosen one by one. DevCycle server keys are included;
  DevCycle client and mobile keys and ConfigCat SDK keys are not. Midtrans
  includes only `Mid-server-`. The 2 Endor Labs rules keep separate IDs and
  thresholds; 2 attributions for one occurrence are not 2 credentials.
- Ionic, Miro and Resend keep their source keywords, even when the token
  itself cannot contain that keyword. Voyage, DeepSeek, Kimi and Z.ai keep
  the source assignment context.
- Clerk and Scalr select only their documented delimiter forms. WorkOS
  candidates with plain alphanumeric bodies can already be attributed to
  Stripe. A new provider finding is therefore not always a new occurrence.
- Capella keeps the 4 source proximity gaps of 32, 12, 12 and 32 ASCII
  bytes. Fal's wildcard context allows 1 ASCII byte other than LF. Asaas and
  Buildkite service delimiters use explicit ASCII classes. Scaleway's context
  allows up to 20 ASCII bytes other than LF. Non-ASCII and malformed bytes in
  those positions do not match.
- Supabase, Thunderstore and Val Town keep their two-digit predicates. Unkey
  needs a digit, an uppercase and a lowercase letter in the whole secret; its
  lowercase prefix supplies the lowercase letter. Temporal's marker supplies
  its required digits. These are anchored secret allowlists; no field or
  expression interpreter is added.
- `gcp-adc-refresh-token` captures only a `1//` refresh token value in a file
  named `application_default_credentials.json`, and needs the Google client
  ID keyword `.apps.googleusercontent.com`. The body has at least 20 bytes,
  the token at most 512 bytes, and whitespace is bounded. It does not capture
  or parse the JSON document. Whole service account documents and the
  generated Bitwarden pair expression are not included.

### Format and boundary supplements (30 rules)

19 rules come from the pinned MIT Betterleaks configuration and 11 from the
pinned Apache-2.0 Veles detectors.

| Rule ID | Matches | Source | Entropy or predicate |
| --- | --- | --- | --- |
| `adobe-client-secret-delimiter` | Adobe client secret before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `alibaba-access-key-id-boundary` | Alibaba Cloud AccessKey ID: `LTAI` and 17 to 21 alphanumeric bytes between word boundaries | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `authress-service-client-access-key-boundary` | Authress service client access key at selected punctuation | Betterleaks | Byte Shannon entropy of at least 4.0 |
| `databricks-api-token-delimiter` | Databricks API token before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `datadog-api-key` | Datadog API key in provider assignment context | Betterleaks | Byte Shannon entropy of at least 3.5 |
| `datadog-application-key-delimiter` | Datadog application key before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy of at least 3.5 |
| `etsy-open-api-key` | Etsy keystring and shared secret pair in API key context | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `gitlab-incoming-mail-address-token` | GitLab incoming mail address token | Betterleaks | Byte Shannon entropy above 3.0 |
| `gitlab-pat-routable-versioned` | Complete versioned GitLab routable personal access token | Betterleaks | Byte Shannon entropy above 4.0 |
| `gocardless-api-token-delimiter` | GoCardless live API token before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy of at least 3.5 |
| `grafana-api-key-base64` | Grafana API key with standard Base64 body characters | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `grafana-cloud-api-token-delimiter` | Grafana Cloud API token before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `grafana-service-account-token-delimiter` | Grafana service account token before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy of at least 3.0 |
| `heroku-api-key-v2-trailing-hyphen-delimiter` | Heroku token with a trailing hyphen `AA` body, before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy above 4.0 |
| `monday-api-token` | Monday API token in provider assignment context | Betterleaks | Byte Shannon entropy of at least 3.5 |
| `sendinblue-api-token-boundary` | Sendinblue API token at selected punctuation | Betterleaks | Byte Shannon entropy of at least 3.2 |
| `sourcegraph-access-token-delimiter` | Sourcegraph access token before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy above 3.0 |
| `stripe-access-token-delimiter` | Stripe access token before escaped quotes or vertical tab | Betterleaks | Byte Shannon entropy above 2.0 |
| `xai-api-key-delimiter` | xAI API key: `xai-` in any ASCII case and 70 to 120 alphanumeric, underscore or hyphen bytes, before a delimiter | Betterleaks | Byte Shannon entropy above 3.5 |
| `digitalocean-pat-boundary` | DigitalOcean personal access token at selected punctuation | Veles | None |
| `hcp-client-secret` | HCP client secret in an exact source label assignment | Veles | None |
| `heroku-platform-key-boundary` | Heroku `AA` platform key at selected punctuation | Veles | None |
| `npm-access-token-boundary` | npm access token at selected punctuation | Veles | None |
| `openrouter-api-key-boundary` | OpenRouter API key before a comma, `]`, `)` or `}` | Veles | None |
| `packagist-organization-read-token` | Packagist organization read token | Veles | None |
| `packagist-organization-update-token` | Packagist organization update token | Veles | None |
| `postman-api-token-boundary` | Postman API token at selected punctuation | Veles | None |
| `sendgrid-api-token-boundary` | SendGrid API token at selected punctuation | Veles | None |
| `slack-config-access-token-166` | Slack configuration access token: `xoxe.xoxp-`, 1 to 10 digits, `-` and a 166-byte alphanumeric body | Veles | None |
| `slack-config-refresh-token-147` | Slack configuration refresh token with a 147-byte body | Veles | None |

- Source predicates stay local to each rule. Betterleaks rules keep the
  source keywords, all source secret and path exclusions, generated
  supersession filters and the exact byte entropy comparison. The one
  exception is the generated Kingfisher filter that leaves exact 80-byte xAI
  bodies to its own rule. `xai-api-key-delimiter` does not keep it: by
  maintainer decision the rule stays independent of the legacy
  `xai-api-key-80` rule, and same-span duplicate findings with that rule are
  accepted. Veles rules do not get Betterleaks filters.
- GoCardless rejects entropy below 3.5. Stripe excludes `sk_test_` and
  WorkOS prefixes.
- The Betterleaks Heroku rule accepts only trailing-hyphen `AA` bodies. The
  Veles Heroku rule keeps the source final word boundary.
- Authress keeps lowercase credential prefixes, `acc` and account IDs.
  Datadog API and application keys keep their 32-byte and 40-byte
  hexadecimal bodies. Etsy captures the full keystring and shared secret
  pair. Grafana accepts the standard Base64 body alphabet. HCP matches a
  secret assignment without a client ID. Packagist organization tokens do
  not need a repository URL. Optional validation parts are not required
  rules or separate findings.
- Most rules consume selected punctuation, escaped quotes or a vertical tab
  after a complete bounded token. Alibaba matches between word boundaries
  and consumes no delimiter. HCP, Packagist and both Slack configuration
  rules keep the source fixed-width prefix extraction above the nominal
  length. HCP's Go whitespace excludes vertical tab; Betterleaks byte
  whitespace includes it. All token alphabets are explicit ASCII.
- The full versioned GitLab token and the 147-byte Slack refresh body can
  appear next to shorter findings from other rules. Before an escaped quote,
  the default `jwt` finding for a Monday token includes one extra backslash,
  while the Monday rule extracts the exact credential. Ordinary Monday JWT
  and Grafana forms can gain provider attribution without a new occurrence.
- Three rules report the same secret span as another rule for a shared
  form. Nothing removes these duplicate findings:
  - `alibaba-access-key-id-boundary` and the default `alibaba-access-key-id`
    rule both report a 20-byte body before a delimiter that the default rule
    accepts, such as a space. Other lengths and a comma give only the pack
    finding.
  - `slack-config-access-token-166` and the default
    `slack-config-access-token` rule both report a one-digit segment with a
    166-byte body. Segments of 2 to 10 digits give only the pack finding.
  - `xai-api-key-delimiter` and `xai-api-key-80` both report an 80-byte body
    before a delimiter or the end of input. On an 81 to 120 byte alphanumeric
    body, `xai-api-key-80` reports its 84-byte prefix and
    `xai-api-key-delimiter` reports the full token.
- The source marks the Betterleaks Alibaba rule `skipReport`, as a part of
  its `alibaba-secret-key` rule. This pack reports it, as the default rule
  does. `xai-api-key-delimiter` also reports `xai-token-` management keys,
  as the source does. `slack-config-refresh-token-147` keeps a one-digit
  segment.

### Connection keys and structured context (6 rules, 1 hidden)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `azure-app-configuration-key-comma` | Azure App Configuration access key before an unquoted comma and a space or tab | 44-byte key | Byte Shannon entropy above 3.5 |
| `azure-servicebus-key-comma` | Azure Service Bus shared access key before an unquoted comma and a space or tab | 44-byte key (capture 2) | Byte Shannon entropy above 3.5; `buffer-v1` `same-candidate` relation to the helper |
| `azure-servicebus-key-comma-tuple` | Hidden helper (`skipReport = true`) for the whole Service Bus tuple | None reported | Byte Shannon entropy above 3.0; source tuple exclusions |
| `jwt-unsigned-bearer-escaped` | `Authorization: Bearer`, one of 3 literal `alg:none` header encodings, a base64url payload, an empty signature, then an escaped quote or backtick | Token without the escaped delimiter | Byte Shannon entropy above 3.0 |
| `kubernetes-secret-yaml-long-context` | One Kubernetes Secret data item with 201 to 1000 ASCII bytes between `kind` and the data item, in either order | Data item, key and value | Source YAML path, keyword, template and empty value predicates |
| `cloudflare-api-token-context` | One of 7 credential labels and a 40-byte token before a comma | Token | None |

- The Azure key rules in the default rules and the extra pack still apply
  on their own.
- The Service Bus parent needs its own complete tuple through the helper. The
  helper keeps the source whole-tuple entropy and exclusions, and the parent
  also needs key entropy above 3.5. The detection input and both ends of the
  full match must be the same, also inside decoded inputs. An explicit rule
  selection must name both IDs.
- The JWT rule is a text pattern for an authentication candidate. It is not a
  JSON or JOSE parser and does not check signatures. Bare unsigned data and
  signed JWTs do not match. The default `jwt` rule can report a signed
  escaped token with its trailing backslash.
- The Kubernetes rule rejects matches that cross `---` or `...` document
  marker lines, including indented marker-like lines, and rejects overlaps
  with a short-context default match. Mapping keys that start with
  `---suffix` or `...suffix` still match. It does not parse YAML.
- Cloudflare excludes the public `CF_ACCOUNT_ID`. Its forward ASCII context
  does not reproduce the Veles pair algorithm. It keeps the source terminal
  word boundary and adds no Betterleaks path or secret predicates.

### Associated credentials (56 rules, 30 hidden)

26 reporting rules need 30 hidden helper rules through `buffer-v1` relations.
All 56 rules use the `bytes-v1` dialect with the exact generated source
pattern. Rule IDs below leave out `rustleaks.association.`; helper IDs leave
out `rustleaks.association.helper.`. A window of `0` has no line limit.

| Reporting rule | Hidden helpers | Window | Entropy or predicate |
| --- | --- | --- | --- |
| `aikido-client-secret` | `aikido-client-id` | 0 | Byte Shannon entropy of at least 3.5 |
| `artifactory-api-key` | `artifactory-jfrog-url` | 0 | Byte Shannon entropy of at least 3.5 |
| `artifactory-reference-token` | `artifactory-jfrog-url` | 0 | Byte Shannon entropy of at least 3.5 |
| `auth0-client-secret-v1` | `auth0-client-id-v1`, `auth0-domain-v1` | 10L | Byte Shannon entropy of at least 3.5 |
| `aws-session-token` | `aws-access-token`, `aws-secret-access-key` | 5L | Byte Shannon entropy above 0.0 |
| `azure-storage-account-key` | `azure-storage-account-name` | 8L | Byte Shannon entropy above 4.0 |
| `browserstack-access-key-v1` | `browserstack-username-v1` | 5L | Byte Shannon entropy of at least 3.0 |
| `canva-client-secret` | `canva-client-id` | 0 | Byte Shannon entropy of at least 3.5 |
| `ebay-client-secret` | `ebay-client-id` | 0 | Byte Shannon entropy of at least 3.0 |
| `exoscale-api-key` | `exoscale-api-secret` | 5L | Byte Shannon entropy of at least 3.0 |
| `langfuse-secret-key-v1` | `langfuse-public-key-v1` | 5L | Byte Shannon entropy of at least 3.0 |
| `miro-client-secret` | `miro-client-id` | 5L | Byte Shannon entropy of at least 3.5 |
| `mongodb-atlas-service-account-secret` | `mongodb-atlas-service-account-id` | 0 | Byte Shannon entropy above 3.0 |
| `mux-access-token-secret-v1` | `mux-access-token-id-v1` | 5L | Byte Shannon entropy of at least 3.5 |
| `ovh-application-secret` | `ovh-application-key`, `ovh-consumer-key` | 20L | Byte Shannon entropy above 3.0 |
| `paypal-client-secret-v1` | `paypal-client-id-v1` | 5L | Byte Shannon entropy of at least 3.5 |
| `planetscale-api-token` | `planetscale-id` | 0 | Byte Shannon entropy above 3.0 |
| `polymarket-api-key` | `polymarket-api-secret`, `polymarket-passphrase` | 20L | Byte Shannon entropy above 3.0 |
| `ramp-client-secret` | `ramp-client-id` | 0 | Byte Shannon entropy of at least 3.5 |
| `razorpay-key-secret-v1` | `razorpay-key-id-v1` | 5L | Byte Shannon entropy of at least 3.0 |
| `salesforce-access-token-v1` | `salesforce-instance-url-v1` | 30L | Byte Shannon entropy of at least 3.3 |
| `supabase-project-api-key` | `supabase-project-url` | 0 | Byte Shannon entropy above 4.0 |
| `tableau-personal-access-token-v1` | `tableau-personal-access-token-name-v1`, `tableau-server-host-v1` | 20L | Byte Shannon entropy of at least 3.5 |
| `upstash-redis-rest-token-v1` | `upstash-redis-rest-url-v1` | 5L | Byte Shannon entropy of at least 3.5 |
| `wiz-client-secret-v1` | `wiz-client-id-v1` | 5L | Byte Shannon entropy of at least 4.0 |
| `zoho-client-secret-v1` | `zoho-client-id-v1` | 5L | Byte Shannon entropy of at least 3.5 |

- All edges use the `full-match-window` relation. The source contract is
  pinned Kingfisher `scan_blob_with_context` without `DetectionOptions`. The
  window and buffer rules are in
  [Rule pack authoring](../../../docs/dev/rule-pack-authoring.md). Raw,
  decoded, sibling and nested buffers cannot supply each other's helpers.
  Native depth-two isolation does not claim that the source API decodes
  recursively.
- These rules set `secretGroup = 0`, so the secret is the first nonempty
  capture of the real match in the full buffer.
- Each helper applies its own keywords, paths, allowlists and byte entropy in
  its buffer. Each source global and local secret predicate is kept, and all
  23 source path exclusions stay on every rule. AWS session tokens and
  Polymarket passphrases reject byte entropy at or below 0, as in the source
  scanner floor.
- The `bytes-v1` patterns match raw bytes with source ASCII case folding and
  the original inline flags, repetition bounds, captures and leftmost-first
  greedy or lazy choice. The AWS session capture keeps the source 16 to 2048
  repetition without Go adaptation.
- 9 bounded bridges in 7 rules keep arbitrary source bytes: 2 Azure key and
  name bridges, 2 Canva ID bridges, 2 PlanetScale ID bridges and 3 Polymarket
  bridges. Limits count bytes. Complete UTF-8 characters and invalid bytes
  are accepted within each byte limit; one byte over is rejected. Dot-all and
  ordinary dot LF and CR rules stay as in the source.
- JFrog, Salesforce and Tableau delimiter guards own exactly one byte, also
  when the range starts or ends inside a UTF-8 character. Next helpers can
  consume other bytes of that character. Matching never normalizes malformed
  input or counts characters instead of bytes.
- Each qualifying helper occurrence appears once per parent in core
  `required_findings`, ordered by edge and occurrence. Helpers never become
  separate reports. Parent finding serialization and ordinary JSON reports
  leave out these records. Explicit support serialization and the core
  accessor show the support bytes. Primary-only redaction keeps supports;
  `without_detected_secrets` removes their secrets too.
- The default AWS access token rule and other default rules stay visible.

### Private Packagist credential roles (2 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `packagist-api-secret` | `packagist_acs_` and 64 to 96 lowercase hexadecimal bytes | Token | None |
| `packagist-api-key` | `packagist_ack_` and 28 to 32 lowercase hexadecimal bytes | Token | None |

- Both prefixes are case-sensitive. ASCII word boundaries that consume no
  bytes reject identifier substrings and slices of longer tokens. This is
  stricter than the unguarded source expressions.
- Each token is its own finding. No counterpart, assignment, path, gap,
  uniqueness, padding, entropy or checksum condition is added. 2 tokens give
  2 findings; 2 pairs give 4.
- The issuer describes ACS as an HMAC secret and documents ACK-only GET
  authentication. See the
  [issuer's authentication documentation](https://packagist.com/docs/api/api-authentication).
  ACS follows the visible Kingfisher selection, whose optional validation
  does not gate detection. Reporting ACK is broader than the hidden
  Kingfisher helper and the conditional partial detection in Veles. Veles
  tuple weighting is not implemented.

### Secret predicates (2 rules)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `mapbox-secret-token` | `sk.`, 23 to 308 base64url payload bytes that start with `eyJ1Ijoi`, a dot, and a 22-byte signature ending in `A`, `Q`, `g` or `w` | Token, 49 to 334 bytes | Byte Shannon entropy of at least 4.0; `base64url-segment-go-regex-v1` |
| `vercel-ai-gateway-key` | `vck_` and exactly 56 ASCII letters, digits, underscores or hyphens | Token, always 60 bytes | Byte Shannon entropy of at least 3.5; `vercel-cl100k-ratio-v1` |

- Both rules use `bytes-v1` outer regexes. Every source global secret filter,
  stopword and path prefilter stays as a separate local allowlist. Paths are
  never tested as secret regexes.
- Mapbox: the prefix is case-sensitive, and the source ASCII word and right
  delimiter guards stay. The predicate decodes only the payload, into at
  most 231 bytes, and applies the source Go expression. It needs the ordered
  `u` and `a` fields, a nonempty user and alphanumeric authorization text,
  and the source whitespace positions. Unicode user text is allowed; other
  JSON layouts, escaped user text and extra fields are not. Nonzero unused
  Base64 bits are allowed. Bad encoding or UTF-8 rejects the candidate and
  scanning continues; the source returns an error instead.
- Vercel: the prefix accepts ASCII case variants. The delimiters are an
  ordinary or escaped quote or backtick, ASCII whitespace, a semicolon, a
  literal `\n` or `\r` in either case, or end of input. Pinned cl100k
  encoding must give at least 25 tokens; 24 tokens gives a ratio of exactly
  2.5 and is rejected. The predicate covers the full source alphabet and
  case range. It uses no dictionary or approximation.
- Predicate details and costs are in
  [Rule pack authoring](../../../docs/dev/rule-pack-authoring.md). The
  tokenizer data is described in the
  [tokenizer data README](../data/README.md).

### Bitwarden CLI client secret (1 rule)

| Rule ID | Matches | Secret | Entropy or predicate |
| --- | --- | --- | --- |
| `bitwarden-cli-client-secret` | Quoted alphanumeric value of the `user_<UUID>_token_apiKeyClientSecret` property | Value, 10 to 50 bytes (capture 2) | Byte Shannon entropy above 0.0 |

- The property can be at any position or depth and can repeat. Go ASCII
  whitespace before the colon has no limit; whitespace after it is at most 20
  bytes. No outer object or fragment limit is added.
- The path must end with the source lowercase suffix
  `bitwarden cli/data.json`, compared with the frozen Go lowercase tables.
  Those include dotted capital I and exclude long s. Backslashes, repeated
  separators and hyphenated folder names do not match. No path component
  boundary is needed before the suffix.
- The rule binds the named property directly. It does not use arbitrary
  bridges or reversed tuples, and it does not bind a nearby string when the
  property is null. It does not reproduce Veles weighted tuple selection or
  the broader generated Kingfisher path expression. It does not check that
  the JSON is complete.
- The generic rule keeps its own entropy threshold. The default global
  allowlist still removes its alphabet stopword. `placeholder123` is still
  accepted; no general placeholder check is added.

## Shared boundaries

ASCII and bytes:

- Token alphabets and case variants are written as explicit ASCII classes.
  Non-ASCII case folding and non-ASCII whitespace never replace them.
- Byte whitespace in detectors is bytes 09 to 0d and 20, including vertical
  tab. Go whitespace in source predicates leaves out vertical tab.
- Consumed delimiters belong to the match, not the secret. Match trimming
  removes leading or trailing LF and keeps CR; neither changes the secret
  bytes. Raw byte ranges and decoded ranges keep the normal engine rules.
  `Fragment::new` starts locations at line zero, and the location helper
  includes the LF before a line in its byte column origin.

Entropy:

- Scalar entropy keeps the Gitleaks behavior: a character count and `<=`
  rejection. These rules keep their stated thresholds and the f64
  calculation.
- `byte-shannon-f64-v1` builds a 256-entry byte histogram, divides each
  nonzero count by the total length in binary64, and adds terms in ascending
  byte order. It does not claim bit-equal `log2` results on every platform.
  The finding reports the native entropy with the normal f32 conversion. The
  value stays available after rule selection.
- Thresholds can drop valid credentials with low entropy, and do not show
  issuer validity. No expression interpreter, tokenizer, word list,
  dependency or validator is added, except the fixed predicates above.

Inherited policy:

- A composition keeps the default global allowlists. For the
  Betterleaks rules, its 13 secret regex exclusions and 2 stopwords match the
  source's global secret exclusions for the ASCII domain. The Veles rules
  inherit them as an extra layer.
- Path exclusions differ. Rustleaks keeps its office, PDF, binary and `.git`
  exclusions. The pinned Betterleaks source also excludes Bun lock files; the
  rules from that source keep that exclusion locally.
- The global allowlist joins its regexes with the legacy flag scope. It can
  suppress mixed-case letter-only Asaas values that the source filters keep.
  A local copy cannot undo a global exclusion.
- Native allow comments, decoding, required-rule behavior and resource
  controls still apply. There is no switch to turn off inherited filtering.
  The pack does not claim the same policy as any source scanner.

Overlap:

- The native generic suppression can replace an overlapping generic finding
  with the provider rule. A token that the generic rule already found then
  gets a better attribution; it is not a new secret. Findings from other
  specific rules stay.
- Bare tokens without an assignment can add occurrences. Tests compare exact
  secret ranges to tell new occurrences from attribution changes.
- Each rule finds matches on its own. A long OpenAI token can contain a
  shorter token-shaped part, old inside new or the reverse. Both findings
  stay at their own spans. One combined source expression would report only
  the outer match. Such nested findings are extra alerts, not extra
  credentials. Output across provider rules is not guaranteed to be
  disjoint.
- Count exact occurrences apart from attribution and duplicates when you
  evaluate the pack.

Resources:

- Some bodies and contexts keep unbounded source repetitions:
  - the Slack session cookie body;
  - the DataStax, Fullstory, Workato and Temporal bodies;
  - the Notify service name and whitespace;
  - the GitLab incoming mail token and HCP assignment whitespace;
  - the first segment of the Yandex access token; and
  - the Bitwarden whitespace before the colon.
- Callers must choose input, work and finding-payload limits. Work units are
  engine checkpoints, not a time limit and not a bound on every regex
  operation.
- The full secret is kept when it is admitted, so a long candidate can have a
  large sensitive payload. A finite payload budget rejects it with an
  incomplete result before finding fields are copied.
- Helpers and their projected copies use work, span, finding and payload
  budgets. Running out of budget gives an incomplete result and never
  publishes a parent with only some of its helpers.
- Cancellation and budget limits in the predicates give typed incomplete
  results. Synthetic large-input tests are not performance guarantees.

Known gaps stay visible. A missing finding does not show that a value is
harmless.

## Provenance and license

| Source | Revision | Rules | License |
| --- | --- | --- | --- |
| [Betterleaks](https://github.com/betterleaks/betterleaks) `config/betterleaks.toml`, SHA-256 in the provenance JSON | `8f376ff9c31e` | The other 284 rules, including the hidden helpers | MIT, `LICENSE.betterleaks` |
| [Veles in OSV-SCALIBR](https://github.com/google/osv-scalibr) `veles/secrets` | `e8621f1fff93` | 19 rules: the 4 finite Veles formats, 11 format supplements, `cloudflare-api-token-context`, the 2 Private Packagist roles and `bitwarden-cli-client-secret` | Apache-2.0, `LICENSE.veles` |
| [Kingfisher](https://github.com/mongodb/kingfisher) | `01e7b817376f` | Archive used to read the Betterleaks and Veles sources as data, and the association contract | Apache-2.0, `LICENSE.kingfisher` |

The table shows 12-character revisions. The provenance JSON records the full
commit IDs and the SHA-256 of each source file.

- The Betterleaks and Veles sources were read as data from the archive in
  the pinned Kingfisher revision
  (`crates/kingfisher-rules/generated/upstream-sources.json.gz`). Generated
  Kingfisher patterns are not the copied source.
- For Veles, the exact detector files, source pattern lines and SHA-256
  values are recorded for each rule. The license and the Google copyrights
  are in `LICENSE.veles` and the adjacent [NOTICE](NOTICE). The archived
  source has no upstream NOTICE.
- `gcp-adc-refresh-token` is a narrower selection of the Betterleaks
  `gcp-application-default-credentials` rule, checked against Google's
  OAuth and ADC documentation.
- `rustleaks-providers-v1.provenance.json` records, for each rule, the source
  URL and SHA-256, original pattern, filters, keywords, selection and every
  change. The `NOTICE` keeps the attribution for each source.
- No downloaded scanner code runs or ships in the pack.

Changes made:

- IDs are namespaced and descriptions are factual.
- ASCII case-insensitive flags are expanded to explicit classes, and byte
  whitespace is written out.
- Source scalar entropy rules use `<=`. Byte entropy rules keep the exact
  source comparison: 151 rules reject below the threshold and 62 at or below
  it, including source scanner floors.
- Companion rules select reviewed format and delimiter cases only.

References:

- [Pinned Veles source](https://github.com/google/osv-scalibr/tree/e8621f1fff93beb5b70e5d6ba5fdc3e9854ec845/veles/secrets)
- [Pinned Betterleaks source](https://github.com/betterleaks/betterleaks/blob/8f376ff9c31ed5309ac448fe601c5dd21b376155/config/betterleaks.toml)
- [Groq security onboarding](https://console.groq.com/docs/production-readiness/security-onboarding)
- [Cerebras support source](https://github.com/Cerebras/vscode-cerebras-chat/blob/main/SUPPORT.md)
- [Replicate API tokens](https://replicate.com/docs/topics/security/api-tokens)
- [NVIDIA registry authentication](https://docs.nvidia.com/nvcf/dev/third-party-registries)
- [Private Packagist API authentication](https://packagist.com/docs/api/api-authentication)

## Maintenance

- Tests in `crates/rustleaks-core/tests/`:

  | Test file | Covers |
  | --- | --- |
  | `provider_rules.rs` | The provider rules up to the generated part, and the Alibaba, Slack access and xAI supplements |
  | `shared_rule_deltas.rs`, `contextual_rule_deltas.rs` | Delimiter companions |
  | `additional_coverage.rs`, `format_coverage.rs`, `special_coverage.rs`, `association_coverage.rs`, `remaining_verified_rules.rs` | The generated rules, with expectations in `tests/support/*.json` |
  | `native_policy.rs`, `native_predicates.rs` | Native loading, identity, entropy and predicates |

  The tests use synthetic positives, near misses, entropy boundaries, exact
  locations, ASCII and Unicode differences, invalid bytes, allowlists, old
  and new format unions, generic overlap, identity and scan budgets. Some
  tests compare with fixed smaller rule compositions and check that existing
  specific findings stay. Fixtures are written by hand and never sent to a
  provider. The tests are a regression contract, not a measure of accuracy
  on real data.
- All 3 packs with the default rules give 542 rules, including 32 hidden
  helpers.
- The rules after the line
  `# Maintained additional coverage; generated by xtask generate native-pack-identity.`
  come from `crates/xtask/src/tooling/native_coverage/providers.toml`, with
  their records in `native_coverage/reviewed.json`. The rules before that
  line are bound by hash. Do not edit generated rules in the pack file.
- Regenerate and check the pack, its provenance and its identity:

  ```sh
  cargo xtask generate native-pack-identity
  cargo xtask generate native-pack-identity --check
  ```

  The build also checks both pack digests and that the provider provenance
  is consistent. Nothing is downloaded at build or run time.
- A refresh needs a review of source changes, exact provenance and license
  bytes, and an evaluation of changed predicates and overlaps. A change in
  what the pack detects needs a new pack ID.
