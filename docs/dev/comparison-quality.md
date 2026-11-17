# Comparison quality inputs

The cross-scanner comparison measures precision and recall on labeled
inputs. This page describes the two labeled sources and the command that
prepares them:

- a constructed corpus that Rustleaks generates from a fixed seed, and
- Samsung CredData, a public third-party dataset, converted at run time.

Both write labels in the shared labels format. The scorer that reads them
belongs to the comparison harness, not to this page.

All output goes to a cache folder outside the repository. The command
refuses an output folder inside the checkout. The repository holds only the
generator, the adapter, the workload manifest and the expected digests.

## Commands

```sh
cargo xtask compare-quality generate --out CACHE
cargo xtask compare-quality verify
cargo xtask compare-quality verify --out CACHE
cargo xtask compare-quality credata --cache CACHE
cargo xtask compare-quality self-test
```

- `generate` writes the constructed corpus to `CACHE/quality/constructed-v1/`.
  It accepts `--seed`, `--scale` and `--force`.
- `verify` without `--out` regenerates the corpus in a temporary folder and
  compares it with the committed digests. With `--out` it checks an existing
  corpus: every label span, the tree digest and the committed digests.
- `credata` converts a prepared CredData checkout into labels. It never
  downloads anything.
- `self-test` runs the generator and the adapter on tiny synthetic data.
  `//crates/xtask:xtask_unit_test` runs it under Bazel on Unix hosts.

The program is Python 3.9 standard library code in
`crates/xtask/src/comparison_quality/`. xtask embeds it with `include_str!`
and runs it with `python3 -I`.

## Labels format

Each line of `labels.jsonl` is one JSON object with these fields, in this
order:

| Field | Meaning |
| --- | --- |
| `workload` | Workload identifier, `constructed-v1` or `credata`. |
| `path` | File path relative to the workload root, with forward slashes. |
| `commit` | Always `null`. Both sources are directory inputs. |
| `start`, `end` | Byte offsets of the labeled text in the file. `end` is exclusive. |
| `line` | One-based line of `start`. |
| `secret_sha256` | SHA-256 of the labeled bytes. The text itself is never stored. |
| `category` | Category name, listed below. |
| `label` | `secret` or `not-secret`. |
| `source` | `constructed` or `credData`. |

## Constructed corpus

### Purpose and limits

The constructed corpus gives every category a known number of secrets and
hard negatives, in realistic file contexts. Its labels come only from how
each value was built. No scanner output is used to make or adjust them.

Limits to disclose with any result:

- Rustleaks maintainers wrote the generator, and anyone can regenerate it.
  It is not a held-out set. A sealed held-out set is a separate input.
- `tuned` is `false` in the manifest. It must become `true` if Rustleaks
  rules or filters are ever changed after looking at results on this corpus.
- The corpus is synthetic. Context text repeats more than in real code.
- Every secret in the tree has a label. A finding that matches no `secret`
  label is a false positive, whether or not it matches a `not-secret` label.
  The `not-secret` labels let the report group false positives by kind.

### Fairness rules

- Formats come from public vendor or standards documentation, listed in
  [Format sources](#format-sources). They were not copied from the rules of
  Rustleaks, Gitleaks, Betterleaks, Kingfisher or any other scanner.
- Values are random, from a SHA-256 based stream keyed by the seed, so the
  bytes do not depend on the Python version or platform.
- Where a published description includes a checksum, the value carries one.
  GitHub tokens end with a CRC32 of the 30-character random part in six
  Base62 digits. GitHub does not publish the Base62 alphabet order or the
  hashed part. The generator uses `0-9A-Za-z` and hashes the random part.
  There is no category of tokens with a wrong checksum, because a tool that
  checks the checksum differently would be marked wrong unfairly.
- Lengths that vendors do not publish are taken from published examples,
  and the source table says so.
- Context text is dense with words such as `key`, `token`, `secret` and
  `password` in lines that hold no credential, so generic rules run.

### Layout

`CACHE/quality/constructed-v1/` holds:

- `tree/`: the files to scan, in several `project-NN` folders;
- `labels.jsonl`: one label per planted value;
- `workload.json`: the workload manifest, with family `labeled`;
- `summary.json`: digests and counts.

The committed copies are `benchmarks/comparison/quality/labeled.json` and
`benchmarks/comparison/quality/constructed-v1.expected.json`. A unit test
fails when the generator sources change without new committed digests. To
update them, run `generate` into an empty cache folder, copy `workload.json`
and `summary.json` over the committed files, and run `verify`.

### Contents

The default corpus uses seed `rustleaks-quality-constructed-v1` and scale 2.
It has 730 files, 820,785 bytes and 1,976 labels: 1,100 secrets and 876 hard
negatives.

| Category | Secret | Not secret | What it holds |
| --- | ---: | ---: | --- |
| `chat-token` | 150 | 0 | Slack bot and user tokens, Slack webhook URLs, Discord and Telegram bot tokens |
| `cloud-key` | 194 | 0 | AWS access key IDs, AWS secret access keys next to them, Google API keys |
| `connection-string` | 60 | 0 | Password or key inside SQL Server, Azure Storage, Azure Service Bus and JDBC strings |
| `database-uri` | 80 | 0 | Password inside PostgreSQL, MySQL, MongoDB, Redis and AMQP URIs |
| `generic-api-key` | 120 | 0 | Random values assigned to names such as `api_key` or `client_secret` |
| `http-auth` | 50 | 0 | Basic and Bearer credentials in logs, shell scripts and docs |
| `jwt` | 60 | 0 | HS256 signed JSON Web Tokens |
| `password` | 100 | 0 | Random passwords and passphrases assigned to password names |
| `payment-key` | 50 | 0 | Stripe live secret and restricted keys |
| `private-key` | 76 | 0 | RSA, PKCS #8, EC, OpenSSH and OpenPGP private key blocks, including Google service account key files |
| `vcs-token` | 160 | 0 | GitHub classic and fine-grained tokens, GitLab tokens |
| `example-key` | 0 | 70 | Example values published in vendor documentation |
| `hash` | 0 | 170 | Git commit IDs, SHA-256 and MD5 digests, image digests, `go.sum` and checksum files |
| `high-entropy` | 0 | 60 | `data:` URIs, asset fingerprints, nonces |
| `identifier` | 0 | 86 | AWS account IDs and ARNs, OAuth client IDs, Twilio account SIDs, service account key IDs |
| `integrity` | 0 | 80 | Subresource Integrity values in HTML and `package-lock.json` |
| `near-miss` | 0 | 70 | Token shapes with a wrong length, alphabet or structure |
| `placeholder` | 0 | 100 | `<YOUR_API_KEY>`, `${API_TOKEN}`, `changeme`, `xxxx` and prefix-only templates |
| `public-key` | 0 | 60 | SSH public keys, PEM public keys and certificates |
| `publishable-key` | 0 | 40 | Stripe live publishable keys, which Stripe documents as safe to expose |
| `test-fixture` | 0 | 60 | Values marked fake, in test paths |
| `uuid` | 0 | 80 | Random UUIDs under request, trace and tenant names |

Contexts: `.env` files, YAML, Docker Compose, GitHub Actions workflows,
JSON, Java properties, INI, TOML, Python, JavaScript, TypeScript, Go, Java,
Ruby, PHP, C#, Rust, shell, Terraform, Dockerfiles, logs, Markdown, HTML,
`package-lock.json`, `go.sum`, checksum files, `authorized_keys` and key
files. Multi-line keys are stored escaped in JSON and `.env` files, as YAML
block scalars, and as raw strings in source code. About 15 percent of the
positives of five kinds sit in test paths, because a real-looking credential
in a test file is still a credential. Some comment lines hold non-ASCII
characters, so byte and character offsets differ.

A label that covers part of a value marks only the secret part: the password
in a URI or connection string, or the credential after `Basic ` or
`Bearer `. A private key label covers the whole block from `-----BEGIN` to
the end of the `END` line.

### Format sources

| Kind | Label | Source |
| --- | --- | --- |
| AWS access key ID and secret access key | secret | [IAM identifier prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes) give `AKIA`. The [access keys page](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) example gives 20 and 40 characters. |
| Google API key | secret | Only the example on the [API keys page](https://docs.cloud.google.com/docs/authentication/api-keys): `AIza` and 39 characters. |
| Google service account key file | secret | [Create and delete service account keys](https://docs.cloud.google.com/iam/docs/keys-create-delete) |
| GitHub tokens | secret | [GitHub token formats](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats) and the [token format post](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/). The 40-character classic length and the fine-grained length are from public examples. |
| GitLab tokens | secret | [Token prefixes](https://docs.gitlab.com/security/tokens/#token-prefixes). The 20-character body is from public examples. |
| Slack tokens | secret | [Token types](https://docs.slack.dev/authentication/tokens/), including the `xoxp-` example layout |
| Slack webhook URL | secret | [Incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/), which says the URL contains a secret |
| Discord bot token | secret | The example in [Discord authentication](https://docs.discord.com/developers/reference#authentication) |
| Telegram bot token | secret | The example in [Authorizing your bot](https://core.telegram.org/bots/api#authorizing-your-bot) |
| Stripe secret and restricted keys | secret | [API keys](https://docs.stripe.com/keys). Lengths are from public examples. |
| Database URIs | secret | [PostgreSQL URIs](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS), [MongoDB connection strings](https://www.mongodb.com/docs/manual/reference/connection-string/), [RabbitMQ URI spec](https://www.rabbitmq.com/docs/uri-spec) |
| Connection strings | secret | [Azure Storage](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string), [ADO.NET syntax](https://learn.microsoft.com/en-us/dotnet/framework/data/adonet/connection-string-syntax), [Service Bus SAS](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-sas), [PostgreSQL JDBC](https://jdbc.postgresql.org/documentation/use/) |
| Private keys | secret | [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468), [RFC 4880 section 6](https://www.rfc-editor.org/rfc/rfc4880#section-6) with its CRC-24, [OpenSSH key format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key). Key material is random bytes inside a DER-shaped outer structure. |
| JSON Web Token | secret | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) |
| HTTP Basic and Bearer credentials | secret | [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617), [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) |
| Generic API keys and passwords | secret | No vendor format. Random values assigned to credential names. |
| Hashes and digests | not secret | [Git object names](https://git-scm.com/docs/gitglossary#def_object_name), [OCI digests](https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests), [`go.sum`](https://go.dev/ref/mod#go-sum-files), [`sha256sum`](https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html) |
| UUID | not secret | [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562), version 4 |
| Integrity values | not secret | [Subresource Integrity](https://www.w3.org/TR/SRI/), [package-lock.json](https://docs.npmjs.com/cli/configuring-npm/package-lock-json) |
| Vendor example keys | not secret | The AWS, Azurite, Discord, Telegram, Slack and Google example values on the pages above |
| Public keys and certificates | not secret | [RFC 4253 section 6.6](https://www.rfc-editor.org/rfc/rfc4253#section-6.6), [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) |
| Stripe publishable key | not secret | [API keys](https://docs.stripe.com/keys) says publishable keys are safe to expose |
| Identifiers | not secret | [IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html) and the identifier fields of the formats above |
| `data:` URIs and other encoded data | not secret | [RFC 2397](https://www.rfc-editor.org/rfc/rfc2397) |
| Placeholders, test fixtures, near misses | not secret | No vendor format. Built to look like the formats above while being invalid or marked fake. |

## Samsung CredData

### Review

Reviewed at commit `01e3d135a90f46c9a7965683b24a05d12e136b33` of
<https://github.com/Samsung/CredData> on 2026-11-17.

- **License.** The repository is under the Apache License 2.0. That covers
  the metadata, the scripts and the README. The README says each data file
  stays under the license of its source project. CredData kept only
  repositories whose license allowed use in a dataset. A license file per
  source repository is copied next to its data.
- **Verdict.** Benchmark use is allowed: the metadata is Apache-2.0, and the
  data files are fetched from their public sources under their own licenses.
  Rustleaks must not redistribute the data. The adapter reads a local copy
  in a cache folder, and nothing from CredData is committed.
- **Download.** `download_data.py` reads `snapshot.json`, which lists 337
  GitHub repositories with pinned commits. It fetches each commit with
  `git fetch --depth 1` into `tmp/`, copies the labeled files into `data/`,
  then rewrites the true values. It needs Linux or macOS, Python 3.10 or
  later, Git and network access to all 337 repositories. Its
  `requirements.txt` adds `pybase62`, used to rewrite values, and other
  packages. The download was not run for this review. The size of `tmp/` is
  not known; `data/` is about 17 million lines in about 11,500 files,
  according to `.ci/benchmark.txt`. A repository that has disappeared stops
  the script.
- **Metadata format.** `meta/` holds one CSV file per repository, 337 files
  and about 6 MB. The columns are `Id`, `FileID`, `Domain`, `RepoName`,
  `FilePath`, `LineStart`, `LineEnd`, `GroundTruth`, `ValueStart`,
  `ValueEnd`, `CryptographyKey`, `PredefinedPattern` and `Category`. Lines
  are one-based. `ValueStart` and `ValueEnd` are character positions in a
  line. An empty or `-1` value means the whole line.
- **Labels.** `T` means the value looks like a real credential. `F` means a
  false positive. `X` means a test value, an example or a placeholder.
  CredData's own scorer counts both `F` and `X` as negatives.
- **Counts.** The adapter read all 67,896 metadata rows at this commit:
  15,753 `T`, 48,061 `F` and 4,082 `X`, in 11,030 files from 337
  repositories. 33,571 rows mark a whole line, 1,003 of them `T`. 1,351
  rows span more than one line, mostly private keys.
- **Categories.** `Category` holds CredSweeper rule names, joined with `:`
  when more than one rule applies. There are 274 distinct values. The most
  common `T` categories are `Key` (3,822), `Password` (2,573), `UUID`
  (2,316), `Secret` (1,263) and `PEM Private Key` (1,161).
- **Obfuscation.** Only `T` values are rewritten. Fixed-format values keep
  their prefix and get random characters from the original character set
  and length. Private key files are replaced by generated keys. Values in
  the `AWS Multi`, `Google Multi`, `JWK`, `Alibaba Multi` and `Twilio Multi`
  categories are not rewritten. `F` and `X` values keep their original text.
  Directory and file names are replaced by hashes under
  `data/<repo>/<scope>/`.

### Effects on a comparison

- **Test paths.** Ground rule 1 labels every credential in test or example
  folders as `T`. At this commit 10,618 of the 15,753 `T` rows are under a
  `test` scope folder. A tool that skips test paths, or treats obvious test
  values as safe, loses recall here by design.
- **Label vocabulary.** CredData labels CredSweeper candidates, including
  UUIDs, salts and nonces, and keyword lines without a vendor format. A
  scanner that reports only vendor formats will show low recall on those
  categories. Report CredData results by category, not only in total.
- **Unlabeled findings.** CredData labels only lines that its source tools
  reported. A finding on an unlabeled line is unknown, not a false positive.
  CredData's own scorer prints it as `LOST` and leaves it out of the
  totals. The harness should do the same for this workload.
- **Rewritten values.** Rewritten values have the right shape but random
  content, so validation and checksum checks may reject them.
- **Prior tuning.** Betterleaks release candidates changed generic filters
  using CredData false positives (pull requests 485 and 487). Its CredData
  score is not a held-out measurement. Rustleaks has not used CredData.
- **Known label noise.** The Betterleaks author reported labels that look
  wrong, worth about 0.05 of F1.

### Prepare and convert

The `credata` command expects the checkout at `CACHE/credata/CredData`,
or at `--checkout`, which must be inside `CACHE`. Prepare it once:

```sh
mkdir -p CACHE/credata
git clone https://github.com/Samsung/CredData CACHE/credata/CredData
git -C CACHE/credata/CredData checkout 01e3d135a90f46c9a7965683b24a05d12e136b33
cd CACHE/credata/CredData
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python download_data.py --data_dir data --jobs 8
```

Then convert, from the Rustleaks checkout:

```sh
cargo xtask compare-quality credata --cache CACHE
```

The command writes `CACHE/credata/labels.jsonl`, `CACHE/credata/workload.json`
(set `credata`, family `labeled`, workload path `credata/CredData/data`)
and `CACHE/credata/summary.json` with counts and digests of the data tree.

Conversion rules:

- `path` is `FilePath` without its leading `data/`.
- `T` becomes `secret`. `F` and `X` become `not-secret`.
- `category` is `credata-` followed by the `Category` text in lower case,
  with each run of other characters replaced by `-`. For example,
  `PEM Private Key` becomes `credata-pem-private-key`.
- Character positions become byte offsets in the UTF-8 file. The download
  script rewrites every labeled file with `\n` line endings, and the adapter
  rejects a file that still holds `\r`.
- A whole-line row covers the line without its newline. A multi-line row
  runs from `ValueStart` on `LineStart` to `ValueEnd` on `LineEnd`.
- Rows with the same path, span and label are written once. Labels may
  overlap, because CredData marks some lines both as a whole and by value.
- A row that cannot be converted, such as a missing file or a line past the
  end, stops the command. `--max-problems N` allows up to N such rows and
  lists them in `summary.json`.
