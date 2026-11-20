# Comparison workloads

This page describes the inputs for comparing Rustleaks with other secret
scanners: pinned public repositories, generated synthetic workloads, and a
matrix of each tool's own rule examples. It explains what each set is, why it
was chosen, which inputs Rustleaks was tuned on, and how to fetch and check
them. The labeled quality corpus is described separately.

No third-party content is stored in this repository. The commands fetch or
build every input at run time into a cache folder that you choose. The
repository holds only the manifests under
`benchmarks/comparison/workloads/` and the code under
`crates/xtask/src/comparison_workloads/`.

## Commands

| Command | What it does |
| --- | --- |
| `cargo xtask compare-workloads fetch --cache DIR` | Fetches the pinned public repositories |
| `cargo xtask compare-workloads generate --cache DIR` | Generates the synthetic workloads and their labels |
| `cargo xtask compare-workloads matrix --cache DIR` | Builds the home-fixtures matrix from pinned upstream sources |
| `cargo xtask compare-workloads verify --cache DIR` | Checks cached workloads before a run |
| `cargo xtask compare-workloads self-test` | Checks the commands offline on tiny synthetic data |

Options:

- `fetch`: `--only ID,...` selects repositories. `--mode dir|git|both`
  overrides the manifest modes. `dir` fetches one commit and `git` fetches
  the full history. Large repositories are skipped unless you pass
  `--allow-large`. A repository that already passes verification is not
  fetched again unless you pass `--force`.
- `generate`: `--only ID,...` selects workloads. `--sizes 1,16` limits the
  size series in MiB. `--scale smoke` makes tiny versions for testing.
  `--write-manifest` rewrites `synthetic.json` after a full run.
- `matrix`: `--tools gitleaks,betterleaks,...` selects fixture sources.
  `--offline` reuses sources that are already in the cache.
- `verify`: `--set public-repos|synthetic|fixtures-matrix|all` and `--only`
  select workloads. `--deep` also runs `git fsck` on full histories.
  `--mode dir|git|both` states which modes the fetched repositories must
  support; by default the manifest modes apply, so a one-commit fetch fails
  for a repository listed with `git` mode.
- Every command accepts `--git PATH` to choose the Git executable.

The cache folder must be outside the repository; the check compares file
identities, so a link or a differently cased path to the repository is
refused. The commands need Python 3.9 or later and Git. Python runs with
`python3 -I`, reads the program from standard input, and uses only the
standard library. `fetch`, `generate` and `matrix` are supported on macOS and
Linux only.

Example:

```sh
cargo xtask compare-workloads fetch --cache ~/rustleaks-cache --only croc,flask
cargo xtask compare-workloads generate --cache ~/rustleaks-cache --sizes 1,16
cargo xtask compare-workloads matrix --cache ~/rustleaks-cache
cargo xtask compare-workloads verify --cache ~/rustleaks-cache
```

## Cache layout

| Path | Content |
| --- | --- |
| `repos/<id>/repo/` | Git repository with one ref, `refs/heads/main`, at the pinned commit, and no checkout |
| `repos/<id>/tree/` | The exact blob bytes of the pinned commit, without `.git` |
| `repos/<id>/fetch.json` | The commands that ran, the Git version, counts and the tree listing hash |
| `synthetic/<id>/` | One synthetic workload |
| `fixtures-matrix/<id>/` | One fixture workload, one folder per case |
| `upstream/<tool>/` | Fetched upstream sources for the matrix |
| `labels/<set>/<id>.jsonl` | Labels, kept outside the scanned folders |
| `inventory/<set>/<id>.json` | File list with sizes and SHA-256, label hash, and Git summary |

Workload manifests give paths relative to the cache folder. Public
repositories have a `paths` field with the `dir` and `git` scan targets.

## Public repositories

`public-repos.json` lists 14 repositories pinned by full commit on
2026-11-17. Each pin is the latest release tag at that date, resolved with
`git ls-remote`. Nine are the repositories of Kingfisher's cross-tool
benchmark. The others fill the size classes, so that each class has more
than one repository, several languages, lockfiles, minified assets and
binary files.

Size classes use the packed history size reported by the hosting API:
small is under about 50 MB, medium is about 50 MB to 1 GB, and large is above
1 GB. Sizes are approximate. Commit counts and file counts come from the
GitHub API at the pinned commit. For mongo, TypeScript and linux the tree
listing was truncated, so their file and lockfile counts are lower bounds.
`fetch` records exact counts in `fetch.json`.

| ID | Class | Languages | Tag | Packed size | Commits | Lockfiles, minified, binaries | Kingfisher benchmark |
| --- | --- | --- | --- | --- | --- | --- | --- |
| croc | small | Go | v11.6.5 | 13 MB | 2,577 | 2, 0, 42 | yes |
| flask | small | Python | 3.1.3 | 13 MB | 5,463 | 2, 0, 5 | no |
| jq | small | C | jq-1.8.2 | 8 MB | 1,925 | 1, 0, 2 | no |
| select2 | small | JavaScript, CSS | 4.1.0 | 15 MB | 2,694 | 1, 11, 81 | no |
| rails | medium | Ruby, JavaScript | v8.1.4.1 | 303 MB | 96,716 | 3, 0, 75 | yes |
| django | medium | Python, JavaScript | 6.1.3 | 291 MB | 34,869 | 2, 5, 81 | yes |
| ruby | medium | C, Ruby | v4.0.9 | 430 MB | 96,659 | 13, 0, 10 | yes |
| lucene | medium | Java | releases/lucene/10.6.0 | 556 MB | 38,783 | 2, 0, 498 | yes |
| bootstrap | medium | JavaScript, SCSS | v5.3.9 | 336 MB | 23,360 | 1, 11, 115 | no |
| prometheus | medium | Go, TypeScript | v3.16.0 | 304 MB | 19,070 | 7, 0, 5 | no |
| gitlab | large | Ruby, JavaScript | v19.5.6-ee | not reported | not measured | present, not counted, present | yes |
| mongo | large | C++, JavaScript, Python | r9.0.8 | 1.5 GB | 102,062 | 15, 0, 137 | yes |
| typescript | large | TypeScript, Go | v7.0.2 | 3.0 GB | 39,124 | 1, 0, 0 | yes |
| linux | large | C | v7.3 | 6.6 GB | 1,485,420 | 1, 0, 1 | yes |

The GitLab API reports no repository size without signing in. Kingfisher
issue 241 reports about 1.75 million blobs in GitLab's full history.

Kingfisher's cross-tool benchmark cloned each default branch without
recording commits. These pins use release tags instead, so the trees are not
the trees Kingfisher measured. The manifest marks the repositories of that
benchmark with `kingfisher_k1: true`. Reports must show them and the other
repositories as separate groups, so that results on Kingfisher's own
benchmark set can be told apart.

### How a repository is fetched

`fetch` runs these steps for each repository and records the exact commands in
`fetch.json`:

```sh
git init --quiet repo
git -C repo fetch --no-tags --quiet URL refs/tags/TAG   # adds --depth 1 for dir only
git -C repo update-ref refs/heads/main COMMIT
git -C repo symbolic-ref HEAD refs/heads/main
```

Before the ref is created, `fetch` checks that the fetched tag resolves to the
pinned commit. A moved tag fails the fetch. The repository then has exactly
the history reachable from the pinned commit, one branch and no tags. This
fixes the history scope for every tool. `tree/` is written from
`git ls-tree` and `git cat-file`, so it holds the committed bytes without
line-ending, filter or export-ignore changes.

Notes:

- `git` mode needs the full history. A partial clone would fetch objects
  during the timed scan, so it is not used.
- `dir` mode needs only `tree/`. With `--mode dir` the fetch uses
  `--depth 1`.
- `repo/` has no checkout, so a directory scan of it sees only `.git`. Scan
  `tree/` for `dir` mode and `repo/` for `git` mode.
- On a case-insensitive file system, paths that differ only in case collide.
  The linux tree has such paths. `fetch` keeps the first path, lists the
  others in `fetch.json`, and prints a warning. Paths the file system cannot
  hold are listed the same way. Use a case-sensitive volume for an exact
  tree.
- The full histories of the large repositories need several GB each. Fetch
  them only when a run needs them.
- Every `git` call has a time limit: 4 hours for `git fetch` and 6 hours for
  local commands. `git fetch` also gets `http.lowSpeedLimit=1000` and
  `http.lowSpeedTime=120`, so it stops when the transfer stays under 1000
  bytes per second for 2 minutes. When `tree/` is written, `git cat-file` is
  killed if one object takes more than 10 minutes, and gets 1 minute to exit
  at the end.

Repositories are used for speed only. They carry no labels. Findings in real
repositories are not recorded in this repository. Each repository keeps its
own license; the manifest names it for reference.

## Synthetic workloads

`synthetic.json` lists 71 generated workloads. Every value comes from a fixed
seed, so a fresh `generate` gives the same bytes and the same Git commit IDs
on every host. `verify` compares each workload with the hashes in the
manifest. The manifest sizes add up to about 6.2 GB. Git workloads list only
their checked-out files, so with Git storage and labels the cache holds
about 6.6 GB.

File modes come from the generator, not from the file system: inventories
hash file bytes only, and generated workloads record their executable paths
separately. Stored archives are written as made on Unix.

### Tuned workloads

The first 19 entries (recipe `cli-synthetic-v1`) are kept byte for byte.
Rustleaks was tuned on these inputs, including `heldout-mixed-8mib`, so the manifest marks them
`tuned: true` and reports must say so. They plant only three token shapes
(GitHub, AWS and Slack) in repetitive filler, which favors designs that skip
work when no keyword is present. Their GitHub tokens do not carry a valid
checksum.

| ID | Shape |
| --- | --- |
| json-4mib, json-768-files | JSON Lines records with sparse tokens |
| base64-20000 | 20,000 Base64-encoded tokens, decode depth 1 |
| files-100000 | 100,000 files of 64 bytes |
| findings-10000 | 10,000 distinct tokens in one file |
| zstd-500 | 500 Zstandard streams |
| invalid-utf8-4mib | Malformed UTF-8 with tokens on both sides |
| multilanguage-256kib, mixed-app-16mib, mixed-clean-4mib, heldout-mixed-8mib | Mixed source trees |
| empty-stdin, tiny-clean-file, tiny-positive, tiny-clean-tree | Startup controls |
| git-20000, git-bounded-control, git-current-tree-control, git-staged-control | Linear history of 20,000 commits and its scope controls |

### Realistic shapes

These workloads (recipe `rustleaks-synthetic-v2`) are marked
`tuned: false`. Each main shape has a size series of 1, 16, 128 and 1,024 MiB,
so that startup cost and throughput can be separated. Files stay at or below
2 MiB, under every tool's default file size limit.

| Shape | Content |
| --- | --- |
| keyword-dense | Configuration and text files full of `key=`, `token:` and `password` words with non-secret values: environment references, placeholders, booleans, paths |
| entropy-negatives | Lockfiles, `go.sum`, checksum lists and ID tables full of hashes, UUIDs and integrity strings |
| mixed-source | Source files in 12 languages with varied line lengths, keyword use in code, and occasional long data lines |
| minified | Minified JavaScript and CSS on one line per file, up to 2 MiB, with inline data URIs |
| binary-mix | Images, shared objects, stored jar archives and fonts mixed with source files |

Planted values:

- Secrets: 12 credential shapes (GitHub, GitLab, AWS, Slack, Stripe, npm,
  PyPI, SendGrid and Shopify tokens, RSA private key blocks, generic
  passwords and database URIs with passwords). Each value is random, has
  upper case, lower case and digits where the format allows, has Shannon
  entropy of at least 3.5, and avoids placeholder words.
- Hard negatives: SHA-256 and SHA-1 hex, UUIDs, `sha512-` integrity strings,
  `h1:` checksums, AWS keys ending in `EXAMPLE`, `ghp_` followed by `x`
  characters, environment references, template placeholders, Base64 data and
  masked values.
- In binary-mix, some shared objects hold a GitHub token shape between NUL
  bytes. These labels have `in_binary: true`, because tools differ in
  whether they read binary files.

### Where the token shapes come from

Each shape follows a provider's published prefix and format. Where the
provider does not state a length or alphabet, the generator uses a value
inside the documented format, and the table says where that choice
coincides with a Gitleaks rule's bounds. A shape that coincides with one
tool's rule favors no tool by itself, but reports should keep it in mind.

| Shape | Source | Coincides with a tool rule |
| --- | --- | --- |
| `ghp_`, 30 letters or digits, and a 6-character checksum | GitHub, [Behind GitHub's new authentication token formats](https://github.blog/security/application-security/behind-githubs-new-authentication-token-formats/), which describes the prefix and the CRC32 checksum | The total shape is the Gitleaks `github-pat` shape. The checksum is the CRC32 of the 30 characters in base62 (0 to 9, A to Z, a to z), padded to 6 characters; the published example in Kingfisher 1.113.0 `github.yml` reproduces with this reading. |
| `glpat-` and 20 characters | GitLab, [Personal access tokens API](https://docs.gitlab.com/api/personal_access_tokens/) | Length 20 is the Gitleaks `gitlab-pat` length. Newer GitLab tokens can be longer. |
| `AKIA` and 16 characters from A to Z and 2 to 7, 20 in all | AWS, [Manage access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) for the prefix and the 20-character example | AWS does not state the alphabet; the Base32 alphabet is the Gitleaks `aws-access-token` alphabet. |
| `xoxb-`, two 12-digit groups and 24 characters | Slack, [Token types](https://api.slack.com/authentication/token-types) for the prefix | The group lengths fall inside the Gitleaks `slack-bot-token` bounds. |
| `sk_live_` and 24 characters | Stripe, [Authentication](https://stripe.com/docs/api/authentication) | Inside the Gitleaks `stripe-access-token` length range. Current Stripe keys can be longer. |
| `npm_`, 30 letters or digits, and a 6-character checksum | npm, [About access tokens](https://docs.npmjs.com/about-access-tokens) for the prefix | Same checksum as GitHub tokens; the published example in Kingfisher 1.113.0 `npm.yml` reproduces with it. Gitleaks `npm-access-token` matches the shape without a checksum. |
| `pypi-AgEIcHlwaS5vcmc` and 70 characters | PyPI, [API tokens](https://pypi.org/help/#apitoken); the fixed part encodes `pypi.org` | Inside the Gitleaks `pypi-upload-token` length range. |
| `SG.`, 22 characters, `.`, 43 characters | SendGrid, [API keys](https://docs.sendgrid.com/ui/account-and-settings/api-keys) | Same total length as the Gitleaks `sendgrid-api-token` rule. |
| `shpat_` and 32 hex digits | Shopify, [Admin API authentication](https://shopify.dev/docs/api/admin-rest#authentication) | Same as the Gitleaks `shopify-access-token` rule. |
| `pscale_tkn_` and 32 characters (dense case) | PlanetScale, [API](https://planetscale.com/docs/api) | 32 is the lower bound of the Gitleaks `planetscale-api-token` rule. |
| RSA private key block | RFC 7468 label `RSA PRIVATE KEY` | Random Base64 body, not a valid key. |
| Database URI with a password | RFC 3986 user information | No Gitleaks default rule. |
| `api_key = '...'` with 40 characters | Generic assignment | Targets generic rules in every tool. |

Hard negatives follow public formats: UUID version 4 (RFC 9562),
Subresource Integrity `sha512-` strings (W3C), Go module `h1:` checksums,
and the `EXAMPLE` suffix of the AWS documentation key.

### Dense findings and long lines

After Kingfisher's dense findings benchmark, five cases at 25, 50, 100,
200 and 400 KB, one file each. Use the time ratio between doublings to find
super-linear cost.

| Case | Shape |
| --- | --- |
| dense-github-pat-lines | One distinct GitHub token shape per line |
| dense-github-pat-single-line | The same tokens separated by spaces on one line |
| dense-generic-single-line | `api_key = '...'` assignments on one line |
| dense-planetscale-pairs | Database ID line followed by a `pscale_tkn_` token line |
| dense-base64-uris | `mysql://user:PASSWORD@db.invalid/test` repeated, then Base64 encoded as one line |

Also `long-line-16mib`, one minified line of 16 MiB with eight planted values,
and `base64-uris-4mib`, the Base64 case at 4 MiB.

### Git history shapes

Built with `git fast-import` and fixed dates. These are `git` mode
workloads.

| ID | Shape |
| --- | --- |
| git-many-branches | 50 trunk commits and 1,000 branches of two commits each; most labels are on branches that HEAD does not reach |
| git-merges | 200 topic branches merged with merge commits; 10 merge commits add a file of their own |
| git-huge-hunk | One commit replaces all 32,768 lines of a file |
| git-many-small-files | One commit changes one line in each of 10,000 files |
| git-renames | 100 pure renames, 50 renames with edits, and one rename among 1,000 modifications |

Labels in Git workloads mark the commit whose change adds the secret. Fields
show scope differences: `reachable_from_head` is false for labels that only
an all-refs scan can see, and `introduced_by: merge` marks values that appear
only in a merge commit's own change. Tools that skip merge diffs, scan only
HEAD, or scan whole blobs rather than patches will differ on these labels by
design.

## Home-fixtures matrix

`matrix` writes every tool's own rule examples as one workload per tool, so
that every tool can be run on every other tool's examples.

| Tool | Source | Pin | License | Cases |
| --- | --- | --- | --- | --- |
| gitleaks | Rule generator true and false positives | `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` | MIT | 6,770 |
| betterleaks | Rule tests in `rules/**/*.go` | v2.0.0-rc.8, `b4b1c4455987636400ce693bd9d8a8e2cf375ed9` | MIT | 2,005 |
| kingfisher | `examples` and `negative_examples` of first-party rules | v2.19.1, `0b57b8122e10050db3cefffde1a555a061e0b280` | Apache-2.0 | 41 |
| kingfisher-v1 | `examples` and `negative_examples` of the 1.x catalog (optional) | v1.113.0, `82d050530cdef9af070b8f9a75701c9c27a948c3` | Apache-2.0 | 2,146 |
| rustleaks | Rule pack test cases in `crates/rustleaks-core/tests/support/` | this repository | MIT | 3,883 |

The licenses were checked in each upstream `LICENSE` file at the pin, and
`matrix` checks them again on every run.

How each source is read:

- Gitleaks draws its true positives at random and runs them only during
  config generation. The cases come from the frozen run in
  `compat/generator-corpus/samples-v1.jsonl`, checked against its digest in
  `compat/test-manifest.toml`. `matrix` also fetches Gitleaks at the pin and
  checks that every sample's rule file exists there.
- Betterleaks tests are Go literals. `matrix` reads string literals joined
  with `+`, package and local constants, composite literals and the
  `rulebuilder` helpers. It skips 155 component-only tests, because a
  component is never reported alone, and 7 tests of rule functions that
  Betterleaks never registers.
- Kingfisher examples are read from the rule YAML files. The reader handles
  plain, quoted and block scalars. Its output was compared with a full YAML
  parser on all 2,187 example values.
- Rustleaks cases are read from this repository.

Each case gets its own folder, `NNNNN-<rule>/`, and keeps its original path
inside it. A leading `/` is dropped. Cases without a path use `input.txt`.
Rules that match on the full path from the scan root may behave differently
because of the case folder.

Cases whose path has a `.git` component, such as `repo/.git/config`, go to a
separate `-dotgit` workload. Only the Rustleaks source has such cases. Report
them as their own row: Rustleaks and Gitleaks skip `.git` in `dir` mode,
while Kingfisher scans it.

Labels for the matrix (the format is in
[Labels](comparison.md#labels)):

- A positive example with a stated secret that occurs in the input gets a
  `secret` label on that exact span (`span: secret`).
- A positive example without a stated secret, or whose secret is decoded,
  gets a `secret` label on the whole case (`span: case`). Gitleaks and
  Kingfisher examples are all of this kind.
- A negative example gets a `not-secret` label on the whole case.
- `expected` gives the home tool's contract: `exact`, `at_least_one`,
  `exactly_one`, `count` or `none`. For `count`, `expected_count` gives the
  number of findings the home tool expects. The scorer uses only
  `exactly_one`, `count` and `none`.
- `fixture_tool`, `fixture_rule`, `fixture_case` and `fixture_origin` name
  the source.

The labels state what each home tool expects of its own rules. They are not
an independent ground truth. A tool without a matching rule is expected to
miss another tool's examples.

The gitleaks and rustleaks workloads are marked `tuned: true`, because
Rustleaks tests replay them. Rustleaks pack rules and the Betterleaks and
Kingfisher catalogs share upstream rule sources; reports must say so.

## Labels

The label format is described in [Labels](comparison.md#labels). Synthetic
labels set `source` to `constructed`, and matrix labels set it to
`fixture`. Synthetic labels come from construction, never from scanner
output. In a synthetic workload every byte outside a `secret` label is
non-secret by construction, so a finding there is a false positive. The
`not-secret` labels mark selected hard negatives so that reports can name
them.

## Verification

`verify` checks a cache before a run:

- Repositories: the only ref is `refs/heads/main` at the pinned commit and
  HEAD matches. The full history is present when `git` mode is required, and
  the commit count matches `fetch.json`. Every file in `tree/` has the Git
  blob ID from the pinned tree, with no extra files. `--deep` adds
  `git fsck`.
- Synthetic workloads: the file list, sizes, SHA-256 digests, label file and
  Git history (HEAD, refs and commit list) match the inventory written at
  generation, and full-scale workloads match `synthetic.json`.
- Matrix workloads: the source commit matches the pin in
  `fixtures-matrix.json`, files and labels match the inventory written by
  `matrix`, and the case and label counts match the manifest.

## Changing the workloads

- Do not change pinned commits or the generator to suit one tool. A change
  starts a new comparison and needs a new held-out set.
- To change synthetic workloads, edit the generator, run
  `cargo xtask compare-workloads generate --cache DIR --write-manifest` at
  full scale, and commit the new `synthetic.json`.
- To update a fixture source, change its pin in `fixtures-matrix.json`, run
  `matrix`, and update the expected counts.
- `cargo xtask compare-workloads self-test` checks the tools offline with tiny
  synthetic data, including a fetch from a local Git repository. Bazel runs it
  through the xtask unit tests.
