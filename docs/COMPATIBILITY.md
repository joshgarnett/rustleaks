# Compatibility profile

The current Rustleaks compatibility profile targets selected library and CLI
behavior from Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. The embedded upstream default
configuration has SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.

The upstream name identifies the backward-compatibility target. It does not
identify Rustleaks as an official release or imply endorsement.

## Supported profile

| Level | Domain | Evidence state |
| --- | --- | --- |
| P0 | Configuration, regular expressions, detection, allowlists, decoding, composite rules, redaction, fingerprints, baselines, ignores, and sessions | Rust regression coverage with historical differential evidence |
| P1 | Readers, files, directories, symlinks, archives, Git, and remote links | Workspace Rust regression coverage with historical differential evidence |
| P2 | CLI precedence, diagnostics, exits, JSON, CSV, JUnit, SARIF, and restricted templates | Workspace Rust regression coverage with historical differential evidence |

Only `rustleaks-core` is in the current public package boundary. P1 and P2 are
repository evidence and do not make the corresponding workspace crates public
packages.

## Base64 decoding modes

`Base64Mode::Compatible` is the default and preserves the pinned decoder
behavior, including printable-ASCII output filtering. The CLI selects it with
`--base64-mode compatible`. `Base64Mode::Extended` (`--base64-mode extended`)
is an explicit Rustleaks extension: accepted candidates can decode to arbitrary
bytes, using standard or URL-safe alphabets with or without padding. Extended
mode rejects noncanonical trailing bits.

Both modes retain candidate discovery and its digit-or-symbol heuristic.
Discovery requires at least 16 alphabet characters and can select substrings
of surrounding input. Neither mode guarantees exhaustive discovery or validates
an entire malformed carrier. Decode depth, source mapping, and scan budgets
continue to apply. Extended results are outside the pinned compatibility
profile; the default preserves historical regression expectations.

## Native and legacy names

Rustleaks provides native `RUSTLEAKS_CONFIG`, `RUSTLEAKS_CONFIG_TOML`,
`.rustleaks.toml`, `.rustleaksignore`, `rustleaks:allow`,
`--rustleaks-ignore-path`, and `--ignore-rustleaks-allow` spellings. Existing
Gitleaks spellings remain accepted for backward compatibility. Native config
sources take precedence when both forms are present. Native and legacy ignore
files are unioned.

Some report schema labels, help details, warning text, config fields, file
names, and historical oracle protocol values retain an upstream spelling when
exact bytes or established automation require it. Each such occurrence is compatibility
data, not Rustleaks branding. The Rustleaks executable name, banner, project
metadata, package names, and primary help text use the Rustleaks name.

## Evidence

The committed gates include:

- 6,770 default-rule helper samples replayed by Rust;
- 3,618 regular-expression requests;
- 112 configuration cases;
- 124 source cases, 34 Git cases, 49 report cases, and 119 CLI variants;
- 283 extracted semantic assertions, of which 115 have direct Rust tests and
  168 have precise non-applicable dispositions;
- six benchmark assertion links and two platform branches with Rust evidence;
- 607 exported upstream API identities, 275 observed test identities, 225 rule
  constructors, and copied fixture manifests; and
- mutation checks that reject pending traceability, missing evidence, stale
  revisions, changed defaults, and identity substitutions.

Findings compare rule identifiers, matches, secrets, locations, source and
commit metadata, entropy bits, tags, required findings, fingerprints,
duplicates, ordering where specified, suppression outcomes, reports, and
structured errors. Normalization is limited to ordering already shown to be
nondeterministic upstream.

The live Go oracle and automatic upstream test/constructor rediscovery are
retired. The accepted revision, default configuration, request/outcome bytes,
Go runtime tokens, generator hashes, copied fixtures and attribution remain
historical provenance. Generated corpus READMEs and manifests describe the
historical generation process; their retired commands are not current operator
instructions. Original generators remain accessible in Git history.

`cargo xtask regression-check` checks frozen artifact integrity, identities,
dispositions and local evidence links, then executes the Rust regression suite.
`cargo xtask qualify` adds complete local Rust release hardening from a clean,
committed candidate. Neither command requires Go or a sibling upstream checkout.
New cases use synthetic inputs with independently reviewed expectations and
negative controls. Current Rust output must never become its own expected
baseline. This policy preserves the selected regression contracts and ends
fresh independent Go comparison; it makes no equivalence claim for unseen inputs.

CLI replay derives the expected current build version from package metadata for
only the three `CLI-BB-001` version outputs and the two `CLI-BB-007` embedded
configuration warnings. It first validates their exact historical fields, then
projects the version-dependent expectations without changing recorded output.
All other fields remain exact. The execution ledger identifies both historical
and current build versions and marks these five expectations explicitly.

The 6,770 helper samples cover 220 rules; negative helper samples cover 82.
The two Dropbox default constructors have no helper samples. Source replay
accounts for all 124 cases with explicit safe and platform dispositions. Git
replay delegates 13 remote cases to SCM tests; report replay delegates 15
template cases to template tests. CLI replay accounts for all 119 variants and
reports executed, platform-inapplicable and native-disposition counts separately.
Archived observations substituted for unavailable host behavior are not counted
as executions. The three valid bootstrap records have Rust regressions;
wrong-protocol is retired adapter behavior, and malformed-regex panic maps to
the supported structured Rust configuration error.

The optional upstream `gore2regex` build tag is outside the profile. The
historical oracle used the standard Go regular-expression implementation from
an ordinary build.
Host-capable template helpers and unsafe panic behavior are replaced with
named, bounded Rust dispositions rather than normalized away.

The public core permits `regex-automata ^0.4.12` and `regex-syntax ^0.8.5` so
applications can unify those maintained dependency lines. Their Unicode tables
include additions after the pinned Go Unicode 15 baseline. Consequently,
Unicode properties and case folding can differ for newly assigned or
reclassified code points; for example, U+105C0 is a letter in the compatible
backend but unassigned in the pinned Go Unicode 15 tables. The accepted
property-name namespace, ASCII behavior, byte spans, and generated lowercase helpers remain
under the existing compatibility boundaries.

## Platforms

The CI workflow (`.github/workflows/ci.yml`) has one native lane for each of
the eight required targets. It runs on every pull request, on every push to
`main`, and weekly. Each lane uses a GitHub-hosted runner with the target's
operating system and architecture:

| Targets | Runner |
| --- | --- |
| `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `aarch64-apple-darwin` | `macos-15` |
| `x86_64-pc-windows-msvc` | `windows-2025` |
| `aarch64-pc-windows-msvc` | `windows-11-arm` |

Each lane checks the host architecture, builds `//:build` for the target
(including the feature-profile library targets), and runs `//:test`. The
`//:test` suite contains every `//:parity` replay target and the CLI tests.
The musl lanes run musl target binaries on the Ubuntu host. Bazel doc tests
are marked incompatible on Windows and musl targets; the Linux GNU and macOS
lanes run them. Each lane keeps its payload-free CLI regression ledger as a workflow
artifact. The workflow's `Required` job fails unless every lane passes.

Other CI jobs run on one host only. `just ci` and the Cargo stable and MSRV
feature-profile checks run on `ubuntu-24.04` (`x86_64`).
`cargo xtask regression-check` runs on `macos-15` (`aarch64`).

Hermetic cross-compilation of the eight targets is compilation evidence only
and is not used to make runtime support claims. The native lanes run the
tests; they do not measure performance or process memory on each platform.
The absence of native evidence is not a compatibility exception.

Run `just parity` for the committed Rust replay. Historical native Go ledgers
remain provenance; new ledgers describe only actual Rust executions and
explicit host limitations.
