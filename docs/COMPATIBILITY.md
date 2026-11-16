# Compatibility profile

The pinned Gitleaks revision is commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. The embedded upstream default
configuration has SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.

The upstream name identifies the backward-compatibility target. It does not
identify Rustleaks as an official release or imply endorsement.

## Compatibility policy

Rustleaks is an independent secret scanner that stays backward compatible with
Gitleaks at the pinned revision. Compatibility covers these points:

- Gitleaks configuration files load and mean the same thing.
- The same input and configuration produce the same findings, including rule
  ID, match, secret, file, line and column, commit metadata and fingerprints.
- Ignore files, baselines and allow comments keep working.
- Gitleaks commands, flags, environment variables and file names (such as
  `.gitleaks.toml` and `.gitleaksignore`) that Rustleaks supports keep working.
- Exit codes do not change.
- Error classes and output streams do not change: each error keeps its class,
  and each kind of output goes to the same stream.
- JSON, CSV, JUnit, SARIF and template reports keep their field names, types
  and meanings.

Rustleaks owns help text, usage and error wording, the banner, log and summary
lines, other diagnostic output, and the order of JSON keys and CSV columns, and
may change them. A change to presentation needs an updated test expectation
that a reviewer checks against the stated intent, recorded as a presentation
disposition when it replaces frozen CLI evidence. Changing a compatibility
guarantee needs maintainer approval, a changelog entry and tests that show the
new behavior.

## Supported profile

| Level | Domain | Evidence state |
| --- | --- | --- |
| P0 | Configuration, regular expressions, detection, allowlists, decoding, composite rules, redaction, fingerprints, baselines, ignores, and sessions | Rust regression coverage with historical differential evidence |
| P1 | Readers, files, directories, symlinks, archives, Git, and remote links | Workspace Rust regression coverage with historical differential evidence |
| P2 | CLI commands and flags, precedence, exits, error classes, output streams, JSON, CSV, JUnit, SARIF, and restricted templates | Workspace Rust regression coverage with historical differential evidence |

Help, usage, error wording and other diagnostic text are presentation, not
part of the profile.

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

Config fields, file names, environment variables, report field names and some
report values keep an upstream spelling where existing configurations,
automation or report consumers depend on it. Historical evidence also keeps
upstream names. Each such occurrence is compatibility data, not Rustleaks
branding. The Rustleaks executable name, banner, project metadata, package
names, and primary help text use the Rustleaks name.

### Report tool name

SARIF and JUnit reports name the tool `gitleaks`: the SARIF driver `name` and
the JUnit `testsuite` `name`. The SARIF driver `semanticVersion` is the fixed
value `v8.0.0`. These values stay the same so that existing SARIF consumers,
such as GitHub code scanning, see the same tool name.

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

Regression tests compare these functional fields exactly: rule identifiers,
matches, secrets, locations, source and commit metadata, entropy bits, tags,
required findings, fingerprints, duplicates, ordering where specified,
suppression outcomes, report fields and values, exit status, and error
classes. Normalization is limited to ordering already shown to be
nondeterministic upstream. Presentation text, such as help, usage and error
wording, must also match its expected text, which a reviewed presentation
disposition can replace.

Report corpus tests compare exact report bytes, and CLI replay compares
findings as compact JSON text. JSON key order and CSV column order are
presentation under the policy, but these tests still pin them. Changing that
order first needs a reviewed change to the report and findings comparisons so
that they compare parsed fields. A presentation disposition alone cannot
cover it.

The live Go oracle and automatic upstream test/constructor rediscovery are
retired. The accepted revision, default configuration, request/outcome bytes,
Go runtime tokens, generator hashes, copied fixtures and attribution remain
historical provenance. Generated corpus READMEs and manifests describe the
historical generation process; their retired commands are not current operator
instructions. Original generators remain accessible in Git history.

`cargo xtask regression-check` checks frozen artifact integrity, identities,
dispositions and local evidence links, then executes the Rust regression suite.
`cargo xtask qualify` adds complete local Rust release hardening from a clean,
committed candidate. Neither command requires Go or a sibling upstream
checkout. New cases use synthetic inputs with independently reviewed
expectations and negative controls. For functional fields, current Rust output
must never become its own expected baseline. For presentation, a reviewer
checks the new text against the stated intent of the change before it becomes
the expected text. This policy keeps the selected regression contracts and runs
no new Go comparison; it makes no equivalence claim for unseen inputs.

CLI replay derives the expected current build version from package metadata
only for the three `CLI-BB-001` version outputs. It first checks their exact
historical fields, then expects the current build version. The two `CLI-BB-007`
embedded configuration variants recorded a minimum version warning, because
the historical build compared the config `minVersion` with its own crate
version. Rustleaks now compares `minVersion` with the implemented Gitleaks
version, 8.30.0, so the warning is not printed. The replay checks the exact
historical warning, which is event 0, and then expects it to be absent. All
other fields remain exact unless a presentation disposition replaces them. The
execution ledger names the historical and current build versions and marks
these five expectations explicitly.

## Presentation dispositions

`compat/presentation-dispositions.toml` holds reviewed presentation changes for
the frozen CLI corpus. Each entry names:

- an `id` for the entry;
- a corpus variant, written as `<case id>/<variant id>`, for example
  `CLI-BB-018/following-positional`;
- one presentation field: `stdout`, `stderr_usage`, or the message of one
  stderr event (`stderr_event_message` with an `event` index). A `stdout`
  entry is allowed only for help output;
- the SHA-256 of the frozen value that it replaces;
- the exact new expected text; and
- the reason for the change.

Expected text is normalized like the replay output for that field:

- stderr event message: the log level and timestamp prefix are removed, the
  text is trimmed, the temporary root becomes `<TMP>`, durations become
  `<DURATION>`, operating system not-found errors become `<os:not-found>`, and
  `exit code:` is written as `exit status:`;
- `stderr_usage`: the block from the `Usage:` line up to the first log line,
  with trailing whitespace trimmed and one final line feed; versioned lines are
  kept; and
- `stdout`: ANSI color codes are removed, and the temporary root becomes
  `<TMP>`.

All fields use the name `rustleaks`. On Windows, only the first path separator
after `<TMP>` is normalized, so avoid nested paths in message dispositions.

The CLI replay requires the new text exactly. A `stderr_usage` entry replaces
the whole usage block, including the stderr events that the block's lines
produce, so the new block may have a different number of lines. Events before
and after the block stay pinned. The replay still compares exit status,
findings, reports, error class, severity, child process cleanup and disclosure
checks with the frozen evidence. A disposition for any of those functional
fields is rejected, and a disposition that no replay uses fails the check.
Message dispositions on the two `CLI-BB-007` embedded configuration variants
use frozen event indices. Event 0 of those variants is the removed warning and
takes no disposition.

The replay computes the error class of an event from its message text with a
keyword classifier, and its severity from the log level token. New wording
must still produce the same class. Log lines keep their level token, and the
usage block keeps its `Usage:` header. A change to the classifier is reviewed
as a functional change.

The same file holds `behavior_supersession` rows for behavior records that no
longer apply as written. `CLI-DEFER-001`, which kept help and parser usage
bytes exact, is superseded. `CLI-009` is narrowed: stream routing, error class
and non-disclosure still apply, and message wording is presentation. The
frozen corpora, `compat/behavior-matrix.toml` and `compat/test-manifest.toml`
do not change and remain historical records.

Before the replay compares output with a frozen value, it rewrites the
executable name `rustleaks` to `gitleaks` and the name `Rustleaks` to
`Gitleaks`. Expected text from a disposition is compared without that rewrite,
so it uses the Rustleaks name.

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
Missing native evidence does not create an exception to the compatibility
policy.

Run `just parity` for the committed Rust replay. Historical native Go ledgers
remain provenance; new ledgers describe only actual Rust executions and
explicit host limitations.
