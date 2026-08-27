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
| P0 | Configuration, regular expressions, detection, allowlists, decoding, composite rules, redaction, fingerprints, baselines, ignores, and sessions | Implemented and differentially tested |
| P1 | Readers, files, directories, symlinks, archives, Git, and remote links | Implemented in workspace crates and differentially tested |
| P2 | CLI precedence, diagnostics, exits, JSON, CSV, JUnit, SARIF, and restricted templates | Implemented in workspace crates and differentially tested |

Only `rustleaks-core` is in the current public package boundary. P1 and P2 are
repository evidence and do not make the corresponding workspace crates public
packages.

## Native and legacy names

Rustleaks provides native `RUSTLEAKS_CONFIG`, `RUSTLEAKS_CONFIG_TOML`,
`.rustleaks.toml`, `.rustleaksignore`, `rustleaks:allow`,
`--rustleaks-ignore-path`, and `--ignore-rustleaks-allow` spellings. Existing
Gitleaks spellings remain accepted for backward compatibility. Native config
sources take precedence when both forms are present. Native and legacy ignore
files are unioned.

Some report schema labels, help details, warning text, config fields, file
names, and oracle protocol values retain an upstream spelling when exact bytes
or established automation require it. Each such occurrence is compatibility
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

The optional upstream `gore2regex` build tag is outside the profile. The oracle
uses the standard Go regular-expression implementation from an ordinary build.
Host-capable template helpers and unsafe panic behavior are replaced with
named, bounded Rust dispositions rather than normalized away.

The public core permits `regex-automata ^0.4.12` and `regex-syntax ^0.8.5` so
applications can unify those maintained dependency lines. Their Unicode tables
include additions after the pinned Go Unicode 15 baseline. Consequently,
Unicode properties and case folding can differ for newly assigned or
reclassified code points; for example, U+105C0 is a letter in the compatible
backend but unassigned in the pinned oracle. The accepted property-name
namespace, ASCII behavior, byte spans, and generated lowercase helpers remain
under the existing compatibility boundaries.

## Platforms

Native GitHub Actions runtime evidence covers `x86_64` and `aarch64` for Linux
GNU, Linux musl, macOS, and Windows MSVC. Each native lane builds the maintained
Bazel graph, feature profiles, and all platform-compatible first-party tests.
The Linux musl lanes exclude only stable-channel Bazel doctest runners because
rules_rust 0.72.0 generates invalid runfiles paths for their LLVM link inputs;
the authoritative Linux GNU gate runs those same doctests. Complete local
evidence also covers `aarch64-apple-darwin`. Hermetic cross-compilation remains
compilation evidence only and is not used to make runtime support claims. The
absence of native evidence is not a compatibility exception.

Run `just parity` for the committed replay. The pinned sibling checkout is
required separately when regenerating or performing the complete differential
oracle validation.
