# Offline validator source review

Disposition: historical-layout validation is implemented; checksum results
remain `Unknown`. No checksum implementation or suppression is selected.

Review date: 2026-11-06. Scope: the historical 40-byte `ghp_` personal access
token layout only. No token is generated through a provider or used against a
provider. Test inputs are synthetic.

GitHub's [2021 format announcement](https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/)
identifies the prefix and explains that token lengths can change. Its
[format article](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
describes a 32-bit CRC32 encoded into six trailing Base62 characters, padded
with zeros. The issuer's current
[authentication reference](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github)
continues to distinguish `ghp_` classic tokens from `github_pat_` fine-grained
tokens and documents a newer stateless installation-token format. The pilot
therefore does not generalize a historic layout across GitHub token prefixes.

These issuer documents do not fully specify the checksum input bytes, CRC32
variant, or Base62 alphabet ordering. An independently invented combination
would not justify an asserted-valid or asserted-invalid provider decision.
`NativeExtension::GithubClassicPatV1` consequently reports layout and checksum
as separate checks. The pure `validation::github_classic_pat` helper returns
both source-omitting results. An exact `ghp_` prefix and 40-byte candidate with
36 ASCII alphanumeric body bytes has a `Valid` historical layout. Within that
exact prefix/length scope, a non-alphanumeric body is `Invalid` for the layout
check. Other lengths and prefixes are `Unknown`, including truncations, legacy
hexadecimal values, fine-grained PATs and newer installation formats. These
statements describe the historical layout, not a token's validity or safety.
Engine annotations also require a known isolated capture boundary; a prefix
captured from a longer token receives `Unknown/AmbiguousBoundary`. The public
helper accepts a complete candidate supplied by its caller.
Checksum remains `Unknown` with `UnspecifiedChecksumContract` for an in-scope
candidate and `UnsupportedFormat` for other candidates.

The implementation performs no CRC computation and makes no checksum validity
claim. This implements bounded historical-layout validation and records a
checksum discovery limitation; it is not completed checksum verification.
A checksum implementation requires a reproducible issuer contract or reviewed
issuer vectors that resolve all three parameters, independent synthetic positive and mutated negative vectors, and
an updated policy/extension identity. Findings must remain visible afterward:
a checksum result alone cannot establish activation or security relevance.

Tests compare findings and legacy serialization with the channel disabled and
enabled, preserve unknown findings, exclude source sentinel strings from logs,
and cap retention across many matches and decoded input. Independent layout
cases include a synthetic positive, a non-ASCII byte, a forbidden underscore,
truncation, an extended length, old hexadecimal and newer prefixed formats.
Per-scan diagnostic capacity also bounds annotation work; zero capacity performs
no offline checks.

Local integrated tests, exact API validation, packaging, external Cargo/Bazel
consumers and the historical full pinned-Go differential passed for their
identified candidate. Current Rust-owned qualification and hosted delivery are
recorded separately in the [roadmap](../ROADMAP.md#current-local-validation) and
[completion record](process-cpu-and-completion.md). Those checks validate the
implemented layout contract and unchanged findings; they establish no checksum
or activation validity.
