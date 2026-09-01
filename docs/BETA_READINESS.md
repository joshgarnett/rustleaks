# Beta readiness

Status: assessed 2026-08-31 against `main` at
`fa7196d5da9306df95c6c0163207d010fc7c096c` before release preparation.

Rustleaks treats beta as a project stabilization decision. Semantic Versioning
defines prerelease ordering but does not define alpha or beta quality. A beta
candidate requires every criterion below. A missing or ambiguous durable
maintainer intent is false, not an invitation to infer a beta decision.

| Criterion | Current evidence | Result |
| --- | --- | --- |
| Public package boundary | Cargo metadata and the build-system contract declare only `rustleaks-core` publishable. Workspace source, report, CLI, compatibility, and codec crates remain `publish = false`. | Pass |
| Durable beta intent and stable design | No durable maintainer statement currently says the core API is entering beta stabilization. | Fail |
| SemVer comparison with published alpha.3 | Required for an exact beta candidate. It is not used to override the failed intent criterion. | Pending |
| Intended public API snapshot | The maintained public API snapshot remains the repository baseline. Exact candidate validation is required during qualification. | Pending |
| Core cargo-vet coverage | The generated inventory reports no exemption in the publishable core normal or build graph. The remaining workspace exemption is outside that graph, but still prevents the repository-wide cargo-vet workstream from being complete. | Pass for beta criterion |
| Rust 1.88 and stable profiles | Required exact-candidate gates have not yet run for the selected next version. | Pending |
| External Cargo and Bazel consumers | Required exact-candidate `just package-check` evidence has not yet run. | Pending |
| Pinned compatibility identity | The Gitleaks commit remains `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`; the default configuration SHA-256 remains `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`. | Pass |
| Local candidate gates | `just ci`, `just security`, `just fuzz-smoke`, and `just release-dry-run` are required after the selected version is committed. | Pending |
| Hosted candidate gates | Native targets, CodeQL, required checks, and the exact hosted release dry run are required after merge. | Pending |
| No applicable blocker | Repository-wide cargo-vet exemptions remain and exact candidate qualification is not complete. No beta conclusion can be inferred. | Not proven |
| Documentation and metadata agreement | Version and changelog synchronization belongs to release preparation. | Pending |

## Packaged-core comparison

The published `rustleaks-core 0.1.0-alpha.3` archive was compared with a
package generated from the stated `main` commit. The comparison excluded only
`.cargo_vcs_info.json` and did not normalize any other file.

- published normalized tree SHA-256:
  `add18be98f76274cfb8411b77b427eb4f07175a277f1773189d5a921bb605447`;
- current normalized tree SHA-256:
  `f2f949aac32e87d954643829c14880df9354c56af64d7437f5855b3eaff360b6`;
- changed packaged file: `src/regex/mod.rs`; and
- change: bound the estimated PikeVM search working set before cache
  allocation and return a structured compile error when the bound is exceeded.

The normalized package content changed. Because beta intent is absent, the
approved version rule selects `0.1.0-alpha.4`, not `0.1.0-beta.1`. Candidate
qualification is required after the version and changelog are updated and the
change is merged. Live crates.io publication and GitHub release creation remain
separate exact-approval actions.
