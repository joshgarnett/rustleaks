# Incident response

This page is for maintainers. Use it for a suspected vulnerability, an
exposed credential, a malicious dependency, a compromised build or release
input, a leaked finding, or an unexplained fuzz, sanitizer, advisory,
provenance or integrity failure.

The private reporting route is described in [`SECURITY.md`](../../SECURITY.md).
Never send vulnerability details to a public issue.

## 1. Receive and preserve

- Move non-public details to the private reporting route. Do not copy a
  credential, exploit, crash artifact or private repository content into a
  public issue, chat, CI log or commit message.
- Record who received the report and when, the affected versions or commits,
  the observed behavior, the environment, and the source of each artifact.
- Keep the smallest necessary evidence in storage with access control. Hash
  artifacts before analysis and work on copies. Do not collect unrelated user
  or repository data.
- Answer within the response times in the [security
  policy](../../SECURITY.md#reporting).

## 2. Triage and contain

- Assign one incident coordinator and a separate technical reviewer.
- Classify the impact on confidentiality, integrity, availability, the
  supply chain and releases. Find out whether a reported secret is synthetic,
  expired or live.
- Pause package publication, releases, dependency updates, and affected CI or
  cache paths until their integrity is understood.
- Revoke and rotate affected credentials through their provider. Never test a
  suspected credential by using it. Review provider audit logs through an
  approved private channel.
- If a dependency or build input is suspect, freeze the exact lockfiles,
  checksums, toolchains, artifacts, logs and provenance of affected builds.
  Turn off the input without destroying evidence.

## 3. Reproduce privately

- Reproduce in a clean temporary environment with synthetic data and the
  exact source revision, lockfiles, features, target, toolchain and command.
- Keep raw output private. Reduce a live credential to a synthetic value that
  does not work before you add a regression test.
- Find the first affected and the first fixed versions or commits. Check all
  public crates, features, source adapters, reporters, CLI paths, build rules,
  workflows, artifacts and targets that share the boundary.
- For a fuzz or sanitizer failure, keep the engine, target, seed, dictionary,
  corpus, options and sanitizer output before you minimize it.

## 4. Fix and verify

- Develop the smallest complete fix on a private branch or advisory fork.
- Add an ordinary deterministic regression test, and any property, fuzz,
  resource, corpus or negative-control test that is needed. A behavior
  change must be explicit and reviewed.
- In a clean checkout, run the affected tests, `just security`,
  `just fuzz-smoke`, `just ci`, the package checks and the native target
  checks. Get a technical review from someone other than the author of the fix.
- Rebuild release artifacts from trusted inputs. Reconcile the source,
  lockfiles, Bazel graph, SBOM, checksums and attestations before publication
  starts again.

## 5. Coordinate disclosure and recovery

- Prepare a GitHub Security Advisory when available. Request a CVE through
  the advisory when the issue needs one.
- Coordinate with RustSec when a Rust package is affected. Give factual
  affected ranges, patched versions, severity reasoning, mitigations, and
  credits agreed with the reporter.
- Yank affected crates.io versions when new installs would create risk.
  Yanking does not delete a version and does not replace a patched release or
  an advisory.
- Tell known downstream users through the least public channel available,
  without credentials or unneeded exploit detail.
- Restore CI, caches, release permissions and publication only after the
  coordinator and the independent reviewer confirm containment and the
  checks.

## 6. Review

- Record the timeline, root cause, affected scope, detection gap,
  containment, evidence, decisions, fixed versions, notifications and
  remaining work.
- Keep confirmed facts apart from assumptions. Correct public statements
  when later evidence changes the assessment.
- Add lasting controls, tests, documentation and ownership, with a dated
  follow-up. Review the [threat model](threat-model.md),
  [dependency policy](dependencies.md), [release process](releasing.md) and
  this procedure.
- Practice this procedure after a major change to reporting, CI, releases or
  ownership.
