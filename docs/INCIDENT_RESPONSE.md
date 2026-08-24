# Security incident response

Use this procedure for a suspected vulnerability, exposed credential,
malicious dependency, compromised build or release input, leaked finding, or
unexplained fuzz, sanitizer, advisory, provenance, or integrity failure.

## 1. Receive and preserve

- Move non-public details to the verified private reporting route. Do not copy
  a credential, exploit, crash artifact, or private repository content into a
  public issue, chat, CI log, or commit message.
- Record who received the report, when it was received, affected versions or
  commits, observed behavior, environment, and the source of each artifact.
- Preserve the smallest necessary evidence in access-controlled storage. Hash
  artifacts before analysis and work from copies. Do not collect unrelated
  user or repository data.
- Acknowledge a private report within three business days and provide an
  initial assessment within seven business days when a private route exists.

## 2. Triage and contain

- Assign one incident coordinator and a separate technical reviewer.
- Classify confidentiality, integrity, availability, supply-chain, and release
  impact. Identify whether a reported secret is synthetic, expired, or live.
- Suspend package publication, releases, dependency updates, and affected CI
  or cache paths until their integrity is understood.
- Revoke and rotate affected credentials through their provider. Do not test a
  suspected credential by using it. Review provider audit logs through an
  approved private channel.
- If a dependency or build input is suspect, freeze the exact lockfiles,
  checksums, toolchains, artifacts, logs, and provenance used by affected
  builds. Disable the input without destroying evidence.

## 3. Reproduce privately

- Reproduce in a clean temporary environment with synthetic data and the exact
  source revision, lockfiles, feature set, target, toolchain, and command.
- Keep raw output private. Reduce a live credential to a nonfunctional
  synthetic reproducer before adding a regression.
- Determine the first affected and first fixed versions or commits. Check all
  public crates, features, source adapters, reporters, CLI paths, build rules,
  workflows, artifacts, and supported targets that share the boundary.
- For a fuzz or sanitizer failure, preserve the engine, target, seed,
  dictionary, corpus, options, and sanitizer diagnostics before minimization.

## 4. Fix and verify

- Develop the smallest complete fix on a private branch or advisory fork.
- Add an ordinary deterministic regression and any needed property, fuzz,
  resource, parity, or negative-control test. A compatibility difference must
  be explicit and reviewed.
- Run the affected targeted tests, `just security`, `just fuzz-smoke`,
  `just ci`, package checks, and supported native target evidence in a clean
  checkout. The CI gate includes committed corpora and parity. Use
  `cargo xtask parity --all` when compatibility behavior or fresh Go evidence
  changed. Obtain a technical review independent of the fix author.
- Rebuild release artifacts from trusted inputs. Reconcile source, lockfiles,
  Bazel graph, SBOM, checksums, and attestations before restoring publication.

## 5. Coordinate disclosure and recovery

- Prepare a GitHub Security Advisory when available. Request a CVE through the
  advisory process when the issue warrants one.
- Coordinate with RustSec for an affected Rust package or ecosystem boundary.
  Provide factual affected ranges, patched versions, severity reasoning,
  mitigations, and credits agreed with the reporter.
- Yank affected crates.io versions when continued installation creates risk.
  Yanking is not deletion and does not replace a patched release or advisory.
- Notify known downstream users through the least public channel available,
  without disclosing credentials or unnecessary exploit detail.
- Restore CI, caches, release permissions, and publication only after the
  incident coordinator and independent reviewer verify containment and gates.

## 6. Factual review

- Record the timeline, root cause, affected scope, detection gap, containment,
  evidence, decisions, fixed versions, notifications, and remaining work.
- Separate confirmed facts from assumptions. Correct public statements when
  later evidence changes the assessment.
- Add durable controls, tests, documentation, ownership, and a dated follow-up.
  Revisit the threat model, dependency policy, release design, and this
  procedure.
- Exercise this procedure before the first public release and after a material
  reporting, CI, release, or ownership change.

The verified private intake endpoint is documented in `SECURITY.md`. Do not
send vulnerability details to a public issue. Setup verified that the route is
enabled without submitting a live report. Exercise the reporting and response
procedure before the first public release.
