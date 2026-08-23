# Updating the pinned upstream

An upstream update is one reviewed transaction. Do not replace the accepted
baseline in place before the candidate diff passes review.

1. Authorize one candidate Gitleaks commit and record its exact revision and
   default-configuration hash.
2. Create an isolated, read-only sibling checkout for that revision. Preserve
   the currently accepted checkout and corpus until the candidate is approved.
3. Update every checked revision/config mirror together; the manifest gate
   must reject a mixed identity.
4. Refresh copied fixtures without changing bytes, modes, symlinks, or license
   provenance.
5. Regenerate API, test, assertion, constructor, benchmark, fixture, and Git
   intention inventories.
6. Generate every differential corpus into a new temporary directory using
   fresh bounded processes. Never overwrite the accepted corpus before review.
7. Review every delta and classify it as exact behavior, a named safe Rust
   disposition, an explicitly deferred profile item, or a defect. Unclassified
   changes fail the update.
8. Re-run owned-unsafe, dependency policy, MSRV, package normalization, public
   API, fuzz replay, resource/performance, target compilation, and complete
   parity gates.
9. Obtain independent compatibility and idiomatic Rust/API reviews on the
   integrated candidate.
10. Record the final revision, config and artifact hashes, counts, tool
    versions, host limitations, and commit. Commit subjects must state the
    shipped behavior and stand on their own.

Native Linux/Windows runtime evidence should be refreshed on matching hosts
when available, but its absence remains a visible nonblocking follow-up. Never
substitute cross-compilation for native runtime results.
