# Updating the accepted upstream baseline

The live Go oracle and automatic upstream rediscovery are retired. The accepted
Gitleaks revision, copied default configuration, historical observations and
fixture provenance remain the current baseline. Existing generator commands in
historical corpora describe the retired import process.

An upstream import requires an approved candidate revision and an explicit
import and qualification plan. Do not overwrite the frozen baseline or infer
that current Rust replay verifies a different upstream revision.

1. Record the candidate commit and default-configuration hash. Review the
   actual upstream range for rule, config, regex, detector, source, report,
   CLI, test, fixture and license changes.
2. Specify the behavior to adopt and its independently reviewable expected
   results. Decide how candidate evidence will be obtained and retained before
   editing accepted inputs. Reintroducing external executable tooling or
   dependencies requires the applicable review and authorization.
3. Preserve the existing historical observations. Version new evidence
   separately, retaining exact source and generator provenance. Never derive
   expected results solely from the current Rust implementation.
4. Update the approved revision/config mirrors and new evidence bindings as
   one transaction. Preserve copied bytes, modes, symlink targets, hashes,
   licenses and NOTICE attribution. Use reviewed deterministic tooling for
   generated changes; do not hand-edit historical outcomes or inventories.
5. Classify every behavior difference as exact supported behavior, a named safe
   Rust disposition, an approved profile exclusion, or a defect. Retain explicit
   executable tests and negative controls; do not normalize away differences.
6. Run `cargo xtask regression-check`, `just ci`, `just security`, and complete
   `cargo xtask qualify` from a clean, committed candidate. Qualification covers
   package/external consumers, Miri, fuzz and performance checks. Refresh the
   matching native target evidence; cross-compilation is compilation evidence.
7. Obtain independent compatibility and Rust/API review. Record final source
   identities, artifact hashes, case counts, commands, results and remaining
   host limitations. Pending native or required hosted checks are not passes.

This process does not authorize publication or changes to repository settings.
