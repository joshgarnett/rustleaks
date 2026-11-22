# Releasing

This page is for maintainers. It lists the steps to qualify and publish a
release. It does not authorize a release. Only `rustleaks-core` is
published to crates.io. The CLI ships as release archives, as `.deb` and
`.rpm` packages for the Linux glibc targets, and through the Homebrew tap
`joshgarnett/homebrew-tap` and the Scoop bucket `joshgarnett/scoop-bucket`.

Each of these actions needs its own maintainer approval: selecting a
version, creating a GitHub release or tag, publishing a crate, pushing to the
tap and bucket, changing a release or trusted publishing setting, and using a
credential. A successful local or hosted dry
run is not approval.

## Checklist

### 1. Prepare the candidate

- [ ] The maintainer approved the version.
- [ ] The workspace manifests and `CHANGELOG.md` name that version.
- [ ] `RUSTLEAKS_VERSION` in `bazel/rust_crate.bzl` and the install examples
      in `docs/user/getting-started.md`, `docs/user/ci.md` and
      `docs/user/library.md` name that version.
- [ ] `DEFAULT_CONFIG_SHA256` in `rustleaks-core` and `DEFAULT_RULES_SHA256`
      in `xtask` agree.
- [ ] The candidate is merged to `main`.

### 2. Qualify locally

From a clean clone of the candidate commit:

```sh
cargo fetch --locked
just ci
just security
just fuzz-smoke
just release-dry-run
```

- [ ] All commands pass.
- [ ] `cargo xtask qualify` passes on the clean, committed candidate.
- [ ] `cargo-semver-checks` passes for each public crate and feature
      profile against the latest version on crates.io, and a person reviewed
      the API change. See the
      [public API README](../../testdata/public-api/README.md).
- [ ] The [scanner comparison](comparison.md) of the previous release with
      the candidate shows no unexplained time, memory or finding regression.

To compare the two builds, list the previous release archive and an
optimized build of the candidate in a private tools manifest (see
[Tools manifest](comparison.md#tools-manifest)), then run on a quiet host:

```sh
just compare run --tools TOOLS --lanes defaults \
  --workloads benchmarks/comparison/workloads/synthetic.json \
  --workloads benchmarks/comparison/quality/labeled.json \
  --cache-root CACHE --output PRIVATE_RUN --baseline PREVIOUS_ID
```

`CACHE` holds the generated workloads (see
[Comparison workloads](comparison-workloads.md) and
[Comparison quality inputs](comparison-quality.md)). The defaults are the
quick settings: 1 warmup and 3 measured runs per cell.
Read `report.md` in the run folder for time and memory ratios and for
finding counts that changed.

### 3. Run the hosted dry run

- [ ] Dispatch `Release Dry Run` with the full 40-character candidate commit
      and the version.
- [ ] Every job passes. See
      [Non-publishing release candidate](#non-publishing-release-candidate).
- [ ] The independently scheduled CodeQL result for the commit is green.

### 4. Ask for approval

- [ ] Prepare the [approval packet](#approval-packet).
- [ ] Get a separate approval for the crates.io publication, for the
      GitHub release and for the package manager push.

### 5. Revalidate just before publishing

- [ ] The candidate is still the clean current `main` commit, with the
      approved version.
- [ ] The dry run passed for that commit, and its artifacts have not expired.
- [ ] Every required branch check is still green.
- [ ] The current package is byte-identical to the package kept by the dry
      run.
- [ ] Evidence that can change without a source edit, such as the advisory
      database result, is still fresh.

If any of these fail, or the candidate, version, workflow, package bytes or
release inputs changed, run a new dry run. The publication workflow repeats
the identity, dry run, artifact retention and package byte checks before it
requests a crates.io credential.

### 6. Publish

- [ ] Dispatch `Publish Crate` with the candidate commit, version and dry run
      ID. See [Publishing the crate](#publishing-the-crate).
- [ ] Dispatch `Publish GitHub Release` from `release.yml` with the same
      values. See [Publishing the GitHub release](#publishing-the-github-release).
- [ ] After its eight verification jobs pass, dispatch
      `Update Package Managers` from `packages.yml` with the version and
      `publish` set. See
      [Updating the package managers](#updating-the-package-managers).

### 7. Verify

- [ ] All eight native verification jobs of the release workflow pass.
- [ ] Registry owner and metadata are correct.
- [ ] The downloaded `.crate` matches the expected hash.
- [ ] The external Cargo and Bazel consumers build against the registry
      version.
- [ ] Every GitHub artifact attestation and checksum verifies.
- [ ] The Homebrew and Scoop install jobs of `Update Package Managers`
      pass, and its push job updated both repositories.
- [ ] On a clean machine for each channel, the release installs and
      `rustleaks --version` prints it: Homebrew on macOS and Linux, Scoop on
      Windows, the `.deb` on Debian or Ubuntu and the `.rpm` on Fedora or
      Red Hat Enterprise Linux. Where the previous release came from the
      same channel, upgrading to the new release works.

If anything differs from the approval packet, follow
[Rollback](#rollback).

## Appendix

### Local qualification details

`cargo fetch --locked` downloads the exact locked registry inputs. The
package and external consumer checks then run offline. The fetch changes no
manifest or lockfile.

`just ci` covers prose and links, Rustdoc, all first-party tests (including
the corpus tests and the CLI corpus replay), and compile checks for the eight declared targets.
`just release-dry-run` inspects the package archive, builds clean external
Cargo and Bazel consumers, and runs the locked Cargo publish check without
upload. The package metadata selects docs.rs documentation for all features
with warnings denied; the hosted dry run repeats that and keeps the exact
`.crate` archive and its file list.

`cargo xtask qualify` checks that the candidate tree is clean and committed,
runs the bounded composite resource tests, compares the public API with the
snapshot and builds with the minimum supported Rust version. The other gates
above cover tests, security, fuzzing and packaging.

Qualification is bound to the candidate commit and tree. Reuse a successful
result while the commit, version, lockfiles, workflow definitions and release
inputs are unchanged. Do not run the full local suite again only because the
candidate moves from qualification to publication. A changed candidate or
release input needs new qualification for the affected part.

### Non-publishing release candidate

`Release Dry Run` runs after the candidate is merged to `main`. It does not
use a protected environment. It rejects any commit other than the current
`origin/main`, receives no registry token, and fails if either usual
crates.io token variable is set. Qualification therefore uses no approval
that protects a later publication.

The package job and the native matrix run beside acceptance, Rust
qualification, security, extended AddressSanitizer fuzz, and worktree and
history self-scan jobs. The summary accepts the candidate only when every job
passes.

Every native job builds the CLI twice with separate Bazel output roots,
requires byte-identical binaries and bundles, then extracts each archive and
runs help and a redacted scan from the packaged executable. Each job emits:

- `rustleaks-<version>-<target>.tar.gz`;
- `SHA256SUMS` for the archive, SBOM and provenance predicate;
- a CycloneDX 1.6 SBOM for the target, with registry checksums and a
  reconciliation of the Cargo and Bazel graphs;
- an unsigned SLSA v1 dry-run provenance predicate;
- a signed GitHub SLSA provenance attestation for the archive, verified
  against the exact `main` commit and release workflow;
- a reproducibility proof and a release manifest; and
- on the two glibc targets, a `.deb` and an `.rpm` package. See
  [Linux packages](#linux-packages).

The source package is built twice into separate Cargo target folders,
compared byte for byte, and gets the same signed provenance check.

#### Licenses and notices

Every native archive has a `licenses/` tree with a target-specific
`index.json`. It covers the release build graph, including the CLI root and
build and proc-macro inputs. It does not claim that every listed package is
linked at runtime. Reviewed runtime groups record their source identities and
targets. The root `LICENSE` and `NOTICE` keep their project meaning.

The notice sources are in `release/notice-inputs/`. The generated catalog and
notice copies are in `release/licenses/`. Regenerate and check them with:

```sh
cargo xtask release-artifact notices
cargo xtask release-artifact notices --check
```

Generation reads all eight target-filtered Cargo graphs and the
checksum-verified locked `.crate` archives from the local Cargo cache. It
keeps nested notices and license alternatives, and rejects missing texts,
stale source supplements, unsafe paths and incomplete runtime mappings. It
uses the current workspace bytes, including uncommitted edits; preparation
uses the candidate's Git blobs. Source supplements have their own version,
archive checksum, VCS pin and file digest. Preparation and verification never
download notices.

CI and release acceptance run `notices --check` after downloading the locked
archives. Preparation matches package coverage with the selected Cargo and
Bazel graph and collects each package's documents again. Verification reads
the candidate's committed catalog, runtime inputs and notice bytes, matches
SBOM coverage, and requires the archive's file set, bytes, order and modes to
match. The release manifest records the notice index digest and the
component and document counts. Notice files are inside the archive and
covered by its checksums and attestation.

Notice collection is attribution evidence only. Any other source or
redistribution requirement stays part of release qualification.

#### Archive verification

The native verifier checks raw tar metadata and the exact expected paths and
sizes before it reads any payload, then hashes payloads in bounded chunks. It
accepts only the emitted gzip format and bounded GNU long paths. Limits are
128 MiB per binary, 256 MiB per decompressed archive, 4,096 regular files and
4,096 bytes per path. The binary size must match the reproducibility proof.

GNU manifests record the highest `GLIBC_X.Y` symbol version found in the
binary. Musl archives must have no ELF interpreter and no dynamic `NEEDED`
entry. macOS builds leave out the nondeterministic Mach-O UUID before the
linker adds any ad-hoc signature. No other difference is normalized.

#### Linux packages

The two glibc lanes build `rustleaks-<version>-<target>.deb` and `.rpm`
with Bazel `rules_pkg` (`//release/linux-packages`). The packages hold the
archive's bytes and nothing else:

1. `cargo xtask release-artifact package-input BUNDLE release/linux-packages/input`
   verifies the bundle and writes the archive's binary, its documents and
   the Debian `Depends` value (`libc6 (>= X.Y)` from the measured glibc
   baseline) into the gitignored input folder.
2. Bazel builds both packages from that folder. The `.rpm` uses the host
   `rpmbuild` with stripping, debug packages, build-ID links and other
   post-install changes turned off, a fixed build host and time 0.
3. `cargo xtask release-artifact add-packages BUNDLE DEB RPM` reads both
   packages and requires that they install exactly the archive's binary at
   `/usr/bin/rustleaks` and its documents under `/usr/share/doc/rustleaks`,
   owned by root, with fixed modes, the release version and architecture,
   and no maintainer scripts. It then adds them to `SHA256SUMS`, the
   provenance subjects and the manifest.

Each Bazel root packages its own bundle, so the bundle comparison also
proves both packages reproducible. The lane then installs, runs and removes
the `.deb` on Debian 10 and the `.rpm` on AlmaLinux 8, which have glibc 2.28,
and checks that the installed binary matches the archive. The signed
attestation covers the archive and both packages. `release-artifact verify`
repeats the content check on a downloaded bundle.

A package version is the release version with `~` in place of `-`, so that
a pre-release sorts before its release.

#### Windows runtime providers

Each Windows lane uses fresh Bazel roots, rejects stale linker maps, and
captures linker maps and library search traces for the CLI. The collector
finds the configured CLI Rustc action and linker, checks the output against
the selected binary, and matches the map's image hash, image base and entry
point. Each native library must have one observed provider path that matches
the reviewed MSVC and SDK identities and file hashes. A missing, changed,
extra or ambiguous provider stops packaging.

Hosted runners update MSVC on their own schedule. The linker's toolset may be
the reviewed version or a newer toolset with the same major version, from the
same Visual Studio edition and major version. For a newer toolset, each MSVC
file must have the reviewed path and role under the new toolset folder, and
the collector records its actual hash and size instead of the pinned values.
Windows SDK files stay pinned. An older toolset, a different major version or
a different set of files stops packaging. Review the Microsoft terms again
when Visual Studio or the MSVC major version changes.

Provider identities are bound into the signed notice index and the release
manifest. The raw Windows evidence is kept as
`runtime-provider-evidence-<target>-<candidate>`, next to the nine releasable
bundles. It is not one of the 67 public release assets. Public verification
checks the portable evidence without a Microsoft toolchain.

#### GNU corresponding source

GNU bundles also contain `rustleaks-<version>-corresponding-source.tar.gz`
and `source-relink.json`. The source archive holds the application source and
the pinned glibc sources, patches, generated headers and build recipes. Each
GNU lane builds from that source, checks that its binary matches the release
binary, changes the startup code, rebuilds and runs a smoke test. Packaging
fails if this proof is missing or does not match.

The signed notice index of the native archive binds the source archive and
`source-relink.json`. The manifest, checksum file and provenance repeat those
bindings. The
[reconstruction instructions](../../release/corresponding-source/README.md)
describe the materials.

Source download is an explicit, pinned `release-artifact fetch-source` step
before offline preparation. Source preparation and public verification never
download replacement inputs. The two GNU lanes must produce the same source
archive. Public verification on GNU targets downloads the source archive and
relink proof and checks their bindings before it extracts or runs the
executable. Publication keeps one source archive and both relink proofs. With
the four Linux packages, a release has 67 public assets. Changed source or runtime evidence needs a new qualification
and dry run.

### Approval packet

Before any external action, present:

- the exact version, commit and tree;
- the packages, artifacts and archive contents;
- native target evidence and command results;
- the public API comparison;
- compatibility and security risks;
- checksums, SBOM reconciliation and provenance; and
- the requested external actions, and the rollback or yank plan.

Stop if a required check is missing, failing, pending, stale or unexplained.

Name the exact version, candidate, dry run ID and external action in the
request. An approval stays valid for that unchanged action while its checks
run; do not ask again. A changed value, a wider scope or a different retry
needs new approval. Crates.io publication and the GitHub tag or release are
separate actions, and each approval must name the action it covers.
Qualification needs no approval, because it cannot publish, tag or use a
registry token.

### Publishing the crate

Dispatch `Publish Crate` from `main` with the candidate commit, version and
`Release Dry Run` run ID. The workflow checks that the candidate is the
current `main`, downloads the kept source package, requires byte-identical
package bytes, and publishes with crates.io Trusted Publishing in the
protected `release` environment. It installs only the pinned Rust toolchain.

The trusted publisher for `rustleaks-core` is:

- repository owner `joshgarnett`;
- repository `rustleaks`;
- workflow `publish.yml`; and
- environment `release`.

Only the publication job gets `id-token: write`. It gets a temporary token
through the official crates.io action and reads no registry secret. Its post
step revokes the token. Never store a registry token in the repository,
workflow configuration, artifacts or logs, and never add a long-lived token
as a fallback.

Cargo adds `.cargo_vcs_info.json` to a package built from a Git worktree. A
squash merge therefore changes the package bytes and checksum even when the
source is the same. The package built from the final `main` commit is the
release package; a branch package does not replace it.

### Publishing the GitHub release

For an approved `<version>`, the tag is `v<version>` and the release name is
`Rustleaks <version>`. Dispatch `Publish GitHub Release` from `release.yml`
with the same candidate, version and dry run ID. Its protected `release` job
downloads all nine kept artifacts, checks package and native checksums,
manifests, SBOMs, provenance and attestations again, then creates the
release. A version with a pre-release suffix, such as `0.2.0-rc.1`, becomes
a GitHub pre-release. Any other version becomes the latest release, even
when a higher version exists. Publish a fix for an older release line only
after deciding which release should be the latest. It
attaches the source package evidence and the evidence for all eight targets.
It does not rebuild anything.

Afterwards the workflow runs a read-only verification on all eight native
targets. Each job downloads its seven public assets, and on the glibc
targets also the source materials and both packages, and restores the
original bundle file names. It checks the version, candidate and target, and
verifies checksums, archive and package contents, SBOM and provenance
bindings and the signed attestation. Only then does it run the published CLI
for help and a redacted scan, and on the glibc targets installs and removes
the `.deb`. It does not rebuild the CLI or ask for another approval. All
eight jobs must pass.

If a verification job fails, the release and tag may already exist. Find the
cause and rerun only the failed verification jobs when a retry makes sense.
Do not rerun the publication job, recreate the tag or replace public assets
as an automatic fix.

### Updating the package managers

Dispatch `Update Package Managers` from `packages.yml` on `main` with the
published version. Leave `publish` unset to check a release without
changing anything; set it, after approval, to push. The workflow:

1. requires that `vVERSION` is a published release whose commit is on
   `main`, and that it is a pre-release exactly when the version has a
   pre-release suffix;
2. downloads the macOS, Linux glibc and Windows archives and verifies their
   signed attestations against `release-dry-run.yml` and `main`. Then
   `cargo xtask release-artifact package-managers` writes
   `Formula/rustleaks.rb` and `bucket/rustleaks.json` with each archive's
   hash. It fails when a hash is not in that target's `SHA256SUMS`;
3. installs the formula from a local tap on macOS Apple silicon, macOS Intel
   and Linux x86_64, and the manifest with Scoop on Windows x86_64 and ARM64.
   Each job requires that the installed binary matches the release manifest
   and runs a redacted scan. Homebrew on Linux ARM64 is not checked here; and
4. only when `publish` is set and every install job passed, runs the
   `publish` job in the protected `release` environment. It creates a
   one-hour token with `actions/create-github-app-token` from the
   `PACKAGING_APP_ID` variable and `PACKAGING_APP_PRIVATE_KEY` secret,
   limited to contents write on the two repositories. It refuses a version
   older than the one in either repository
   (`cargo xtask release-artifact check-upgrade`), then commits and pushes
   the changed file to `main` of each. The xtask build and both clones run
   before the token exists. The two pushes are separate: if the second
   fails, rerun the workflow with the same version, which skips the
   repository that is already up to date.

A pre-release pushed to the tap or bucket becomes what `brew install` and
`scoop install` give everyone. Push one only to test a channel, and push the
next release soon after.

### Rollback

If registry metadata, package contents, checksums, attestations, native smoke
tests or the public API differ from the approval packet:

1. Stop further publication.
2. Remove or quarantine the GitHub release assets. If the package
   managers were updated, revert the commit in `joshgarnett/homebrew-tap`
   and `joshgarnett/scoop-bucket`.
3. Follow the [incident response](incident-response.md) procedure.
4. Yank the crates.io version when new installs would create risk. Yanking
   does not delete the package and does not replace a fixed release, an
   advisory or coordinated disclosure.

Never move a tag or release that points to the wrong tree. Publish a factual
correction only after the incident review and a new explicit approval.
