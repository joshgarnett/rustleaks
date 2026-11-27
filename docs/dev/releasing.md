# Releasing

This page is for maintainers. It lists the steps to check and publish a
release. It does not authorize a release. Only `rustleaks-core` is
published to crates.io. The CLI ships as release archives, as `.deb` and
`.rpm` packages for the Linux glibc targets, and through the Homebrew tap
`joshgarnett/homebrew-tap` and the Scoop bucket `joshgarnett/scoop-bucket`.
The Go package is published to `joshgarnett/rustleaks-go`, and the Python
package to PyPI as `rustleaks`. All of them use the release version. The
Python package uses its [PEP 440 form](#python-version).

## Approvals

Each of these actions needs its own maintainer approval: selecting a
version, creating a GitHub release or tag, publishing a crate, pushing to the
tap and bucket, changing a release or trusted publishing setting, and using a
credential. Pushing a commit or tag to `joshgarnett/rustleaks-go` and
uploading to PyPI need their own approval too. A successful local or hosted dry run is not approval. The release
checks need no approval, because they cannot publish, tag or use a registry
token.

Ask with the [approval packet](#approval-packet). Name the exact version,
candidate, dry run ID and external action in the request. Crates.io
publication, the GitHub tag or release, the package manager push, the
`rustleaks-go` push and the PyPI upload are separate actions, and each approval must name the action it covers. An
approval stays valid for that unchanged action while its checks run; do not
ask again. A changed value, a wider scope or a different retry needs new
approval.

## Checklist

### 1. Prepare the candidate

- [ ] The maintainer approved the version.
- [ ] These files name that version:
      - `[workspace.package]` in the root `Cargo.toml`;
      - the `=VERSION` path dependency pins in
        `crates/rustleaks-cli/Cargo.toml`, `crates/rustleaks-eval/Cargo.toml`,
        `crates/rustleaks-ffi/Cargo.toml`, `crates/rustleaks-report/Cargo.toml`
        and `crates/rustleaks-sources/Cargo.toml`;
      - the `module()` version in `MODULE.bazel` and `RUSTLEAKS_VERSION` in
        `bazel/rust_crate.bzl`;
      - `CHANGELOG.md` and the Status section of `README.md`;
      - the install examples in `docs/user/getting-started.md`,
        `docs/user/ci.md`, `docs/user/library.md`, `docs/user/go.md` and
        `docs/user/python.md`;
      - `packageVersion` in `bindings/go/library.go`; and
      - in the [PEP 440 form](#python-version), `RUSTLEAKS_PYTHON_VERSION`
        in `bazel/rust_crate.bzl`, `version` in
        `bindings/python/pyproject.toml` and `__version__` in
        `bindings/python/src/rustleaks/_version.py`.

      `cargo xtask build-system-check`, which `just test` runs, fails when
      `MODULE.bazel`, `RUSTLEAKS_VERSION` or `bindings/go/library.go`
      differs from the Cargo version, or when one of the three Python
      versions differs from its PEP 440 form.
- [ ] The generated files that name the version are regenerated:
      `just deps-repin` (`Cargo.lock` and `cargo-bazel-lock.json`),
      `cargo xtask generate vet-inventory`,
      `cargo xtask release-artifact notices` and
      `bazelisk run //crates/rustleaks-eval:rustleaks_quality -- baseline`
      (`testdata/quality-corpus/baseline-v1.json`).
- [ ] `DEFAULT_CONFIG_SHA256` in `rustleaks-core` and `DEFAULT_RULES_SHA256`
      in `xtask` agree.
- [ ] The candidate is merged to `main`.

### 2. Run the local checks

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
- [ ] `cargo-semver-checks` passes for `rustleaks-core` against the latest
      version on crates.io, and a person reviewed the API change. See the
      [public API README](../../testdata/public-api/README.md).
- [ ] A [scanner comparison](comparison.md) of the previous release with
      this candidate commit shows no unexplained time, memory or finding
      regression. A comparison of an earlier commit does not count.

To compare the two builds, list the previous release archive and an
optimized build of the candidate commit in a private tools manifest (see
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
- [ ] The CodeQL run for the candidate's push to `main` is green.

### 4. Ask for approval

- [ ] Prepare the [approval packet](#approval-packet).
- [ ] Get a separate [approval](#approvals) for the crates.io publication,
      for the GitHub release, for the package manager push, for the
      `rustleaks-go` push and for the PyPI upload.

### 5. Revalidate just before publishing

- [ ] The candidate is still the clean current `main` commit, with the
      approved version.
- [ ] The dry run passed for that commit, and its artifacts have not expired.
- [ ] Every required branch check is still green.
- [ ] The current package is byte-identical to the package kept by the dry
      run.
- [ ] Evidence that can change without a source edit, such as the advisory
      database result, is still fresh.

The release checks are bound to the candidate commit and tree. Reuse a
successful result while the commit, version, lockfiles, workflow definitions,
package bytes and release inputs are unchanged, and do not run the full local
suite again only because the candidate moves from checking to publication.
If any item above fails, or one of those inputs changed, run the affected
checks and a new dry run. The publication workflow repeats the identity, dry
run, artifact retention and package byte checks before it requests a
crates.io credential.

### 6. Publish

- [ ] Dispatch `Publish Crate` with the candidate commit, version and dry run
      ID. See [Publishing the crate](#publishing-the-crate).
- [ ] Dispatch `Publish GitHub Release` from `release.yml` with the same
      values. See [Publishing the GitHub release](#publishing-the-github-release).
- [ ] After its eight verification jobs pass, dispatch
      `Update Package Managers` from `packages.yml` with the version and
      `publish` set. See
      [Updating the package managers](#updating-the-package-managers).
      Skip this item for a pre-release while the tap and bucket hold a
      stable release: a pre-release is not pushed to them.
- [ ] After the GitHub release, with its
      `rustleaks-VERSION-corresponding-source.tar.gz`, is published and while
      `main` is still the candidate, dispatch `Publish Go Module` from
      `publish-go.yml` and `Publish Python Package` from
      `publish-python.yml` with the candidate commit, version and dry run
      ID. Both refuse a version without that release. See
      [Publishing the Go and Python packages](#publishing-the-go-and-python-packages).

### 7. Verify

- [ ] All eight native verification jobs of the release workflow pass.
- [ ] Registry owner and metadata are correct.
- [ ] The downloaded `.crate` matches the expected hash.
- [ ] The external Cargo and Bazel consumers build against the registry
      version.
- [ ] Every GitHub artifact attestation and checksum verifies.
- [ ] Unless the package managers were skipped for a pre-release, the
      Homebrew and Scoop install jobs of `Update Package Managers` pass,
      and its push job updated both repositories.
- [ ] The `verify` job of `Publish Go Module` passes: the Go checksum
      database has the dry run's hashes for all nine modules.
- [ ] `Publish Python Package` found all eight wheels on PyPI with the dry
      run's SHA-256.
- [ ] On a clean machine, `go get github.com/joshgarnett/rustleaks-go@vVERSION`
      and `python -m pip install rustleaks==PYTHON_VERSION`, with the
      [Python version](#python-version), install the release, and a scan
      finds a synthetic key.
- [ ] On a clean machine for each channel, the release installs and
      `rustleaks --version` prints it: Homebrew on macOS and Linux, Scoop on
      Windows, the `.deb` on Debian or Ubuntu and the `.rpm` on Fedora or
      Red Hat Enterprise Linux. Where the previous release came from the
      same channel, upgrading to the new release works.

If anything differs from the approval packet, follow
[Rollback](#rollback).

## Appendix

### Local check details

`cargo fetch --locked` downloads the exact locked registry inputs. The
package and external consumer checks then run offline. The fetch changes no
manifest or lockfile.

[Security checks](security-checks.md) lists what `just ci` and
`just security` run. `just release-dry-run` inspects the package archive, builds clean external
Cargo and Bazel consumers, and runs the locked Cargo publish check without
upload. The package metadata selects docs.rs documentation for all features
with warnings denied; the hosted dry run repeats that and keeps the exact
`.crate` archive and its file list.

`cargo xtask qualify` checks that the candidate tree is clean and committed,
runs the bounded composite resource tests, compares the public API with the
snapshot and builds with the minimum supported Rust version. The other gates
above cover tests, security, fuzzing and packaging.

When to reuse these results is in
[Revalidate just before publishing](#5-revalidate-just-before-publishing).

### Non-publishing release candidate

`Release Dry Run` runs after the candidate is merged to `main`. It does not
use a protected environment. It rejects any commit other than the current
`origin/main`, receives no registry token, and fails if either usual
crates.io token variable is set. The release checks therefore use no
approval that protects a later publication.

The package job and the native matrix run beside acceptance, Rust release
checks, security, extended AddressSanitizer fuzz, and worktree and
history self-scan jobs. The summary accepts the candidate only when every job
passes.

Every native job builds the CLI twice with separate Bazel output roots,
requires byte-identical binaries and bundles, then extracts each archive and
runs help and a redacted scan from the packaged executable. The `release-*`
configurations in `.bazelrc` build with `--compilation_mode=opt` and
`--stamp=no`. The Linux and macOS ones also set
`--@rules_rust//rust/settings:lto=fat` and
`--@rules_rust//rust/settings:codegen_units=1`. These settings make those
binaries 25 to 30 percent smaller and their startup about 10 percent shorter
in instructions. Scan speed stays within 1 percent. The Windows
configurations do not set them, because a macOS or Linux host cannot link
Windows binaries, so only this dry run could prove them. Each job emits:

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

The `bindings` job runs `Binding Packages` (`bindings.yml`). See
[Binding packages](#binding-packages).

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
redistribution requirement stays part of the release checks.

#### Archive verification

The native verifier checks raw tar metadata and the exact expected paths and
sizes before it reads any payload, then hashes payloads in bounded chunks. It
accepts only the emitted gzip format and bounded GNU long paths. Limits are
128 MiB per binary, 256 MiB per decompressed archive, 4,096 regular files and
4,096 bytes per path. The binary size must match the reproducibility proof.

GNU manifests record the highest `GLIBC_X.Y` symbol version found in the
binary. Musl archives must have no ELF interpreter and no dynamic `NEEDED`
entry. `release-artifact prepare` also checks the ELF type of each Linux
binary: the GNU binaries must be PIE (`ET_DYN`) with an interpreter, and the
x86_64 musl binary must be a static PIE. Rust's `aarch64-unknown-linux-musl`
target links a static executable that is not PIE (`ET_EXEC`), so the check
requires only static linking there and accepts either type.

For macOS binaries the same check requires a thin 64-bit Mach-O executable
for the target's CPU with one `LC_UUID` load command. dyld on recent macOS
refuses to start an executable that is linked against a recent SDK and has
no UUID, and the hosted macOS runners do not enforce that, so a binary
without one passes every smoke test there. The hermetic `ld64.lld` derives
the UUID from a hash of the linked output, so the two isolated builds keep
the same UUID and stay byte identical. No build difference is normalized.

The native Linux and macOS CI lanes run the same check,
`release-artifact check-executable`, on their CLI build, and the macOS
release lanes run it on the first build before the smoke test. The bindings
dry run applies the `LC_UUID` check to the installed macOS library.

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

The same source archive covers `librustleaks_ffi.so` in the two
`manylinux_2_28` wheels of the version, which links the glibc
`libc_nonshared.a` members of `io/stat64.c` and `io/fstat64.c`. The
[reconstruction instructions](../../release/corresponding-source/README.md)
also show how to relink that library. The binding publish workflows require
the GitHub release with this archive first (see
[Publishing the Go and Python packages](#publishing-the-go-and-python-packages)).

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
the four Linux packages, a release has 67 public assets. Changed source or
runtime evidence needs new release checks and a new dry run.

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
[Approvals](#approvals) says what the request must name.

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
a GitHub pre-release. For any other version, GitHub decides from the
version and date whether it becomes the latest release, so a fix for an
older release line may not become the latest. It
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
   `main`, that the `vVERSION` tag points at that same commit, and that it
   is a pre-release exactly when the version has a pre-release suffix;
2. downloads the macOS, Linux glibc and Windows archives and verifies their
   signed attestations against `release-dry-run.yml` and `main`. Then
   `cargo xtask release-artifact package-managers` writes
   `Formula/rustleaks.rb` and `bucket/rustleaks.json` with each archive's
   hash. It fails when a hash is not in that target's `SHA256SUMS`;
3. installs the formula from a local tap on macOS Apple silicon, macOS Intel
   and Linux x86_64, and the manifest with Scoop on Windows x86_64 and ARM64.
   Each job requires that the installed binary matches the release manifest
   and runs a redacted scan. Homebrew on Linux ARM64 is not checked here;
4. only when `publish` is set, runs `check-channels` without a credential.
   It clones `main` of both repositories and runs
   `release-artifact check-upgrade` from xtask, which refuses a version
   older than the one in either repository, and a pre-release when the
   repository holds a stable release. It records the commit it checked in
   each repository; and
5. only when `publish` is set and every job above passed, runs the
   `publish` job in the protected `release` environment. This job runs only
   Git, the GitHub CLI and the pinned token action: it checks out no
   Rustleaks code and runs no setup action or Cargo. It clones both
   repositories again and stops unless `main` is still the commit that
   `check-channels` checked. Then it creates
   a one-hour token with `actions/create-github-app-token` from the
   `PACKAGING_APP_ID` variable and `PACKAGING_APP_PRIVATE_KEY` secret,
   limited to contents write on the two repositories, and commits and
   pushes the changed file to `main` of each. The push is not forced, so it
   fails if `main` moved. The two pushes are separate: if the second fails,
   start a new run of the workflow with the same version, which skips the
   repository that is already up to date. Do not use "Re-run failed jobs":
   it reuses the commits that the old `check-channels` recorded, so the
   repository that was already pushed fails the check.

A pre-release pushed to the tap or bucket becomes what `brew install` and
`scoop install` give everyone. So a pre-release is not pushed to a
repository that holds a stable release: `check-upgrade` refuses to write
it, because the Scoop manifest's `checkver: github` follows stable
releases. Since 0.2.0 both repositories hold a stable release, so do not
set `publish` for a pre-release such as `0.3.0-alpha.1`. A run without
`publish` still writes and installs the formula and manifest. A pre-release
can replace a pre-release, and a stable release can replace either. The Go
module and the Python package of a pre-release are published as usual.

### Binding packages

`Binding Packages` builds and checks the Go and Python packages of one
commit. The release dry run and the weekly workflow call it, and it can run
by hand. It publishes nothing and uses no credential. Only the release dry
run sets its `attest` input, which adds a build provenance attestation of
the checksums.

1. On each native lane it builds `//release/native:all` and
   `//release/python:wheel` with the lane's `release-bindings-*` config from
   `.bazelrc`. Those configs are the lane's release settings, with two
   differences: musl lanes build for `//platforms:linux_<cpu>_musl_c`, so the
   shared library links the shared musl libc, and macOS libraries keep their
   Mach-O UUID, because dyld does not load a dylib without one. The Go
   archive leaves out the LLVM bitcode sections that Rust's standard library
   objects carry, because Go refuses a cgo library with bitcode.
2. `cargo xtask bindings finish-wheel` turns the Bazel wheel into the
   release wheel. It adds the target's third-party license texts and
   notices from the native notice catalog (the same files the CLI archive
   of that target carries under `licenses/`) to
   `.dist-info/licenses/third-party/`. The catalog covers the CLI's build
   graph, so the files are a superset of what the library links, and its
   `index.json` describes the CLI binary of that target. It also writes core metadata 2.4 with
   `License-Expression`, `Keywords` and one `License-File` per license file.
3. `cargo xtask bindings go-layout` writes the `rustleaks-go` repository
   from `bindings/go/`, the templates in `release/go/` and the eight
   libraries: the main module, one module per platform under `lib/`, and
   the main module's `go.sum`. Each `lib/<platform>` module holds
   `LICENSE`, `NOTICE` and the target's `licenses/` tree. A Unix module
   keeps its static library in the Go package `native/`, which links it
   with cgo and holds nothing else. Go checks every library-named file
   under a `-L` folder, and the glibc notice `COPYING.LIB` is not a
   library. The folder is a package so that `go mod vendor` copies the
   archive.
   `cargo xtask bindings go-proxy` writes a file-based Go module proxy of
   the nine modules and their `go.sum` lines in `hashes.txt`.
4. The job keeps the layout (`rustleaks-go/`), the proxy (`proxy/`), the
   eight wheels (`wheels/`) and `SHA256SUMS` as the artifact
   `rustleaks-bindings-<version>-packages`. `SHA256SUMS` lists every other
   file of the artifact. When `attest` is set, the job attests `SHA256SUMS`
   with `actions/attest-build-provenance` and keeps the bundle as
   `SHA256SUMS.attestation.jsonl`. The dry run jobs below check every
   checksum and that the artifact holds no file that `SHA256SUMS` does not
   list. The publish workflows also check the attestation. Weekly and
   manual runs make no attestation.
5. On each native lane, `cargo xtask bindings dry-run` builds a Go program
   from that proxy with the Bazel-pinned Go SDK and the lane's C compiler
   (`musl-gcc` with `-tags musl` and static linking on musl, no cgo on
   Windows) and runs a scan. Every `go.sum` line Go records must equal one
   that xtask computed. It then runs `go mod vendor`, builds the program
   again with `-mod=vendor` and no module proxy, and requires the same
   output. On Linux the vendored archive must define `_Unwind_Resume`
   exactly once. Then `release/python/upload.py check` builds the
   PyPI upload form from the wheel and requires every field to be present
   and to match `bindings/python/pyproject.toml`. The dry run installs the
   wheel into a new virtual environment of each of CPython 3.12, 3.13, 3.14
   and 3.15 with `pip --no-index`, compares the installed metadata with
   `pyproject.toml` and runs a scan. Last, it checks the library against its
   wheel tag. On glibc no symbol may be newer than the `manylinux` version.
   On musl the library may need only `libc.so` and must bind at load, so
   loading it under the host's musl 1.2 resolves every symbol. On macOS it
   may need only system libraries, and its deployment target must not be
   newer than the `macosx` version.

The wheel platform tags are `manylinux_2_28` on glibc (the hermetic
toolchain's glibc floor), `musllinux_1_2` on musl, `macosx_14_0` on macOS
(the toolchain's deployment target), `win_amd64` and `win_arm64`.

The license expression of the wheels, in `pyproject.toml` and
`LIBRARY_LICENSE` in `crates/xtask/src/bindings/wheel.rs`, is
`MIT AND BSD-3-Clause AND Apache-2.0 AND Apache-2.0 WITH LLVM-exception`:
`rustleaks-core` is `MIT AND BSD-3-Clause AND Apache-2.0`, every other
linked crate offers MIT, and the Rust standard library and the hermetic
toolchain link LLVM runtime code under `Apache-2.0 WITH LLVM-exception`.
`finish-wheel` fails when the two differ. Review the expression when the
library's dependencies change.

As with the `.deb` and `.rpm` packages, whose `license` field is `MIT`, the
expression names the licenses of the project and of the Rust code and LLVM
runtime that every wheel links. It does not list every term of every
component. The runtime components that the notice catalog lists without an
SPDX expression keep their terms in the wheel's `licenses/` tree, which
`License-File` names. These are the glibc nonshared support on GNU, the
Microsoft C runtime on Windows, and the standard library's bundled
attributions. The GNU wheels' glibc code also has the corresponding source
above.

#### Python version

The Python package, its wheel file names and its PyPI release use the
PEP 440 form of the release version. `cargo xtask bindings python-version
VERSION` prints it, and the xtask checks use the same mapping:

| Release version | Python version |
| --- | --- |
| `X.Y.Z` | `X.Y.Z` |
| `X.Y.Z-alpha.N` | `X.Y.ZaN` |
| `X.Y.Z-beta.N` | `X.Y.ZbN` |
| `X.Y.Z-rc.N` | `X.Y.ZrcN` |

Any other pre-release suffix, and build metadata, has no Python version, and
the checks fail on it. So `0.3.0-alpha.1` is `0.3.0a1` on PyPI and in
`rustleaks-0.3.0a1-py3-none-<platform>.whl`. The native library reports the
release version, and the package compares the PEP 440 form of it with
`__version__`. The Go module, its tags and the GitHub release use the
release version itself, such as `v0.3.0-alpha.1`.

### Publishing the Go and Python packages

Publish the binding packages of a version only after its
[GitHub release](#publishing-the-github-release), while `main` is still the
release commit. Dispatch `Publish Go Module` and `Publish Python Package`
from `main` with the candidate commit, version and dry run ID. Each one
first requires that the candidate is the clean current `main` and that the
binding files name the version. Then it requires that the GitHub release
`vVERSION` is published, holds
`rustleaks-VERSION-corresponding-source.tar.gz`, and that its tag names the
candidate, so a package version always names the released commit. The
release must be a GitHub pre-release exactly when the version has a
pre-release suffix, as `release.yml` creates it. Last, it
requires that the dry run passed for that commit. Then it checks the
`rustleaks-bindings-<version>-packages` artifact as described in
[Binding packages](#binding-packages): the attestation of `SHA256SUMS`
against `bindings.yml` and the candidate commit, every checksum, and the
file set. Neither one builds anything: they publish the dry run's files.

`Publish Go Module` refuses a version that already has a tag in
`joshgarnett/rustleaks-go`, because a published Go version cannot be
replaced. Its `publish` job runs in the protected `release` environment,
with only Git, the GitHub CLI and the pinned token action, as in
[Updating the package managers](#updating-the-package-managers). It
replaces the whole tree of `main` with the layout, or starts `main` with it
in an empty repository. It commits the layout as the
`rustleaks-packaging` App, and pushes the commit, the `vVERSION` tag and the
eight `lib/<platform>/vVERSION` tags in one atomic push. The `verify` job then
waits for the Go checksum database and compares its hashes for all nine
modules with the dry run's `hashes.txt`. The README and CONTRIBUTING files
of `rustleaks-go` come from `release/go/`; they say that the repository is a
published copy and that issues and pull requests go to this repository.

The first Go publication also needs:

- `joshgarnett/rustleaks-go` to exist and to be public. It may be empty, with
  no branch and no tag. Then the check job records an empty head. The
  publish job starts a new repository with `main` as its branch and commits
  the layout. It checks that `rustleaks-go` still has no refs, then creates
  `main` and every tag in the one atomic push. When `rustleaks-go` has a `main`,
  the workflow clones it and pushes a fast-forward commit on top of it. A
  repository that has refs but no `main` stops the workflow;
- no tag in `rustleaks-go` that starts with `v` or `lib/`;
- the `rustleaks-packaging` App installed on `rustleaks-go` with contents
  write, and the `PACKAGING_APP_ID` variable and `PACKAGING_APP_PRIVATE_KEY`
  secret in the `release` environment; and
- no branch protection on `rustleaks-go` `main` that rejects the App's push.

To withdraw a bad Go version, add a `retract` directive to
`bindings/go/go.mod`; `go-layout` copies `retract` lines into the published
`go.mod`. Then release a new version.

`Publish Python Package` runs in the protected `release` environment with
`id-token: write`. Its `version` input is the release version, such as
`0.3.0-alpha.1`. It requires that `Cargo.toml` names that version, and takes
the [Python version](#python-version), such as `0.3.0a1`, from
`bindings/python/pyproject.toml` for the wheel file names and the PyPI
release. It exchanges the GitHub identity token for a short-lived
PyPI upload token (PyPI trusted publishing). `release/python/upload.py
upload` then uploads each wheel with every core metadata field of the wheel
in the form, because PyPI creates the release metadata from the first
upload's form and never changes it. The last step checks each file's SHA-256
and the release's `requires_python`, summary and license expression on
PyPI. Before the first upload, the maintainer must register this
repository, the workflow file `publish-python.yml` and the environment
`release` as a trusted publisher of the PyPI project `rustleaks`; that is a
separate approval.

### Rollback

If registry metadata, package contents, checksums, attestations, native smoke
tests or the public API differ from the approval packet:

1. Stop further publication.
2. Remove or quarantine the GitHub release assets. If the package
   managers were updated, revert the commit in `joshgarnett/homebrew-tap`
   and `joshgarnett/scoop-bucket`. A Go version cannot be removed: publish
   a new version whose `go.mod` retracts the bad one. A PyPI release can be
   yanked; a file name can never be uploaded again.
3. Follow the [incident response](incident-response.md) procedure.
4. Yank the crates.io version when new installs would create risk. Yanking
   does not delete the package and does not replace a fixed release, an
   advisory or coordinated disclosure.

Never move a tag or release that points to the wrong tree. Publish a factual
correction only after the incident review and a new explicit approval.
