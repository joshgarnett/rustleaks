# GNU corresponding source and relinking

The `rustleaks-VERSION-corresponding-source.tar.gz` release asset is the
source archive for the two GNU Linux executables. It holds the application
source, and the glibc source and build inputs that the executables use.

The signed native archive records the SHA-256 digest of the source archive
in `corresponding_source` in `licenses/index.json`. Before you extract the
source archive, verify the GitHub attestation of the native archive and
check that digest. The release also keeps the relink proof for each GNU
target.

## Contents and provenance

`application.tar` is `git archive --format=tar` of the exact release
candidate. It holds the CLI, the source adapters, the rest of the workspace
source, licenses, the Cargo and Bazel lockfiles and the build definitions,
with Git file modes and symbolic links. The published core crate does not
contain this application source.

`inputs/` holds the upstream archives below, unchanged. They keep their
license files, copyright notices, file modes and symbolic links.
`manifest.json` lists the original URL and the digest of each one.

| Material | Identity and use |
| --- | --- |
| glibc source | 2.28, commit `92d25389c255b0da9b56bc05694f0702cd22921a`, including startup and nonshared support source and `COPYING.LIB` |
| Hermetic LLVM Bazel module | 0.8.11, complete module source with glibc build definitions, helper rules, compiler defines, copied support source and notices |
| BCR module patch | Exact `module_dot_bazel_version.patch` applied to LLVM 0.8.11 by the Bazel Central Registry |
| Generated glibc headers | Exact x86_64 and AArch64 GNU 2.28 header archives selected by the module's header index |

The glibc patches are part of the supplied LLVM module. Apply them in order,
with one leading path component stripped:

1. `0001-Add-empty-config.h.patch` supplies the empty `include/config.h`.
2. `0002-Add-abi-tag.h.patch` supplies the Linux ABI tag header.
3. `0003-Adding-libc-modules.h.patch` supplies the module definitions header.

The module's `3rd_party/libc/glibc/glibc.BUILD.bazel` sets the compiler
defines that a `config.h` from `configure` would set. It also selects copied
support source, such as `csu/abi-note-2.31.S`. The whole module is included,
because the glibc build needs its helper definitions, runtime rules and
source notices. The glibc source archive alone does not have them.

`crates/xtask/src/release_artifact/corresponding_source.rs` generates
`manifest.json`. The manifest names the candidate, the original inputs, the
selected build files, the patches in order, and the SHA-256 digest and mode
of every member of the source archive except itself. The signed native
archive records the digest of the whole source archive, so the manifest
does not need to contain its own digest.

## Reconstruct and substitute glibc startup source

Use a native Linux x86_64 or AArch64 host with the tools named in the
application's `.bazelversion`, `rust-toolchain.toml` and setup documentation.
These steps change no toolchain or dependency version. Bazel downloads the
other dependencies and build tools from the supplied lockfiles. This archive
is not an offline copy of every dependency or operating system component.

The example below assumes that you extracted the verified source archive to
`/tmp/rustleaks-corresponding-source` and that `/tmp/rustleaks-relink` does
not exist yet. These commands extract the application and library sources
and apply the release patches:

```sh
mkdir -p /tmp/rustleaks-relink/application
tar -xf /tmp/rustleaks-corresponding-source/application.tar -C /tmp/rustleaks-relink/application
tar -xzf /tmp/rustleaks-corresponding-source/inputs/92d25389c255b0da9b56bc05694f0702cd22921a.tar.gz -C /tmp/rustleaks-relink
tar -xzf /tmp/rustleaks-corresponding-source/inputs/hermetic-llvm-v0.8.11.tar.gz -C /tmp/rustleaks-relink
git -C /tmp/rustleaks-relink/hermetic-llvm-0.8.11 apply --no-index -p1 /tmp/rustleaks-corresponding-source/inputs/module_dot_bazel_version.patch
git -C /tmp/rustleaks-relink/glibc-92d25389c255b0da9b56bc05694f0702cd22921a apply --no-index -p1 /tmp/rustleaks-relink/hermetic-llvm-0.8.11/3rd_party/libc/glibc/0001-Add-empty-config.h.patch /tmp/rustleaks-relink/hermetic-llvm-0.8.11/3rd_party/libc/glibc/0002-Add-abi-tag.h.patch /tmp/rustleaks-relink/hermetic-llvm-0.8.11/3rd_party/libc/glibc/0003-Adding-libc-modules.h.patch
cp /tmp/rustleaks-relink/hermetic-llvm-0.8.11/3rd_party/libc/glibc/glibc.BUILD.bazel /tmp/rustleaks-relink/glibc-92d25389c255b0da9b56bc05694f0702cd22921a/BUILD.bazel
touch /tmp/rustleaks-relink/glibc-92d25389c255b0da9b56bc05694f0702cd22921a/REPO.bazel
```

For x86_64, edit
`/tmp/rustleaks-relink/glibc-92d25389c255b0da9b56bc05694f0702cd22921a/sysdeps/x86_64/start.S`.
For example, insert sixteen `nop` instruction lines right after
`ENTRY (_start)`. This change does not affect the ABI, and the release proof
uses it. Keep the copyright header and the other startup instructions.

Build and relink with the supplied module and the changed library source:

```sh
cd /tmp/rustleaks-relink/application
bazelisk --output_user_root=/tmp/rustleaks-relink/bazel build --config=release-linux-x86_64-gnu --distdir=/tmp/rustleaks-corresponding-source/inputs --override_repository=llvm+=/tmp/rustleaks-relink/hermetic-llvm-0.8.11 --override_repository=llvm++glibc+glibc_x86_64-linux-gnu.2.28=/tmp/rustleaks-relink/glibc-92d25389c255b0da9b56bc05694f0702cd22921a //crates/rustleaks-cli:rustleaks
/tmp/rustleaks-relink/application/bazel-bin/crates/rustleaks-cli/rustleaks --help
/tmp/rustleaks-relink/application/bazel-bin/crates/rustleaks-cli/rustleaks --version
```

For AArch64, edit `sysdeps/aarch64/start.S` directly after `_start:` and use
the native AArch64 build command:

```sh
cd /tmp/rustleaks-relink/application
bazelisk --output_user_root=/tmp/rustleaks-relink/bazel build --config=release-linux-aarch64-gnu --distdir=/tmp/rustleaks-corresponding-source/inputs --override_repository=llvm+=/tmp/rustleaks-relink/hermetic-llvm-0.8.11 --override_repository=llvm++glibc+glibc_aarch64-linux-gnu.2.28=/tmp/rustleaks-relink/glibc-92d25389c255b0da9b56bc05694f0702cd22921a //crates/rustleaks-cli:rustleaks
/tmp/rustleaks-relink/application/bazel-bin/crates/rustleaks-cli/rustleaks --help
/tmp/rustleaks-relink/application/bazel-bin/crates/rustleaks-cli/rustleaks --version
```

The repository overrides replace the startup and nonshared compile inputs.
The generated headers and linker rules stay the same. The application is
rebuilt from source, so no separate application object files are needed.
You can make other ABI-compatible changes to the supplied glibc source or the
module's support source with the same overrides.

## Maintainer generation and proof

`cargo xtask release-artifact fetch-source REPOSITORY_CACHE` downloads the
five fixed inputs and checks their SHA-256 digests.
`prepare-source REPOSITORY_CACHE COMMIT OUTPUT` reads only those cached
inputs and the Git blobs of the candidate. It fails when an input is missing
or changed, and it never downloads. Both GNU native jobs build the same
archive bytes, each in its own folder.

`cargo xtask release-artifact relink-source ARCHIVE COMMIT TARGET WORK PROOF`
needs a native GNU Linux host for the target and a new work folder. It
checks the archive against the candidate before it extracts it. Then it runs
the steps above twice: once unchanged, and once with sixteen `nop`
instructions at the glibc startup entry. It checks that the ELF entry of the
changed executable holds those instruction bytes, that the entry of the
unchanged executable does not, and that `--help` and `--version` work for
both. Release preparation also requires the SHA-256 of the unchanged
executable to equal the native release binary.

The proof holds the candidate, the target, the source archive digest, the
original and changed startup digests, the binary digests, the instruction
marker and the `--help` and `--version` results. It holds no local paths or
timestamps. The release keeps the proof and records it in the signed native
archive. Building the source archive alone does not show that the proof
passed.
