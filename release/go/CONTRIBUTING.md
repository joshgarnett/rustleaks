# Contributing

This repository is a published copy. The Rustleaks release workflow writes
every file in it, so a change made here is lost at the next release.

Open issues and pull requests in
[joshgarnett/rustleaks](https://github.com/joshgarnett/rustleaks), and follow
its [CONTRIBUTING.md](https://github.com/joshgarnett/rustleaks/blob/main/CONTRIBUTING.md).

- The Go code is in `bindings/go/` there.
- The native library is the `crates/rustleaks-ffi` crate there. Each `lib/`
  module here holds the library that the release built for one platform.
- The files under `lib/` and the `library_*.go` files here are generated
  from `release/go/` there.

To build and test the Go package from a checkout of joshgarnett/rustleaks,
install Bazelisk and Just and run:

```sh
just test-go
```

Bazel downloads the pinned Go SDK and builds the native library for your
system. You do not need a separate Go or Rust installation.
