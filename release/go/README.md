# rustleaks-go

This repository holds the published Go module
`github.com/joshgarnett/rustleaks-go`, version {{version}}. It is a copy that
the Rustleaks release workflow writes. Do not open issues or pull requests
here. The code lives in [`bindings/go/`](https://github.com/joshgarnett/rustleaks/tree/main/bindings/go)
of [joshgarnett/rustleaks](https://github.com/joshgarnett/rustleaks), and
issues and pull requests go there. See [CONTRIBUTING.md](CONTRIBUTING.md).

The package scans bytes and text for secrets with the Rustleaks engine, in
your process. The [Go guide](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/go.md)
explains the API, the options and the defaults.

## Install

```sh
go get github.com/joshgarnett/rustleaks-go@v{{version}}
```

Each platform's native library is in its own module under `lib/`. A build
downloads only the module for its platform, but `go mod tidy` and
`go mod vendor` download all of them.

| Platform | Module | Needs |
| --- | --- | --- |
| Linux x86_64 and ARM64, glibc | `lib/linux-amd64`, `lib/linux-arm64` | cgo and a C compiler |
| Linux x86_64 and ARM64, musl | `lib/linux-amd64-musl`, `lib/linux-arm64-musl` | cgo, a musl C compiler and `-tags musl` |
| macOS x86_64 and ARM64 | `lib/darwin-amd64`, `lib/darwin-arm64` | cgo and a C compiler |
| Windows x86_64 and ARM64 | `lib/windows-amd64`, `lib/windows-arm64` | Nothing: the package loads an embedded DLL without cgo |

On musl, for example on Alpine Linux with `musl-dev` installed:

```sh
go build -tags musl ./...
```

On Linux and macOS a build with `CGO_ENABLED=0` fails with an error that
names the cause.

## License

MIT. See the `LICENSE` and `NOTICE` files. Each `lib/` module carries
the same two files.
