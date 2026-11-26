//go:build !cgo && !windows

package rustleaks

// On Linux and macOS the package links the Rust static library with cgo. A
// build without cgo stops here instead of producing a package that cannot
// scan. Build with CGO_ENABLED=1 and a C compiler.
var _ = rustleaks_needs_cgo_on_linux_and_macos_set_CGO_ENABLED_1
