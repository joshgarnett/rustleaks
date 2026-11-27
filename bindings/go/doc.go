// Package rustleaks scans bytes for secrets in process with the Rustleaks
// engine, a Rust library that the package calls through a small C ABI.
//
// Build an Engine once with New and reuse it. With no options it uses every
// built-in rule. ScanString and ScanBytes return the findings of one input:
//
//	engine, err := rustleaks.New()
//	if err != nil {
//		return err
//	}
//	defer engine.Close()
//	findings, err := engine.ScanString(ctx, input, rustleaks.WithPath("config/app.env"))
//
// On Linux and macOS the package links the Rust static library with cgo,
// so it needs a C compiler and CGO_ENABLED=1. On Windows it loads the Rust
// DLL with the syscall package and needs neither.
//
// Findings hold secret bytes. Their String, GoString, Format, LogValue and
// MarshalJSON methods leave the secret out. The package does not erase inputs or
// findings from memory.
//
// The user guide is at
// https://github.com/joshgarnett/rustleaks/blob/main/docs/user/go.md.
package rustleaks
