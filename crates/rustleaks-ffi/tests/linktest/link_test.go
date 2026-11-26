//go:build !windows

// Package linktest checks that a Go program can link the Rustleaks static
// library next to another Rust static library built by the same Rust
// version.
package linktest

/*
#include <stdint.h>

// From crates/rustleaks-ffi/include/rustleaks.h.
int32_t rustleaks_abi_version(uint32_t *out);

uint64_t other_rust_answer(void);
*/
import "C"

import "testing"

func TestBothRustLibrariesLink(t *testing.T) {
	var abi C.uint32_t
	if status := C.rustleaks_abi_version(&abi); status != 0 {
		t.Fatalf("rustleaks_abi_version returned %d", status)
	}
	if abi == 0 {
		t.Fatal("rustleaks_abi_version wrote 0")
	}
	if got := C.other_rust_answer(); got != 42 {
		t.Fatalf("other_rust_answer() = %d, want 42", got)
	}
}
