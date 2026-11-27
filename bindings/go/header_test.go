package rustleaks

import (
	"bytes"
	"os"
	"testing"
)

// The package compiles against its own copy of the C header, so that the
// published module builds without this repository. The copy must equal the
// header of the library.
func TestHeaderCopyMatchesLibraryHeader(t *testing.T) {
	library, err := os.ReadFile(repoFile(t, "crates/rustleaks-ffi/include/rustleaks.h"))
	if err != nil {
		t.Fatal(err)
	}
	local, err := os.ReadFile(repoFile(t, "bindings/go/rustleaks.h"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(local, library) {
		t.Fatal("bindings/go/rustleaks.h differs from crates/rustleaks-ffi/include/rustleaks.h; copy it again")
	}
}
