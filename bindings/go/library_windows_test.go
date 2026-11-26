//go:build windows

package rustleaks

import (
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// TestEmbeddedDLLLoads extracts the DLL that Bazel built, as the release
// generator embeds it, and loads the extracted copy.
func TestEmbeddedDLLLoads(t *testing.T) {
	path, err := testLibraryPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lib := fakeLibrary(t, data)
	lib.version = packageVersion
	extracted, err := extractLibrary(cacheRoot(t), lib)
	if err != nil {
		t.Fatal(err)
	}
	handle, procs, err := loadDLL(extracted)
	if err != nil {
		t.Fatal(err)
	}
	// Free this second copy so that the test can remove its folder. The
	// package itself never unloads the DLL.
	defer syscall.FreeLibrary(handle)
	var abi uint32
	result, _, _ := syscall.SyscallN(procs.abiVersion, uintptr(unsafe.Pointer(&abi)))
	if int32(uint32(result)) != statusOK || abi != abiVersion {
		t.Fatalf("rustleaks_abi_version: status %d, ABI %d", int32(uint32(result)), abi)
	}
}

func TestLoadDLLRejectsARelativePath(t *testing.T) {
	if _, _, err := loadDLL("rustleaks_ffi.dll"); err == nil {
		t.Fatal("a relative DLL path was loaded")
	}
}
