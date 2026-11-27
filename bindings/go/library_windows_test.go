//go:build windows && (amd64 || arm64)

package rustleaks

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// TestEmbeddedDLLLoads extracts the DLL that Bazel built, as the release
// generator embeds it, and loads the extracted copy with its hash check.
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
	handle, procs, err := loadDLL(extracted, lib.dllSHA256)
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

func TestLoadDLLChecksTheHash(t *testing.T) {
	path, err := testLibraryPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDLL(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("a DLL with the wrong hash was loaded")
	}
}

func TestLoadDLLRejectsARelativePath(t *testing.T) {
	if _, _, err := loadDLL("rustleaks_ffi.dll", ""); err == nil {
		t.Fatal("a relative DLL path was loaded")
	}
}

// While the loader holds the file, no one can write, rename or delete it.
func TestOpenShareReadBlocksChanges(t *testing.T) {
	path := filepath.Join(cacheRoot(t), "library.dll")
	if err := os.WriteFile(path, []byte("library"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openShareRead(path)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Error("the file opened for writing while the loader held it")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Error("the file was renamed while the loader held it")
	}
	if err := os.Remove(path); err == nil {
		t.Error("the file was removed while the loader held it")
	}
	if other, err := os.Open(path); err != nil {
		t.Errorf("the file cannot be read while the loader holds it: %v", err)
	} else {
		other.Close()
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("the file cannot be removed after the loader closed it: %v", err)
	}
}
