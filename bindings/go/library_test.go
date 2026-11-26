package rustleaks

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"
)

func TestChooseLibraryOrder(t *testing.T) {
	set := filepath.Join(t.TempDir(), "set.dll")
	env := filepath.Join(t.TempDir(), "env.dll")
	embedded := &embeddedDLL{version: "0.2.0"}

	if path, lib, err := chooseLibrary(set, env, embedded); err != nil || path != set || lib != nil {
		t.Errorf("SetLibraryPath first: %q %v %v", path, lib, err)
	}
	if path, lib, err := chooseLibrary("", env, embedded); err != nil || path != env || lib != nil {
		t.Errorf("environment second: %q %v %v", path, lib, err)
	}
	if path, lib, err := chooseLibrary("", "", embedded); err != nil || path != "" || lib != embedded {
		t.Errorf("embedded library third: %q %v %v", path, lib, err)
	}
	var libErr *LibraryError
	if _, _, err := chooseLibrary("", "", nil); !errors.As(err, &libErr) {
		t.Errorf("no source: %v, want *LibraryError", err)
	}
	if _, _, err := chooseLibrary("", "relative.dll", embedded); !errors.As(err, &libErr) {
		t.Errorf("relative environment path: %v, want *LibraryError", err)
	}
}

func TestSetLibraryPathAfterLoad(t *testing.T) {
	// An engine loads the library.
	e := markerEngine(t)
	_ = e
	err := SetLibraryPath(filepath.Join(t.TempDir(), "other.dll"))
	if runtime.GOOS != "windows" {
		if err != nil {
			t.Fatalf("SetLibraryPath on %s: %v, want nil", runtime.GOOS, err)
		}
		return
	}
	var libErr *LibraryError
	if !errors.As(err, &libErr) {
		t.Fatalf("SetLibraryPath after load: %v, want *LibraryError", err)
	}
}

func TestLibraryMatchesThePackage(t *testing.T) {
	if err := ensureLibrary(); err != nil {
		t.Fatal(err)
	}
	if err := checkLibraryIdentity(); err != nil {
		t.Fatal(err)
	}
}

func TestNoEmbeddedLibraryInThisRepository(t *testing.T) {
	if embeddedLibrary != nil {
		t.Fatal("embeddedLibrary is set; only the release generator sets it")
	}
}
