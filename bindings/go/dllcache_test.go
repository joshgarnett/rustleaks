package rustleaks

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The extraction tests use fake library bytes. Loading a real DLL is tested
// on Windows in library_windows_test.go.

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func fakeLibrary(t testing.TB, data []byte) *embeddedDLL {
	t.Helper()
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &embeddedDLL{
		version:    "0.2.0",
		dllSHA256:  sha256Hex(data),
		gzipSHA256: sha256Hex(compressed.Bytes()),
		gzipped:    compressed.Bytes(),
	}
}

// cacheRoot returns a temporary cache root. Extracted files are read-only,
// so the cleanup makes them writable before removal.
func cacheRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return root
}

func TestExtractLibraryWritesAPrivateReadOnlyFile(t *testing.T) {
	root := cacheRoot(t)
	data := []byte("fake library bytes")
	lib := fakeLibrary(t, data)
	path, err := extractLibrary(root, lib)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "0.2.0-"+lib.dllSHA256[:16], "rustleaks_ffi.dll")
	if path != want {
		t.Fatalf("path %s, want %s", path, want)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("file holds %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("file mode %v is writable", info.Mode())
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && dir.Mode().Perm() != 0o700 {
		t.Errorf("folder mode %v, want 0700", dir.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("the folder holds %d entries, want only the library", len(entries))
	}
}

func TestExtractLibraryReusesAFileWithTheRightHash(t *testing.T) {
	root := cacheRoot(t)
	lib := fakeLibrary(t, []byte("first"))
	path, err := extractLibrary(root, lib)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	again, err := extractLibrary(root, lib)
	if err != nil || again != path {
		t.Fatalf("second extraction %s, %v", again, err)
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("a valid file was written again")
	}
}

func TestExtractLibraryReplacesAChangedFile(t *testing.T) {
	root := cacheRoot(t)
	data := []byte("the real library")
	lib := fakeLibrary(t, data)
	path, err := extractLibrary(root, lib)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed by someone"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := extractLibrary(root, lib)
	if err != nil || again != path {
		t.Fatalf("extraction over a changed file: %s, %v", again, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, data) {
		t.Fatalf("file holds %q after extraction", got)
	}
}

func TestExtractLibraryChecksBothHashes(t *testing.T) {
	root := cacheRoot(t)
	lib := fakeLibrary(t, []byte("library"))

	badCompressed := *lib
	badCompressed.gzipped = append([]byte(nil), lib.gzipped...)
	badCompressed.gzipped[len(badCompressed.gzipped)-1] ^= 0xff
	if _, err := extractLibrary(root, &badCompressed); err == nil {
		t.Error("changed compressed bytes were accepted")
	}

	badExtracted := fakeLibrary(t, []byte("other library"))
	badExtracted.dllSHA256 = lib.dllSHA256
	if _, err := extractLibrary(root, badExtracted); err == nil {
		t.Error("decompressed bytes with the wrong hash were accepted")
	}
	dir := filepath.Join(root, "0.2.0-"+lib.dllSHA256[:16])
	if _, err := os.Stat(filepath.Join(dir, embeddedLibraryName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a library with the wrong hash was written: %v", err)
	}
}

func TestExtractLibraryRejectsBadMetadata(t *testing.T) {
	root := cacheRoot(t)
	for name, change := range map[string]func(*embeddedDLL){
		"version path":  func(l *embeddedDLL) { l.version = "../0.2.0" },
		"dot version":   func(l *embeddedDLL) { l.version = ".." },
		"empty version": func(l *embeddedDLL) { l.version = "" },
		"short hash":    func(l *embeddedDLL) { l.dllSHA256 = "abcd" },
		"not hex":       func(l *embeddedDLL) { l.dllSHA256 = strings.Repeat("z", 64) },
		"not gzip":      func(l *embeddedDLL) { l.gzipped = []byte("plain"); l.gzipSHA256 = sha256Hex(l.gzipped) },
		"gzip hash":     func(l *embeddedDLL) { l.gzipSHA256 = "" },
	} {
		lib := fakeLibrary(t, []byte("library"))
		change(lib)
		_, err := extractLibrary(root, lib)
		var libErr *LibraryError
		if !errors.As(err, &libErr) {
			t.Errorf("%s: error %v, want *LibraryError", name, err)
		}
	}
}

func TestExtractLibraryWaitsForTheLock(t *testing.T) {
	root := cacheRoot(t)
	lib := fakeLibrary(t, []byte("locked library"))
	dir := filepath.Join(root, "0.2.0-"+lib.dllSHA256[:16])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := extractLibrary(root, lib)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("extraction did not wait for the lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExtractLibraryRemovesAStaleLock(t *testing.T) {
	root := cacheRoot(t)
	lib := fakeLibrary(t, []byte("stale lock library"))
	dir := filepath.Join(root, "0.2.0-"+lib.dllSHA256[:16])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, ".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleLock)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := extractLibrary(root, lib); err != nil {
		t.Fatal(err)
	}
}

func TestExtractLibraryFromManyGoroutines(t *testing.T) {
	root := cacheRoot(t)
	data := bytes.Repeat([]byte("concurrent library "), 10000)
	lib := fakeLibrary(t, data)
	var wg sync.WaitGroup
	paths := make([]string, 8)
	errs := make([]error, 8)
	for i := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			paths[i], errs[i] = extractLibrary(root, lib)
		}()
	}
	wg.Wait()
	for i := range paths {
		if errs[i] != nil || paths[i] != paths[0] {
			t.Fatalf("goroutine %d: %s, %v", i, paths[i], errs[i])
		}
	}
	if got, _ := os.ReadFile(paths[0]); !bytes.Equal(got, data) {
		t.Fatal("the library bytes are wrong")
	}
}
