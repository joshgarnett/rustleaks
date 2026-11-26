package rustleaks

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The embedded Windows DLL is written once to a cache folder and loaded
// from there. This code is plain file handling, so it builds and is tested
// on every system.

const (
	// maxLibraryBytes bounds the decompressed library.
	maxLibraryBytes = 256 << 20
	// lockWait is how long extraction waits for another process that holds
	// the lock. The system releases a lock when its process ends, so a lock
	// is never left behind.
	lockWait = 2 * time.Minute
	lockPoll = 50 * time.Millisecond
)

// extractLibrary writes lib to root/<version>-<hash prefix>/rustleaks_ffi.dll
// unless a file with the expected hash is already there, and returns the
// file path.
//
// The file is read-only. On Linux and macOS, where only the tests use this
// code, the folder has mode 0700; on Windows it inherits the access rules
// of the user cache folder. The compressed bytes are checked before
// decompression and the result before it is written. A lock that the
// system holds for the process keeps two processes from writing at once,
// and the file appears only by rename from a temporary file in the same
// folder. An existing file is used only after its hash is checked again.
func extractLibrary(root string, lib *embeddedDLL) (string, error) {
	return extractLibraryWait(root, lib, lockWait)
}

// extractLibraryWait is extractLibrary with the longest wait for the lock.
func extractLibraryWait(root string, lib *embeddedDLL, wait time.Duration) (string, error) {
	fail := func(message string, err error) (string, error) {
		return "", &LibraryError{Kind: LibraryLoad, Op: "extract library", Path: root, Message: message, Err: err}
	}
	if !validVersion(lib.version) {
		return fail("the embedded library has no valid version", nil)
	}
	want := strings.ToLower(lib.dllSHA256)
	if len(want) != sha256.Size*2 || !isHex(want) {
		return fail("the embedded library has no valid SHA-256", nil)
	}
	if !hashMatches(lib.gzipped, lib.gzipSHA256) {
		return fail("the embedded library does not match its SHA-256", nil)
	}

	dir := filepath.Join(root, lib.version+"-"+want[:16])
	if err := makeCacheDir(dir); err != nil {
		return fail("cannot create the cache folder", err)
	}
	target := filepath.Join(dir, embeddedLibraryName)
	if fileHashMatches(target, want) {
		return target, nil
	}

	unlock, err := lockFile(filepath.Join(dir, ".lock"), wait)
	if err != nil {
		// The holder may have finished the file without releasing the lock
		// yet.
		if fileHashMatches(target, want) {
			return target, nil
		}
		return fail("cannot lock the cache folder", err)
	}
	defer unlock()
	// Another process may have written the file while this one waited.
	if fileHashMatches(target, want) {
		return target, nil
	}

	data, err := gunzip(lib.gzipped)
	if err != nil {
		return fail("cannot decompress the embedded library", err)
	}
	if !hashMatches(data, want) {
		return fail("the decompressed library does not match its SHA-256", nil)
	}
	if err := writeReadOnly(dir, target, data); err != nil {
		return fail("cannot write the library", err)
	}
	if !fileHashMatches(target, want) {
		return fail("the written library does not match its SHA-256", nil)
	}
	return target, nil
}

func validVersion(v string) bool {
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '.' || r == '-' || r == '+') {
			return false
		}
	}
	return v != "" && v != "." && v != ".."
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func hashMatches(data []byte, want string) bool {
	sum := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(sum[:]), want)
}

// fileHashMatches reports whether path is a regular file whose SHA-256 is
// want.
func fileHashMatches(path, want string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxLibraryBytes {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxLibraryBytes+1)); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want)
}

// makeCacheDir creates dir with mode 0700 and checks that it is a folder,
// not a link. Windows ignores the mode, and the folder inherits the access
// rules of its parent.
func makeCacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("the cache path is not a folder")
	}
	if info.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

func gunzip(compressed []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(r, maxLibraryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxLibraryBytes {
		return nil, errors.New("the library is larger than 256 MiB")
	}
	return data, r.Close()
}

// writeReadOnly writes data to a temporary file in dir, makes it read-only
// and renames it to target. A file already at target, which failed its hash
// check, is removed first.
func writeReadOnly(dir, target string, data []byte) (err error) {
	tmp, err := os.CreateTemp(dir, ".rustleaks-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Chmod(name, 0o600)
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(name, 0o400); err != nil {
		return err
	}
	if _, statErr := os.Lstat(target); statErr == nil {
		_ = os.Chmod(target, 0o600)
		if err = os.Remove(target); err != nil {
			return err
		}
	}
	return os.Rename(name, target)
}
