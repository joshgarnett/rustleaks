// Package nativelib passes a native library that a platform module embeds
// to the rustleaks package.
//
// Most programs never import it. On Windows, a platform module calls
// Register from an init function, and the rustleaks package reads the
// library with Registered when it creates its first engine. Linux and macOS
// link the library with cgo and do not use this package.
package nativelib

import "sync"

// Library is a native library embedded in a program.
type Library struct {
	// Version is the Rustleaks version of the library, such as "0.2.0".
	Version string
	// Name is the file name to write, such as "rustleaks_ffi.dll". It must
	// be a plain file name, without a folder.
	Name string
	// Compressed holds the gzip-compressed library.
	Compressed []byte
	// CompressedSHA256 is the lowercase hex SHA-256 of Compressed.
	CompressedSHA256 string
	// SHA256 is the lowercase hex SHA-256 of the library after
	// decompression.
	SHA256 string
}

var (
	mu         sync.Mutex
	registered *Library
)

// Register records lib for the rustleaks package. Call it once, from an
// init function. A later call replaces the earlier library.
func Register(lib Library) {
	mu.Lock()
	defer mu.Unlock()
	registered = &lib
}

// Registered returns the library that Register recorded, if any.
func Registered() (Library, bool) {
	mu.Lock()
	defer mu.Unlock()
	if registered == nil {
		return Library{}, false
	}
	return *registered, true
}
