package rustleaks

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"unsafe"
)

// packageVersion is the Rustleaks version of this package. The native
// library must have the same version.
const packageVersion = "0.2.0"

// LibraryPathEnv names the environment variable that gives the absolute
// path of the Rustleaks DLL on Windows.
const LibraryPathEnv = "RUSTLEAKS_LIBRARY_PATH"

// embeddedDLL is a Rustleaks DLL embedded in the program.
type embeddedDLL struct {
	version    string // Rustleaks version of the DLL, such as "0.2.0"
	dllSHA256  string // lowercase hex SHA-256 of the DLL
	gzipSHA256 string // lowercase hex SHA-256 of gzipped
	gzipped    []byte // the gzip-compressed DLL
}

// embeddedLibrary is the DLL that the Windows platform module embeds. The
// release generator writes a build-tagged file for each Windows platform
// into the published module that sets it from that module. In this
// repository it is nil, and the tests give the DLL path instead.
var embeddedLibrary *embeddedDLL

// embeddedLibraryName is the file name of an extracted DLL.
const embeddedLibraryName = "rustleaks_ffi.dll"

var library struct {
	mu     sync.Mutex
	loaded bool
	path   string
}

// SetLibraryPath sets the absolute path of the Rustleaks DLL on Windows. It
// takes precedence over RUSTLEAKS_LIBRARY_PATH and over a library embedded
// by a platform module. Call it before the first New; after the library is
// loaded it returns a *LibraryError.
//
// On Linux and macOS cgo links the library into the program, and
// SetLibraryPath does nothing and returns nil.
func SetLibraryPath(path string) error {
	if !libraryPathUsed {
		return nil
	}
	library.mu.Lock()
	defer library.mu.Unlock()
	if library.loaded {
		return &LibraryError{Op: "set library path", Message: "the library is already loaded"}
	}
	if !filepath.IsAbs(path) {
		return &LibraryError{Op: "set library path", Path: path, Message: "the library path is not absolute"}
	}
	library.path = path
	return nil
}

// ensureLibrary loads the native library once and checks that its ABI
// number and version match this package. A failed load is tried again on
// the next call.
func ensureLibrary() error {
	library.mu.Lock()
	defer library.mu.Unlock()
	if library.loaded {
		return nil
	}
	if err := loadNativeLibrary(); err != nil {
		return err
	}
	if err := checkLibraryIdentity(); err != nil {
		return err
	}
	library.loaded = true
	return nil
}

func checkLibraryIdentity() error {
	var abi uint32
	if status := callABIVersion(&abi); status != statusOK {
		return statusError("read the library ABI number", status)
	}
	if abi != abiVersion {
		return &LibraryError{Op: "check library", Message: "the library has ABI number " +
			strconv.FormatUint(uint64(abi), 10) + ", but this package needs " + strconv.Itoa(abiVersion)}
	}
	var ptr unsafe.Pointer
	var n uintptr
	if status := callVersion(&ptr, &n); status != statusOK {
		return statusError("read the library version", status)
	}
	if version := nativeString(nativeBytes{ptr: ptr, len: n}); version != packageVersion {
		return &LibraryError{Op: "check library", Message: "the library is version " + version +
			", but this package is version " + packageVersion}
	}
	return nil
}

// resolveLibraryPath returns the DLL path on Windows: the SetLibraryPath
// value, then RUSTLEAKS_LIBRARY_PATH, then the embedded library, written to
// the user cache folder. The caller holds library.mu.
func resolveLibraryPath() (string, error) {
	path, lib, err := chooseLibrary(library.path, os.Getenv(LibraryPathEnv), embeddedLibrary)
	if err != nil || lib == nil {
		return path, err
	}
	if lib.version != packageVersion {
		return "", &LibraryError{Op: "load", Message: "the embedded library is version " + lib.version +
			", but this package is version " + packageVersion}
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", &LibraryError{Op: "extract library", Message: "cannot find the user cache folder", Err: err}
	}
	return extractLibrary(filepath.Join(cache, "rustleaks"), lib)
}

// chooseLibrary picks the library source in order: a path set with
// SetLibraryPath, the environment variable, the embedded library. It
// returns either a path or the embedded library.
func chooseLibrary(setPath, envPath string, embedded *embeddedDLL) (string, *embeddedDLL, error) {
	switch {
	case setPath != "":
		return setPath, nil, nil
	case envPath != "":
		if !filepath.IsAbs(envPath) {
			return "", nil, &LibraryError{Op: "load", Path: envPath,
				Message: LibraryPathEnv + " is not an absolute path"}
		}
		return envPath, nil, nil
	case embedded != nil:
		return "", embedded, nil
	default:
		return "", nil, &LibraryError{Op: "load", Message: "no Rustleaks library: import the " +
			"platform module for this system, call SetLibraryPath, or set " + LibraryPathEnv}
	}
}
