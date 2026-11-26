//go:build windows

package rustleaks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// On Windows the package loads the Rust DLL at run time with the syscall
// package, so it builds without cgo or a C compiler.

// libraryPathUsed reports whether SetLibraryPath and RUSTLEAKS_LIBRARY_PATH
// choose the library on this system.
const libraryPathUsed = true

// loadLibrarySearchSystem32 makes LoadLibraryExW look for the DLLs that the
// Rust DLL needs only in System32. The DLL is built with a static C runtime
// and needs only system DLLs.
const loadLibrarySearchSystem32 = 0x00000800

// nativeProcs holds the address of every export the package calls.
type nativeProcs struct {
	abiVersion, version                                        uintptr
	optionsNew, optionsSetConfig, optionsAddRuleID             uintptr
	optionsSetU64, optionsSetBool, optionsFree                 uintptr
	engineNew, engineFree, engineWorkers, engineMaxInputBytes  uintptr
	engineRuleCount, engineRule                                uintptr
	cancelNew, cancelSet, cancelFree                           uintptr
	scan, resultStatus, resultCount, resultFinding, resultFree uintptr
	errorKind, errorMessage, errorFree                         uintptr
}

func (p *nativeProcs) symbols() map[string]*uintptr {
	return map[string]*uintptr{
		"rustleaks_abi_version":            &p.abiVersion,
		"rustleaks_version":                &p.version,
		"rustleaks_options_new":            &p.optionsNew,
		"rustleaks_options_set_config":     &p.optionsSetConfig,
		"rustleaks_options_add_rule_id":    &p.optionsAddRuleID,
		"rustleaks_options_set_u64":        &p.optionsSetU64,
		"rustleaks_options_set_bool":       &p.optionsSetBool,
		"rustleaks_options_free":           &p.optionsFree,
		"rustleaks_engine_new":             &p.engineNew,
		"rustleaks_engine_free":            &p.engineFree,
		"rustleaks_engine_workers":         &p.engineWorkers,
		"rustleaks_engine_max_input_bytes": &p.engineMaxInputBytes,
		"rustleaks_engine_rule_count":      &p.engineRuleCount,
		"rustleaks_engine_rule":            &p.engineRule,
		"rustleaks_cancel_new":             &p.cancelNew,
		"rustleaks_cancel_set":             &p.cancelSet,
		"rustleaks_cancel_free":            &p.cancelFree,
		"rustleaks_scan":                   &p.scan,
		"rustleaks_result_status":          &p.resultStatus,
		"rustleaks_result_count":           &p.resultCount,
		"rustleaks_result_finding":         &p.resultFinding,
		"rustleaks_result_free":            &p.resultFree,
		"rustleaks_error_kind":             &p.errorKind,
		"rustleaks_error_message":          &p.errorMessage,
		"rustleaks_error_free":             &p.errorFree,
	}
}

// procs is written once by loadNativeLibrary, under the library lock and
// before any other call, and only read after that.
var procs nativeProcs

// loadNativeLibrary finds the DLL and loads it. The DLL is never unloaded.
func loadNativeLibrary() error {
	path, want, err := resolveLibraryPath()
	if err != nil {
		return err
	}
	_, loaded, err := loadDLL(path, want)
	if err != nil {
		return err
	}
	procs = loaded
	return nil
}

// loadDLL loads the DLL at an absolute path, and only System32 is searched
// for the DLLs it needs. It holds the file open without write or delete
// sharing from before the hash check until the load returns, so no other
// process can change the file in between. want is the expected hex SHA-256,
// or empty for a path the caller chose.
func loadDLL(path, want string) (syscall.Handle, nativeProcs, error) {
	var loaded nativeProcs
	fail := func(message string, err error) (syscall.Handle, nativeProcs, error) {
		return 0, loaded, &LibraryError{Kind: LibraryLoad, Op: "load", Path: path, Message: message, Err: err}
	}
	if !filepath.IsAbs(path) {
		return fail("the library path is not absolute", nil)
	}
	file, err := openShareRead(path)
	if err != nil {
		return fail("cannot open the library", err)
	}
	defer file.Close()
	if want != "" {
		h := sha256.New()
		if _, err := io.Copy(h, io.LimitReader(file, maxLibraryBytes+1)); err != nil {
			return fail("cannot read the library", err)
		}
		if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
			return fail("the library does not match its SHA-256", nil)
		}
	}
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fail("cannot load kernel32.dll", err)
	}
	loadLibraryEx, err := kernel32.FindProc("LoadLibraryExW")
	if err != nil {
		return fail("cannot find LoadLibraryExW", err)
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fail("the library path holds a NUL character", err)
	}
	result, _, callErr := loadLibraryEx.Call(
		uintptr(unsafe.Pointer(name)),
		0,
		loadLibrarySearchSystem32,
	)
	if result == 0 {
		return fail("cannot load the library", callErr)
	}
	handle := syscall.Handle(result)
	for symbol, target := range loaded.symbols() {
		address, err := syscall.GetProcAddress(handle, symbol)
		if err != nil {
			_ = syscall.FreeLibrary(handle)
			return fail(fmt.Sprintf("the library has no %s export", symbol), err)
		}
		*target = address
	}
	return handle, loaded, nil
}

// openShareRead opens path for reading and lets other handles only read
// it, so while the file is open no one can write, rename or delete it.
func openShareRead(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// call calls an export and returns its int32 status. Every caller converts
// its pointer arguments to uintptr in the argument list of call, and
// go:uintptrescapes keeps what they point to alive and in place until call
// returns, as for syscall.SyscallN.
//
//go:uintptrescapes
func call(proc uintptr, args ...uintptr) int32 {
	result, _, _ := syscall.SyscallN(proc, args...)
	return int32(uint32(result))
}

func callABIVersion(out *uint32) int32 {
	return call(procs.abiVersion, uintptr(unsafe.Pointer(out)))
}

func callVersion(ptr *unsafe.Pointer, n *uintptr) int32 {
	return call(procs.version, uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(n)))
}

func callOptionsNew(abi uint32, out *unsafe.Pointer) int32 {
	return call(procs.optionsNew, uintptr(abi), uintptr(unsafe.Pointer(out)))
}

func callOptionsSetConfig(options, config unsafe.Pointer, n uintptr) int32 {
	return call(procs.optionsSetConfig, uintptr(options), uintptr(config), n)
}

func callOptionsAddRuleID(options, id unsafe.Pointer, n uintptr) int32 {
	return call(procs.optionsAddRuleID, uintptr(options), uintptr(id), n)
}

func callOptionsSetU64(options unsafe.Pointer, key uint32, value uint64) int32 {
	return call(procs.optionsSetU64, uintptr(options), uintptr(key), uintptr(value))
}

func callOptionsSetBool(options unsafe.Pointer, key uint32, value uint8) int32 {
	return call(procs.optionsSetBool, uintptr(options), uintptr(key), uintptr(value))
}

func callOptionsFree(options unsafe.Pointer) int32 {
	return call(procs.optionsFree, uintptr(options))
}

func callEngineNew(options unsafe.Pointer, out, failure *unsafe.Pointer) int32 {
	return call(procs.engineNew, uintptr(options), uintptr(unsafe.Pointer(out)), uintptr(unsafe.Pointer(failure)))
}

func callEngineFree(engine unsafe.Pointer) int32 {
	return call(procs.engineFree, uintptr(engine))
}

func callEngineWorkers(engine unsafe.Pointer, out *uintptr) int32 {
	return call(procs.engineWorkers, uintptr(engine), uintptr(unsafe.Pointer(out)))
}

func callEngineMaxInputBytes(engine unsafe.Pointer, out *uint64) int32 {
	return call(procs.engineMaxInputBytes, uintptr(engine), uintptr(unsafe.Pointer(out)))
}

func callEngineRuleCount(engine unsafe.Pointer, out *uintptr) int32 {
	return call(procs.engineRuleCount, uintptr(engine), uintptr(unsafe.Pointer(out)))
}

func callEngineRule(engine unsafe.Pointer, index uintptr, out *ruleView) int32 {
	return call(procs.engineRule, uintptr(engine), index, uintptr(unsafe.Pointer(out)))
}

func callCancelNew(out *unsafe.Pointer) int32 {
	return call(procs.cancelNew, uintptr(unsafe.Pointer(out)))
}

func callCancelSet(cancel unsafe.Pointer) int32 {
	return call(procs.cancelSet, uintptr(cancel))
}

func callCancelFree(cancel unsafe.Pointer) int32 {
	return call(procs.cancelFree, uintptr(cancel))
}

// callScan passes Go memory to the DLL: the input bytes and args. call
// keeps every pointer argument alive and in place until it returns, and the
// caller keeps the path alive. The library copies both before it returns.
func callScan(engine, input unsafe.Pointer, n uintptr, args *scanArgs, cancel unsafe.Pointer, out, failure *unsafe.Pointer) int32 {
	return call(
		procs.scan,
		uintptr(engine),
		uintptr(input),
		n,
		uintptr(unsafe.Pointer(args)),
		uintptr(cancel),
		uintptr(unsafe.Pointer(out)),
		uintptr(unsafe.Pointer(failure)),
	)
}

func callResultStatus(result unsafe.Pointer, out *statusView) int32 {
	return call(procs.resultStatus, uintptr(result), uintptr(unsafe.Pointer(out)))
}

func callResultCount(result unsafe.Pointer, out *uintptr) int32 {
	return call(procs.resultCount, uintptr(result), uintptr(unsafe.Pointer(out)))
}

func callResultFinding(result unsafe.Pointer, index uintptr, out *findingView) int32 {
	return call(procs.resultFinding, uintptr(result), index, uintptr(unsafe.Pointer(out)))
}

func callResultFree(result unsafe.Pointer) int32 {
	return call(procs.resultFree, uintptr(result))
}

func callErrorKind(failure unsafe.Pointer, out *int32) int32 {
	return call(procs.errorKind, uintptr(failure), uintptr(unsafe.Pointer(out)))
}

func callErrorMessage(failure unsafe.Pointer, ptr *unsafe.Pointer, n *uintptr) int32 {
	return call(procs.errorMessage, uintptr(failure), uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(n)))
}

func callErrorFree(failure unsafe.Pointer) int32 {
	return call(procs.errorFree, uintptr(failure))
}
