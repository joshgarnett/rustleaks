//go:build windows

package rustleaks

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	loadLibrarySearchDLLLoadDir = 0x00000100
	loadLibrarySearchSystem32   = 0x00000800
)

var procs struct {
	add, sum, stack uintptr
}

// loadLibrary loads the DLL at an absolute path. Only the DLL's own folder
// and System32 are searched for its dependencies.
func loadLibrary(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("library path %q is not absolute", path)
	}
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return err
	}
	loadLibraryEx, err := kernel32.FindProc("LoadLibraryExW")
	if err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, _, callErr := loadLibraryEx.Call(
		uintptr(unsafe.Pointer(name)),
		0,
		loadLibrarySearchDLLLoadDir|loadLibrarySearchSystem32,
	)
	if handle == 0 {
		return fmt.Errorf("load %s: %w", path, callErr)
	}
	for symbol, target := range map[string]*uintptr{
		"spike_add":   &procs.add,
		"spike_sum":   &procs.sum,
		"spike_stack": &procs.stack,
	} {
		address, err := syscall.GetProcAddress(syscall.Handle(handle), symbol)
		if err != nil {
			return fmt.Errorf("find %s: %w", symbol, err)
		}
		*target = address
	}
	return nil
}

func spikeAdd(a, b uint64) uint64 {
	mustBeLoaded()
	result, _, _ := syscall.SyscallN(procs.add, uintptr(a), uintptr(b))
	return uint64(result)
}

func spikeSum(data []byte) uint64 {
	mustBeLoaded()
	if len(data) == 0 {
		result, _, _ := syscall.SyscallN(procs.sum, 0, 0)
		return uint64(result)
	}
	result, _, _ := syscall.SyscallN(procs.sum, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	runtime.KeepAlive(data)
	return uint64(result)
}

func spikeStack(kib uint32) uint64 {
	mustBeLoaded()
	result, _, _ := syscall.SyscallN(procs.stack, uintptr(kib))
	return uint64(result)
}

func mustBeLoaded() {
	if procs.add == 0 || procs.sum == 0 || procs.stack == 0 {
		panic(errors.New("rustleaks: library is not loaded"))
	}
}
