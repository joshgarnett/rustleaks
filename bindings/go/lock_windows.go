//go:build windows

package rustleaks

import (
	"errors"
	"syscall"
	"time"
)

// errorSharingViolation is ERROR_SHARING_VIOLATION.
const errorSharingViolation syscall.Errno = 32

// lockFile opens path with no sharing, waiting up to wait while another
// handle has it open. The system closes the handle, and so releases the
// lock, when the process ends. The file stays in place.
func lockFile(path string, wait time.Duration) (func(), error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
			syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			return func() { _ = syscall.CloseHandle(handle) }, nil
		}
		if !errors.Is(err, errorSharingViolation) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, errors.New("another process holds " + path)
		}
		time.Sleep(lockPoll)
	}
}
