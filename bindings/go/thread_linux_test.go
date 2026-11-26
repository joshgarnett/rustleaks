//go:build linux

package rustleaks

import (
	"os"
	"syscall"
)

// onMainThread reports whether the calling goroutine runs on the process's
// main thread, and whether that answer is known. On Linux the main thread's
// ID is the process ID.
func onMainThread() (main, known bool) {
	return syscall.Gettid() == os.Getpid(), true
}
