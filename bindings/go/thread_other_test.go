//go:build !linux

package rustleaks

// onMainThread cannot tell the main thread apart on this system.
func onMainThread() (main, known bool) {
	return false, false
}
